// Copyright (c) 2024 Cloudflare, Inc.
// SPDX-License-Identifier: BSD-3-Clause

//! The PINE VDAF as described in
//! [draft-chen-cfrg-vdaf-pine-00](https://github.com/junyechen1996/draft-chen-cfrg-vdaf-pine/).
//!
//! PINE is designed for aggregating "gradients" with a bounded "L2-norm". A gradient is a vector
//! of real numbers, called "coordinates"; the L2-norm of a gradient is the square root of the sum
//! of the square of each coordinates. (This is also sometimes called the "Euclidean norm".)
//!
//! Like Prio3, PINE is designed around a fully linear proof (FLP) used to verify that each
//! gradient being aggregated has an L2-norm that is no larger than the specified bound.
//!
//! PINE is based on the scheme from [Rothblum et al. 2023](https://arxiv.org/abs/2311.10237).

use std::marker::PhantomData;

use prio_draft09::{
    field::{FftFriendlyFieldElement, Field128, Field64},
    vdaf::{xof::XofTurboShake128, VdafError},
};

use flp::{PineType, PineTypeSquaredNormEqual};

const ALPHA: f64 = 8.7;

const DST_SIZE: usize = 7;

const USAGE_MEAS_SHARE: u16 = 1;
const USAGE_PROOF_SHARE: u16 = 2;
const USAGE_PROVE_RAND: u16 = 4;
const USAGE_QUERY_RAND: u16 = 5;
const USAGE_VF_JOINT_RAND: u16 = 3;
const USAGE_VF_JOINT_RAND_SEED: u16 = 6;
const USAGE_VF_JOINT_RAND_PART: u16 = 7;
const USAGE_WR_JOINT_RAND: u16 = 8;
const USAGE_WR_JOINT_RAND_SEED: u16 = 9;
const USAGE_WR_JOINT_RAND_PART: u16 = 10;

/// The PINE VDAF.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Pine<F, X, const SEED_SIZE: usize> {
    pub flp: PineType<F>,
    pub flp_sq_norm_equal: PineTypeSquaredNormEqual<F>,

    // PINE parameters
    num_proofs: u8,
    num_proofs_sq_norm_equal: u8,
    encoded_gradient_and_sq_norm_len: usize,
    encoded_input_len: usize,

    algorithm_id: u32,
    phantom_data: PhantomData<X>,
}

pub type Pine128 = Pine<Field128, XofTurboShake128, 16>;

impl Pine128 {
    /// Construct an instance of [`Pine128`] with the provided parameters.
    pub fn new_128(
        norm_bound: u64,
        dimension: usize,
        frac_bits: usize,
        chunk_len: usize,
        chunk_len_sq_norm_equal: usize,
    ) -> Result<Self, VdafError> {
        Self::new(
            &PineParam {
                norm_bound,
                dimension,
                frac_bits,
                chunk_len,
                chunk_len_sq_norm_equal,
                num_proofs: 1,
                num_proofs_sq_norm_equal: 1,
                num_wr_tests: 100,
                num_wr_successes: 100,
            },
            0xffff_ffff,
        )
    }
}

pub type Pine64 = Pine<Field64, XofTurboShake128, 16>;

impl Pine64 {
    /// Construct an instance of [`Pine64`] with the provided parameters.
    pub fn new_64(
        norm_bound: u64,
        dimension: usize,
        frac_bits: usize,
        chunk_len: usize,
        chunk_len_sq_norm_equal: usize,
    ) -> Result<Self, VdafError> {
        Self::new(
            &PineParam {
                norm_bound,
                dimension,
                frac_bits,
                chunk_len,
                chunk_len_sq_norm_equal,
                num_proofs: 2,
                num_proofs_sq_norm_equal: 1,
                num_wr_tests: 100,
                num_wr_successes: 100,
            },
            0xffff_ffff,
        )
    }
}

#[derive(
    Clone, Copy, Debug, serde::Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize,
)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(any(test, feature = "test-utils"), derive(deepsize::DeepSizeOf))]
pub struct PineParam {
    pub(crate) norm_bound: u64,
    pub(crate) dimension: usize,
    pub(crate) frac_bits: usize,
    pub(crate) chunk_len: usize,
    pub(crate) chunk_len_sq_norm_equal: usize,
    pub(crate) num_proofs: u8,
    pub(crate) num_proofs_sq_norm_equal: u8,
    pub(crate) num_wr_tests: usize,
    pub(crate) num_wr_successes: usize,
}

impl<F: FftFriendlyFieldElement, X, const SEED_SIZE: usize> Pine<F, X, SEED_SIZE> {
    /// Construct an instance of the Pine VDAF.
    ///
    /// # Parameters
    ///
    /// * `norm_bound`: Maximum L2-norm of each gradient, encoded as follows. Let `b: f64` denote
    ///   the desired L2-norm bound. We expect this parameter to be computed by multiplying `b` by
    ///   `2^frac_bits`, taking the floor, and converting to an integer.
    ///
    /// * `dimension`: Length of each gradient
    ///
    /// * `frac_bits`: Number of bits of precision used to encode the fractional component of each
    ///   gradient coordinate
    ///
    /// * `chunk_len`: Chunk length for the main FLP circuit.
    ///
    /// * `chunk_len_sq_norm_equal`: Chunk length for the squared-norm equality check circuit.
    ///
    /// * `num_proofs`: The number of FLP proofs to generate.
    ///
    /// * `algorithm_id`: The VDAF algorithm ID.
    pub(crate) fn new(param: &PineParam, algorithm_id: u32) -> Result<Self, VdafError> {
        if param.num_wr_tests < param.num_wr_successes {
            return Err(VdafError::Uncategorized(
                "init failed: num_wr_successes is larger than num_wr_tests".to_string(),
            ));
        }

        if param.norm_bound == 0
            || F::Integer::try_from(usize::try_from(param.norm_bound).map_err(|e| {
                VdafError::Uncategorized(format!(
                    "init failed: error while converting norm bound to usize: {e}"
                ))
            })?)
            .map_err(|e| {
                VdafError::Uncategorized(format!(
                    "init failed: error while converting norm bound to field integer: {e}"
                ))
            })? > F::modulus() >> 1
        {
            return Err(VdafError::Uncategorized(
                "init failed: norm bound must be positive".into(),
            ));
        }

        if param.dimension == 0 {
            return Err(VdafError::Uncategorized(
                "init failed: 0-dimension inputs are invalid".into(),
            ));
        }

        if param.frac_bits >= 128 {
            return Err(VdafError::Uncategorized(
                "init failed: number of fractional bits must not exceed 128".into(),
            ));
        }

        let Some(sq_norm_bound_int) = param.norm_bound.checked_mul(param.norm_bound) else {
            return Err(VdafError::Uncategorized(
                "init failed: squared norm is too large for u64".into(),
            ));
        };

        let (sq_norm_bound, sq_norm_bits) = {
            let sq_norm_bits = bits(sq_norm_bound_int);
            let sq_norm_bound = usize::try_from(sq_norm_bound_int).map_err(|e| {
                VdafError::Uncategorized(format!(
                    "init failed: failed to convert squared norm bound to usize: {e}"
                ))
            })?;
            let sq_norm_bound = F::Integer::try_from(sq_norm_bound).map_err(|e| {
                VdafError::Uncategorized(format!(
                    "init failed: failed to convert squared norm bound to field integer: {e}"
                ))
            })?;
            if sq_norm_bound >= F::modulus() {
                return Err(VdafError::Uncategorized(
                    "init failed: squared norm bound is too large for field".into(),
                ));
            }
            let sq_norm_bound = F::from(sq_norm_bound);
            (sq_norm_bound, sq_norm_bits)
        };

        let (wr_test_bound, wr_test_bits) = {
            #[expect(clippy::cast_possible_truncation)]
            #[expect(clippy::cast_sign_loss)]
            let wr_test_bound_int =
                (((param.norm_bound as f64) * ALPHA).ceil() as u64 + 1).next_power_of_two();
            let wr_test_bits = bits(2 * wr_test_bound_int - 1);
            let wr_test_bound = usize::try_from(wr_test_bound_int).map_err(|e| {
                VdafError::Uncategorized(format!(
                    "init failed: failed to convert wraparound test bound to usize: {e}"
                ))
            })?;
            let wr_test_bound = F::Integer::try_from(wr_test_bound).map_err(|e| {
                VdafError::Uncategorized(format!(
                    "init failed: failed to convert wraparound test bound to field integer: {e}"
                ))
            })?;
            if wr_test_bound >= F::modulus() {
                return Err(VdafError::Uncategorized(
                    "init failed: wraparound test bound is too large for field".into(),
                ));
            }
            let wr_test_bound = F::from(wr_test_bound);
            (wr_test_bound, wr_test_bits)
        };

        // FlP encoded measurement length parameters. The components of the input are:
        //
        // * gradient (length `dimension`)
        // * reported squared norm (`2 * sq_norm_bits`)
        // * reported wraparound test results (`1 + wr_test_bits * num_wr_tests`)
        // * wraparound test results (`num_wr_tests`)
        //
        // Length of the gradient and reported squared norm.
        let encoded_gradient_and_sq_norm_len = param.dimension + 2 * sq_norm_bits;

        // Length of the gradient, reported squared norm, and reported test results.
        let encoded_input_len =
            encoded_gradient_and_sq_norm_len + (1 + wr_test_bits) * param.num_wr_tests;

        // Length of the bit-checked portion of the encoded measurement: the reported squared norm
        // and the reported wraparound test results.
        let bit_checked_len = 2 * sq_norm_bits + (1 + wr_test_bits) * param.num_wr_tests;

        // The length of the fully encoded measurement passed to each validity circuit.
        let input_len = encoded_input_len + param.num_wr_tests;

        // Number of gadget calls. The gadget is used for the bit checks, wraparound tests, and
        // squared norm computation.
        let gadget_calls = chunk_count(param.chunk_len, bit_checked_len)
            + chunk_count(param.chunk_len, param.num_wr_tests);
        let gadget_calls_sq_norm_equal =
            chunk_count(param.chunk_len_sq_norm_equal, param.dimension);

        Ok(Self {
            flp: PineType {
                dimension: param.dimension,
                frac_bits: param.frac_bits,
                chunk_len: param.chunk_len,
                num_wr_tests: param.num_wr_tests,
                num_wr_successes: param.num_wr_successes,
                sq_norm_bound,
                sq_norm_bits,
                wr_test_bound,
                wr_test_bits,
                bit_checked_len,
                input_len,
                gadget_calls,
                algorithm_id,
            },
            flp_sq_norm_equal: PineTypeSquaredNormEqual {
                dimension: param.dimension,
                chunk_len: param.chunk_len_sq_norm_equal,
                sq_norm_bits,
                input_len,
                gadget_calls: gadget_calls_sq_norm_equal,
                phantom_data: PhantomData,
            },
            num_proofs: param.num_proofs,
            num_proofs_sq_norm_equal: param.num_proofs_sq_norm_equal,
            encoded_gradient_and_sq_norm_len,
            encoded_input_len,
            algorithm_id,
            phantom_data: PhantomData,
        })
    }
}

fn f64_to_field<F: FftFriendlyFieldElement>(x: f64, two_to_frac_bits: f64) -> Result<F, VdafError> {
    let neg = x < 0_f64;
    if !x.is_normal() && x != 0_f64 {
        return Err(VdafError::Uncategorized(
            "f64 encoding failed: input is subnormal".into(),
        ));
    }

    let out = x * two_to_frac_bits;
    let out = out.floor();
    let out = if neg { -out } else { out };
    #[expect(clippy::cast_possible_truncation)]
    #[expect(clippy::cast_sign_loss)]
    let out = out as u64;
    let out = usize::try_from(out).map_err(|e| {
        VdafError::Uncategorized(format!(
            "f64 encoding failed: failed to convert to usize: {e}"
        ))
    })?;
    let out = F::Integer::try_from(out).map_err(|e| {
        VdafError::Uncategorized(format!(
            "f64 encoding failed: field too small for gradient coordinate: {e}"
        ))
    })?;
    let out = F::from(out);
    let out = if neg { -out } else { out };
    Ok(out)
}

fn field_to_f64<F: FftFriendlyFieldElement>(x: F, two_to_frac_bits: f64) -> Result<f64, VdafError> {
    let out = F::Integer::from(x);
    let neg = out > F::modulus() >> 1;
    let out = if neg { F::modulus() - out } else { out };
    let out: u64 = out.try_into().map_err(|e| {
        VdafError::Uncategorized(format!(
            "f64 decoding failed: failed to convert to u64: {e}"
        ))
    })?;
    let out = out as f64;
    let out = if neg { -out } else { out };
    let out = out / two_to_frac_bits;
    Ok(out)
}

/// Compute the number of bits required to encode `x` in binary.
fn bits(x: u64) -> usize {
    if x == 0 {
        return 1;
    }

    // According to the Rust docs, `y` is the base-2 logarithm of `x` rounded down to the nearest
    // integer: https://doc.rust-lang.org/std/primitive.u64.html#method.ilog2
    let mut y = x.ilog2();

    // `x >= 2^y` by construction. We always add a bit because the largest number that can be
    // represented with `y` bits is `2^y-1`.
    y += 1;

    y.try_into().unwrap()
}

fn chunk_count(chunk_length: usize, length: usize) -> usize {
    length.div_ceil(chunk_length)
}

fn dst(algorithm_id: u32, usage: u16) -> [u8; DST_SIZE] {
    let mut dst = [0; DST_SIZE];
    dst[0] = 1; // VERSION, draft-cheng-cfrg-vdaf-pine-01
    dst[1..5].copy_from_slice(&algorithm_id.to_be_bytes()); // algo
    dst[5..].copy_from_slice(&usage.to_be_bytes()); // usage
    dst
}

#[cfg(test)]
fn norm_bound_f64_to_u64(norm_bound: f64, frac_bits: usize) -> u64 {
    let two_to_frac_bits = f64::from(1 << frac_bits);
    let norm_bound = norm_bound * two_to_frac_bits;
    let norm_bound = norm_bound.floor();
    #[expect(clippy::cast_sign_loss)]
    #[expect(clippy::cast_possible_truncation)]
    let norm_bound = norm_bound as u64;
    norm_bound
}

pub mod flp;
pub mod msg;
#[cfg(test)]
mod test_vec;
pub mod vdaf;

#[cfg(test)]
mod tests {
    use prio_draft09::field::Field128;

    use super::*;

    #[test]
    fn test_bits() {
        assert_eq!(bits(0), 1);
        assert_eq!(bits(1), 1);
        assert_eq!(bits(2), 2);
        assert_eq!(bits(3), 2);
        assert_eq!(bits(4), 3);
        assert_eq!(bits(7), 3);
        assert_eq!(bits(8), 4);
        assert_eq!(bits(15), 4);
        assert_eq!(bits(16), 5);
        assert_eq!(bits(31), 5);
        assert_eq!(bits(32), 6);
        assert_eq!(bits(63), 6);
        assert_eq!(bits(64), 7);
        assert_eq!(bits(127), 7);
        assert_eq!(bits(128), 8);
        assert_eq!(bits(u64::MAX), 64);
    }

    #[test]
    fn encode_f64() {
        let two_to_frac_bits = f64::from(1 << 15);

        struct TestCase {
            float: f64,
            elem: Field128,
        }

        // These test cases were generated by the unit tests for the reference code.
        for t in [
            TestCase {
                float: -100.0,
                elem: Field128::from(340_282_366_920_938_462_946_865_773_367_897_489_409),
            },
            TestCase {
                float: -1.0,
                elem: Field128::from(340_282_366_920_938_462_946_865_773_367_900_733_441),
            },
            TestCase {
                float: -0.0001,
                elem: Field128::from(340_282_366_920_938_462_946_865_773_367_900_766_205),
            },
            TestCase {
                float: -0.0,
                elem: Field128::from(0),
            },
            TestCase {
                float: 0.0,
                elem: Field128::from(0),
            },
            TestCase {
                float: 0.0001,
                elem: Field128::from(3),
            },
            TestCase {
                float: 0.1,
                elem: Field128::from(3276),
            },
            TestCase {
                float: 0.5,
                elem: Field128::from(16384),
            },
            TestCase {
                float: 1.0,
                elem: Field128::from(32768),
            },
            TestCase {
                float: 10_000.0,
                elem: Field128::from(327_680_000),
            },
        ] {
            assert_eq!(
                f64_to_field::<Field128>(t.float, two_to_frac_bits).unwrap(),
                t.elem,
                "{}",
                t.float,
            );
        }
    }

    #[test]
    fn decode_f64() {
        let two_to_frac_bits = f64::from(1 << 15);

        struct TestCase {
            input: f64,
            expected_output: f64,
        }

        // These test cases were copied from the unit tests for the reference code.
        for t in [
            TestCase {
                input: -100.0,
                expected_output: -100.0,
            },
            TestCase {
                input: -1.0,
                expected_output: -1.0,
            },
            TestCase {
                input: -0.0001,
                expected_output: -0.000_122_070_312_5,
            },
            TestCase {
                input: -0.0,
                expected_output: -0.0,
            },
            TestCase {
                input: 0.0,
                expected_output: 0.0,
            },
            TestCase {
                input: 0.0001,
                expected_output: 9.155_273_437_5e-05,
            },
            TestCase {
                input: 0.1,
                expected_output: 0.099_975_585_937_5,
            },
            TestCase {
                input: 0.5,
                expected_output: 0.5,
            },
            TestCase {
                input: 1.0,
                expected_output: 1.0,
            },
            TestCase {
                input: 10_000.0,
                expected_output: 10_000.0,
            },
        ] {
            // clippy: We expect the values to match precisely.
            #[expect(clippy::float_cmp)]
            {
                assert_eq!(
                    field_to_f64(
                        f64_to_field::<Field128>(t.input, two_to_frac_bits).unwrap(),
                        two_to_frac_bits
                    )
                    .unwrap(),
                    t.expected_output,
                    "{}",
                    t.input,
                );
            }
        }
    }

    #[test]
    fn bounds() {
        struct TestCase<F> {
            norm_bound: f64,
            frac_bits: usize,
            expected_sq_norm_bound: F,
            expected_sq_norm_bits: usize,
            expected_wr_test_bound: F,
            expected_wr_test_bits: usize,
        }

        for t in [
            TestCase {
                norm_bound: 1.0,
                frac_bits: 15,
                expected_sq_norm_bound: Field128::from(1_073_741_824),
                expected_sq_norm_bits: 31,
                expected_wr_test_bound: Field128::from(524_288),
                expected_wr_test_bits: 20,
            },
            TestCase {
                norm_bound: 1.0,
                frac_bits: 24,
                expected_sq_norm_bound: Field128::from(281_474_976_710_656),
                expected_sq_norm_bits: 49,
                expected_wr_test_bound: Field128::from(268_435_456),
                expected_wr_test_bits: 29,
            },
            TestCase {
                norm_bound: 1000.0,
                frac_bits: 15,
                expected_sq_norm_bound: Field128::from(1_073_741_824_000_000),
                expected_sq_norm_bits: 50,
                expected_wr_test_bound: Field128::from(536_870_912),
                expected_wr_test_bits: 30,
            },
            TestCase {
                norm_bound: 0.0001,
                frac_bits: 15,
                expected_sq_norm_bound: Field128::from(9),
                expected_sq_norm_bits: 4,
                expected_wr_test_bound: Field128::from(32),
                expected_wr_test_bits: 6,
            },
            TestCase {
                norm_bound: 1.0,
                frac_bits: 0,
                expected_sq_norm_bound: Field128::from(1),
                expected_sq_norm_bits: 1,
                expected_wr_test_bound: Field128::from(16),
                expected_wr_test_bits: 5,
            },
            TestCase {
                norm_bound: 1337.0,
                frac_bits: 0,
                expected_sq_norm_bound: Field128::from(1_787_569),
                expected_sq_norm_bits: 21,
                expected_wr_test_bound: Field128::from(16384),
                expected_wr_test_bits: 15,
            },
        ] {
            let pine = Pine::new_128(
                norm_bound_f64_to_u64(t.norm_bound, t.frac_bits),
                10, // not used by test
                t.frac_bits,
                1, // not used by tests
                1, // not used by tests
            )
            .unwrap();

            assert_eq!(
                pine.flp.sq_norm_bound, t.expected_sq_norm_bound,
                "sq_norm_bound"
            );
            assert_eq!(
                pine.flp.sq_norm_bits, t.expected_sq_norm_bits,
                "sq_norm_bits"
            );
            assert_eq!(
                pine.flp.wr_test_bound, t.expected_wr_test_bound,
                "wr_test_bound"
            );
            assert_eq!(
                pine.flp.wr_test_bits, t.expected_wr_test_bits,
                "wr_test_bits"
            );
        }
    }

    // Test that parameters are copied consistently across the structs that use them.
    #[test]
    fn parameter_consistency() {
        let frac_bits = 19;
        let param = PineParam {
            norm_bound: norm_bound_f64_to_u64(1000.0, frac_bits),
            dimension: 10_000,
            frac_bits,
            chunk_len: 1_337,
            chunk_len_sq_norm_equal: 54,
            num_proofs: 3,
            num_proofs_sq_norm_equal: 2,
            num_wr_tests: 145,
            num_wr_successes: 100,
        };

        let pine = Pine::<Field64, XofTurboShake128, 16>::new(&param, 0xdead_beef).unwrap();

        // PineParam -> PineType
        assert_eq!(pine.flp.dimension, param.dimension);
        assert_eq!(pine.flp.frac_bits, param.frac_bits);
        assert_eq!(pine.flp.chunk_len, param.chunk_len);
        assert_eq!(pine.flp.num_wr_tests, param.num_wr_tests);
        assert_eq!(pine.flp.num_wr_successes, param.num_wr_successes);

        // PineParam -> PineTypeSquaredNormEqual
        assert_eq!(pine.flp_sq_norm_equal.dimension, param.dimension);
        assert_eq!(
            pine.flp_sq_norm_equal.chunk_len,
            param.chunk_len_sq_norm_equal
        );

        // PineParam -> PineType, PineTypeSquaredNormEqual
        assert_eq!(pine.flp.sq_norm_bits, pine.flp_sq_norm_equal.sq_norm_bits);
        assert_eq!(pine.flp.input_len, pine.flp_sq_norm_equal.input_len);

        // PineParam -> Pine
        assert_eq!(pine.num_proofs, param.num_proofs);
        assert_eq!(
            pine.num_proofs_sq_norm_equal,
            param.num_proofs_sq_norm_equal
        );
        assert_eq!(pine.algorithm_id, 0xdead_beef);
    }
}
