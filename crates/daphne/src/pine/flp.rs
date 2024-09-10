// Copyright (c) 2024 Cloudflare, Inc.
// SPDX-License-Identifier: BSD-3-Clause

//! Circuits for defining validity of PINE measurements.
//!
//! A PINE measurement is a vector of `f64`s with a bounded "L2-norm", hereafter "norm". To check
//! if a given measurement is valid, we compute the squared norm and check that it falls in the
//! range we expect. We also need to ensure the squared norm is not so large that it wraps around
//! the field modulus. Otherwise, a squared norm that is too large may appear to be in range when
//! in fact it is not.
//!
//! Wraparound enforcement is accomplished by a sequence of probabilistic tests devised by
//! [[ROCT23]]. A successful wraparound test indicates, w.h.p., that the squared norm of the
//! gradient, as it is represented in the field, is a value between 0 and an upper bound that
//! depends on the circuit parameters.
//!
//! This functionality is split into two circuits:
//!
//! * [`PineTypeSquaredNormEqual`] computes the squared norm of the gradient and checks that
//!   it is equal to the value claimed by the client.
//!
//! * [`PineType`] checks that the squared norm claimed by the client is in range and checks if the
//!   wraparound checks succeeded. This type also implements the functionality for encoding the
//!   gradient and the wraparound test results.
//!
//! The functionality is split into two circuits for performance reasons:
//! [`PineTypeSquaredNormEqual`] does not require joint randomness, which means we can usually get
//! away with generating one proof for it; [`PineType`] needs joint randomness, which means we must
//! usually generate more than one proof in order to compensate for offline attacks, especially for
//! smaller field sizes.
//!
//! [ROCT23]: https://arxiv.org/abs/2311.10237

use std::marker::PhantomData;

use prio::{
    field::FftFriendlyFieldElement,
    flp::{
        gadgets::{Mul, ParallelSum, ParallelSumGadget, PolyEval},
        FlpError, Gadget, Type,
    },
    vdaf::{
        xof::{Seed, Xof},
        VdafError,
    },
};
use rand::Rng;

use super::{chunk_count, dst, f64_to_field, field_to_f64, USAGE_WR_JOINT_RAND};

/// The main FLP used to check each measurement's validity.
///
/// The circuit checks that the claimed squared norm is in range and that the wraparound tests
/// succeeded. This type also implements encoding of the measurement, including running the
/// wraparound tests.
///
/// To ensure a gradient is valid, it is also necessary to run [`PineTypeSquaredNormEqual`] on the
/// encoded measurement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PineType<F> {
    // PINE parameters
    pub(crate) dimension: usize,
    pub(crate) frac_bits: usize,
    pub(crate) chunk_len: usize,
    pub(crate) num_wr_tests: usize,
    pub(crate) num_wr_successes: usize,

    // FLP parameters
    pub(crate) sq_norm_bound: F,
    pub(crate) sq_norm_bits: usize,
    pub(crate) wr_test_bound: F,
    pub(crate) wr_test_bits: usize,
    pub(crate) input_len: usize,
    pub(crate) bit_checked_len: usize,
    pub(crate) gadget_calls: usize,
    pub(crate) algorithm_id: u32, // Used to construct an [`Xof`] for running the wraparound tests
}

impl<F: FftFriendlyFieldElement> PineType<F> {
    /// Encode a gradient using the provided seed for the wraparound tests.
    ///
    /// Return the encoded measurement `meas` and wraparound test results `wr_test_results`. The
    /// input to the FLP circuit is `meas || wr_test_results`.
    pub fn encode_with_wr_joint_rand<X: Xof<SEED_SIZE>, const SEED_SIZE: usize>(
        &self,
        gradient: impl Iterator<Item = f64>,
        wr_joint_rand_seed: &Seed<SEED_SIZE>,
    ) -> Result<(Vec<F>, Vec<F>), VdafError> {
        let mut meas = Vec::with_capacity(self.input_len());
        self.append_encoded_gradient(&mut meas, gradient)?;
        let wr_test_results =
            self.append_wr_test_results::<X, SEED_SIZE>(&mut meas, wr_joint_rand_seed)?;
        Ok((meas, wr_test_results))
    }

    /// Append the encoded gradient and range-checked squared norm to the buffer (`meas`). The
    /// buffer is expected to be empty.
    ///
    /// In case of error, the buffer may have been modified and must be cleared before re-use.
    pub(crate) fn append_encoded_gradient(
        &self,
        meas: &mut Vec<F>,
        gradient: impl Iterator<Item = f64>,
    ) -> Result<(), VdafError> {
        let two_to_frac_bits = f64::from(1 << self.frac_bits);

        // Encode the gradient and compute the squared norm.
        let mut sq_norm = F::zero();
        let mut gradient_len = 0;
        for x in gradient {
            let encoded_x = f64_to_field(x, two_to_frac_bits)?;
            meas.push(encoded_x);
            sq_norm += encoded_x * encoded_x;
            gradient_len += 1;
        }

        if gradient_len != self.dimension {
            return Err(VdafError::Uncategorized(
                "gradient encoding failed: gradient has unexpected dimension".into(),
            ));
        }

        // Encode the range checked, squared norm.
        let (_in_range, v, u) = range_checked(sq_norm, F::zero(), self.sq_norm_bound);
        let v_bits = F::encode_as_bitvector(F::Integer::from(v), self.sq_norm_bits)?;
        let u_bits = F::encode_as_bitvector(F::Integer::from(u), self.sq_norm_bits)?;
        for x in v_bits.into_iter().chain(u_bits.into_iter()) {
            meas.push(x);
        }

        Ok(())
    }

    /// Append the bit-encoded, range-checked wraparound test results to the buffer (`meas`) and
    /// return the results. The buffer is expected to contain the encoded gradient and
    /// range-checked squared norm.
    ///
    /// Each test result consists of the range-checked dot-product of a random `{-1, 0, 1}`-vector
    /// (derived from `wr_joint_rand_seed`) and the gradient and the "success bit" that indicates
    /// whether the test was successful (i.e., the dot product is in the desired range).
    ///
    /// The intermediate test results are the dot products. The caller is meant to pass `meas ||
    /// wr_test_results` to the FLP: the verifier gets `meas` from the verifier and computes
    /// `wr_test_results` on its own.
    ///
    /// In case of error, the buffer may have been modified and must be cleared before re-use.
    pub(crate) fn append_wr_test_results<X: Xof<SEED_SIZE>, const SEED_SIZE: usize>(
        &self,
        meas: &mut Vec<F>,
        wr_joint_rand_seed: &Seed<SEED_SIZE>,
    ) -> Result<Vec<F>, VdafError> {
        let wr_test_results =
            self.run_wr_tests::<X, SEED_SIZE>(&meas[..self.dimension], wr_joint_rand_seed);

        let mut wr_success_count = 0;
        for wr_test_result in &wr_test_results {
            // Append the range-checked test result.
            let (in_range, v, _u) = range_checked(
                *wr_test_result,
                -self.wr_test_bound + F::one(),
                self.wr_test_bound,
            );
            let v_bits = F::encode_as_bitvector(F::Integer::from(v), self.wr_test_bits)?;
            for x in v_bits {
                meas.push(x);
            }

            // Append the success bit.
            if in_range && wr_success_count < self.num_wr_successes {
                wr_success_count += 1;
                meas.push(F::one());
            } else {
                meas.push(F::zero());
            }
        }

        if wr_success_count != self.num_wr_successes {
            return Err(VdafError::Uncategorized(
                "append wraparound tests failed: insufficient number of successes".into(),
            ));
        }

        Ok(wr_test_results)
    }

    /// Run the wraparound tests. For each test, compute the dot product of the gradient and a
    /// random `{-1, 0, 1}`-vector derived from the provided seed.
    pub(crate) fn run_wr_tests<X: Xof<SEED_SIZE>, const SEED_SIZE: usize>(
        &self,
        gradient: &[F],
        wr_joint_rand_seed: &Seed<SEED_SIZE>,
    ) -> Vec<F> {
        debug_assert_eq!(gradient.len(), self.dimension);
        let mut xof = X::seed_stream(
            wr_joint_rand_seed,
            &dst(self.algorithm_id, USAGE_WR_JOINT_RAND),
            &[],
        );
        let rand_len_per_test = chunk_count(4, self.dimension);
        let mut rand = vec![0_u8; rand_len_per_test * self.num_wr_tests];
        xof.fill(&mut rand[..]);

        let mut wr_test_results = vec![F::zero(); self.num_wr_tests];
        for (wr_test_result, rand_per_test) in wr_test_results
            .iter_mut()
            .zip(rand.chunks(rand_len_per_test))
        {
            for (gradient_chunk, mut r) in
                gradient.chunks_exact(4).zip(rand_per_test.iter().copied())
            {
                for x in gradient_chunk {
                    match r & 3 {
                        0 => *wr_test_result -= *x,
                        3 => *wr_test_result += *x,
                        _ => (),
                    };
                    r >>= 2;
                }
            }

            let gradient_chunk = gradient.chunks_exact(4).remainder();
            let mut r = rand_per_test.last().copied().unwrap();
            for x in gradient_chunk {
                match r & 3 {
                    0 => *wr_test_result -= *x,
                    3 => *wr_test_result += *x,
                    _ => (),
                };
                r >>= 2;
            }
        }

        wr_test_results
    }

    /// Check that element of `bit_checked` is `0` or `1`.
    fn eval_bit_checks(
        &self,
        buf: &mut Vec<F>,
        gadget: &mut [Box<dyn Gadget<F>>],
        bit_checked: &[F],
        r_bit_check: F,
        shares_inv: F,
    ) -> Result<F, FlpError> {
        debug_assert_eq!(bit_checked.len(), self.bit_checked_len);
        debug_assert_eq!(buf.capacity(), self.chunk_len * 2);
        buf.clear();

        // Construct a polynomial from the bits and evaluate it at `r_bit_check`. The
        // polynomial is
        //
        // ```
        // f(x) = B[0]*(B[0]-1) + x*B[1]*(B[1]-1) + x^2*B[2]*(B[2]-1) + ...
        // ```
        //
        // where `B[i]` is the `(i-1)`-th bit. The value of `B[i](B[i]-1)` is 0 if and only if
        // `B[i]` is 0 or 1. Thus if one of the bits is non-zero, then `f(r_bit_check)` will be
        // non-zero w.h.p.
        //
        // This corresponds to the first call to `parallel_sum()` in the validity circuit of
        // the reference implementation.
        let mut r_power = F::one();
        bit_checked
            .chunks(self.chunk_len)
            .map(|chunk| {
                for x in chunk {
                    buf.push(r_power * *x);
                    buf.push(*x - shares_inv);
                    r_power *= r_bit_check;
                }
                for _ in buf.len()..buf.capacity() {
                    buf.push(F::zero());
                }

                let y = gadget[0].call(buf);
                buf.clear();
                y
            })
            .try_fold(F::zero(), |x, y| Ok(x + y?))
    }

    /// Check two things:
    ///
    /// (1) For each wraparound test, (i) the reported success bit (`wr_test_g`) is 0 or (ii)
    ///     the success bit is 1 and the reported result (`wr_test_v`) was computed correctly.
    ///
    /// (2) The number of reported successes is equal to the expected number of successes.
    ///
    /// See [[ROCT23]], Figure 2 for details.
    ///
    /// A test is only successful if the reported result is in the specified range. The range is
    /// chosen so that it is sufficient to bit-check the reported result. See [ROCT23], Remark
    /// 3.2 for details.
    ///
    /// These checks are only valid if the bit checks were successful (i.e., the output of
    /// `eval_bit_checks()` was `0`).
    ///
    /// [ROCT23]: https://arxiv.org/abs/2311.10237
    fn eval_wr_checks(
        &self,
        buf: &mut Vec<F>,
        gadget: &mut [Box<dyn Gadget<F>>],
        wr_test_bits: &[F],
        wr_test_results: &[F],
        r_wr_test: F,
        shares_inv: F,
    ) -> Result<(F, F), FlpError> {
        debug_assert_eq!(
            wr_test_bits.len(),
            self.num_wr_tests * (self.wr_test_bits + 1)
        );
        debug_assert_eq!(wr_test_results.len(), self.num_wr_tests);
        debug_assert_eq!(buf.capacity(), self.chunk_len * 2);
        buf.clear();

        // For each test, add up the success bits (i.e., each `wr_test_g`).
        let mut wr_success_count = F::zero();

        // For each test, multiply `wr_test_v - wr_test + wr_test_bound` by `wr_test_g`. The
        // result is 0 if (i) or (ii) holds. Similar to the bit checks, interpret these values
        // as coefficients of a polynomial and evaluate the polynomial at `r_wr_test`.
        let mut wr_tests_result = F::zero();

        // The following loop corresponds to the second call to `parallel_sum()` in the validity
        // circuit of the reference implementation.
        let mut r_power = F::one();
        let wr_test_bound = (self.wr_test_bound - F::one()) * shares_inv;
        for (bits, wr_test_result) in wr_test_bits
            .chunks_exact(self.wr_test_bits + 1)
            .zip(wr_test_results)
        {
            let wr_test_v_bits = &bits[..self.wr_test_bits];
            let wr_test_v = F::decode_bitvector(wr_test_v_bits)?;
            let wr_test_g = bits[self.wr_test_bits];

            buf.push(r_power * (*wr_test_result - wr_test_v + wr_test_bound));
            buf.push(wr_test_g);
            wr_success_count += wr_test_g;
            r_power *= r_wr_test;

            if buf.len() == self.chunk_len * 2 {
                wr_tests_result += gadget[0].call(buf)?;
                buf.clear();
            }
        }

        if !buf.is_empty() {
            for _ in buf.len()..self.chunk_len * 2 {
                buf.push(F::zero());
            }
            wr_tests_result += gadget[0].call(buf)?;
        }

        Ok((
            wr_tests_result,
            // The success count is equal to the expected value.
            wr_success_count
                - F::from(F::Integer::try_from(self.num_wr_successes).map_err(|_| {
                    FlpError::Valid("num_wr_successes is too large for field".to_string())
                })?) * shares_inv,
        ))
    }

    /// Check that the reported squared norm is in range. The result is only valid if the bit
    /// checks and the wraparound tests were successful, i.e., `eval_bit_checks()` and
    /// `eval_wr_checks()` each output `0`.
    fn eval_norm_range_check(
        &self,
        sq_norm_v_bits: &[F],
        sq_norm_u_bits: &[F],
        shares_inv: F,
    ) -> Result<F, FlpError> {
        debug_assert_eq!(sq_norm_v_bits.len(), self.sq_norm_bits);
        debug_assert_eq!(sq_norm_u_bits.len(), self.sq_norm_bits);
        let sq_norm_v = F::decode_bitvector(sq_norm_v_bits)?;
        let sq_norm_u = F::decode_bitvector(sq_norm_u_bits)?;

        Ok(
            // The reported squared norm is in range (see [ROCT223], Figure 1).
            sq_norm_v + sq_norm_u - self.sq_norm_bound * shares_inv,
        )
    }
}

impl<F: FftFriendlyFieldElement> Type for PineType<F> {
    type Measurement = (); // Not used by Pine
    type AggregateResult = Vec<f64>;
    type Field = F;

    fn encode_measurement(&self, _measurement: &()) -> Result<Vec<F>, FlpError> {
        // PINE uses a randomized encoding, where the randomness is derived by the protocol.
        unimplemented!("use encode_with_wr_joint_rand() instead")
    }

    fn decode_result(&self, data: &[F], _num_measurements: usize) -> Result<Vec<f64>, FlpError> {
        let two_to_frac_bits = f64::from(1 << self.frac_bits);

        data.iter()
            .map(|encoded| field_to_f64(*encoded, two_to_frac_bits))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| FlpError::Decode(e.to_string()))
    }

    fn gadget(&self) -> Vec<Box<dyn Gadget<F>>> {
        vec![Box::new(ParallelSum::new(
            Mul::new(self.gadget_calls),
            self.chunk_len,
        ))]
    }

    fn valid(
        &self,
        gadget: &mut Vec<Box<dyn Gadget<F>>>,
        meas: &[F],
        joint_rand: &[F],
        num_shares: usize,
    ) -> Result<F, FlpError> {
        let mut buf = Vec::with_capacity(self.chunk_len * 2);
        let shares_inv = F::from(F::Integer::try_from(num_shares).unwrap()).inv();

        // Unpack the encoded measurement. It is composed of the following components:
        //
        // * The gradient `encoded_gradient`, not used by this circuit. It is used by
        // [`PineTypeSquaredNormEqual`] instead.
        //
        // * A pair `(sq_norm_v_bits, sq_norm_u_bits)`, the bit-encoded, range-checked, squared
        //   norm of the gradient.
        //
        // * For each wraparound test, a pair `(wr_test_v_bits, wr_test_g)`: `wr_test_v_bits` is
        //   the bit-encoded, range-checked test result; and `wr_test_g` is an indication of
        //   whether the test succeeded (i.e., the result is in the specified range).
        //
        // * For each wraparound test, the result `wr_test_result`.
        let (_encoded_gradient, rest) = meas.split_at(self.dimension);
        let (bit_checked, rest) = rest.split_at(self.bit_checked_len);
        let (wr_test_results, rest) = rest.split_at(self.num_wr_tests);
        assert!(rest.is_empty());

        // Unpack the bit checked values.
        let (sq_norm_v_bits, rest) = bit_checked.split_at(self.sq_norm_bits);
        let (sq_norm_u_bits, rest) = rest.split_at(self.sq_norm_bits);
        let (wr_test_bits, rest) = rest.split_at(self.num_wr_tests * (self.wr_test_bits + 1));
        assert!(rest.is_empty());

        // Unpack the joint randomness.
        let [r_bit_check, r_wr_test, r_final] = joint_rand.try_into().unwrap();

        // Check that each of bit-checked value is either 0 or 1.
        let bit_check_result =
            self.eval_bit_checks(&mut buf, gadget, bit_checked, r_bit_check, shares_inv)?;

        let (wr_tests_result, wr_success_count_check_result) = self.eval_wr_checks(
            &mut buf,
            gadget,
            wr_test_bits,
            wr_test_results,
            r_wr_test,
            shares_inv,
        )?;

        let sq_norm_range_check_result =
            self.eval_norm_range_check(sq_norm_v_bits, sq_norm_u_bits, shares_inv)?;

        let mut result = bit_check_result;
        let mut r_power = r_final;
        result += r_power * sq_norm_range_check_result;
        r_power *= r_final;
        result += r_power * wr_tests_result;
        r_power *= r_final;
        result += r_power * wr_success_count_check_result;
        Ok(result)
    }

    fn truncate(&self, mut input: Vec<F>) -> Result<Vec<F>, FlpError> {
        input.truncate(self.dimension);
        Ok(input)
    }

    fn input_len(&self) -> usize {
        self.input_len
    }

    fn proof_len(&self) -> usize {
        2 * self.chunk_len + 2 * ((1 + self.gadget_calls).next_power_of_two() - 1) + 1
    }

    fn verifier_len(&self) -> usize {
        2 * self.chunk_len + 2
    }

    fn output_len(&self) -> usize {
        self.dimension
    }

    fn joint_rand_len(&self) -> usize {
        3
    }

    fn prove_rand_len(&self) -> usize {
        self.chunk_len * 2
    }

    fn query_rand_len(&self) -> usize {
        1
    }
}

/// FLP used to check that the squared norm of the gradient is equal to the claimed value.
///
/// To ensure a gradient is valid, it is also necessary to run [`PineType`] on the encoded
/// measurement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PineTypeSquaredNormEqual<F> {
    // PINE parameters
    pub(crate) dimension: usize,
    pub(crate) chunk_len: usize,

    // FLP parameters
    pub(crate) sq_norm_bits: usize,
    pub(crate) gadget_calls: usize,
    pub(crate) input_len: usize,
    pub(crate) phantom_data: PhantomData<F>,
}

impl<F: FftFriendlyFieldElement> Type for PineTypeSquaredNormEqual<F> {
    type Measurement = (); // Not used by this type.
    type AggregateResult = (); // Not used by this type.
    type Field = F;

    fn encode_measurement(&self, _measurement: &()) -> Result<Vec<F>, FlpError> {
        unimplemented!("use PineType to encode the measurement")
    }

    fn decode_result(&self, _data: &[F], _num_measurements: usize) -> Result<(), FlpError> {
        unimplemented!("use PineType to decode the aggregate result")
    }

    fn truncate(&self, _input: Vec<F>) -> Result<Vec<F>, FlpError> {
        unimplemented!("use PineType to truncate the input")
    }

    fn output_len(&self) -> usize {
        unimplemented!("use PineType to truncate the input")
    }

    fn gadget(&self) -> Vec<Box<dyn Gadget<F>>> {
        vec![Box::new(ParallelSum::new(
            PolyEval::new(vec![F::zero(), F::zero(), F::one()], self.gadget_calls),
            self.chunk_len,
        ))]
    }

    fn valid(
        &self,
        gadget: &mut Vec<Box<dyn Gadget<F>>>,
        meas: &[F],
        _joint_rand: &[F],
        _num_shares: usize,
    ) -> Result<F, FlpError> {
        let mut buf = Vec::with_capacity(self.chunk_len);
        let (encoded_gradient, rest) = meas.split_at(self.dimension);
        let (sq_norm_v_bits, _rest) = rest.split_at(self.sq_norm_bits);

        // Compute the squared norm of the gradient.
        //
        // This corresponds to the third call to `parallel_sum()` in the validity circuit of the
        // reference implementation.
        let sq_norm = encoded_gradient
            .chunks(self.chunk_len)
            .map(|chunk| {
                buf.extend(chunk);
                for _ in buf.len()..buf.capacity() {
                    buf.push(F::zero());
                }

                let y = gadget[0].call(&buf);
                buf.clear();
                y
            })
            .try_fold(F::zero(), |x, y| Ok::<_, FlpError>(x + y?))?;

        let sq_norm_v = F::decode_bitvector(sq_norm_v_bits)?;
        Ok(sq_norm_v - sq_norm)
    }

    fn input_len(&self) -> usize {
        self.input_len
    }

    fn proof_len(&self) -> usize {
        self.chunk_len + 2 * ((1_usize + self.gadget_calls).next_power_of_two() - 1) + 1
    }

    fn verifier_len(&self) -> usize {
        self.chunk_len + 2
    }

    fn joint_rand_len(&self) -> usize {
        0
    }

    fn prove_rand_len(&self) -> usize {
        self.chunk_len
    }

    fn query_rand_len(&self) -> usize {
        1
    }
}

fn range_checked<F: FftFriendlyFieldElement>(x: F, lower_bound: F, upper_bound: F) -> (bool, F, F) {
    let v = x - lower_bound;
    let u = upper_bound - x;
    let is_in_range = F::Integer::from(v) <= F::Integer::from(upper_bound - lower_bound);
    (is_in_range, v, u)
}

#[cfg(test)]
mod tests {
    use prio::{
        field::{Field128, FieldElement, FieldElementWithInteger},
        flp::{test_utils::FlpTest, Type},
        vdaf::xof::XofTurboShake128,
    };
    use rand::prelude::*;
    use std::iter;

    use crate::pine::{norm_bound_f64_to_u64, Pine};

    use super::*;

    #[test]
    fn encode_gradient() {
        let dimension = 10;
        let frac_bits = 4;
        let norm_bound = norm_bound_f64_to_u64(100.0, frac_bits);
        let pine = Pine::new_128(norm_bound, dimension, frac_bits, 4, 5).unwrap();

        // We use whole numbers here so that we can test gradient decoding without losing any
        // precision.
        let gradient = (0..dimension).map(|i| i as f64);

        let mut meas = Vec::new();
        pine.flp
            .append_encoded_gradient(&mut meas, gradient.clone())
            .unwrap();
        let (encoded_gradient, rest) = meas.split_at(pine.flp.dimension);
        let (sq_norm_v_bits, rest) = rest.split_at(pine.flp.sq_norm_bits);
        let (sq_norm_u_bits, rest) = rest.split_at(pine.flp.sq_norm_bits);
        assert!(rest.is_empty());

        let sq_norm = encoded_gradient
            .iter()
            .map(move |x| x * x)
            .reduce(|s, x| s + x)
            .unwrap();

        // Test that the encoded gradient decodes into the gradient.
        assert_eq!(
            pine.flp.decode_result(encoded_gradient, 1).unwrap(),
            gradient.clone().collect::<Vec<_>>()
        );

        // Test that the truncated measurement is equal to the encoded gradient.
        assert_eq!(encoded_gradient, pine.flp.truncate(meas.clone()).unwrap());
        assert_eq!(pine.flp.output_len(), encoded_gradient.len());

        // Test that the range-checked squared norm was computed correctly.
        let sq_norm_v = Field128::decode_bitvector(sq_norm_v_bits).unwrap();
        let sq_norm_u = Field128::decode_bitvector(sq_norm_u_bits).unwrap();
        assert_eq!(sq_norm_v, sq_norm);
        assert_eq!(sq_norm_u, pine.flp.sq_norm_bound - sq_norm);
    }

    #[test]
    fn encode_wr_tests() {
        let mut rng = thread_rng();
        let norm_bound = norm_bound_f64_to_u64(10.0, 15);
        let pine = Pine::new_128(norm_bound, 10, 15, 4, 5).unwrap();
        let gradient = iter::repeat_with(|| rng.gen_range(-0.1..0.1)).take(10);

        let (input, wr_test_results) = pine
            .flp
            .encode_with_wr_joint_rand::<XofTurboShake128, 16>(gradient, &Seed::generate().unwrap())
            .unwrap();
        let (_encoded_gradient, rest) = input.split_at(pine.flp.dimension);
        let (bit_checked, rest) = rest.split_at(pine.flp.bit_checked_len);
        assert!(rest.is_empty());

        let (_sq_norm_bits, rest) = bit_checked.split_at(pine.flp.sq_norm_bits * 2);
        for (wr_test_bits, wr_test_result) in
            rest.chunks(pine.flp.wr_test_bits + 1).zip(wr_test_results)
        {
            let wr_test_v =
                Field128::decode_bitvector(&wr_test_bits[..pine.flp.wr_test_bits]).unwrap();
            let wr_test_g = wr_test_bits[pine.flp.wr_test_bits];

            // Test that the range-checked result was correctly computed from the intermediate result.
            assert_eq!(
                wr_test_v - pine.flp.wr_test_bound + Field128::one(),
                wr_test_result
            );

            // Test that the success bit is well-formed.
            assert!(wr_test_g == Field128::one() || wr_test_g == Field128::zero());
        }
    }

    impl<F: FftFriendlyFieldElement> Pine<F, XofTurboShake128, 16> {
        fn run_valid_test_case(&self, gradient: impl Iterator<Item = f64>) {
            let (mut input, wr_test_results) = self
                .flp
                .encode_with_wr_joint_rand::<XofTurboShake128, 16>(
                    gradient,
                    &Seed::generate().unwrap(),
                )
                .unwrap();
            input.extend_from_slice(&wr_test_results);

            FlpTest::expect_valid_no_output::<2>(&self.flp, &input);
            FlpTest::expect_valid_no_output::<3>(&self.flp_sq_norm_equal, &input);
        }
    }

    #[test]
    fn valid() {
        const DIM: usize = 1000;
        let norm_bound = norm_bound_f64_to_u64(1000.0, 15);
        let pine = Pine::new_128(norm_bound, DIM, 15, 27, 100).unwrap();
        pine.run_valid_test_case((0..DIM).map(|i| i as f64 * 0.01));
    }

    #[test]
    fn valid_small_dimension() {
        const DIM: usize = 1;
        let norm_bound = norm_bound_f64_to_u64(1.0, 15);
        let pine = Pine::new_128(norm_bound, DIM, 15, 4, 1).unwrap();
        pine.run_valid_test_case([0.75].into_iter());
    }

    #[test]
    fn valid_negative_values() {
        const DIM: usize = 1337;
        let norm_bound = norm_bound_f64_to_u64(1000.0, 15);
        let pine = Pine::new_128(norm_bound, DIM, 15, 4, 30).unwrap();
        pine.run_valid_test_case((0..DIM).map(|i| i as f64 * -0.01));
    }

    #[test]
    fn valid_random_values() {
        const DIM: usize = 1000;
        let norm_bound = norm_bound_f64_to_u64(100.0, 15);
        let pine = Pine::new_128(norm_bound, DIM, 15, 4, 99).unwrap();
        let mut rng = thread_rng();
        pine.run_valid_test_case(iter::repeat_with(|| rng.gen_range(-0.1..0.1)).take(DIM));
    }

    #[test]
    fn invalid_mutated_gradient() {
        const DIM: usize = 10;
        let norm_bound = norm_bound_f64_to_u64(100.0, 15);
        let pine = Pine::new_128(norm_bound, DIM, 15, 4, 5).unwrap();
        let (mut input, wr_test_results) = pine
            .flp
            .encode_with_wr_joint_rand::<XofTurboShake128, 16>(
                [0.0; DIM].into_iter(),
                &Seed::generate().unwrap(),
            )
            .unwrap();
        input.extend_from_slice(&wr_test_results);

        // Tweak the last coordinate of the gradient.
        input[DIM - 1] += Field128::from(1);

        FlpTest::expect_invalid::<2>(
            &pine.flp_sq_norm_equal,
            &input[..pine.flp_sq_norm_equal.input_len()],
        );
    }

    #[test]
    fn invalid_mutated_sq_norm() {
        const DIM: usize = 10;
        let norm_bound = norm_bound_f64_to_u64(100.0, 15);
        let pine = Pine::new_128(norm_bound, DIM, 15, 4, 5).unwrap();
        let (mut input, wr_test_results) = pine
            .flp
            .encode_with_wr_joint_rand::<XofTurboShake128, 16>(
                [0.0; DIM].into_iter(),
                &Seed::generate().unwrap(),
            )
            .unwrap();
        input.extend_from_slice(&wr_test_results);

        // Flip the first bit of the range-checked squared norm.
        input[DIM] = if input[DIM] == Field128::one() {
            Field128::zero()
        } else {
            Field128::one()
        };

        FlpTest::expect_invalid::<2>(&pine.flp, &input);
    }

    #[test]
    fn invalid_mutated_wr_result() {
        const DIM: usize = 10;
        let norm_bound = norm_bound_f64_to_u64(100.0, 15);
        let pine = Pine::new_128(norm_bound, DIM, 15, 4, 5).unwrap();
        let (mut input, wr_test_results) = pine
            .flp
            .encode_with_wr_joint_rand::<XofTurboShake128, 16>(
                [0.0; DIM].into_iter(),
                &Seed::generate().unwrap(),
            )
            .unwrap();
        input.extend_from_slice(&wr_test_results);

        // Flip the first bit of the first wraparound result.
        let i = pine.flp.dimension + (2 * pine.flp.sq_norm_bits);
        input[i] = if input[i] == Field128::one() {
            Field128::zero()
        } else {
            Field128::one()
        };

        FlpTest::expect_invalid::<2>(&pine.flp, &input);
    }

    #[test]
    fn invalid_mutated_success_bit() {
        const DIM: usize = 10;
        let norm_bound = norm_bound_f64_to_u64(100.0, 15);
        let pine = Pine::new_128(norm_bound, DIM, 15, 4, 5).unwrap();
        let (mut input, wr_test_results) = pine
            .flp
            .encode_with_wr_joint_rand::<XofTurboShake128, 16>(
                [0.0; DIM].into_iter(),
                &Seed::generate().unwrap(),
            )
            .unwrap();
        input.extend_from_slice(&wr_test_results);

        // Flip the first wraparound result success bit.
        let i = pine.flp.dimension + (2 * pine.flp.sq_norm_bits) + pine.flp.wr_test_bits;
        input[i] = if input[i] == Field128::one() {
            Field128::zero()
        } else {
            Field128::one()
        };

        FlpTest::expect_invalid::<2>(&pine.flp, &input);
    }

    #[test]
    fn invalid_dot_prod_mismatch() {
        const DIM: usize = 10;
        let norm_bound = norm_bound_f64_to_u64(100.0, 15);
        let pine = Pine::new_128(norm_bound, DIM, 15, 4, 5).unwrap();
        let (mut input, wr_test_results) = pine
            .flp
            .encode_with_wr_joint_rand::<XofTurboShake128, 16>(
                [0.1; DIM].into_iter(),
                &Seed::generate().unwrap(),
            )
            .unwrap();
        let i = input.len();
        input.extend_from_slice(&wr_test_results);

        // Garble several dot products so that they don't match the range-checked version.
        for x in &mut input[i..] {
            *x *= Field128::from(1337);
        }

        FlpTest::expect_invalid::<2>(&pine.flp, &input);
    }
}
