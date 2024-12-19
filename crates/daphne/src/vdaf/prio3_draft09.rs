// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Parameters for the [Prio3 VDAF](https://datatracker.ietf.org/doc/draft-irtf-cfrg-vdaf/09/).

use crate::{
    fatal_error, messages::taskprov::VDAF_TYPE_PRIO3_SUM_VEC_FIELD64_MULTIPROOF_HMAC_SHA256_AES128,
    vdaf::VdafError,
};

use prio_draft09::{
    codec::ParameterizedDecode,
    field::Field64,
    flp::{
        gadgets::{Mul, ParallelSum},
        types::SumVec,
        Type,
    },
    vdaf::{
        prio3::{Prio3, Prio3InputShare, Prio3PrepareShare, Prio3PrepareState, Prio3PublicShare},
        xof::{Xof, XofHmacSha256Aes128},
        Aggregator,
    },
};

type Prio3SumVecField64MultiproofHmacSha256Aes128 =
    Prio3<SumVec<Field64, ParallelSum<Field64, Mul<Field64>>>, XofHmacSha256Aes128, 32>;

pub(crate) fn new_prio3_sum_vec_field64_multiproof_hmac_sha256_aes128(
    bits: usize,
    length: usize,
    chunk_length: usize,
    num_proofs: u8,
) -> Result<Prio3SumVecField64MultiproofHmacSha256Aes128, VdafError> {
    Prio3::new(
        2,
        num_proofs,
        VDAF_TYPE_PRIO3_SUM_VEC_FIELD64_MULTIPROOF_HMAC_SHA256_AES128,
        SumVec::new(bits, length, chunk_length).map_err(|e| {
            VdafError::Dap(fatal_error!(
                err = ?e,
                "failed to create sum vec from bits({bits}), length({length}), chunk_length({chunk_length})"
            ))
        })?,
    )
    .map_err(|e| VdafError::Dap(fatal_error!(err = ?e, "failed to create prio3")))
}

type Prio3Draft09Prepared<T, const SEED_SIZE: usize> = (
    Prio3PrepareState<<T as Type>::Field, SEED_SIZE>,
    Prio3PrepareShare<<T as Type>::Field, SEED_SIZE>,
);

pub(crate) fn prep_init_draft09<T, P, const SEED_SIZE: usize>(
    vdaf: Prio3<T, P, SEED_SIZE>,
    verify_key: &[u8; SEED_SIZE],
    agg_id: usize,
    nonce: &[u8; 16],
    public_share_data: &[u8],
    input_share_data: &[u8],
) -> Result<Prio3Draft09Prepared<T, SEED_SIZE>, VdafError>
where
    T: Type,
    P: Xof<SEED_SIZE>,
{
    // Parse the public share.
    let public_share = Prio3PublicShare::get_decoded_with_param(&vdaf, public_share_data)?;

    // Parse the input share.
    let input_share = Prio3InputShare::get_decoded_with_param(&(&vdaf, agg_id), input_share_data)?;

    // Run the prepare-init algorithm, returning the initial state.
    Ok(vdaf.prepare_init(verify_key, agg_id, &(), nonce, &public_share, &input_share)?)
}

#[cfg(test)]
mod test {

    use prio_draft09::vdaf::prio3_test::check_test_vec;

    use crate::{
        hpke::HpkeKemId,
        testing::AggregationJobTest,
        vdaf::{
            prio3_draft09::new_prio3_sum_vec_field64_multiproof_hmac_sha256_aes128, Prio3Config,
            VdafConfig,
        },
        DapAggregateResult, DapAggregationParam, DapMeasurement, DapVersion,
    };

    #[test]
    fn roundtrip_sum_vec_field64_multiproof_hmac_sha256_aes128_draft09() {
        let mut t = AggregationJobTest::new(
            &VdafConfig::Prio3(
                Prio3Config::Draft09SumVecField64MultiproofHmacSha256Aes128 {
                    bits: 23,
                    length: 2,
                    chunk_length: 1,
                    num_proofs: 4,
                },
            ),
            HpkeKemId::X25519HkdfSha256,
            DapVersion::Draft09,
        );
        let got = t.roundtrip(
            DapAggregationParam::Empty,
            vec![
                DapMeasurement::U64Vec(vec![1337, 0]),
                DapMeasurement::U64Vec(vec![0, 1337]),
                DapMeasurement::U64Vec(vec![1, 1]),
            ],
        );
        assert_eq!(got, DapAggregateResult::U64Vec(vec![1338, 1338]));
    }

    #[test]
    fn test_vec_sum_vec_field64_multiproof_hmac_sha256_aes128() {
        for test_vec_json_str in [
            include_str!("test_vec/Prio3SumVecField64MultiproofHmacSha256Aes128_0.json"),
            include_str!("test_vec/Prio3SumVecField64MultiproofHmacSha256Aes128_1.json"),
            include_str!("test_vec/Prio3SumVecField64MultiproofHmacSha256Aes128_2.json"),
        ] {
            check_test_vec(test_vec_json_str, |json_params, num_aggregators| {
                assert_eq!(num_aggregators, 2);
                new_prio3_sum_vec_field64_multiproof_hmac_sha256_aes128(
                    json_params["bits"].as_u64().unwrap().try_into().unwrap(),
                    json_params["length"].as_u64().unwrap().try_into().unwrap(),
                    json_params["chunk_length"]
                        .as_u64()
                        .unwrap()
                        .try_into()
                        .unwrap(),
                    json_params["proofs"].as_u64().unwrap().try_into().unwrap(),
                )
                .unwrap()
            });
        }
    }
}
