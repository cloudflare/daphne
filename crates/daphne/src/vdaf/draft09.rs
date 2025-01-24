// Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! DAP-09 compatibility.

use crate::{
    fatal_error, messages::taskprov::VDAF_TYPE_PRIO3_SUM_VEC_FIELD64_MULTIPROOF_HMAC_SHA256_AES128,
    vdaf::VdafError,
};

use prio_draft09::{
    codec::{Encode, ParameterizedDecode},
    field::Field64,
    flp::{
        gadgets::{Mul, ParallelSum},
        types::SumVec,
        Type,
    },
    vdaf::{
        prio3::{Prio3, Prio3InputShare, Prio3PrepareShare, Prio3PrepareState, Prio3PublicShare},
        xof::{Xof, XofHmacSha256Aes128},
        Aggregator, Client, Collector, PrepareTransition, Vdaf,
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

pub(crate) fn shard_then_encode<V: Vdaf + Client<16>>(
    vdaf: &V,
    measurement: &V::Measurement,
    nonce: &[u8; 16],
) -> Result<(Vec<u8>, [Vec<u8>; 2]), VdafError> {
    let (public_share, input_shares) = vdaf.shard(measurement, nonce)?;

    Ok((
        public_share.get_encoded()?,
        input_shares
            .iter()
            .map(|input_share| input_share.get_encoded())
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            .map_err(|e: Vec<_>| {
                VdafError::Dap(fatal_error!(
                    err = format!("expected 2 input shares got {}", e.len())
                ))
            })?,
    ))
}

pub(crate) fn prep_init<T, P, const SEED_SIZE: usize>(
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

pub(crate) fn prep_finish_from_shares<V, const VERIFY_KEY_SIZE: usize, const NONCE_SIZE: usize>(
    vdaf: &V,
    host_state: V::PrepareState,
    host_share: V::PrepareShare,
    peer_share_data: &[u8],
) -> Result<(V::OutputShare, Vec<u8>), VdafError>
where
    V: Vdaf<AggregationParam = ()> + Aggregator<VERIFY_KEY_SIZE, NONCE_SIZE>,
{
    // Decode the peer's inbound message.
    let peer_share = V::PrepareShare::get_decoded_with_param(&host_state, peer_share_data)?;

    // Preprocess the inbound messages.
    let message = vdaf.prepare_shares_to_prepare_message(&(), [peer_share, host_share])?;
    let message_data = message.get_encoded()?;

    // Compute the host's output share.
    match vdaf.prepare_next(host_state, message)? {
        PrepareTransition::Continue(..) => Err(VdafError::Dap(fatal_error!(
            err = format!("prep_finish_from_shares: unexpected transition")
        ))),
        PrepareTransition::Finish(out_share) => Ok((out_share, message_data)),
    }
}

pub(crate) fn prep_finish<V, const VERIFY_KEY_SIZE: usize, const NONCE_SIZE: usize>(
    vdaf: &V,
    host_state: V::PrepareState,
    peer_message_data: &[u8],
) -> Result<V::OutputShare, VdafError>
where
    V: Vdaf + Aggregator<VERIFY_KEY_SIZE, NONCE_SIZE>,
{
    // Decode the inbound message from the peer, which contains the preprocessed prepare message.
    let peer_message = V::PrepareMessage::get_decoded_with_param(&host_state, peer_message_data)?;

    // Compute the host's output share.
    match vdaf.prepare_next(host_state, peer_message)? {
        PrepareTransition::Continue(..) => Err(VdafError::Dap(fatal_error!(
            err = format!("prep_finish: unexpected transition"),
        ))),
        PrepareTransition::Finish(out_share) => Ok(out_share),
    }
}

pub(crate) fn unshard<V, M>(
    vdaf: &V,
    num_measurements: usize,
    agg_shares: M,
) -> Result<V::AggregateResult, VdafError>
where
    V: Vdaf<AggregationParam = ()> + Collector,
    M: IntoIterator<Item = Vec<u8>>,
{
    let mut agg_shares_vec = Vec::with_capacity(vdaf.num_aggregators());
    for data in agg_shares {
        let agg_share = V::AggregateShare::get_decoded_with_param(&(vdaf, &()), data.as_ref())?;
        agg_shares_vec.push(agg_share);
    }
    Ok(vdaf.unshard(&(), agg_shares_vec, num_measurements)?)
}

#[cfg(test)]
mod test {

    use prio_draft09::vdaf::prio3_test::check_test_vec;

    use super::*;

    use crate::{
        hpke::HpkeKemId,
        testing::AggregationJobTest,
        vdaf::{Prio3Config, VdafConfig},
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
    fn test_vec_sum_vec_field64_multiproof_hmac_sha256_aes128_draft09() {
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
