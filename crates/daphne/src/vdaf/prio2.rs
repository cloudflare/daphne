// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Prio2, the Prio-based construction used in ENPA. This is not a standard
//! [VDAF](https://datatracker.ietf.org/doc/draft-patton-cfrg-vdaf/).

use crate::{
    fatal_error, vdaf::VdafError, DapAggregateResult, DapMeasurement, VdafAggregateShare,
    VdafPrepShare, VdafPrepState, VdafVerifyKey,
};
use prio::{
    codec::{Decode, Encode, ParameterizedDecode},
    field::FieldPrio2,
    vdaf::{
        prio2::{Prio2, Prio2PrepareShare},
        AggregateShare, Aggregator, Client, Collector, PrepareTransition, Share, Vdaf,
    },
};

/// Split the given measurement into a sequence of encoded input shares.
pub(crate) fn prio2_shard(
    dimension: usize,
    measurement: DapMeasurement,
    nonce: &[u8; 16],
) -> Result<(Vec<u8>, [Vec<u8>; 2]), VdafError> {
    let vdaf = Prio2::new(dimension).map_err(|e| {
        VdafError::Dap(fatal_error!(err = ?e, "failed to create prio2 from {dimension}"))
    })?;
    let (public_share, input_shares) = match measurement {
        DapMeasurement::U32Vec(ref data) => vdaf.shard(data, nonce)?,
        _ => {
            return Err(VdafError::Dap(fatal_error!(
                err = "prio2_shard: unexpected measurement type"
            )))
        }
    };

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

/// Consume an input share and return the corresponding prep state and share.
pub(crate) fn prio2_prep_init(
    dimension: usize,
    verify_key: &VdafVerifyKey,
    agg_id: usize,
    nonce: &[u8; 16],
    public_share_data: &[u8],
    input_share_data: &[u8],
) -> Result<(VdafPrepState, VdafPrepShare), VdafError> {
    let VdafVerifyKey::L32(verify_key) = verify_key else {
        return Err(VdafError::Dap(fatal_error!(
            err = "unhandled verify key type"
        )));
    };

    let vdaf = Prio2::new(dimension).map_err(|e| {
        VdafError::Dap(fatal_error!(err = ?e, "failed to create prio2 from {dimension}"))
    })?;
    <()>::get_decoded_with_param(&vdaf, public_share_data)?;
    let input_share: Share<FieldPrio2, 32> =
        Share::get_decoded_with_param(&(&vdaf, agg_id), input_share_data)?;
    let (state, share) = vdaf.prepare_init(verify_key, agg_id, &(), nonce, &(), &input_share)?;
    Ok((VdafPrepState::Prio2(state), VdafPrepShare::Prio2(share)))
}

/// Consume the prep shares and return our output share.
pub(crate) fn prio2_prep_finish_from_shares(
    dimension: usize,
    host_state: VdafPrepState,
    host_share: VdafPrepShare,
    peer_share_data: &[u8],
) -> Result<(VdafAggregateShare, Vec<u8>), VdafError> {
    let vdaf = Prio2::new(dimension).map_err(|e| {
        VdafError::Dap(fatal_error!(err = ?e, "failed to create prio2 from {dimension}"))
    })?;
    let (out_share, outbound) = match (host_state, host_share) {
        (VdafPrepState::Prio2(state), VdafPrepShare::Prio2(share)) => {
            let peer_share = Prio2PrepareShare::get_decoded_with_param(&state, peer_share_data)?;
            vdaf.prepare_shares_to_prepare_message(&(), [share, peer_share])?;
            match vdaf.prepare_next(state, ())? {
                PrepareTransition::Continue(..) => {
                    return Err(VdafError::Dap(fatal_error!(
                        err = "prio2_prep_finish_from_shares: unexpected transition (continued)",
                    )))
                }
                PrepareTransition::Finish(out_share) => (out_share, Vec::new()),
            }
        }
        _ => {
            return Err(VdafError::Dap(fatal_error!(
                err = "prio2_prep_finish_from_shares: host state does not match share",
            )))
        }
    };
    let agg_share = VdafAggregateShare::Field32(vdaf.aggregate(&(), [out_share])?);
    Ok((agg_share, outbound))
}

/// Consume the prep message and return our output share.
pub(crate) fn prio2_prep_finish(
    dimension: usize,
    host_state: VdafPrepState,
    peer_message_data: &[u8],
) -> Result<VdafAggregateShare, VdafError> {
    let vdaf = Prio2::new(dimension).map_err(|e| {
        VdafError::Dap(fatal_error!(err = ?e, "failed to create prio2 from {dimension}"))
    })?;
    <()>::get_decoded(peer_message_data)?;
    let out_share = match host_state {
        VdafPrepState::Prio2(state) => match vdaf.prepare_next(state, ())? {
            PrepareTransition::Continue(..) => {
                return Err(VdafError::Dap(fatal_error!(
                    err = "prio2_prep_finish: unexpected transition (continued)",
                )))
            }
            PrepareTransition::Finish(out_share) => out_share,
        },
        _ => {
            return Err(VdafError::Dap(fatal_error!(
                err = "prio2_prep_finish: unexpected state type"
            )))
        }
    };
    let agg_share = VdafAggregateShare::Field32(vdaf.aggregate(&(), [out_share])?);
    Ok(agg_share)
}

/// Interpret `encoded_agg_shares` as a sequence of encoded aggregate shares and unshard them.
pub(crate) fn prio2_unshard<M: IntoIterator<Item = Vec<u8>>>(
    dimension: usize,
    num_measurements: usize,
    encoded_agg_shares: M,
) -> Result<DapAggregateResult, VdafError> {
    let vdaf = Prio2::new(dimension).map_err(|e| {
        VdafError::Dap(fatal_error!(err = ?e, "failed to create prio2 from {dimension}"))
    })?;
    let mut agg_shares = Vec::with_capacity(vdaf.num_aggregators());
    for encoded in encoded_agg_shares {
        let agg_share = AggregateShare::get_decoded_with_param(&(&vdaf, &()), encoded.as_ref())?;
        agg_shares.push(agg_share);
    }
    let agg_res = vdaf.unshard(&(), agg_shares, num_measurements)?;
    Ok(DapAggregateResult::U32Vec(agg_res))
}

#[cfg(test)]
mod test {
    use crate::{
        hpke::HpkeKemId, test_versions, testing::AggregationJobTest, vdaf::VdafConfig,
        DapAggregateResult, DapAggregationParam, DapMeasurement, DapVersion,
    };

    fn roundtrip(version: DapVersion) {
        let mut t = AggregationJobTest::new(
            &VdafConfig::Prio2 { dimension: 5 },
            HpkeKemId::X25519HkdfSha256,
            version,
        );
        let got = t.roundtrip(
            DapAggregationParam::Empty,
            vec![
                DapMeasurement::U32Vec(vec![1, 1, 0, 0, 1]),
                DapMeasurement::U32Vec(vec![1, 1, 0, 0, 1]),
                DapMeasurement::U32Vec(vec![1, 0, 0, 0, 1]),
                DapMeasurement::U32Vec(vec![0, 1, 0, 0, 1]),
                DapMeasurement::U32Vec(vec![0, 0, 1, 0, 1]),
            ],
        );
        assert_eq!(got, DapAggregateResult::U32Vec(vec![3, 3, 1, 0, 5]));
    }

    test_versions! { roundtrip }
}
