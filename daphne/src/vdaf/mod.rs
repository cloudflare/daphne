// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Verifiable, Distributed Aggregation Functions
//! ([VDAFs](https://datatracker.ietf.org/doc/draft-irtf-cfrg-vdaf/)).

use crate::{
    hpke::HpkeDecrypter,
    messages::{
        AggregateContinueReq, AggregateInitializeReq, AggregateResp, BatchParameter, BatchSelector,
        HpkeCiphertext, HpkeConfig, Id, Nonce, Report, ReportMetadata, ReportShare, Time,
        Transition, TransitionFailure, TransitionVar,
    },
    vdaf::{
        prio2::{
            prio2_encode_prepare_message, prio2_helper_prepare_finish, prio2_leader_prepare_finish,
            prio2_prepare_init, prio2_shard, prio2_unshard,
        },
        prio3::{
            prio3_encode_prepare_message, prio3_helper_prepare_finish, prio3_leader_prepare_finish,
            prio3_prepare_init, prio3_shard, prio3_unshard,
        },
    },
    DapAbort, DapAggregateResult, DapAggregateShare, DapError, DapHelperState, DapHelperTransition,
    DapLeaderState, DapLeaderTransition, DapLeaderUncommitted, DapMeasurement, DapOutputShare,
    VdafConfig,
};
use prio::{
    codec::{CodecError, Encode},
    field::{Field128, Field64, FieldPrio2},
    vdaf::{
        prio2::{Prio2PrepareShare, Prio2PrepareState},
        prio3::{Prio3PrepareShare, Prio3PrepareState},
    },
};
use rand::prelude::*;
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, convert::TryInto};

const CTX_INPUT_SHARE: &[u8] = b"dap-01 input share";
const CTX_AGG_SHARE: &[u8] = b"dap-01 aggregate share";
const CTX_ROLE_COLLECTOR: u8 = 0;
const CTX_ROLE_CLIENT: u8 = 1;
const CTX_ROLE_LEADER: u8 = 2;
const CTX_ROLE_HELPER: u8 = 3;

#[derive(Debug, thiserror::Error)]
pub(crate) enum VdafError {
    #[error("{0}")]
    Codec(#[from] CodecError),
    #[error("{0}")]
    Vdaf(#[from] prio::vdaf::VdafError),
}

#[derive(Clone)]
pub(crate) enum VdafVerifyKey {
    Prio3([u8; 16]),
    Prio2([u8; 32]),
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum VdafState {
    Prio2(Prio2PrepareState),
    Prio3Field64(Prio3PrepareState<Field64, 16>),
    Prio3Field128(Prio3PrepareState<Field128, 16>),
}

#[derive(Clone, Debug)]
pub(crate) enum VdafMessage {
    Prio2Share(Prio2PrepareShare),
    Prio3ShareField64(Prio3PrepareShare<Field64, 16>),
    Prio3ShareField128(Prio3PrepareShare<Field128, 16>),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) enum VdafAggregateShare {
    Field64(prio::vdaf::AggregateShare<Field64>),
    Field128(prio::vdaf::AggregateShare<Field128>),
    FieldPrio2(prio::vdaf::AggregateShare<FieldPrio2>),
}

impl Encode for VdafAggregateShare {
    fn encode(&self, bytes: &mut Vec<u8>) {
        match self {
            VdafAggregateShare::Field64(agg_share) => bytes.append(&mut agg_share.into()),
            VdafAggregateShare::Field128(agg_share) => bytes.append(&mut agg_share.into()),
            VdafAggregateShare::FieldPrio2(agg_share) => bytes.append(&mut agg_share.into()),
        }
    }
}

impl VdafConfig {
    pub(crate) fn get_decoded_verify_key(&self, bytes: &[u8]) -> Result<VdafVerifyKey, DapError> {
        match self {
            Self::Prio3(..) => Ok(VdafVerifyKey::Prio3(
                <[u8; 16]>::try_from(bytes).map_err(|e| CodecError::Other(Box::new(e)))?,
            )),
            Self::Prio2 { .. } => Ok(VdafVerifyKey::Prio2(
                <[u8; 32]>::try_from(bytes).map_err(|e| CodecError::Other(Box::new(e)))?,
            )),
        }
    }

    /// Checks if the provided aggregation parameter is valid for the underling VDAF being
    /// executed.
    pub fn is_valid_agg_param(&self, agg_param: &[u8]) -> bool {
        match self {
            Self::Prio3(..) | Self::Prio2 { .. } => agg_param.is_empty(),
        }
    }

    /// Generate the Aggregators' shared verification parameters.
    #[cfg(test)]
    pub(crate) fn gen_verify_key(&self) -> VdafVerifyKey {
        let mut rng = thread_rng();
        match self {
            Self::Prio3(..) => VdafVerifyKey::Prio3(rng.gen()),
            Self::Prio2 { .. } => VdafVerifyKey::Prio2(rng.gen()),
        }
    }

    /// Generate a report for a measurement. This method is run by the Client.
    ///
    /// # Inputs
    ///
    /// * `hpke_config_list` is the sequence of HPKE configs, the first belonging to the Leader and the
    /// remainder belonging to the Helpers. Note that the current draft only supports one Helper,
    /// so this method will return an error if `hpke_config_list.len() != 2`.
    ///
    /// * `now` is the number of seconds since the UNIX epoch. It is the caller's responsibility to
    /// ensure this value is truncated to the nearest `min_batch_duration`, as required by the
    /// spec.
    ///
    /// * `task_id` is the DAP task for which this report is being generated.
    ///
    /// * `measurement` is the measurement.
    //
    // TODO spec: Decide if truncating the timestamp should be a MAY or SHOULD.
    pub fn produce_report(
        &self,
        hpke_config_list: &[HpkeConfig],
        time: Time,
        task_id: &Id,
        measurement: DapMeasurement,
    ) -> Result<Report, DapError> {
        let mut rng = thread_rng();
        let metadata = ReportMetadata {
            nonce: Nonce(rng.gen()),
            time,
            extensions: Vec::new(),
        };

        let encoded_input_shares = match self {
            Self::Prio3(prio3_config) => prio3_shard(prio3_config, measurement)?,
            Self::Prio2 { dimension } => prio2_shard(*dimension, measurement)?,
        };

        if hpke_config_list.len() != encoded_input_shares.len() {
            return Err(DapError::Fatal("unexpected number of HPKE configs".into()));
        }

        const N: usize = CTX_INPUT_SHARE.len();
        let mut info = [0; N + 2];
        info[..N].copy_from_slice(CTX_INPUT_SHARE);
        info[N] = CTX_ROLE_CLIENT; // Sender role (receiver role set below)

        let mut aad = Vec::with_capacity(58);
        task_id.encode(&mut aad);
        metadata.encode(&mut aad);

        let mut encrypted_input_shares = Vec::with_capacity(encoded_input_shares.len());
        for (i, (hpke_config, input_share_data)) in hpke_config_list
            .iter()
            .zip(encoded_input_shares)
            .enumerate()
        {
            info[N + 1] = if i == 0 {
                CTX_ROLE_LEADER
            } else {
                CTX_ROLE_HELPER
            }; // Receiver role
            let (enc, payload) = hpke_config.encrypt(&info, &aad, &input_share_data)?;

            encrypted_input_shares.push(HpkeCiphertext {
                config_id: hpke_config.id,
                enc,
                payload,
            });
        }

        Ok(Report {
            task_id: task_id.clone(),
            metadata,
            encrypted_input_shares,
        })
    }

    /// Consume an encrypted input share sent in a report by the Client and return the Prepare
    /// step. This is run by an Aggregator.
    ///
    /// # Inputs
    ///
    /// * `decryptor` is used to decrypt the input share.
    ///
    /// * `verify_key` is the secret VDAF verification key shared by the Aggregators.
    ///
    /// * `task_id` is the DAP task ID indicated by the report.
    ///
    /// * `nonce` is the report nonce.
    ///
    /// * `encrypted_input_share` is the encrypted input share.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn consume_report_share(
        &self,
        decrypter: &impl HpkeDecrypter<'_>,
        is_leader: bool,
        verify_key: &VdafVerifyKey,
        task_id: &Id,
        metadata: &ReportMetadata,
        encrypted_input_share: &HpkeCiphertext,
    ) -> Result<(VdafState, VdafMessage), DapError> {
        const N: usize = CTX_INPUT_SHARE.len();
        let mut info = [0; N + 2];
        info[..N].copy_from_slice(CTX_INPUT_SHARE);
        info[N] = CTX_ROLE_CLIENT; // Sender role
        info[N + 1] = if is_leader {
            CTX_ROLE_LEADER
        } else {
            CTX_ROLE_HELPER
        }; // Receiver role

        let mut aad = Vec::with_capacity(58);
        task_id.encode(&mut aad);
        metadata.encode(&mut aad);

        let input_share_data = decrypter
            .hpke_decrypt(task_id, &info, &aad, encrypted_input_share)
            .await?;

        let agg_id = if is_leader { 0 } else { 1 };
        match (self, verify_key) {
            (Self::Prio3(ref prio3_config), VdafVerifyKey::Prio3(ref verify_key)) => {
                Ok(prio3_prepare_init(
                    prio3_config,
                    verify_key,
                    agg_id,
                    metadata.nonce.as_ref(),
                    &input_share_data,
                )?)
            }
            (Self::Prio2 { dimension }, VdafVerifyKey::Prio2(ref verify_key)) => {
                Ok(prio2_prepare_init(
                    *dimension,
                    verify_key,
                    agg_id,
                    metadata.nonce.as_ref(),
                    &input_share_data,
                )?)
            }
            _ => Err(DapError::fatal("VDAF verify key does not match config")),
        }
    }

    /// Initialize the aggregation flow for a sequence of reports. The outputs are the Leader's
    /// state for the aggregation flow and the initial aggregate request to be sent to the Helper.
    /// This method is called by the Leader.
    ///
    /// Note: This method does not compute the message authentication tag. It is up to the caller
    /// to do so.
    ///
    /// # inputs
    ///
    /// * `decrypter` is used to decrypt the Leader's report shares.
    ///
    /// * `verify_key` is the secret VDAF verification key shared by the Aggregators.
    ///
    /// * `task_id` indicates the DAP task for which the set of reports are being aggregated.
    ///
    /// * `reports` is the set of reports uploaded by Clients.
    pub(crate) async fn produce_agg_init_req(
        &self,
        decrypter: &impl HpkeDecrypter<'_>,
        verify_key: &VdafVerifyKey,
        task_id: &Id,
        agg_job_id: &Id,
        reports: Vec<Report>,
    ) -> Result<DapLeaderTransition<AggregateInitializeReq>, DapAbort> {
        let mut processed = HashSet::with_capacity(reports.len());
        let mut states = Vec::with_capacity(reports.len());
        let mut seq = Vec::with_capacity(reports.len());
        for report in reports.into_iter() {
            if processed.contains(&report.metadata.nonce) {
                return Err(DapError::fatal(
                    "tried to process report sequence with non-unique nonces",
                )
                .into());
            }
            processed.insert(report.metadata.nonce.clone());

            if &report.task_id != task_id || report.encrypted_input_shares.len() != 2 {
                return Err(
                    DapError::fatal("tried to process report with incorrect task ID").into(),
                );
            }

            let (leader_share, helper_share) = {
                let mut it = report.encrypted_input_shares.into_iter();
                (it.next().unwrap(), it.next().unwrap())
            };

            match self
                .consume_report_share(
                    decrypter,
                    true, // is_leader
                    verify_key,
                    task_id,
                    &report.metadata,
                    &leader_share,
                )
                .await
            {
                Ok((step, message)) => {
                    states.push((
                        step,
                        message,
                        report.metadata.time,
                        report.metadata.nonce.clone(),
                    ));
                    seq.push(ReportShare {
                        metadata: report.metadata,
                        encrypted_input_share: helper_share,
                    });
                }

                // Skip report that can't be processed any further.
                //
                // TODO Emit metric for failure reason
                Err(DapError::Transition(..)) => (),

                Err(e) => return Err(DapAbort::Internal(Box::new(e))),
            };
        }

        if seq.is_empty() {
            return Ok(DapLeaderTransition::Skip);
        }

        Ok(DapLeaderTransition::Continue(
            DapLeaderState { seq: states },
            AggregateInitializeReq {
                task_id: task_id.clone(),
                agg_job_id: agg_job_id.clone(),
                agg_param: Vec::default(),
                batch_param: BatchParameter::TimeInterval,
                report_shares: seq,
            },
        ))
    }

    /// Consume an initial aggregate request from the Leader. The outputs are the Helper's state
    /// for the aggregation flow and the aggregate response to send to the Leader.  This method is
    /// run by the Helper.
    ///
    /// Note: The helper state parameter of the aggregate response is left empty. The caller may
    /// wish to encrypt the state and insert it into the aggregate response structure.
    ///
    /// Note: This method does not compute the message authentication tag. It is up to the caller
    /// to do so.
    ///
    /// # Inputs
    ///
    /// * `decrypter` is used to decrypt the Helper's report shares.
    ///
    /// * `verify_key` is the secret VDAF verification key shared by the Aggregators.
    ///
    /// * `task_id` indicates the DAP task for which the reports are being processed.
    ///
    /// * `agg_init_req` is the request sent by the Leader.
    ///
    /// * `early_rejects` is a tableindicating the set of reports in `agg_init_req` that the Helper
    /// knows in advance it must reject. Each key is the report's nonce and the corresponding value
    /// is the transition failure the Helper is to transmit.
    pub(crate) async fn handle_agg_init_req(
        &self,
        decrypter: &impl HpkeDecrypter<'_>,
        verify_key: &VdafVerifyKey,
        agg_init_req: &AggregateInitializeReq,
    ) -> Result<DapHelperTransition<AggregateResp>, DapAbort> {
        let num_reports = agg_init_req.report_shares.len();
        let mut processed = HashSet::with_capacity(num_reports);
        let mut states = Vec::with_capacity(num_reports);
        let mut transitions = Vec::with_capacity(num_reports);
        for report_share in agg_init_req.report_shares.iter() {
            if processed.contains(&report_share.metadata.nonce) {
                return Err(DapAbort::UnrecognizedMessage);
            }
            processed.insert(report_share.metadata.nonce.clone());

            let var = match self
                .consume_report_share(
                    decrypter,
                    false, // is_leader
                    verify_key,
                    &agg_init_req.task_id,
                    &report_share.metadata,
                    &report_share.encrypted_input_share,
                )
                .await
            {
                Ok((step, message)) => {
                    let message_data = match self {
                        Self::Prio3(..) => prio3_encode_prepare_message(&message),
                        Self::Prio2 { .. } => prio2_encode_prepare_message(&message),
                    };
                    states.push((
                        step,
                        report_share.metadata.time,
                        report_share.metadata.nonce.clone(),
                    ));
                    TransitionVar::Continued(message_data)
                }

                Err(DapError::Transition(failure_reason)) => TransitionVar::Failed(failure_reason),

                Err(e) => return Err(DapAbort::Internal(Box::new(e))),
            };

            transitions.push(Transition {
                nonce: report_share.metadata.nonce.clone(),
                var,
            });
        }

        Ok(DapHelperTransition::Continue(
            DapHelperState { seq: states },
            AggregateResp { transitions },
        ))
    }

    /// Handle an aggregate response from the Helper. This method is run by the Leader.
    ///
    /// Note: This method does not compute the message authentication tag. It is up to the caller
    /// to do so.
    ///
    /// # Inputs
    ///
    /// * `task_id` is the DAP task for which the reports are being aggregated.
    ///
    /// * `state` is the Leader's current state.
    ///
    /// * `agg_resp` is the previous aggregate response sent by the Helper.
    pub(crate) fn handle_agg_resp(
        &self,
        task_id: &Id,
        agg_job_id: &Id,
        state: DapLeaderState,
        agg_resp: AggregateResp,
    ) -> Result<DapLeaderTransition<AggregateContinueReq>, DapAbort> {
        if agg_resp.transitions.len() != state.seq.len() {
            return Err(DapAbort::UnrecognizedMessage);
        }

        let mut seq = Vec::with_capacity(state.seq.len());
        let mut states = Vec::with_capacity(state.seq.len());
        for (helper, (leader_step, leader_message, leader_time, leader_nonce)) in
            agg_resp.transitions.into_iter().zip(state.seq.into_iter())
        {
            // TODO spec: Consider removing the nonce from the AggregateResp.
            if helper.nonce != leader_nonce {
                return Err(DapAbort::UnrecognizedMessage);
            }

            let helper_message = match &helper.var {
                TransitionVar::Continued(message) => message,

                // Skip report that can't be processed any further.
                //
                // TODO Log the reason the report was skipped.
                TransitionVar::Failed(..) => continue,

                // TODO Log the fact that the helper sent an unexpected message.
                TransitionVar::Finished => return Err(DapAbort::UnrecognizedMessage),
            };

            let res = match self {
                Self::Prio3(prio3_config) => prio3_leader_prepare_finish(
                    prio3_config,
                    leader_step,
                    leader_message,
                    helper_message,
                ),
                Self::Prio2 { dimension } => prio2_leader_prepare_finish(
                    *dimension,
                    leader_step,
                    leader_message,
                    helper_message,
                ),
            };

            match res {
                Ok((data, message)) => {
                    let checksum =
                        ring::digest::digest(&ring::digest::SHA256, &leader_nonce.get_encoded());

                    states.push((
                        DapOutputShare {
                            time: leader_time,
                            checksum: checksum.as_ref().try_into().unwrap(),
                            data,
                        },
                        leader_nonce.clone(),
                    ));

                    seq.push(Transition {
                        nonce: leader_nonce,
                        var: TransitionVar::Continued(message),
                    });
                }

                // Skip report that can't be processed any further.
                //
                // TODO Log the reason the report was skipped.
                Err(VdafError::Codec(..)) | Err(VdafError::Vdaf(..)) => (),
            };
        }

        if seq.is_empty() {
            return Ok(DapLeaderTransition::Skip);
        }

        Ok(DapLeaderTransition::Uncommitted(
            DapLeaderUncommitted { seq: states },
            AggregateContinueReq {
                task_id: task_id.clone(),
                agg_job_id: agg_job_id.clone(),
                transitions: seq,
            },
        ))
    }

    /// Handle an aggregate request from the Leader. This method is called by the Helper.
    ///
    /// Note: This method does not compute the message authentication tag. It is up to the caller
    /// to do so.
    ///
    /// # Inputs
    ///
    /// * `state` is the helper's current state.
    ///
    /// * `agg_cont_req` is the aggregate request sent by the Leader.
    pub(crate) fn handle_agg_cont_req(
        &self,
        state: DapHelperState,
        agg_cont_req: &AggregateContinueReq,
    ) -> Result<DapHelperTransition<AggregateResp>, DapAbort> {
        let mut processed = HashSet::with_capacity(state.seq.len());
        let mut recognized = HashSet::with_capacity(state.seq.len());
        for (_, _, nonce) in state.seq.iter() {
            recognized.insert(nonce.clone());
        }

        let num_reports = state.seq.len();
        let mut transitions = Vec::with_capacity(num_reports);
        let mut out_shares = Vec::with_capacity(num_reports);
        let mut leader_iter = agg_cont_req.transitions.iter();
        let mut helper_iter = state.seq.into_iter();
        for leader in &mut leader_iter {
            // If the nonce is not recognized, then respond with a transition failure.
            //
            // TODO spec: Having to enforce this is awkward because, in order to disambiguate the
            // trigger condition from the leader skipping a report that can't be processed, we have
            // to make two passes of the request. (The first step is to compute `recognized`). It
            // would be nice if we didn't have to keep track of the set of processed reports. One
            // way to avoid this would be to require the leader to send the reports in a well-known
            // order, say, in ascending order by nonce.
            if !recognized.contains(&leader.nonce) || processed.contains(&leader.nonce) {
                return Err(DapAbort::UnrecognizedMessage);
            }

            for (helper_step, helper_time, helper_nonce) in &mut helper_iter {
                processed.insert(helper_nonce.clone());
                if helper_nonce != leader.nonce {
                    // Presumably the leader has skipped this report.
                    continue;
                }

                let leader_message = match &leader.var {
                    TransitionVar::Continued(message) => message,

                    // TODO Log the fact that the helper sent an unexpected message.
                    _ => return Err(DapAbort::UnrecognizedMessage),
                };

                let res = match self {
                    Self::Prio3(prio3_config) => {
                        prio3_helper_prepare_finish(prio3_config, helper_step, leader_message)
                    }
                    Self::Prio2 { dimension } => {
                        prio2_helper_prepare_finish(*dimension, helper_step, leader_message)
                    }
                };

                let var = match res {
                    Ok(data) => {
                        let checksum = ring::digest::digest(
                            &ring::digest::SHA256,
                            &helper_nonce.get_encoded(),
                        );

                        out_shares.push(DapOutputShare {
                            time: helper_time,
                            checksum: checksum.as_ref().try_into().unwrap(),
                            data,
                        });
                        TransitionVar::Finished
                    }

                    Err(VdafError::Codec(..)) | Err(VdafError::Vdaf(..)) => {
                        TransitionVar::Failed(TransitionFailure::VdafPrepError)
                    }
                };

                transitions.push(Transition {
                    nonce: helper_nonce,
                    var,
                });

                break;
            }
        }

        Ok(DapHelperTransition::Finish(
            out_shares,
            AggregateResp { transitions },
        ))
    }

    /// Handle the last aggregate response from the Helper. This method is run by the Leader.
    ///
    /// Note: This method does not compute the message authentication tag. It is up to the caller
    /// to do so.
    ///
    /// # Inputs
    ///
    /// * `task_id` is the DAP task for which the reports are being aggregated.
    ///
    /// * `uncommited` is the Leader's current state, i.e., the set of output shares output from
    /// the previous round that have not yet been commmitted to.
    ///
    /// * `agg_resp` is the previous aggregate response sent by the Helper.
    pub(crate) fn handle_final_agg_resp(
        &self,
        uncommitted: DapLeaderUncommitted,
        agg_resp: AggregateResp,
    ) -> Result<Vec<DapOutputShare>, DapAbort> {
        if agg_resp.transitions.len() != uncommitted.seq.len() {
            return Err(DapAbort::UnrecognizedMessage);
        }

        let mut out_shares = Vec::with_capacity(uncommitted.seq.len());
        for (helper, (out_share, leader_nonce)) in agg_resp
            .transitions
            .into_iter()
            .zip(uncommitted.seq.into_iter())
        {
            // TODO spec: Consider removing the nonce from the AggregateResp.
            if helper.nonce != leader_nonce {
                return Err(DapAbort::UnrecognizedMessage);
            }

            match &helper.var {
                // TODO Log the fact that the helper sent an unexpected message.
                TransitionVar::Continued(..) => return Err(DapAbort::UnrecognizedMessage),

                // Skip report that can't be processed any further.
                //
                // TODO Log the reason the report was skipped.
                TransitionVar::Failed(..) => continue,

                TransitionVar::Finished => out_shares.push(out_share),
            };
        }

        Ok(out_shares)
    }

    /// Encrypt an aggregate share under the Collector's public key. This method is run by the
    /// Leader in reponse to a collect request.
    ///
    /// # Inputs
    ///
    /// * `hpke_config` is the Collector's HPKE public key.
    ///
    /// * `task_id` is the DAP task ID.
    ///
    /// * `batch_interval` is the batch interval for the aggregate share.
    ///
    /// * `agg_share` is the aggregate share.
    pub(crate) fn produce_leader_encrypted_agg_share(
        &self,
        hpke_config: &HpkeConfig,
        task_id: &Id,
        batch_selector: &BatchSelector,
        agg_share: &DapAggregateShare,
    ) -> Result<HpkeCiphertext, DapAbort> {
        produce_encrypted_agg_share(true, hpke_config, task_id, batch_selector, agg_share)
    }

    /// Like [`produce_leader_encrypted_agg_share`] but run by the Helper in response to an
    /// aggregate-share request.
    pub(crate) fn produce_helper_encrypted_agg_share(
        &self,
        hpke_config: &HpkeConfig,
        task_id: &Id,
        batch_selector: &BatchSelector,
        agg_share: &DapAggregateShare,
    ) -> Result<HpkeCiphertext, DapAbort> {
        produce_encrypted_agg_share(false, hpke_config, task_id, batch_selector, agg_share)
    }

    /// Decrypt and unshard a sequence of aggregate shares. This method is run by the Collector
    /// after completing a collect request.
    ///
    /// # Inputs
    ///
    /// * `decrypter` is used to decrypt the aggregate shares.
    ///
    /// * `task_id` is the DAP task ID.
    ///
    /// * `batch_interval` is the batch interval for the aggregate share.
    ///
    /// * `encrypted_agg_shares` is the set of encrypted aggregate shares produced by the
    /// Aggregators. The first encrypted aggregate shares must be the Leader's.
    //
    // TODO spec: Allow the collector to have multiple HPKE public keys (the way Aggregators do).
    pub async fn consume_encrypted_agg_shares(
        &self,
        decrypter: &impl HpkeDecrypter<'_>,
        task_id: &Id,
        batch_selector: &BatchSelector,
        encrypted_agg_shares: Vec<HpkeCiphertext>,
    ) -> Result<DapAggregateResult, DapError> {
        const N: usize = CTX_AGG_SHARE.len();
        let mut info = [0; N + 2];
        info[..N].copy_from_slice(CTX_AGG_SHARE);
        info[N + 1] = CTX_ROLE_COLLECTOR; // Receiver role (sender role set below)

        let mut aad = Vec::with_capacity(40);
        task_id.encode(&mut aad);
        batch_selector.encode(&mut aad);

        let mut agg_shares = Vec::with_capacity(encrypted_agg_shares.len());
        for (i, agg_share_ciphertext) in encrypted_agg_shares.iter().enumerate() {
            info[N] = if i == 0 {
                CTX_ROLE_LEADER
            } else {
                CTX_ROLE_HELPER
            };

            let agg_share_data = decrypter
                .hpke_decrypt(task_id, &info, &aad, agg_share_ciphertext)
                .await?;
            agg_shares.push(agg_share_data);
        }

        if agg_shares.len() != encrypted_agg_shares.len() {
            return Err(DapError::Fatal(
                "one or more HPKE ciphertexts with unrecognized config ID".into(),
            ));
        }

        match self {
            Self::Prio3(prio3_config) => Ok(prio3_unshard(prio3_config, agg_shares)?),
            Self::Prio2 { dimension } => Ok(prio2_unshard(*dimension, agg_shares)?),
        }
    }
}

fn produce_encrypted_agg_share(
    is_leader: bool,
    hpke_config: &HpkeConfig,
    task_id: &Id,
    batch_selector: &BatchSelector,
    agg_share: &DapAggregateShare,
) -> Result<HpkeCiphertext, DapAbort> {
    let agg_share_data = agg_share
        .data
        .as_ref()
        .ok_or_else(|| DapError::fatal("empty aggregate share"))?
        .get_encoded();

    const N: usize = CTX_AGG_SHARE.len();
    let mut info = [0; N + 2];
    info[..N].copy_from_slice(CTX_AGG_SHARE);
    info[N] = if is_leader {
        CTX_ROLE_LEADER
    } else {
        CTX_ROLE_HELPER
    }; // Sender role
    info[N + 1] = CTX_ROLE_COLLECTOR; // Receiver role

    // TODO spec: Consider adding agg param to AAD.
    let mut aad = Vec::with_capacity(40);
    task_id.encode(&mut aad);
    batch_selector.encode(&mut aad);

    let (enc, payload) = hpke_config
        .encrypt(&info, &aad, &agg_share_data)
        .map_err(|e| DapAbort::Internal(Box::new(e)))?;
    Ok(HpkeCiphertext {
        config_id: hpke_config.id,
        enc,
        payload,
    })
}

#[cfg(test)]
mod mod_test;
pub mod prio2;
#[cfg(test)]
mod prio2_test;
pub mod prio3;
#[cfg(test)]
mod prio3_test;
