// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Verifiable, Distributed Aggregation Functions
//! ([VDAFs](https://datatracker.ietf.org/doc/draft-irtf-cfrg-vdaf/)).

use crate::{
    messages::{
        encode_u16_bytes, AggregateReq, AggregateReqVar, AggregateResp, HpkeCiphertext, HpkeConfig,
        Id, Interval, Nonce, Report, ReportShare, Transition, TransitionFailure, TransitionVar,
    },
    roles::HpkeDecrypter,
    vdaf::prio3::{
        prio3_encode_prepare_message, prio3_get_decoded_verify_param, prio3_helper_prepare_finish,
        prio3_leader_prepare_finish, prio3_prepare_start, prio3_setup, prio3_shard, prio3_unshard,
        Prio3Error,
    },
    DapAbort, DapAggregateResult, DapAggregateShare, DapError, DapHelperState, DapHelperTransition,
    DapLeaderState, DapLeaderTransition, DapLeaderUncommitted, DapMeasurement, DapOutputShare,
    DapVerifyParam, VdafConfig,
};
use prio::{
    codec::Encode,
    field::{Field128, Field64},
    vdaf::prio3::{Prio3PrepareMessage, Prio3PrepareStep, Prio3VerifyParam},
};
use rand::prelude::*;
use ring::hmac;
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, convert::TryInto};

const CTX_INPUT_SHARE_PREFIX: &[u8] = b"ppm input share";
const CTX_AGG_SHARE_PREFIX: &[u8] = b"ppm aggregate share";
const CTX_ROLE_COLLECTOR: u8 = 0;
const CTX_ROLE_CLIENT: u8 = 1;
const CTX_ROLE_LEADER: u8 = 2;
const CTX_ROLE_HELPER: u8 = 3;

// TODO(MVP) This will be removed after moving to libprio 0.8.0.
#[derive(Clone)]
pub(crate) enum VdafVerifyParam {
    Prio3(Prio3VerifyParam<16>),
}

#[cfg(test)]
impl VdafVerifyParam {
    pub(crate) fn into_prio3(self) -> Prio3VerifyParam<16> {
        match self {
            VdafVerifyParam::Prio3(verify_param) => verify_param,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum VdafStep {
    Prio3Field64(Prio3PrepareStep<Field64, 16>),
    Prio3Field128(Prio3PrepareStep<Field128, 16>),
}

#[derive(Clone, Debug)]
pub(crate) enum VdafMessage {
    Prio3Field64(Prio3PrepareMessage<Field64, 16>),
    Prio3Field128(Prio3PrepareMessage<Field128, 16>),
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) enum VdafAggregateShare {
    Field64(prio::vdaf::AggregateShare<Field64>),
    Field128(prio::vdaf::AggregateShare<Field128>),
}

impl Encode for VdafAggregateShare {
    fn encode(&self, bytes: &mut Vec<u8>) {
        match self {
            VdafAggregateShare::Field64(vdaf_agg_share) => vdaf_agg_share.encode(bytes),
            VdafAggregateShare::Field128(vdaf_agg_share) => vdaf_agg_share.encode(bytes),
        }
    }
}

impl VdafConfig {
    pub(crate) fn get_decoded_verify_param(
        &self,
        data: &[u8],
    ) -> Result<VdafVerifyParam, DapAbort> {
        match self {
            Self::Prio3(prio3_config) => prio3_get_decoded_verify_param(prio3_config, data)
                .map_err(|e| DapAbort::Internal(Box::new(e))),
        }
    }

    /// Checks if the provided aggregation parameter is valid for the underling VDAF being
    /// executed.
    pub fn is_valid_agg_param(&self, agg_param: &[u8]) -> bool {
        match self {
            Self::Prio3(..) => agg_param.is_empty(),
        }
    }

    /// Generate the Aggregators' secret VDAF verification parameters. The first is used by the
    /// Leader and the second is used by the Helper. This method is run out-of-band while
    /// configuring the Aggregators.
    //
    // TODO We may need to change this API to accommodate a public parameter for the VDAF.
    pub fn setup(&self) -> Result<(DapVerifyParam, DapVerifyParam), DapAbort> {
        let (leader_vdaf, helper_vdaf) = match self {
            Self::Prio3(prio3_config) => {
                prio3_setup(prio3_config).map_err(|e| DapAbort::Internal(Box::new(e)))?
            }
        };

        let mut rng = thread_rng();
        let hmac_key: [u8; 32] = rng.gen();
        let hmac = hmac::Key::new(hmac::HMAC_SHA256, &hmac_key);

        Ok((
            DapVerifyParam {
                vdaf: leader_vdaf,
                hmac: hmac.clone(),
            },
            DapVerifyParam {
                vdaf: helper_vdaf,
                hmac,
            },
        ))
    }

    /// Generate a report for a measurement. This method is run by the Client.
    ///
    /// # Inputs
    ///
    /// * `hpke_config_list` is the sequence of HPKE configs, the first belonging to the Leader and the
    /// remainder belonging to the Helpers. Note that the current draft only supports one Helper,
    /// so this method will return an error if `hpke_config_list.len() != 2`.
    ///
    /// * `now` is the number of seconds since the UNIX epoch.
    ///
    /// * `task_id` is the DAP task for which this report is being generated.
    ///
    /// * `measurement` is the measurement.
    //
    // TODO We may need to change this API to accommodate a public parameter for the VDAF.
    pub fn produce_report(
        &self,
        hpke_config_list: &[HpkeConfig],
        now: u64,
        task_id: &Id,
        measurement: DapMeasurement,
    ) -> Result<Report, DapError> {
        let mut rng = thread_rng();
        let nonce = Nonce {
            time: now,
            rand: rng.gen(),
        };

        let encoded_input_shares = match self {
            Self::Prio3(prio3_config) => prio3_shard(prio3_config, measurement)?,
        };

        if hpke_config_list.len() != encoded_input_shares.len() {
            return Err(DapError::Fatal("unexpected number of HPKE configs".into()));
        }

        let mut info = Vec::with_capacity(CTX_INPUT_SHARE_PREFIX.len() + 34);
        task_id.encode(&mut info);
        info.extend_from_slice(CTX_INPUT_SHARE_PREFIX);
        info.push(CTX_ROLE_CLIENT);
        info.push(0); // Receiver role (overwritten below)
        let receiver_role_index = info.len() - 1;

        let mut aad = Vec::with_capacity(10);
        nonce.encode(&mut aad);
        0_u16.encode(&mut aad); // Empty extensions

        let mut encrypted_input_shares = Vec::with_capacity(encoded_input_shares.len());
        for (i, (hpke_config, input_share_data)) in hpke_config_list
            .iter()
            .zip(encoded_input_shares)
            .enumerate()
        {
            info[receiver_role_index] = if i == 0 {
                CTX_ROLE_LEADER
            } else {
                CTX_ROLE_HELPER
            };
            let (enc, payload) = hpke_config.encrypt(&info, &aad, &input_share_data)?;

            encrypted_input_shares.push(HpkeCiphertext {
                config_id: hpke_config.id,
                enc,
                payload,
            });
        }

        Ok(Report {
            task_id: task_id.clone(),
            nonce,
            ignored_extensions: vec![],
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
    /// * `verify_param` is the Aggregator's secret VDAF verification parameter.
    ///
    /// * `task_id` is the DAP task ID indicated by the report.
    ///
    /// * `nonce` is the report nonce.
    ///
    /// * `encrypted_input_share` is the encrypted input share.
    //
    // TODO spec: Note in the spec that we MUST ignore extensions we don't recognize, as they may
    // be intended for the other aggregator. (Does this make sense?)
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn consume_report_share<D: HpkeDecrypter>(
        &self,
        decrypter: &D,
        is_leader: bool,
        verify_param: &DapVerifyParam,
        task_id: &Id,
        nonce: &Nonce,
        extensions: &[u8],
        encrypted_input_share: &HpkeCiphertext,
    ) -> Result<(VdafStep, VdafMessage), DapError> {
        let mut info = Vec::with_capacity(CTX_INPUT_SHARE_PREFIX.len() + 34);
        task_id.encode(&mut info);
        info.extend_from_slice(CTX_INPUT_SHARE_PREFIX);
        info.push(CTX_ROLE_CLIENT);
        info.push(if is_leader {
            CTX_ROLE_LEADER
        } else {
            CTX_ROLE_HELPER
        });

        let mut aad = Vec::with_capacity(10);
        nonce.encode(&mut aad);
        let nonce_len = aad.len();
        encode_u16_bytes(&mut aad, extensions);

        let input_share_data =
            decrypter.hpke_decrypt(task_id, &info, &aad, encrypted_input_share)?;

        let nonce_data = &aad[..nonce_len];
        match (self, &verify_param.vdaf) {
            (Self::Prio3(ref prio3_config), VdafVerifyParam::Prio3(ref verify_param)) => Ok(
                prio3_prepare_start(prio3_config, verify_param, nonce_data, &input_share_data)?,
            ),
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
    /// * `verify_param` is the Leader's secret VDAF verification parameter.
    ///
    /// * `task_id` indicates the DAP task for which the set of reports are being aggregated.
    ///
    /// * `reports` is the set of reports uploaded by Clients.
    pub fn produce_agg_init_req<D: HpkeDecrypter>(
        &self,
        decrypter: &D,
        verify_param: &DapVerifyParam,
        task_id: &Id,
        agg_job_id: &Id,
        reports: Vec<Report>,
    ) -> Result<DapLeaderTransition<AggregateReq>, DapAbort> {
        let mut processed = HashSet::with_capacity(reports.len());
        let mut states = Vec::with_capacity(reports.len());
        let mut seq = Vec::with_capacity(reports.len());
        for report in reports.into_iter() {
            if processed.contains(&report.nonce) {
                return Err(DapError::fatal(
                    "tried to process report sequence with non-unique nonces",
                )
                .into());
            }
            processed.insert(report.nonce.clone());

            if &report.task_id != task_id || report.encrypted_input_shares.len() != 2 {
                return Err(
                    DapError::fatal("tried to process report with incorrect task ID").into(),
                );
            }

            let (leader_share, helper_share) = {
                let mut it = report.encrypted_input_shares.into_iter();
                (it.next().unwrap(), it.next().unwrap())
            };

            match self.consume_report_share(
                decrypter,
                true, // is_leader
                verify_param,
                task_id,
                &report.nonce,
                &report.ignored_extensions,
                &leader_share,
            ) {
                Ok((step, message)) => {
                    states.push((step, message, report.nonce.clone()));
                    seq.push(ReportShare {
                        nonce: report.nonce,
                        ignored_extensions: report.ignored_extensions,
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
            AggregateReq {
                task_id: task_id.clone(),
                agg_job_id: agg_job_id.clone(),
                var: AggregateReqVar::Init {
                    agg_param: Vec::new(),
                    seq,
                },
                tag: None,
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
    /// * `verify_param` is the Helper's secret VDAF verification parameter.
    ///
    /// * `task_id` indicates the DAP task for which the reports are being processed.
    ///
    /// * `agg_req` is the aggregate request sent by the peer.
    ///
    /// * `early_tran_fail_for` is a callback used to determine if a report should be rejected based on
    /// the sequence of aggregate and collect requests made for the task so far. Its input is the
    /// nonce of report share in `agg_req` and its return value is an optional transition failure.
    pub fn handle_agg_init_req<D, F>(
        &self,
        decrypter: &D,
        verify_param: &DapVerifyParam,
        agg_req: &AggregateReq,
        early_tran_fail_for: F,
    ) -> Result<DapHelperTransition<AggregateResp>, DapAbort>
    where
        D: HpkeDecrypter,
        F: Fn(&Nonce) -> Option<TransitionFailure>,
    {
        let report_shares = agg_req.get_report_shares_ref()?;
        let mut processed = HashSet::with_capacity(report_shares.len());
        let mut states = Vec::with_capacity(report_shares.len());
        let mut seq = Vec::with_capacity(report_shares.len());
        for report_share in report_shares.iter() {
            if processed.contains(&report_share.nonce) {
                return Err(DapAbort::UnrecognizedMessage);
            }
            processed.insert(report_share.nonce.clone());

            if let Some(failure) = early_tran_fail_for(&report_share.nonce) {
                seq.push(Transition {
                    nonce: report_share.nonce.clone(),
                    var: TransitionVar::Failed(failure),
                });
                continue;
            }

            let var = match self.consume_report_share(
                decrypter,
                false, // is_leader
                verify_param,
                &agg_req.task_id,
                &report_share.nonce,
                &report_share.ignored_extensions,
                &report_share.encrypted_input_share,
            ) {
                Ok((step, message)) => {
                    let message_data = prio3_encode_prepare_message(&message);
                    states.push((step, report_share.nonce.clone()));
                    TransitionVar::Continued(message_data)
                }

                Err(DapError::Transition(failure_reason)) => TransitionVar::Failed(failure_reason),

                Err(e) => return Err(DapAbort::Internal(Box::new(e))),
            };

            seq.push(Transition {
                nonce: report_share.nonce.clone(),
                var,
            });
        }

        Ok(DapHelperTransition::Continue(
            DapHelperState { seq: states },
            AggregateResp { seq, tag: None },
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
    pub fn handle_agg_resp(
        &self,
        task_id: &Id,
        agg_job_id: &Id,
        state: DapLeaderState,
        agg_resp: AggregateResp,
    ) -> Result<DapLeaderTransition<AggregateReq>, DapAbort> {
        if agg_resp.seq.len() != state.seq.len() {
            return Err(DapAbort::UnrecognizedMessage);
        }

        let mut seq = Vec::with_capacity(state.seq.len());
        let mut states = Vec::with_capacity(state.seq.len());
        for (helper, (leader_step, leader_message, leader_nonce)) in
            agg_resp.seq.into_iter().zip(state.seq.into_iter())
        {
            // TODO spec: Consider removing the nonce from the AggregateResp.
            if helper.nonce != leader_nonce {
                return Err(DapAbort::UnrecognizedMessage);
            }

            match self {
                Self::Prio3(prio3_config) => {
                    let helper_message = match &helper.var {
                        TransitionVar::Continued(message) => message,

                        // Skip report that can't be processed any further.
                        //
                        // TODO Log the reason the report was skipped.
                        TransitionVar::Failed(..) => continue,

                        // TODO Log the fact that the helper sent an unexpected message.
                        TransitionVar::Finished => return Err(DapAbort::UnrecognizedMessage),
                    };

                    match prio3_leader_prepare_finish(
                        prio3_config,
                        leader_step,
                        leader_message,
                        helper_message,
                    ) {
                        Ok((data, message)) => {
                            let checksum = ring::digest::digest(
                                &ring::digest::SHA256,
                                &leader_nonce.get_encoded(),
                            );

                            states.push((
                                DapOutputShare {
                                    time: leader_nonce.time,
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
                        Err(Prio3Error::Codec(..)) | Err(Prio3Error::Vdaf(..)) => (),
                    }
                }
            };
        }

        if seq.is_empty() {
            return Ok(DapLeaderTransition::Skip);
        }

        Ok(DapLeaderTransition::Uncommitted(
            DapLeaderUncommitted { seq: states },
            AggregateReq {
                task_id: task_id.clone(),
                agg_job_id: agg_job_id.clone(),
                var: AggregateReqVar::Continue { seq },
                tag: None,
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
    /// * `agg_req` is the aggregate request sent by the Leader.
    pub fn handle_agg_cont_req(
        &self,
        state: DapHelperState,
        agg_req: &AggregateReq,
    ) -> Result<DapHelperTransition<AggregateResp>, DapAbort> {
        let mut processed = HashSet::with_capacity(state.seq.len());
        let mut recognized = HashSet::with_capacity(state.seq.len());
        for (_, nonce) in state.seq.iter() {
            recognized.insert(nonce.clone());
        }

        let leader_transitions = agg_req.get_transitions_ref()?;
        let mut seq = Vec::with_capacity(state.seq.len());
        let mut out_shares = Vec::with_capacity(state.seq.len());
        let mut leader_iter = leader_transitions.iter();
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

            for (helper_step, helper_nonce) in &mut helper_iter {
                processed.insert(helper_nonce.clone());
                if helper_nonce != leader.nonce {
                    // Presumably the leader has skipped this report.
                    continue;
                }

                let var = match self {
                    Self::Prio3(prio3_config) => {
                        let leader_message = match &leader.var {
                            TransitionVar::Continued(message) => message,

                            // TODO Log the fact that the helper sent an unexpected message.
                            _ => return Err(DapAbort::UnrecognizedMessage),
                        };

                        match prio3_helper_prepare_finish(prio3_config, helper_step, leader_message)
                        {
                            Ok(data) => {
                                let checksum = ring::digest::digest(
                                    &ring::digest::SHA256,
                                    &helper_nonce.get_encoded(),
                                );

                                out_shares.push(DapOutputShare {
                                    time: helper_nonce.time,
                                    checksum: checksum.as_ref().try_into().unwrap(),
                                    data,
                                });
                                TransitionVar::Finished
                            }

                            Err(Prio3Error::Codec(..)) | Err(Prio3Error::Vdaf(..)) => {
                                TransitionVar::Failed(TransitionFailure::VdafPrepError)
                            }
                        }
                    }
                };

                seq.push(Transition {
                    nonce: helper_nonce,
                    var,
                });

                break;
            }
        }

        Ok(DapHelperTransition::Finish(
            out_shares,
            AggregateResp { seq, tag: None },
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
    pub fn handle_final_agg_resp(
        &self,
        uncommitted: DapLeaderUncommitted,
        agg_resp: AggregateResp,
    ) -> Result<Vec<DapOutputShare>, DapAbort> {
        if agg_resp.seq.len() != uncommitted.seq.len() {
            return Err(DapAbort::UnrecognizedMessage);
        }

        let mut out_shares = Vec::with_capacity(uncommitted.seq.len());
        for (helper, (out_share, leader_nonce)) in
            agg_resp.seq.into_iter().zip(uncommitted.seq.into_iter())
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
    pub fn produce_leader_encrypted_agg_share(
        &self,
        hpke_config: &HpkeConfig,
        task_id: &Id,
        batch_interval: &Interval,
        agg_share: &DapAggregateShare,
    ) -> Result<HpkeCiphertext, DapAbort> {
        produce_encrypted_agg_share(true, hpke_config, task_id, batch_interval, agg_share)
    }

    /// Like [`produce_leader_encrypted_agg_share`] but run by the Helper in response to an
    /// aggregate-share request.
    pub fn produce_helper_encrypted_agg_share(
        &self,
        hpke_config: &HpkeConfig,
        task_id: &Id,
        batch_interval: &Interval,
        agg_share: &DapAggregateShare,
    ) -> Result<HpkeCiphertext, DapAbort> {
        produce_encrypted_agg_share(false, hpke_config, task_id, batch_interval, agg_share)
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
    pub fn consume_encrypted_agg_shares<D: HpkeDecrypter>(
        &self,
        decrypter: &D,
        task_id: &Id,
        batch_interval: &Interval,
        encrypted_agg_shares: Vec<HpkeCiphertext>,
    ) -> Result<DapAggregateResult, DapError> {
        // TODO Validate the batch interval.This requires adding the min batch duration to `Vdaf`.
        let mut info = Vec::with_capacity(CTX_AGG_SHARE_PREFIX.len() + 34);
        task_id.encode(&mut info);
        info.extend_from_slice(CTX_AGG_SHARE_PREFIX);
        info.push(0); // Sender role (overwritten below)
        let sender_role_index = info.len() - 1;
        info.push(CTX_ROLE_COLLECTOR);

        let mut aad = Vec::with_capacity(8);
        batch_interval.encode(&mut aad);

        let mut agg_shares = Vec::with_capacity(encrypted_agg_shares.len());
        for (i, agg_share_ciphertext) in encrypted_agg_shares.iter().enumerate() {
            info[sender_role_index] = if i == 0 {
                CTX_ROLE_LEADER
            } else {
                CTX_ROLE_HELPER
            };

            let agg_share_data =
                decrypter.hpke_decrypt(task_id, &info, &aad, agg_share_ciphertext)?;
            agg_shares.push(agg_share_data);
        }

        if agg_shares.len() != encrypted_agg_shares.len() {
            return Err(DapError::Fatal(
                "one or more HPKE ciphertexts with unrecognized config ID".into(),
            ));
        }

        match self {
            Self::Prio3(prio3_config) => Ok(prio3_unshard(prio3_config, agg_shares)?),
        }
    }
}

fn produce_encrypted_agg_share(
    is_leader: bool,
    hpke_config: &HpkeConfig,
    task_id: &Id,
    batch_interval: &Interval,
    agg_share: &DapAggregateShare,
) -> Result<HpkeCiphertext, DapAbort> {
    // TODO Validate the batch interval. This requires adding the min batch duration to `Vdaf`.
    let agg_share_data = agg_share
        .data
        .as_ref()
        .ok_or_else(|| DapError::fatal("empty aggregate share"))?
        .get_encoded();

    let mut info = Vec::with_capacity(CTX_AGG_SHARE_PREFIX.len() + 34);
    task_id.encode(&mut info);
    info.extend_from_slice(CTX_AGG_SHARE_PREFIX);
    info.push(match is_leader {
        true => CTX_ROLE_LEADER,
        false => CTX_ROLE_HELPER,
    });
    info.push(CTX_ROLE_COLLECTOR);

    let mut aad = Vec::with_capacity(8);
    batch_interval.encode(&mut aad);

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
pub mod prio3;
#[cfg(test)]
mod prio3_test;
