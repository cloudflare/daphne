// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Verifiable, Distributed Aggregation Functions
//! ([VDAFs](https://datatracker.ietf.org/doc/draft-irtf-cfrg-vdaf/)).

use crate::{
    error::DapAbort,
    fatal_error,
    hpke::HpkeDecrypter,
    messages::{
        encode_u32_bytes, AggregationJobContinueReq, AggregationJobInitReq, AggregationJobResp,
        BatchSelector, Extension, HpkeCiphertext, HpkeConfig, PartialBatchSelector,
        PlaintextInputShare, Report, ReportId, ReportMetadata, ReportShare, TaskId, Time,
        Transition, TransitionFailure, TransitionVar,
    },
    metrics::ContextualizedDaphneMetrics,
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
    DapAggregateResult, DapAggregateShare, DapError, DapHelperState, DapHelperTransition,
    DapLeaderState, DapLeaderTransition, DapLeaderUncommitted, DapMeasurement, DapOutputShare,
    DapTaskConfig, DapVersion, MetaAggregationJobId, VdafConfig,
};
use prio::{
    codec::{CodecError, Decode, Encode, ParameterizedEncode},
    field::{Field128, Field64, FieldPrio2},
    vdaf::{
        prio2::{Prio2PrepareShare, Prio2PrepareState},
        prio3::{Prio3PrepareShare, Prio3PrepareState},
    },
};
use rand::prelude::*;
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, convert::TryInto};

const CTX_INPUT_SHARE_DRAFT02: &[u8] = b"dap-02 input share";
const CTX_INPUT_SHARE_DRAFT04: &[u8] = b"dap-04 input share";
const CTX_AGG_SHARE_DRAFT02: &[u8] = b"dap-02 aggregate share";
const CTX_AGG_SHARE_DRAFT04: &[u8] = b"dap-04 aggregate share";
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

/// A VDAF verification key.
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VdafVerifyKey {
    Prio3(#[serde(with = "hex")] [u8; 16]),
    Prio2(#[serde(with = "hex")] [u8; 32]),
}

impl AsRef<[u8]> for VdafVerifyKey {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Prio3(ref bytes) => &bytes[..],
            Self::Prio2(ref bytes) => &bytes[..],
        }
    }
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
#[serde(rename_all = "snake_case")]
pub(crate) enum VdafAggregateShare {
    Field64(prio::vdaf::AggregateShare<Field64>),
    Field128(prio::vdaf::AggregateShare<Field128>),
    FieldPrio2(prio::vdaf::AggregateShare<FieldPrio2>),
}

impl Encode for VdafAggregateShare {
    fn encode(&self, bytes: &mut Vec<u8>) {
        match self {
            VdafAggregateShare::Field64(agg_share) => agg_share.encode(bytes),
            VdafAggregateShare::Field128(agg_share) => agg_share.encode(bytes),
            VdafAggregateShare::FieldPrio2(agg_share) => agg_share.encode(bytes),
        }
    }
}

fn unimplemented_version_abort() -> DapAbort {
    DapAbort::BadRequest("unimplemented version".to_string())
}

fn unimplemented_version() -> DapError {
    DapError::Abort(unimplemented_version_abort())
}

impl VdafConfig {
    /// Parse a verification key from raw bytes.
    pub fn get_decoded_verify_key(&self, bytes: &[u8]) -> Result<VdafVerifyKey, DapError> {
        match self {
            Self::Prio3(..) => Ok(VdafVerifyKey::Prio3(<[u8; 16]>::try_from(bytes).map_err(
                |e| DapAbort::from_codec_error(CodecError::Other(Box::new(e)), None),
            )?)),
            Self::Prio2 { .. } => {
                Ok(VdafVerifyKey::Prio2(<[u8; 32]>::try_from(bytes).map_err(
                    |e| DapAbort::from_codec_error(CodecError::Other(Box::new(e)), None),
                )?))
            }
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
    pub fn gen_verify_key(&self) -> VdafVerifyKey {
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
    ///
    /// * `extensions` are the extensions.
    ///
    /// * `version` is the DapVersion to use.
    //
    // TODO(issue #100): Truncate the timestamp, as required in DAP-02.
    pub fn produce_report_with_extensions(
        &self,
        hpke_config_list: &[HpkeConfig],
        time: Time,
        task_id: &TaskId,
        measurement: DapMeasurement,
        extensions: Vec<Extension>,
        version: DapVersion,
    ) -> Result<Report, DapError> {
        let mut rng = thread_rng();
        let report_id = ReportId(rng.gen());
        let (public_share, input_shares) = self.produce_input_shares(measurement, &report_id.0)?;
        self.produce_report_with_extensions_for_shares(
            public_share,
            input_shares,
            hpke_config_list,
            time,
            task_id,
            &report_id,
            extensions,
            version,
        )
    }

    /// Generate a report for the given public and input shares with the given extensions.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn produce_report_with_extensions_for_shares(
        &self,
        public_share: Vec<u8>,
        mut input_shares: Vec<Vec<u8>>,
        hpke_config_list: &[HpkeConfig],
        time: Time,
        task_id: &TaskId,
        report_id: &ReportId,
        extensions: Vec<Extension>,
        version: DapVersion,
    ) -> Result<Report, DapError> {
        let report_extensions = match version {
            DapVersion::Draft02 => extensions.clone(),
            _ => vec![],
        };
        let metadata = ReportMetadata {
            id: report_id.clone(),
            time,
            extensions: report_extensions,
        };

        if version != DapVersion::Draft02 {
            let mut encoded: Vec<Vec<u8>> = Vec::new();
            for share in input_shares.into_iter() {
                let input_share = PlaintextInputShare {
                    extensions: extensions.clone(),
                    payload: share,
                };
                encoded.push(PlaintextInputShare::get_encoded(&input_share));
            }
            input_shares = encoded;
        }

        if hpke_config_list.len() != input_shares.len() {
            return Err(fatal_error!(err = "unexpected number of HPKE configs"));
        }

        let input_share_text = match version {
            DapVersion::Draft02 => CTX_INPUT_SHARE_DRAFT02,
            DapVersion::Draft04 => CTX_INPUT_SHARE_DRAFT04,
            _ => return Err(unimplemented_version()),
        };
        let n: usize = input_share_text.len();
        let mut info = Vec::new();
        info.reserve(n + 2);
        info.extend_from_slice(input_share_text);
        info.push(CTX_ROLE_CLIENT); // Sender role
        info.push(CTX_ROLE_LEADER); // Receiver role placeholder; updated below.

        let mut aad = Vec::with_capacity(58);
        task_id.encode(&mut aad);
        metadata.encode_with_param(&version, &mut aad);
        // NOTE(cjpatton): In DAP-02, the tag-length prefix is not specified. However, the intent
        // was to include the prefix, and it is specified unambiguoiusly in DAP-03. All of our
        // partners for interop have agreed to include the prefix for DAP-02, so we have hard-coded
        // it here.
        encode_u32_bytes(&mut aad, &public_share);

        let mut encrypted_input_shares = Vec::with_capacity(input_shares.len());
        for (i, (hpke_config, input_share_data)) in
            hpke_config_list.iter().zip(input_shares).enumerate()
        {
            info[n + 1] = if i == 0 {
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
            draft02_task_id: task_id.for_request_payload(&version),
            report_metadata: metadata,
            public_share,
            encrypted_input_shares,
        })
    }

    /// Generate shares for a measurement.
    pub(crate) fn produce_input_shares(
        &self,
        measurement: DapMeasurement,
        nonce: &[u8; 16],
    ) -> Result<(Vec<u8>, Vec<Vec<u8>>), DapError> {
        match self {
            Self::Prio3(prio3_config) => Ok(prio3_shard(prio3_config, measurement, nonce)?),
            Self::Prio2 { dimension } => Ok(prio2_shard(*dimension, measurement, nonce)?),
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
    ///
    /// * `version` is the DapVersion to use.
    pub fn produce_report(
        &self,
        hpke_config_list: &[HpkeConfig],
        time: Time,
        task_id: &TaskId,
        measurement: DapMeasurement,
        version: DapVersion,
    ) -> Result<Report, DapError> {
        self.produce_report_with_extensions(
            hpke_config_list,
            time,
            task_id,
            measurement,
            Vec::new(),
            version,
        )
    }

    /// Consume a report share sent by the Client and return the initial Prepare step. This is run
    /// by each Aggregator.
    ///
    /// # Inputs
    ///
    /// * `decryptor` is used to decrypt the input share.
    ///
    /// * `verify_key` is the secret VDAF verification key shared by the Aggregators.
    ///
    /// * `task_id` is the DAP task ID indicated by the report.
    ///
    /// * `report_id` is the report ID.
    ///
    /// * `encrypted_input_share` is the encrypted input share.
    ///
    /// * `version` is the DapVersion to use.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn consume_report_share(
        &self,
        decrypter: &impl HpkeDecrypter,
        is_leader: bool,
        task_id: &TaskId,
        task_config: &DapTaskConfig,
        metadata: &ReportMetadata,
        public_share: &[u8],
        encrypted_input_share: &HpkeCiphertext,
    ) -> Result<(VdafState, VdafMessage), DapError> {
        if metadata.time >= task_config.expiration {
            return Err(DapError::Transition(TransitionFailure::TaskExpired));
        }

        let input_share_text = match task_config.version {
            DapVersion::Draft02 => CTX_INPUT_SHARE_DRAFT02,
            DapVersion::Draft04 => CTX_INPUT_SHARE_DRAFT04,
            _ => return Err(unimplemented_version()),
        };
        let n: usize = input_share_text.len();
        let mut info = Vec::new();
        info.reserve(n + 2);
        info.extend_from_slice(input_share_text);
        info.push(CTX_ROLE_CLIENT); // Sender role (receiver role set below)
        info.push(if is_leader {
            CTX_ROLE_LEADER
        } else {
            CTX_ROLE_HELPER
        }); // Receiver role

        let mut aad = Vec::with_capacity(58);
        task_id.encode(&mut aad);
        metadata.encode_with_param(&task_config.version, &mut aad);
        // TODO spec: Consider folding the public share into a field called "header".
        encode_u32_bytes(&mut aad, public_share);

        let encoded_input_share = decrypter
            .hpke_decrypt(task_id, &info, &aad, encrypted_input_share)
            .await?;
        // For Draft02, the encoded input share is the VDAF-specific payload, but for Draft03 and
        // later it is a serialized PlaintextInputShare.  For simplicity in later code, we wrap the Draft02
        // payload into a PlaintextInputShare.
        let input_share = match task_config.version {
            DapVersion::Draft02 => PlaintextInputShare {
                extensions: vec![],
                payload: encoded_input_share,
            },
            _ => PlaintextInputShare::get_decoded(&encoded_input_share)
                .map_err(|e| DapAbort::from_codec_error(e, task_id.clone()))?,
        };

        let agg_id = usize::from(!is_leader);
        match (self, &task_config.vdaf_verify_key) {
            (Self::Prio3(ref prio3_config), VdafVerifyKey::Prio3(ref verify_key)) => {
                Ok(prio3_prepare_init(
                    prio3_config,
                    verify_key,
                    agg_id,
                    &metadata.id.0,
                    public_share,
                    &input_share.payload,
                )?)
            }
            (Self::Prio2 { dimension }, VdafVerifyKey::Prio2(ref verify_key)) => {
                Ok(prio2_prepare_init(
                    *dimension,
                    verify_key,
                    agg_id,
                    &metadata.id.0,
                    public_share,
                    &input_share.payload,
                )?)
            }
            _ => Err(fatal_error!(err = "VDAF verify key does not match config")),
        }
    }

    /// Initialize the aggregation flow for a sequence of reports. The outputs are the Leader's
    /// state for the aggregation flow and the initial aggregate request to be sent to the Helper.
    /// This method is called by the Leader.
    #[allow(clippy::too_many_arguments)]
    pub async fn produce_agg_job_init_req(
        &self,
        decrypter: &impl HpkeDecrypter,
        task_id: &TaskId,
        task_config: &DapTaskConfig,
        agg_job_id: &MetaAggregationJobId<'_>,
        part_batch_sel: &PartialBatchSelector,
        reports: Vec<Report>,
        metrics: &ContextualizedDaphneMetrics<'_>,
    ) -> Result<DapLeaderTransition<AggregationJobInitReq>, DapAbort> {
        let mut processed = HashSet::with_capacity(reports.len());
        let mut states = Vec::with_capacity(reports.len());
        let mut seq = Vec::with_capacity(reports.len());
        for report in reports.into_iter() {
            if processed.contains(&report.report_metadata.id) {
                return Err(fatal_error!(
                    err = "tried to process report sequence with non-unique report IDs",
                    non_unique_id = %report.report_metadata.id,
                )
                .into());
            }
            processed.insert(report.report_metadata.id.clone());

            let (leader_share, helper_share) = {
                let mut it = report.encrypted_input_shares.into_iter();
                (it.next().unwrap(), it.next().unwrap())
            };

            match self
                .consume_report_share(
                    decrypter,
                    true, // is_leader
                    task_id,
                    task_config,
                    &report.report_metadata,
                    &report.public_share,
                    &leader_share,
                )
                .await
            {
                Ok((step, message)) => {
                    states.push((
                        step,
                        message,
                        report.report_metadata.time,
                        report.report_metadata.id.clone(),
                    ));
                    seq.push(ReportShare {
                        report_metadata: report.report_metadata,
                        public_share: report.public_share,
                        encrypted_input_share: helper_share,
                    });
                }

                // Skip report that can't be processed any further.
                Err(DapError::Transition(failure)) => {
                    metrics.report_inc_by(&format!("rejected_{failure}"), 1)
                }

                Err(e) => return Err(DapAbort::Internal(Box::new(e))),
            };
        }

        if seq.is_empty() {
            return Ok(DapLeaderTransition::Skip);
        }

        Ok(DapLeaderTransition::Continue(
            DapLeaderState { seq: states },
            AggregationJobInitReq {
                draft02_task_id: task_id.for_request_payload(&task_config.version),
                draft02_agg_job_id: agg_job_id.for_request_payload(),
                agg_param: Vec::default(),
                part_batch_sel: part_batch_sel.clone(),
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
    /// * `agg_job_init_req` is the request sent by the Leader.
    ///
    /// * `version` is the DapVersion to use.
    pub(crate) async fn handle_agg_job_init_req(
        &self,
        decrypter: &impl HpkeDecrypter,
        task_id: &TaskId,
        task_config: &DapTaskConfig,
        agg_job_init_req: &AggregationJobInitReq,
        metrics: &ContextualizedDaphneMetrics<'_>,
    ) -> Result<DapHelperTransition<AggregationJobResp>, DapAbort> {
        let num_reports = agg_job_init_req.report_shares.len();
        let mut processed = HashSet::with_capacity(num_reports);
        let mut states = Vec::with_capacity(num_reports);
        let mut transitions = Vec::with_capacity(num_reports);
        for report_share in agg_job_init_req.report_shares.iter() {
            if processed.contains(&report_share.report_metadata.id) {
                return Err(DapAbort::UnrecognizedMessage {
                    detail: format!(
                        "report ID {} appears twice in the same aggregation job",
                        report_share.report_metadata.id.to_base64url()
                    ),
                    task_id: Some(task_id.clone()),
                });
            }
            processed.insert(report_share.report_metadata.id.clone());

            let var = match self
                .consume_report_share(
                    decrypter,
                    false, // is_leader
                    task_id,
                    task_config,
                    &report_share.report_metadata,
                    &report_share.public_share,
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
                        report_share.report_metadata.time,
                        report_share.report_metadata.id.clone(),
                    ));
                    TransitionVar::Continued(message_data)
                }

                Err(DapError::Transition(failure)) => {
                    metrics.report_inc_by(&format!("rejected_{failure}"), 1);
                    TransitionVar::Failed(failure)
                }

                Err(e) => return Err(DapAbort::Internal(Box::new(e))),
            };

            transitions.push(Transition {
                report_id: report_share.report_metadata.id.clone(),
                var,
            });
        }

        Ok(DapHelperTransition::Continue(
            DapHelperState {
                part_batch_sel: agg_job_init_req.part_batch_sel.clone(),
                seq: states,
            },
            AggregationJobResp { transitions },
        ))
    }

    /// Handle an aggregate response from the Helper. This method is run by the Leader.
    pub fn handle_agg_job_resp(
        &self,
        task_id: &TaskId,
        agg_job_id: &MetaAggregationJobId,
        state: DapLeaderState,
        agg_job_resp: AggregationJobResp,
        version: DapVersion,
        metrics: &ContextualizedDaphneMetrics<'_>,
    ) -> Result<DapLeaderTransition<AggregationJobContinueReq>, DapAbort> {
        if agg_job_resp.transitions.len() != state.seq.len() {
            return Err(DapAbort::UnrecognizedMessage {
                detail: format!(
                    "aggregation job response has {} reports; expected {}",
                    agg_job_resp.transitions.len(),
                    state.seq.len(),
                ),
                task_id: Some(task_id.clone()),
            });
        }

        let mut seq = Vec::with_capacity(state.seq.len());
        let mut states = Vec::with_capacity(state.seq.len());
        for (helper, (leader_step, leader_message, leader_time, leader_report_id)) in agg_job_resp
            .transitions
            .into_iter()
            .zip(state.seq.into_iter())
        {
            // TODO spec: Consider removing the report ID from the AggregationJobResp.
            if helper.report_id != leader_report_id {
                return Err(DapAbort::UnrecognizedMessage {
                    detail: format!(
                        "report ID {} appears out of order in aggregation job response",
                        helper.report_id.to_base64url()
                    ),
                    task_id: Some(task_id.clone()),
                });
            }

            let helper_message = match &helper.var {
                TransitionVar::Continued(message) => message,

                // Skip report that can't be processed any further.
                TransitionVar::Failed(failure) => {
                    metrics.report_inc_by(&format!("rejected_{failure}"), 1);
                    continue;
                }

                // TODO Log the fact that the helper sent an unexpected message.
                TransitionVar::Finished => {
                    return Err(DapAbort::UnrecognizedMessage {
                        detail: "helper sent unexpected `Finished` message".to_string(),
                        task_id: Some(task_id.clone()),
                    })
                }
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
                    let checksum = ring::digest::digest(
                        &ring::digest::SHA256,
                        &leader_report_id.get_encoded(),
                    );

                    states.push((
                        DapOutputShare {
                            time: leader_time,
                            checksum: checksum.as_ref().try_into().unwrap(),
                            data,
                        },
                        leader_report_id.clone(),
                    ));

                    seq.push(Transition {
                        report_id: leader_report_id,
                        var: TransitionVar::Continued(message),
                    });
                }

                // Skip report that can't be processed any further.
                Err(VdafError::Codec(..)) | Err(VdafError::Vdaf(..)) => {
                    let failure = TransitionFailure::VdafPrepError;
                    metrics.report_inc_by(&format!("rejected_{failure}"), 1);
                }
            };
        }

        if seq.is_empty() {
            return Ok(DapLeaderTransition::Skip);
        }

        Ok(DapLeaderTransition::Uncommitted(
            DapLeaderUncommitted { seq: states },
            AggregationJobContinueReq {
                draft02_task_id: task_id.for_request_payload(&version),
                draft02_agg_job_id: agg_job_id.for_request_payload(),
                round: if version == DapVersion::Draft02 {
                    None
                } else {
                    Some(1)
                },
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
    pub(crate) fn handle_agg_job_cont_req(
        &self,
        task_id: &TaskId,
        agg_job_id: &MetaAggregationJobId,
        state: DapHelperState,
        agg_cont_req: &AggregationJobContinueReq,
        metrics: &ContextualizedDaphneMetrics<'_>,
    ) -> Result<DapHelperTransition<AggregationJobResp>, DapAbort> {
        if let Some(round) = agg_cont_req.round {
            if round == 0 {
                return Err(DapAbort::UnrecognizedMessage {
                    detail: "request shouldn't indicate round 0".into(),
                    task_id: Some(task_id.clone()),
                });
            }
            // TODO(bhalleycf) For now, there is only ever one round, and we don't try to do
            // aggregation-round-skew-recovery.
            if round != 1 {
                return Err(DapAbort::RoundMismatch {
                    detail: format!("The request indicates round {round}; round 1 was expected."),
                    task_id: task_id.clone(),
                    agg_job_id_base64url: agg_job_id.to_base64url(),
                });
            }
        }
        let mut processed = HashSet::with_capacity(state.seq.len());
        let mut recognized = HashSet::with_capacity(state.seq.len());
        for (_, _, report_id) in state.seq.iter() {
            recognized.insert(report_id.clone());
        }
        let num_reports = state.seq.len();
        let mut transitions = Vec::with_capacity(num_reports);
        let mut out_shares = Vec::with_capacity(num_reports);
        let mut leader_iter = agg_cont_req.transitions.iter();
        let mut helper_iter = state.seq.into_iter();
        for leader in &mut leader_iter {
            // If the report ID is not recognized, then respond with a transition failure.
            //
            // TODO spec: Having to enforce this is awkward because, in order to disambiguate the
            // trigger condition from the leader skipping a report that can't be processed, we have
            // to make two passes of the request. (The first step is to compute `recognized`). It
            // would be nice if we didn't have to keep track of the set of processed reports. One
            // way to avoid this would be to require the leader to send the reports in a well-known
            // order, say, in ascending order by ID.
            if !recognized.contains(&leader.report_id) {
                return Err(DapAbort::UnrecognizedMessage {
                    detail: format!(
                        "report ID {} does not appear in the Helper's reports",
                        leader.report_id.to_base64url()
                    ),
                    task_id: Some(task_id.clone()),
                });
            }
            if processed.contains(&leader.report_id) {
                return Err(DapAbort::UnrecognizedMessage {
                    detail: format!(
                        "report ID {} appears twice in the same aggregation job",
                        leader.report_id.to_base64url()
                    ),
                    task_id: Some(task_id.clone()),
                });
            }

            for (helper_step, helper_time, helper_report_id) in &mut helper_iter {
                processed.insert(helper_report_id.clone());
                if helper_report_id != leader.report_id {
                    // Presumably the leader has skipped this report.
                    continue;
                }

                let leader_message = match &leader.var {
                    TransitionVar::Continued(message) => message,

                    // TODO Log the fact that the helper sent an unexpected message.
                    _ => {
                        return Err(DapAbort::UnrecognizedMessage {
                            detail: "helper sent unexpected message instead of `Continued`"
                                .to_string(),
                            task_id: Some(task_id.clone()),
                        })
                    }
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
                            &helper_report_id.get_encoded(),
                        );

                        out_shares.push(DapOutputShare {
                            time: helper_time,
                            checksum: checksum.as_ref().try_into().unwrap(),
                            data,
                        });
                        TransitionVar::Finished
                    }

                    Err(VdafError::Codec(..)) | Err(VdafError::Vdaf(..)) => {
                        let failure = TransitionFailure::VdafPrepError;
                        metrics.report_inc_by(&format!("rejected_{failure}"), 1);
                        TransitionVar::Failed(failure)
                    }
                };

                transitions.push(Transition {
                    report_id: helper_report_id,
                    var,
                });

                break;
            }
        }

        Ok(DapHelperTransition::Finish(
            out_shares,
            AggregationJobResp { transitions },
        ))
    }

    /// Handle the last aggregate response from the Helper. This method is run by the Leader.
    pub fn handle_final_agg_job_resp(
        &self,
        uncommitted: DapLeaderUncommitted,
        agg_job_resp: AggregationJobResp,
        metrics: &ContextualizedDaphneMetrics,
    ) -> Result<Vec<DapOutputShare>, DapAbort> {
        if agg_job_resp.transitions.len() != uncommitted.seq.len() {
            return Err(DapAbort::UnrecognizedMessage {
                detail: format!(
                    "the Leader has {} reports, but it received {} reports from the Helper",
                    uncommitted.seq.len(),
                    agg_job_resp.transitions.len()
                ),
                task_id: None,
            });
        }

        let mut out_shares = Vec::with_capacity(uncommitted.seq.len());
        for (helper, (out_share, leader_report_id)) in agg_job_resp
            .transitions
            .into_iter()
            .zip(uncommitted.seq.into_iter())
        {
            // TODO spec: Consider removing the report ID from the AggregationJobResp.
            if helper.report_id != leader_report_id {
                return Err(DapAbort::UnrecognizedMessage {
                    detail: format!(
                        "report ID {} appears out of order in aggregation job response",
                        helper.report_id.to_base64url()
                    ),
                    task_id: None,
                });
            }

            match &helper.var {
                // TODO Log the fact that the helper sent an unexpected message.
                TransitionVar::Continued(..) => {
                    return Err(DapAbort::UnrecognizedMessage {
                        detail: "helper sent unexpected `Continued` message".to_string(),
                        task_id: None,
                    })
                }

                // Skip report that can't be processed any further.
                TransitionVar::Failed(failure) => {
                    metrics.report_inc_by(&format!("rejected_{failure}"), 1);
                    continue;
                }

                TransitionVar::Finished => out_shares.push(out_share),
            };
        }

        Ok(out_shares)
    }

    /// Encrypt an aggregate share under the Collector's public key. This method is run by the
    /// Leader in reponse to a collect request.
    pub fn produce_leader_encrypted_agg_share(
        &self,
        hpke_config: &HpkeConfig,
        task_id: &TaskId,
        batch_sel: &BatchSelector,
        agg_share: &DapAggregateShare,
        version: DapVersion,
    ) -> Result<HpkeCiphertext, DapAbort> {
        produce_encrypted_agg_share(true, hpke_config, task_id, batch_sel, agg_share, version)
    }

    /// Like [`produce_leader_encrypted_agg_share`](Self::produce_leader_encrypted_agg_share) but run by the Helper in response to an
    /// aggregate-share request.
    pub fn produce_helper_encrypted_agg_share(
        &self,
        hpke_config: &HpkeConfig,
        task_id: &TaskId,
        batch_sel: &BatchSelector,
        agg_share: &DapAggregateShare,
        version: DapVersion,
    ) -> Result<HpkeCiphertext, DapAbort> {
        produce_encrypted_agg_share(false, hpke_config, task_id, batch_sel, agg_share, version)
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
    ///
    /// * `version` is the DapVersion to use.
    //
    // TODO spec: Allow the collector to have multiple HPKE public keys (the way Aggregators do).
    pub async fn consume_encrypted_agg_shares(
        &self,
        decrypter: &impl HpkeDecrypter,
        task_id: &TaskId,
        batch_sel: &BatchSelector,
        report_count: u64,
        encrypted_agg_shares: Vec<HpkeCiphertext>,
        version: DapVersion,
    ) -> Result<DapAggregateResult, DapError> {
        let agg_share_text = match version {
            DapVersion::Draft02 => CTX_AGG_SHARE_DRAFT02,
            DapVersion::Draft04 => CTX_AGG_SHARE_DRAFT04,
            _ => return Err(unimplemented_version()),
        };
        let n: usize = agg_share_text.len();
        let mut info = Vec::new();
        info.reserve(n + 2);
        info.extend_from_slice(agg_share_text);
        info.push(CTX_ROLE_LEADER); // Sender role placeholder
        info.push(CTX_ROLE_COLLECTOR); // Receiver role

        let mut aad = Vec::with_capacity(40);
        task_id.encode(&mut aad);
        batch_sel.encode(&mut aad);

        let mut agg_shares = Vec::with_capacity(encrypted_agg_shares.len());
        for (i, agg_share_ciphertext) in encrypted_agg_shares.iter().enumerate() {
            info[n] = if i == 0 {
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
            return Err(fatal_error!(
                err = "one or more HPKE ciphertexts with unrecognized config ID",
            ));
        }

        let num_measurements = usize::try_from(report_count).unwrap();
        match self {
            Self::Prio3(prio3_config) => {
                Ok(prio3_unshard(prio3_config, num_measurements, agg_shares)?)
            }
            Self::Prio2 { dimension } => {
                Ok(prio2_unshard(*dimension, num_measurements, agg_shares)?)
            }
        }
    }
}

fn produce_encrypted_agg_share(
    is_leader: bool,
    hpke_config: &HpkeConfig,
    task_id: &TaskId,
    batch_sel: &BatchSelector,
    agg_share: &DapAggregateShare,
    version: DapVersion,
) -> Result<HpkeCiphertext, DapAbort> {
    let agg_share_data = agg_share
        .data
        .as_ref()
        .ok_or_else(|| fatal_error!(err = "empty aggregate share"))?
        .get_encoded();

    let agg_share_text = match version {
        DapVersion::Draft02 => CTX_AGG_SHARE_DRAFT02,
        DapVersion::Draft04 => CTX_AGG_SHARE_DRAFT04,
        _ => return Err(unimplemented_version_abort()),
    };
    let n: usize = agg_share_text.len();
    let mut info = Vec::new();
    info.reserve(n + 2);
    info.extend_from_slice(agg_share_text);
    info.push(if is_leader {
        CTX_ROLE_LEADER
    } else {
        CTX_ROLE_HELPER
    }); // Sender role
    info.push(CTX_ROLE_COLLECTOR); // Receiver role

    // TODO spec: Consider adding agg param to AAD.
    let mut aad = Vec::with_capacity(40);
    task_id.encode(&mut aad);
    batch_sel.encode(&mut aad);

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
