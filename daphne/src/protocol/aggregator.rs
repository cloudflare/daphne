// Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

#[cfg(any(test, feature = "test-utils"))]
use crate::vdaf::mastic::{mastic_prep_finish, mastic_prep_finish_from_shares, mastic_prep_init};
use crate::{
    error::DapAbort,
    fatal_error,
    hpke::{HpkeConfig, HpkeDecrypter},
    messages::{
        encode_u32_bytes, encode_u32_prefixed, AggregationJobContinueReq, AggregationJobInitReq,
        AggregationJobResp, Base64Encode, BatchSelector, Extension, HpkeCiphertext,
        PartialBatchSelector, PlaintextInputShare, PrepareInit, Report, ReportId, ReportMetadata,
        ReportShare, TaskId, Transition, TransitionFailure, TransitionVar,
    },
    metrics::DaphneMetrics,
    roles::DapReportInitializer,
    vdaf::{
        prio2::{prio2_prep_finish, prio2_prep_finish_from_shares, prio2_prep_init},
        prio3::{prio3_prep_finish, prio3_prep_finish_from_shares, prio3_prep_init},
        VdafError, VdafPrepMessage, VdafPrepState, VdafVerifyKey,
    },
    AggregationJobReportState, DapAggregateShare, DapAggregateSpan, DapAggregationJobState,
    DapAggregationJobUncommitted, DapAggregationParam, DapError, DapHelperAggregationJobTransition,
    DapLeaderAggregationJobTransition, DapOutputShare, DapTaskConfig, DapVersion,
    MetaAggregationJobId, VdafConfig,
};
use prio::codec::{
    encode_u32_items, CodecError, Decode, Encode, ParameterizedDecode, ParameterizedEncode,
};
use replace_with::replace_with_or_abort;
use std::{
    collections::{HashMap, HashSet},
    io::Cursor,
    iter::zip,
};

use super::{
    CTX_AGG_SHARE_DRAFT02, CTX_AGG_SHARE_DRAFT09, CTX_INPUT_SHARE_DRAFT02, CTX_INPUT_SHARE_DRAFT09,
    CTX_ROLE_CLIENT, CTX_ROLE_COLLECTOR, CTX_ROLE_HELPER, CTX_ROLE_LEADER,
};

// Ping-pong message framing as defined in draft-irtf-cfrg-vdaf-08, Section 5.8. We do not
// implement the "continue" message type because we only support 1-round VDAFs.
enum PingPongMessageType {
    Initialize = 0,
    Finish = 2,
}

// This is essentially a re-implementation of a method in the `messages` module. However the goal
// here is to make it zero-copy. See https://github.com/cloudflare/daphne/issues/15.
fn decode_ping_pong_framed(
    bytes: &[u8],
    expected_type: PingPongMessageType,
) -> Result<&[u8], CodecError> {
    let mut r = Cursor::new(bytes);

    let message_type = u8::decode(&mut r)?;
    if message_type != expected_type as u8 {
        return Err(CodecError::UnexpectedValue);
    }

    let message_len = u32::decode(&mut r)?.try_into().unwrap();
    let message_start = usize::try_from(r.position()).unwrap();
    if bytes.len() - message_start < message_len {
        return Err(CodecError::LengthPrefixTooBig(message_len));
    }
    if bytes.len() - message_start > message_len {
        return Err(CodecError::BytesLeftOver(message_len));
    }

    Ok(&bytes[message_start..])
}

/// Report state during aggregation initialization.
pub trait EarlyReportState {
    fn metadata(&self) -> &ReportMetadata;
    fn is_ready(&self) -> bool;
}

/// The state of a report that is unchanged during the initialization flow:
///
/// [`Report`]/[`PrepareInit`]
/// -> [`EarlyReportStateConsumed`]
/// -> [`EarlyReportStateInitialized`]
/// -> [`Transition`]
#[derive(Clone)]
#[cfg_attr(any(test, feature = "test-utils"), derive(deepsize::DeepSizeOf))]
pub struct ReportState {
    pub metadata: ReportMetadata,
    pub public_share: Vec<u8>,
    // comes from [`PrepareInit::draft_latest_payload`]
    pub draft_latest_prep_init_payload: Option<Vec<u8>>,
}

/// Report state during aggregation initialization after consuming the report share. This involves
/// decryption as well a few validation steps.
#[derive(Clone)]
#[cfg_attr(any(test, feature = "test-utils"), derive(deepsize::DeepSizeOf))]
pub enum EarlyReportStateConsumed {
    Ready {
        state: ReportState,
        input_share: Vec<u8>,
    },
    Rejected {
        metadata: ReportMetadata,
        failure: TransitionFailure,
    },
}

impl EarlyReportStateConsumed {
    pub(crate) async fn consume(
        decrypter: &impl HpkeDecrypter,
        is_leader: bool,
        task_id: &TaskId,
        task_config: &DapTaskConfig,
        state: ReportState,
        encrypted_input_share: HpkeCiphertext,
    ) -> Result<EarlyReportStateConsumed, DapError> {
        if state.metadata.time >= task_config.expiration {
            return Ok(Self::Rejected {
                metadata: state.metadata,
                failure: TransitionFailure::TaskExpired,
            });
        }

        let input_share_text = match task_config.version {
            DapVersion::Draft02 => CTX_INPUT_SHARE_DRAFT02,
            DapVersion::Draft09 | DapVersion::Latest => CTX_INPUT_SHARE_DRAFT09,
        };
        let n: usize = input_share_text.len();
        let mut info = Vec::with_capacity(n + 2);
        info.extend_from_slice(input_share_text);
        info.push(CTX_ROLE_CLIENT); // Sender role (receiver role set below)
        info.push(if is_leader {
            CTX_ROLE_LEADER
        } else {
            CTX_ROLE_HELPER
        }); // Receiver role

        let mut aad = Vec::with_capacity(58);
        task_id.encode(&mut aad).map_err(DapError::encoding)?;
        state
            .metadata
            .encode_with_param(&task_config.version, &mut aad)
            .map_err(DapError::encoding)?;
        encode_u32_bytes(&mut aad, &state.public_share).map_err(DapError::encoding)?;

        let encoded_input_share = match decrypter
            .hpke_decrypt(task_id, &info, &aad, &encrypted_input_share)
            .await
        {
            Ok(encoded_input_share) => encoded_input_share,
            Err(DapError::Transition(failure)) => {
                return Ok(Self::Rejected {
                    metadata: state.metadata,
                    failure,
                })
            }
            Err(e) => return Err(e),
        };

        // draft02 compatibility: The plaintext is passed to the VDAF directly. In the latest
        // draft, the plaintext also encodes the report extensions.
        let (input_share, draft09_extensions) = match task_config.version {
            DapVersion::Draft02 => (encoded_input_share, None),
            DapVersion::Draft09 | DapVersion::Latest => {
                match PlaintextInputShare::get_decoded_with_param(
                    &task_config.version,
                    &encoded_input_share,
                ) {
                    Ok(input_share) => (input_share.payload, Some(input_share.extensions)),
                    Err(..) => {
                        return Ok(Self::Rejected {
                            metadata: state.metadata,
                            failure: TransitionFailure::InvalidMessage,
                        })
                    }
                }
            }
        };

        // Handle report extensions.
        {
            let extensions = match task_config.version {
                DapVersion::Draft09 | DapVersion::Latest => draft09_extensions.as_ref().unwrap(),
                DapVersion::Draft02 => state.metadata.draft02_extensions.as_ref().unwrap(),
            };

            let mut taskprov_indicated = false;
            let mut seen: HashSet<u16> = HashSet::with_capacity(extensions.len());
            for extension in extensions {
                // Reject reports with duplicated extensions.
                if !seen.insert(extension.type_code()) {
                    return Ok(Self::Rejected {
                        metadata: state.metadata,
                        failure: TransitionFailure::InvalidMessage,
                    });
                }

                match (task_config.version, extension) {
                    (.., Extension::Taskprov { .. }) if task_config.method_is_taskprov() => {
                        taskprov_indicated = true;
                    }

                    // Reject reports with unrecognized extensions.
                    (DapVersion::Draft09 | DapVersion::Latest, ..) => {
                        return Ok(Self::Rejected {
                            metadata: state.metadata,
                            failure: TransitionFailure::InvalidMessage,
                        })
                    }

                    // draft02 compatibility: Ignore unrecognized extensions.
                    (DapVersion::Draft02, ..) => (),
                }
            }

            if task_config.method_is_taskprov() && !taskprov_indicated {
                // taskprov: If the task configuration method is taskprov, then we expect each
                // report to indicate support.
                return Ok(Self::Rejected {
                    metadata: state.metadata,
                    failure: TransitionFailure::InvalidMessage,
                });
            }
        }

        Ok(Self::Ready { state, input_share })
    }

    /// Convert this `EarlyReportStateConsumed` into a rejected [`EarlyReportStateInitialized`] using
    /// `failure` as the reason. If this is already a rejected report, the passed in `failure`
    /// value overwrites the previous one.
    pub fn into_initialized_rejected_due_to(
        self,
        failure: TransitionFailure,
    ) -> EarlyReportStateInitialized {
        let metadata = match self {
            Self::Ready {
                state: ReportState { metadata, .. },
                ..
            }
            | Self::Rejected { metadata, .. } => metadata,
        };
        EarlyReportStateInitialized::Rejected { metadata, failure }
    }
}

impl EarlyReportState for EarlyReportStateConsumed {
    fn metadata(&self) -> &ReportMetadata {
        match self {
            Self::Ready {
                state: ReportState { metadata, .. },
                ..
            }
            | Self::Rejected { metadata, .. } => metadata,
        }
    }

    fn is_ready(&self) -> bool {
        matches!(self, Self::Ready { .. })
    }
}

/// Report state during aggregation initialization after the VDAF preparation step.
#[derive(Clone)]
#[cfg_attr(any(test, feature = "test-utils"), derive(deepsize::DeepSizeOf))]
pub enum EarlyReportStateInitialized {
    Ready {
        state: ReportState,
        vdaf_state: VdafPrepState,
        message: VdafPrepMessage,
    },
    Rejected {
        metadata: ReportMetadata,
        failure: TransitionFailure,
    },
}

impl EarlyReportStateInitialized {
    /// Initialize VDAF preparation for a report. This method is meant to be called by
    /// [`DapReportInitializer`].
    pub fn initialize(
        is_leader: bool,
        vdaf_verify_key: &VdafVerifyKey,
        vdaf_config: &VdafConfig,
        agg_param: &DapAggregationParam,
        early_report_state_consumed: EarlyReportStateConsumed,
    ) -> Result<Self, DapError> {
        // We need to use this variable for Mastic, which is currently only enabled in tests or
        // when the feature "test-utils" is enabled.
        let _ = agg_param;

        let (state, input_share) = match early_report_state_consumed {
            EarlyReportStateConsumed::Ready { state, input_share } => (state, input_share),
            EarlyReportStateConsumed::Rejected { metadata, failure } => {
                return Ok(Self::Rejected { metadata, failure })
            }
        };

        let agg_id = usize::from(!is_leader);
        let res = match vdaf_config {
            VdafConfig::Prio3(ref prio3_config) => prio3_prep_init(
                prio3_config,
                vdaf_verify_key,
                agg_id,
                &state.metadata.id.0,
                &state.public_share,
                &input_share,
            ),
            VdafConfig::Prio2 { dimension } => prio2_prep_init(
                *dimension,
                vdaf_verify_key,
                agg_id,
                &state.metadata.id.0,
                &state.public_share,
                &input_share,
            ),
            #[cfg(any(test, feature = "test-utils"))]
            VdafConfig::Mastic {
                input_size,
                weight_config,
            } => mastic_prep_init(
                *input_size,
                *weight_config,
                vdaf_verify_key,
                agg_param,
                &state.public_share,
                input_share.as_ref(),
            ),
        };

        let early_report_state_initialized = match res {
            Ok((vdaf_state, message)) => Self::Ready {
                state,
                vdaf_state,
                message,
            },
            Err(..) => Self::Rejected {
                metadata: state.metadata,
                failure: TransitionFailure::VdafPrepError,
            },
        };
        Ok(early_report_state_initialized)
    }

    /// Turn this report into a rejected report using `failure` as the reason for it's rejection.
    pub fn reject_due_to(&mut self, failure: TransitionFailure) {
        // this never aborts because the closure never panics
        replace_with_or_abort(self, |self_| {
            let metadata = match self_ {
                Self::Rejected { metadata, .. }
                | Self::Ready {
                    state: ReportState { metadata, .. },
                    ..
                } => metadata,
            };
            Self::Rejected { metadata, failure }
        });
    }
}

impl EarlyReportState for EarlyReportStateInitialized {
    fn metadata(&self) -> &ReportMetadata {
        match self {
            Self::Ready {
                state: ReportState { metadata, .. },
                ..
            }
            | Self::Rejected { metadata, .. } => metadata,
        }
    }

    fn is_ready(&self) -> bool {
        matches!(self, Self::Ready { .. })
    }
}

pub(crate) enum ReportProcessedStatus {
    /// The report should be marked as aggregated. However it has already been committed to
    /// storage, so don't do so again.
    Aggregated,

    /// The report should be marked as rejected, e.g., because a replay was detected.
    Rejected(TransitionFailure),
}

impl DapTaskConfig {
    /// Initialize the aggregation flow for a sequence of reports. The outputs are the Leader's
    /// state for the aggregation flow and the initial aggregate request to be sent to the Helper.
    /// This method is called by the Leader.
    #[allow(clippy::too_many_arguments)]
    pub async fn produce_agg_job_init_req(
        &self,
        decrypter: &impl HpkeDecrypter,
        initializer: &impl DapReportInitializer,
        task_id: &TaskId,
        agg_job_id: &MetaAggregationJobId,
        part_batch_sel: &PartialBatchSelector,
        agg_param: &DapAggregationParam,
        reports: Vec<Report>,
        metrics: &dyn DaphneMetrics,
    ) -> Result<DapLeaderAggregationJobTransition<AggregationJobInitReq>, DapError> {
        let mut consumed_reports = Vec::with_capacity(reports.len());
        let mut helper_shares = Vec::with_capacity(reports.len());
        {
            let mut processed = HashSet::with_capacity(reports.len());
            for report in reports {
                if processed.contains(&report.report_metadata.id) {
                    return Err(fatal_error!(
                        err = "tried to process report sequence with non-unique report IDs",
                        non_unique_id = %report.report_metadata.id,
                    ));
                }
                processed.insert(report.report_metadata.id);

                let [leader_share, helper_share] = report.encrypted_input_shares;

                consumed_reports.push(
                    EarlyReportStateConsumed::consume(
                        decrypter,
                        true,
                        task_id,
                        self,
                        ReportState {
                            metadata: report.report_metadata,
                            public_share: report.public_share,
                            draft_latest_prep_init_payload: None,
                        },
                        leader_share,
                    )
                    .await?,
                );
                helper_shares.push(helper_share);
            }
        }
        let initialized_reports = initializer
            .initialize_reports(
                true,
                task_id,
                self,
                part_batch_sel,
                agg_param,
                consumed_reports,
            )
            .await?;

        assert_eq!(initialized_reports.len(), helper_shares.len());

        let mut states = Vec::with_capacity(initialized_reports.len());
        let mut prep_inits = Vec::with_capacity(initialized_reports.len());
        for (initialized_report, helper_share) in zip(initialized_reports, helper_shares) {
            match initialized_report {
                EarlyReportStateInitialized::Ready {
                    state,
                    vdaf_state,
                    message: prep_share,
                } => {
                    // draft02 compatibility: In the latest version, the Leader sends the Helper
                    // its initial prep share in the first request.
                    let (draft02_prep_share, draft09_payload) = match self.version {
                        DapVersion::Draft02 => (Some(prep_share), None),
                        DapVersion::Draft09 | DapVersion::Latest => {
                            let mut outbound = Vec::with_capacity(
                                prep_share
                                    .encoded_len_with_param(&self.version)
                                    .unwrap_or(0)
                                    + 5,
                            );
                            // Add the ping-pong "initialize" message framing
                            // (draft-irtf-cfrg-vdaf-08, Section 5.8).
                            outbound.push(PingPongMessageType::Initialize as u8);
                            encode_u32_items(&mut outbound, &self.version, &[prep_share])
                                .map_err(DapError::encoding)?;
                            (None, Some(outbound))
                        }
                    };

                    states.push(AggregationJobReportState {
                        draft02_prep_share,
                        prep_state: vdaf_state,
                        time: state.metadata.time,
                        report_id: state.metadata.id,
                    });
                    prep_inits.push(PrepareInit {
                        report_share: ReportShare {
                            report_metadata: state.metadata,
                            public_share: state.public_share,
                            encrypted_input_share: helper_share,
                        },
                        draft09_payload,
                    });
                }

                EarlyReportStateInitialized::Rejected { failure, .. } => {
                    // Skip report that can't be processed any further.
                    metrics.report_inc_by(&format!("rejected_{failure}"), 1);
                    continue;
                }
            }
        }

        if prep_inits.is_empty() {
            return Ok(DapLeaderAggregationJobTransition::Finished(
                DapAggregateSpan::default(),
            ));
        }

        Ok(DapLeaderAggregationJobTransition::Continued(
            DapAggregationJobState {
                seq: states,
                part_batch_sel: part_batch_sel.clone(),
            },
            AggregationJobInitReq {
                draft02_task_id: task_id.for_request_payload(&self.version),
                draft02_agg_job_id: agg_job_id.for_request_payload(),
                agg_param: agg_param.get_encoded().map_err(DapError::encoding)?,
                part_batch_sel: part_batch_sel.clone(),
                prep_inits,
            },
        ))
    }

    pub(crate) async fn helper_initialize_reports(
        &self,
        decrypter: &impl HpkeDecrypter,
        initializer: &impl DapReportInitializer,
        task_id: &TaskId,
        agg_job_init_req: AggregationJobInitReq,
    ) -> Result<Vec<EarlyReportStateInitialized>, DapError> {
        let num_reports = agg_job_init_req.prep_inits.len();
        let mut consumed_reports = Vec::with_capacity(num_reports);
        {
            let mut processed = HashSet::with_capacity(num_reports);
            for prep_init in agg_job_init_req.prep_inits {
                if processed.contains(&prep_init.report_share.report_metadata.id) {
                    return Err(DapAbort::InvalidMessage {
                        detail: format!(
                            "report ID {} appears twice in the same aggregation job",
                            prep_init.report_share.report_metadata.id.to_base64url()
                        ),
                        task_id: Some(*task_id),
                    }
                    .into());
                }
                processed.insert(prep_init.report_share.report_metadata.id);

                consumed_reports.push(
                    EarlyReportStateConsumed::consume(
                        decrypter,
                        false,
                        task_id,
                        self,
                        ReportState {
                            metadata: prep_init.report_share.report_metadata,
                            public_share: prep_init.report_share.public_share,
                            draft_latest_prep_init_payload: prep_init.draft09_payload,
                        },
                        prep_init.report_share.encrypted_input_share,
                    )
                    .await?,
                );
            }
        }

        let agg_param =
            DapAggregationParam::get_decoded_with_param(&self.vdaf, &agg_job_init_req.agg_param)
                .map_err(|e| DapAbort::from_codec_error(e, *task_id))?;

        let initialized_reports = initializer
            .initialize_reports(
                false,
                task_id,
                self,
                &agg_job_init_req.part_batch_sel,
                &agg_param,
                consumed_reports,
            )
            .await?;

        Ok(initialized_reports)
    }

    /// Consume an initial aggregate request from the Leader. The outputs are the Helper's state
    /// for the aggregation flow and the aggregate response to send to the Leader. This method is
    /// run by the Helper.
    pub(crate) fn handle_agg_job_init_req(
        &self,
        task_id: &TaskId,
        report_status: &HashMap<ReportId, ReportProcessedStatus>,
        part_batch_sel: &PartialBatchSelector,
        initialized_reports: &[EarlyReportStateInitialized],
        metrics: &dyn DaphneMetrics,
    ) -> Result<DapHelperAggregationJobTransition<AggregationJobResp>, DapError> {
        match self.version {
            DapVersion::Draft02 => Ok(Self::draft02_handle_agg_job_init_req(
                report_status,
                part_batch_sel,
                initialized_reports,
                metrics,
            )),
            DapVersion::Draft09 | DapVersion::Latest => self.draft09_handle_agg_job_init_req(
                task_id,
                report_status,
                part_batch_sel,
                initialized_reports,
            ),
        }
    }

    fn draft02_handle_agg_job_init_req(
        report_status: &HashMap<ReportId, ReportProcessedStatus>,
        part_batch_sel: &PartialBatchSelector,
        initialized_reports: &[EarlyReportStateInitialized],
        metrics: &dyn DaphneMetrics,
    ) -> DapHelperAggregationJobTransition<AggregationJobResp> {
        let num_reports = initialized_reports.len();
        let mut states = Vec::with_capacity(num_reports);
        let mut transitions = Vec::with_capacity(num_reports);

        for initialized_report in initialized_reports {
            let var = match report_status.get(&initialized_report.metadata().id) {
                Some(ReportProcessedStatus::Rejected(failure)) => TransitionVar::Failed(*failure),
                Some(ReportProcessedStatus::Aggregated) => TransitionVar::Finished,
                None => match initialized_report {
                    EarlyReportStateInitialized::Ready {
                        state,
                        vdaf_state: helper_prep_state,
                        message: helper_prep_share,
                    } => {
                        states.push(AggregationJobReportState {
                            draft02_prep_share: None,
                            prep_state: helper_prep_state.clone(),
                            time: state.metadata.time,
                            report_id: state.metadata.id,
                        });
                        helper_prep_share
                            .get_encoded()
                            .map(TransitionVar::Continued)
                            .expect("failed to encode prep share")
                    }

                    EarlyReportStateInitialized::Rejected {
                        metadata: _,
                        failure,
                    } => {
                        metrics.report_inc_by(&format!("rejected_{failure}"), 1);
                        TransitionVar::Failed(*failure)
                    }
                },
            };

            transitions.push(Transition {
                report_id: initialized_report.metadata().id,
                var,
            });
        }

        DapHelperAggregationJobTransition::Continued(
            DapAggregationJobState {
                part_batch_sel: part_batch_sel.clone(),
                seq: states,
            },
            AggregationJobResp { transitions },
        )
    }

    fn draft09_handle_agg_job_init_req(
        &self,
        task_id: &TaskId,
        report_status: &HashMap<ReportId, ReportProcessedStatus>,
        part_batch_sel: &PartialBatchSelector,
        initialized_reports: &[EarlyReportStateInitialized],
    ) -> Result<DapHelperAggregationJobTransition<AggregationJobResp>, DapError> {
        let num_reports = initialized_reports.len();
        let mut agg_span = DapAggregateSpan::default();
        let mut transitions = Vec::with_capacity(num_reports);

        for initialized_report in initialized_reports {
            let var = match report_status.get(&initialized_report.metadata().id) {
                Some(ReportProcessedStatus::Rejected(failure)) => TransitionVar::Failed(*failure),
                Some(ReportProcessedStatus::Aggregated) => TransitionVar::Finished,
                None => match initialized_report {
                    EarlyReportStateInitialized::Ready {
                        state,
                        vdaf_state: helper_prep_state,
                        message: helper_prep_share,
                    } => {
                        let Some(leader_inbound) = &state.draft_latest_prep_init_payload else {
                            return Err(DapAbort::InvalidMessage {
                                detail: "PrepareInit with missing payload".to_string(),
                                task_id: Some(*task_id),
                            }
                            .into());
                        };

                        // Decode the ping-pong "initialize" message framing.
                        // (draft-irtf-cfrg-vdaf-08, Section 5.8).
                        let leader_prep_share = decode_ping_pong_framed(
                            leader_inbound,
                            PingPongMessageType::Initialize,
                        )
                        .map_err(VdafError::Codec);

                        let res =
                            leader_prep_share.and_then(|leader_prep_share| match &self.vdaf {
                                VdafConfig::Prio3(prio3_config) => prio3_prep_finish_from_shares(
                                    prio3_config,
                                    1,
                                    helper_prep_state.clone(),
                                    helper_prep_share.clone(),
                                    leader_prep_share,
                                ),
                                VdafConfig::Prio2 { dimension } => prio2_prep_finish_from_shares(
                                    *dimension,
                                    helper_prep_state.clone(),
                                    helper_prep_share.clone(),
                                    leader_prep_share,
                                ),
                                #[cfg(any(test, feature = "test-utils"))]
                                VdafConfig::Mastic {
                                    input_size: _,
                                    weight_config,
                                } => mastic_prep_finish_from_shares(
                                    *weight_config,
                                    helper_prep_state.clone(),
                                    helper_prep_share.clone(),
                                    leader_prep_share,
                                ),
                            });

                        match res {
                            Ok((data, prep_msg)) => {
                                agg_span.add_out_share(
                                    self,
                                    part_batch_sel,
                                    state.metadata.id,
                                    state.metadata.time,
                                    data,
                                )?;

                                let mut outbound = Vec::with_capacity(1 + prep_msg.len());
                                // Add ping-pong "finish" message framing (draft-irtf-cfrg-vdaf-08,
                                // Section 5.8).
                                outbound.push(PingPongMessageType::Finish as u8);
                                encode_u32_bytes(&mut outbound, &prep_msg)
                                    .map_err(DapError::encoding)?;
                                TransitionVar::Continued(outbound)
                            }

                            Err(VdafError::Codec(..) | VdafError::Vdaf(..)) => {
                                let failure = TransitionFailure::VdafPrepError;
                                TransitionVar::Failed(failure)
                            }

                            Err(VdafError::Dap(e)) => return Err(e),
                        }
                    }

                    EarlyReportStateInitialized::Rejected {
                        metadata: _,
                        failure,
                    } => TransitionVar::Failed(*failure),
                },
            };

            transitions.push(Transition {
                report_id: initialized_report.metadata().id,
                var,
            });
        }

        Ok(DapHelperAggregationJobTransition::Finished(
            agg_span,
            AggregationJobResp { transitions },
        ))
    }

    /// Handle an aggregate response from the Helper. This method is run by the Leader.
    pub fn handle_agg_job_resp(
        &self,
        task_id: &TaskId,
        agg_job_id: &MetaAggregationJobId,
        state: DapAggregationJobState,
        agg_job_resp: AggregationJobResp,
        metrics: &dyn DaphneMetrics,
    ) -> Result<DapLeaderAggregationJobTransition<AggregationJobContinueReq>, DapError> {
        match self.version {
            DapVersion::Draft02 => self
                .draft02_handle_agg_job_resp(task_id, agg_job_id, state, agg_job_resp, metrics)
                .map_err(Into::into),
            DapVersion::Draft09 | DapVersion::Latest => {
                self.draft09_handle_agg_job_resp(task_id, state, agg_job_resp, metrics)
            }
        }
    }

    fn draft02_handle_agg_job_resp(
        &self,
        task_id: &TaskId,
        agg_job_id: &MetaAggregationJobId,
        state: DapAggregationJobState,
        agg_job_resp: AggregationJobResp,
        metrics: &dyn DaphneMetrics,
    ) -> Result<DapLeaderAggregationJobTransition<AggregationJobContinueReq>, DapError> {
        if agg_job_resp.transitions.len() != state.seq.len() {
            return Err(DapAbort::InvalidMessage {
                detail: format!(
                    "aggregation job response has {} reports; expected {}",
                    agg_job_resp.transitions.len(),
                    state.seq.len(),
                ),
                task_id: Some(*task_id),
            }
            .into());
        }

        let mut transitions = Vec::with_capacity(state.seq.len());
        let mut out_shares = Vec::with_capacity(state.seq.len());
        for (helper, leader) in zip(agg_job_resp.transitions, state.seq) {
            if helper.report_id != leader.report_id {
                return Err(DapAbort::InvalidMessage {
                    detail: format!(
                        "report ID {} appears out of order in aggregation job response",
                        helper.report_id.to_base64url()
                    ),
                    task_id: Some(*task_id),
                }
                .into());
            }

            let helper_prep_share = match &helper.var {
                TransitionVar::Continued(payload) => payload,

                // Skip report that can't be processed any further.
                TransitionVar::Failed(failure) => {
                    metrics.report_inc_by(&format!("rejected_{failure}"), 1);
                    continue;
                }

                TransitionVar::Finished => {
                    return Err(DapAbort::InvalidMessage {
                        detail: "helper sent unexpected `Finished` message".to_string(),
                        task_id: Some(*task_id),
                    }
                    .into())
                }
            };

            let res = match &self.vdaf {
                VdafConfig::Prio3(prio3_config) => prio3_prep_finish_from_shares(
                    prio3_config,
                    0,
                    leader.prep_state,
                    leader.draft02_prep_share.unwrap(),
                    helper_prep_share,
                ),
                VdafConfig::Prio2 { dimension } => prio2_prep_finish_from_shares(
                    *dimension,
                    leader.prep_state,
                    leader.draft02_prep_share.unwrap(),
                    helper_prep_share,
                ),
                #[cfg(any(test, feature = "test-utils"))]
                // draft02 compatibility: In theory we should be able to support Mastic (or
                // Poplar1) in a limited capacity. However, this would probably overcomplicate the
                // code. Since we don't plan to use it, don't support it.
                VdafConfig::Mastic { .. } => unreachable!("draft02: Mastic is not supported"),
            };

            match res {
                Ok((data, prep_msg)) => {
                    out_shares.push(DapOutputShare {
                        report_id: leader.report_id,
                        time: leader.time,
                        data,
                    });

                    transitions.push(Transition {
                        report_id: leader.report_id,
                        var: TransitionVar::Continued(prep_msg),
                    });
                }

                // Skip report that can't be processed any further.
                Err(VdafError::Codec(..) | VdafError::Vdaf(..)) => {
                    let failure = TransitionFailure::VdafPrepError;
                    metrics.report_inc_by(&format!("rejected_{failure}"), 1);
                }

                Err(VdafError::Dap(e)) => return Err(e),
            }
        }

        if transitions.is_empty() {
            return Ok(DapLeaderAggregationJobTransition::Finished(
                DapAggregateSpan::default(),
            ));
        }

        Ok(DapLeaderAggregationJobTransition::Uncommitted(
            DapAggregationJobUncommitted {
                seq: out_shares,
                part_batch_sel: state.part_batch_sel,
            },
            AggregationJobContinueReq {
                draft02_task_id: task_id.for_request_payload(&self.version),
                draft02_agg_job_id: agg_job_id.for_request_payload(),
                round: None,
                transitions,
            },
        ))
    }

    fn draft09_handle_agg_job_resp(
        &self,
        task_id: &TaskId,
        state: DapAggregationJobState,
        agg_job_resp: AggregationJobResp,
        metrics: &dyn DaphneMetrics,
    ) -> Result<DapLeaderAggregationJobTransition<AggregationJobContinueReq>, DapError> {
        if agg_job_resp.transitions.len() != state.seq.len() {
            return Err(DapAbort::InvalidMessage {
                detail: format!(
                    "aggregation job response has {} reports; expected {}",
                    agg_job_resp.transitions.len(),
                    state.seq.len(),
                ),
                task_id: Some(*task_id),
            }
            .into());
        }

        let mut agg_span = DapAggregateSpan::default();
        for (helper, leader) in zip(agg_job_resp.transitions, state.seq) {
            if helper.report_id != leader.report_id {
                return Err(DapAbort::InvalidMessage {
                    detail: format!(
                        "report ID {} appears out of order in aggregation job response",
                        helper.report_id.to_base64url()
                    ),
                    task_id: Some(*task_id),
                }
                .into());
            }

            let prep_msg = match &helper.var {
                TransitionVar::Continued(inbound) => {
                    // Decode the ping-pong "finish" message frame (draft-irtf-cfrg-vdaf-08,
                    // Section 5.8). Abort the aggregation job if not found.
                    let Ok(prep_msg) =
                        decode_ping_pong_framed(inbound, PingPongMessageType::Finish)
                    else {
                        // The Helper has done something wrong but may have already committed this
                        // report to storage. If we just reject it, then a batch mismatch is
                        // inevitable.
                        return Err(DapAbort::InvalidMessage {
                            detail: "The Helper's AggregationJobResp is invalid, but it may have already committed its state change. A batch mismatch is inevitable.".to_string(),
                            task_id: Some(*task_id),
                        }.into());
                    };

                    prep_msg
                }

                // Skip report that can't be processed any further.
                TransitionVar::Failed(failure) => {
                    metrics.report_inc_by(&format!("rejected_{failure}"), 1);
                    continue;
                }

                TransitionVar::Finished => {
                    return Err(DapAbort::InvalidMessage {
                        detail: "helper sent unexpected `Finished` message".to_string(),
                        task_id: Some(*task_id),
                    }
                    .into())
                }
            };

            let res = match &self.vdaf {
                VdafConfig::Prio3(prio3_config) => {
                    prio3_prep_finish(prio3_config, leader.prep_state, prep_msg)
                }
                VdafConfig::Prio2 { dimension } => {
                    prio2_prep_finish(*dimension, leader.prep_state, prep_msg)
                }
                #[cfg(any(test, feature = "test-utils"))]
                VdafConfig::Mastic { .. } => mastic_prep_finish(leader.prep_state, prep_msg),
            };

            match res {
                Ok(data) => {
                    agg_span.add_out_share(
                        self,
                        &state.part_batch_sel,
                        leader.report_id,
                        leader.time,
                        data,
                    )?;
                }

                Err(VdafError::Codec(..) | VdafError::Vdaf(..)) => {
                    let failure = TransitionFailure::VdafPrepError;
                    metrics.report_inc_by(&format!("rejected_{failure}"), 1);
                }

                Err(VdafError::Dap(e)) => return Err(e),
            }
        }

        Ok(DapLeaderAggregationJobTransition::Finished(agg_span))
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
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn handle_agg_job_cont_req(
        &self,
        task_id: &TaskId,
        state: &DapAggregationJobState,
        report_status: &HashMap<ReportId, ReportProcessedStatus>,
        agg_job_id: &MetaAggregationJobId,
        agg_job_cont_req: &AggregationJobContinueReq,
    ) -> Result<(DapAggregateSpan<DapAggregateShare>, AggregationJobResp), DapError> {
        match agg_job_cont_req.round {
            Some(1) | None => {}
            Some(0) => {
                return Err(DapAbort::InvalidMessage {
                    detail: "request shouldn't indicate round 0".into(),
                    task_id: Some(*task_id),
                }
                .into())
            }
            // TODO(bhalleycf) For now, there is only ever one round, and we don't try to do
            // aggregation-round-skew-recovery.
            Some(r) => {
                return Err(DapAbort::RoundMismatch {
                    detail: format!("The request indicates round {r}; round 1 was expected."),
                    task_id: *task_id,
                    agg_job_id_base64url: agg_job_id.to_base64url(),
                }
                .into())
            }
        }
        let mut processed = HashSet::with_capacity(state.seq.len());
        let recognized = state
            .seq
            .iter()
            .map(|report_state| report_state.report_id)
            .collect::<HashSet<_>>();
        let mut transitions = Vec::with_capacity(state.seq.len());
        let mut agg_span = DapAggregateSpan::default();
        let mut helper_iter = state.seq.iter();
        for leader in &agg_job_cont_req.transitions {
            // If the report ID is not recognized, then respond with a transition failure.
            //
            // TODO spec: Having to enforce this is awkward because, in order to disambiguate the
            // trigger condition from the leader skipping a report that can't be processed, we have
            // to make two passes of the request. (The first step is to compute `recognized`). It
            // would be nice if we didn't have to keep track of the set of processed reports. One
            // way to avoid this would be to require the leader to send the reports in a well-known
            // order, say, in ascending order by ID.
            if !recognized.contains(&leader.report_id) {
                return Err(DapAbort::InvalidMessage {
                    detail: format!(
                        "report ID {} does not appear in the Helper's reports",
                        leader.report_id.to_base64url()
                    ),
                    task_id: Some(*task_id),
                }
                .into());
            }
            if processed.contains(&leader.report_id) {
                return Err(DapAbort::InvalidMessage {
                    detail: format!(
                        "report ID {} appears twice in the same aggregation job",
                        leader.report_id.to_base64url()
                    ),
                    task_id: Some(*task_id),
                }
                .into());
            }

            // Find the next helper report that matches leader.report_id.
            let next_helper_report = helper_iter.by_ref().find(|report_state| {
                // Presumably the report was removed from the candidate set by the Leader.
                processed.insert(report_state.report_id);
                report_state.report_id == leader.report_id
            });

            let Some(AggregationJobReportState {
                draft02_prep_share: _,
                prep_state,
                time,
                report_id,
            }) = next_helper_report
            else {
                // If the Helper iterator is empty, it means the leader passed in more report ids
                // than we know about.
                break;
            };

            let TransitionVar::Continued(leader_message) = &leader.var else {
                return Err(DapAbort::InvalidMessage {
                    detail: "helper sent unexpected message instead of `Continued`".to_string(),
                    task_id: Some(*task_id),
                }
                .into());
            };

            let var = match report_status.get(&leader.report_id) {
                Some(ReportProcessedStatus::Rejected(failure)) => TransitionVar::Failed(*failure),
                Some(ReportProcessedStatus::Aggregated) => TransitionVar::Finished,
                None => {
                    let res = match &self.vdaf {
                        VdafConfig::Prio3(prio3_config) => {
                            prio3_prep_finish(prio3_config, prep_state.clone(), leader_message)
                        }
                        VdafConfig::Prio2 { dimension } => {
                            prio2_prep_finish(*dimension, prep_state.clone(), leader_message)
                        }
                        #[cfg(any(test, feature = "test-utils"))]
                        // draft02 compatibility: In theory we should be able to support Mastic (or
                        // Poplar1) in a limited capacity. However, this would probably
                        // overcomplicate the code.
                        VdafConfig::Mastic { .. } => {
                            unreachable!("draft02: Mastic is not supported")
                        }
                    };

                    match res {
                        Ok(data) => {
                            agg_span.add_out_share(
                                self,
                                &state.part_batch_sel,
                                *report_id,
                                *time,
                                data,
                            )?;
                            TransitionVar::Finished
                        }

                        Err(VdafError::Codec(..) | VdafError::Vdaf(..)) => {
                            let failure = TransitionFailure::VdafPrepError;
                            TransitionVar::Failed(failure)
                        }

                        Err(VdafError::Dap(e)) => return Err(e),
                    }
                }
            };

            transitions.push(Transition {
                report_id: *report_id,
                var,
            });
        }

        Ok((agg_span, AggregationJobResp { transitions }))
    }

    /// Handle the last aggregate response from the Helper. This method is run by the Leader.
    pub fn handle_final_agg_job_resp(
        &self,
        state: DapAggregationJobUncommitted,
        agg_job_resp: AggregationJobResp,
        metrics: &dyn DaphneMetrics,
    ) -> Result<DapAggregateSpan<DapAggregateShare>, DapError> {
        if agg_job_resp.transitions.len() != state.seq.len() {
            return Err(DapAbort::InvalidMessage {
                detail: format!(
                    "the Leader has {} reports, but it received {} reports from the Helper",
                    state.seq.len(),
                    agg_job_resp.transitions.len()
                ),
                task_id: None,
            }
            .into());
        }

        let mut agg_span = DapAggregateSpan::default();
        for (helper, out_share) in zip(agg_job_resp.transitions, state.seq) {
            if helper.report_id != out_share.report_id {
                return Err(DapAbort::InvalidMessage {
                    detail: format!(
                        "report ID {} appears out of order in aggregation job response",
                        helper.report_id.to_base64url()
                    ),
                    task_id: None,
                }
                .into());
            }

            match &helper.var {
                TransitionVar::Continued(..) => {
                    return Err(DapAbort::InvalidMessage {
                        detail: "helper sent unexpected `Continued` message".to_string(),
                        task_id: None,
                    }
                    .into())
                }

                // Skip report that can't be processed any further.
                TransitionVar::Failed(failure) => {
                    metrics.report_inc_by(&format!("rejected_{failure}"), 1);
                    continue;
                }

                TransitionVar::Finished => agg_span.add_out_share(
                    self,
                    &state.part_batch_sel,
                    out_share.report_id,
                    out_share.time,
                    out_share.data,
                )?,
            };
        }

        Ok(agg_span)
    }

    /// Encrypt an aggregate share under the Collector's public key. This method is run by the
    /// Leader in reponse to a collect request.
    pub fn produce_leader_encrypted_agg_share(
        &self,
        hpke_config: &HpkeConfig,
        task_id: &TaskId,
        batch_sel: &BatchSelector,
        agg_param: &DapAggregationParam,
        agg_share: &DapAggregateShare,
        version: DapVersion,
    ) -> Result<HpkeCiphertext, DapError> {
        produce_encrypted_agg_share(
            true,
            hpke_config,
            task_id,
            batch_sel,
            agg_param,
            agg_share,
            version,
        )
    }

    /// Like [`produce_leader_encrypted_agg_share`](VdafConfig::produce_leader_encrypted_agg_share) but run by the Helper in response to an
    /// aggregate-share request.
    pub fn produce_helper_encrypted_agg_share(
        &self,
        hpke_config: &HpkeConfig,
        task_id: &TaskId,
        batch_sel: &BatchSelector,
        agg_param: &DapAggregationParam,
        agg_share: &DapAggregateShare,
        version: DapVersion,
    ) -> Result<HpkeCiphertext, DapError> {
        produce_encrypted_agg_share(
            false,
            hpke_config,
            task_id,
            batch_sel,
            agg_param,
            agg_share,
            version,
        )
    }
}

fn produce_encrypted_agg_share(
    is_leader: bool,
    hpke_config: &HpkeConfig,
    task_id: &TaskId,
    batch_sel: &BatchSelector,
    agg_param: &DapAggregationParam,
    agg_share: &DapAggregateShare,
    version: DapVersion,
) -> Result<HpkeCiphertext, DapError> {
    let agg_share_data = agg_share
        .data
        .as_ref()
        .ok_or_else(|| fatal_error!(err = "empty aggregate share"))?
        .get_encoded()
        .map_err(DapError::encoding)?;

    let agg_share_text = match version {
        DapVersion::Draft02 => CTX_AGG_SHARE_DRAFT02,
        DapVersion::Draft09 | DapVersion::Latest => CTX_AGG_SHARE_DRAFT09,
    };
    let n: usize = agg_share_text.len();
    let mut info = Vec::with_capacity(n + 2);
    info.extend_from_slice(agg_share_text);
    info.push(if is_leader {
        CTX_ROLE_LEADER
    } else {
        CTX_ROLE_HELPER
    }); // Sender role
    info.push(CTX_ROLE_COLLECTOR); // Receiver role

    let mut aad = Vec::with_capacity(40);
    task_id.encode(&mut aad).map_err(DapError::encoding)?;
    if version != DapVersion::Draft02 {
        encode_u32_prefixed(version, &mut aad, |_version, bytes| agg_param.encode(bytes))
            .map_err(DapError::encoding)?;
    }
    batch_sel.encode(&mut aad).map_err(DapError::encoding)?;

    let (enc, payload) = hpke_config.encrypt(&info, &aad, &agg_share_data)?;
    Ok(HpkeCiphertext {
        config_id: hpke_config.id,
        enc,
        payload,
    })
}
