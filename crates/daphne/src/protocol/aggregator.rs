// Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

#[cfg(feature = "experimental")]
use crate::vdaf::mastic::{mastic_prep_finish, mastic_prep_finish_from_shares, mastic_prep_init};
use crate::{
    constants::{DapAggregatorRole, DapRole},
    error::DapAbort,
    fatal_error,
    hpke::{HpkeConfig, HpkeDecrypter},
    messages::{
        self, encode_u32_bytes, encode_u32_prefixed, AggregationJobInitReq, AggregationJobResp,
        Base64Encode, BatchSelector, Extension, HpkeCiphertext, PartialBatchSelector,
        PlaintextInputShare, PrepareInit, Report, ReportId, ReportMetadata, ReportShare, TaskId,
        Transition, TransitionFailure, TransitionVar,
    },
    metrics::{DaphneMetrics, ReportStatus},
    vdaf::{
        prio2::{prio2_prep_finish, prio2_prep_finish_from_shares, prio2_prep_init},
        prio3::{prio3_prep_finish, prio3_prep_finish_from_shares, prio3_prep_init},
        VdafError, VdafPrepShare, VdafPrepState,
    },
    AggregationJobReportState, DapAggregateShare, DapAggregateSpan, DapAggregationJobState,
    DapAggregationParam, DapError, DapTaskConfig, DapVersion, VdafConfig,
};
use prio::codec::{
    encode_u32_items, CodecError, Decode, Encode, ParameterizedDecode, ParameterizedEncode,
};
use std::{
    collections::{HashMap, HashSet},
    io::Cursor,
    iter::zip,
    ops::Range,
};

use super::{CTX_AGG_SHARE_DRAFT09, CTX_INPUT_SHARE_DRAFT09};
use rayon::iter::{IntoParallelIterator, ParallelIterator as _};

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

/// Report state during aggregation initialization after the VDAF preparation step.
#[expect(clippy::large_enum_variant)]
#[derive(Clone)]
#[cfg_attr(any(test, feature = "test-utils"), derive(Debug, deepsize::DeepSizeOf))]
pub enum InitializedReport {
    Ready {
        metadata: ReportMetadata,
        public_share: Vec<u8>,
        prep_share: VdafPrepShare,
        prep_state: VdafPrepState,
        // Set by the Helper.
        peer_prep_share: Option<Vec<u8>>,
    },
    Rejected {
        metadata: ReportMetadata,
        failure: TransitionFailure,
    },
}

impl InitializedReport {
    #[expect(clippy::too_many_arguments)]
    pub(crate) fn new(
        decrypter: &impl HpkeDecrypter,
        valid_report_range: Range<messages::Time>,
        role: DapAggregatorRole,
        task_id: &TaskId,
        task_config: &DapTaskConfig,
        report_share: ReportShare,
        prep_init_payload: Option<Vec<u8>>,
        // We need to use this variable for Mastic, which is currently fenced by the
        // "experimental" feature.
        #[cfg_attr(not(feature = "experimental"), expect(unused_variables))]
        agg_param: &DapAggregationParam,
    ) -> Result<Self, DapError> {
        macro_rules! reject {
            ($failure:ident) => {
                return Ok(Self::Rejected {
                    metadata: report_share.report_metadata,
                    failure: TransitionFailure::$failure,
                })
            };
        }
        match report_share.report_metadata.time {
            t if t >= task_config.not_after => reject!(TaskExpired),
            t if t < valid_report_range.start => reject!(ReportDropped),
            t if valid_report_range.end < t => reject!(ReportTooEarly),
            _ => {}
        }

        // decrypt input share
        let PlaintextInputShare {
            extensions,
            payload: input_share,
        } = {
            let input_share_text = match task_config.version {
                DapVersion::Draft09 | DapVersion::Latest => CTX_INPUT_SHARE_DRAFT09,
            };
            let mut info = Vec::with_capacity(input_share_text.len() + 2);
            info.extend_from_slice(input_share_text);
            info.push(DapRole::Client as _); // Sender role
            info.push(role as _); // Receiver role

            let mut aad = Vec::with_capacity(58);
            task_id.encode(&mut aad).map_err(DapError::encoding)?;
            report_share
                .report_metadata
                .encode_with_param(&task_config.version, &mut aad)
                .map_err(DapError::encoding)?;
            encode_u32_bytes(&mut aad, &report_share.public_share).map_err(DapError::encoding)?;

            let encoded_input_share =
                match decrypter.hpke_decrypt(&info, &aad, &report_share.encrypted_input_share) {
                    Ok(encoded_input_share) => encoded_input_share,
                    Err(DapError::Transition(failure)) => {
                        return Ok(Self::Rejected {
                            metadata: report_share.report_metadata,
                            failure,
                        })
                    }
                    Err(e) => return Err(e),
                };

            let Ok(plaintext) = PlaintextInputShare::get_decoded_with_param(
                &task_config.version,
                &encoded_input_share,
            ) else {
                reject!(InvalidMessage)
            };
            plaintext
        };

        // Handle report extensions.
        {
            if no_duplicates(extensions.iter().map(|e| e.type_code())).is_err() {
                reject!(InvalidMessage)
            }
            let mut taskprov_indicated = false;
            for extension in extensions {
                match extension {
                    Extension::Taskprov { .. } if task_config.method_is_taskprov() => {
                        taskprov_indicated = true;
                    }

                    // Reject reports with unrecognized extensions.
                    _ => reject!(InvalidMessage),
                }
            }

            if task_config.method_is_taskprov() && !taskprov_indicated {
                // taskprov: If the task configuration method is taskprov, then we expect each
                // report to indicate support.
                reject!(InvalidMessage);
            }
        }

        // Decode the ping-pong "initialize" message framing.
        // (draft-irtf-cfrg-vdaf-08, Section 5.8).
        let peer_prep_share = match prep_init_payload
            .as_ref()
            .map(|payload| decode_ping_pong_framed(payload, PingPongMessageType::Initialize))
            .transpose()
        {
            Ok(peer_prep_share) => peer_prep_share,
            Err(e) => {
                tracing::warn!(error = ?e, "rejecting report");
                reject!(VdafPrepError);
            }
        };

        let agg_id = match role {
            DapAggregatorRole::Leader => 0,
            DapAggregatorRole::Helper => 1,
        };
        let res = match &task_config.vdaf {
            VdafConfig::Prio3(ref prio3_config) => prio3_prep_init(
                prio3_config,
                &task_config.vdaf_verify_key,
                agg_id,
                &report_share.report_metadata.id.0,
                &report_share.public_share,
                &input_share,
            ),
            VdafConfig::Prio2 { dimension } => prio2_prep_init(
                *dimension,
                &task_config.vdaf_verify_key,
                agg_id,
                &report_share.report_metadata.id.0,
                &report_share.public_share,
                &input_share,
            ),
            #[cfg(feature = "experimental")]
            VdafConfig::Mastic {
                input_size,
                weight_config,
            } => mastic_prep_init(
                *input_size,
                *weight_config,
                &task_config.vdaf_verify_key,
                agg_param,
                &report_share.public_share,
                input_share.as_ref(),
            ),
            VdafConfig::Pine(pine) => pine.prep_init(
                &task_config.vdaf_verify_key,
                agg_id,
                &report_share.report_metadata.id.0,
                &report_share.public_share,
                &input_share,
            ),
        };

        Ok(match res {
            Ok((prep_state, prep_share)) => Self::Ready {
                metadata: report_share.report_metadata,
                public_share: report_share.public_share,
                peer_prep_share: peer_prep_share.map(|p| p.to_vec()),
                prep_share,
                prep_state,
            },
            Err(e) => {
                tracing::warn!(error = ?e, "rejecting report");
                reject!(VdafPrepError);
            }
        })
    }

    pub(crate) fn metadata(&self) -> &ReportMetadata {
        match self {
            Self::Ready { metadata, .. } | Self::Rejected { metadata, .. } => metadata,
        }
    }
}

pub(crate) enum ReportProcessedStatus {
    /// The report should be marked as aggregated. However it has already been committed to
    /// storage, so don't do so again.
    Aggregated,

    /// The report should be marked as rejected, e.g., because a replay was detected.
    Rejected(TransitionFailure),
}

#[derive(Default, Debug, Clone, Copy)]
pub enum ReplayProtection {
    #[default]
    Enabled,
    InsecureDisabled,
}

impl ReplayProtection {
    pub const fn enabled(&self) -> bool {
        matches!(self, ReplayProtection::Enabled)
    }

    pub const fn disabled(&self) -> bool {
        matches!(self, ReplayProtection::InsecureDisabled)
    }
}

impl DapTaskConfig {
    /// Leader -> Helper: Initialize the aggregation flow for a sequence of reports. The outputs are the Leader's
    /// state for the aggregation flow and the outbound `AggregationJobInitReq` message.
    #[expect(clippy::too_many_arguments)]
    pub fn produce_agg_job_req<S>(
        &self,
        decrypter: impl HpkeDecrypter,
        valid_report_time_range: Range<messages::Time>,
        task_id: &TaskId,
        part_batch_sel: &PartialBatchSelector,
        agg_param: &DapAggregationParam,
        reports: S,
        metrics: &dyn DaphneMetrics,
    ) -> Result<(DapAggregationJobState, AggregationJobInitReq), DapError>
    where
        S: Iterator<Item = Report>,
    {
        self.produce_agg_job_req_impl(
            decrypter,
            valid_report_time_range,
            task_id,
            part_batch_sel,
            agg_param,
            reports,
            metrics,
            ReplayProtection::Enabled,
        )
    }

    #[expect(clippy::too_many_arguments)]
    fn produce_agg_job_req_impl<S>(
        &self,
        decrypter: impl HpkeDecrypter,
        valid_report_time_range: Range<messages::Time>,
        task_id: &TaskId,
        part_batch_sel: &PartialBatchSelector,
        agg_param: &DapAggregationParam,
        reports: S,
        metrics: &dyn DaphneMetrics,
        replay_protection: ReplayProtection,
    ) -> Result<(DapAggregationJobState, AggregationJobInitReq), DapError>
    where
        S: Iterator<Item = Report>,
    {
        let (report_count_hint, _upper_bound) = reports.size_hint();

        let mut states = Vec::with_capacity(report_count_hint);
        let mut prep_inits = Vec::with_capacity(report_count_hint);

        let mut processed = replay_protection
            .enabled()
            .then(|| HashSet::with_capacity(report_count_hint));
        for report in reports {
            if let Some(processed) = &mut processed {
                if processed.contains(&report.report_metadata.id) {
                    return Err(fatal_error!(
                        err = "tried to process report sequence with non-unique report IDs",
                        non_unique_id = %report.report_metadata.id,
                    ));
                }
                processed.insert(report.report_metadata.id);
            }

            let [leader_share, helper_share] = report.encrypted_input_shares;

            let initialized_report = InitializedReport::new(
                &decrypter,
                valid_report_time_range.clone(),
                DapAggregatorRole::Leader,
                task_id,
                self,
                ReportShare {
                    report_metadata: report.report_metadata,
                    public_share: report.public_share,
                    encrypted_input_share: leader_share,
                },
                None,
                agg_param,
            )?;
            match initialized_report {
                InitializedReport::Ready {
                    metadata,
                    public_share,
                    peer_prep_share: _,
                    prep_share,
                    prep_state,
                } => {
                    let payload = {
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
                        outbound
                    };

                    states.push(AggregationJobReportState {
                        prep_state,
                        time: metadata.time,
                        report_id: metadata.id,
                    });
                    prep_inits.push(PrepareInit {
                        report_share: ReportShare {
                            report_metadata: metadata,
                            public_share,
                            encrypted_input_share: helper_share,
                        },
                        payload,
                    });
                }

                InitializedReport::Rejected { failure, .. } => {
                    // Skip report that can't be processed any further.
                    metrics.report_inc_by(ReportStatus::Rejected(failure), 1);
                    continue;
                }
            }
        }

        Ok((
            DapAggregationJobState {
                seq: states,
                part_batch_sel: part_batch_sel.clone(),
            },
            AggregationJobInitReq {
                agg_param: agg_param.get_encoded().map_err(DapError::encoding)?,
                part_batch_sel: part_batch_sel.clone(),
                prep_inits,
            },
        ))
    }

    #[expect(clippy::too_many_arguments)]
    #[cfg(any(test, feature = "test-utils"))]
    pub fn test_produce_agg_job_req<S>(
        &self,
        decrypter: impl HpkeDecrypter,
        valid_report_time_range: Range<messages::Time>,
        task_id: &TaskId,
        part_batch_sel: &PartialBatchSelector,
        agg_param: &DapAggregationParam,
        reports: S,
        metrics: &dyn DaphneMetrics,
        replay_protection: ReplayProtection,
    ) -> Result<(DapAggregationJobState, AggregationJobInitReq), DapError>
    where
        S: Iterator<Item = Report>,
    {
        self.produce_agg_job_req_impl(
            decrypter,
            valid_report_time_range,
            task_id,
            part_batch_sel,
            agg_param,
            reports,
            metrics,
            replay_protection,
        )
    }

    /// Helper: Consume the `AggregationJobInitReq` sent by the Leader and return the initialized
    /// reports.
    #[tracing::instrument(skip_all)]
    pub fn consume_agg_job_req<H>(
        &self,
        decrypter: &H,
        valid_report_time_range: Range<messages::Time>,
        task_id: &TaskId,
        agg_job_init_req: AggregationJobInitReq,
        replay_protection: ReplayProtection,
    ) -> Result<Vec<InitializedReport>, DapError>
    where
        H: HpkeDecrypter + Sync,
    {
        let agg_param =
            DapAggregationParam::get_decoded_with_param(&self.vdaf, &agg_job_init_req.agg_param)
                .map_err(|e| DapAbort::from_codec_error(e, *task_id))?;
        if replay_protection.enabled() {
            no_duplicates(
                agg_job_init_req
                    .prep_inits
                    .iter()
                    .map(|p| p.report_share.report_metadata.id),
            )
            .map_err(|id| DapAbort::InvalidMessage {
                detail: format!("report ID {id} appears twice in the same aggregation job"),
                task_id: *task_id,
            })?;
        }

        agg_job_init_req
            .prep_inits
            .into_par_iter()
            .map(|prep_init| {
                InitializedReport::new(
                    decrypter,
                    valid_report_time_range.clone(),
                    DapAggregatorRole::Helper,
                    task_id,
                    self,
                    prep_init.report_share,
                    Some(prep_init.payload),
                    &agg_param,
                )
            })
            .collect()
    }

    /// Helper -> Leader: Produce the `AggregationJobResp` message to send to the Leader and
    /// compute Helper's aggregate share span.
    #[tracing::instrument(skip_all, fields(report_count = report_status.len()))]
    pub(crate) fn produce_agg_job_resp(
        &self,
        report_status: &HashMap<ReportId, ReportProcessedStatus>,
        part_batch_sel: &PartialBatchSelector,
        initialized_reports: &[InitializedReport],
    ) -> Result<(DapAggregateSpan<DapAggregateShare>, AggregationJobResp), DapError> {
        let num_reports = initialized_reports.len();
        let mut agg_span = DapAggregateSpan::default();
        let mut transitions = Vec::with_capacity(num_reports);

        for initialized_report in initialized_reports {
            let status = report_status.get(&initialized_report.metadata().id);
            let var = match status {
                Some(ReportProcessedStatus::Rejected(failure)) => TransitionVar::Failed(*failure),
                Some(ReportProcessedStatus::Aggregated) | None => match initialized_report {
                    InitializedReport::Ready {
                        metadata,
                        public_share: _,
                        peer_prep_share: Some(leader_prep_share),
                        prep_share: helper_prep_share,
                        prep_state: helper_prep_state,
                    } => {
                        let res = match &self.vdaf {
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
                            #[cfg(feature = "experimental")]
                            VdafConfig::Mastic {
                                input_size: _,
                                weight_config,
                            } => mastic_prep_finish_from_shares(
                                *weight_config,
                                helper_prep_state.clone(),
                                helper_prep_share.clone(),
                                leader_prep_share,
                            ),
                            VdafConfig::Pine(pine) => pine.prep_finish_from_shares(
                                1,
                                helper_prep_state.clone(),
                                helper_prep_share.clone(),
                                leader_prep_share,
                            ),
                        };

                        match res {
                            Ok((data, prep_msg)) => {
                                // If we have not processed this report yet, then add the output
                                // share to the aggregate span.
                                if status.is_none() {
                                    agg_span.add_out_share(
                                        self,
                                        part_batch_sel,
                                        metadata.id,
                                        metadata.time,
                                        data,
                                    )?;
                                }

                                let mut outbound = Vec::with_capacity(1 + prep_msg.len());
                                // Add ping-pong "finish" message framing (draft-irtf-cfrg-vdaf-08,
                                // Section 5.8).
                                outbound.push(PingPongMessageType::Finish as u8);
                                encode_u32_bytes(&mut outbound, &prep_msg)
                                    .map_err(DapError::encoding)?;
                                TransitionVar::Continued(outbound)
                            }

                            Err(e @ (VdafError::Codec(..) | VdafError::Vdaf(..))) => {
                                tracing::warn!(error = ?e, "rejecting report");
                                TransitionVar::Failed(TransitionFailure::VdafPrepError)
                            }

                            Err(VdafError::Dap(e)) => return Err(e),
                        }
                    }

                    InitializedReport::Ready {
                        peer_prep_share: None,
                        ..
                    } => return Err(fatal_error!(err = "expected leader prep share, got none")),

                    InitializedReport::Rejected {
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

        Ok((agg_span, AggregationJobResp { transitions }))
    }

    /// Leader: Consume the `AggregationJobResp` message sent by the Helper and compute the
    /// Leader's aggregate share span.
    pub fn consume_agg_job_resp(
        &self,
        task_id: &TaskId,
        state: DapAggregationJobState,
        agg_job_resp: AggregationJobResp,
        metrics: &dyn DaphneMetrics,
    ) -> Result<DapAggregateSpan<DapAggregateShare>, DapError> {
        if agg_job_resp.transitions.len() != state.seq.len() {
            return Err(DapAbort::InvalidMessage {
                detail: format!(
                    "aggregation job response has {} reports; expected {}",
                    agg_job_resp.transitions.len(),
                    state.seq.len(),
                ),
                task_id: *task_id,
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
                    task_id: *task_id,
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
                            task_id: *task_id,
                        }.into());
                    };

                    prep_msg
                }

                // Skip report that can't be processed any further.
                TransitionVar::Failed(failure) => {
                    metrics.report_inc_by(ReportStatus::Rejected(*failure), 1);
                    continue;
                }
            };

            let res = match &self.vdaf {
                VdafConfig::Prio3(prio3_config) => {
                    prio3_prep_finish(prio3_config, leader.prep_state, prep_msg)
                }
                VdafConfig::Prio2 { dimension } => {
                    prio2_prep_finish(*dimension, leader.prep_state, prep_msg)
                }
                #[cfg(feature = "experimental")]
                VdafConfig::Mastic { .. } => mastic_prep_finish(leader.prep_state, prep_msg),
                VdafConfig::Pine(pine) => pine.prep_finish(leader.prep_state, prep_msg),
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

                Err(e @ (VdafError::Codec(..) | VdafError::Vdaf(..))) => {
                    tracing::warn!(error = ?e, "rejecting report");
                    metrics
                        .report_inc_by(ReportStatus::Rejected(TransitionFailure::VdafPrepError), 1);
                }

                Err(VdafError::Dap(e)) => return Err(e),
            }
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
            DapAggregatorRole::Leader,
            hpke_config,
            task_id,
            batch_sel,
            agg_param,
            agg_share,
            version,
        )
    }

    /// Like [`produce_leader_encrypted_agg_share`](Self::produce_leader_encrypted_agg_share) but run by the Helper in response to an
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
            DapAggregatorRole::Helper,
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
    role: DapAggregatorRole,
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

    let agg_share_text = CTX_AGG_SHARE_DRAFT09;
    let n: usize = agg_share_text.len();
    let mut info = Vec::with_capacity(n + 2);
    info.extend_from_slice(agg_share_text);
    info.push(role as _); // Sender role
    info.push(DapRole::Collector as _); // Receiver role

    let mut aad = Vec::with_capacity(40);
    task_id.encode(&mut aad).map_err(DapError::encoding)?;
    encode_u32_prefixed(version, &mut aad, |_version, bytes| agg_param.encode(bytes))
        .map_err(DapError::encoding)?;
    batch_sel
        .encode_with_param(&version, &mut aad)
        .map_err(DapError::encoding)?;

    hpke_config.encrypt(&info, &aad, &agg_share_data)
}

/// checks if an iterator has no duplicate items, returns the ok if there are no dups or an error
/// with the first offending item.
fn no_duplicates<I>(iterator: I) -> Result<(), I::Item>
where
    I: Iterator,
    I::Item: Eq + std::hash::Hash + Copy,
{
    let (lower, upper) = iterator.size_hint();
    let mut seen = HashSet::with_capacity(upper.unwrap_or(lower));

    for item in iterator {
        if !seen.insert(item) {
            return Err(item);
        }
    }
    Ok(())
}
