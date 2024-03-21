// Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

#[cfg(any(test, feature = "test-utils"))]
use crate::vdaf::mastic::{mastic_prep_finish, mastic_prep_finish_from_shares, mastic_prep_init};
use crate::{
    error::DapAbort,
    fatal_error,
    hpke::{HpkeConfig, HpkeDecrypter},
    messages::{
        encode_u32_bytes, encode_u32_prefixed, AggregationJobInitReq, AggregationJobResp,
        Base64Encode, BatchSelector, Extension, HpkeCiphertext, PartialBatchSelector,
        PlaintextInputShare, PrepareInit, ReportId, ReportMetadata, ReportShare, TaskId,
        Transition, TransitionFailure, TransitionVar,
    },
    metrics::{DaphneMetrics, ReportStatus},
    roles::DapReportProcessor,
    vdaf::{
        prio2::{prio2_prep_finish, prio2_prep_finish_from_shares, prio2_prep_init},
        prio3::{prio3_prep_finish, prio3_prep_finish_from_shares, prio3_prep_init},
        VdafError, VdafPrepMessage, VdafPrepState, VdafVerifyKey,
    },
    AggregationJobReportState, DapAggregateShare, DapAggregateSpan, DapAggregationJobState,
    DapAggregationParam, DapError, DapPendingReport, DapTaskConfig, DapVersion, VdafConfig,
};
use futures::{Stream, StreamExt};
use prio::codec::{
    encode_u32_items, CodecError, Decode, Encode, ParameterizedDecode, ParameterizedEncode,
};
use std::{
    collections::{HashMap, HashSet},
    io::Cursor,
    iter::zip,
    pin::pin,
};

use super::{
    CTX_AGG_SHARE_DRAFT09, CTX_INPUT_SHARE_DRAFT09, CTX_ROLE_CLIENT, CTX_ROLE_COLLECTOR,
    CTX_ROLE_HELPER, CTX_ROLE_LEADER,
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

/// Early report state.
///
/// An aggregator begins aggregation of a report a new [`ReportShare`] or the [`ReportId`] of a
/// stored report. The report transitions through three phases before the aggregator produces its
/// outbound message ([`AggregationJobInitReq`] in case of the leader; [`AggregationJobResp`] in
/// case of the helper):
///
/// ```txt
///     ReportShare     ReportId
///         |              |
///         v              v
///  1. EarlyReportStateConsumed
///                 |              +----------+
///                 |------------->| report   |
///                 |<-------------| storage  |
///                 v              +----------+
///  2. EarlyReportStateFetched
///                 |
///                 v
///  3. EarlyReportStateInitialized
/// ```
///
/// 1. [`EarlyReportStateConsumed`]: All of the early validation steps have been completed: The
///    report share has been decrypted and the report extensions have been processed; and the time
///    checks have been performed.
///
/// 2. [`EarlyReportStateFetched`]: The report state has been fetched from storage, if applicable.
///    If the report is new (i.e., this is the first time it has been aggregated), then it has been
///    stored for future aggregation, if applicable (e.g., for heavy hitters).
///
/// 3. [`EarlyReportStateInitialized`]: Preparation has been initialized for the report. The leader
///    will send its prep share, then complete preparation when it gets a response from the helper.
///    On the other hand, the helper already has the leader's prep share at this point, and will
///    complete preparation before producing its response.
pub trait EarlyReportState {
    fn report_id(&self) -> ReportId;
    fn is_ready(&self) -> bool;
}

/// A report that has been consumed. See [`EarlyReportState`].
#[derive(Clone)]
#[cfg_attr(any(test, feature = "test-utils"), derive(deepsize::DeepSizeOf))]
pub enum EarlyReportStateConsumed {
    New {
        metadata: ReportMetadata,
        public_share: Vec<u8>,
        input_share: Vec<u8>,
        // Set by the Helper.
        peer_prep_share: Option<Vec<u8>>,
    },
    /// draft09 compatibility: This variant is only used in the latest version. It is required to
    /// support the heavy hitters mode of operation for DAP.
    Stored {
        id: ReportId,
        // Set by the Helper.
        peer_prep_share: Option<Vec<u8>>,
    },
    Rejected {
        id: ReportId,
        failure: TransitionFailure,
    },
}

impl EarlyReportStateConsumed {
    pub(crate) async fn consume(
        decrypter: &impl HpkeDecrypter,
        processor: &impl DapReportProcessor,
        is_leader: bool,
        task_id: &TaskId,
        task_config: &DapTaskConfig,
        report_share: ReportShare,
        prep_init_payload: Option<Vec<u8>>,
    ) -> Result<EarlyReportStateConsumed, DapError> {
        if report_share.report_metadata.time >= task_config.expiration {
            return Ok(Self::Rejected {
                id: report_share.report_metadata.id,
                failure: TransitionFailure::TaskExpired,
            });
        }

        let valid_report_range = processor.valid_report_time_range();
        if report_share.report_metadata.time < valid_report_range.start {
            // If the report time is before the first valid timestamp, we drop it
            // because it's too late.
            return Ok(EarlyReportStateConsumed::Rejected {
                id: report_share.report_metadata.id,
                failure: TransitionFailure::ReportDropped,
            });
        }

        if valid_report_range.end < report_share.report_metadata.time {
            // If the report time is too far in the future of the maximum allowed
            // time skew so we reject it.
            return Ok(EarlyReportStateConsumed::Rejected {
                id: report_share.report_metadata.id,
                failure: TransitionFailure::ReportTooEarly,
            });
        }

        let input_share_text = CTX_INPUT_SHARE_DRAFT09;
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
        report_share
            .report_metadata
            .encode_with_param(&task_config.version, &mut aad)
            .map_err(DapError::encoding)?;
        encode_u32_bytes(&mut aad, &report_share.public_share).map_err(DapError::encoding)?;

        let encoded_input_share = match decrypter
            .hpke_decrypt(task_id, &info, &aad, &report_share.encrypted_input_share)
            .await
        {
            Ok(encoded_input_share) => encoded_input_share,
            Err(DapError::Transition(failure)) => {
                return Ok(Self::Rejected {
                    id: report_share.report_metadata.id,
                    failure,
                })
            }
            Err(e) => return Err(e),
        };

        let (input_share, extensions) = {
            match PlaintextInputShare::get_decoded_with_param(
                &task_config.version,
                &encoded_input_share,
            ) {
                Ok(input_share) => (input_share.payload, input_share.extensions),
                Err(..) => {
                    return Ok(Self::Rejected {
                        id: report_share.report_metadata.id,
                        failure: TransitionFailure::InvalidMessage,
                    })
                }
            }
        };

        // Handle report extensions.
        {
            let mut taskprov_indicated = false;
            let mut seen: HashSet<u16> = HashSet::with_capacity(extensions.len());
            for extension in extensions {
                // Reject reports with duplicated extensions.
                if !seen.insert(extension.type_code()) {
                    return Ok(Self::Rejected {
                        id: report_share.report_metadata.id,
                        failure: TransitionFailure::InvalidMessage,
                    });
                }

                match extension {
                    Extension::Taskprov { .. } if task_config.method_is_taskprov() => {
                        taskprov_indicated = true;
                    }

                    // Reject reports with unrecognized extensions.
                    _ => {
                        return Ok(Self::Rejected {
                            id: report_share.report_metadata.id,
                            failure: TransitionFailure::InvalidMessage,
                        })
                    }
                }
            }

            if task_config.method_is_taskprov() && !taskprov_indicated {
                // taskprov: If the task configuration method is taskprov, then we expect each
                // report to indicate support.
                return Ok(Self::Rejected {
                    id: report_share.report_metadata.id,
                    failure: TransitionFailure::InvalidMessage,
                });
            }
        }

        // Decode the ping-pong "initialize" message framing.
        // (draft-irtf-cfrg-vdaf-08, Section 5.8).
        let peer_prep_share = match prep_init_payload
            .as_ref()
            .map(|payload| decode_ping_pong_framed(payload, PingPongMessageType::Initialize))
            .transpose()
        {
            Ok(peer_prep_share) => peer_prep_share.map(|bytes| bytes.to_vec()),
            Err(e) => {
                tracing::warn!(error = ?e, "rejecting report");
                return Ok(Self::Rejected {
                    id: report_share.report_metadata.id,
                    failure: TransitionFailure::VdafPrepError,
                });
            }
        };

        Ok(Self::New {
            metadata: report_share.report_metadata,
            public_share: report_share.public_share,
            peer_prep_share,
            input_share,
        })
    }

    #[cfg(test)]
    pub(crate) fn try_into_fetched(self) -> Option<EarlyReportStateFetched> {
        match self {
            Self::New {
                metadata,
                public_share,
                input_share,
                peer_prep_share,
            } => Some(EarlyReportStateFetched::Ready {
                metadata,
                public_share,
                input_share,
                peer_prep_share,
            }),
            Self::Stored { .. } => None,
            Self::Rejected { id, failure } => {
                Some(EarlyReportStateFetched::Rejected { id, failure })
            }
        }
    }
}

impl EarlyReportState for EarlyReportStateConsumed {
    fn report_id(&self) -> ReportId {
        match self {
            Self::New { metadata, .. } => metadata.id,
            Self::Stored { id, .. } | Self::Rejected { id, .. } => *id,
        }
    }

    fn is_ready(&self) -> bool {
        matches!(self, Self::New { .. } | Self::Stored { .. })
    }
}

/// A report that has been fetched. See [`EarlyReportState`].
#[derive(Clone)]
#[cfg_attr(any(test, feature = "test-utils"), derive(deepsize::DeepSizeOf))]
pub enum EarlyReportStateFetched {
    Ready {
        metadata: ReportMetadata,
        public_share: Vec<u8>,
        input_share: Vec<u8>,
        // Set by the Helper.
        peer_prep_share: Option<Vec<u8>>,
    },
    Rejected {
        id: ReportId,
        failure: TransitionFailure,
    },
}

impl EarlyReportState for EarlyReportStateFetched {
    fn report_id(&self) -> ReportId {
        match self {
            Self::Ready { metadata, .. } => metadata.id,
            Self::Rejected { id, .. } => *id,
        }
    }

    fn is_ready(&self) -> bool {
        matches!(self, Self::Ready { .. })
    }
}

impl EarlyReportStateFetched {
    /// Initialize VDAF preparation for a report. This method is meant to be called by
    /// [`DapReportProcessor`].
    pub fn into_initialized(
        self,
        is_leader: bool,
        vdaf_verify_key: &VdafVerifyKey,
        vdaf_config: &VdafConfig,
        agg_param: &DapAggregationParam,
    ) -> Result<EarlyReportStateInitialized, DapError> {
        // TODO heavy hitters: Remove this once we use the aggregation parameter when compiling
        // with the default feature set.
        #[cfg(not(any(test, feature = "test-utils")))]
        let _ = agg_param;

        let (metadata, public_share, input_share, peer_prep_share) = match self {
            Self::Ready {
                metadata,
                public_share,
                input_share,
                peer_prep_share,
            } => (metadata, public_share, input_share, peer_prep_share),
            Self::Rejected { id, failure } => {
                return Ok(EarlyReportStateInitialized::Rejected { id, failure })
            }
        };

        let agg_id = usize::from(!is_leader);
        let res = match vdaf_config {
            VdafConfig::Prio3(ref prio3_config) => prio3_prep_init(
                prio3_config,
                vdaf_verify_key,
                agg_id,
                &metadata.id.0,
                &public_share,
                &input_share,
            ),
            VdafConfig::Prio2 { dimension } => prio2_prep_init(
                *dimension,
                vdaf_verify_key,
                agg_id,
                &metadata.id.0,
                &public_share,
                &input_share,
            ),
            #[cfg(any(test, feature = "test-utils"))]
            VdafConfig::Mastic {
                input_size,
                weight_config,
                threshold: _,
            } => mastic_prep_init(
                *input_size,
                *weight_config,
                vdaf_verify_key,
                agg_param,
                &public_share,
                input_share.as_ref(),
            ),
        };

        let early_report_state_initialized = match res {
            Ok((prep_state, prep_share)) => EarlyReportStateInitialized::Ready {
                metadata,
                public_share,
                peer_prep_share,
                prep_share,
                prep_state,
            },
            Err(e) => {
                tracing::warn!(error = ?e, "rejecting report");
                EarlyReportStateInitialized::Rejected {
                    id: metadata.id,
                    failure: TransitionFailure::VdafPrepError,
                }
            }
        };
        Ok(early_report_state_initialized)
    }
}

/// A report that has been initialized. See [`EarlyReportState`].
#[derive(Clone)]
#[cfg_attr(any(test, feature = "test-utils"), derive(deepsize::DeepSizeOf))]
#[allow(clippy::large_enum_variant)]
pub enum EarlyReportStateInitialized {
    Ready {
        metadata: ReportMetadata,
        public_share: Vec<u8>,
        // Set by the Helper.
        peer_prep_share: Option<Vec<u8>>,
        prep_share: VdafPrepMessage,
        prep_state: VdafPrepState,
    },
    Rejected {
        id: ReportId,
        failure: TransitionFailure,
    },
}

impl EarlyReportState for EarlyReportStateInitialized {
    fn report_id(&self) -> ReportId {
        match self {
            Self::Ready { metadata, .. } => metadata.id,
            Self::Rejected { id, .. } => *id,
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
    /// Leader -> Helper: Initialize the aggregation flow for a sequence of reports. The outputs are the Leader's
    /// state for the aggregation flow and the outbound `AggregationJobInitReq` message.
    #[allow(clippy::too_many_arguments)]
    pub async fn produce_agg_job_req<S>(
        &self,
        decrypter: &impl HpkeDecrypter,
        processor: &impl DapReportProcessor,
        task_id: &TaskId,
        part_batch_sel: &PartialBatchSelector,
        agg_param: &DapAggregationParam,
        reports: S,
        metrics: &dyn DaphneMetrics,
    ) -> Result<(DapAggregationJobState, AggregationJobInitReq), DapError>
    where
        S: Stream<Item = DapPendingReport>,
    {
        let (report_count_hint, _upper_bound) = reports.size_hint();
        let mut consumed_reports = Vec::with_capacity(report_count_hint);
        let mut helper_report_shares = Vec::with_capacity(report_count_hint);
        {
            let mut processed = HashSet::with_capacity(report_count_hint);
            let mut reports = pin!(reports);
            while let Some(pending_report) = reports.next().await {
                let report_id = pending_report.report_id();
                if processed.contains(&report_id) {
                    return Err(fatal_error!(
                        err = "tried to process report sequence with non-unique report IDs",
                        non_unique_id = %report_id,
                    ));
                }
                processed.insert(report_id);

                consumed_reports.push(match pending_report {
                    DapPendingReport::New(report) => {
                        let [leader_share, helper_share] = report.encrypted_input_shares;
                        helper_report_shares.push(Some(helper_share));

                        EarlyReportStateConsumed::consume(
                            decrypter,
                            processor,
                            true,
                            task_id,
                            self,
                            ReportShare {
                                report_metadata: report.report_metadata,
                                public_share: report.public_share,
                                encrypted_input_share: leader_share,
                            },
                            None,
                        )
                        .await?
                    }
                    DapPendingReport::Stored(report_id) => {
                        helper_report_shares.push(None);

                        EarlyReportStateConsumed::Stored {
                            id: report_id,
                            peer_prep_share: None,
                        }
                    }
                });
            }
        }

        let fetched_reports = processor
            .fetch_stored_reports(task_id, consumed_reports)
            .await?;

        let initialized_reports = processor
            .initialize_reports(true, self, agg_param, fetched_reports)
            .await?;

        debug_assert_eq!(initialized_reports.len(), helper_report_shares.len());

        let mut states = Vec::with_capacity(initialized_reports.len());
        let mut prep_inits = Vec::with_capacity(initialized_reports.len());
        for (initialized_report, helper_report_share) in
            zip(initialized_reports, helper_report_shares)
        {
            match initialized_report {
                EarlyReportStateInitialized::Ready {
                    metadata,
                    public_share,
                    peer_prep_share: None,
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

                    prep_inits.push(match helper_report_share {
                        Some(encrypted_input_share) => PrepareInit::New {
                            report_share: ReportShare {
                                report_metadata: metadata,
                                public_share,
                                encrypted_input_share,
                            },
                            payload,
                        },
                        None => {
                            #[cfg(any(test, feature = "test-utils"))]
                            {
                                PrepareInit::Stored {
                                    report_id: metadata.id,
                                    payload,
                                }
                            }
                            #[cfg(not(any(test, feature = "test-utils")))]
                            {
                                unreachable!()
                            }
                        }
                    });
                }
                EarlyReportStateInitialized::Ready {
                    metadata: _,
                    public_share: _,
                    peer_prep_share: Some(_),
                    prep_share: _,
                    prep_state: _,
                } => {
                    return Err(fatal_error!(
                        err = "encountered initialized report with peer prep share set"
                    ))
                }

                EarlyReportStateInitialized::Rejected { failure, .. } => {
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

    /// Helper: Consume the `AggregationJobInitReq` sent by the Leader and return the initialized
    /// reports.
    pub async fn consume_agg_job_req(
        &self,
        decrypter: &impl HpkeDecrypter,
        processor: &impl DapReportProcessor,
        task_id: &TaskId,
        agg_job_init_req: AggregationJobInitReq,
    ) -> Result<Vec<EarlyReportStateInitialized>, DapError> {
        let AggregationJobInitReq {
            agg_param,
            part_batch_sel: _,
            prep_inits,
        } = agg_job_init_req;
        let num_reports = prep_inits.len();
        let mut consumed_reports = Vec::with_capacity(num_reports);
        {
            let mut processed = HashSet::with_capacity(num_reports);
            for prep_init in prep_inits {
                let report_id = prep_init.report_id();
                if processed.contains(&report_id) {
                    return Err(DapAbort::InvalidMessage {
                        detail: format!(
                            "report ID {} appears twice in the same aggregation job",
                            report_id.to_base64url()
                        ),
                        task_id: Some(*task_id),
                    }
                    .into());
                }
                processed.insert(report_id);

                consumed_reports.push(match prep_init {
                    PrepareInit::New {
                        report_share,
                        payload,
                    } => {
                        EarlyReportStateConsumed::consume(
                            decrypter,
                            processor,
                            false,
                            task_id,
                            self,
                            report_share,
                            Some(payload),
                        )
                        .await?
                    }
                    #[cfg(any(test, feature = "test-utils"))]
                    PrepareInit::Stored { report_id, payload } => {
                        // Decode the ping-pong "initialize" message framing.
                        // (draft-irtf-cfrg-vdaf-08, Section 5.8).
                        match decode_ping_pong_framed(&payload, PingPongMessageType::Initialize) {
                            Ok(peer_prep_share) => EarlyReportStateConsumed::Stored {
                                id: report_id,
                                peer_prep_share: Some(peer_prep_share.to_vec()),
                            },
                            Err(_) => EarlyReportStateConsumed::Rejected {
                                id: report_id,
                                failure: TransitionFailure::VdafPrepError,
                            },
                        }
                    }
                });
            }
        }

        let fetched_reports = processor
            .fetch_stored_reports(task_id, consumed_reports)
            .await?;

        let agg_param = DapAggregationParam::get_decoded_with_param(&self.vdaf, &agg_param)
            .map_err(|e| DapAbort::from_codec_error(e, *task_id))?;

        let initialized_reports = processor
            .initialize_reports(false, self, &agg_param, fetched_reports)
            .await?;

        Ok(initialized_reports)
    }

    /// Helper -> Leader: Produce the `AggregationJobResp` message to send to the Leader and
    /// compute Helper's aggregate share span.
    pub(crate) async fn produce_agg_job_resp(
        &self,
        processor: &impl DapReportProcessor,
        task_id: &TaskId,
        report_status: &HashMap<ReportId, ReportProcessedStatus>,
        part_batch_sel: &PartialBatchSelector,
        initialized_reports: &[EarlyReportStateInitialized],
    ) -> Result<(DapAggregateSpan<DapAggregateShare>, AggregationJobResp), DapError> {
        let num_reports = initialized_reports.len();
        let mut agg_span = DapAggregateSpan::default();
        let mut transitions = Vec::with_capacity(num_reports);

        for initialized_report in initialized_reports {
            let var = match report_status.get(&initialized_report.report_id()) {
                Some(ReportProcessedStatus::Rejected(failure)) => TransitionVar::Failed(*failure),
                Some(ReportProcessedStatus::Aggregated) => TransitionVar::Finished,
                None => match initialized_report {
                    EarlyReportStateInitialized::Ready {
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
                            #[cfg(any(test, feature = "test-utils"))]
                            VdafConfig::Mastic {
                                input_size: _,
                                weight_config,
                                threshold: _,
                            } => mastic_prep_finish_from_shares(
                                *weight_config,
                                helper_prep_state.clone(),
                                helper_prep_share.clone(),
                                leader_prep_share,
                            ),
                        };

                        match res {
                            Ok((data, prep_msg)) => {
                                agg_span.add_out_share(
                                    self,
                                    part_batch_sel,
                                    metadata.id,
                                    metadata.time,
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

                            Err(e @ (VdafError::Codec(..) | VdafError::Vdaf(..))) => {
                                tracing::warn!(error = ?e, "rejecting report");
                                TransitionVar::Failed(TransitionFailure::VdafPrepError)
                            }

                            Err(VdafError::Dap(e)) => return Err(e),
                        }
                    }

                    EarlyReportStateInitialized::Ready {
                        peer_prep_share: None,
                        ..
                    } => return Err(fatal_error!(err = "expected leader prep share, got none")),

                    EarlyReportStateInitialized::Rejected { id: _, failure } => {
                        TransitionVar::Failed(*failure)
                    }
                },
            };

            transitions.push(Transition {
                report_id: initialized_report.report_id(),
                var,
            });
        }

        processor
            .mark_stored_rejected(
                task_id,
                transitions
                    .iter()
                    .filter_map(|transition| match transition.var {
                        TransitionVar::Failed(failure) => Some((transition.report_id, failure)),
                        TransitionVar::Finished | TransitionVar::Continued(_) => None,
                    }),
            )
            .await?;

        Ok((agg_span, AggregationJobResp { transitions }))
    }

    /// Leader: Consume the `AggregationJobResp` message sent by the Helper and compute the
    /// Leader's aggregate share span.
    pub async fn consume_agg_job_resp(
        &self,
        processor: &impl DapReportProcessor,
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
                task_id: Some(*task_id),
            }
            .into());
        }

        let mut rejects = Vec::with_capacity(agg_job_resp.transitions.len());
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
                    metrics.report_inc_by(ReportStatus::Rejected(*failure), 1);
                    rejects.push((leader.report_id, *failure));
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

                Err(e @ (VdafError::Codec(..) | VdafError::Vdaf(..))) => {
                    tracing::warn!(error = ?e, "rejecting report");
                    let failure = TransitionFailure::VdafPrepError;
                    metrics.report_inc_by(ReportStatus::Rejected(failure), 1);
                    rejects.push((leader.report_id, failure));
                }

                Err(VdafError::Dap(e)) => return Err(e),
            }
        }

        processor
            .mark_stored_rejected(task_id, rejects.into_iter())
            .await?;

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

    let agg_share_text = CTX_AGG_SHARE_DRAFT09;
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
    encode_u32_prefixed(version, &mut aad, |_version, bytes| agg_param.encode(bytes))
        .map_err(DapError::encoding)?;
    batch_sel.encode(&mut aad).map_err(DapError::encoding)?;

    hpke_config.encrypt(&info, &aad, &agg_share_data)
}
