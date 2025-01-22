// Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use crate::{
    constants::DapAggregatorRole,
    hpke::{info_and_aad, HpkeDecrypter},
    messages::{
        self, Extension, PlaintextInputShare, ReportError, ReportMetadata, ReportShare, TaskId,
    },
    protocol::{check_no_duplicates, decode_ping_pong_framed, PingPongMessageType},
    vdaf::{VdafConfig, VdafPrepShare, VdafPrepState, VdafVerifyKey},
    DapAggregationParam, DapError, DapTaskConfig, DapVersion,
};
use prio::codec::{CodecError, ParameterizedDecode as _};
use std::{
    borrow::Cow,
    ops::{Deref, Range},
};

/// Report state during aggregation initialization after the VDAF preparation step.
///
/// The `Peer` parameter can be:
/// - `()` if the report came from a client.
/// - [`WithPeerPrepShare`] if the report came from the leader.
#[allow(clippy::large_enum_variant)]
#[derive(Clone)]
#[cfg_attr(any(test, feature = "test-utils"), derive(Debug, deepsize::DeepSizeOf))]
pub enum InitializedReport<Peer> {
    Ready {
        metadata: ReportMetadata,
        public_share: Vec<u8>,
        prep_share: VdafPrepShare,
        prep_state: VdafPrepState,
        peer_prep_share: Peer,
    },
    Rejected {
        metadata: ReportMetadata,
        report_err: ReportError,
    },
}

pub struct WithPeerPrepShare(Vec<u8>);

impl From<Vec<u8>> for WithPeerPrepShare {
    fn from(value: Vec<u8>) -> Self {
        Self(value)
    }
}

impl Deref for WithPeerPrepShare {
    type Target = Vec<u8>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl InitializedReport<()> {
    pub fn from_client<'s>(
        decrypter: &impl HpkeDecrypter,
        valid_report_range: Range<messages::Time>,
        task_id: &TaskId,
        task_config: impl Into<PartialDapTaskConfigForReportInit<'s>>,
        report_share: ReportShare,
        agg_param: &DapAggregationParam,
    ) -> Result<Self, DapError> {
        let tc: PartialDapTaskConfigForReportInit = task_config.into().clone();
        tracing::warn!("DapTaskConfig times:{}..{}", tc.not_before, tc.not_after);
        Self::initialize(
            decrypter,
            valid_report_range,
            task_id,
            tc.clone(),
            report_share,
            (),
            agg_param,
        )
    }
}

impl InitializedReport<WithPeerPrepShare> {
    pub fn from_leader<'s>(
        decrypter: &impl HpkeDecrypter,
        valid_report_range: Range<messages::Time>,
        task_id: &TaskId,
        task_config: impl Into<PartialDapTaskConfigForReportInit<'s>>,
        report_share: ReportShare,
        prep_init_payload: Vec<u8>,
        agg_param: &DapAggregationParam,
    ) -> Result<Self, DapError> {
        Self::initialize(
            decrypter,
            valid_report_range,
            task_id,
            task_config,
            report_share,
            prep_init_payload,
            agg_param,
        )
    }
}

impl<'s> From<&'s DapTaskConfig> for PartialDapTaskConfigForReportInit<'s> {
    fn from(config: &'s DapTaskConfig) -> Self {
        PartialDapTaskConfigForReportInit {
            not_before: config.not_before,
            not_after: config.not_after,
            method_is_taskprov: config.method_is_taskprov(),
            version: config.version,
            vdaf: Cow::Borrowed(&config.vdaf),
            vdaf_verify_key: config.vdaf_verify_key.clone(),
        }
    }
}

impl<'s> From<&'s PartialDapTaskConfigForReportInit<'_>> for PartialDapTaskConfigForReportInit<'s> {
    fn from(config: &'s PartialDapTaskConfigForReportInit<'_>) -> Self {
        Self {
            not_before: config.not_before,
            not_after: config.not_after,
            method_is_taskprov: config.method_is_taskprov,
            version: config.version,
            vdaf: Cow::Borrowed(&config.vdaf),
            vdaf_verify_key: config.vdaf_verify_key.clone(),
        }
    }
}

#[derive(Clone)]
pub struct PartialDapTaskConfigForReportInit<'s> {
    pub not_before: messages::Time,
    pub not_after: messages::Time,
    pub method_is_taskprov: bool,
    pub version: DapVersion,
    pub vdaf: Cow<'s, VdafConfig>,
    pub vdaf_verify_key: VdafVerifyKey,
}

impl<P> InitializedReport<P> {
    fn initialize<'s, S>(
        decrypter: &impl HpkeDecrypter,
        valid_report_range: Range<messages::Time>,
        task_id: &TaskId,
        task_config: impl Into<PartialDapTaskConfigForReportInit<'s>>,
        report_share: ReportShare,
        prep_init_payload: S,
        agg_param: &DapAggregationParam,
    ) -> Result<Self, DapError>
    where
        S: PrepInitPayload<Decoded = P>,
    {
        let task_config = task_config.into();
        macro_rules! reject {
            ($failure:ident) => {
                {tracing::warn!("Rejected - {}\nTimestamp - {}", ReportError::$failure, report_share.report_metadata.time);
                return Ok(InitializedReport::Rejected {
                    metadata: report_share.report_metadata,
                    report_err: ReportError::$failure,
                })}
            };
        }

        tracing::info!("report timestamp: {}", report_share.report_metadata.time);
        tracing::info!("valid_report_range: {}..{}", valid_report_range.start, valid_report_range.end);
        tracing::info!("task_config.range: {}..{}", task_config.not_before, task_config.not_after);

        match report_share.report_metadata.time {
            t if t >= task_config.not_after => reject!(TaskExpired),
            t if t < task_config.not_before => {tracing::warn!("Reject TaskNotStarted"); reject!(TaskNotStarted)},
            t if t < valid_report_range.start => reject!(ReportDropped),
            t if valid_report_range.end < t => reject!(ReportTooEarly),
            _ => {}
        }

        tracing::warn!("All tests pass");
        match (
            &report_share.report_metadata.public_extensions,
            task_config.version,
        ) {
            (Some(..), crate::DapVersion::Latest) | (None, crate::DapVersion::Draft09) => (),
            (_, _) => reject!(InvalidMessage),
        }
        // decrypt input share
        let PlaintextInputShare {
            private_extensions,
            payload: input_share,
        } = {
            let info = info_and_aad::InputShare {
                version: task_config.version,
                receiver: S::ROLE,
                task_id,
                report_metadata: &report_share.report_metadata,
                public_share: &report_share.public_share,
            };

            let encoded_input_share =
                match decrypter.hpke_decrypt(info, &report_share.encrypted_input_share) {
                    Ok(encoded_input_share) => encoded_input_share,
                    Err(DapError::ReportError(err)) => {
                        return Ok(InitializedReport::Rejected {
                            metadata: report_share.report_metadata,
                            report_err: err,
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
            // Check for duplicates in public and private extensions
            if check_no_duplicates(
                private_extensions
                    .iter()
                    .chain(
                        report_share
                            .report_metadata
                            .public_extensions
                            .as_deref()
                            .unwrap_or_default(),
                    )
                    .map(|e| e.type_code()),
            )
            .is_err()
            {
                reject!(InvalidMessage)
            }

            let mut taskprov_indicated = false;
            for extension in private_extensions.iter().chain(
                report_share
                    .report_metadata
                    .public_extensions
                    .as_deref()
                    .unwrap_or_default(),
            ) {
                match extension {
                    Extension::Taskprov { .. } => {
                        taskprov_indicated = task_config.method_is_taskprov;
                    }
                    // Reject reports with unrecognized extensions.
                    Extension::NotImplemented { .. } => reject!(InvalidMessage),
                }
            }

            if task_config.method_is_taskprov && !taskprov_indicated {
                // taskprov: If the task configuration method is taskprov, then we expect each
                // report to indicate support.
                reject!(InvalidMessage);
            }
        }

        // Decode the ping-pong "initialize" message framing.
        // (draft-irtf-cfrg-vdaf-08, Section 5.8).
        let peer_prep_share = match prep_init_payload.decode_ping_pong_framed() {
            Ok(peer_prep_share) => peer_prep_share,
            Err(e) => {
                tracing::warn!(error = ?e, "rejecting report");
                reject!(VdafPrepError);
            }
        };

        let agg_id = match S::ROLE {
            DapAggregatorRole::Leader => 0,
            DapAggregatorRole::Helper => 1,
        };
        let res = task_config.vdaf.prep_init(
            task_config.version,
            &task_config.vdaf_verify_key,
            *task_id,
            agg_id,
            agg_param,
            report_share.report_metadata.id.as_ref(),
            &report_share.public_share,
            &input_share,
        );

        match res {
            Ok((prep_state, prep_share)) => Ok(InitializedReport::Ready {
                metadata: report_share.report_metadata,
                public_share: report_share.public_share,
                peer_prep_share,
                prep_share,
                prep_state,
            }),
            Err(e) => {
                tracing::warn!(error = ?e, "rejecting report");
                reject!(VdafPrepError);
            }
        }
    }

    pub(crate) fn metadata(&self) -> &ReportMetadata {
        match self {
            Self::Ready { metadata, .. } | Self::Rejected { metadata, .. } => metadata,
        }
    }
}

/// This trait's purpose is to permit sharing the initialization logic of reports from clients and
/// from leaders, by generically implemeting the only part that's different.
trait PrepInitPayload {
    type Decoded;
    const ROLE: DapAggregatorRole;
    fn decode_ping_pong_framed(&self) -> Result<Self::Decoded, CodecError>;
}

impl PrepInitPayload for () {
    type Decoded = ();
    const ROLE: DapAggregatorRole = DapAggregatorRole::Leader;
    fn decode_ping_pong_framed(&self) -> Result<Self::Decoded, CodecError> {
        Ok(())
    }
}

impl PrepInitPayload for Vec<u8> {
    type Decoded = WithPeerPrepShare;
    const ROLE: DapAggregatorRole = DapAggregatorRole::Helper;
    fn decode_ping_pong_framed(&self) -> Result<Self::Decoded, CodecError> {
        decode_ping_pong_framed(self, PingPongMessageType::Initialize)
            .map(|b| WithPeerPrepShare(b.to_vec()))
    }
}
