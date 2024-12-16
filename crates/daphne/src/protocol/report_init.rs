// Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

#[cfg(feature = "experimental")]
use crate::vdaf::mastic::mastic_prep_init;
use crate::{
    constants::DapAggregatorRole,
    hpke::{info_and_aad, HpkeDecrypter},
    messages::{
        self, Extension, PlaintextInputShare, ReportMetadata, ReportShare, TaskId,
        TransitionFailure,
    },
    protocol::{decode_ping_pong_framed, no_duplicates, PingPongMessageType},
    vdaf::{
        prio2::prio2_prep_init, prio2_draft09::prio2_draft09_prep_init, prio3::prio3_prep_init,
        prio3_draft09::prio3_draft09_prep_init, VdafConfig, VdafPrepShare, VdafPrepState,
    },
    DapAggregationParam, DapError, DapTaskConfig,
};
use prio::codec::{CodecError, ParameterizedDecode as _};
use std::ops::{Deref, Range};

/// Report state during aggregation initialization after the VDAF preparation step.
///
/// The `Peer` parameter can be:
/// - `()` if the report came from a client.
/// - [`WithPeerPrepShare`] if the report came from the leader.
#[expect(clippy::large_enum_variant)]
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
        failure: TransitionFailure,
    },
}

pub struct WithPeerPrepShare(Vec<u8>);

impl Deref for WithPeerPrepShare {
    type Target = Vec<u8>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl InitializedReport<()> {
    pub fn from_client(
        decrypter: &impl HpkeDecrypter,
        valid_report_range: Range<messages::Time>,
        task_id: &TaskId,
        task_config: &DapTaskConfig,
        report_share: ReportShare,
        agg_param: &DapAggregationParam,
    ) -> Result<Self, DapError> {
        Self::initialize(
            decrypter,
            valid_report_range,
            task_id,
            task_config,
            report_share,
            (),
            agg_param,
        )
    }
}

impl InitializedReport<WithPeerPrepShare> {
    pub fn from_leader(
        decrypter: &impl HpkeDecrypter,
        valid_report_range: Range<messages::Time>,
        task_id: &TaskId,
        task_config: &DapTaskConfig,
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

impl<P> InitializedReport<P> {
    fn initialize<S>(
        decrypter: &impl HpkeDecrypter,
        valid_report_range: Range<messages::Time>,
        task_id: &TaskId,
        task_config: &DapTaskConfig,
        report_share: ReportShare,
        prep_init_payload: S,
        // We need to use this variable for Mastic, which is currently fenced by the
        // "experimental" feature.
        #[cfg_attr(not(feature = "experimental"), expect(unused_variables))]
        agg_param: &DapAggregationParam,
    ) -> Result<Self, DapError>
    where
        S: PrepInitPayload<Decoded = P>,
    {
        macro_rules! reject {
            ($failure:ident) => {
                return Ok(InitializedReport::Rejected {
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
                    Err(DapError::Transition(failure)) => {
                        return Ok(InitializedReport::Rejected {
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
        let res = match &task_config.vdaf {
            VdafConfig::Prio3Draft09(ref prio3_config) => prio3_draft09_prep_init(
                prio3_config,
                &task_config.vdaf_verify_key,
                agg_id,
                &report_share.report_metadata.id.0,
                &report_share.public_share,
                &input_share,
            ),
            VdafConfig::Prio3(ref prio3_config) => prio3_prep_init(
                prio3_config,
                &task_config.vdaf_verify_key,
                *task_id,
                agg_id,
                &report_share.report_metadata.id.0,
                &report_share.public_share,
                &input_share,
            ),
            VdafConfig::Prio2Draft09 { dimension } => prio2_draft09_prep_init(
                *dimension,
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
                *task_id,
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
