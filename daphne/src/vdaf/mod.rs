// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Verifiable, Distributed Aggregation Functions
//! ([VDAFs](https://datatracker.ietf.org/doc/draft-irtf-cfrg-vdaf/)).

pub mod prio2;
pub mod prio3;

use crate::{
    error::DapAbort,
    fatal_error,
    hpke::{HpkeConfig, HpkeDecrypter},
    messages::{
        encode_u32_bytes, AggregationJobContinueReq, AggregationJobInitReq, AggregationJobResp,
        BatchSelector, Extension, HpkeCiphertext, PartialBatchSelector, PlaintextInputShare,
        PrepareInit, Report, ReportId, ReportMetadata, ReportShare, TaskId, Time, Transition,
        TransitionFailure, TransitionVar,
    },
    metrics::DaphneMetrics,
    roles::DapReportInitializer,
    vdaf::{
        prio2::{
            prio2_decode_prep_state, prio2_prep_finish, prio2_prep_finish_from_shares,
            prio2_prep_init, prio2_shard, prio2_unshard,
        },
        prio3::{
            prio3_decode_prep_state, prio3_prep_finish, prio3_prep_finish_from_shares,
            prio3_prep_init, prio3_shard, prio3_unshard,
        },
    },
    AggregationJobReportState, DapAggregateResult, DapAggregateShare, DapAggregateSpan,
    DapAggregationJobState, DapAggregationJobUncommitted, DapError,
    DapHelperAggregationJobTransition, DapLeaderAggregationJobTransition, DapMeasurement,
    DapOutputShare, DapTaskConfig, DapVersion, MetaAggregationJobId, VdafConfig,
};
#[cfg(any(test, feature = "test-utils"))]
use prio::field::FieldElement;
use prio::{
    codec::{CodecError, Decode, Encode, ParameterizedDecode, ParameterizedEncode},
    field::{Field128, Field64, FieldPrio2},
    vdaf::{
        prio2::{Prio2PrepareShare, Prio2PrepareState},
        prio3::{Prio3PrepareShare, Prio3PrepareState},
    },
};
use rand::prelude::*;
use replace_with::replace_with_or_abort;
use serde::{Deserialize, Serialize, Serializer};
use std::{
    borrow::Cow,
    collections::{HashMap, HashSet},
};

const CTX_INPUT_SHARE_DRAFT02: &[u8] = b"dap-02 input share";
const CTX_INPUT_SHARE_DRAFT07: &[u8] = b"dap-07 input share";
const CTX_AGG_SHARE_DRAFT02: &[u8] = b"dap-02 aggregate share";
const CTX_AGG_SHARE_DRAFT07: &[u8] = b"dap-07 aggregate share";
const CTX_ROLE_COLLECTOR: u8 = 0;
const CTX_ROLE_CLIENT: u8 = 1;
const CTX_ROLE_LEADER: u8 = 2;
const CTX_ROLE_HELPER: u8 = 3;

pub(crate) const VDAF_VERIFY_KEY_SIZE_PRIO3: usize = 16;
pub(crate) const VDAF_VERIFY_KEY_SIZE_PRIO2: usize = 32;

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
#[cfg_attr(any(test, feature = "test-utils"), derive(deepsize::DeepSizeOf))]
pub enum VdafVerifyKey {
    Prio3(#[serde(with = "hex")] [u8; VDAF_VERIFY_KEY_SIZE_PRIO3]),
    Prio2(#[serde(with = "hex")] [u8; VDAF_VERIFY_KEY_SIZE_PRIO2]),
}

impl AsRef<[u8]> for VdafVerifyKey {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Prio3(ref bytes) => &bytes[..],
            Self::Prio2(ref bytes) => &bytes[..],
        }
    }
}

/// Report state during aggregation initialization.
pub trait EarlyReportState {
    fn metadata(&self) -> &ReportMetadata;
    fn is_ready(&self) -> bool;
}

/// Report state during aggregation initialization after consuming the report share. This involves
/// decryption as well a few validation steps.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EarlyReportStateConsumed<'req> {
    Ready {
        metadata: Cow<'req, ReportMetadata>,
        #[serde(with = "serialize_bytes")]
        public_share: Cow<'req, [u8]>,
        #[serde(with = "serialize_bytes")]
        input_share: Vec<u8>,
    },
    Rejected {
        metadata: Cow<'req, ReportMetadata>,
        failure: TransitionFailure,
    },
}

impl<'req> EarlyReportStateConsumed<'req> {
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn consume(
        decrypter: &impl HpkeDecrypter,
        is_leader: bool,
        task_id: &TaskId,
        task_config: &DapTaskConfig,
        metadata: Cow<'req, ReportMetadata>,
        public_share: Cow<'req, [u8]>,
        encrypted_input_share: &HpkeCiphertext,
    ) -> Result<EarlyReportStateConsumed<'req>, DapError> {
        if metadata.time >= task_config.expiration {
            return Ok(Self::Rejected {
                metadata,
                failure: TransitionFailure::TaskExpired,
            });
        }

        let input_share_text = match task_config.version {
            DapVersion::Draft02 => CTX_INPUT_SHARE_DRAFT02,
            DapVersion::Draft07 => CTX_INPUT_SHARE_DRAFT07,
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
        encode_u32_bytes(&mut aad, public_share.as_ref());

        let encoded_input_share = match decrypter
            .hpke_decrypt(task_id, &info, &aad, encrypted_input_share)
            .await
        {
            Ok(encoded_input_share) => encoded_input_share,
            Err(DapError::Transition(failure)) => return Ok(Self::Rejected { metadata, failure }),
            Err(e) => return Err(e),
        };

        // For Draft02, the encoded input share is the VDAF-specific payload, but for Draft03 and
        // later it is a serialized PlaintextInputShare.  For simplicity in later code, we wrap the Draft02
        // payload into a PlaintextInputShare.
        let input_share = match task_config.version {
            DapVersion::Draft02 => PlaintextInputShare {
                extensions: vec![],
                payload: encoded_input_share,
            },
            DapVersion::Draft07 => match PlaintextInputShare::get_decoded(&encoded_input_share) {
                Ok(input_share) => input_share,
                Err(..) => {
                    return Ok(Self::Rejected {
                        metadata,
                        failure: TransitionFailure::UnrecognizedMessage,
                    })
                }
            },
        };

        Ok(Self::Ready {
            metadata,
            public_share,
            input_share: input_share.payload,
        })
    }

    /// Convert this `EarlyReportStateConsumed` into a rejected [`EarlyReportStateInitialized`] using
    /// `failure` as the reason. If this is already a rejected report, the passed in `failure`
    /// value overwrites the previous one.
    pub fn into_initialized_rejected_due_to(
        self,
        failure: TransitionFailure,
    ) -> EarlyReportStateInitialized<'req> {
        let metadata = match self {
            Self::Ready { metadata, .. } | Self::Rejected { metadata, .. } => metadata,
        };
        EarlyReportStateInitialized::Rejected { metadata, failure }
    }
}

impl EarlyReportState for EarlyReportStateConsumed<'_> {
    fn metadata(&self) -> &ReportMetadata {
        match self {
            Self::Ready { metadata, .. } | Self::Rejected { metadata, .. } => metadata,
        }
    }

    fn is_ready(&self) -> bool {
        matches!(self, Self::Ready { .. })
    }
}

/// Report state during aggregation initialization after the VDAF preparation step.
#[derive(Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EarlyReportStateInitialized<'req> {
    Ready {
        metadata: Cow<'req, ReportMetadata>,
        #[serde(with = "serialize_bytes")]
        public_share: Cow<'req, [u8]>,
        #[serde(serialize_with = "serialize_encodable")]
        state: VdafPrepState,
        #[serde(serialize_with = "serialize_encodable")]
        message: VdafPrepMessage,
    },
    Rejected {
        metadata: Cow<'req, ReportMetadata>,
        failure: TransitionFailure,
    },
}

mod serialize_bytes {
    use serde::{de, Deserializer, Serializer};
    pub(super) fn serialize<S, T>(x: &T, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
        T: AsRef<[u8]>,
    {
        s.serialize_str(&hex::encode(x.as_ref()))
    }

    pub(super) fn deserialize<'de, D, T>(deserializer: D) -> Result<T, D::Error>
    where
        D: Deserializer<'de>,
        T: TryFrom<Vec<u8>>,
        <T as TryFrom<Vec<u8>>>::Error: std::fmt::Display,
    {
        hex::deserialize::<_, Vec<u8>>(deserializer)
            .and_then(|bytes| bytes.try_into().map_err(de::Error::custom))
    }
}

fn serialize_encodable<S, T>(x: &T, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    T: Encode,
{
    s.serialize_str(&hex::encode(x.get_encoded()))
}

impl<'req> EarlyReportStateInitialized<'req> {
    /// Initialize VDAF preparation for a report. This method is meant to be called by
    /// [`DapReportInitializer`].
    pub fn initialize(
        is_leader: bool,
        vdaf_verify_key: &VdafVerifyKey,
        vdaf_config: &VdafConfig,
        early_report_state_consumed: EarlyReportStateConsumed<'req>,
    ) -> Result<Self, DapError> {
        let (metadata, public_share, input_share) = match early_report_state_consumed {
            EarlyReportStateConsumed::Ready {
                metadata,
                public_share,
                input_share,
            } => (metadata, public_share, input_share),
            EarlyReportStateConsumed::Rejected { metadata, failure } => {
                return Ok(Self::Rejected { metadata, failure })
            }
        };

        let agg_id = usize::from(!is_leader);
        let res = match (vdaf_config, vdaf_verify_key) {
            (VdafConfig::Prio3(ref prio3_config), VdafVerifyKey::Prio3(ref verify_key)) => {
                prio3_prep_init(
                    prio3_config,
                    verify_key,
                    agg_id,
                    &metadata.as_ref().id.0,
                    public_share.as_ref(),
                    input_share.as_ref(),
                )
            }
            (VdafConfig::Prio2 { dimension }, VdafVerifyKey::Prio2(ref verify_key)) => {
                prio2_prep_init(
                    *dimension,
                    verify_key,
                    agg_id,
                    &metadata.as_ref().id.0,
                    public_share.as_ref(),
                    input_share.as_ref(),
                )
            }
            _ => return Err(fatal_error!(err = "VDAF verify key does not match config")),
        };

        let early_report_state_initialized = match res {
            Ok((state, message)) => Self::Ready {
                metadata,
                public_share,
                state,
                message,
            },
            Err(..) => Self::Rejected {
                metadata,
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
                Self::Rejected { metadata, .. } | Self::Ready { metadata, .. } => metadata,
            };
            Self::Rejected { metadata, failure }
        });
    }
}

impl EarlyReportState for EarlyReportStateInitialized<'_> {
    fn metadata(&self) -> &ReportMetadata {
        match self {
            Self::Ready { metadata, .. } | Self::Rejected { metadata, .. } => metadata,
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

/// VDAF preparation state.
#[derive(Clone)]
#[cfg_attr(any(test, feature = "test-utils"), derive(Debug, Eq, PartialEq))]
pub enum VdafPrepState {
    Prio2(Prio2PrepareState),
    Prio3Field64(Prio3PrepareState<Field64, 16>),
    Prio3Field128(Prio3PrepareState<Field128, 16>),
}

#[cfg(any(test, feature = "test-utils"))]
impl deepsize::DeepSizeOf for VdafPrepState {
    fn deep_size_of_children(&self, _context: &mut deepsize::Context) -> usize {
        // This method is, as documented, an estimation of the size of the children. Since it can't
        // be known for this type due to it's encapsulation, I will count the size of it as 0.
        //
        // This happens to be correct for helpers but not for leaders
        match self {
            VdafPrepState::Prio2(_)
            | VdafPrepState::Prio3Field64(_)
            | VdafPrepState::Prio3Field128(_) => 0,
        }
    }
}

impl Encode for VdafPrepState {
    fn encode(&self, bytes: &mut Vec<u8>) {
        match self {
            Self::Prio3Field64(state) => state.encode(bytes),
            Self::Prio3Field128(state) => state.encode(bytes),
            Self::Prio2(state) => state.encode(bytes),
        }
    }
}

impl<'a> ParameterizedDecode<(&'a VdafConfig, bool /* is_leader */)> for VdafPrepState {
    fn decode_with_param(
        (vdaf_config, is_leader): &(&VdafConfig, bool),
        bytes: &mut std::io::Cursor<&[u8]>,
    ) -> Result<Self, CodecError> {
        let agg_id = usize::from(!is_leader);
        match vdaf_config {
            VdafConfig::Prio3(ref prio3_config) => {
                Ok(prio3_decode_prep_state(prio3_config, agg_id, bytes)
                    .map_err(|e| CodecError::Other(Box::new(e)))?)
            }
            VdafConfig::Prio2 { dimension } => {
                Ok(prio2_decode_prep_state(*dimension, agg_id, bytes)
                    .map_err(|e| CodecError::Other(Box::new(e)))?)
            }
        }
    }
}

/// VDAF preparation message.
#[derive(Clone)]
#[cfg_attr(any(test, feature = "test-utils"), derive(Debug))]
pub enum VdafPrepMessage {
    Prio2Share(Prio2PrepareShare),
    Prio3ShareField64(Prio3PrepareShare<Field64, 16>),
    Prio3ShareField128(Prio3PrepareShare<Field128, 16>),
}

#[cfg(any(test, feature = "test-utils"))]
impl deepsize::DeepSizeOf for VdafPrepMessage {
    fn deep_size_of_children(&self, _context: &mut deepsize::Context) -> usize {
        match self {
            // The Prio2 prep share consists of three field elements.
            Self::Prio2Share(_msg) => 3 * FieldPrio2::ENCODED_SIZE,
            // The Prio3 prep share consists of an optional XOF seed for the Aggregator's joint
            // randomness part and a sequence of field elements for the Aggregator's verifier
            // share. The length of the verifier share depends on the Prio3 type, which we don't
            // know at this point. Likewise, whether the XOF seed is present depends on the Prio3
            // type.
            Self::Prio3ShareField64(..) | Self::Prio3ShareField128(..) => 0,
        }
    }
}

impl Encode for VdafPrepMessage {
    fn encode(&self, bytes: &mut Vec<u8>) {
        match self {
            Self::Prio3ShareField64(share) => share.encode(bytes),
            Self::Prio3ShareField128(share) => share.encode(bytes),
            Self::Prio2Share(share) => share.encode(bytes),
        }
    }
}

impl ParameterizedDecode<VdafPrepState> for VdafPrepMessage {
    fn decode_with_param(
        state: &VdafPrepState,
        bytes: &mut std::io::Cursor<&[u8]>,
    ) -> Result<Self, CodecError> {
        match state {
            VdafPrepState::Prio3Field64(state) => Ok(VdafPrepMessage::Prio3ShareField64(
                Prio3PrepareShare::decode_with_param(state, bytes)?,
            )),
            VdafPrepState::Prio3Field128(state) => Ok(VdafPrepMessage::Prio3ShareField128(
                Prio3PrepareShare::decode_with_param(state, bytes)?,
            )),
            VdafPrepState::Prio2(state) => Ok(VdafPrepMessage::Prio2Share(
                Prio2PrepareShare::decode_with_param(state, bytes)?,
            )),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VdafAggregateShare {
    Field64(prio::vdaf::AggregateShare<Field64>),
    Field128(prio::vdaf::AggregateShare<Field128>),
    FieldPrio2(prio::vdaf::AggregateShare<FieldPrio2>),
}

#[cfg(any(test, feature = "test-utils"))]
impl deepsize::DeepSizeOf for VdafAggregateShare {
    fn deep_size_of_children(&self, _context: &mut deepsize::Context) -> usize {
        match self {
            VdafAggregateShare::Field64(s) => std::mem::size_of_val(s.as_ref()),
            VdafAggregateShare::Field128(s) => std::mem::size_of_val(s.as_ref()),
            VdafAggregateShare::FieldPrio2(s) => std::mem::size_of_val(s.as_ref()),
        }
    }
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
    /// * `version` is the `DapVersion` to use.
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
        Self::produce_report_with_extensions_for_shares(
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
            DapVersion::Draft07 => vec![],
        };
        let metadata = ReportMetadata {
            id: *report_id,
            time,
            extensions: report_extensions,
        };

        if version != DapVersion::Draft02 {
            let mut encoded: Vec<Vec<u8>> = Vec::new();
            for share in input_shares {
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
            DapVersion::Draft07 => CTX_INPUT_SHARE_DRAFT07,
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
    /// * `version` is the `DapVersion` to use.
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

    /// Initialize the aggregation flow for a sequence of reports. The outputs are the Leader's
    /// state for the aggregation flow and the initial aggregate request to be sent to the Helper.
    /// This method is called by the Leader.
    #[allow(clippy::too_many_arguments)]
    pub async fn produce_agg_job_init_req(
        &self,
        decrypter: &impl HpkeDecrypter,
        initializer: &impl DapReportInitializer,
        task_id: &TaskId,
        task_config: &DapTaskConfig,
        agg_job_id: &MetaAggregationJobId,
        part_batch_sel: &PartialBatchSelector,
        reports: Vec<Report>,
        metrics: &DaphneMetrics,
    ) -> Result<DapLeaderAggregationJobTransition<AggregationJobInitReq>, DapAbort> {
        let mut processed = HashSet::with_capacity(reports.len());
        let mut states = Vec::with_capacity(reports.len());
        let mut seq = Vec::with_capacity(reports.len());
        let mut consumed_reports = Vec::with_capacity(reports.len());
        let mut helper_shares = Vec::with_capacity(reports.len());
        for report in reports {
            if processed.contains(&report.report_metadata.id) {
                return Err(fatal_error!(
                    err = "tried to process report sequence with non-unique report IDs",
                    non_unique_id = %report.report_metadata.id,
                )
                .into());
            }
            processed.insert(report.report_metadata.id);

            let (leader_share, helper_share) = {
                let mut it = report.encrypted_input_shares.into_iter();
                (it.next().unwrap(), it.next().unwrap())
            };

            consumed_reports.push(
                EarlyReportStateConsumed::consume(
                    decrypter,
                    true,
                    task_id,
                    task_config,
                    Cow::Owned(report.report_metadata),
                    Cow::Owned(report.public_share),
                    &leader_share,
                )
                .await?,
            );
            helper_shares.push(helper_share);
        }

        let initialized_reports = initializer
            .initialize_reports(true, task_id, task_config, part_batch_sel, consumed_reports)
            .await?;

        assert_eq!(initialized_reports.len(), helper_shares.len());
        for (initialized_report, helper_share) in initialized_reports
            .into_iter()
            .zip(helper_shares.into_iter())
        {
            match initialized_report {
                EarlyReportStateInitialized::Ready {
                    metadata,
                    public_share,
                    state,
                    message,
                } => {
                    // draft02 compatibility: In the latest version, the Leader sends the Helper
                    // its initial prep share in the first request.
                    let (draft02_prep_share, draft07_payload) = match task_config.version {
                        DapVersion::Draft02 => (Some(message), None),
                        DapVersion::Draft07 => (
                            None,
                            Some(message.get_encoded_with_param(&task_config.version)),
                        ),
                    };

                    states.push(AggregationJobReportState {
                        draft02_prep_share,
                        prep_state: state,
                        time: metadata.time,
                        report_id: metadata.id,
                    });
                    seq.push(PrepareInit {
                        report_share: ReportShare {
                            report_metadata: metadata.into_owned(),
                            public_share: public_share.into_owned(),
                            encrypted_input_share: helper_share,
                        },
                        draft07_payload,
                    });
                }

                EarlyReportStateInitialized::Rejected { failure, .. } => {
                    // Skip report that can't be processed any further.
                    metrics.report_inc_by(&format!("rejected_{failure}"), 1);
                    continue;
                }
            }
        }

        if seq.is_empty() {
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
                draft02_task_id: task_id.for_request_payload(&task_config.version),
                draft02_agg_job_id: agg_job_id.for_request_payload(),
                agg_param: Vec::default(),
                part_batch_sel: part_batch_sel.clone(),
                prep_inits: seq,
            },
        ))
    }

    pub(crate) async fn helper_initialize_reports<'req>(
        &self,
        decrypter: &impl HpkeDecrypter,
        initializer: &impl DapReportInitializer,
        task_id: &TaskId,
        task_config: &DapTaskConfig,
        agg_job_init_req: &'req AggregationJobInitReq,
    ) -> Result<Vec<EarlyReportStateInitialized<'req>>, DapAbort> {
        let num_reports = agg_job_init_req.prep_inits.len();
        let mut processed = HashSet::with_capacity(num_reports);
        let mut consumed_reports = Vec::with_capacity(num_reports);
        for prep_init in &agg_job_init_req.prep_inits {
            if processed.contains(&prep_init.report_share.report_metadata.id) {
                return Err(DapAbort::UnrecognizedMessage {
                    detail: format!(
                        "report ID {} appears twice in the same aggregation job",
                        prep_init.report_share.report_metadata.id.to_base64url()
                    ),
                    task_id: Some(*task_id),
                });
            }
            processed.insert(prep_init.report_share.report_metadata.id);

            consumed_reports.push(
                EarlyReportStateConsumed::consume(
                    decrypter,
                    false,
                    task_id,
                    task_config,
                    Cow::Borrowed(&prep_init.report_share.report_metadata),
                    Cow::Borrowed(&prep_init.report_share.public_share),
                    &prep_init.report_share.encrypted_input_share,
                )
                .await?,
            );
        }

        let initialized_reports = initializer
            .initialize_reports(
                false,
                task_id,
                task_config,
                &agg_job_init_req.part_batch_sel,
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
        task_config: &DapTaskConfig,
        report_status: &HashMap<ReportId, ReportProcessedStatus>,
        initialized_reports: &[EarlyReportStateInitialized<'_>],
        agg_job_init_req: &AggregationJobInitReq,
        metrics: &DaphneMetrics,
    ) -> Result<DapHelperAggregationJobTransition<AggregationJobResp>, DapAbort> {
        match task_config.version {
            DapVersion::Draft02 => Ok(Self::draft02_handle_agg_job_init_req(
                report_status,
                initialized_reports,
                agg_job_init_req,
                metrics,
            )),
            DapVersion::Draft07 => self.draft07_handle_agg_job_init_req(
                task_id,
                task_config,
                report_status,
                initialized_reports,
                agg_job_init_req,
                metrics,
            ),
        }
    }

    fn draft02_handle_agg_job_init_req(
        report_status: &HashMap<ReportId, ReportProcessedStatus>,
        initialized_reports: &[EarlyReportStateInitialized<'_>],
        agg_job_init_req: &AggregationJobInitReq,
        metrics: &DaphneMetrics,
    ) -> DapHelperAggregationJobTransition<AggregationJobResp> {
        let num_reports = agg_job_init_req.prep_inits.len();
        let mut states = Vec::with_capacity(num_reports);
        let mut transitions = Vec::with_capacity(num_reports);

        for (initialized_report, prep_init) in initialized_reports
            .iter()
            .zip(agg_job_init_req.prep_inits.iter())
        {
            let var = match report_status.get(&prep_init.report_share.report_metadata.id) {
                Some(ReportProcessedStatus::Rejected(failure)) => TransitionVar::Failed(*failure),
                Some(ReportProcessedStatus::Aggregated) => TransitionVar::Finished,
                None => match initialized_report {
                    EarlyReportStateInitialized::Ready {
                        metadata,
                        public_share: _,
                        state: helper_prep_state,
                        message: helper_prep_share,
                    } => {
                        states.push(AggregationJobReportState {
                            draft02_prep_share: None,
                            prep_state: helper_prep_state.clone(),
                            time: metadata.time,
                            report_id: metadata.id,
                        });
                        TransitionVar::Continued(helper_prep_share.get_encoded())
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
                report_id: prep_init.report_share.report_metadata.id,
                var,
            });
        }

        DapHelperAggregationJobTransition::Continued(
            DapAggregationJobState {
                part_batch_sel: agg_job_init_req.part_batch_sel.clone(),
                seq: states,
            },
            AggregationJobResp { transitions },
        )
    }

    fn draft07_handle_agg_job_init_req(
        &self,
        task_id: &TaskId,
        task_config: &DapTaskConfig,
        report_status: &HashMap<ReportId, ReportProcessedStatus>,
        initialized_reports: &[EarlyReportStateInitialized<'_>],
        agg_job_init_req: &AggregationJobInitReq,
        metrics: &DaphneMetrics,
    ) -> Result<DapHelperAggregationJobTransition<AggregationJobResp>, DapAbort> {
        let num_reports = agg_job_init_req.prep_inits.len();
        let mut agg_span = DapAggregateSpan::default();
        let mut transitions = Vec::with_capacity(num_reports);

        for (initialized_report, prep_init) in initialized_reports
            .iter()
            .zip(agg_job_init_req.prep_inits.iter())
        {
            let var = match report_status.get(&prep_init.report_share.report_metadata.id) {
                Some(ReportProcessedStatus::Rejected(failure)) => TransitionVar::Failed(*failure),
                Some(ReportProcessedStatus::Aggregated) => TransitionVar::Finished,
                None => match initialized_report {
                    EarlyReportStateInitialized::Ready {
                        metadata,
                        public_share: _,
                        state: helper_prep_state,
                        message: helper_prep_share,
                    } => {
                        let Some(ref leader_prep_share) = prep_init.draft07_payload else {
                            return Err(DapAbort::UnrecognizedMessage {
                                detail: "PrepareInit with missing payload".to_string(),
                                task_id: Some(*task_id),
                            });
                        };

                        let res = match self {
                            Self::Prio3(prio3_config) => prio3_prep_finish_from_shares(
                                prio3_config,
                                1,
                                helper_prep_state.clone(),
                                helper_prep_share.clone(),
                                leader_prep_share,
                            ),
                            Self::Prio2 { dimension } => prio2_prep_finish_from_shares(
                                *dimension,
                                helper_prep_state.clone(),
                                helper_prep_share.clone(),
                                leader_prep_share,
                            ),
                        };

                        match res {
                            Ok((data, prep_msg)) => {
                                agg_span.add_out_share(
                                    task_config,
                                    &agg_job_init_req.part_batch_sel,
                                    metadata.id,
                                    metadata.time,
                                    data,
                                )?;
                                TransitionVar::Continued(prep_msg)
                            }

                            Err(VdafError::Codec(..) | VdafError::Vdaf(..)) => {
                                let failure = TransitionFailure::VdafPrepError;
                                metrics.report_inc_by(&format!("rejected_{failure}"), 1);
                                TransitionVar::Failed(failure)
                            }
                        }
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
                report_id: prep_init.report_share.report_metadata.id,
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
        task_config: &DapTaskConfig,
        agg_job_id: &MetaAggregationJobId,
        state: DapAggregationJobState,
        agg_job_resp: AggregationJobResp,
        metrics: &DaphneMetrics,
    ) -> Result<DapLeaderAggregationJobTransition<AggregationJobContinueReq>, DapAbort> {
        match task_config.version {
            DapVersion::Draft02 => self.draft02_handle_agg_job_resp(
                task_id,
                task_config,
                agg_job_id,
                state,
                agg_job_resp,
                metrics,
            ),
            DapVersion::Draft07 => {
                self.draft07_handle_agg_job_resp(task_id, task_config, state, agg_job_resp, metrics)
            }
        }
    }

    fn draft02_handle_agg_job_resp(
        &self,
        task_id: &TaskId,
        task_config: &DapTaskConfig,
        agg_job_id: &MetaAggregationJobId,
        state: DapAggregationJobState,
        agg_job_resp: AggregationJobResp,
        metrics: &DaphneMetrics,
    ) -> Result<DapLeaderAggregationJobTransition<AggregationJobContinueReq>, DapAbort> {
        if agg_job_resp.transitions.len() != state.seq.len() {
            return Err(DapAbort::UnrecognizedMessage {
                detail: format!(
                    "aggregation job response has {} reports; expected {}",
                    agg_job_resp.transitions.len(),
                    state.seq.len(),
                ),
                task_id: Some(*task_id),
            });
        }

        let mut transitions = Vec::with_capacity(state.seq.len());
        let mut out_shares = Vec::with_capacity(state.seq.len());
        for (helper, leader) in agg_job_resp
            .transitions
            .into_iter()
            .zip(state.seq.into_iter())
        {
            if helper.report_id != leader.report_id {
                return Err(DapAbort::UnrecognizedMessage {
                    detail: format!(
                        "report ID {} appears out of order in aggregation job response",
                        helper.report_id.to_base64url()
                    ),
                    task_id: Some(*task_id),
                });
            }

            let helper_prep_share = match &helper.var {
                TransitionVar::Continued(payload) => payload,

                // Skip report that can't be processed any further.
                TransitionVar::Failed(failure) => {
                    metrics.report_inc_by(&format!("rejected_{failure}"), 1);
                    continue;
                }

                // TODO Log the fact that the helper sent an unexpected message.
                TransitionVar::Finished => {
                    return Err(DapAbort::UnrecognizedMessage {
                        detail: "helper sent unexpected `Finished` message".to_string(),
                        task_id: Some(*task_id),
                    })
                }
            };

            let res = match self {
                Self::Prio3(prio3_config) => prio3_prep_finish_from_shares(
                    prio3_config,
                    0,
                    leader.prep_state,
                    leader.draft02_prep_share.unwrap(),
                    helper_prep_share,
                ),
                Self::Prio2 { dimension } => prio2_prep_finish_from_shares(
                    *dimension,
                    leader.prep_state,
                    leader.draft02_prep_share.unwrap(),
                    helper_prep_share,
                ),
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
                draft02_task_id: task_id.for_request_payload(&task_config.version),
                draft02_agg_job_id: agg_job_id.for_request_payload(),
                round: None,
                transitions,
            },
        ))
    }

    fn draft07_handle_agg_job_resp(
        &self,
        task_id: &TaskId,
        task_config: &DapTaskConfig,
        state: DapAggregationJobState,
        agg_job_resp: AggregationJobResp,
        metrics: &DaphneMetrics,
    ) -> Result<DapLeaderAggregationJobTransition<AggregationJobContinueReq>, DapAbort> {
        if agg_job_resp.transitions.len() != state.seq.len() {
            return Err(DapAbort::UnrecognizedMessage {
                detail: format!(
                    "aggregation job response has {} reports; expected {}",
                    agg_job_resp.transitions.len(),
                    state.seq.len(),
                ),
                task_id: Some(*task_id),
            });
        }

        let mut agg_span = DapAggregateSpan::default();
        for (helper, leader) in agg_job_resp
            .transitions
            .into_iter()
            .zip(state.seq.into_iter())
        {
            if helper.report_id != leader.report_id {
                return Err(DapAbort::UnrecognizedMessage {
                    detail: format!(
                        "report ID {} appears out of order in aggregation job response",
                        helper.report_id.to_base64url()
                    ),
                    task_id: Some(*task_id),
                });
            }

            let prep_msg = match &helper.var {
                // TODO(cjpatton) issue #350: Square this with the wire format of the spec.
                TransitionVar::Continued(payload) => payload,

                // Skip report that can't be processed any further.
                TransitionVar::Failed(failure) => {
                    metrics.report_inc_by(&format!("rejected_{failure}"), 1);
                    continue;
                }

                TransitionVar::Finished => {
                    return Err(DapAbort::UnrecognizedMessage {
                        detail: "helper sent unexpected `Finished` message".to_string(),
                        task_id: Some(*task_id),
                    })
                }
            };

            let res = match self {
                Self::Prio3(prio3_config) => {
                    prio3_prep_finish(prio3_config, leader.prep_state, prep_msg)
                }
                Self::Prio2 { dimension } => {
                    prio2_prep_finish(*dimension, leader.prep_state, prep_msg)
                }
            };

            match res {
                Ok(data) => {
                    agg_span.add_out_share(
                        task_config,
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
        task_config: &DapTaskConfig,
        state: &DapAggregationJobState,
        report_status: &HashMap<ReportId, ReportProcessedStatus>,
        agg_job_id: &MetaAggregationJobId,
        agg_job_cont_req: &AggregationJobContinueReq,
    ) -> Result<(DapAggregateSpan<DapAggregateShare>, AggregationJobResp), DapAbort> {
        match agg_job_cont_req.round {
            Some(1) | None => {}
            Some(0) => {
                return Err(DapAbort::UnrecognizedMessage {
                    detail: "request shouldn't indicate round 0".into(),
                    task_id: Some(*task_id),
                })
            }
            // TODO(bhalleycf) For now, there is only ever one round, and we don't try to do
            // aggregation-round-skew-recovery.
            Some(r) => {
                return Err(DapAbort::RoundMismatch {
                    detail: format!("The request indicates round {r}; round 1 was expected."),
                    task_id: *task_id,
                    agg_job_id_base64url: agg_job_id.to_base64url(),
                })
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
                return Err(DapAbort::UnrecognizedMessage {
                    detail: format!(
                        "report ID {} does not appear in the Helper's reports",
                        leader.report_id.to_base64url()
                    ),
                    task_id: Some(*task_id),
                });
            }
            if processed.contains(&leader.report_id) {
                return Err(DapAbort::UnrecognizedMessage {
                    detail: format!(
                        "report ID {} appears twice in the same aggregation job",
                        leader.report_id.to_base64url()
                    ),
                    task_id: Some(*task_id),
                });
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
                return Err(DapAbort::UnrecognizedMessage {
                    detail: "helper sent unexpected message instead of `Continued`".to_string(),
                    task_id: Some(*task_id),
                });
            };

            let var = match report_status.get(&leader.report_id) {
                Some(ReportProcessedStatus::Rejected(failure)) => TransitionVar::Failed(*failure),
                Some(ReportProcessedStatus::Aggregated) => TransitionVar::Finished,
                None => {
                    let res = match self {
                        Self::Prio3(prio3_config) => {
                            prio3_prep_finish(prio3_config, prep_state.clone(), leader_message)
                        }
                        Self::Prio2 { dimension } => {
                            prio2_prep_finish(*dimension, prep_state.clone(), leader_message)
                        }
                    };

                    match res {
                        Ok(data) => {
                            agg_span.add_out_share(
                                task_config,
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
        task_config: &DapTaskConfig,
        state: DapAggregationJobUncommitted,
        agg_job_resp: AggregationJobResp,
        metrics: &DaphneMetrics,
    ) -> Result<DapAggregateSpan<DapAggregateShare>, DapAbort> {
        if agg_job_resp.transitions.len() != state.seq.len() {
            return Err(DapAbort::UnrecognizedMessage {
                detail: format!(
                    "the Leader has {} reports, but it received {} reports from the Helper",
                    state.seq.len(),
                    agg_job_resp.transitions.len()
                ),
                task_id: None,
            });
        }

        let mut agg_span = DapAggregateSpan::default();
        for (helper, out_share) in agg_job_resp.transitions.into_iter().zip(state.seq) {
            if helper.report_id != out_share.report_id {
                return Err(DapAbort::UnrecognizedMessage {
                    detail: format!(
                        "report ID {} appears out of order in aggregation job response",
                        helper.report_id.to_base64url()
                    ),
                    task_id: None,
                });
            }

            match &helper.var {
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

                TransitionVar::Finished => agg_span.add_out_share(
                    task_config,
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
    /// * `version` is the `DapVersion` to use.
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
            DapVersion::Draft07 => CTX_AGG_SHARE_DRAFT07,
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
        DapVersion::Draft07 => CTX_AGG_SHARE_DRAFT07,
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
mod test {
    use crate::{
        assert_metrics_include, async_test_versions,
        error::DapAbort,
        hpke::{HpkeAeadId, HpkeConfig, HpkeKdfId, HpkeKemId},
        messages::{
            AggregationJobInitReq, BatchSelector, Interval, PartialBatchSelector, PrepareInit,
            Report, ReportId, ReportShare, Transition, TransitionFailure, TransitionVar,
        },
        test_versions,
        testing::AggregationJobTest,
        DapAggregateResult, DapAggregateShare, DapAggregateSpan, DapAggregationJobState,
        DapAggregationJobUncommitted, DapError, DapHelperAggregationJobTransition,
        DapLeaderAggregationJobTransition, DapMeasurement, DapVersion, Prio3Config,
        VdafAggregateShare, VdafConfig, VdafPrepMessage, VdafPrepState,
    };
    use assert_matches::assert_matches;
    use hpke_rs::HpkePublicKey;
    use prio::{
        codec::Encode,
        field::Field64,
        vdaf::{
            prio3::Prio3, AggregateShare, Aggregator as VdafAggregator, Collector as VdafCollector,
            OutputShare, PrepareTransition,
        },
    };
    use rand::prelude::*;
    use std::{borrow::Cow, fmt::Debug};

    use super::{EarlyReportStateConsumed, EarlyReportStateInitialized};

    impl<M: Debug> DapLeaderAggregationJobTransition<M> {
        fn unwrap_continued(self) -> (DapAggregationJobState, M) {
            let Self::Continued(state, message) = self else {
                panic!("unexpected transition")
            };
            (state, message)
        }

        fn unwrap_finished(self) -> DapAggregateSpan<DapAggregateShare> {
            let Self::Finished(agg_span) = self else {
                panic!("unexpected transition")
            };
            agg_span
        }

        pub(crate) fn unwrap_uncommitted(self) -> (DapAggregationJobUncommitted, M) {
            let Self::Uncommitted(uncommitted, message) = self else {
                panic!("unexpected transition")
            };
            (uncommitted, message)
        }
    }

    impl<M: Debug> DapHelperAggregationJobTransition<M> {
        fn unwrap_continued(self) -> (DapAggregationJobState, M) {
            let Self::Continued(state, message) = self else {
                panic!("unexpected transition")
            };
            (state, message)
        }

        fn unwrap_finished(self) -> (DapAggregateSpan<DapAggregateShare>, M) {
            let Self::Finished(agg_span, msg) = self else {
                panic!("unexpected transition")
            };
            (agg_span, msg)
        }

        fn into_message(self) -> M {
            match self {
                Self::Continued(_, msg) | Self::Finished(_, msg) => msg,
            }
        }
    }

    // TODO Exercise all of the Prio3 variants and not just Count.
    const TEST_VDAF: &VdafConfig = &VdafConfig::Prio3(Prio3Config::Count);

    async fn roundtrip_report(version: DapVersion) {
        let t = AggregationJobTest::new(TEST_VDAF, HpkeKemId::X25519HkdfSha256, version);
        let report = t
            .task_config
            .vdaf
            .produce_report(
                &t.client_hpke_config_list,
                t.now,
                &t.task_id,
                DapMeasurement::U64(1),
                version,
            )
            .unwrap();

        let early_report_state_consumed = EarlyReportStateConsumed::consume(
            &t.leader_hpke_receiver_config,
            true, // is_leader
            &t.task_id,
            &t.task_config,
            Cow::Borrowed(&report.report_metadata),
            Cow::Borrowed(&report.public_share),
            &report.encrypted_input_shares[0],
        )
        .await
        .unwrap();
        let EarlyReportStateInitialized::Ready {
            state: leader_step,
            message: leader_share,
            ..
        } = EarlyReportStateInitialized::initialize(
            true,
            &t.task_config.vdaf_verify_key,
            &t.task_config.vdaf,
            early_report_state_consumed,
        )
        .unwrap()
        else {
            panic!("rejected unexpectedly");
        };

        let early_report_state_consumed = EarlyReportStateConsumed::consume(
            &t.helper_hpke_receiver_config,
            false, // is_helper
            &t.task_id,
            &t.task_config,
            Cow::Borrowed(&report.report_metadata),
            Cow::Borrowed(&report.public_share),
            &report.encrypted_input_shares[1],
        )
        .await
        .unwrap();
        let EarlyReportStateInitialized::Ready {
            state: helper_step,
            message: helper_share,
            ..
        } = EarlyReportStateInitialized::initialize(
            false,
            &t.task_config.vdaf_verify_key,
            &t.task_config.vdaf,
            early_report_state_consumed,
        )
        .unwrap()
        else {
            panic!("rejected unexpectedly");
        };

        match (leader_step, helper_step, leader_share, helper_share) {
            (
                VdafPrepState::Prio3Field64(leader_step),
                VdafPrepState::Prio3Field64(helper_step),
                VdafPrepMessage::Prio3ShareField64(leader_share),
                VdafPrepMessage::Prio3ShareField64(helper_share),
            ) => {
                let vdaf = Prio3::new_count(2).unwrap();
                let message = vdaf
                    .prepare_shares_to_prepare_message(&(), [leader_share, helper_share])
                    .unwrap();

                let leader_out_share = assert_matches!(
                    vdaf.prepare_next(leader_step, message.clone()).unwrap(),
                    PrepareTransition::Finish(out_share) => out_share
                );
                let leader_agg_share = vdaf.aggregate(&(), [leader_out_share]).unwrap();

                let helper_out_share = assert_matches!(
                    vdaf.prepare_next(helper_step, message).unwrap(),
                    PrepareTransition::Finish(out_share) => out_share
                );
                let helper_agg_share = vdaf.aggregate(&(), [helper_out_share]).unwrap();

                assert_eq!(
                    vdaf.unshard(&(), vec![leader_agg_share, helper_agg_share], 1)
                        .unwrap(),
                    1,
                );
            }
            _ => {
                panic!("unexpected output from leader or helper");
            }
        }
    }

    async_test_versions! { roundtrip_report }

    fn roundtrip_report_unsupported_hpke_suite(version: DapVersion) {
        let t = AggregationJobTest::new(TEST_VDAF, HpkeKemId::X25519HkdfSha256, version);

        // The helper's HPKE config indicates a KEM type no supported by the client.
        let unsupported_hpke_config_list = vec![
            t.client_hpke_config_list[0].clone(),
            HpkeConfig {
                id: thread_rng().gen(),
                kem_id: HpkeKemId::NotImplemented(999),
                kdf_id: HpkeKdfId::HkdfSha256,
                aead_id: HpkeAeadId::Aes128Gcm,
                public_key: HpkePublicKey::from(b"some KEM public key".to_vec()),
            },
        ];

        let res = t.task_config.vdaf.produce_report(
            &unsupported_hpke_config_list,
            t.now,
            &t.task_id,
            DapMeasurement::U64(1),
            version,
        );
        assert_matches!(
            res,
            Err(DapError::Fatal(s)) => assert_eq!(s.to_string(), "HPKE ciphersuite not implemented (999, 1, 1)")
        );
    }

    test_versions! { roundtrip_report_unsupported_hpke_suite }

    async fn produce_agg_job_init_req(version: DapVersion) {
        let t = AggregationJobTest::new(TEST_VDAF, HpkeKemId::X25519HkdfSha256, version);
        let reports = t.produce_reports(vec![
            DapMeasurement::U64(1),
            DapMeasurement::U64(0),
            DapMeasurement::U64(0),
        ]);

        let (leader_state, agg_job_init_req) = t
            .produce_agg_job_init_req(reports.clone())
            .await
            .unwrap_continued();
        assert_eq!(leader_state.seq.len(), 3);
        assert_eq!(
            agg_job_init_req.draft02_task_id,
            t.task_id.for_request_payload(&version)
        );
        assert_eq!(agg_job_init_req.agg_param.len(), 0);
        assert_eq!(agg_job_init_req.prep_inits.len(), 3);
        for (prep_init, report) in agg_job_init_req.prep_inits.iter().zip(reports.iter()) {
            assert_eq!(
                prep_init.report_share.report_metadata.id,
                report.report_metadata.id
            );
        }

        match t.handle_agg_job_init_req(&agg_job_init_req).await {
            DapHelperAggregationJobTransition::Continued(helper_state, agg_job_resp) => {
                assert_eq!(helper_state.seq.len(), 3);
                assert_eq!(agg_job_resp.transitions.len(), 3);
                for (sub, report) in agg_job_resp.transitions.iter().zip(reports.iter()) {
                    assert_eq!(sub.report_id, report.report_metadata.id);
                }
            }
            DapHelperAggregationJobTransition::Finished(agg_span, agg_job_resp) => {
                assert_eq!(agg_span.report_count(), 3);
                assert_eq!(agg_job_resp.transitions.len(), 3);
            }
        }
    }

    async_test_versions! { produce_agg_job_init_req }

    async fn produce_agg_job_init_req_skip_hpke_decrypt_err(version: DapVersion) {
        let t = AggregationJobTest::new(TEST_VDAF, HpkeKemId::X25519HkdfSha256, version);
        let mut reports = t.produce_reports(vec![DapMeasurement::U64(1)]);

        // Simulate HPKE decryption error of leader's report share.
        reports[0].encrypted_input_shares[0].payload[0] ^= 1;

        assert_eq!(
            t.produce_agg_job_init_req(reports)
                .await
                .unwrap_finished()
                .report_count(),
            0
        );
        assert_metrics_include!(t.leader_registry, {
            r#"report_counter{env="test_leader",host="leader.com",status="rejected_hpke_decrypt_error"}"#: 1,
        });
    }

    async_test_versions! { produce_agg_job_init_req_skip_hpke_decrypt_err }

    async fn produce_agg_job_init_req_skip_hpke_unknown_config_id(version: DapVersion) {
        let t = AggregationJobTest::new(TEST_VDAF, HpkeKemId::X25519HkdfSha256, version);
        let mut reports = t.produce_reports(vec![DapMeasurement::U64(1)]);

        // Client tries to send Leader encrypted input with incorrect config ID.
        reports[0].encrypted_input_shares[0].config_id ^= 1;

        assert_eq!(
            t.produce_agg_job_init_req(reports)
                .await
                .unwrap_finished()
                .report_count(),
            0
        );
        assert_metrics_include!(t.leader_registry, {
            r#"report_counter{env="test_leader",host="leader.com",status="rejected_hpke_unknown_config_id"}"#: 1,
        });
    }

    async_test_versions! { produce_agg_job_init_req_skip_hpke_unknown_config_id }

    async fn produce_agg_job_init_req_skip_vdaf_prep_error(version: DapVersion) {
        let t = AggregationJobTest::new(TEST_VDAF, HpkeKemId::X25519HkdfSha256, version);
        let reports = vec![
            t.produce_invalid_report_public_share_decode_failure(DapMeasurement::U64(1), version),
            t.produce_invalid_report_input_share_decode_failure(DapMeasurement::U64(1), version),
        ];

        assert_eq!(
            t.produce_agg_job_init_req(reports)
                .await
                .unwrap_finished()
                .report_count(),
            0
        );
        assert_metrics_include!(t.leader_registry, {
            r#"report_counter{env="test_leader",host="leader.com",status="rejected_vdaf_prep_error"}"#: 2,
        });
    }

    async_test_versions! { produce_agg_job_init_req_skip_vdaf_prep_error }

    async fn handle_agg_job_init_req_hpke_decrypt_err(version: DapVersion) {
        let t = AggregationJobTest::new(TEST_VDAF, HpkeKemId::X25519HkdfSha256, version);
        let mut reports = t.produce_reports(vec![DapMeasurement::U64(1)]);

        // Simulate HPKE decryption error of helper's report share.
        reports[0].encrypted_input_shares[1].payload[0] ^= 1;

        let (_, agg_job_init_req) = t
            .produce_agg_job_init_req(reports.clone())
            .await
            .unwrap_continued();
        let agg_job_resp = t
            .handle_agg_job_init_req(&agg_job_init_req)
            .await
            .into_message();

        assert_eq!(agg_job_resp.transitions.len(), 1);
        assert_matches!(
            agg_job_resp.transitions[0].var,
            TransitionVar::Failed(TransitionFailure::HpkeDecryptError)
        );

        assert_metrics_include!(t.helper_registry, {
            r#"report_counter{env="test_helper",host="helper.org",status="rejected_hpke_decrypt_error"}"#: 1,
        });
    }

    async_test_versions! { handle_agg_job_init_req_hpke_decrypt_err }

    async fn handle_agg_job_init_req_hpke_unknown_config_id(version: DapVersion) {
        let t = AggregationJobTest::new(TEST_VDAF, HpkeKemId::X25519HkdfSha256, version);
        let mut reports = t.produce_reports(vec![DapMeasurement::U64(1)]);

        // Client tries to send Helper encrypted input with incorrect config ID.
        reports[0].encrypted_input_shares[1].config_id ^= 1;

        let (_, agg_job_init_req) = t
            .produce_agg_job_init_req(reports.clone())
            .await
            .unwrap_continued();
        let agg_job_resp = t
            .handle_agg_job_init_req(&agg_job_init_req)
            .await
            .into_message();

        assert_eq!(agg_job_resp.transitions.len(), 1);
        assert_matches!(
            agg_job_resp.transitions[0].var,
            TransitionVar::Failed(TransitionFailure::HpkeUnknownConfigId)
        );

        assert_metrics_include!(t.helper_registry, {
            r#"report_counter{env="test_helper",host="helper.org",status="rejected_hpke_unknown_config_id"}"#: 1,
        });
    }

    async_test_versions! { handle_agg_job_init_req_hpke_unknown_config_id }

    async fn handle_agg_job_init_req_vdaf_prep_error(version: DapVersion) {
        let t = AggregationJobTest::new(TEST_VDAF, HpkeKemId::X25519HkdfSha256, version);
        let report0 =
            t.produce_invalid_report_public_share_decode_failure(DapMeasurement::U64(1), version);
        let report1 =
            t.produce_invalid_report_input_share_decode_failure(DapMeasurement::U64(1), version);

        let agg_job_init_req = AggregationJobInitReq {
            draft02_task_id: t.task_id.for_request_payload(&version),
            draft02_agg_job_id: t.agg_job_id.for_request_payload(),
            agg_param: Vec::new(),
            part_batch_sel: PartialBatchSelector::TimeInterval,
            prep_inits: vec![
                PrepareInit {
                    report_share: ReportShare {
                        report_metadata: report0.report_metadata,
                        public_share: report0.public_share,
                        encrypted_input_share: report0.encrypted_input_shares[1].clone(),
                    },
                    draft07_payload: None,
                },
                PrepareInit {
                    report_share: ReportShare {
                        report_metadata: report1.report_metadata,
                        public_share: report1.public_share,
                        encrypted_input_share: report1.encrypted_input_shares[1].clone(),
                    },
                    draft07_payload: None,
                },
            ],
        };

        let agg_job_resp = t
            .handle_agg_job_init_req(&agg_job_init_req)
            .await
            .into_message();

        assert_eq!(agg_job_resp.transitions.len(), 2);
        assert_matches!(
            agg_job_resp.transitions[0].var,
            TransitionVar::Failed(TransitionFailure::VdafPrepError)
        );
        assert_matches!(
            agg_job_resp.transitions[1].var,
            TransitionVar::Failed(TransitionFailure::VdafPrepError)
        );

        assert_metrics_include!(t.helper_registry, {
            r#"report_counter{env="test_helper",host="helper.org",status="rejected_vdaf_prep_error"}"#: 2,
        });
    }

    async_test_versions! { handle_agg_job_init_req_vdaf_prep_error }

    async fn agg_job_resp_abort_transition_out_of_order(version: DapVersion) {
        let t = AggregationJobTest::new(TEST_VDAF, HpkeKemId::X25519HkdfSha256, version);
        let reports = t.produce_reports(vec![DapMeasurement::U64(1), DapMeasurement::U64(1)]);
        let (leader_state, agg_job_init_req) =
            t.produce_agg_job_init_req(reports).await.unwrap_continued();
        let mut agg_job_resp = t
            .handle_agg_job_init_req(&agg_job_init_req)
            .await
            .into_message();

        // Helper sends transitions out of order.
        let tmp = agg_job_resp.transitions[0].clone();
        agg_job_resp.transitions[0] = agg_job_resp.transitions[1].clone();
        agg_job_resp.transitions[1] = tmp;

        assert_matches!(
            t.handle_agg_job_resp_expect_err(leader_state, agg_job_resp),
            DapAbort::UnrecognizedMessage { .. }
        );
    }

    async_test_versions! { agg_job_resp_abort_transition_out_of_order }

    async fn agg_job_resp_abort_report_id_repeated(version: DapVersion) {
        let t = AggregationJobTest::new(TEST_VDAF, HpkeKemId::X25519HkdfSha256, version);
        let reports = t.produce_reports(vec![DapMeasurement::U64(1), DapMeasurement::U64(1)]);
        let (leader_state, agg_job_init_req) =
            t.produce_agg_job_init_req(reports).await.unwrap_continued();
        let mut agg_job_resp = t
            .handle_agg_job_init_req(&agg_job_init_req)
            .await
            .into_message();

        // Helper sends a transition twice.
        let repeated_transition = agg_job_resp.transitions[0].clone();
        agg_job_resp.transitions.push(repeated_transition);

        assert_matches!(
            t.handle_agg_job_resp_expect_err(leader_state, agg_job_resp),
            DapAbort::UnrecognizedMessage { .. }
        );
    }

    async_test_versions! { agg_job_resp_abort_report_id_repeated }

    async fn agg_job_resp_abort_unrecognized_report_id(version: DapVersion) {
        let mut rng = thread_rng();
        let t = AggregationJobTest::new(TEST_VDAF, HpkeKemId::X25519HkdfSha256, version);
        let reports = t.produce_reports(vec![DapMeasurement::U64(1), DapMeasurement::U64(1)]);
        let (leader_state, agg_job_init_req) =
            t.produce_agg_job_init_req(reports).await.unwrap_continued();
        let mut agg_job_resp = t
            .handle_agg_job_init_req(&agg_job_init_req)
            .await
            .into_message();

        // Helper sent a transition with an unrecognized report ID.
        agg_job_resp.transitions.push(Transition {
            report_id: ReportId(rng.gen()),
            var: TransitionVar::Continued(b"whatever".to_vec()),
        });

        assert_matches!(
            t.handle_agg_job_resp_expect_err(leader_state, agg_job_resp),
            DapAbort::UnrecognizedMessage { .. }
        );
    }

    async_test_versions! { agg_job_resp_abort_unrecognized_report_id }

    async fn agg_job_resp_abort_invalid_transition(version: DapVersion) {
        let t = AggregationJobTest::new(TEST_VDAF, HpkeKemId::X25519HkdfSha256, version);
        let reports = t.produce_reports(vec![DapMeasurement::U64(1)]);
        let (leader_state, agg_job_init_req) =
            t.produce_agg_job_init_req(reports).await.unwrap_continued();
        let mut agg_job_resp = t
            .handle_agg_job_init_req(&agg_job_init_req)
            .await
            .into_message();

        // Helper sent a transition with an unrecognized report ID.
        agg_job_resp.transitions[0].var = TransitionVar::Finished;

        assert_matches!(
            t.handle_agg_job_resp_expect_err(leader_state, agg_job_resp),
            DapAbort::UnrecognizedMessage { .. }
        );
    }

    async_test_versions! { agg_job_resp_abort_invalid_transition }

    async fn agg_job_cont_req(version: DapVersion) {
        let t = AggregationJobTest::new(TEST_VDAF, HpkeKemId::X25519HkdfSha256, version);
        let reports = t.produce_reports(vec![
            DapMeasurement::U64(1),
            DapMeasurement::U64(1),
            DapMeasurement::U64(0),
            DapMeasurement::U64(0),
            DapMeasurement::U64(1),
        ]);

        let (leader_state, agg_job_init_req) =
            t.produce_agg_job_init_req(reports).await.unwrap_continued();

        let (leader_agg_span, helper_agg_span) =
            match t.handle_agg_job_init_req(&agg_job_init_req).await {
                DapHelperAggregationJobTransition::Continued(helper_state, agg_job_resp) => {
                    // draft02
                    let (leader_uncommitted, agg_job_cont_req) = t
                        .handle_agg_job_resp(leader_state, agg_job_resp)
                        .unwrap_uncommitted();

                    let (helper_agg_span, agg_job_resp) =
                        t.handle_agg_job_cont_req(&helper_state, &agg_job_cont_req);
                    assert_eq!(helper_agg_span.report_count(), 5);
                    assert_eq!(agg_job_resp.transitions.len(), 5);

                    let leader_agg_span =
                        t.handle_final_agg_job_resp(leader_uncommitted, agg_job_resp);

                    (leader_agg_span, helper_agg_span)
                }
                DapHelperAggregationJobTransition::Finished(helper_agg_span, agg_job_resp) => {
                    let leader_agg_span = t
                        .handle_agg_job_resp(leader_state, agg_job_resp)
                        .unwrap_finished();

                    (leader_agg_span, helper_agg_span)
                }
            };

        assert_eq!(leader_agg_span.report_count(), 5);
        let num_measurements = leader_agg_span.report_count();

        let VdafAggregateShare::Field64(leader_agg_share) =
            leader_agg_span.collapsed().data.unwrap()
        else {
            panic!("unexpected VdafAggregateShare variant")
        };

        let VdafAggregateShare::Field64(helper_agg_share) =
            helper_agg_span.collapsed().data.unwrap()
        else {
            panic!("unexpected VdafAggregateShare variant")
        };

        let vdaf = Prio3::new_count(2).unwrap();
        assert_eq!(
            vdaf.unshard(&(), [leader_agg_share, helper_agg_share], num_measurements,)
                .unwrap(),
            3,
        );
    }

    async_test_versions! { agg_job_cont_req }

    #[tokio::test]
    async fn agg_job_cont_req_skip_vdaf_prep_error_draft02() {
        let t =
            AggregationJobTest::new(TEST_VDAF, HpkeKemId::X25519HkdfSha256, DapVersion::Draft02);
        let mut reports = t.produce_reports(vec![DapMeasurement::U64(1), DapMeasurement::U64(1)]);
        reports.insert(
            1,
            t.produce_invalid_report_vdaf_prep_failure(DapMeasurement::U64(1), DapVersion::Draft02),
        );

        let (leader_state, agg_job_init_req) =
            t.produce_agg_job_init_req(reports).await.unwrap_continued();
        let (helper_state, agg_job_resp) = t
            .handle_agg_job_init_req(&agg_job_init_req)
            .await
            .unwrap_continued();

        let (_, agg_job_cont_req) = t
            .handle_agg_job_resp(leader_state, agg_job_resp)
            .unwrap_uncommitted();

        let (helper_agg_span, agg_job_resp) =
            t.handle_agg_job_cont_req(&helper_state, &agg_job_cont_req);

        assert_eq!(2, helper_agg_span.report_count());
        assert_eq!(2, agg_job_resp.transitions.len());
        assert_eq!(
            agg_job_resp.transitions[0].report_id,
            agg_job_init_req.prep_inits[0]
                .report_share
                .report_metadata
                .id
        );
        assert_eq!(
            agg_job_resp.transitions[1].report_id,
            agg_job_init_req.prep_inits[2]
                .report_share
                .report_metadata
                .id
        );

        assert_metrics_include!(t.leader_registry, {
            r#"report_counter{env="test_leader",host="leader.com",status="rejected_vdaf_prep_error"}"#: 1,
        });
    }

    #[tokio::test]
    async fn agg_job_init_req_skip_vdaf_prep_error_draft07() {
        let t =
            AggregationJobTest::new(TEST_VDAF, HpkeKemId::X25519HkdfSha256, DapVersion::Draft07);
        let mut reports = t.produce_reports(vec![DapMeasurement::U64(1), DapMeasurement::U64(1)]);
        reports.insert(
            1,
            t.produce_invalid_report_vdaf_prep_failure(DapMeasurement::U64(1), DapVersion::Draft07),
        );

        let (leader_state, agg_job_init_req) =
            t.produce_agg_job_init_req(reports).await.unwrap_continued();
        let (helper_agg_span, agg_job_resp) = t
            .handle_agg_job_init_req(&agg_job_init_req)
            .await
            .unwrap_finished();

        assert_eq!(2, helper_agg_span.report_count());
        assert_eq!(3, agg_job_resp.transitions.len());
        for i in 0..3 {
            assert_eq!(
                agg_job_resp.transitions[i].report_id,
                agg_job_init_req.prep_inits[i]
                    .report_share
                    .report_metadata
                    .id
            );
        }

        let DapLeaderAggregationJobTransition::Finished(leader_agg_span) =
            t.handle_agg_job_resp(leader_state, agg_job_resp)
        else {
            panic!("unexpected transition")
        };
        assert_eq!(leader_agg_span.report_count(), 2);
    }

    #[tokio::test]
    async fn agg_cont_abort_unrecognized_report_id_draft02() {
        let mut rng = thread_rng();
        let t =
            AggregationJobTest::new(TEST_VDAF, HpkeKemId::X25519HkdfSha256, DapVersion::Draft02);
        let reports = t.produce_reports(vec![DapMeasurement::U64(1), DapMeasurement::U64(1)]);
        let (leader_state, agg_job_init_req) =
            t.produce_agg_job_init_req(reports).await.unwrap_continued();
        let (helper_state, agg_job_resp) = t
            .handle_agg_job_init_req(&agg_job_init_req)
            .await
            .unwrap_continued();

        let (_, mut agg_job_cont_req) = t
            .handle_agg_job_resp(leader_state, agg_job_resp)
            .unwrap_uncommitted();
        // Leader sends a Transition with an unrecognized report_id.
        agg_job_cont_req.transitions.insert(
            1,
            Transition {
                report_id: ReportId(rng.gen()),
                var: TransitionVar::Finished, // Expected transition type for Prio3 at this stage
            },
        );

        assert_matches!(
            t.handle_agg_job_cont_req_expect_err(helper_state, &agg_job_cont_req),
            DapAbort::UnrecognizedMessage { .. }
        );
    }

    #[tokio::test]
    async fn agg_job_cont_req_abort_transition_out_of_order_draft02() {
        let t =
            AggregationJobTest::new(TEST_VDAF, HpkeKemId::X25519HkdfSha256, DapVersion::Draft02);
        let reports = t.produce_reports(vec![DapMeasurement::U64(1), DapMeasurement::U64(1)]);
        let (leader_state, agg_job_init_req) =
            t.produce_agg_job_init_req(reports).await.unwrap_continued();
        let (helper_state, agg_job_resp) = t
            .handle_agg_job_init_req(&agg_job_init_req)
            .await
            .unwrap_continued();

        let (_, mut agg_job_cont_req) = t
            .handle_agg_job_resp(leader_state, agg_job_resp)
            .unwrap_uncommitted();
        // Leader sends transitions out of order.
        let tmp = agg_job_cont_req.transitions[0].clone();
        agg_job_cont_req.transitions[0] = agg_job_cont_req.transitions[1].clone();
        agg_job_cont_req.transitions[1] = tmp;

        assert_matches!(
            t.handle_agg_job_cont_req_expect_err(helper_state, &agg_job_cont_req),
            DapAbort::UnrecognizedMessage { .. }
        );
    }

    #[tokio::test]
    async fn agg_job_cont_req_abort_report_id_repeated_draft02() {
        let t =
            AggregationJobTest::new(TEST_VDAF, HpkeKemId::X25519HkdfSha256, DapVersion::Draft02);
        let reports = t.produce_reports(vec![DapMeasurement::U64(1), DapMeasurement::U64(1)]);
        let (leader_state, agg_job_init_req) =
            t.produce_agg_job_init_req(reports).await.unwrap_continued();
        let (helper_state, agg_job_resp) = t
            .handle_agg_job_init_req(&agg_job_init_req)
            .await
            .unwrap_continued();

        let (_, mut agg_job_cont_req) = t
            .handle_agg_job_resp(leader_state, agg_job_resp)
            .unwrap_uncommitted();
        // Leader sends a transition twice.
        let repeated_transition = agg_job_cont_req.transitions[0].clone();
        agg_job_cont_req.transitions.push(repeated_transition);

        assert_matches!(
            t.handle_agg_job_cont_req_expect_err(helper_state, &agg_job_cont_req),
            DapAbort::UnrecognizedMessage { .. }
        );
    }

    async fn encrypted_agg_share(version: DapVersion) {
        let t = AggregationJobTest::new(TEST_VDAF, HpkeKemId::X25519HkdfSha256, version);
        let leader_agg_share = DapAggregateShare {
            report_count: 50,
            min_time: 1_637_359_200,
            max_time: 1_637_359_200,
            checksum: [0; 32],
            data: Some(VdafAggregateShare::Field64(AggregateShare::from(
                OutputShare::from(vec![Field64::from(23)]),
            ))),
        };
        let helper_agg_share = DapAggregateShare {
            report_count: 50,
            min_time: 1_637_359_200,
            max_time: 1_637_359_200,
            checksum: [0; 32],
            data: Some(VdafAggregateShare::Field64(AggregateShare::from(
                OutputShare::from(vec![Field64::from(9)]),
            ))),
        };

        let batch_selector = BatchSelector::TimeInterval {
            batch_interval: Interval {
                start: 1_637_359_200,
                duration: 7200,
            },
        };
        let leader_encrypted_agg_share =
            t.produce_leader_encrypted_agg_share(&batch_selector, &leader_agg_share);
        let helper_encrypted_agg_share =
            t.produce_helper_encrypted_agg_share(&batch_selector, &helper_agg_share);
        let agg_res = t
            .consume_encrypted_agg_shares(
                &batch_selector,
                50,
                vec![leader_encrypted_agg_share, helper_encrypted_agg_share],
            )
            .await;

        assert_eq!(agg_res, DapAggregateResult::U64(32));
    }

    async_test_versions! { encrypted_agg_share }

    #[tokio::test]
    async fn helper_state_serialization_draft02() {
        let t =
            AggregationJobTest::new(TEST_VDAF, HpkeKemId::X25519HkdfSha256, DapVersion::Draft02);
        let reports = t.produce_reports(vec![
            DapMeasurement::U64(1),
            DapMeasurement::U64(1),
            DapMeasurement::U64(0),
            DapMeasurement::U64(0),
            DapMeasurement::U64(1),
        ]);
        let (_, agg_job_init_req) = t.produce_agg_job_init_req(reports).await.unwrap_continued();
        let (want, _) = t
            .handle_agg_job_init_req(&agg_job_init_req)
            .await
            .unwrap_continued();

        let got = DapAggregationJobState::get_decoded(TEST_VDAF, &want.get_encoded()).unwrap();
        assert_eq!(got.get_encoded(), want.get_encoded());

        assert!(DapAggregationJobState::get_decoded(TEST_VDAF, b"invalid helper state").is_err());
    }

    impl AggregationJobTest {
        // Tweak the Helper's share so that decoding succeeds but preparation fails.
        fn produce_invalid_report_vdaf_prep_failure(
            &self,
            measurement: DapMeasurement,
            version: DapVersion,
        ) -> Report {
            let report_id = ReportId(thread_rng().gen());
            let (invalid_public_share, mut invalid_input_shares) = self
                .task_config
                .vdaf
                .produce_input_shares(measurement, &report_id.0)
                .unwrap();
            invalid_input_shares[1][0] ^= 1; // The first bit is incorrect!
            VdafConfig::produce_report_with_extensions_for_shares(
                invalid_public_share,
                invalid_input_shares,
                &self.client_hpke_config_list,
                self.now,
                &self.task_id,
                &report_id,
                Vec::new(), // extensions
                version,
            )
            .unwrap()
        }

        // Tweak the public share so that it can't be decoded.
        fn produce_invalid_report_public_share_decode_failure(
            &self,
            measurement: DapMeasurement,
            version: DapVersion,
        ) -> Report {
            let report_id = ReportId(thread_rng().gen());
            let (mut invalid_public_share, invalid_input_shares) = self
                .task_config
                .vdaf
                .produce_input_shares(measurement, &report_id.0)
                .unwrap();
            invalid_public_share.push(1); // Add spurious byte at the end
            VdafConfig::produce_report_with_extensions_for_shares(
                invalid_public_share,
                invalid_input_shares,
                &self.client_hpke_config_list,
                self.now,
                &self.task_id,
                &report_id,
                Vec::new(), // extensions
                version,
            )
            .unwrap()
        }

        // Tweak the input shares so that they can't be decoded.
        fn produce_invalid_report_input_share_decode_failure(
            &self,
            measurement: DapMeasurement,
            version: DapVersion,
        ) -> Report {
            let report_id = ReportId(thread_rng().gen());
            let (invalid_public_share, mut invalid_input_shares) = self
                .task_config
                .vdaf
                .produce_input_shares(measurement, &report_id.0)
                .unwrap();
            invalid_input_shares[0].push(1); // Add a spurious byte to the Leader's share
            invalid_input_shares[1].push(1); // Add a spurious byte to the Helper's share
            VdafConfig::produce_report_with_extensions_for_shares(
                invalid_public_share,
                invalid_input_shares,
                &self.client_hpke_config_list,
                self.now,
                &self.task_id,
                &report_id,
                Vec::new(), // extensions
                version,
            )
            .unwrap()
        }
    }
}
