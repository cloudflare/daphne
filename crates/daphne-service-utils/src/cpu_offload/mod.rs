// Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use crate::{
    capnproto_payload::{CapnprotoPayloadDecode, CapnprotoPayloadEncode},
    cpu_offload_capnp::{
        self,
        hpke_receiver_config::{self, hpke_config},
        initialize_reports,
        initialized_reports::{self, initialized_report},
        partial_dap_task_config, prepare_init, report_metadata, time_range, u8_l16, u8_l32,
        vdaf_verify_key,
    },
};
use capnp::struct_list;
use daphne::{
    constants::DapAggregatorRole,
    hpke::{HpkeConfig, HpkeReceiverConfig},
    messages::{self, HpkeCiphertext, PrepareInit, ReportId, ReportMetadata, ReportShare, TaskId},
    vdaf::{VdafConfig, VdafPrepShare, VdafPrepState, VdafVerifyKey},
    InitializedReport, PartialDapTaskConfigForReportInit, WithPeerPrepShare,
};
use prio::codec::{Encode, ParameterizedDecode, ParameterizedEncode};
use std::{borrow::Cow, ops::Range};

// --- General functions ---
impl CapnprotoPayloadEncode for [u8; 32] {
    type Builder<'a> = u8_l32::Builder<'a>;

    fn encode_to_builder(&self, mut builder: Self::Builder<'_>) {
        builder.set_fst(u64::from_le_bytes(self[0..8].try_into().unwrap()));
        builder.set_snd(u64::from_le_bytes(self[8..16].try_into().unwrap()));
        builder.set_thr(u64::from_le_bytes(self[16..24].try_into().unwrap()));
        builder.set_frh(u64::from_le_bytes(self[24..32].try_into().unwrap()));
    }
}

impl CapnprotoPayloadDecode for [u8; 32] {
    type Reader<'a> = u8_l32::Reader<'a>;

    fn decode_from_reader(reader: Self::Reader<'_>) -> capnp::Result<Self>
    where
        Self: Sized,
    {
        let mut array = [0; 32];
        array[0..8].copy_from_slice(&reader.get_fst().to_le_bytes());
        array[8..16].copy_from_slice(&reader.get_snd().to_le_bytes());
        array[16..24].copy_from_slice(&reader.get_thr().to_le_bytes());
        array[24..32].copy_from_slice(&reader.get_frh().to_le_bytes());
        Ok(array)
    }
}

impl CapnprotoPayloadEncode for [u8; 16] {
    type Builder<'a> = u8_l16::Builder<'a>;

    fn encode_to_builder(&self, mut builder: Self::Builder<'_>) {
        builder.set_fst(u64::from_le_bytes(self[0..8].try_into().unwrap()));
        builder.set_snd(u64::from_le_bytes(self[8..16].try_into().unwrap()));
    }
}

impl CapnprotoPayloadDecode for [u8; 16] {
    type Reader<'a> = u8_l16::Reader<'a>;

    fn decode_from_reader(reader: Self::Reader<'_>) -> capnp::Result<Self>
    where
        Self: Sized,
    {
        let mut array = [0; 16];
        array[0..8].copy_from_slice(&reader.get_fst().to_le_bytes());
        array[8..16].copy_from_slice(&reader.get_snd().to_le_bytes());
        Ok(array)
    }
}

macro_rules! capnp_encode_ids {
    ($($id:ident => $inner:ident),*$(,)?) => {
        $(
        impl CapnprotoPayloadEncode for $id {
            type Builder<'a> = $inner::Builder<'a>;

            fn encode_to_builder(&self, builder: Self::Builder<'_>) {
                self.0.encode_to_builder(builder)
            }
        }

        impl CapnprotoPayloadDecode for $id {
            type Reader<'a> = $inner::Reader<'a>;

            fn decode_from_reader(reader: Self::Reader<'_>) -> capnp::Result<Self>
            where
                Self: Sized,
            {
               <_>::decode_from_reader(reader).map(Self)
            }
        }
        )*
    };
}

capnp_encode_ids! {
    TaskId => u8_l32,
    ReportId => u8_l16,
}

fn encode_list<I, O, F>(list: I, mut builder: struct_list::Builder<'_, O>, mut encode: F)
where
    I: IntoIterator,
    O: capnp::traits::OwnedStruct,
    F: for<'b> FnMut(I::Item, O::Builder<'b>),
{
    for (i, item) in list.into_iter().enumerate() {
        encode(item, builder.reborrow().get(i.try_into().unwrap()));
    }
}
// -------------------------

pub struct InitializeReports<'s> {
    pub hpke_keys: Cow<'s, [HpkeReceiverConfig]>,
    pub valid_report_range: Range<messages::Time>,
    pub task_id: TaskId,
    pub task_config: PartialDapTaskConfigForReportInit<'s>,
    pub agg_param: Cow<'s, [u8]>,
    pub prep_inits: Vec<PrepareInit>,
}

impl CapnprotoPayloadEncode for InitializeReports<'_> {
    type Builder<'a> = initialize_reports::Builder<'a>;

    fn encode_to_builder(&self, mut builder: Self::Builder<'_>) {
        let InitializeReports {
            hpke_keys,
            valid_report_range,
            task_id,
            task_config,
            agg_param,
            prep_inits,
        } = self;
        hpke_keys.as_ref().encode_to_builder(
            builder.reborrow().init_hpke_keys(
                hpke_keys
                    .len()
                    .try_into()
                    .expect("can't serialize more than u32::MAX hpke_keys"),
            ),
        );
        valid_report_range.encode_to_builder(builder.reborrow().init_valid_report_range());
        task_id.encode_to_builder(builder.reborrow().init_task_id());
        task_config.encode_to_builder(builder.reborrow().init_task_config());
        builder.set_agg_param(agg_param);
        prep_inits.encode_to_builder(
            builder.init_prep_inits(
                prep_inits
                    .len()
                    .try_into()
                    .expect("can't serialize more than u32::MAX prep_inits"),
            ),
        );
    }
}

impl CapnprotoPayloadDecode for InitializeReports<'static> {
    type Reader<'a> = initialize_reports::Reader<'a>;

    fn decode_from_reader(reader: Self::Reader<'_>) -> capnp::Result<Self>
    where
        Self: Sized,
    {
        let task_config = <_>::decode_from_reader(reader.get_task_config()?)?;

        Ok(Self {
            hpke_keys: Cow::Owned(<_>::decode_from_reader(reader.get_hpke_keys()?)?),
            valid_report_range: <_>::decode_from_reader(reader.get_valid_report_range()?)?,
            task_id: <_>::decode_from_reader(reader.get_task_id()?)?,
            agg_param: Cow::Owned(reader.get_agg_param()?.to_vec()),
            task_config,
            prep_inits: <_>::decode_from_reader(reader.get_prep_inits()?)?,
        })
    }
}

impl CapnprotoPayloadEncode for [HpkeReceiverConfig] {
    type Builder<'a> = struct_list::Builder<'a, hpke_receiver_config::Owned>;

    fn encode_to_builder(&self, builder: Self::Builder<'_>) {
        encode_list(self, builder, |key, mut builder| {
            let HpkeReceiverConfig {
                config,
                private_key,
            } = key;
            {
                let mut builder = builder.reborrow().init_config();
                let HpkeConfig {
                    id,
                    kem_id,
                    kdf_id,
                    aead_id,
                    public_key,
                } = config;
                builder.set_id(*id);
                builder.set_kem_id(match kem_id {
                    daphne::hpke::HpkeKemId::P256HkdfSha256 => {
                        hpke_config::HpkeKemId::P256HkdfSha256
                    }
                    daphne::hpke::HpkeKemId::X25519HkdfSha256 => {
                        hpke_config::HpkeKemId::X25519HkdfSha256
                    }
                    daphne::hpke::HpkeKemId::NotImplemented(n) => {
                        unimplemented!("HpkeKemId({n})")
                    }
                });
                builder.set_kdf_id(match kdf_id {
                    daphne::hpke::HpkeKdfId::HkdfSha256 => hpke_config::HpkeKdfId::HkdfSha256,
                    daphne::hpke::HpkeKdfId::NotImplemented(n) => {
                        unimplemented!("HpkeKdfId({n})")
                    }
                });
                builder.set_aead_id(match aead_id {
                    daphne::hpke::HpkeAeadId::Aes128Gcm => hpke_config::HpkeAeadId::Aes128Gcm,
                    daphne::hpke::HpkeAeadId::NotImplemented(n) => {
                        unimplemented!("HpkeAeadId({n})")
                    }
                });
                builder.set_public_key(public_key.as_slice());
            };
            builder.set_private_key(private_key.as_slice());
        });
    }
}

impl CapnprotoPayloadDecode for Vec<HpkeReceiverConfig> {
    type Reader<'a> = struct_list::Reader<'a, hpke_receiver_config::Owned>;

    fn decode_from_reader(reader: Self::Reader<'_>) -> capnp::Result<Self>
    where
        Self: Sized,
    {
        reader
            .into_iter()
            .map(|key| {
                Ok(HpkeReceiverConfig {
                    config: {
                        let config = key.get_config()?;
                        HpkeConfig {
                            id: config.get_id(),
                            kem_id: match config.get_kem_id()? {
                                hpke_config::HpkeKemId::P256HkdfSha256 => {
                                    daphne::hpke::HpkeKemId::P256HkdfSha256
                                }
                                hpke_config::HpkeKemId::X25519HkdfSha256 => {
                                    daphne::hpke::HpkeKemId::X25519HkdfSha256
                                }
                            },
                            kdf_id: match config.get_kdf_id()? {
                                hpke_config::HpkeKdfId::HkdfSha256 => {
                                    daphne::hpke::HpkeKdfId::HkdfSha256
                                }
                            },
                            aead_id: match config.get_aead_id()? {
                                hpke_config::HpkeAeadId::Aes128Gcm => {
                                    daphne::hpke::HpkeAeadId::Aes128Gcm
                                }
                            },
                            public_key: config.get_public_key()?.into(),
                        }
                    },
                    private_key: key.get_private_key()?.into(),
                })
            })
            .collect()
    }
}

impl CapnprotoPayloadEncode for Range<messages::Time> {
    type Builder<'a> = time_range::Builder<'a>;

    fn encode_to_builder(&self, mut builder: Self::Builder<'_>) {
        builder.set_start(self.start);
        builder.set_end(self.end);
    }
}

impl CapnprotoPayloadDecode for Range<messages::Time> {
    type Reader<'a> = time_range::Reader<'a>;

    fn decode_from_reader(reader: Self::Reader<'_>) -> capnp::Result<Self>
    where
        Self: Sized,
    {
        Ok(reader.get_start()..reader.get_end())
    }
}

impl CapnprotoPayloadEncode for PartialDapTaskConfigForReportInit<'_> {
    type Builder<'a> = partial_dap_task_config::Builder<'a>;

    fn encode_to_builder(&self, mut builder: Self::Builder<'_>) {
        let PartialDapTaskConfigForReportInit {
            not_after,
            method_is_taskprov,
            version,
            vdaf,
            vdaf_verify_key,
        } = self;
        builder.set_not_after(*not_after);
        builder.set_method_is_taskprov(*method_is_taskprov);
        builder.set_version(match version {
            daphne::DapVersion::Draft09 => cpu_offload_capnp::DapVersion::Draft09,
            daphne::DapVersion::Latest => cpu_offload_capnp::DapVersion::DraftLatest,
        });
        builder.set_vdaf(encode_vdaf_config(vdaf).as_slice().into());
        {
            let builder = builder.reborrow().init_vdaf_verify_key();
            match vdaf_verify_key.as_ref() {
                daphne::vdaf::VdafVerifyKey::L16(array) => {
                    array.encode_to_builder(builder.init_l16());
                }
                daphne::vdaf::VdafVerifyKey::L32(array) => {
                    array.encode_to_builder(builder.init_l32());
                }
            }
        }
    }
}

impl CapnprotoPayloadDecode for PartialDapTaskConfigForReportInit<'static> {
    type Reader<'a> = partial_dap_task_config::Reader<'a>;

    fn decode_from_reader(reader: Self::Reader<'_>) -> capnp::Result<Self>
    where
        Self: Sized,
    {
        Ok(Self {
            not_after: reader.get_not_after(),
            method_is_taskprov: reader.get_method_is_taskprov(),
            version: match reader.get_version()? {
                cpu_offload_capnp::DapVersion::Draft09 => daphne::DapVersion::Draft09,
                cpu_offload_capnp::DapVersion::DraftLatest => daphne::DapVersion::Latest,
            },
            vdaf: Cow::Owned(<_>::decode_from_reader(reader.reborrow().get_vdaf()?)?),
            vdaf_verify_key: match reader.get_vdaf_verify_key()?.which()? {
                vdaf_verify_key::Which::L16(reader) => {
                    Cow::Owned(VdafVerifyKey::L16(<_>::decode_from_reader(reader?)?))
                }
                vdaf_verify_key::Which::L32(reader) => {
                    Cow::Owned(VdafVerifyKey::L32(<_>::decode_from_reader(reader?)?))
                }
            },
        })
    }
}

fn encode_vdaf_config(vdaf: &VdafConfig) -> Vec<u8> {
    serde_json::to_vec(vdaf).unwrap()
}

impl CapnprotoPayloadDecode for VdafConfig {
    type Reader<'a> = capnp::text::Reader<'a>;

    fn decode_from_reader(reader: Self::Reader<'_>) -> capnp::Result<Self>
    where
        Self: Sized,
    {
        serde_json::from_slice(reader.as_bytes()).map_err(to_capnp)
    }
}

impl CapnprotoPayloadEncode for [PrepareInit] {
    type Builder<'a> = struct_list::Builder<'a, prepare_init::Owned>;

    fn encode_to_builder(&self, builder: Self::Builder<'_>) {
        encode_list(self, builder, |prep, mut builder| {
            let PrepareInit {
                report_share,
                payload,
            } = prep;
            builder.set_payload(payload);
            {
                let ReportShare {
                    report_metadata,
                    public_share,
                    encrypted_input_share,
                } = report_share;
                let mut builder = builder.init_report_share();
                builder.set_public_share(public_share);
                report_metadata.encode_to_builder(builder.reborrow().init_report_metadata());
                {
                    let HpkeCiphertext {
                        config_id,
                        enc,
                        payload,
                    } = encrypted_input_share;
                    let mut builder = builder.reborrow().init_encrypted_input_share();
                    builder.set_config_id(*config_id);
                    builder.set_enc(enc);
                    builder.set_payload(payload);
                }
            }
        });
    }
}

impl CapnprotoPayloadDecode for Vec<PrepareInit> {
    type Reader<'a> = struct_list::Reader<'a, prepare_init::Owned>;

    fn decode_from_reader(reader: Self::Reader<'_>) -> capnp::Result<Self>
    where
        Self: Sized,
    {
        reader
            .into_iter()
            .map(|reader| {
                Ok(PrepareInit {
                    report_share: {
                        let reader = reader.get_report_share()?;
                        ReportShare {
                            report_metadata: <_>::decode_from_reader(
                                reader.get_report_metadata()?,
                            )?,
                            public_share: reader.get_public_share()?.to_vec(),
                            encrypted_input_share: {
                                let reader = reader.get_encrypted_input_share()?;
                                HpkeCiphertext {
                                    config_id: reader.get_config_id(),
                                    enc: reader.get_enc()?.to_vec(),
                                    payload: reader.get_payload()?.to_vec(),
                                }
                            },
                        }
                    },
                    payload: reader.get_payload()?.to_vec(),
                })
            })
            .collect()
    }
}

impl CapnprotoPayloadEncode for ReportMetadata {
    type Builder<'a> = report_metadata::Builder<'a>;

    fn encode_to_builder(&self, mut builder: Self::Builder<'_>) {
        let Self { id, time } = self;
        id.encode_to_builder(builder.reborrow().init_id());
        builder.set_time(*time);
    }
}

impl CapnprotoPayloadDecode for ReportMetadata {
    type Reader<'a> = report_metadata::Reader<'a>;

    fn decode_from_reader(reader: Self::Reader<'_>) -> capnp::Result<Self>
    where
        Self: Sized,
    {
        Ok(Self {
            id: <_>::decode_from_reader(reader.get_id()?)?,
            time: reader.get_time(),
        })
    }
}

pub struct InitializedReports {
    pub vdaf: VdafConfig,
    pub reports: Vec<InitializedReport<WithPeerPrepShare>>,
}

impl CapnprotoPayloadEncode for InitializedReports {
    type Builder<'a> = initialized_reports::Builder<'a>;

    fn encode_to_builder(&self, mut builder: Self::Builder<'_>) {
        let Self { vdaf, reports } = self;
        builder.set_vdaf_config(encode_vdaf_config(vdaf).as_slice().into());
        encode_list(
            reports,
            builder.init_reports(
                reports
                    .len()
                    .try_into()
                    .expect("can't serialize more than u32::MAX reports"),
            ),
            |report, builder| match report {
                InitializedReport::Ready {
                    metadata,
                    public_share,
                    prep_share,
                    prep_state,
                    peer_prep_share,
                } => {
                    let mut builder = builder.init_ready();
                    metadata.encode_to_builder(builder.reborrow().init_metadata());
                    builder.set_public_share(public_share);
                    let mut buffer = Vec::new();
                    {
                        prep_share
                            .encode_with_param(prep_state, &mut buffer)
                            .unwrap();
                        builder.set_prep_share(&buffer);
                        buffer.clear();
                    }
                    {
                        prep_state.encode(&mut buffer).unwrap();
                        builder.set_prep_state(&buffer);
                        buffer.clear();
                    }
                    builder.set_peer_prep_share(peer_prep_share);
                }
                InitializedReport::Rejected {
                    metadata,
                    report_err,
                } => {
                    let mut builder = builder.init_rejected();
                    metadata.encode_to_builder(builder.reborrow().init_metadata());
                    builder.set_failure((*report_err).into());
                }
            },
        );
    }
}

impl CapnprotoPayloadDecode for InitializedReports {
    type Reader<'a> = initialized_reports::Reader<'a>;

    fn decode_from_reader(reader: Self::Reader<'_>) -> capnp::Result<Self>
    where
        Self: Sized,
    {
        let vdaf = <_>::decode_from_reader(reader.get_vdaf_config()?)?;
        Ok(Self {
            reports: reader
                .get_reports()?
                .into_iter()
                .map(|report| match report.which()? {
                    initialized_report::Which::Ready(reader) => {
                        let prep_state = VdafPrepState::get_decoded_with_param(
                            &(&vdaf, DapAggregatorRole::Helper),
                            reader.get_prep_state()?,
                        )
                        .map_err(to_capnp)?;
                        Ok(InitializedReport::Ready {
                            metadata: <_>::decode_from_reader(reader.get_metadata()?)?,
                            public_share: reader.get_public_share()?.to_vec(),
                            prep_share: VdafPrepShare::get_decoded_with_param(
                                &prep_state,
                                reader.get_prep_share()?,
                            )
                            .map_err(to_capnp)?,
                            prep_state,
                            peer_prep_share: reader.get_peer_prep_share()?.to_vec().into(),
                        })
                    }
                    initialized_report::Which::Rejected(reader) => {
                        Ok(InitializedReport::Rejected {
                            metadata: <_>::decode_from_reader(reader.get_metadata()?)?,
                            report_err: reader.get_failure()?.into(),
                        })
                    }
                })
                .collect::<capnp::Result<_>>()?,
            vdaf,
        })
    }
}

impl From<messages::ReportError> for initialized_report::ReportError {
    fn from(failure: messages::ReportError) -> Self {
        match failure {
            messages::ReportError::Reserved => Self::Reserved,
            messages::ReportError::BatchCollected => Self::BatchCollected,
            messages::ReportError::ReportReplayed => Self::ReportReplayed,
            messages::ReportError::ReportDropped => Self::ReportDropped,
            messages::ReportError::HpkeUnknownConfigId => Self::HpkeUnknownConfigId,
            messages::ReportError::HpkeDecryptError => Self::HpkeDecryptError,
            messages::ReportError::VdafPrepError => Self::VdafPrepError,
            messages::ReportError::BatchSaturated => Self::BatchSaturated,
            messages::ReportError::TaskExpired => Self::TaskExpired,
            messages::ReportError::InvalidMessage => Self::InvalidMessage,
            messages::ReportError::ReportTooEarly => Self::ReportTooEarly,
            messages::ReportError::TaskNotStarted => Self::TaskNotStarted,
        }
    }
}

// Since messages::ReportError is foreign, implement Into instead of From
impl From<initialized_report::ReportError> for messages::ReportError {
    fn from(val: initialized_report::ReportError) -> Self {
        match val {
            initialized_report::ReportError::Reserved => Self::Reserved,
            initialized_report::ReportError::BatchCollected => Self::BatchCollected,
            initialized_report::ReportError::ReportReplayed => Self::ReportReplayed,
            initialized_report::ReportError::ReportDropped => Self::ReportDropped,
            initialized_report::ReportError::HpkeUnknownConfigId => Self::HpkeUnknownConfigId,
            initialized_report::ReportError::HpkeDecryptError => Self::HpkeDecryptError,
            initialized_report::ReportError::VdafPrepError => Self::VdafPrepError,
            initialized_report::ReportError::BatchSaturated => Self::BatchSaturated,
            initialized_report::ReportError::TaskExpired => Self::TaskExpired,
            initialized_report::ReportError::InvalidMessage => Self::InvalidMessage,
            initialized_report::ReportError::ReportTooEarly => Self::ReportTooEarly,
            initialized_report::ReportError::TaskNotStarted => Self::TaskNotStarted,
        }
    }
}

fn to_capnp<E: ToString>(e: E) -> capnp::Error {
    capnp::Error {
        kind: capnp::ErrorKind::Failed,
        extra: e.to_string(),
    }
}
