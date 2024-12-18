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
    InitializedReport, PartialDapTaskConfig, WithPeerPrepShare,
};
use prio::codec::{Encode, ParameterizedDecode, ParameterizedEncode};
use std::{borrow::Cow, ops::Range};

// --- General functions ---
fn encode_l8_l32(array: &[u8; 32], mut builder: u8_l32::Builder<'_>) {
    builder.set_fst(u64::from_le_bytes(array[0..8].try_into().unwrap()));
    builder.set_snd(u64::from_le_bytes(array[8..16].try_into().unwrap()));
    builder.set_thr(u64::from_le_bytes(array[16..24].try_into().unwrap()));
    builder.set_frh(u64::from_le_bytes(array[24..32].try_into().unwrap()));
}

fn decode_l8_l32(reader: u8_l32::Reader<'_>) -> [u8; 32] {
    let mut array = [0; 32];
    array[0..8].copy_from_slice(&reader.get_fst().to_le_bytes());
    array[8..16].copy_from_slice(&reader.get_snd().to_le_bytes());
    array[16..24].copy_from_slice(&reader.get_thr().to_le_bytes());
    array[24..32].copy_from_slice(&reader.get_frh().to_le_bytes());
    array
}

fn encode_l8_l16(array: &[u8; 16], mut builder: u8_l16::Builder<'_>) {
    builder.set_fst(u64::from_le_bytes(array[0..8].try_into().unwrap()));
    builder.set_snd(u64::from_le_bytes(array[8..16].try_into().unwrap()));
}

fn decode_l8_l16(reader: u8_l16::Reader<'_>) -> [u8; 16] {
    let mut array = [0; 16];
    array[0..8].copy_from_slice(&reader.get_fst().to_le_bytes());
    array[8..16].copy_from_slice(&reader.get_snd().to_le_bytes());
    array
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
    pub task_config: PartialDapTaskConfig<'s>,
    pub agg_param: Cow<'s, [u8]>,
    pub prep_inits: Vec<PrepareInit>,
}

impl CapnprotoPayloadEncode for InitializeReports<'_> {
    fn encode_to_builder(&self) -> capnp::message::Builder<capnp::message::HeapAllocator> {
        let mut message = capnp::message::Builder::new_default();
        let mut builder = message.init_root::<initialize_reports::Builder>();
        let InitializeReports {
            hpke_keys,
            valid_report_range,
            task_id,
            task_config,
            agg_param,
            prep_inits,
        } = self;
        encode_hpke_keys(
            hpke_keys.as_ref(),
            builder.reborrow().init_hpke_keys(
                hpke_keys
                    .len()
                    .try_into()
                    .expect("can't serialize more than u32::MAX hpke_keys"),
            ),
        );
        encode_valid_report_range(
            valid_report_range,
            builder.reborrow().init_valid_report_range(),
        );
        encode_l8_l32(&task_id.0, builder.reborrow().init_task_id());
        encode_task_config(task_config, builder.reborrow().init_task_config());
        builder.set_agg_param(agg_param);
        encode_prep_inits(
            prep_inits,
            builder.init_prep_inits(
                prep_inits
                    .len()
                    .try_into()
                    .expect("can't serialize more than u32::MAX prep_inits"),
            ),
        );
        message
    }
}

impl CapnprotoPayloadDecode for InitializeReports<'static> {
    fn decode_from_reader(
        reader: capnp::message::Reader<capnp::serialize::OwnedSegments>,
    ) -> capnp::Result<Self>
    where
        Self: Sized,
    {
        let reader = reader.get_root::<initialize_reports::Reader>()?;

        let task_config = decode_task_config(reader.get_task_config()?)?;

        Ok(Self {
            hpke_keys: Cow::Owned(decode_hpke_keys(reader.get_hpke_keys()?)?),
            valid_report_range: decode_valid_report_range(reader.get_valid_report_range()?),
            task_id: TaskId(decode_l8_l32(reader.get_task_id()?)),
            agg_param: Cow::Owned(reader.get_agg_param()?.to_vec()),
            task_config,
            prep_inits: decode_prep_inits(reader.get_prep_inits()?)?,
        })
    }
}

fn encode_hpke_keys(
    hpke_keys: &[HpkeReceiverConfig],
    builder: struct_list::Builder<'_, hpke_receiver_config::Owned>,
) {
    encode_list(hpke_keys, builder, |key, mut builder| {
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
                daphne::hpke::HpkeKemId::P256HkdfSha256 => hpke_config::HpkeKemId::P256HkdfSha256,
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

fn decode_hpke_keys(
    reader: struct_list::Reader<'_, hpke_receiver_config::Owned>,
) -> capnp::Result<Vec<HpkeReceiverConfig>> {
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

fn encode_valid_report_range(
    valid_report_range: &Range<u64>,
    mut builder: time_range::Builder<'_>,
) {
    builder.set_start(valid_report_range.start);
    builder.set_end(valid_report_range.end);
}

fn decode_valid_report_range(reader: time_range::Reader<'_>) -> Range<messages::Time> {
    reader.get_start()..reader.get_end()
}

fn encode_task_config(
    task_config: &PartialDapTaskConfig,
    mut builder: partial_dap_task_config::Builder<'_>,
) {
    let PartialDapTaskConfig {
        not_after,
        method_is_taskprov,
        version,
        vdaf,
        vdaf_verify_key,
    } = task_config;
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
            daphne::vdaf::VdafVerifyKey::L16(array) => encode_l8_l16(array, builder.init_l16()),
            daphne::vdaf::VdafVerifyKey::L32(array) => encode_l8_l32(array, builder.init_l32()),
        }
    }
}

fn decode_task_config(
    reader: partial_dap_task_config::Reader<'_>,
) -> capnp::Result<PartialDapTaskConfig<'static>> {
    Ok(PartialDapTaskConfig {
        not_after: reader.get_not_after(),
        method_is_taskprov: reader.get_method_is_taskprov(),
        version: match reader.get_version()? {
            cpu_offload_capnp::DapVersion::Draft09 => daphne::DapVersion::Draft09,
            cpu_offload_capnp::DapVersion::DraftLatest => daphne::DapVersion::Latest,
        },
        vdaf: Cow::Owned(decode_vdaf_config(reader.reborrow().get_vdaf()?)?),
        vdaf_verify_key: match reader.get_vdaf_verify_key()?.which()? {
            vdaf_verify_key::Which::L16(reader) => {
                Cow::Owned(VdafVerifyKey::L16(decode_l8_l16(reader?)))
            }
            vdaf_verify_key::Which::L32(reader) => {
                Cow::Owned(VdafVerifyKey::L32(decode_l8_l32(reader?)))
            }
        },
    })
}

fn encode_vdaf_config(vdaf: &VdafConfig) -> Vec<u8> {
    serde_json::to_vec(vdaf).unwrap()
}

fn decode_vdaf_config(reader: capnp::text::Reader<'_>) -> capnp::Result<VdafConfig> {
    serde_json::from_slice(reader.as_bytes()).map_err(to_capnp)
}

fn encode_prep_inits(
    prep_inits: &[PrepareInit],
    builder: struct_list::Builder<'_, prepare_init::Owned>,
) {
    encode_list(prep_inits, builder, |prep, mut builder| {
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
            encode_report_metadata(report_metadata, builder.reborrow().init_report_metadata());
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

fn decode_prep_inits(
    reader: struct_list::Reader<'_, prepare_init::Owned>,
) -> capnp::Result<Vec<PrepareInit>> {
    reader
        .into_iter()
        .map(|reader| {
            Ok(PrepareInit {
                report_share: {
                    let reader = reader.get_report_share()?;
                    ReportShare {
                        report_metadata: decode_report_metadata(reader.get_report_metadata()?)?,
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

fn encode_report_metadata(metadata: &ReportMetadata, mut builder: report_metadata::Builder<'_>) {
    let ReportMetadata { id, time } = metadata;
    encode_l8_l16(&id.0, builder.reborrow().init_id());
    builder.set_time(*time);
}

fn decode_report_metadata(reader: report_metadata::Reader<'_>) -> capnp::Result<ReportMetadata> {
    Ok(ReportMetadata {
        id: ReportId(decode_l8_l16(reader.get_id()?)),
        time: reader.get_time(),
    })
}

pub struct InitializedReports {
    pub vdaf: VdafConfig,
    pub reports: Vec<InitializedReport<WithPeerPrepShare>>,
}

impl CapnprotoPayloadEncode for InitializedReports {
    fn encode_to_builder(&self) -> capnp::message::Builder<capnp::message::HeapAllocator> {
        let mut message = capnp::message::Builder::new_default();
        let mut builder = message.init_root::<initialized_reports::Builder>();
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
                    encode_report_metadata(metadata, builder.reborrow().init_metadata());
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
                InitializedReport::Rejected { metadata, failure } => {
                    let mut builder = builder.init_rejected();
                    encode_report_metadata(metadata, builder.reborrow().init_metadata());
                    builder.set_failure(encode_report_error(*failure));
                }
            },
        );
        message
    }
}

impl CapnprotoPayloadDecode for InitializedReports {
    fn decode_from_reader(
        reader: capnp::message::Reader<capnp::serialize::OwnedSegments>,
    ) -> capnp::Result<Self>
    where
        Self: Sized,
    {
        let reader = reader.get_root::<initialized_reports::Reader>()?;
        let vdaf = decode_vdaf_config(reader.get_vdaf_config()?)?;
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
                            metadata: decode_report_metadata(reader.get_metadata()?)?,
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
                            metadata: decode_report_metadata(reader.get_metadata()?)?,
                            failure: decode_report_error(reader.get_failure()?),
                        })
                    }
                })
                .collect::<capnp::Result<_>>()?,
            vdaf,
        })
    }
}

fn encode_report_error(failure: messages::TransitionFailure) -> initialized_report::ReportError {
    match failure {
        messages::TransitionFailure::Reserved => initialized_report::ReportError::Reserved,
        messages::TransitionFailure::BatchCollected => {
            initialized_report::ReportError::BatchCollected
        }
        messages::TransitionFailure::ReportReplayed => {
            initialized_report::ReportError::ReportReplayed
        }
        messages::TransitionFailure::ReportDropped => {
            initialized_report::ReportError::ReportDropped
        }
        messages::TransitionFailure::HpkeUnknownConfigId => {
            initialized_report::ReportError::HpkeUnknownConfigId
        }
        messages::TransitionFailure::HpkeDecryptError => {
            initialized_report::ReportError::HpkeDecryptError
        }
        messages::TransitionFailure::VdafPrepError => {
            initialized_report::ReportError::VdafPrepError
        }
        messages::TransitionFailure::BatchSaturated => {
            initialized_report::ReportError::BatchSaturated
        }
        messages::TransitionFailure::TaskExpired => initialized_report::ReportError::TaskExpired,
        messages::TransitionFailure::InvalidMessage => {
            initialized_report::ReportError::InvalidMessage
        }
        messages::TransitionFailure::ReportTooEarly => {
            initialized_report::ReportError::ReportTooEarly
        }
        messages::TransitionFailure::TaskNotStarted => {
            initialized_report::ReportError::TaskNotStarted
        }
    }
}

fn decode_report_error(failure: initialized_report::ReportError) -> messages::TransitionFailure {
    match failure {
        initialized_report::ReportError::Reserved => messages::TransitionFailure::Reserved,
        initialized_report::ReportError::BatchCollected => {
            messages::TransitionFailure::BatchCollected
        }
        initialized_report::ReportError::ReportReplayed => {
            messages::TransitionFailure::ReportReplayed
        }
        initialized_report::ReportError::ReportDropped => {
            messages::TransitionFailure::ReportDropped
        }
        initialized_report::ReportError::HpkeUnknownConfigId => {
            messages::TransitionFailure::HpkeUnknownConfigId
        }
        initialized_report::ReportError::HpkeDecryptError => {
            messages::TransitionFailure::HpkeDecryptError
        }
        initialized_report::ReportError::VdafPrepError => {
            messages::TransitionFailure::VdafPrepError
        }
        initialized_report::ReportError::BatchSaturated => {
            messages::TransitionFailure::BatchSaturated
        }
        initialized_report::ReportError::TaskExpired => messages::TransitionFailure::TaskExpired,
        initialized_report::ReportError::InvalidMessage => {
            messages::TransitionFailure::InvalidMessage
        }
        initialized_report::ReportError::ReportTooEarly => {
            messages::TransitionFailure::ReportTooEarly
        }
        initialized_report::ReportError::TaskNotStarted => {
            messages::TransitionFailure::TaskNotStarted
        }
    }
}

fn to_capnp<E: ToString>(e: E) -> capnp::Error {
    capnp::Error {
        kind: capnp::ErrorKind::Failed,
        extra: e.to_string(),
    }
}
