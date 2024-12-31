// Copyright (c) 2025 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use crate::{
    capnproto::{
        decode_list, encode_list, usize_to_capnp_len, CapnprotoPayloadDecode,
        CapnprotoPayloadEncode,
    },
    compute_offload_capnp::{
        hpke_receiver_config::{self, hpke_config},
        initialize_reports,
        initialized_reports::{self, initialized_report},
        partial_dap_task_config, prepare_init, public_extensions_list, report_metadata, time_range,
    },
};
use daphne::{
    constants::DapAggregatorRole,
    hpke::{HpkeConfig, HpkeReceiverConfig},
    messages::{self, Extension, HpkeCiphertext, PrepareInit, ReportMetadata, ReportShare, TaskId},
    vdaf::{VdafConfig, VdafPrepShare, VdafPrepState},
    InitializedReport, PartialDapTaskConfigForReportInit, WithPeerPrepShare,
};
use prio::codec::{Decode, Encode, ParameterizedDecode, ParameterizedEncode};
use std::{borrow::Cow, ops::Range};

pub struct InitializeReports<'s> {
    pub hpke_keys: Cow<'s, [HpkeReceiverConfig]>,
    /// Output of [`DapAggregator::valid_report_time_range`](daphne::roles::DapAggregator) at the
    /// start of the aggregation job.
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
        encode_list(
            hpke_keys.as_ref(),
            builder
                .reborrow()
                .init_hpke_keys(usize_to_capnp_len(hpke_keys.len())),
        );
        valid_report_range.encode_to_builder(builder.reborrow().init_valid_report_range());
        task_id.encode_to_builder(builder.reborrow().init_task_id());
        task_config.encode_to_builder(builder.reborrow().init_task_config());
        builder.set_agg_param(agg_param);
        encode_list(
            prep_inits,
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
            hpke_keys: Cow::Owned(decode_list::<HpkeReceiverConfig, _, _>(
                reader.get_hpke_keys()?,
            )?),
            valid_report_range: <_>::decode_from_reader(reader.get_valid_report_range()?)?,
            task_id: <_>::decode_from_reader(reader.get_task_id()?)?,
            agg_param: Cow::Owned(reader.get_agg_param()?.to_vec()),
            task_config,
            prep_inits: decode_list::<PrepareInit, _, _>(reader.get_prep_inits()?)?,
        })
    }
}

impl CapnprotoPayloadEncode for HpkeReceiverConfig {
    type Builder<'a> = hpke_receiver_config::Builder<'a>;

    fn encode_to_builder(&self, mut builder: Self::Builder<'_>) {
        let HpkeReceiverConfig {
            config,
            private_key,
        } = self;
        config.encode_to_builder(builder.reborrow().init_config());
        builder.set_private_key(private_key.as_slice());
    }
}

impl CapnprotoPayloadDecode for HpkeReceiverConfig {
    type Reader<'a> = hpke_receiver_config::Reader<'a>;

    fn decode_from_reader(reader: Self::Reader<'_>) -> capnp::Result<Self>
    where
        Self: Sized,
    {
        Ok(Self {
            config: <_>::decode_from_reader(reader.get_config()?)?,
            private_key: reader.get_private_key()?.into(),
        })
    }
}

impl CapnprotoPayloadEncode for HpkeConfig {
    type Builder<'a> = hpke_config::Builder<'a>;

    fn encode_to_builder(&self, mut builder: Self::Builder<'_>) {
        let HpkeConfig {
            id,
            kem_id,
            kdf_id,
            aead_id,
            public_key,
        } = self;
        builder.set_id(*id);
        builder.set_kem_id(match kem_id {
            daphne::hpke::HpkeKemId::P256HkdfSha256 => hpke_config::HpkeKemId::P256HkdfSha256,
            daphne::hpke::HpkeKemId::X25519HkdfSha256 => hpke_config::HpkeKemId::X25519HkdfSha256,
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
    }
}

impl CapnprotoPayloadDecode for HpkeConfig {
    type Reader<'a> = hpke_config::Reader<'a>;

    fn decode_from_reader(reader: Self::Reader<'_>) -> capnp::Result<Self>
    where
        Self: Sized,
    {
        Ok(Self {
            id: reader.get_id(),
            kem_id: match reader.get_kem_id()? {
                hpke_config::HpkeKemId::P256HkdfSha256 => daphne::hpke::HpkeKemId::P256HkdfSha256,
                hpke_config::HpkeKemId::X25519HkdfSha256 => {
                    daphne::hpke::HpkeKemId::X25519HkdfSha256
                }
            },
            kdf_id: match reader.get_kdf_id()? {
                hpke_config::HpkeKdfId::HkdfSha256 => daphne::hpke::HpkeKdfId::HkdfSha256,
            },
            aead_id: match reader.get_aead_id()? {
                hpke_config::HpkeAeadId::Aes128Gcm => daphne::hpke::HpkeAeadId::Aes128Gcm,
            },
            public_key: reader.get_public_key()?.into(),
        })
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
            not_before,
            not_after,
            method_is_taskprov,
            version,
            vdaf,
            vdaf_verify_key,
        } = self;
        builder.set_not_before(*not_before);
        builder.set_not_after(*not_after);
        builder.set_method_is_taskprov(*method_is_taskprov);
        builder.set_version((*version).into());
        builder.set_vdaf(encode_vdaf_config(vdaf).as_slice().into());
        vdaf_verify_key
            .inner()
            .encode_to_builder(builder.reborrow().init_vdaf_verify_key());
    }
}

impl CapnprotoPayloadDecode for PartialDapTaskConfigForReportInit<'static> {
    type Reader<'a> = partial_dap_task_config::Reader<'a>;

    fn decode_from_reader(reader: Self::Reader<'_>) -> capnp::Result<Self>
    where
        Self: Sized,
    {
        Ok(Self {
            not_before: reader.get_not_before(),
            not_after: reader.get_not_after(),
            method_is_taskprov: reader.get_method_is_taskprov(),
            version: reader.get_version()?.into(),
            vdaf: Cow::Owned(<_>::decode_from_reader(reader.reborrow().get_vdaf()?)?),
            vdaf_verify_key: <_>::from(<[u8; 32]>::decode_from_reader(
                reader.get_vdaf_verify_key()?,
            )?),
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

impl CapnprotoPayloadEncode for PrepareInit {
    type Builder<'a> = prepare_init::Builder<'a>;

    fn encode_to_builder(&self, mut builder: Self::Builder<'_>) {
        let PrepareInit {
            report_share,
            payload,
        } = self;
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
    }
}

impl CapnprotoPayloadDecode for PrepareInit {
    type Reader<'a> = prepare_init::Reader<'a>;

    fn decode_from_reader(reader: Self::Reader<'_>) -> capnp::Result<Self>
    where
        Self: Sized,
    {
        Ok(Self {
            report_share: {
                let reader = reader.get_report_share()?;
                ReportShare {
                    report_metadata: <_>::decode_from_reader(reader.get_report_metadata()?)?,
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
    }
}

impl CapnprotoPayloadEncode for ReportMetadata {
    type Builder<'a> = report_metadata::Builder<'a>;

    fn encode_to_builder(&self, mut builder: Self::Builder<'_>) {
        let Self {
            id,
            time,
            public_extensions,
        } = self;
        id.encode_to_builder(builder.reborrow().init_id());
        builder.set_time(*time);
        if let Some(ref extensions) = public_extensions {
            let mut e = builder
                .init_public_extensions()
                .init_list(usize_to_capnp_len(extensions.len()));
            for (i, data) in extensions
                .iter()
                .enumerate()
                .map(|(i, ext)| (usize_to_capnp_len(i), ext.get_encoded().unwrap()))
            {
                e.reborrow().set(i, &data);
            }
        } else {
            builder.init_public_extensions().set_none(());
        }
    }
}

impl CapnprotoPayloadDecode for ReportMetadata {
    type Reader<'a> = report_metadata::Reader<'a>;

    fn decode_from_reader(reader: Self::Reader<'_>) -> capnp::Result<Self>
    where
        Self: Sized,
    {
        let id = <_>::decode_from_reader(reader.get_id()?)?;
        let time = reader.get_time();
        let public_extensions = match reader.get_public_extensions()?.which()? {
            public_extensions_list::List(list) => Some(
                list?
                    .into_iter()
                    .map(|data| {
                        Extension::get_decoded(data?)
                            .map_err(|e| capnp::Error::failed(e.to_string()))
                    })
                    .collect::<Result<Vec<_>, capnp::Error>>()?,
            ),
            public_extensions_list::None(()) => None,
        };

        Ok(Self {
            id,
            time,
            public_extensions,
        })
    }
}

impl CapnprotoPayloadEncode for InitializedReport<WithPeerPrepShare> {
    type Builder<'a> = initialized_reports::initialized_report::Builder<'a>;

    fn encode_to_builder(&self, builder: Self::Builder<'_>) {
        match self {
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
        }
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
            builder.init_reports(usize_to_capnp_len(reports.len())),
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

fn to_capnp<E: ToString>(e: E) -> capnp::Error {
    capnp::Error {
        kind: capnp::ErrorKind::Failed,
        extra: e.to_string(),
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::capnproto::{CapnprotoPayloadDecodeExt, CapnprotoPayloadEncodeExt};

    #[test]
    fn report_metadata_roundtrip() {
        let report_metadata = ReportMetadata {
            id: messages::ReportId(rand::random()),
            time: rand::random(),
            public_extensions: Some(vec![
                Extension::Taskprov,
                Extension::NotImplemented {
                    typ: 23,
                    payload: b"some extension payload".to_vec(),
                },
            ]),
        };

        assert_eq!(
            report_metadata,
            ReportMetadata::decode_from_bytes(&report_metadata.encode_to_bytes()).unwrap()
        );
    }

    #[test]
    fn report_metadata_roundtrip_draft09() {
        let report_metadata = ReportMetadata {
            id: messages::ReportId(rand::random()),
            time: rand::random(),
            // draft09 compatibility: Previously there was no extensions field in the report
            // metadata.
            public_extensions: None,
        };

        assert_eq!(
            report_metadata,
            ReportMetadata::decode_from_bytes(&report_metadata.encode_to_bytes()).unwrap()
        );
    }
}
