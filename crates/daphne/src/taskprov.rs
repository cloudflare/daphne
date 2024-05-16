// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! draft-wang-ppm-dap-taskprov: Functions for implementing the taskprov extension. The extension's
//! behavior depends on the version of DAP, i.e., each version of taskprov implies a version of
//! DAP.

use crate::{
    fatal_error,
    hpke::HpkeConfig,
    messages::{
        self, decode_base64url_vec,
        taskprov::{QueryConfigVar, TaskConfig, VdafTypeVar},
        TaskId,
    },
    vdaf::VdafVerifyKey,
    DapAbort, DapError, DapQueryConfig, DapRequest, DapTaskConfig, DapTaskConfigMethod, DapVersion,
    Prio3Config, VdafConfig,
};
use prio::codec::ParameterizedDecode;
use ring::{
    digest,
    hkdf::{Prk, Salt, HKDF_SHA256},
};
use url::Url;

/// SHA-256 of "dap-taskprov"
#[allow(dead_code)]
pub(crate) const TASKPROV_SALT: [u8; 32] = [
    0x28, 0xb9, 0xbb, 0x4f, 0x62, 0x4f, 0x67, 0x9a, 0xc1, 0x98, 0xd9, 0x68, 0xf4, 0xb0, 0x9e, 0xec,
    0x74, 0x01, 0x7a, 0x52, 0xcb, 0x4c, 0xf6, 0x39, 0xfb, 0x83, 0xe0, 0x47, 0x72, 0x3a, 0x0f, 0xfe,
];

/// Compute the task id of a serialized task config.
pub(crate) fn compute_task_id(serialized: &[u8]) -> TaskId {
    let d = digest::digest(&digest::SHA256, serialized);
    let dref = d.as_ref();
    let mut b: [u8; 32] = [0; 32];
    b[..32].copy_from_slice(&dref[..32]);
    TaskId(b)
}

// The documentation for ring::hkdf says computing the Salt is expensive, and we use the same PRK all the
// time, so we have structured the code so it would be possible to generate the PRK once and then
// compute a VDAF verify key many times from the PRK, but we do not actually exploit this currently.

/// Extract pseudorandom key from the pre-shared secret used for the "taskprov" extension.
pub(crate) fn extract_prk_from_verify_key_init(
    _version: DapVersion,
    verify_key_init: &[u8; 32],
) -> Prk {
    // The documentation says computing the Salt is expensive, and we use the same PRK all the
    // time, so we compute it once.
    Salt::new(HKDF_SHA256, &TASKPROV_SALT).extract(verify_key_init)
}

impl VdafConfig {
    fn expand_into_taskprov_verify_key(&self, prk: &Prk, task_id: &TaskId) -> VdafVerifyKey {
        let mut verify_key = self.uninitialized_verify_key();
        let info = [task_id.as_ref()];
        // This expand(), and the associated fill() below can only fail if the length is wrong,
        // and it won't be, so we unwrap().
        let okm = prk.expand(&info, verify_key.clone()).unwrap();
        okm.fill(verify_key.as_mut()).unwrap();
        verify_key
    }
}

/// Compute the VDAF verify key for `task_id` and the specified VDAF type using the
/// pre-shared secret `verify_key_init`.
///
/// This is a convenience function to call `compute_vdaf_verify_prk`() and
/// `compute_vdaf_verify_key_from_prk`(). Callers reusing the same PRK frequently
/// should consider computing the prk once and then calling `compute_vdaf_verify_key_from_prk`()
/// directly.
fn compute_vdaf_verify_key(
    version: DapVersion,
    verify_key_init: &[u8; 32],
    task_id: &TaskId,
    vdaf_config: &VdafConfig,
) -> VdafVerifyKey {
    vdaf_config.expand_into_taskprov_verify_key(
        &extract_prk_from_verify_key_init(version, verify_key_init),
        task_id,
    )
}

/// Opt out due to invalid configuration.
//
// TODO taskprov spec: Decide if this should be a different error type.
fn malformed_task_config(task_id: &TaskId, detail: String) -> DapAbort {
    DapAbort::InvalidTask {
        detail,
        task_id: *task_id,
    }
}

/// Convert a task config advertised by the peer into a [`DapTaskConfig`].
///
/// The `task_id` is the task ID indicated by the request; if this does not match the derived task
/// ID, then we return `Err(DapError::Abort(DapAbort::UnrecognizedTask))`.
pub fn resolve_advertised_task_config<S>(
    req: &'_ DapRequest<S>,
    verify_key_init: &[u8; 32],
    collector_hpke_config: &HpkeConfig,
    task_id: &TaskId,
) -> Result<Option<DapTaskConfig>, DapAbort> {
    let Some(advertised_task_config) = get_taskprov_task_config(req, task_id)? else {
        return Ok(None);
    };

    let task_config = DapTaskConfig::try_from_taskprov(
        req.version,
        task_id, // get_taskprov_task_config() checks that this matches the derived ID
        advertised_task_config,
        verify_key_init,
        collector_hpke_config,
    )?;

    Ok(Some(task_config))
}

/// Check for a taskprov extension in the report, and return it if found.
fn get_taskprov_task_config<S>(
    req: &'_ DapRequest<S>,
    task_id: &TaskId,
) -> Result<Option<TaskConfig>, DapAbort> {
    let taskprov_data = if let Some(ref taskprov_base64url) = req.taskprov {
        decode_base64url_vec(taskprov_base64url).ok_or_else(|| {
            DapAbort::BadRequest(
                r#"Invalid advertisement in "dap-taskprov" header: base64url parsing failed"#
                    .to_string(),
            )
        })?
    } else {
        return Ok(None);
    };

    if compute_task_id(taskprov_data.as_ref()) != *task_id {
        // Return unrecognizedTask following section 5.1 of the taskprov draft.
        return Err(DapAbort::UnrecognizedTask);
    }

    // Return unrecognizedMessage if parsing fails following section 5.1 of the taskprov draft.
    let task_config = TaskConfig::get_decoded_with_param(&req.version, taskprov_data.as_ref())
        .map_err(|e| DapAbort::from_codec_error(e, *task_id))?;

    Ok(Some(task_config))
}

fn url_from_bytes(task_id: &TaskId, url_bytes: &[u8]) -> Result<Url, DapAbort> {
    let url_string = std::str::from_utf8(url_bytes).map_err(|e| {
        malformed_task_config(
            task_id,
            format!("Encountered error while parsing URL bytes as string: {e}"),
        )
    })?;
    Url::parse(url_string).map_err(|e| {
        malformed_task_config(
            task_id,
            format!("Encountered error while parsing URL string: {e}"),
        )
    })
}

impl DapQueryConfig {
    fn try_from_taskprov(task_id: &TaskId, var: QueryConfigVar) -> Result<Self, DapAbort> {
        match var {
            QueryConfigVar::FixedSize { max_batch_size: 0 } => Ok(DapQueryConfig::FixedSize {
                max_batch_size: None,
            }),
            QueryConfigVar::FixedSize { max_batch_size } => Ok(DapQueryConfig::FixedSize {
                max_batch_size: Some(max_batch_size.into()),
            }),
            QueryConfigVar::TimeInterval => Ok(DapQueryConfig::TimeInterval),
            QueryConfigVar::NotImplemented { typ, .. } => Err(DapAbort::InvalidTask {
                detail: format!("unimplemented query type ({typ})"),
                task_id: *task_id,
            }),
        }
    }
}

impl VdafConfig {
    fn try_from_taskprov(
        task_id: &TaskId,
        version: DapVersion,
        var: VdafTypeVar,
    ) -> Result<Self, DapAbort> {
        match (version, var) {
            (_, VdafTypeVar::Prio2 { dimension }) => Ok(VdafConfig::Prio2 {
                dimension: dimension.try_into().map_err(|_| DapAbort::InvalidTask {
                    detail: "dimension is larger than the system's word size".to_string(),
                    task_id: *task_id,
                })?,
            }),
            (
                DapVersion::Draft09 | DapVersion::Latest,
                VdafTypeVar::Prio3SumVecField64MultiproofHmacSha256Aes128 {
                    bits,
                    length,
                    chunk_length,
                    num_proofs,
                },
            ) => {
                const MAX_PROOFS: u8 = 3;
                if num_proofs == 0 || num_proofs > MAX_PROOFS {
                    return Err(DapAbort::InvalidTask { detail: format!("invalid number of proofs for Prio3SumVecField64MultiproofHmacSha256Aes128: got {num_proofs}; expected a value in range [0, {MAX_PROOFS}]"), task_id: *task_id });
                }
                Ok(VdafConfig::Prio3(
                    Prio3Config::SumVecField64MultiproofHmacSha256Aes128 {
                        bits: bits.into(),
                        length: length.try_into().map_err(|_| DapAbort::InvalidTask {
                            detail: "length is larger than the system's word size".to_string(),
                            task_id: *task_id,
                        })?,
                        chunk_length: chunk_length.try_into().map_err(|_| {
                            DapAbort::InvalidTask {
                                detail: "chunk_length is larger than the system's word size"
                                    .to_string(),
                                task_id: *task_id,
                            }
                        })?,
                        num_proofs,
                    },
                ))
            }
            (_, VdafTypeVar::NotImplemented { typ, .. }) => Err(DapAbort::InvalidTask {
                detail: format!("unimplemented VDAF type ({typ})"),
                task_id: *task_id,
            }),
        }
    }
}

impl DapTaskConfig {
    pub fn try_from_taskprov(
        version: DapVersion,
        task_id: &TaskId,
        task_config: TaskConfig,
        vdaf_verify_key_init: &[u8; 32],
        collector_hpke_config: &HpkeConfig,
    ) -> Result<DapTaskConfig, DapAbort> {
        // Only one query per batch is currently supported.
        if task_config.query_config.max_batch_query_count != 1 {
            return Err(DapAbort::InvalidTask {
                detail: format!(
                    "unsupported max batch query count {}",
                    task_config.query_config.max_batch_query_count
                ),
                task_id: *task_id,
            });
        }

        let vdaf = VdafConfig::try_from_taskprov(task_id, version, task_config.vdaf_config.var)?;
        let vdaf_verify_key =
            compute_vdaf_verify_key(version, vdaf_verify_key_init, task_id, &vdaf);
        Ok(DapTaskConfig {
            version,
            leader_url: url_from_bytes(task_id, &task_config.leader_url.bytes)?,
            helper_url: url_from_bytes(task_id, &task_config.helper_url.bytes)?,
            time_precision: task_config.query_config.time_precision,
            expiration: task_config.task_expiration,
            min_batch_size: task_config.query_config.min_batch_size.into(),
            query: DapQueryConfig::try_from_taskprov(task_id, task_config.query_config.var)?,
            vdaf,
            vdaf_verify_key,
            collector_hpke_config: collector_hpke_config.clone(),
            method: DapTaskConfigMethod::Taskprov {
                info: Some(task_config.task_info),
            },
        })
    }
}

impl TryFrom<&DapQueryConfig> for messages::taskprov::QueryConfigVar {
    type Error = DapError;

    fn try_from(query_config: &DapQueryConfig) -> Result<Self, DapError> {
        Ok(match query_config {
            DapQueryConfig::TimeInterval => messages::taskprov::QueryConfigVar::TimeInterval,
            DapQueryConfig::FixedSize { max_batch_size } => {
                messages::taskprov::QueryConfigVar::FixedSize {
                    max_batch_size: max_batch_size.unwrap_or(0).try_into().map_err(|_| {
                        fatal_error!(err = "task max batch size is too large for taskprov")
                    })?,
                }
            }
        })
    }
}

impl TryFrom<&VdafConfig> for messages::taskprov::VdafTypeVar {
    type Error = DapError;

    fn try_from(vdaf_config: &VdafConfig) -> Result<Self, DapError> {
        match vdaf_config {
            VdafConfig::Prio2 { dimension } => Ok(Self::Prio2 {
                dimension: (*dimension).try_into().map_err(|_| {
                    fatal_error!(err = "{vdaf_config}: dimension is too large for taskprov")
                })?,
            }),
            VdafConfig::Prio3(Prio3Config::SumVecField64MultiproofHmacSha256Aes128 {
                bits,
                length,
                chunk_length,
                num_proofs,
            }) => Ok(Self::Prio3SumVecField64MultiproofHmacSha256Aes128 {
                bits: (*bits).try_into().map_err(|_| {
                    fatal_error!(err = format!("{vdaf_config}: bits is too large for taskprov"))
                })?,
                length: (*length).try_into().map_err(|_| {
                    fatal_error!(err = format!("{vdaf_config}: bits is too large for taskprov"))
                })?,

                chunk_length: (*chunk_length).try_into().map_err(|_| {
                    fatal_error!(err = format!("{vdaf_config}: bits is too large for taskprov"))
                })?,
                num_proofs: *num_proofs,
            }),
            VdafConfig::Prio3(..) => Err(fatal_error!(
                err = format!("{vdaf_config} is not currently supported for taskprov")
            )),
            #[cfg(any(test, feature = "test-utils"))]
            VdafConfig::Mastic { .. } => Err(fatal_error!(
                err = format!("{vdaf_config} is not currently supported for taskprov")
            )),
        }
    }
}

impl TryFrom<&DapTaskConfig> for messages::taskprov::TaskConfig {
    type Error = DapError;

    fn try_from(task_config: &DapTaskConfig) -> Result<Self, DapError> {
        let DapTaskConfigMethod::Taskprov {
            info: Some(task_info),
        } = &task_config.method
        else {
            return Err(fatal_error!(err = "task was not configured by taskprov"));
        };

        Ok(Self {
            task_info: task_info.clone(),
            leader_url: messages::taskprov::UrlBytes {
                bytes: task_config.leader_url.to_string().into_bytes(),
            },
            helper_url: messages::taskprov::UrlBytes {
                bytes: task_config.helper_url.to_string().into_bytes(),
            },
            query_config: messages::taskprov::QueryConfig {
                time_precision: task_config.time_precision,
                min_batch_size: task_config.min_batch_size.try_into().map_err(|_| {
                    fatal_error!(err = "task min batch size is too large for taskprov")
                })?,
                max_batch_query_count: 1,
                var: (&task_config.query).try_into()?,
            },
            task_expiration: task_config.expiration,
            vdaf_config: messages::taskprov::VdafConfig {
                dp_config: messages::taskprov::DpConfig::None,
                var: (&task_config.vdaf).try_into()?,
            },
        })
    }
}

#[cfg(test)]
mod test {
    use assert_matches::assert_matches;
    use prio::codec::ParameterizedEncode;

    use super::{compute_task_id, compute_vdaf_verify_key, resolve_advertised_task_config};
    use crate::{
        error::DapAbort,
        hpke::{HpkeKemId, HpkeReceiverConfig},
        messages::{self, encode_base64url, TaskId},
        test_versions,
        vdaf::{VdafConfig, VdafVerifyKey},
        DapRequest, DapResource, DapTaskConfig, DapVersion,
    };

    /// Test conversion between the serialized task configuration and a `DapTaskConfig`.
    fn try_from_taskprov(version: DapVersion) {
        let taskprov_config = messages::taskprov::TaskConfig {
            task_info: "cool task".as_bytes().to_vec(),
            leader_url: messages::taskprov::UrlBytes {
                bytes: b"https://leader.com/".to_vec(),
            },
            helper_url: messages::taskprov::UrlBytes {
                bytes: b"http://helper.org:8788/".to_vec(),
            },
            query_config: messages::taskprov::QueryConfig {
                time_precision: 3600,
                max_batch_query_count: 1,
                min_batch_size: 1,
                var: messages::taskprov::QueryConfigVar::FixedSize { max_batch_size: 2 },
            },
            task_expiration: 1337,
            vdaf_config: messages::taskprov::VdafConfig {
                dp_config: messages::taskprov::DpConfig::None,
                var: messages::taskprov::VdafTypeVar::Prio2 { dimension: 10 },
            },
        };

        let task_id = compute_task_id(&taskprov_config.get_encoded_with_param(&version).unwrap());

        let task_config = DapTaskConfig::try_from_taskprov(
            version,
            &task_id,
            taskprov_config.clone(),
            &[0; 32],
            &HpkeReceiverConfig::gen(23, HpkeKemId::P256HkdfSha256)
                .unwrap()
                .config,
        )
        .unwrap();

        assert_eq!(
            messages::taskprov::TaskConfig::try_from(&task_config).unwrap(),
            taskprov_config
        );
    }

    test_versions! { try_from_taskprov }

    fn check_vdaf_key_computation(version: DapVersion) {
        let task_id = TaskId([
            0xb4, 0x76, 0x9b, 0xb0, 0x63, 0xa8, 0xb3, 0x31, 0x2a, 0xf7, 0x42, 0x97, 0xf3, 0x0f,
            0xdb, 0xf8, 0xe0, 0xb7, 0x1c, 0x2e, 0xb2, 0x48, 0x1f, 0x59, 0x1d, 0x1d, 0x7d, 0xe6,
            0x6a, 0x4c, 0xe3, 0x4f,
        ]);
        let verify_key_init: [u8; 32] = [
            0x1a, 0x2a, 0x3f, 0x1b, 0xeb, 0xb4, 0xbb, 0xe4, 0x55, 0xea, 0xac, 0xee, 0x29, 0x1a,
            0x0f, 0x32, 0xd7, 0xe1, 0xbc, 0x6c, 0x75, 0x10, 0x05, 0x60, 0x7b, 0x81, 0xda, 0xc3,
            0xa7, 0xda, 0x76, 0x1d,
        ];
        let vk = compute_vdaf_verify_key(
            version,
            &verify_key_init,
            &task_id,
            &VdafConfig::Prio2 { dimension: 10 },
        );
        let expected: [u8; 32] = [
            251, 209, 125, 181, 57, 15, 148, 158, 227, 45, 38, 52, 220, 73, 159, 91, 145, 40, 123,
            204, 49, 124, 7, 97, 221, 4, 232, 53, 194, 171, 19, 51,
        ];
        match &vk {
            VdafVerifyKey::L32(bytes) => assert_eq!(*bytes, expected),
            VdafVerifyKey::L16(..) => unreachable!(),
        }
    }

    test_versions! { check_vdaf_key_computation }

    fn resolve_advertised_task_config_expect_abort_unrecognized_vdaf(version: DapVersion) {
        // Create a request for a taskprov task with an unrecognized VDAF.
        let (req, task_id) = {
            let taskprov_task_config_bytes = messages::taskprov::TaskConfig {
                task_info: "cool task".as_bytes().to_vec(),
                leader_url: messages::taskprov::UrlBytes {
                    bytes: b"https://leader.com/".to_vec(),
                },
                helper_url: messages::taskprov::UrlBytes {
                    bytes: b"http://helper.org:8788/".to_vec(),
                },
                query_config: messages::taskprov::QueryConfig {
                    time_precision: 3600,
                    max_batch_query_count: 1,
                    min_batch_size: 1,
                    var: messages::taskprov::QueryConfigVar::FixedSize { max_batch_size: 2 },
                },
                task_expiration: 0,
                vdaf_config: messages::taskprov::VdafConfig {
                    dp_config: messages::taskprov::DpConfig::None,
                    // unrecognized VDAF
                    var: messages::taskprov::VdafTypeVar::NotImplemented {
                        typ: 1337,
                        param: b"vdaf type param".to_vec(),
                    },
                },
            }
            .get_encoded_with_param(&version)
            .unwrap();
            let task_id = compute_task_id(&taskprov_task_config_bytes);
            let taskprov_task_config_base64url = encode_base64url(&taskprov_task_config_bytes);

            let req = DapRequest::<()> {
                version,
                media_type: None, // ignored by test
                task_id: Some(task_id),
                resource: DapResource::Undefined, // ignored by test
                payload: Vec::default(),          // ignored by test
                sender_auth: None,                // ignored by test
                taskprov: Some(taskprov_task_config_base64url),
            };

            (req, task_id)
        };

        let collector_hpke_config = HpkeReceiverConfig::gen(23, HpkeKemId::X25519HkdfSha256)
            .unwrap()
            .config;

        assert_matches!(
            resolve_advertised_task_config(&req, &[0; 32], &collector_hpke_config, &task_id).unwrap_err(),
            DapAbort::InvalidTask{ detail, .. } if detail == "unimplemented VDAF type (1337)"
        );
    }

    test_versions! { resolve_advertised_task_config_expect_abort_unrecognized_vdaf }

    fn resolve_advertised_task_config_ignore_unimplemented_dp_ocnfig(version: DapVersion) {
        // Create a request for a taskprov task with an unrecognized DP mechanism.
        let (req, task_id) = {
            let taskprov_task_config_bytes = messages::taskprov::TaskConfig {
                task_info: "cool task".as_bytes().to_vec(),
                leader_url: messages::taskprov::UrlBytes {
                    bytes: b"https://leader.com/".to_vec(),
                },
                helper_url: messages::taskprov::UrlBytes {
                    bytes: b"http://helper.org:8788/".to_vec(),
                },
                query_config: messages::taskprov::QueryConfig {
                    time_precision: 3600,
                    max_batch_query_count: 1,
                    min_batch_size: 1,
                    var: messages::taskprov::QueryConfigVar::FixedSize { max_batch_size: 2 },
                },
                task_expiration: 0,
                vdaf_config: messages::taskprov::VdafConfig {
                    dp_config: messages::taskprov::DpConfig::NotImplemented {
                        typ: 99,
                        param: b"Just, do it!".to_vec(),
                    },
                    var: messages::taskprov::VdafTypeVar::Prio2 { dimension: 1337 },
                },
            }
            .get_encoded_with_param(&version)
            .unwrap();
            let task_id = compute_task_id(&taskprov_task_config_bytes);
            let taskprov_task_config_base64url = encode_base64url(&taskprov_task_config_bytes);

            let req = DapRequest::<()> {
                version,
                media_type: None, // ignored by test
                task_id: Some(task_id),
                resource: DapResource::Undefined, // ignored by test
                payload: Vec::default(),          // ignored by test
                sender_auth: None,                // ignored by test
                taskprov: Some(taskprov_task_config_base64url),
            };

            (req, task_id)
        };

        let collector_hpke_config = HpkeReceiverConfig::gen(23, HpkeKemId::X25519HkdfSha256)
            .unwrap()
            .config;

        let _ = resolve_advertised_task_config(&req, &[0; 32], &collector_hpke_config, &task_id)
            .unwrap();
    }

    test_versions! { resolve_advertised_task_config_ignore_unimplemented_dp_ocnfig }
}
