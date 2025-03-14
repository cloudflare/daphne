// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! draft-wang-ppm-dap-taskprov: Functions for implementing the taskprov extension. The extension's
//! behavior depends on the version of DAP, i.e., each version of taskprov implies a version of
//! DAP.

use std::num::NonZeroUsize;

use crate::{
    error::DapAbort,
    fatal_error,
    hpke::HpkeConfig,
    messages::{self, taskprov::TaskprovAdvertisement, Duration, TaskId, Time},
    pine::PineParam,
    roles::aggregator::TaskprovConfig,
    vdaf::VdafVerifyKey,
    vdaf::{
        pine::{pine32_hmac_sha256_aes128, pine64_hmac_sha256_aes128, PineConfig},
        Prio3Config,
    },
    DapBatchMode, DapError, DapTaskConfig, DapTaskConfigMethod, DapTaskLifetime, DapVersion,
    VdafConfig,
};
use ring::{
    digest,
    hkdf::{Prk, Salt, HKDF_SHA256},
};
use serde::{Deserialize, Serialize};
use url::Url;

/// SHA-256 of `b"dap-taskprov"`.
const TASKPROV_SALT: [u8; 32] = [
    40, 185, 187, 79, 98, 79, 103, 154, 193, 152, 217, 104, 244, 176, 158, 236, 116, 1, 122, 82,
    203, 76, 246, 57, 251, 131, 224, 71, 114, 58, 15, 254,
];

/// SHA-256 of `b"dap-takprov task id"`.
const TASKPROV_TASK_ID_SALT: [u8; 32] = [
    70, 13, 237, 116, 40, 100, 135, 190, 152, 104, 104, 209, 157, 184, 219, 27, 5, 132, 88, 56,
    228, 214, 41, 30, 241, 91, 110, 32, 82, 11, 220, 130,
];

/// Compute the task id of a serialized task config.
pub(crate) fn compute_task_id(version: DapVersion, taskprov_advertisemnt_bytes: &[u8]) -> TaskId {
    let mut hash = ring::digest::Context::new(&digest::SHA256);
    if version == DapVersion::Latest {
        hash.update(&TASKPROV_TASK_ID_SALT);
    }
    hash.update(taskprov_advertisemnt_bytes);
    let digest = hash.finish();
    TaskId(digest.as_ref().try_into().unwrap())
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

fn expand_into_taskprov_verify_key(prk: &Prk, task_id: &TaskId) -> VdafVerifyKey {
    let mut verify_key = VdafVerifyKey([0; 32]);
    let info = [task_id.as_ref()];
    // This expand(), and the associated fill() below can only fail if the length is wrong,
    // and it won't be, so we unwrap().
    let okm = prk.expand(&info, verify_key.clone()).unwrap();
    okm.fill(verify_key.as_mut()).unwrap();
    verify_key
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
) -> VdafVerifyKey {
    expand_into_taskprov_verify_key(
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

impl DapBatchMode {
    fn try_from_taskprov_advertisement(
        task_id: &TaskId,
        var: messages::taskprov::QueryConfig,
    ) -> Result<Self, DapAbort> {
        match var {
            messages::taskprov::QueryConfig::LeaderSelected {
                draft09_max_batch_size,
            } => Ok(DapBatchMode::LeaderSelected {
                draft09_max_batch_size,
            }),
            messages::taskprov::QueryConfig::TimeInterval => Ok(DapBatchMode::TimeInterval),
            messages::taskprov::QueryConfig::NotImplemented { mode, .. } => {
                Err(DapAbort::InvalidTask {
                    detail: format!("unimplemented batch mode ({mode})"),
                    task_id: *task_id,
                })
            }
        }
    }
}

impl PineParam {
    fn opt_out_reason(&self, min_proofs: u8) -> Option<String> {
        const MAX_DIM: usize = 300_000;
        const MAX_PROOFS: u8 = 8;
        const MIN_WR_SUCCESSES: usize = 30;
        const MAX_WR_TESTS: usize = 165;

        if self.dimension > MAX_DIM {
            Some(format!("dimension must not exceed {MAX_DIM}"))
        } else if self.num_wr_successes < MIN_WR_SUCCESSES {
            Some(format!(
                "number of wraparound test successes must be at least {MIN_WR_SUCCESSES}"
            ))
        } else if self.num_wr_tests > MAX_WR_TESTS {
            Some(format!(
                "number of wraparound tests must not exceed {MAX_WR_TESTS}"
            ))
        } else if !(min_proofs..=MAX_PROOFS).contains(&self.num_proofs) {
            Some(format!(
                "number of proofs must be in range {min_proofs}..{MAX_PROOFS} inclusive"
            ))
        } else if !(1..=MAX_PROOFS).contains(&self.num_proofs_sq_norm_equal) {
            Some(format!(
                "number of proofs for the squared norm equality check must be in range 1..{MAX_PROOFS} inclusive"
            ))
        } else {
            None
        }
    }
}

impl VdafConfig {
    fn try_from_taskprov_advertisement(
        task_id: &TaskId,
        version: DapVersion,
        vdaf_config: messages::taskprov::VdafConfig,
    ) -> Result<Self, DapAbort> {
        const PRIO3_MAX_PROOFS: u8 = 3;

        match (version, vdaf_config) {
            (_, messages::taskprov::VdafConfig::Prio2 { dimension }) => Ok(VdafConfig::Prio2 {
                dimension: dimension.try_into().map_err(|_| DapAbort::InvalidTask {
                    detail: "dimension is larger than the system's word size".to_string(),
                    task_id: *task_id,
                })?,
            }),
            (
                DapVersion::Draft09,
                messages::taskprov::VdafConfig::Prio3SumVecField64MultiproofHmacSha256Aes128 {
                    bits,
                    length,
                    chunk_length,
                    num_proofs,
                },
            ) => {
                if !(1..=PRIO3_MAX_PROOFS).contains(&num_proofs) {
                    return Err(DapAbort::InvalidTask {
                        detail: format!(
                            "number of proofs must be in range 1..{PRIO3_MAX_PROOFS} inclusive"
                        ),
                        task_id: *task_id,
                    });
                }
                Ok(VdafConfig::Prio3(
                    Prio3Config::Draft09SumVecField64MultiproofHmacSha256Aes128 {
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
            (
                DapVersion::Draft09,
                messages::taskprov::VdafConfig::Pine32HmacSha256Aes128 { param },
            ) => {
                if let Err(e) = pine32_hmac_sha256_aes128(&param) {
                    Err(DapAbort::InvalidTask {
                        detail: format!("invalid parameters for Pine32: {e}"),
                        task_id: *task_id,
                    })
                } else if let Some(reason) = param.opt_out_reason(5) {
                    Err(DapAbort::InvalidTask {
                        detail: format!("unsupported parameters for Pine32: {reason}"),
                        task_id: *task_id,
                    })
                } else {
                    Ok(VdafConfig::Pine(PineConfig::Field32HmacSha256Aes128 {
                        param,
                    }))
                }
            }
            (
                DapVersion::Draft09,
                messages::taskprov::VdafConfig::Pine64HmacSha256Aes128 { param },
            ) => {
                if let Err(e) = pine64_hmac_sha256_aes128(&param) {
                    Err(DapAbort::InvalidTask {
                        detail: format!("invalid parameters for Pine64: {e}"),
                        task_id: *task_id,
                    })
                } else if let Some(reason) = param.opt_out_reason(2) {
                    Err(DapAbort::InvalidTask {
                        detail: format!("unsupported parameters for Pine64: {reason}"),
                        task_id: *task_id,
                    })
                } else {
                    Ok(VdafConfig::Pine(PineConfig::Field64HmacSha256Aes128 {
                        param,
                    }))
                }
            }
            (_, messages::taskprov::VdafConfig::NotImplemented { typ, .. }) => {
                Err(DapAbort::InvalidTask {
                    detail: format!("unimplemented VDAF type ({typ})"),
                    task_id: *task_id,
                })
            }
            (_, _) => Err(DapAbort::InvalidTask {
                detail: format!("VDAF not supported in {version}"),
                task_id: *task_id,
            }),
        }
    }
}

#[derive(Clone, Deserialize, Serialize)]
pub struct OptInParam {
    /// Same as [`DapTaskConfig`].
    pub not_before: Time,

    /// Same as [`DapTaskConfig`].
    #[serde(default = "crate::default_num_agg_span_shards")]
    pub num_agg_span_shards: NonZeroUsize,
}

/// A task config configured by taskprov that we still need to opt into.
#[cfg_attr(any(test, feature = "test-utils"), derive(Debug))]
pub struct DapTaskConfigNeedsOptIn {
    /// Same as [`DapTaskConfig`].
    pub(crate) version: DapVersion,
    pub(crate) leader_url: Url,
    pub(crate) helper_url: Url,
    pub(crate) time_precision: Duration,
    pub(crate) min_batch_size: u64,
    pub(crate) query: DapBatchMode,
    pub(crate) vdaf: VdafConfig,
    pub(crate) vdaf_verify_key: VdafVerifyKey,
    pub(crate) collector_hpke_config: HpkeConfig,
    pub(crate) method: DapTaskConfigMethod,

    /// Lifetime of the task.
    ///
    /// draft09: Only the expiration date is conveyed by the taskprov advertisement.
    pub lifetime: DapTaskLifetime,
}

impl DapTaskConfigNeedsOptIn {
    /// Return the time after which the task is no longer valid.
    pub fn not_after(&self) -> Time {
        match self.lifetime {
            DapTaskLifetime::Draft09 { expiration } => expiration,
            DapTaskLifetime::Latest { start, duration } => start + duration,
        }
    }

    pub(crate) fn try_from_taskprov_advertisement(
        version: DapVersion,
        task_id: &TaskId,
        taskprov_advertisement: TaskprovAdvertisement,
        taskprov_config: TaskprovConfig<'_>,
    ) -> Result<Self, DapAbort> {
        // Only one query per batch is currently supported.
        if !matches!(
            taskprov_advertisement.draft09_max_batch_query_count,
            None | Some(1)
        ) {
            return Err(DapAbort::InvalidTask {
                detail: format!(
                    "unsupported max batch query count {:?}",
                    taskprov_advertisement.draft09_max_batch_query_count
                ),
                task_id: *task_id,
            });
        }

        let vdaf = VdafConfig::try_from_taskprov_advertisement(
            task_id,
            version,
            taskprov_advertisement.vdaf_config,
        )?;
        let vdaf_verify_key =
            compute_vdaf_verify_key(version, taskprov_config.vdaf_verify_key_init, task_id);
        Ok(Self {
            version,
            leader_url: url_from_bytes(task_id, &taskprov_advertisement.leader_url.bytes)?,
            helper_url: url_from_bytes(task_id, &taskprov_advertisement.helper_url.bytes)?,
            time_precision: taskprov_advertisement.time_precision,
            lifetime: taskprov_advertisement.lifetime,
            min_batch_size: taskprov_advertisement.min_batch_size.into(),
            query: DapBatchMode::try_from_taskprov_advertisement(
                task_id,
                taskprov_advertisement.query_config,
            )?,
            vdaf,
            vdaf_verify_key,
            collector_hpke_config: taskprov_config.hpke_collector_config.clone(),
            method: DapTaskConfigMethod::Taskprov {
                info: taskprov_advertisement.task_info,
            },
        })
    }

    /// Complete configuration of a task via taskprov using the supplied parameters.
    pub fn into_opted_in(self, param: &OptInParam) -> DapTaskConfig {
        let (not_before, not_after) = match self.lifetime {
            DapTaskLifetime::Latest { start, duration } => (start, start.saturating_add(duration)),
            // draft09 compatibility: Previously the task start time was not conveyed by the
            // taskprov advertisement, so we need to get this value from the opt-in parameters.
            DapTaskLifetime::Draft09 { expiration } => (param.not_before, expiration),
        };

        DapTaskConfig {
            version: self.version,
            leader_url: self.leader_url,
            helper_url: self.helper_url,
            time_precision: self.time_precision,
            min_batch_size: self.min_batch_size,
            query: self.query,
            vdaf: self.vdaf,
            not_before,
            not_after,
            vdaf_verify_key: self.vdaf_verify_key,
            collector_hpke_config: self.collector_hpke_config,
            method: self.method,
            num_agg_span_shards: param.num_agg_span_shards,
        }
    }
}

impl TryFrom<&DapBatchMode> for messages::taskprov::QueryConfig {
    type Error = DapError;

    fn try_from(query_config: &DapBatchMode) -> Result<Self, DapError> {
        Ok(match query_config {
            DapBatchMode::TimeInterval => messages::taskprov::QueryConfig::TimeInterval,
            DapBatchMode::LeaderSelected {
                draft09_max_batch_size,
            } => messages::taskprov::QueryConfig::LeaderSelected {
                draft09_max_batch_size: *draft09_max_batch_size,
            },
        })
    }
}

impl TryFrom<&VdafConfig> for messages::taskprov::VdafConfig {
    type Error = DapError;

    fn try_from(vdaf_config: &VdafConfig) -> Result<Self, DapError> {
        match vdaf_config {
            VdafConfig::Prio2 { dimension } => Ok(Self::Prio2 {
                dimension: (*dimension).try_into().map_err(|_| {
                    fatal_error!(err = "{vdaf_config}: dimension is too large for taskprov")
                })?,
            }),
            VdafConfig::Prio3(Prio3Config::Draft09SumVecField64MultiproofHmacSha256Aes128 {
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
            #[cfg(feature = "experimental")]
            VdafConfig::Mastic { .. } => Err(fatal_error!(
                err = format!("{vdaf_config} is not currently supported for taskprov")
            )),
            VdafConfig::Pine(PineConfig::Field32HmacSha256Aes128 { param }) => {
                Ok(Self::Pine32HmacSha256Aes128 { param: *param })
            }
            VdafConfig::Pine(PineConfig::Field64HmacSha256Aes128 { param }) => {
                Ok(Self::Pine64HmacSha256Aes128 { param: *param })
            }
        }
    }
}

impl TryFrom<&DapTaskConfig> for messages::taskprov::TaskprovAdvertisement {
    type Error = DapError;

    fn try_from(task_config: &DapTaskConfig) -> Result<Self, DapError> {
        let DapTaskConfigMethod::Taskprov { info: task_info } = &task_config.method else {
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
            time_precision: task_config.time_precision,
            min_batch_size: task_config
                .min_batch_size
                .try_into()
                .map_err(|_| fatal_error!(err = "task min batch size is too large for taskprov"))?,
            query_config: (&task_config.query).try_into()?,
            lifetime: task_config.lifetime(),
            vdaf_config: (&task_config.vdaf).try_into()?,
            extensions: Vec::new(),
            draft09_max_batch_query_count: match task_config.version {
                DapVersion::Draft09 => Some(1),
                DapVersion::Latest => None,
            },
            draft09_dp_config: match task_config.version {
                DapVersion::Draft09 => Some(messages::taskprov::DpConfig::None),
                DapVersion::Latest => None,
            },
        })
    }
}

#[cfg(test)]
mod test {
    use std::num::{NonZeroU32, NonZeroUsize};

    use prio::codec::ParameterizedEncode;

    use super::{compute_task_id, compute_vdaf_verify_key};
    use crate::{
        error::DapAbort,
        hpke::{HpkeKemId, HpkeReceiverConfig},
        messages::{self, TaskId},
        taskprov::{DapTaskConfigNeedsOptIn, OptInParam},
        test_versions,
        vdaf::VdafVerifyKey,
        DapRequestMeta, DapTaskLifetime, DapVersion,
    };

    /// Test conversion between the serialized task configuration and a `DapTaskConfig`.
    fn try_from_taskprov_advertisement(version: DapVersion) {
        let taskprov_advertisemnt = messages::taskprov::TaskprovAdvertisement {
            task_info: "cool task".as_bytes().to_vec(),
            leader_url: messages::taskprov::UrlBytes {
                bytes: b"https://leader.com/".to_vec(),
            },
            helper_url: messages::taskprov::UrlBytes {
                bytes: b"http://helper.org:8788/".to_vec(),
            },
            time_precision: 3600,
            min_batch_size: 1,
            query_config: messages::taskprov::QueryConfig::LeaderSelected {
                draft09_max_batch_size: match version {
                    DapVersion::Draft09 => Some(NonZeroU32::new(2).unwrap()),
                    DapVersion::Latest => None,
                },
            },
            lifetime: DapTaskLifetime::from_validity_range(version, 1337, 1337),
            vdaf_config: messages::taskprov::VdafConfig::Prio2 { dimension: 10 },
            extensions: Vec::new(),
            draft09_max_batch_query_count: match version {
                DapVersion::Draft09 => Some(1),
                DapVersion::Latest => None,
            },
            draft09_dp_config: match version {
                DapVersion::Draft09 => Some(messages::taskprov::DpConfig::None),
                DapVersion::Latest => None,
            },
        };

        let task_id = compute_task_id(
            version,
            &taskprov_advertisemnt
                .get_encoded_with_param(&version)
                .unwrap(),
        );

        let task_config = DapTaskConfigNeedsOptIn::try_from_taskprov_advertisement(
            version,
            &task_id,
            taskprov_advertisemnt.clone(),
            crate::roles::aggregator::TaskprovConfig {
                hpke_collector_config: &HpkeReceiverConfig::gen(23, HpkeKemId::P256HkdfSha256)
                    .unwrap()
                    .config,
                vdaf_verify_key_init: &[0; 32],
            },
        )
        .unwrap()
        .into_opted_in(&OptInParam {
            not_before: 0,
            num_agg_span_shards: NonZeroUsize::new(1).unwrap(),
        });

        assert_eq!(
            messages::taskprov::TaskprovAdvertisement::try_from(&task_config).unwrap(),
            taskprov_advertisemnt
        );
    }

    test_versions! { try_from_taskprov_advertisement }

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
        let VdafVerifyKey(verify_key) =
            compute_vdaf_verify_key(version, &verify_key_init, &task_id);
        let expected: [u8; 32] = [
            251, 209, 125, 181, 57, 15, 148, 158, 227, 45, 38, 52, 220, 73, 159, 91, 145, 40, 123,
            204, 49, 124, 7, 97, 221, 4, 232, 53, 194, 171, 19, 51,
        ];
        assert_eq!(verify_key, expected);
    }

    test_versions! { check_vdaf_key_computation }

    #[test]
    fn check_task_id_draft09() {
        let taskprov_advertisemnt_bytes = messages::taskprov::TaskprovAdvertisement {
            task_info: "cool task".as_bytes().to_vec(),
            leader_url: messages::taskprov::UrlBytes {
                bytes: b"https://leader.com/".to_vec(),
            },
            helper_url: messages::taskprov::UrlBytes {
                bytes: b"http://helper.org:8788/".to_vec(),
            },
            time_precision: 3600,
            min_batch_size: 1,
            query_config: messages::taskprov::QueryConfig::LeaderSelected {
                draft09_max_batch_size: Some(NonZeroU32::new(2).unwrap()),
            },
            lifetime: DapTaskLifetime::Draft09 { expiration: 23 },
            vdaf_config: messages::taskprov::VdafConfig::Prio2 { dimension: 10 },
            extensions: Vec::new(),
            draft09_max_batch_query_count: Some(23),
            draft09_dp_config: Some(messages::taskprov::DpConfig::None),
        }
        .get_encoded_with_param(&DapVersion::Draft09)
        .unwrap();

        let expected_task_id = TaskId([
            142, 26, 248, 229, 126, 249, 222, 59, 10, 221, 34, 151, 27, 60, 28, 0, 134, 194, 142,
            84, 167, 128, 139, 140, 98, 35, 119, 117, 109, 108, 125, 211,
        ]);
        let task_id = compute_task_id(DapVersion::Latest, &taskprov_advertisemnt_bytes);
        println!("{:?}", task_id.0);
        assert_eq!(task_id, expected_task_id);
    }

    #[test]
    fn check_task_id() {
        let taskprov_advertisemnt_bytes = messages::taskprov::TaskprovAdvertisement {
            task_info: "cool task".as_bytes().to_vec(),
            leader_url: messages::taskprov::UrlBytes {
                bytes: b"https://leader.com/".to_vec(),
            },
            helper_url: messages::taskprov::UrlBytes {
                bytes: b"http://helper.org:8788/".to_vec(),
            },
            time_precision: 3600,
            min_batch_size: 1,
            query_config: messages::taskprov::QueryConfig::LeaderSelected {
                draft09_max_batch_size: None,
            },
            lifetime: DapTaskLifetime::Latest {
                start: 23,
                duration: 23,
            },
            vdaf_config: messages::taskprov::VdafConfig::Prio2 { dimension: 10 },
            extensions: Vec::new(),
            draft09_max_batch_query_count: None,
            draft09_dp_config: None,
        }
        .get_encoded_with_param(&DapVersion::Latest)
        .unwrap();

        let expected_task_id = TaskId([
            29, 66, 37, 142, 99, 73, 46, 14, 193, 147, 230, 204, 154, 75, 129, 177, 55, 2, 228, 62,
            227, 204, 248, 200, 120, 251, 5, 161, 203, 149, 72, 55,
        ]);
        let task_id = compute_task_id(DapVersion::Latest, &taskprov_advertisemnt_bytes);
        println!("{:?}", task_id.0);
        assert_eq!(task_id, expected_task_id);
    }

    fn resolve_advertised_task_config_expect_abort_unrecognized_vdaf(version: DapVersion) {
        // Create a request for a taskprov task with an unrecognized VDAF.
        let (req, task_id) = {
            let taskprov_advertisement = messages::taskprov::TaskprovAdvertisement {
                task_info: "cool task".as_bytes().to_vec(),
                leader_url: messages::taskprov::UrlBytes {
                    bytes: b"https://leader.com/".to_vec(),
                },
                helper_url: messages::taskprov::UrlBytes {
                    bytes: b"http://helper.org:8788/".to_vec(),
                },
                time_precision: 3600,
                min_batch_size: 1,
                query_config: messages::taskprov::QueryConfig::LeaderSelected {
                    draft09_max_batch_size: match version {
                        DapVersion::Draft09 => Some(NonZeroU32::new(2).unwrap()),
                        DapVersion::Latest => None,
                    },
                },
                lifetime: DapTaskLifetime::from_validity_range(version, 0, 0),
                // unrecognized VDAF
                vdaf_config: messages::taskprov::VdafConfig::NotImplemented {
                    typ: 1337,
                    param: b"vdaf type param".to_vec(),
                },
                extensions: Vec::new(),
                draft09_max_batch_query_count: match version {
                    DapVersion::Draft09 => Some(1),
                    DapVersion::Latest => None,
                },
                draft09_dp_config: match version {
                    DapVersion::Draft09 => Some(messages::taskprov::DpConfig::None),
                    DapVersion::Latest => None,
                },
            };
            let task_id = {
                compute_task_id(
                    version,
                    &taskprov_advertisement
                        .get_encoded_with_param(&version)
                        .unwrap(),
                )
            };

            let req = DapRequestMeta {
                version,
                task_id,
                taskprov_advertisement: Some(taskprov_advertisement),
                media_type: None, // ignored by test
            };

            (req, task_id)
        };

        let collector_hpke_config = HpkeReceiverConfig::gen(23, HpkeKemId::X25519HkdfSha256)
            .unwrap()
            .config;

        assert_matches::assert_matches!(
            DapTaskConfigNeedsOptIn::try_from_taskprov_advertisement(
                req.version,
                &task_id,
                req.taskprov_advertisement.unwrap(),
                crate::roles::aggregator::TaskprovConfig {
                    vdaf_verify_key_init: &[0; 32],
                    hpke_collector_config: &collector_hpke_config,
                },
            ).unwrap_err(),
            DapAbort::InvalidTask{ detail, .. } if detail == "unimplemented VDAF type (1337)"
        );
    }

    test_versions! { resolve_advertised_task_config_expect_abort_unrecognized_vdaf }

    fn resolve_advertised_task_config_ignore_unimplemented_dp_ocnfig(version: DapVersion) {
        // Create a request for a taskprov task with an unrecognized DP mechanism.
        let (req, task_id) = {
            let taskprov_advertisement = messages::taskprov::TaskprovAdvertisement {
                task_info: "cool task".as_bytes().to_vec(),
                leader_url: messages::taskprov::UrlBytes {
                    bytes: b"https://leader.com/".to_vec(),
                },
                helper_url: messages::taskprov::UrlBytes {
                    bytes: b"http://helper.org:8788/".to_vec(),
                },
                time_precision: 3600,
                min_batch_size: 1,
                query_config: messages::taskprov::QueryConfig::LeaderSelected {
                    draft09_max_batch_size: match version {
                        DapVersion::Draft09 => Some(NonZeroU32::new(2).unwrap()),
                        DapVersion::Latest => None,
                    },
                },
                lifetime: DapTaskLifetime::from_validity_range(version, 0, 0),
                vdaf_config: messages::taskprov::VdafConfig::Prio2 { dimension: 1337 },
                extensions: Vec::new(),
                draft09_max_batch_query_count: match version {
                    DapVersion::Draft09 => Some(1),
                    DapVersion::Latest => None,
                },
                draft09_dp_config: match version {
                    DapVersion::Draft09 => Some(messages::taskprov::DpConfig::NotImplemented {
                        typ: 99,
                        param: b"Just, do it!".to_vec(),
                    }),
                    DapVersion::Latest => None,
                },
            };
            let task_id = {
                compute_task_id(
                    version,
                    &taskprov_advertisement
                        .get_encoded_with_param(&version)
                        .unwrap(),
                )
            };

            let req = crate::DapRequestMeta {
                version,
                task_id,
                taskprov_advertisement: Some(taskprov_advertisement),
                media_type: None,
            };

            (req, task_id)
        };

        let collector_hpke_config = HpkeReceiverConfig::gen(23, HpkeKemId::X25519HkdfSha256)
            .unwrap()
            .config;

        let _ = DapTaskConfigNeedsOptIn::try_from_taskprov_advertisement(
            req.version,
            &task_id,
            req.taskprov_advertisement.unwrap(),
            crate::roles::aggregator::TaskprovConfig {
                hpke_collector_config: &collector_hpke_config,
                vdaf_verify_key_init: &[0; 32],
            },
        )
        .unwrap();
    }

    test_versions! { resolve_advertised_task_config_ignore_unimplemented_dp_ocnfig }
}
