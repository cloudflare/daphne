// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use crate::{
    fatal_error,
    hpke::HpkeConfig,
    messages::{
        decode_base64url_vec,
        taskprov::{QueryConfigVar, TaskConfig, VdafType, VdafTypeVar},
        Extension, ReportMetadata, TaskId,
    },
    vdaf::VdafVerifyKey,
    DapAbort, DapError, DapQueryConfig, DapRequest, DapTaskConfig, DapVersion, Prio3Config,
    VdafConfig,
};
use prio::codec::ParameterizedDecode;
use ring::{
    digest,
    hkdf::{Prk, Salt, HKDF_SHA256},
};
use serde::{Deserialize, Serialize};
use std::{borrow::Cow, str};
use url::Url;

/// DAP taskprov version.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum TaskprovVersion {
    #[serde(rename = "v02")]
    Draft02,

    #[serde(other)]
    Unknown,
}

/// SHA-256 of "dap-taskprov"
#[allow(dead_code)]
pub(crate) const TASK_PROV_SALT_DRAFT02: [u8; 32] = [
    0x28, 0xb9, 0xbb, 0x4f, 0x62, 0x4f, 0x67, 0x9a, 0xc1, 0x98, 0xd9, 0x68, 0xf4, 0xb0, 0x9e, 0xec,
    0x74, 0x01, 0x7a, 0x52, 0xcb, 0x4c, 0xf6, 0x39, 0xfb, 0x83, 0xe0, 0x47, 0x72, 0x3a, 0x0f, 0xfe,
];

fn compute_task_id_draft02(serialized: &[u8]) -> TaskId {
    let d = digest::digest(&digest::SHA256, serialized);
    let dref = d.as_ref();
    let mut b: [u8; 32] = [0; 32];
    b[..32].copy_from_slice(&dref[..32]);
    TaskId(b)
}

/// Compute the task id of a serialized task config.
pub fn compute_task_id(version: TaskprovVersion, serialized: &[u8]) -> Result<TaskId, DapError> {
    match version {
        TaskprovVersion::Draft02 => Ok(compute_task_id_draft02(serialized)),
        TaskprovVersion::Unknown => Err(fatal_error!(
            err = "attempted to resolve taskprov task with unknown version",
        )),
    }
}

// The documentation for ring::hkdf says computing the Salt is expensive, and we use the same PRK all the
// time, so we have structured the code so it would be possible to generate the PRK once and then
// compute a VDAF verify key many times from the PRK, but we do not actually exploit this currently.

/// Extract pseudorandom key from the pre-shared secret used for the "taskprov" extension.
pub(crate) fn extract_prk_from_verify_key_init(
    version: TaskprovVersion,
    verify_key_init: &[u8; 32],
) -> Prk {
    // The documentation says computing the Salt is expensive, and we use the same PRK all the
    // time, so we compute it once.
    let value = match version {
        TaskprovVersion::Draft02 => &TASK_PROV_SALT_DRAFT02,
        _ => panic!("unimplemented taskprov version"),
    };
    Salt::new(HKDF_SHA256, value).extract(verify_key_init)
}

/// Expand a pseudorandom key into the VDAF verification key for a given task.
pub(crate) fn expand_prk_into_verify_key(
    prk: &Prk,
    task_id: &TaskId,
    vdaf_type: VdafType,
) -> VdafVerifyKey {
    let info = [task_id.as_ref()];
    // This expand(), and the associated fill() below can only fail if the length is wrong,
    // and it won't be, so we unwrap().
    let okm = prk.expand(&info, vdaf_type).unwrap();
    match &vdaf_type {
        VdafType::Prio3Aes128Count | VdafType::Prio3Aes128Sum | VdafType::Prio3Aes128Histogram => {
            let mut bytes = [0u8; 16];
            okm.fill(&mut bytes[..]).unwrap();
            VdafVerifyKey::Prio3(bytes)
        }
        _ => panic!("Unknown VDAF type"),
    }
}

/// Compute the VDAF verify key for task_id and the specified VDAF type using the
/// pre-shared secret verify_key_init.
///
/// This is a convenience function to call compute_vdaf_verify_prk() and
/// compute_vdaf_verify_key_from_prk(). Callers reusing the same PRK frequently
/// should consider computing the prk once and then calling compute_vdaf_verify_key_from_prk()
/// directly.
#[allow(dead_code)]
pub(crate) fn compute_vdaf_verify_key(
    version: TaskprovVersion,
    verify_key_init: &[u8; 32],
    task_id: &TaskId,
    vdaf_type: VdafType,
) -> VdafVerifyKey {
    expand_prk_into_verify_key(
        &extract_prk_from_verify_key_init(version, verify_key_init),
        task_id,
        vdaf_type,
    )
}

/// Opt out due to invalid configuration.
//
// TODO taskprov spec: Decide if this should be a different error type.
fn malformed_task_config(task_id: &TaskId, detail: String) -> DapError {
    DapError::Abort(DapAbort::InvalidTask {
        detail,
        task_id: task_id.clone(),
    })
}

/// Convert a task config advertised by the peer into a [`DapTaskConfig`].
///
/// The `task_id` is the task ID indicated by the request; if this does not match the derived task
/// ID, then we return `Err(DapError::Abort(DapAbort::UnrecognizedTask))`.
///
/// We first look for the taskprov advertisement first in the request header (`req.taskprov`, which
/// is set to the value of the "dap-taskprov" HTTP header, if available). We then look for the
/// advertisement in the metadata of one of the reports incident to the request
/// (`report_metadata_advertisement.extensions`). If not found, then we return `Ok(None)`.
pub fn resolve_advertised_task_config<S>(
    req: &'_ DapRequest<S>,
    taskprov_version: TaskprovVersion,
    verify_key_init: &[u8; 32],
    collector_hpke_config: &HpkeConfig,
    task_id: &TaskId,
    report_metadata_advertisement: Option<&ReportMetadata>,
) -> Result<Option<DapTaskConfig>, DapError> {
    let Some(advertised_task_config) = get_taskprov_task_config(
        req,
        taskprov_version,
        task_id,
        report_metadata_advertisement,
    ).map_err(DapError::Abort)? else {
        return Ok(None);
    };

    let task_config = DapTaskConfig::try_from_taskprov(
        req.version,
        taskprov_version,
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
    taskprov_version: TaskprovVersion,
    task_id: &TaskId,
    report_metadata_advertisement: Option<&ReportMetadata>,
) -> Result<Option<TaskConfig>, DapAbort> {
    let taskprov_data = if let Some(ref taskprov_base64url) = req.taskprov {
        Cow::Owned(decode_base64url_vec(taskprov_base64url).ok_or_else(|| {
            DapAbort::BadRequest(
                r#"Invalid advertisement in "dap-taskprov" header: base64url parsing failed"#
                    .to_string(),
            )
        })?)
    } else if let Some(metadata) = report_metadata_advertisement {
        let taskprovs: Vec<&Extension> = metadata
            .extensions
            .iter()
            .filter(|x| matches!(x, Extension::Taskprov { .. }))
            .collect();
        match taskprovs.len() {
            0 => return Ok(None),
            1 => match &taskprovs[0] {
                Extension::Taskprov { payload } => Cow::Borrowed(payload),
                _ => panic!("cannot happen"),
            },
            _ => {
                // The decoder already returns an error if an extension of a give type occurs more
                // than once.
                panic!("should not happen")
            }
        }
    } else {
        return Ok(None);
    };

    if compute_task_id(taskprov_version, taskprov_data.as_ref())? != *task_id {
        // Return unrecognizedTask following section 5.1 of the taskprov draft.
        return Err(DapAbort::UnrecognizedTask);
    }

    // Return unrecognizedMessage if parsing fails following section 5.1 of the taskprov draft.
    let task_config = TaskConfig::get_decoded_with_param(&taskprov_version, taskprov_data.as_ref())
        .map_err(|e| DapAbort::from_codec_error(e, task_id.clone()))?;

    Ok(Some(task_config))
}

fn url_from_bytes(task_id: &TaskId, url_bytes: &[u8]) -> Result<Url, DapError> {
    let url_string = str::from_utf8(url_bytes).map_err(|e| {
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

impl From<QueryConfigVar> for DapQueryConfig {
    fn from(var: QueryConfigVar) -> Self {
        match var {
            QueryConfigVar::FixedSize { max_batch_size } => DapQueryConfig::FixedSize {
                max_batch_size: max_batch_size.into(),
            },
            QueryConfigVar::TimeInterval => DapQueryConfig::TimeInterval,
        }
    }
}

impl From<VdafTypeVar> for VdafConfig {
    fn from(var: VdafTypeVar) -> Self {
        match var {
            VdafTypeVar::Prio3Aes128Count => VdafConfig::Prio3(Prio3Config::Count),
            VdafTypeVar::Prio3Aes128Histogram { len_length } => {
                VdafConfig::Prio3(Prio3Config::Histogram {
                    len: len_length.into(),
                })
            }
            VdafTypeVar::Prio3Aes128Sum { bit_length } => VdafConfig::Prio3(Prio3Config::Sum {
                bits: bit_length.into(),
            }),
            VdafTypeVar::Poplar1Aes128 { .. } | VdafTypeVar::NotImplemented(..) => {
                unreachable!("VDAF not implemented")
            }
        }
    }
}

impl DapTaskConfig {
    pub fn try_from_taskprov(
        dap_version: DapVersion,
        taskprov_version: TaskprovVersion,
        task_id: &TaskId,
        task_config: TaskConfig,
        vdaf_verify_key_init: &[u8; 32],
        collector_hpke_config: &HpkeConfig,
    ) -> Result<DapTaskConfig, DapError> {
        if task_config.aggregator_endpoints.len() != 2 {
            return Err(malformed_task_config(
                task_id,
                format!(
                    "The task config indicates an invalid number of Aggregators ({})",
                    task_config.aggregator_endpoints.len()
                ),
            ));
        }
        let vdaf_type = VdafType::from(task_config.vdaf_config.var.clone());
        Ok(DapTaskConfig {
            version: dap_version,
            leader_url: url_from_bytes(task_id, &task_config.aggregator_endpoints[0].bytes)?,
            helper_url: url_from_bytes(task_id, &task_config.aggregator_endpoints[1].bytes)?,
            time_precision: task_config.query_config.time_precision,
            expiration: task_config.task_expiration,
            min_batch_size: task_config.query_config.min_batch_size.into(),
            query: DapQueryConfig::from(task_config.query_config.var),
            vdaf: VdafConfig::from(task_config.vdaf_config.var),
            vdaf_verify_key: compute_vdaf_verify_key(
                taskprov_version,
                vdaf_verify_key_init,
                task_id,
                vdaf_type,
            ),
            collector_hpke_config: collector_hpke_config.clone(),
            taskprov: true,
        })
    }
}

impl ReportMetadata {
    /// Does this metatdata have a taskprov extension and does it match the specified id?
    pub fn is_taskprov(&self, version: TaskprovVersion, task_id: &TaskId) -> bool {
        // Don't check for taskprov usage if we don't know the version.
        if matches!(version, TaskprovVersion::Unknown) {
            return false;
        }

        return self.extensions.iter().any(|x| match x {
            Extension::Taskprov { payload } => {
                *task_id == compute_task_id(version, payload).unwrap()
            }
            _ => false,
        });
    }
}
