// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use crate::{
    messages::{
        taskprov::{QueryConfigVar, TaskConfig, VdafType, VdafTypeVar},
        Extension, HpkeConfig, Id, ReportMetadata,
    },
    vdaf::VdafVerifyKey,
    DapAbort, DapError, DapQueryConfig, DapTaskConfig, DapVersion, Prio3Config, VdafConfig,
};
use prio::codec::Decode;
use ring::{
    hkdf::{Prk, Salt, HKDF_SHA256},
    hmac::HMAC_SHA256,
    hmac::{sign, Key},
};
use std::str;
use url::Url;

/// SHA-256 of "dap-taskprov-00"
#[allow(dead_code)]
pub(crate) const TASK_PROV_SALT: [u8; 32] = [
    0x4d, 0x63, 0x1a, 0xeb, 0xa8, 0xdf, 0xe0, 0x1b, 0x34, 0x4c, 0x29, 0x2d, 0x17, 0xba, 0x34, 0x9a,
    0x78, 0x97, 0xbf, 0x64, 0x88, 0x00, 0x55, 0x1c, 0x0d, 0x75, 0x32, 0xab, 0x61, 0x4b, 0xe2, 0x21,
];

/// Compute the task id of a serialized task config.
pub fn compute_task_id(serialized: &[u8]) -> Id {
    // This is an implementation of HKDF-Expand as the ring::hkdf API does not expose the result
    // of the expand step.
    let key = Key::new(HMAC_SHA256, &TASK_PROV_SALT);
    let digest = sign(&key, serialized);
    let mut b: [u8; 32] = [0; 32];
    let d = digest.as_ref();
    b[..32].copy_from_slice(&d[..32]);
    Id(b)
}

// The documentation for ring::hkdf says computing the Salt is expensive, and we use the same PRK all the
// time, so we have structured the code so it would be possible to generate the PRK once and then
// compute a VDAF verify key many times from the PRK, but we do not actually exploit this currently.

/// Extract pseudorandom key from the pre-shared secret used for the "taskprov" extension.
pub(crate) fn extract_prk_from_verify_key_init(verify_key_init: &[u8]) -> Prk {
    // The documentation says computing the Salt is expensive, and we use the same PRK all the
    // time, so we compute it once.
    Salt::new(HKDF_SHA256, &TASK_PROV_SALT).extract(verify_key_init)
}

/// Expand a pseudorandom key into the VDAF verification key for a given task.
pub(crate) fn expand_prk_into_verify_key(
    prk: &Prk,
    task_id: &Id,
    vdaf_type: VdafType,
) -> VdafVerifyKey {
    let info = [task_id.as_ref()];
    match &vdaf_type {
        VdafType::Prio3Aes128Count | VdafType::Prio3Aes128Sum | VdafType::Prio3Aes128Histogram => {
            // This expand(), and the associated fill() below can only fail if the length is wrong,
            // and it won't be, so we unwrap().
            let okm = prk.expand(&info, vdaf_type.clone()).unwrap();
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
    verify_key_init: &[u8],
    task_id: &Id,
    vdaf_type: VdafType,
) -> VdafVerifyKey {
    expand_prk_into_verify_key(
        &extract_prk_from_verify_key_init(verify_key_init),
        task_id,
        vdaf_type,
    )
}

pub fn bad_request(detail: &str) -> DapError {
    DapError::Abort(DapAbort::BadRequest(detail.to_string()))
}

/// Check for a taskprov extension in the report, and return it if found.
pub fn get_taskprov_task_config(
    task_id: &Id,
    metadata: &ReportMetadata,
) -> Result<Option<TaskConfig>, DapError> {
    let taskprovs: Vec<&Extension> = metadata
        .extensions
        .iter()
        .filter(|x| matches!(x, Extension::Taskprov { .. }))
        .collect();
    match taskprovs.len() {
        0 => Ok(None),
        1 => match &taskprovs[0] {
            Extension::Taskprov { payload } => {
                if compute_task_id(&payload[..]) != *task_id {
                    // Return unrecognizedTask following section 5.1 of the taskprov draft.
                    return Err(DapError::Abort(DapAbort::UnrecognizedTask));
                }
                // Return unrecognizedMessage if parsing fails following section 5.1 of the taskprov draft.
                let task_config = TaskConfig::get_decoded(payload)
                    .map_err(|_| DapError::Abort(DapAbort::UnrecognizedMessage))?;
                Ok(Some(task_config))
            }
            _ => panic!("cannot happen"),
        },
        _ => {
            // The decoder already returns an error if an extension of a give type occurs more than once.
            panic!("should not happen")
        }
    }
}

fn url_from_bytes(bytes: &[u8]) -> Result<Url, DapError> {
    let s = str::from_utf8(bytes).map_err(|_| bad_request("bad URL UTF8"))?;
    Url::parse(s).map_err(|_| bad_request("bad URL syntax"))
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
            VdafTypeVar::Prio3Aes128Histogram { buckets } => {
                VdafConfig::Prio3(Prio3Config::Histogram { buckets })
            }
            VdafTypeVar::Prio3Aes128Sum { bit_length } => VdafConfig::Prio3(Prio3Config::Sum {
                bits: bit_length.into(),
            }),
            _ => panic!("poplar1 is not implemented"),
        }
    }
}

impl DapTaskConfig {
    pub fn try_from_taskprov(
        version: DapVersion,
        task_id: &Id,
        task_config: TaskConfig,
        vdaf_verify_key_init: &[u8],
        collector_hpke_config: &HpkeConfig,
    ) -> Result<DapTaskConfig, DapError> {
        if task_config.aggregator_endpoints.len() != 2 {
            return Err(bad_request("number of aggregator endpoints is not 2"));
        }
        let vdaf_type = VdafType::from(task_config.vdaf_config.var.clone());
        Ok(DapTaskConfig {
            version,
            leader_url: url_from_bytes(&task_config.aggregator_endpoints[0].bytes)?,
            helper_url: url_from_bytes(&task_config.aggregator_endpoints[1].bytes)?,
            time_precision: task_config.query_config.time_precision,
            expiration: task_config.task_expiration,
            min_batch_size: task_config.query_config.min_batch_size.into(),
            query: DapQueryConfig::from(task_config.query_config.var),
            vdaf: VdafConfig::from(task_config.vdaf_config.var),
            vdaf_verify_key: compute_vdaf_verify_key(vdaf_verify_key_init, task_id, vdaf_type),
            collector_hpke_config: collector_hpke_config.clone(),
        })
    }
}

impl ReportMetadata {
    /// Does this metatdata have a taskprov extension and does it match the specified id?
    pub fn is_taskprov(&self, task_id: &Id) -> bool {
        return self.extensions.iter().any(|x| match x {
            Extension::Taskprov { payload } => *task_id == compute_task_id(payload),
            _ => false,
        });
    }
}
