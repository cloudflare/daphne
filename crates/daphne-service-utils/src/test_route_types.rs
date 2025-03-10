// Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Types used in `/internal/*` routes to implement the [interop][interop] draft
//!
//! [interop]: https://divergentdave.github.io/draft-dcook-ppm-dap-interop-test-design/draft-dcook-ppm-dap-interop-test-design.html

use daphne::{
    constants::DapAggregatorRole,
    messages::{Duration, TaskId},
    vdaf::{Prio3Config, VdafConfig},
    DapTaskLifetime,
};
use serde::{Deserialize, Serialize};
use std::num::NonZeroU32;
use url::Url;

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct InternalTestEndpointForTask {
    pub role: DapAggregatorRole,
}

#[derive(Serialize, Deserialize)]
pub struct InternalTestVdaf {
    #[serde(rename = "type")]
    pub typ: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bits: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub length: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chunk_length: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dimension: Option<String>,
}

impl From<VdafConfig> for InternalTestVdaf {
    fn from(vdaf: VdafConfig) -> Self {
        let (typ, bits, length, chunk_length, dimension) = match vdaf {
            VdafConfig::Prio3(prio3) => match prio3 {
                Prio3Config::Count => ("Prio3Count", None, None, None, None),
                Prio3Config::Sum { max_measurement } => (
                    "Prio3Sum",
                    Some(usize::try_from(max_measurement).unwrap()),
                    None,
                    None,
                    None,
                ),
                Prio3Config::Histogram {
                    length,
                    chunk_length,
                } => (
                    "Prio3Histogram",
                    None,
                    Some(length),
                    Some(chunk_length),
                    None,
                ),
                Prio3Config::SumVec {
                    bits,
                    length,
                    chunk_length,
                } => (
                    "Prio3SumVec",
                    Some(bits),
                    Some(length),
                    Some(chunk_length),
                    None,
                ),
                Prio3Config::Draft09SumVecField64MultiproofHmacSha256Aes128 {
                    bits,
                    length,
                    chunk_length,
                    num_proofs: _unimplemented,
                } => (
                    "Prio3Draft09SumVecField64MultiproofHmacSha256Aes128",
                    Some(bits),
                    Some(length),
                    Some(chunk_length),
                    None,
                ),
            },
            VdafConfig::Prio2 { dimension } => ("Prio2", None, None, None, Some(dimension)),
            VdafConfig::Pine(_) => ("Pine", None, None, None, None),
            #[cfg(feature = "experimental")]
            VdafConfig::Mastic { .. } => todo!(),
        };
        Self {
            typ: typ.into(),
            bits: bits.map(|a| a.to_string()),
            length: length.map(|a| a.to_string()),
            chunk_length: chunk_length.map(|a| a.to_string()),
            dimension: dimension.map(|a| a.to_string()),
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct InternalTestAddTask {
    pub task_id: TaskId, // base64url
    pub leader: Url,
    pub helper: Url,
    pub vdaf: InternalTestVdaf,
    pub leader_authentication_token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub collector_authentication_token: Option<String>,
    pub role: DapAggregatorRole,
    pub vdaf_verify_key: String, // base64url
    pub batch_mode: u8,
    pub min_batch_size: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_batch_size: Option<NonZeroU32>,
    pub time_precision: Duration,
    pub collector_hpke_config: String, // base64url
    // TODO(cjpatton) Align this with draft-dcook-ppm-dap-interop-test-design once it's updated to
    // DAP-13. I'm pretty sure we won't need to be backwards compatible.
    pub lifetime: DapTaskLifetime,
}
