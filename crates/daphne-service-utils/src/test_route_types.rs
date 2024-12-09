// Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Types used in `/internal/*` routes to implement the [interop][interop] draft
//!
//! [interop]: https://divergentdave.github.io/draft-dcook-ppm-dap-interop-test-design/draft-dcook-ppm-dap-interop-test-design.html

use daphne::{
    constants::DapAggregatorRole,
    messages::{Duration, TaskId, Time},
    vdaf::{Prio3Config, VdafConfig},
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
}

impl From<VdafConfig> for InternalTestVdaf {
    fn from(vdaf: VdafConfig) -> Self {
        let (typ, bits, length, chunk_length) = match vdaf {
            VdafConfig::Prio3Draft09(prio3) => match prio3 {
                Prio3Config::Count => ("Prio3Count", None, None, None),
                Prio3Config::Sum { bits } => ("Prio3Sum", Some(bits), None, None),
                Prio3Config::Histogram {
                    length,
                    chunk_length,
                } => ("Prio3Histogram", None, Some(length), Some(chunk_length)),
                Prio3Config::SumVec {
                    bits,
                    length,
                    chunk_length,
                } => ("Prio3SumVec", Some(bits), Some(length), Some(chunk_length)),
                Prio3Config::SumVecField64MultiproofHmacSha256Aes128 {
                    bits,
                    length,
                    chunk_length,
                    num_proofs: _unimplemented,
                } => (
                    "Prio3SumVecField64MultiproofHmacSha256Aes128",
                    Some(bits),
                    Some(length),
                    Some(chunk_length),
                ),
            },
            VdafConfig::Prio3(prio3) => match prio3 {
                Prio3Config::Count => ("Prio3Count", None, None, None),
                Prio3Config::Sum { bits } => ("Prio3Sum", Some(bits), None, None),
                Prio3Config::Histogram {
                    length,
                    chunk_length,
                } => ("Prio3Histogram", None, Some(length), Some(chunk_length)),
                Prio3Config::SumVec {
                    bits,
                    length,
                    chunk_length,
                } => ("Prio3SumVec", Some(bits), Some(length), Some(chunk_length)),
                Prio3Config::SumVecField64MultiproofHmacSha256Aes128 {
                    bits,
                    length,
                    chunk_length,
                    num_proofs: _unimplemented,
                } => (
                    "Prio3SumVecField64MultiproofHmacSha256Aes128",
                    Some(bits),
                    Some(length),
                    Some(chunk_length),
                ),
            },
            VdafConfig::Prio2 { .. } => ("Prio2", None, None, None),
            VdafConfig::Pine(_) => ("Pine", None, None, None),
            #[cfg(feature = "experimental")]
            VdafConfig::Mastic { .. } => todo!(),
        };
        Self {
            typ: typ.into(),
            bits: bits.map(|a| a.to_string()),
            length: length.map(|a| a.to_string()),
            chunk_length: chunk_length.map(|a| a.to_string()),
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
    pub task_expiration: Time,
}
