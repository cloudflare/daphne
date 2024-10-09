// Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use daphne::messages::{Duration, TaskId, Time};
use serde::{Deserialize, Serialize};
use url::Url;

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct InternalTestEndpointForTask {
    pub role: super::DapRole,
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
    pub role: super::DapRole,
    pub vdaf_verify_key: String, // base64url
    pub query_type: u8,
    pub min_batch_size: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_batch_size: Option<u64>,
    pub time_precision: Duration,
    pub collector_hpke_config: String, // base64url
    pub task_expiration: Time,
}
