// Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use daphne::{
    hpke::{HpkeConfig, HpkeReceiverConfig},
    DapGlobalConfig, DapVersion,
};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::{auth::DaphneWorkerAuthMethod, DapRole};

/// draft-wang-ppm-dap-taskprov: Long-lived parameters for the taskprov extension.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TaskprovConfig {
    /// HPKE collector configuration for all taskprov tasks.
    pub hpke_collector_config: HpkeConfig,

    /// VDAF verify key init secret, used to generate the VDAF verification key for a taskprov task.
    #[serde(with = "hex")]
    pub vdaf_verify_key_init: [u8; 32],

    /// Leader, Helper: Method for authorizing Leader requests.
    pub leader_auth: DaphneWorkerAuthMethod,

    /// Leader: Method for authorizing Collector requests.
    pub collector_auth: Option<DaphneWorkerAuthMethod>,
}

pub type HpkeRecieverConfigList = Vec<HpkeReceiverConfig>;

/// Daphne service configuration, including long-lived parameters used across DAP tasks.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DaphneServiceConfig {
    pub env: String,

    /// Indicates if DaphneWorker is used as the Leader.
    pub role: DapRole,

    /// Global DAP configuration.
    #[serde(flatten)]
    pub global: DapGlobalConfig,

    /// Sharding key, used to compute the ReportsPending or ReportsProcessed shard to map a report
    /// to (based on the report ID).
    #[serde(with = "hex")]
    pub report_shard_key: [u8; 32],

    /// Shard count, the number of report storage shards. This should be a power of 2.
    pub report_shard_count: u64,

    /// draft-dcook-ppm-dap-interop-test-design: Base URL of the Aggregator (unversioned). If set,
    /// this field is used for endpoint configuration for interop testing.
    pub base_url: Option<Url>,

    /// draft-wang-ppm-dap-taskprov: Long-lived parameters for the taskprov extension. If not set,
    /// then taskprov will be disabled.
    pub taskprov: Option<TaskprovConfig>,

    /// Default DAP version to use if not specified by the API URL
    pub default_version: DapVersion,

    /// The report storage epoch duration. This value is used to control the period of time for
    /// which an Aggregator guarantees storage of reports and/or report metadata.
    ///
    /// A report will be accepted if its timestamp is no more than the specified number of seconds
    /// before the current time.
    pub report_storage_epoch_duration: daphne::messages::Duration,
}

/// Deployment types for Daphne-Worker. This defines overrides used to control inter-Aggregator
/// communication.
#[derive(Serialize, Deserialize, Debug, Default, Clone, Copy)]
#[serde(rename_all = "snake_case")]
pub enum DaphneWorkerDeployment {
    /// Daphne-Worker is running in a production environment. No behavior overrides are applied.
    #[default]
    Prod,
    /// Daphne-Worker is running in a development environment. Any durable objects that are created
    /// will be registered by the garbage collector so that they can be deleted manually using the
    /// internal test API.
    Dev,
}
