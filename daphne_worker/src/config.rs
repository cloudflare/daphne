// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Daphne-Worker implements a Workers backend for Daphne.

//! Daphne-Worker configuration.

use crate::{
    durable::{
        report_store::durable_report_store_name, BINDING_DAP_GARBAGE_COLLECTOR, DURABLE_DELETE_ALL,
    },
    int_err,
};
use daphne::{
    auth::BearerToken,
    constants,
    hpke::HpkeReceiverConfig,
    messages::{Id, Interval, Nonce},
    DapError, DapGlobalConfig, DapRequest, DapTaskConfig,
};
use prio::{
    codec::{Decode, Encode},
    vdaf::prg::{Prg, PrgAes128, Seed, SeedStream},
};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
use worker::*;

/// Long-lived parameters used a daphne across DAP tasks.
pub(crate) struct DaphneWorkerConfig<D> {
    ctx: Arc<Mutex<Option<RouteContext<D>>>>,

    /// HTTP client to use for making requests to the Helper. This is only used if Daphne-Worker is
    /// configured as the DAP Helper.
    pub(crate) client: Option<reqwest_wasm::Client>,

    pub(crate) global_config: DapGlobalConfig,
    pub(crate) tasks: HashMap<Id, DapTaskConfig>,
    pub(crate) hpke_receiver_config_list: Vec<HpkeReceiverConfig>,

    /// Leader's bearer token for each task.
    pub(crate) leader_bearer_tokens: HashMap<Id, BearerToken>,

    /// Collector's bearer token for each task. This is only populated if Daphne-Worker is
    /// configured as the DAP Leader, i.e., if `DAP_AGGREGATOR_ROLE == "leader"`.
    pub(crate) collector_bearer_tokens: Option<HashMap<Id, BearerToken>>,

    /// Deployment type. This controls certain behavior overrides relevant to specific deployments.
    pub(crate) deployment: DaphneWorkerDeployment,

    // TODO(issue#12) Make `bucket_key` and `bucket_count` unique per task.
    bucket_key: Seed<16>,
    bucket_count: u64,
}

impl<D> DaphneWorkerConfig<D> {
    /// Fetch DAP parameters from environment variables.
    pub(crate) fn from_worker_context(ctx: RouteContext<D>) -> Result<Self> {
        let global_config: DapGlobalConfig =
            serde_json::from_str(ctx.secret("GLOBAL_CONFIG")?.to_string().as_ref())
                .map_err(|e| Error::RustError(format!("Failed to parse GLOBAL_CONFIG: {}", e)))?;

        let tasks: HashMap<Id, DapTaskConfig> =
            serde_json::from_str(ctx.secret("DAP_TASK_LIST")?.to_string().as_ref())
                .map_err(|e| Error::RustError(format!("Failed to parse DAP_TASK_LIST: {}", e)))?;

        let hpke_receiver_config_list: Vec<HpkeReceiverConfig> = serde_json::from_str(
            ctx.secret("DAP_HPKE_RECEIVER_CONFIG_LIST")?
                .to_string()
                .as_ref(),
        )
        .map_err(|e| {
            Error::RustError(format!(
                "Failed to parse DAP_HPKE_RECEIVER_CONFIG_LIST: {}",
                e
            ))
        })?;

        if hpke_receiver_config_list.is_empty() {
            return Err(Error::RustError("empty DAP_HPKE_CONFIG_LIST".to_string()));
        }

        let bucket_key = Seed::get_decoded(
            &hex::decode(ctx.secret("DAP_BUCKET_KEY")?.to_string()).map_err(int_err)?,
        )
        .map_err(int_err)?;

        let bucket_count: u64 =
            ctx.var("DAP_BUCKET_COUNT")?
                .to_string()
                .parse()
                .map_err(|err| {
                    Error::RustError(format!("Failed to parse DAP_BUCKET_COUNT: {}", err))
                })?;

        let leader_bearer_tokens: HashMap<Id, BearerToken> = serde_json::from_str(
            ctx.secret("DAP_LEADER_BEARER_TOKEN_LIST")?
                .to_string()
                .as_ref(),
        )
        .map_err(|e| {
            Error::RustError(format!(
                "Failed to parse DAP_LEADER_BEARER_TOKEN_LIST: {}",
                e
            ))
        })?;

        let is_leader = match ctx.var("DAP_AGGREGATOR_ROLE")?.to_string().as_str() {
            "leader" => true,
            "helper" => false,
            other => {
                return Err(Error::RustError(format!(
                    "Invalid value for DAP_AGGREGATOR_ROLE: '{}'",
                    other
                )))
            }
        };

        let deployment = if let Ok(deployment) = ctx.var("DAP_DEPLOYMENT") {
            match deployment.to_string().as_str() {
                "dev" => DaphneWorkerDeployment::Dev,
                "prod" => DaphneWorkerDeployment::Prod,
                s => {
                    return Err(Error::RustError(format!(
                        "Invalid value for DAP_DEPLOYMENT: {}",
                        s
                    )))
                }
            }
        } else {
            DaphneWorkerDeployment::default()
        };
        if !matches!(deployment, DaphneWorkerDeployment::Prod) {
            console_debug!("DAP deployment override applied: {:?}", deployment);
        }

        let client = if is_leader {
            // TODO Configure this client to use HTTPS only, excpet if running in a test
            // environment.
            Some(reqwest_wasm::Client::new())
        } else {
            None
        };

        let collector_bearer_tokens = if is_leader {
            let tokens: HashMap<Id, BearerToken> = serde_json::from_str(
                ctx.secret("DAP_COLLECTOR_BEARER_TOKEN_LIST")?
                    .to_string()
                    .as_ref(),
            )
            .map_err(|e| {
                Error::RustError(format!(
                    "Failed to parse DAP_COLLECTOR_BEARER_TOKEN_LIST: {}",
                    e
                ))
            })?;
            Some(tokens)
        } else {
            None
        };

        Ok(Self {
            ctx: Arc::new(Mutex::new(Some(ctx))),
            client,
            global_config,
            tasks,
            hpke_receiver_config_list,
            leader_bearer_tokens,
            collector_bearer_tokens,
            deployment,
            bucket_key,
            bucket_count,
        })
    }

    // TODO This method is at the wrong level of abstraction. To construct a DaphneWorkerConfig we
    // need an HTTP client and a Worker context, neither of which is necessary for the unit tests
    // for which this method is used.
    #[cfg(test)]
    pub(crate) fn from_test_config(
        json_global_config: &str,
        json_task_list: &str,
        json_hpke_receiver_config_list: &str,
        json_bucket_key: &str,
        bucket_count: u64,
    ) -> Result<Self> {
        let bucket_key =
            Seed::get_decoded(&hex::decode(json_bucket_key).map_err(int_err)?).map_err(int_err)?;

        Ok(DaphneWorkerConfig {
            ctx: Arc::new(Mutex::new(None)),
            client: None,
            global_config: serde_json::from_str(json_global_config)?,
            tasks: serde_json::from_str(json_task_list)?,
            hpke_receiver_config_list: serde_json::from_str(json_hpke_receiver_config_list)?,
            leader_bearer_tokens: HashMap::default(),
            collector_bearer_tokens: None,
            deployment: DaphneWorkerDeployment::default(),
            bucket_key,
            bucket_count,
        })
    }

    /// Derive the batch name for a report for the given task and with the given nonce.
    pub(crate) fn durable_report_store_name(
        &self,
        task_config: &DapTaskConfig,
        task_id: &Id,
        nonce: &Nonce,
    ) -> String {
        let mut bucket_seed = [0; 8];
        PrgAes128::seed_stream(&self.bucket_key, &nonce.get_encoded()).fill(&mut bucket_seed);
        let bucket = u64::from_be_bytes(bucket_seed) % self.bucket_count;
        let time = nonce.time - (nonce.time % task_config.min_batch_duration);
        durable_report_store_name(&task_id.to_base64url(), time, bucket)
    }

    /// Enumerate the sequence of batch names for a given task ID and batch interval. This method
    /// returns an error if the task ID isn't recognized or if the batch interval is invalid, e.g.,
    /// the start and end times doen't align with the minimum batch duration.
    pub(crate) fn iter_report_store_names(
        &self,
        task_id: &Id,
        interval: &Interval,
    ) -> Result<DurableNameIterator> {
        let task_id_base64url = task_id.to_base64url();

        let time_step = self
            .tasks
            .get(task_id)
            .ok_or_else(|| {
                Error::RustError(format!("Unrecognized task ID: {}", task_id_base64url))
            })?
            .min_batch_duration;

        if interval.end() <= interval.start {
            return Err(Error::RustError(
                "Invalid batch interval: End time must be strictly later than start time"
                    .to_string(),
            ));
        }

        if interval.start % time_step != 0 || interval.end() % time_step != 0 {
            return Err(Error::RustError(
                "Batch interval does not align with min_batch_duration".to_string(),
            ));
        }

        Ok(DurableNameIterator {
            task_id_base64url,
            time_start: interval.start,
            time_mod: interval.end() - interval.start,
            time_step,
            time_offset: 0,
            bucket_count: self.bucket_count,
            bucket: 0,
        })
    }

    pub(crate) fn durable_object(&self, binding: &str) -> Result<ObjectNamespace> {
        self.ctx
            .lock()
            .map_err(int_err)?
            .as_ref()
            .expect("no route context configured")
            .durable_object(binding)
    }

    pub(crate) fn get_hpke_receiver_config_for(
        &self,
        hpke_config_id: u8,
    ) -> Option<&HpkeReceiverConfig> {
        for hpke_receiver_config in self.hpke_receiver_config_list.iter() {
            if hpke_config_id == hpke_receiver_config.config.id {
                return Some(hpke_receiver_config);
            }
        }
        None
    }

    /// Clear all persistant durable objects storage.
    ///
    /// TODO(cjpatton) Gate this to non-prod deployments. (Prod should do migration.)
    pub(crate) async fn internal_delete_all(&self) -> std::result::Result<(), DapError> {
        let namespace = self.durable_object(BINDING_DAP_GARBAGE_COLLECTOR)?;
        let stub = namespace.id_from_name("garbage_collector")?.get_stub()?;
        durable_post!(stub, DURABLE_DELETE_ALL, &()).await?;
        Ok(())
    }

    pub(crate) async fn worker_request_to_dap(
        &self,
        mut req: Request,
    ) -> Result<DapRequest<BearerToken>> {
        let sender_auth = req.headers().get("DAP-Auth-Token")?.map(BearerToken::from);
        let content_type = req.headers().get("Content-Type")?;

        let media_type = match content_type {
            Some(s) => constants::media_type_for(&s),
            None => None,
        };

        let payload = req.bytes().await?;
        Ok(DapRequest {
            payload,
            url: req.url()?,
            media_type,
            sender_auth,
        })
    }
}

/// Deployment types for Daphne-Worker. This defines overrides used to control inter-Aggregator
/// communication.
#[derive(Debug, Default)]
pub(crate) enum DaphneWorkerDeployment {
    /// Daphne-Worker is running in a local development environment. In this setting, the hostname
    /// of the Leader and Helper URLs are overwritten with localhost.
    Dev,

    /// Daphne-Worker is running in a production environment. No behavior overrides are applied.
    #[default]
    Prod,
}

/// An iterator over a sequence of batch names for a given batch interval.
pub(crate) struct DurableNameIterator {
    task_id_base64url: String,
    time_start: u64,
    time_mod: u64,
    time_step: u64,
    time_offset: u64,
    bucket_count: u64,
    bucket: u64,
}

impl Iterator for DurableNameIterator {
    type Item = String;

    fn next(&mut self) -> Option<String> {
        if self.bucket == self.bucket_count {
            return None;
        }

        let window = self.time_start + self.time_offset;
        let durable_name = durable_report_store_name(&self.task_id_base64url, window, self.bucket);

        self.time_offset = (self.time_offset + self.time_step) % self.time_mod;
        if self.time_offset == 0 {
            self.bucket += 1;
        }
        Some(durable_name)
    }
}
