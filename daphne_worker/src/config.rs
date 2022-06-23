// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Daphne-Worker implements a Workers backend for Daphne.

//! Daphne-Worker configuration.

use crate::{
    dap,
    durable::{
        aggregate_store::{durable_agg_store_name, DURABLE_AGGREGATE_STORE_DELETE_ALL},
        leader_state_store::{durable_leader_state_name, DURABLE_LEADER_STATE_DELETE_ALL},
        report_store::{durable_report_store_name, DURABLE_REPORT_STORE_DELETE_ALL},
    },
    utils::{int_err, now},
};
use daphne::{
    auth::BearerToken,
    hpke::HpkeSecretKey,
    messages::{HpkeConfig, Id, Interval, Nonce},
    roles::DapAggregator,
    DapError, DapTaskConfig,
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

    pub(crate) tasks: HashMap<Id, DapTaskConfig>,
    pub(crate) hpke_config_list: Vec<HpkeConfig>,
    pub(crate) hpke_secret_key_list: Vec<HpkeSecretKey>,

    /// Leader's bearer token for each task.
    pub(crate) leader_bearer_tokens: HashMap<Id, BearerToken>,

    /// Collector's bearer token for each task. This is only populated if Daphne-Worker is
    /// configured as the DAP Leader, i.e., if `DAP_AGGREGATOR_ROLE == "leader"`.
    pub(crate) collector_bearer_tokens: Option<HashMap<Id, BearerToken>>,

    // TODO(MVP) Make `bucket_Key` and `bucket_count` unique per task.
    bucket_key: Seed<16>,
    bucket_count: u64,
}

impl<D> DaphneWorkerConfig<D> {
    /// Fetch DAP parameters from environment variables.
    pub(crate) fn from_worker_context(ctx: RouteContext<D>) -> Result<Self> {
        let mut tasks: HashMap<Id, DapTaskConfig> =
            serde_json::from_str(ctx.var("DAP_TASK_LIST")?.to_string().as_ref())
                .map_err(|e| Error::RustError(format!("Failed to parse DAP_TASK_LIST: {}", e)))?;

        // When running in a local development environment, override the hostname of each
        // aggregator URL with 127.0.0.1.
        if let Ok(env) = ctx.var("DAP_ENV") {
            if env.as_ref() == "dev" {
                console_log!("DAP_ENV: Hostname override applied");
                for (_, task_config) in tasks.iter_mut() {
                    task_config.leader_url.set_host(Some("127.0.0.1")).unwrap();
                    task_config.helper_url.set_host(Some("127.0.0.1")).unwrap();
                }
            }
        }

        let hpke_config_list_hex: Vec<String> = serde_json::from_str(
            ctx.var("DAP_HPKE_CONFIG_LIST")?.to_string().as_ref(),
        )
        .map_err(|e| Error::RustError(format!("Failed to parse DAP_HPKE_CONFIG_LIST: {}", e)))?;
        // TODO(MVP) Encode as JSON objects rather than hex blobs.
        let mut hpke_config_list = Vec::with_capacity(hpke_config_list_hex.len());
        for hex in hpke_config_list_hex {
            let bytes = hex::decode(hex).map_err(int_err)?;
            let hpke_config = HpkeConfig::get_decoded(&bytes).map_err(int_err)?;
            hpke_config_list.push(hpke_config);
        }

        let hpke_secret_key_list: Vec<HpkeSecretKey> =
            serde_json::from_str(ctx.var("DAP_HPKE_SECRET_KEY_LIST")?.to_string().as_ref())
                .map_err(|e| {
                    Error::RustError(format!("Failed to parse DAP_HPKE_SECRET_KEY_LIST: {}", e))
                })?;

        if hpke_secret_key_list.len() != hpke_config_list.len() {
            return Err(Error::RustError(
                "Length of DAP_HPKE_CONFIG_LIST does not match length of DAP_HPKE_SECRET_KEY_LIST"
                    .to_string(),
            ));
        }

        if hpke_config_list.is_empty() {
            return Err(Error::RustError("empty DAP_HPKE_CONFIG_LIST".to_string()));
        }

        let bucket_key = Seed::get_decoded(
            &hex::decode(ctx.var("DAP_BUCKET_KEY")?.to_string()).map_err(int_err)?,
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
            ctx.var("DAP_LEADER_BEARER_TOKEN_LIST")?
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

        let client = if is_leader {
            // TODO Configure this client to use HTTPS only, excpet if running in a test
            // environment (i.e., if DAP_ENV = true).
            Some(reqwest_wasm::Client::new())
        } else {
            None
        };

        let collector_bearer_tokens = if is_leader {
            let tokens: HashMap<Id, BearerToken> = serde_json::from_str(
                ctx.var("DAP_COLLECTOR_BEARER_TOKEN_LIST")?
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
            tasks,
            hpke_config_list,
            hpke_secret_key_list,
            leader_bearer_tokens,
            collector_bearer_tokens,
            bucket_key,
            bucket_count,
        })
    }

    // TODO This method is at the wrong level of abstraction. To construct a DaphneWorkerConfig we
    // need an HTTP client and a Worker context, neither of which is necessary for the unit tests
    // for which this method is used.
    #[cfg(test)]
    pub(crate) fn from_test_config(
        json_task_list: &str,
        json_hpke_config_list: &str,
        json_hpke_secret_key_list: &str,
        json_bucket_key: &str,
        bucket_count: u64,
    ) -> Result<Self> {
        let bucket_key =
            Seed::get_decoded(&hex::decode(json_bucket_key).map_err(int_err)?).map_err(int_err)?;

        let hpke_config_list_hex: Vec<String> = serde_json::from_str(json_hpke_config_list)?;
        // TODO(MVP) Encode as JSON objects rather than hex blobs.
        let mut hpke_config_list = Vec::with_capacity(hpke_config_list_hex.len());
        for hex in hpke_config_list_hex {
            let bytes = hex::decode(hex).map_err(int_err)?;
            let hpke_config = HpkeConfig::get_decoded(&bytes).map_err(int_err)?;
            hpke_config_list.push(hpke_config);
        }

        Ok(DaphneWorkerConfig {
            ctx: Arc::new(Mutex::new(None)),
            client: None,
            tasks: serde_json::from_str(json_task_list)?,
            hpke_config_list,
            hpke_secret_key_list: serde_json::from_str(json_hpke_secret_key_list)?,
            leader_bearer_tokens: HashMap::default(),
            collector_bearer_tokens: None,
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

    pub(crate) fn get_hpke_secret_key_for(&self, hpke_config_id: u8) -> Option<&HpkeSecretKey> {
        for hpke_secret_key in self.hpke_secret_key_list.iter() {
            if hpke_config_id == hpke_secret_key.id {
                return Some(hpke_secret_key);
            }
        }
        None
    }

    pub(crate) async fn internal_reset(
        &self,
        task_id: &Id,
        batch_info: &Option<Interval>,
    ) -> std::result::Result<(), DapError> {
        let task_config = self
            .get_task_config_for(task_id)
            .ok_or_else(|| DapError::fatal(dap::INT_ERR_UNRECOGNIZED_TASK))?;

        let batch_interval = if let Some(batch_interval) = batch_info {
            if !batch_interval.is_valid_for(task_config) {
                return Err(DapError::fatal(dap::INT_ERR_INVALID_BATCH_INTERVAL));
            }
            batch_interval.clone()
        } else {
            task_config.current_batch_window(now())
        };

        // Delete all report data in the batch interval.
        let namespace = self.durable_object("DAP_REPORT_STORE")?;
        for durable_name in self.iter_report_store_names(task_id, &batch_interval)? {
            let stub = namespace.id_from_name(&durable_name)?.get_stub()?;
            // TODO Don't block on DO requests (issue multiple requests simultaneously).
            durable_post!(stub, DURABLE_REPORT_STORE_DELETE_ALL, &()).await?;
        }

        // Delete all aggregate data in the batch interval.
        let namespace = self.durable_object("DAP_AGGREGATE_STORE")?;
        let task_id_base64url = task_id.to_base64url();
        for window in (batch_interval.start..batch_interval.end())
            .step_by(task_config.min_batch_duration.try_into().unwrap())
        {
            let agg_name = durable_agg_store_name(&task_id_base64url, window);
            let stub = namespace.id_from_name(&agg_name)?.get_stub()?;
            // TODO Don't block on DO requests (issue multiple requests simultaneously).
            durable_post!(stub, DURABLE_AGGREGATE_STORE_DELETE_ALL, &()).await?;
        }

        // Clear the leader's state.
        let namespace = self.durable_object("DAP_LEADER_STATE_STORE")?;
        for task_id in self.tasks.keys() {
            let stub = namespace
                .id_from_name(&durable_leader_state_name(task_id))?
                .get_stub()?;
            // TODO Don't block on DO requests (issue multiple requests simultaneously).
            durable_post!(stub, DURABLE_LEADER_STATE_DELETE_ALL, &()).await?;
        }

        Ok(())
    }
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
