// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Daphne-Worker implements a Workers backend for Daphne.

//! Daphne-Worker configuration.

use crate::{
    dap_err,
    durable::{
        durable_name_report_store, durable_name_task,
        leader_batch_queue::{LeaderBatchQueueResult, DURABLE_LEADER_BATCH_QUEUE_CURRENT},
        DurableConnector, BINDING_DAP_GARBAGE_COLLECTOR, BINDING_DAP_LEADER_BATCH_QUEUE,
        DURABLE_DELETE_ALL,
    },
    int_err,
};
use daphne::{
    auth::BearerToken,
    constants,
    hpke::HpkeReceiverConfig,
    messages::{HpkeConfig, Id, ReportMetadata},
    DapError, DapGlobalConfig, DapQueryConfig, DapRequest, DapTaskConfig, DapVersion,
};
use matchit::Router;
use prio::{
    codec::Decode,
    vdaf::prg::{Prg, PrgAes128, Seed, SeedStream},
};
use std::{
    collections::HashMap,
    sync::{Arc, RwLock, RwLockReadGuard},
};
use worker::{kv::KvStore, *};

pub(crate) const KV_KEY_PREFIX_HPKE_RECEIVER_CONFIG: &str = "hpke_receiver_config";

/// Long-lived parameters used a daphne across DAP tasks.
pub(crate) struct DaphneWorkerConfig<D> {
    ctx: Option<RouteContext<D>>,

    /// HTTP client to use for making requests to the Helper. This is only used if Daphne-Worker is
    /// configured as the DAP Helper.
    pub(crate) client: Option<reqwest_wasm::Client>,

    pub(crate) global_config: DapGlobalConfig,
    pub(crate) tasks: HashMap<Id, DapTaskConfig>,

    /// Cached HPKE receiver config. This will be populated when Daphne-Worker obtains an HPKE
    /// receiver config for the first time from Cloudflare KV.
    pub(crate) hpke_receiver_configs: Arc<RwLock<HashMap<u8, HpkeReceiverConfig>>>,

    /// Leader's bearer token for each task.
    pub(crate) leader_bearer_tokens: HashMap<Id, BearerToken>,

    /// Collector's bearer token for each task. This is only populated if Daphne-Worker is
    /// configured as the DAP Leader, i.e., if `DAP_AGGREGATOR_ROLE == "leader"`.
    pub(crate) collector_bearer_tokens: Option<HashMap<Id, BearerToken>>,

    /// Deployment type. This controls certain behavior overrides relevant to specific deployments.
    pub(crate) deployment: DaphneWorkerDeployment,

    /// Sharding key, used to compute the ReportsPending or ReportsProcessed shard to map a report
    /// to (based on the report ID).
    report_shard_key: Seed<16>,

    /// Shard count, the number of report storage shards. This should be a power of 2.
    report_shard_count: u64,
}

impl<D> DaphneWorkerConfig<D> {
    /// Fetch DAP parameters from environment variables.
    pub(crate) fn from_worker_context(ctx: RouteContext<D>) -> Result<Self> {
        let global_config: DapGlobalConfig = serde_json::from_str(
            ctx.var("DAP_GLOBAL_CONFIG")?.to_string().as_ref(),
        )
        .map_err(|e| Error::RustError(format!("Failed to parse DAP_GLOBAL_CONFIG: {}", e)))?;

        let tasks: HashMap<Id, DapTaskConfig> =
            serde_json::from_str(ctx.secret("DAP_TASK_LIST")?.to_string().as_ref())
                .map_err(|e| Error::RustError(format!("Failed to parse DAP_TASK_LIST: {}", e)))?;

        let report_shard_key = Seed::get_decoded(
            &hex::decode(ctx.secret("DAP_REPORT_SHARD_KEY")?.to_string()).map_err(int_err)?,
        )
        .map_err(int_err)?;

        let report_shard_count: u64 = ctx
            .var("DAP_REPORT_SHARD_COUNT")?
            .to_string()
            .parse()
            .map_err(|err| {
                Error::RustError(format!("Failed to parse DAP_REPORT_SHARD_COUNT: {}", err))
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
            ctx: Some(ctx),
            client,
            global_config,
            tasks,
            hpke_receiver_configs: Arc::new(RwLock::new(HashMap::new())),
            leader_bearer_tokens,
            collector_bearer_tokens,
            deployment,
            report_shard_key,
            report_shard_count,
        })
    }

    // TODO This method is at the wrong level of abstraction. To construct a DaphneWorkerConfig we
    // need an HTTP client and a Worker context, neither of which is necessary for the unit tests
    // for which this method is used.
    #[cfg(test)]
    pub(crate) fn from_test_config(
        json_global_config: &str,
        json_task_list: &str,
        json_report_shard_key: &str,
        report_shard_count: u64,
    ) -> Result<Self> {
        let report_shard_key =
            Seed::get_decoded(&hex::decode(json_report_shard_key).map_err(int_err)?)
                .map_err(int_err)?;

        Ok(DaphneWorkerConfig {
            ctx: None,
            client: None,
            global_config: serde_json::from_str(json_global_config)?,
            tasks: serde_json::from_str(json_task_list)?,
            hpke_receiver_configs: Arc::new(RwLock::new(HashMap::new())),
            leader_bearer_tokens: HashMap::default(),
            collector_bearer_tokens: None,
            deployment: DaphneWorkerDeployment::default(),
            report_shard_key,
            report_shard_count,
        })
    }

    /// Derive the batch name for a report for the given task and with the given nonce.
    pub(crate) fn durable_name_report_store(
        &self,
        task_config: &DapTaskConfig,
        task_id_hex: &str,
        metadata: &ReportMetadata,
    ) -> String {
        let mut shard_seed = [0; 8];
        PrgAes128::seed_stream(&self.report_shard_key, metadata.nonce.as_ref())
            .fill(&mut shard_seed);
        let shard = u64::from_be_bytes(shard_seed) % self.report_shard_count;
        let epoch =
            metadata.time - (metadata.time % self.global_config.report_storage_epoch_duration);
        durable_name_report_store(&task_config.version, task_id_hex, epoch, shard)
    }

    pub(crate) fn durable(&self) -> DurableConnector<'_> {
        DurableConnector::new(&self.ctx.as_ref().expect("no route context configured").env)
    }

    pub(crate) fn kv(&self, binding: &str) -> Result<KvStore> {
        self.ctx
            .as_ref()
            .ok_or_else(|| Error::RustError("route context does not exist".to_string()))?
            .kv(binding)
    }

    // Get a reference to the HPKE receiver configs, ensuring that the config indicated by
    // `hpke_config_id` is cached (if it exists).
    pub(crate) async fn hpke_receiver_config(
        &self,
        hpke_config_id: u8,
    ) -> Result<Option<GuardedHpkeReceiverConfig>> {
        // If the config is cached, then return immediately.
        {
            let hpke_receiver_configs = self.hpke_receiver_configs.read().map_err(|e| {
                Error::RustError(format!(
                    "Failed to lock hpke_receiver_configs for reading: {}",
                    e
                ))
            })?;

            if hpke_receiver_configs.get(&hpke_config_id).is_some() {
                return Ok(Some(GuardedHpkeReceiverConfig {
                    hpke_receiver_configs,
                    hpke_config_id,
                }));
            }
        }

        // If the config is not cached, try to populate it from KV before returning.
        let new_key = format!("{}/{}", KV_KEY_PREFIX_HPKE_RECEIVER_CONFIG, hpke_config_id);
        let kv_store = self.kv("DAP_HPKE_RECEIVER_CONFIG_STORE")?;
        let builder = kv_store.get(&new_key);
        if let Some(hpke_receiver_config) = builder.json::<HpkeReceiverConfig>().await? {
            // TODO(cjpatton) Consider indicating whether a config is known to not exist. This
            // would avoid hitting KV multiple times when the same expired config is used for
            // multiple reports.
            let mut hpke_receiver_configs = self.hpke_receiver_configs.write().map_err(|e| {
                Error::RustError(format!(
                    "Failed to lock hpke_receiver_configs for writing: {}",
                    e
                ))
            })?;
            hpke_receiver_configs.insert(hpke_config_id, hpke_receiver_config);
        }

        let hpke_receiver_configs = self.hpke_receiver_configs.read().map_err(|e| {
            Error::RustError(format!(
                "Failed to lock hpke_receiver_configs for reading: {}",
                e
            ))
        })?;

        if hpke_receiver_configs.get(&hpke_config_id).is_some() {
            Ok(Some(GuardedHpkeReceiverConfig {
                hpke_receiver_configs,
                hpke_config_id,
            }))
        } else {
            Ok(None)
        }
    }

    /// Clear all persistant durable objects storage.
    ///
    /// TODO(cjpatton) Gate this to non-prod deployments. (Prod should do migration.)
    pub(crate) async fn internal_delete_all(&self) -> std::result::Result<(), DapError> {
        self.durable()
            .post(
                BINDING_DAP_GARBAGE_COLLECTOR,
                DURABLE_DELETE_ALL,
                "garbage_collector".to_string(),
                &(),
            )
            .await
            .map_err(dap_err)?;
        Ok(())
    }

    /// Get the batch ID for the oldest batch that has not been collected. This method is only
    /// appliable to fixed-size tasks.
    pub(crate) async fn internal_current_batch(
        &self,
        task_id: &Id,
    ) -> std::result::Result<Id, DapError> {
        let task_config = self.try_get_task_config_for(task_id)?;
        if !matches!(task_config.query, DapQueryConfig::FixedSize { .. }) {
            return Err(DapError::fatal("query type mismatch"));
        }

        let res: LeaderBatchQueueResult = self
            .durable()
            .get(
                BINDING_DAP_LEADER_BATCH_QUEUE,
                DURABLE_LEADER_BATCH_QUEUE_CURRENT,
                durable_name_task(&task_config.version, &task_id.to_hex()),
            )
            .await
            .map_err(dap_err)?;

        match res {
            LeaderBatchQueueResult::Ok(batch_id) => Ok(batch_id),

            // TODO spec: If we end up taking the current batch semantics of
            // https://github.com/ietf-wg-ppm/draft-ietf-ppm-dap/pull/313, then we'll need to
            // define an error type for this case.
            LeaderBatchQueueResult::EmptyQueue => Err(DapError::fatal("empty batch queue")),
        }
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

        let url = req.url()?;
        let path = url.path();
        let mut router: Router<bool> = Router::new();
        router.insert("/:version/*remaining", true).unwrap();
        let url_match = router.at(path).unwrap();
        let version = url_match
            .params
            .get("version")
            .ok_or_else(|| Error::RustError(format!("Failed to parse path: {}", path)))?;

        let payload = req.bytes().await?;
        Ok(DapRequest {
            version: DapVersion::from(version),
            payload,
            url: req.url()?,
            media_type,
            sender_auth,
        })
    }

    pub(crate) fn try_get_task_config_for(
        &self,
        task_id: &Id,
    ) -> std::result::Result<&DapTaskConfig, DapError> {
        self.tasks
            .get(task_id)
            .ok_or_else(|| DapError::fatal("unrecognized task"))
    }
}

/// RwLockReadGuard'ed HPKE receiver config.
pub(crate) struct GuardedHpkeReceiverConfig<'a> {
    hpke_receiver_configs: RwLockReadGuard<'a, HashMap<u8, HpkeReceiverConfig>>,
    hpke_config_id: u8,
}

impl AsRef<HpkeConfig> for GuardedHpkeReceiverConfig<'_> {
    fn as_ref(&self) -> &HpkeConfig {
        &self
            .hpke_receiver_configs
            .get(&self.hpke_config_id)
            .unwrap()
            .config
    }
}

impl GuardedHpkeReceiverConfig<'_> {
    pub(crate) fn decryptor(&self) -> &HpkeReceiverConfig {
        self.hpke_receiver_configs
            .get(&self.hpke_config_id)
            .unwrap()
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
