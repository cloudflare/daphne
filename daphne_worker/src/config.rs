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
    int_err, InternalTestAddTask, InternalTestEndpointForTask, InternalTestRole,
};
use daphne::{
    auth::BearerToken,
    constants,
    hpke::HpkeReceiverConfig,
    messages::{decode_base64url_vec, HpkeConfig, Id, ReportMetadata},
    DapAbort, DapError, DapGlobalConfig, DapQueryConfig, DapRequest, DapTaskConfig, DapVersion,
    Prio3Config, VdafConfig,
};
use matchit::Router;
use prio::{
    codec::Decode,
    vdaf::prg::{Prg, PrgAes128, Seed, SeedStream},
};
use serde::{Deserialize, Serialize};
use std::{
    borrow::Cow,
    collections::HashMap,
    io::Cursor,
    sync::{Arc, RwLock, RwLockReadGuard},
    time::Duration,
};
use worker::{kv::KvStore, *};

pub(crate) const KV_KEY_PREFIX_HPKE_RECEIVER_CONFIG: &str = "hpke_receiver_config";
pub(crate) const KV_KEY_PREFIX_BEARER_TOKEN_LEADER: &str = "bearer_token/leader/task";
pub(crate) const KV_KEY_PREFIX_BEARER_TOKEN_COLLECTOR: &str = "bearer_token/collector/task";
pub(crate) const KV_KEY_PREFIX_TASK_CONFIG: &str = "config/task";
pub(crate) const KV_BINDING_DAP_CONFIG: &str = "DAP_CONFIG";

/// Long-lived parameters for tasks using draft-wang-ppm-dap-taskprov-02 ("taskprov").
pub(crate) struct TaskprovConfig {
    /// HPKE collector configuration for all taskprov tasks.
    pub(crate) hpke_collector_config: HpkeConfig,

    /// VDAF verify key init secret, used to generate the VDAF verification key for a taskprov task.
    pub(crate) vdaf_verify_key_init: Vec<u8>,

    /// Leader bearer token for all taskprov tasks
    pub(crate) leader_bearer_token: BearerToken,

    /// Collector bearer token for all taskprov tasks
    pub(crate) collector_bearer_token: BearerToken,
}

/// Long-lived parameters used by Daphne-Worker across DAP tasks.
pub(crate) struct DaphneWorkerConfig {
    /// Indicates if DaphneWorker is used as the Leader.
    is_leader: bool,

    /// Global DAP configuration.
    pub(crate) global: DapGlobalConfig,

    /// Deployment type. This controls certain behavior overrides relevant to specific deployments.
    pub(crate) deployment: DaphneWorkerDeployment,

    /// Leader: Key used to derive collection job IDs. This field is not configured by the Helper.
    pub(crate) collect_id_key: Option<Seed<16>>,

    /// Sharding key, used to compute the ReportsPending or ReportsProcessed shard to map a report
    /// to (based on the report ID).
    report_shard_key: Seed<16>,

    /// Shard count, the number of report storage shards. This should be a power of 2.
    report_shard_count: u64,

    /// Base URL of the Aggregator (unversioned).
    base_url: Url,

    /// Optional: draft-wang-ppm-dap-taskprov-02 configuration. If not configured, then taskprov
    /// will be disabled.
    pub(crate) taskprov: Option<TaskprovConfig>,

    /// Default DAP version to use if not specified by the API URL
    pub(crate) default_version: DapVersion,

    /// Admin bearer token. If configured, it is used to authorize requests from the administrator.
    pub(crate) admin_token: Option<BearerToken>,

    /// Helper: Time to wait before deleting an instance of HelperStateStore. This field is not
    /// configured by the Leader.
    pub(crate) helper_state_store_garbage_collect_after_secs: Option<Duration>,

    /// Additional time to wait before deletng an instance of ReportsProcessed. Added to the value
    /// of the `report_storage_epoch_duration` field of the global DAP configuration.
    pub(crate) processed_alarm_safety_interval: Duration,
}

impl DaphneWorkerConfig {
    pub(crate) fn from_worker_env(env: &Env) -> Result<Self> {
        let is_leader = match env.var("DAP_AGGREGATOR_ROLE")?.to_string().as_str() {
            "leader" => true,
            "helper" => false,
            other => {
                return Err(Error::RustError(format!(
                    "Invalid value for DAP_AGGREGATOR_ROLE: '{}'",
                    other
                )))
            }
        };

        let global: DapGlobalConfig = serde_json::from_str(
            env.var("DAP_GLOBAL_CONFIG")?.to_string().as_ref(),
        )
        .map_err(|e| Error::RustError(format!("Failed to parse DAP_GLOBAL_CONFIG: {}", e)))?;

        let default_version =
            DapVersion::from(env.var("DAP_DEFAULT_VERSION")?.to_string().as_ref());

        let base_url: Url = env
            .var("DAP_BASE_URL")?
            .to_string()
            .parse()
            .map_err(int_err)?;

        let collect_id_key = if is_leader {
            let collect_id_key_hex = env
                .secret("DAP_COLLECT_ID_KEY")
                .map_err(|e| format!("failed to load DAP_COLLECT_ID_KEY: {}", e))?
                .to_string();
            let collect_id_key =
                Seed::get_decoded(&hex::decode(collect_id_key_hex).map_err(int_err)?)
                    .map_err(int_err)?;
            Some(collect_id_key)
        } else {
            None
        };

        let report_shard_key = Seed::get_decoded(
            &hex::decode(env.secret("DAP_REPORT_SHARD_KEY")?.to_string()).map_err(int_err)?,
        )
        .map_err(int_err)?;

        let report_shard_count: u64 = env
            .var("DAP_REPORT_SHARD_COUNT")?
            .to_string()
            .parse()
            .map_err(|err| {
                Error::RustError(format!("Failed to parse DAP_REPORT_SHARD_COUNT: {}", err))
            })?;

        let deployment = if let Ok(deployment) = env.var("DAP_DEPLOYMENT") {
            match deployment.to_string().as_str() {
                "prod" => DaphneWorkerDeployment::Prod,
                "dev" => DaphneWorkerDeployment::Dev,
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

        let taskprov = if global.allow_taskprov {
            let hpke_collector_config = serde_json::from_str(
                env.var("DAP_TASKPROV_HPKE_COLLECTOR_CONFIG")?
                    .to_string()
                    .as_ref(),
            )?;

            let vdaf_verify_key_init =
                hex::decode(env.secret("DAP_TASKPROV_VDAF_VERIFY_KEY_INIT")?.to_string())
                    .map_err(int_err)?;

            let leader_bearer_token =
                BearerToken::from(env.secret("DAP_TASKPROV_LEADER_BEARER_TOKEN")?.to_string());

            let collector_bearer_token = BearerToken::from(
                env.secret("DAP_TASKPROV_COLLECTOR_BEARER_TOKEN")?
                    .to_string(),
            );

            Some(TaskprovConfig {
                hpke_collector_config,
                vdaf_verify_key_init,
                leader_bearer_token,
                collector_bearer_token,
            })
        } else {
            None
        };

        let admin_token = match env.secret("DAP_ADMIN_BEARER_TOKEN") {
            Ok(raw) => Some(BearerToken::from(raw.to_string())),
            Err(err) => {
                console_log!("DAP_ADMIN_BEARER_TOKEN not configured: {:?}", err);
                None
            }
        };

        let helper_state_store_garbage_collect_after_secs = if !is_leader {
            Some(Duration::from_secs(
                env.var("DAP_HELPER_STATE_STORE_GARBAGE_COLLECT_AFTER_SECS")?
                    .to_string()
                    .parse()
                    .map_err(|err| {
                        Error::RustError(format!(
                            "Failed to parse DAP_HELPER_STATE_STORE_GARBAGE_COLLECT_AFTER_SECS: {}",
                            err
                        ))
                    })?,
            ))
        } else {
            None
        };

        let processed_alarm_safety_interval = Duration::from_secs(
            env.var("DAP_PROCESSED_ALARM_SAFETY_INTERVAL")?
                .to_string()
                .parse()
                .map_err(|err| {
                    Error::RustError(format!(
                        "Failed to parse DAP_PROCESSED_ALARM_SAFETY_INTERVAL: {}",
                        err
                    ))
                })?,
        );

        Ok(Self {
            global,
            deployment,
            collect_id_key,
            report_shard_key,
            report_shard_count,
            base_url,
            is_leader,
            taskprov,
            default_version,
            admin_token,
            helper_state_store_garbage_collect_after_secs,
            processed_alarm_safety_interval,
        })
    }

    /// Derive the batch name for a report for the given task and with the given report ID.
    pub(crate) fn durable_name_report_store(
        &self,
        task_config: &DapTaskConfig,
        task_id_hex: &str,
        metadata: &ReportMetadata,
    ) -> String {
        let mut shard_seed = [0; 8];
        PrgAes128::seed_stream(&self.report_shard_key, metadata.id.as_ref()).fill(&mut shard_seed);
        let shard = u64::from_be_bytes(shard_seed) % self.report_shard_count;
        let epoch = metadata.time - (metadata.time % self.global.report_storage_epoch_duration);
        durable_name_report_store(&task_config.version, task_id_hex, epoch, shard)
    }
}

/// Daphne-Worker state. Constructed upon receiving an HTTP request.
pub(crate) struct DaphneWorker<D> {
    context: Option<RouteContext<D>>,
    pub(crate) config: DaphneWorkerConfig,

    /// HTTP client to use for making requests to the Helper. This is only used if Daphne-Worker is
    /// configured as the DAP Helper.
    pub(crate) client: Option<reqwest_wasm::Client>,

    /// Cached HPKE receiver config. This will be populated when Daphne-Worker obtains an HPKE
    /// receiver config for the first time from Cloudflare KV.
    hpke_receiver_configs: Arc<RwLock<HashMap<u8, HpkeReceiverConfig>>>,

    /// Laeder bearer token per task.
    leader_bearer_tokens: Arc<RwLock<HashMap<Id, BearerToken>>>,

    /// Collector bearer token per task.
    collector_bearer_tokens: Arc<RwLock<HashMap<Id, BearerToken>>>,

    /// Task list.
    tasks: Arc<RwLock<HashMap<Id, DapTaskConfig>>>,
}

impl<D> DaphneWorker<D> {
    pub(crate) fn from_worker_context(context: RouteContext<D>) -> Result<Self> {
        let config = DaphneWorkerConfig::from_worker_env(&context.env)?;

        let client = if config.is_leader {
            // TODO Configure this client to use HTTPS only, excpet if running in a test
            // environment.
            Some(reqwest_wasm::Client::new())
        } else {
            None
        };

        Ok(Self {
            context: Some(context),
            config,
            client,
            hpke_receiver_configs: Arc::new(RwLock::new(HashMap::new())),
            leader_bearer_tokens: Arc::new(RwLock::new(HashMap::new())),
            collector_bearer_tokens: Arc::new(RwLock::new(HashMap::new())),
            tasks: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    pub(crate) fn durable(&self) -> DurableConnector<'_> {
        DurableConnector::new(
            &self
                .context
                .as_ref()
                .expect("no route context configured")
                .env,
        )
    }

    pub(crate) fn kv(&self) -> Result<KvStore> {
        self.context
            .as_ref()
            .ok_or_else(|| Error::RustError("route context does not exist".to_string()))?
            .kv(KV_BINDING_DAP_CONFIG)
    }

    /// Set a key/value pair unless the key already exists. If the key exists, then return the current
    /// value. Otherwise return nothing.
    async fn kv_set_if_not_exists<K, V>(
        &self,
        kv_key_prefix: &str,
        kv_key_suffix: &K,
        kv_value: V,
    ) -> Result<Option<V>>
    where
        K: ToString,
        V: for<'de> Deserialize<'de> + Serialize,
    {
        let kv_key = format!("{}/{}", kv_key_prefix, kv_key_suffix.to_string());
        let kv_store = self.kv()?;
        let builder = kv_store.get(&kv_key);
        let res: Option<V> = builder.json().await?;
        if res.is_some() {
            return Ok(res);
        }

        kv_store.put(&kv_key, kv_value)?.execute().await?;
        Ok(None)
    }

    async fn kv_get_cached<'srv, 'req, K, V>(
        &self,
        map: &'srv Arc<RwLock<HashMap<K, V>>>,
        kv_key_prefix: &str,
        kv_key_suffix: Cow<'req, K>,
    ) -> Result<Option<Guarded<'req, K, V>>>
    where
        K: Clone + Eq + std::hash::Hash + ToString,
        V: for<'de> Deserialize<'de>,
        'srv: 'req,
    {
        // If the value is cached, then return immediately.
        {
            let guarded_map = map
                .read()
                .map_err(|e| Error::RustError(format!("Failed to lock map for reading: {}", e)))?;

            if guarded_map.get(&kv_key_suffix).is_some() {
                return Ok(Some(Guarded {
                    guarded_map,
                    key: kv_key_suffix,
                }));
            }
        }

        // If the value is not cached, try to populate it from KV before returning.
        let kv_key = format!("{}/{}", kv_key_prefix, kv_key_suffix.to_string());
        let kv_store = self.kv()?;
        let builder = kv_store.get(&kv_key);
        if let Some(kv_value) = builder.json::<V>().await? {
            // TODO(cjpatton) Consider indicating whether the value is known to not exist. For HPKE
            // configs, this would avoid hitting KV multiple times when the same expired config is
            // used for multiple reports.
            let mut guarded_map = map
                .write()
                .map_err(|e| Error::RustError(format!("Failed to lock map for writing: {}", e)))?;
            guarded_map.insert(kv_key_suffix.clone().into_owned(), kv_value);
        }

        let guarded_map = map
            .read()
            .map_err(|e| Error::RustError(format!("Failed to lock map for reading: {}", e)))?;

        if guarded_map.get(kv_key_suffix.as_ref()).is_some() {
            Ok(Some(Guarded {
                guarded_map,
                key: kv_key_suffix,
            }))
        } else {
            Ok(None)
        }
    }

    /// Get a reference to the HPKE receiver configs, ensuring that the config indicated by
    /// `hpke_config_id` is cached (if it exists).
    pub(crate) async fn get_hpke_receiver_config(
        &self,
        hpke_config_id: u8,
    ) -> Result<Option<GuardedHpkeReceiverConfig>> {
        self.kv_get_cached(
            &self.hpke_receiver_configs,
            KV_KEY_PREFIX_HPKE_RECEIVER_CONFIG,
            Cow::Owned(hpke_config_id),
        )
        .await
    }

    /// Retrieve from KV the Leader's bearer token for the given task.
    pub(crate) async fn get_leader_bearer_token<'a>(
        &'a self,
        task_id: &'a Id,
    ) -> Result<Option<GuardedBearerToken>> {
        self.kv_get_cached(
            &self.leader_bearer_tokens,
            KV_KEY_PREFIX_BEARER_TOKEN_LEADER,
            Cow::Borrowed(task_id),
        )
        .await
    }

    /// Set a leader bearer token for the given task.
    pub(crate) async fn set_leader_bearer_token(
        &self,
        task_id: &Id,
        token: &BearerToken,
    ) -> Result<Option<BearerToken>> {
        self.kv_set_if_not_exists(KV_KEY_PREFIX_BEARER_TOKEN_LEADER, task_id, token.clone())
            .await
    }

    /// Retrieve from KV the Collector's bearer token for the given task.
    pub(crate) async fn get_collector_bearer_token<'a>(
        &'a self,
        task_id: &'a Id,
    ) -> Result<Option<GuardedBearerToken>> {
        self.kv_get_cached(
            &self.collector_bearer_tokens,
            KV_KEY_PREFIX_BEARER_TOKEN_COLLECTOR,
            Cow::Borrowed(task_id),
        )
        .await
    }

    /// Retrieve from KV the configuration for the given task.
    pub(crate) async fn get_task_config<'srv, 'req>(
        &'srv self,
        task_id: Cow<'req, Id>,
    ) -> Result<Option<GuardedDapTaskConfig<'req>>>
    where
        'srv: 'req,
    {
        self.kv_get_cached(&self.tasks, KV_KEY_PREFIX_TASK_CONFIG, task_id)
            .await
    }

    /// Define a task in KV
    pub(crate) async fn set_task_config(
        &self,
        task_id: &Id,
        task_config: &DapTaskConfig,
    ) -> Result<Option<DapTaskConfig>> {
        self.kv_set_if_not_exists(KV_KEY_PREFIX_TASK_CONFIG, task_id, task_config.clone())
            .await
    }

    /// Try retrieving from KV the configuration for the given task. Return an error if the
    /// indicated task is not recognized.
    pub(crate) async fn try_get_task_config<'srv, 'req>(
        &'srv self,
        task_id: &'req Id,
    ) -> std::result::Result<GuardedDapTaskConfig<'req>, DapError>
    where
        'srv: 'req,
    {
        self.get_task_config(Cow::Borrowed(task_id))
            .await
            .map_err(dap_err)?
            .ok_or(DapError::Abort(DapAbort::UnrecognizedTask))
    }

    /// Clear all persistant durable objects storage.
    ///
    /// TODO(cjpatton) Gate this to non-prod deployments. (Prod should do migration.)
    pub(crate) async fn internal_delete_all(&self) -> std::result::Result<(), DapError> {
        let durable = self.durable();
        let future_delete_durable = durable.post(
            BINDING_DAP_GARBAGE_COLLECTOR,
            DURABLE_DELETE_ALL,
            "garbage_collector".to_string(),
            &(),
        );

        let kv_store = self.kv().map_err(dap_err)?;
        for kv_key in kv_store
            .list()
            .execute()
            .await
            .map_err(|e| DapError::Fatal(format!("kv_store: {}", e)))?
            .keys
        {
            kv_store
                .delete(kv_key.name.as_str())
                .await
                .map_err(|e| DapError::Fatal(format!("kv_store: {}", e)))?;
            console_debug!("deleted KV item {}", kv_key.name);
        }

        future_delete_durable.await.map_err(dap_err)?;
        Ok(())
    }

    /// Get the batch ID for the oldest batch that has not been collected. This method is only
    /// applicable to fixed-size tasks.
    pub(crate) async fn internal_current_batch(
        &self,
        task_id: &Id,
    ) -> std::result::Result<Id, DapError> {
        let task_config = self.try_get_task_config(task_id).await?;
        if !matches!(task_config.as_ref().query, DapQueryConfig::FixedSize { .. }) {
            return Err(DapError::fatal("query type mismatch"));
        }

        let res: LeaderBatchQueueResult = self
            .durable()
            .get(
                BINDING_DAP_LEADER_BATCH_QUEUE,
                DURABLE_LEADER_BATCH_QUEUE_CURRENT,
                durable_name_task(&task_config.as_ref().version, &task_id.to_hex()),
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

    /// Get the URL to use for this endpoint, as required by
    /// draft-dcook-ppm-dap-interop-test-design-02.
    pub(crate) async fn internal_endpoint_for_task(
        &self,
        version: DapVersion,
        cmd: InternalTestEndpointForTask,
    ) -> Result<Response> {
        if self.config.is_leader && !matches!(cmd.role, InternalTestRole::Leader)
            || !self.config.is_leader && !matches!(cmd.role, InternalTestRole::Helper)
        {
            return Response::from_json(&serde_json::json!({
                "status": "error",
                "error": "role mismatch",
            }));
        }

        Response::from_json(&serde_json::json!({
            "status": "success",
            "endpoint": format!("{}{}/", self.config.base_url.path(), version.as_ref()),
        }))
    }

    /// Configure Daphne-Worker a task, as required by draft-dcook-ppm-dap-interop-test-design-02.
    pub(crate) async fn internal_add_task(
        &self,
        version: DapVersion,
        cmd: InternalTestAddTask,
    ) -> Result<()> {
        // Task ID.
        let task_id_data = decode_base64url_vec(cmd.task_id.as_bytes())
            .ok_or_else(|| int_err("task ID is not valid URL-safe base64"))?;
        let task_id = Id::get_decoded(&task_id_data).map_err(int_err)?;

        // VDAF config.
        let vdaf = match (cmd.vdaf.typ.as_ref(), cmd.vdaf.bits) {
            ("Prio3Aes128Count", None) => VdafConfig::Prio3(Prio3Config::Count),
            ("Prio3Aes128Sum", Some(bits)) => {
                let bits = bits.parse().map_err(int_err)?;
                VdafConfig::Prio3(Prio3Config::Sum { bits })
            }
            _ => return Err(int_err("command failed: unrecognized VDAF")),
        };

        // VDAF verificaiton key.
        let vdaf_verify_key_data = decode_base64url_vec(cmd.verify_key.as_bytes())
            .ok_or_else(|| int_err("VDAF verify key is not valid URL-safe base64"))?;
        let vdaf_verify_key = vdaf
            .get_decoded_verify_key(&vdaf_verify_key_data)
            .map_err(int_err)?;

        // Collector HPKE config.
        let collector_hpke_config_data = decode_base64url_vec(cmd.collector_hpke_config.as_bytes())
            .ok_or_else(|| int_err("HPKE collector config is not valid URL-safe base64"))?;
        let collector_hpke_config =
            HpkeConfig::get_decoded(&collector_hpke_config_data).map_err(int_err)?;

        // Leader authentication token.
        let token = BearerToken::from(cmd.leader_authentication_token);
        if self
            .kv_set_if_not_exists(KV_KEY_PREFIX_BEARER_TOKEN_LEADER, &task_id, token)
            .await?
            .is_some()
        {
            return Err(int_err(format!(
                "command failed: token already exists for the given task ({}) and bearer role (leader)",
                cmd.task_id
            )));
        }

        // Collector authentication token.
        match (cmd.role, cmd.collector_authentication_token) {
            (InternalTestRole::Leader, Some(token_string)) => {
                let token = BearerToken::from(token_string);
                if self
                    .kv_set_if_not_exists(KV_KEY_PREFIX_BEARER_TOKEN_COLLECTOR, &task_id, token)
                    .await?
                    .is_some()
                {
                    return Err(int_err(format!(
                        "command failed: token already exists for the given task ({}) and bearer role (collector)",
                        cmd.task_id
                    )));
                }
            }
            (InternalTestRole::Leader, None) => {
                return Err(int_err(
                    "command failed: missing collector authentication token",
                ))
            }
            (InternalTestRole::Helper, None) => (),
            (InternalTestRole::Helper, Some(..)) => {
                return Err(int_err(
                    "command failed: unexpected collector authentication token",
                ));
            }
        };

        // Query configuraiton.
        let query = match (cmd.query_type, cmd.max_batch_size) {
            (1, None) => DapQueryConfig::TimeInterval,
            (1, Some(..)) => return Err(int_err("command failed: unexpected max batch size")),
            (2, Some(max_batch_size)) => DapQueryConfig::FixedSize { max_batch_size },
            (2, None) => return Err(int_err("command failed: missing max batch size")),
            _ => return Err(int_err("command failed: unrecognized query type")),
        };

        if self
            .kv_set_if_not_exists(
                KV_KEY_PREFIX_TASK_CONFIG,
                &task_id,
                DapTaskConfig {
                    version,
                    leader_url: cmd.leader,
                    helper_url: cmd.helper,
                    time_precision: cmd.time_precision,
                    expiration: cmd.task_expiration,
                    min_batch_size: cmd.min_batch_size,
                    query,
                    vdaf,
                    vdaf_verify_key,
                    collector_hpke_config,
                },
            )
            .await?
            .is_some()
        {
            Err(int_err(format!(
                "command failed: config already exists for the given task ({})",
                cmd.task_id
            )))
        } else {
            Ok(())
        }
    }

    pub(crate) fn extract_version_parameter(&self, req: &Request) -> Result<DapVersion> {
        let url = req.url()?;
        let path = url.path();
        let mut router: Router<bool> = Router::new();
        router.insert("/:version/*remaining", true).unwrap();
        let url_match = router.at(path).unwrap();
        let version = url_match
            .params
            .get("version")
            .ok_or_else(|| Error::RustError(format!("Failed to parse path: {}", path)))?;
        Ok(DapVersion::from(version))
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

        let version = self.extract_version_parameter(&req)?;
        let payload = req.bytes().await?;

        // Parse the task ID from the front of the request payload and use it to look up the
        // expected bearer token.
        //
        // TODO(cjpatton) Add regression tests that ensure each protocol message is prefixed by the
        // task ID.
        //
        // TODO spec: Consider moving the task ID out of the payload. Right now we're parsing it
        // twice so that we have a reference to the task ID before parsing the entire message.
        let mut r = Cursor::new(payload.as_ref());
        let task_id = Id::decode(&mut r).ok();

        Ok(DapRequest {
            version,
            task_id,
            payload,
            url: req.url()?,
            media_type,
            sender_auth,
        })
    }

    pub(crate) fn least_valid_report_time(&self, now: u64) -> u64 {
        now.saturating_sub(self.config.global.report_storage_epoch_duration)
    }

    pub(crate) fn greatest_valid_report_time(&self, now: u64) -> u64 {
        now.saturating_add(self.config.global.report_storage_max_future_time_skew)
    }
}

/// RwLockReadGuard'ed object, used to catch items fetched from KV.
pub(crate) struct Guarded<'a, K: Clone, V> {
    guarded_map: RwLockReadGuard<'a, HashMap<K, V>>,
    key: Cow<'a, K>,
}

impl<K: Clone + Eq + std::hash::Hash, V> Guarded<'_, K, V> {
    pub(crate) fn key(&self) -> &K {
        self.key.as_ref()
    }

    pub(crate) fn value(&self) -> &V {
        self.guarded_map.get(self.key.as_ref()).unwrap()
    }
}

pub(crate) type GuardedHpkeReceiverConfig<'a> = Guarded<'a, u8, HpkeReceiverConfig>;

impl AsRef<HpkeConfig> for GuardedHpkeReceiverConfig<'_> {
    fn as_ref(&self) -> &HpkeConfig {
        &self.value().config
    }
}

pub(crate) type GuardedBearerToken<'a> = Guarded<'a, Id, BearerToken>;

impl AsRef<BearerToken> for GuardedBearerToken<'_> {
    fn as_ref(&self) -> &BearerToken {
        self.value()
    }
}

pub(crate) type GuardedDapTaskConfig<'a> = Guarded<'a, Id, DapTaskConfig>;

impl AsRef<DapTaskConfig> for GuardedDapTaskConfig<'_> {
    fn as_ref(&self) -> &DapTaskConfig {
        self.value()
    }
}

/// Deployment types for Daphne-Worker. This defines overrides used to control inter-Aggregator
/// communication.
#[derive(Debug, Default)]
pub(crate) enum DaphneWorkerDeployment {
    /// Daphne-Worker is running in a production environment. No behavior overrides are applied.
    #[default]
    Prod,
    /// Daphne-Worker is running in a development environment. Any durable objects that are created
    /// will be registered by the garbage collector so that they can be deleted manually using the
    /// internal test API.
    Dev,
}
