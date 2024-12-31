// Copyright (c) 2025 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

mod cache;

use std::{any::Any, fmt::Display, future::Future, sync::RwLock};

use mappable_rc::Marc;
use serde::{de::DeserializeOwned, Serialize};
use tracing::{info_span, Instrument};

use super::Error;
use crate::storage_proxy;
use cache::Cache;
use daphne::messages::Time;
use worker::send::SendWrapper;

#[derive(Default)]
pub struct State {
    cache: RwLock<Cache>,
}

impl State {
    #[cfg(feature = "test-utils")]
    pub fn reset(&self) {
        let Self { cache } = self;

        *cache.write().unwrap() = Default::default();
    }
}

pub(crate) struct Kv<'h> {
    env: &'h SendWrapper<worker::Env>,
    state: &'h State,
}

pub trait KvPrefix {
    const PREFIX: &'static str;

    type Key: Display;
    type Value: Any + Send + Sync + Serialize + DeserializeOwned;
}

pub mod prefix {
    use std::{
        fmt::{self, Display},
        marker::PhantomData,
    };

    use daphne::{
        constants::DapRole,
        hpke::HpkeReceiverConfig,
        messages::{Base64Encode, TaskId},
        taskprov, DapTaskConfig, DapVersion,
    };
    use daphne_service_utils::bearer_token::BearerToken;
    use serde::{de::DeserializeOwned, Serialize};

    use super::KvPrefix;

    pub type HpkeRecieverConfigList = Vec<HpkeReceiverConfig>;

    #[derive(Debug)]
    pub struct GlobalConfigOverride<V>(PhantomData<V>);

    /// List of global overrides stored in kv.
    #[derive(Debug)]
    #[cfg_attr(feature = "test-utils", derive(serde::Serialize, serde::Deserialize))]
    pub enum GlobalOverrides {
        /// A `bool` describing whether to skip replay protection.
        SkipReplayProtection,
        /// The default number of aggregate span shards to use in new tasks.
        DefaultNumAggSpanShards,
    }

    impl Display for GlobalOverrides {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            let key = match self {
                Self::SkipReplayProtection => "skip_replay_protection",
                Self::DefaultNumAggSpanShards => "default_num_agg_span_shards",
            };
            f.write_str(key)
        }
    }

    impl<V> KvPrefix for GlobalConfigOverride<V>
    where
        V: Send + Sync + Serialize + DeserializeOwned + 'static,
    {
        const PREFIX: &'static str = "global_config/override";

        type Key = GlobalOverrides;
        type Value = V;
    }

    pub struct TaskConfig();
    impl KvPrefix for TaskConfig {
        const PREFIX: &'static str = "config/task";

        type Key = TaskId;
        type Value = DapTaskConfig;
    }

    pub struct TaskprovOptInParam();
    impl KvPrefix for TaskprovOptInParam {
        const PREFIX: &'static str = "taskprov/opt_in_param";

        type Key = TaskId;
        type Value = taskprov::OptInParam;
    }

    pub struct HpkeReceiverConfigSet();
    impl KvPrefix for HpkeReceiverConfigSet {
        const PREFIX: &'static str = "hpke_receiver_config_set";

        type Key = DapVersion;
        type Value = HpkeRecieverConfigList;
    }

    pub struct KvBearerToken();
    impl KvPrefix for KvBearerToken {
        const PREFIX: &'static str = "bearer_token";

        type Key = KvBearerTokenKey;
        type Value = BearerToken;
    }

    #[derive(Debug)]
    pub struct KvBearerTokenKey(DapRole, TaskId);
    impl From<(DapRole, TaskId)> for KvBearerTokenKey {
        fn from((s, t): (DapRole, TaskId)) -> Self {
            Self(s, t)
        }
    }
    impl fmt::Display for KvBearerTokenKey {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            let Self(sender, task_id) = self;
            let task_id = task_id.to_base64url();
            match sender {
                DapRole::Client => write!(f, "client/task/{task_id}"),
                DapRole::Collector => write!(f, "collector/task/{task_id}"),
                DapRole::Helper => write!(f, "helper/task/{task_id}"),
                DapRole::Leader => write!(f, "leader/task/{task_id}"),
            }
        }
    }
}

/// Options for getting items from KV.
#[derive(Default, Debug)]
pub(crate) struct KvGetOptions {
    /// Cache the response from KV regardless of whether a value was found. If the value was not
    /// found, then [`Kv::get`] and its cousins will return `None` until the cache line expires.
    ///
    /// In most cases we want this option to be disabled. This option is useful in situations where
    /// we don't expect the value to be in KV and the user is not latency-sensitive. For example,
    /// we store overrides for [`DapGlobalConfig`] in KV, but we can wait a few minutes for these
    /// overrides to take effect. Setting this option prevents us from hitting KV harder than we
    /// need to.
    pub(crate) cache_not_found: bool,
}

pub(crate) enum GetOrInsertError<E> {
    StorageProxy(Error),
    Other(E),
}

impl<E, E2> From<E2> for GetOrInsertError<E>
where
    Error: From<E2>,
{
    fn from(error: E2) -> Self {
        Self::StorageProxy(error.into())
    }
}

impl<'h> Kv<'h> {
    pub fn new(env: &'h SendWrapper<worker::Env>, state: &'h State) -> Self {
        Self { env, state }
    }

    pub async fn get<P>(
        &self,
        key: &P::Key,
        opt: &KvGetOptions,
    ) -> Result<Option<Marc<P::Value>>, Error>
    where
        P: KvPrefix,
        P::Key: std::fmt::Debug,
    {
        self.get_mapped::<P, _, _>(key, opt, |t| Some(t)).await
    }

    pub async fn get_cloned<P>(
        &self,
        key: &P::Key,
        opt: &KvGetOptions,
    ) -> Result<Option<P::Value>, Error>
    where
        P: KvPrefix,
        P::Key: std::fmt::Debug,
        P::Value: Clone,
    {
        Ok(self.get::<P>(key, opt).await?.map(|t| t.as_ref().clone()))
    }

    pub async fn get_mapped<P, R, F>(
        &self,
        key: &P::Key,
        opt: &KvGetOptions,
        mapper: F,
    ) -> Result<Option<Marc<R>>, Error>
    where
        P: KvPrefix,
        P::Key: std::fmt::Debug,
        F: for<'s> FnOnce(&'s P::Value) -> Option<&'s R>,
        R: Send + Sync + 'static,
    {
        self.get_internal::<P, _, _>(key, opt, Some)
            .await
            .map(|opt| opt.flatten().map(|marc| Marc::try_map(marc, mapper).ok()))
            .map(Option::flatten)
    }

    pub async fn get_or_insert_with<P, Fut, E>(
        &self,
        key: &P::Key,
        opt: &KvGetOptions,
        default: impl FnOnce() -> Fut,
        expiration: Option<Time>,
    ) -> Result<Marc<P::Value>, GetOrInsertError<E>>
    where
        P: KvPrefix,
        P::Key: std::fmt::Debug,
        E: Send + Sync + 'static,
        Fut: Future<Output = Result<P::Value, E>>,
    {
        if let Some(v) = self.get_internal::<P, _, _>(key, opt, |marc| marc).await? {
            return Ok(v);
        }
        let default = default().await.map_err(GetOrInsertError::Other)?;
        let cached = self.put_internal::<P>(key, default, expiration).await?;
        Ok(cached)
    }

    pub async fn peek<P, R, F>(
        &self,
        key: &P::Key,
        opt: &KvGetOptions,
        peeker: F,
    ) -> Result<Option<R>, Error>
    where
        P: KvPrefix,
        P::Key: std::fmt::Debug,
        F: FnOnce(&P::Value) -> R,
    {
        self.get_internal::<P, _, _>(key, opt, Some)
            .await
            .map(|opt| opt.flatten().map(|marc| peeker(&marc)))
    }

    async fn get_internal<P, R, F>(
        &self,
        key: &P::Key,
        opt: &KvGetOptions,
        mapper: F,
    ) -> Result<Option<R>, Error>
    where
        P: KvPrefix,
        P::Key: std::fmt::Debug,
        F: FnOnce(Marc<P::Value>) -> R,
    {
        let key = Self::to_key::<P>(key);
        tracing::debug!(key, "GET");
        match self.state.cache.read().unwrap().get::<P>(&key) {
            cache::CacheResult::Miss => {}
            cache::CacheResult::Hit(t) => return Ok(t.map(mapper)),
            cache::CacheResult::MismatchedType => {
                tracing::warn!(
                    "cache mismatched type, wanted {}",
                    std::any::type_name::<P::Value>()
                );
            }
        }
        let span = info_span!(
            "uncached kv_get",
            ?key,
            ?opt,
            prefix = std::any::type_name::<P>()
        );
        async {
            if let Some(v) = storage_proxy::kv_get(self.env, &key).await? {
                let t = Marc::new(serde_json::from_slice::<P::Value>(&v)?);
                let r = mapper(t.clone());
                self.state.cache.write().unwrap().put::<P>(key, Some(t));
                Ok(Some(r))
            } else {
                if opt.cache_not_found {
                    self.state.cache.write().unwrap().put::<P>(key, None);
                }
                Ok(None)
            }
        }
        .instrument(span)
        .await
    }

    pub async fn put_internal<P>(
        &self,
        key: &P::Key,
        value: P::Value,
        expiration: Option<Time>,
    ) -> Result<Marc<P::Value>, Error>
    where
        P: KvPrefix,
        P::Key: std::fmt::Debug,
        P::Value: Serialize,
    {
        let key = Self::to_key::<P>(key);
        tracing::debug!(key, "PUT");

        storage_proxy::kv_put(
            self.env,
            expiration,
            &key,
            &serde_json::to_vec(&value).unwrap(),
        )
        .await?;

        let value = Marc::new(value);
        self.state
            .cache
            .write()
            .unwrap()
            .put::<P>(key, Some(value.clone()));
        Ok(value)
    }

    pub async fn put_with_expiration<P>(
        &self,
        key: &P::Key,
        value: P::Value,
        expiration: Time,
    ) -> Result<Marc<P::Value>, Error>
    where
        P: KvPrefix,
        P::Key: std::fmt::Debug,
        P::Value: Serialize,
    {
        self.put_internal::<P>(key, value, Some(expiration)).await
    }

    #[cfg_attr(not(feature = "test-utils"), allow(dead_code))]
    pub async fn put<P>(&self, key: &P::Key, value: P::Value) -> Result<Marc<P::Value>, Error>
    where
        P: KvPrefix,
        P::Key: std::fmt::Debug,
        P::Value: Serialize,
    {
        self.put_internal::<P>(key, value, None).await
    }

    /// Stores a value in kv if it doesn't already exist.
    ///
    /// If the value already exists, returns the passed in value inside the Ok variant.
    pub async fn put_if_not_exists_internal<P>(
        &self,
        key: &P::Key,
        value: P::Value,
        expiration: Option<Time>,
    ) -> Result<Option<P::Value>, Error>
    where
        P: KvPrefix,
        P::Key: std::fmt::Debug,
    {
        let key = Self::to_key::<P>(key);

        tracing::debug!(key, "PUT if not exists");

        let inserted = storage_proxy::kv_put_if_not_exists(
            self.env,
            expiration,
            &key,
            &serde_json::to_vec(&value).unwrap(),
        )
        .await?;
        if inserted {
            self.state
                .cache
                .write()
                .unwrap()
                .put::<P>(key, Some(value.into()));
            Ok(None)
        } else {
            Ok(Some(value))
        }
    }

    #[cfg_attr(not(feature = "test-utils"), allow(dead_code))]
    pub async fn put_if_not_exists_with_expiration<P>(
        &self,
        key: &P::Key,
        value: P::Value,
        expiration: Time,
    ) -> Result<Option<P::Value>, Error>
    where
        P: KvPrefix,
        P::Key: std::fmt::Debug,
        P::Value: Serialize,
    {
        self.put_if_not_exists_internal::<P>(key, value, Some(expiration))
            .await
    }

    #[cfg_attr(not(feature = "test-utils"), allow(dead_code))]
    pub async fn put_if_not_exists<P>(
        &self,
        key: &P::Key,
        value: P::Value,
    ) -> Result<Option<P::Value>, Error>
    where
        P: KvPrefix,
        P::Key: std::fmt::Debug,
        P::Value: Serialize,
    {
        self.put_if_not_exists_internal::<P>(key, value, None).await
    }

    #[tracing::instrument(skip_all, fields(key, prefix = std::any::type_name::<P>()))]
    pub async fn only_cache_put<P>(&self, key: &P::Key, value: P::Value)
    where
        P: KvPrefix,
        P::Key: std::fmt::Debug,
    {
        let key = Self::to_key::<P>(key);
        self.state
            .cache
            .write()
            .unwrap()
            .put::<P>(key, Some(value.into()));
    }

    fn to_key<P: KvPrefix>(key: &P::Key) -> String {
        format!("{}/{key}", P::PREFIX)
    }
}
