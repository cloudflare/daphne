// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use anyhow::Context;
use assert_matches::assert_matches;
use daphne::{
    constants::{DapAggregatorRole, DapMediaType},
    hpke::{HpkeAeadId, HpkeConfig, HpkeKdfId, HpkeKemId, HpkeReceiverConfig},
    messages::{
        encode_base64url, taskprov::TaskprovAdvertisement, Base64Encode, BatchId, CollectionJobId,
        Duration, HpkeConfigList, Interval, TaskId,
    },
    vdaf::{Prio3Config, VdafConfig},
    DapGlobalConfig, DapLeaderProcessTelemetry, DapQueryConfig, DapTaskConfig, DapVersion,
};
use daphne_service_utils::http_headers;
use futures::StreamExt;
use hpke_rs::{HpkePrivateKey, HpkePublicKey};
use prio::codec::{Decode, Encode};
use rand::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::time::SystemTime;
use std::{
    any::{self, Any},
    num::{NonZeroU32, NonZeroUsize},
    ops::Range,
};
use tokio::time::timeout;
use url::Url;

const VDAF_CONFIG: &VdafConfig = &VdafConfig::Prio3(Prio3Config::Sum { bits: 10 });
pub(crate) const MIN_BATCH_SIZE: u64 = 10;
pub(crate) const MAX_BATCH_SIZE: u32 = 12;
pub(crate) const TIME_PRECISION: Duration = 3600; // seconds

#[derive(Deserialize)]
struct InternalTestCommandResult {
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

pub struct TestRunner {
    pub global_config: DapGlobalConfig,
    pub task_id: TaskId,
    pub task_config: DapTaskConfig,
    pub now: u64,
    pub leader_url: Url,
    pub helper_url: Url,
    pub leader_bearer_token: String,
    pub collector_bearer_token: String,
    pub collector_hpke_receiver: HpkeReceiverConfig,
    pub taskprov_vdaf_verify_key_init: [u8; 32],
    pub taskprov_collector_hpke_receiver: HpkeReceiverConfig,
    pub version: DapVersion,
    pub http_client: reqwest::Client,
}

impl TestRunner {
    pub async fn default_with_version(version: DapVersion) -> Self {
        Self::with(version, &DapQueryConfig::TimeInterval).await
    }

    pub async fn leader_selected(version: DapVersion) -> Self {
        Self::with(
            version,
            &DapQueryConfig::LeaderSelected {
                max_batch_size: Some(NonZeroU32::new(MAX_BATCH_SIZE).unwrap()),
            },
        )
        .await
    }

    async fn with(version: DapVersion, query_config: &DapQueryConfig) -> Self {
        println!("\n############ starting test prep ############");
        let mut rng = thread_rng();
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let task_id = TaskId(rng.gen());

        // When running in a local development environment, override the hostname of each
        // aggregator URL with 127.0.0.1.
        let mut leader_url = Url::parse(&format!("http://leader:8787/{version}/")).unwrap();
        let mut helper_url = Url::parse(&format!("http://helper:8788/{version}/")).unwrap();
        if let Ok(env) = std::env::var("DAP_DEPLOYMENT") {
            if env == "dev" {
                leader_url.set_host(Some("127.0.0.1")).unwrap();
                helper_url.set_host(Some("127.0.0.1")).unwrap();
            } else {
                panic!("unrecognized value for DAP_DEPLOYMENT: '{env}'");
            }
        };
        println!("leader_url = {leader_url}");

        let collector_hpke_receiver =
            HpkeReceiverConfig::gen(rng.gen(), HpkeKemId::X25519HkdfSha256).unwrap();

        let global_config = DapGlobalConfig {
            max_batch_duration: 360_000,
            min_batch_interval_start: 259_200,
            max_batch_interval_end: 259_200,
            supported_hpke_kems: vec![HpkeKemId::X25519HkdfSha256],
            default_num_agg_span_shards: NonZeroUsize::new(1).unwrap(),
        };

        let task_config = DapTaskConfig {
            version,
            leader_url: leader_url.clone(),
            helper_url: helper_url.clone(),
            not_before: now,
            not_after: now + 604_800, // one week from now
            time_precision: TIME_PRECISION,
            min_batch_size: MIN_BATCH_SIZE,
            query: query_config.clone(),
            vdaf: *VDAF_CONFIG,
            vdaf_verify_key: VDAF_CONFIG.gen_verify_key(),
            collector_hpke_config: collector_hpke_receiver.config.clone(),
            method: Default::default(),
            num_agg_span_shards: global_config.default_num_agg_span_shards,
        };

        // This block needs to be kept in-sync with daphne-worker-test/wrangler.toml.
        let taskprov_vdaf_verify_key_init =
            hex::decode("b029a72fa327931a5cb643dcadcaafa098fcbfac07d990cb9e7c9a8675fafb18")
                .unwrap()
                .try_into()
                .unwrap();
        let taskprov_collector_hpke_receiver = HpkeReceiverConfig::try_from((
            HpkeConfig {
                id: 23,
                kem_id: HpkeKemId::P256HkdfSha256,
                kdf_id: HpkeKdfId::HkdfSha256,
                aead_id: HpkeAeadId::Aes128Gcm,
                public_key: HpkePublicKey::from(hex::decode("047dab625e0d269abcc28c611bebf5a60987ddf7e23df0e0aa343e5774ad81a1d0160d9252b82b4b5c52354205f5ec945645cb79facff8d85c9c31b490cdf35466").unwrap())
            },
            HpkePrivateKey::from(hex::decode("9ce9851512df3ea674b108b305c3f8c424955a94d93fd53ecf3c3f17f7d1df9e").unwrap())
        )).expect("bad hpke configuration");

        let leader_bearer_token = hex::encode(rng.gen::<[u8; 16]>());
        let collector_bearer_token = hex::encode(rng.gen::<[u8; 16]>());
        let t = Self {
            global_config,
            task_id,
            now,
            task_config,
            leader_url,
            helper_url,
            leader_bearer_token,
            collector_bearer_token,
            collector_hpke_receiver,
            taskprov_vdaf_verify_key_init,
            taskprov_collector_hpke_receiver,
            version,
            http_client: reqwest::ClientBuilder::new()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap(),
        };

        let vdaf_verify_key_base64url = encode_base64url(t.task_config.vdaf_verify_key.as_ref());

        let collector_hpke_config_base64url =
            encode_base64url(t.collector_hpke_receiver.config.get_encoded().unwrap());

        let vdaf = json!({
            "type": "Prio3Sum",
            "bits": assert_matches!(
                t.task_config.vdaf,
                VdafConfig::Prio3(Prio3Config::Sum{ bits }) => format!("{bits}")
            ),
        });

        let (query_type, max_batch_size) = match t.task_config.query {
            DapQueryConfig::TimeInterval => (1, None),
            DapQueryConfig::LeaderSelected { max_batch_size } => (2, Some(max_batch_size)),
        };

        const MAX_ATTEMPTS: usize = 10;
        for attempt in 1..=MAX_ATTEMPTS {
            let failed_connections = futures::stream::iter([&t.leader_url, &t.helper_url])
                .then(|url| async {
                    (
                        t.http_client
                            .post(url.join("/internal/test/ready").unwrap())
                            .send()
                            .await
                            .map(|r| r.status()),
                        url.clone(),
                    )
                })
                .filter_map(|(result, url)| async move {
                    match result {
                        Ok(s) if s.is_success() => None,
                        Ok(s) => Some(format!("status code for {url} was {s}")),
                        Err(e) => Some(format!("connection to {url} failed: {e:?}")),
                    }
                })
                .collect::<Vec<_>>();
            match timeout(std::time::Duration::from_secs(5), failed_connections)
                .await
                .map(|f| f.first().cloned())
            {
                Ok(Some(failure)) if attempt == MAX_ATTEMPTS => {
                    panic!("One of the aggregators was not ready in time: {failure}")
                }
                Ok(Some(_)) => tokio::time::sleep(std::time::Duration::from_secs(1)).await,
                Err(_elapsed) => {}
                Ok(None) => break,
            }
        }

        // Configure the endpoints.
        //
        // First, delete the data from the previous test.
        t.internal_delete_all(&t.batch_interval()).await.unwrap();

        // Configure the Leader with the task.
        let leader_add_task_cmd = json!({
            "task_id": t.task_id.to_base64url(),
            "leader": t.leader_url,
            "helper": t.helper_url,
            "vdaf": vdaf.clone(),
            "leader_authentication_token": t.leader_bearer_token.clone(),
            "collector_authentication_token": t.collector_bearer_token.clone(),
            "role": "leader",
            "vdaf_verify_key": vdaf_verify_key_base64url,
            "query_type": query_type,
            "min_batch_size": t.task_config.min_batch_size,
            "max_batch_size": max_batch_size,
            "time_precision": t.task_config.time_precision,
            "collector_hpke_config": collector_hpke_config_base64url.clone(),
            "task_expiration": t.task_config.not_after,
        });
        let add_task_path = format!("{}/internal/test/add_task", version.as_ref());
        let res: InternalTestCommandResult = t
            .leader_post_internal(&add_task_path, &leader_add_task_cmd)
            .await
            .unwrap();
        assert_eq!(
            res.status, "success",
            "response status: {}, error: {:?}",
            res.status, res.error
        );

        // Configure the Helper with the task.
        let helper_add_task_cmd = json!({
            "task_id": t.task_id.to_base64url(),
            "leader": t.leader_url,
            "helper": t.helper_url,
            "vdaf": vdaf.clone(),
            "leader_authentication_token": t.leader_bearer_token.clone(),
            "role": "helper",
            "vdaf_verify_key": vdaf_verify_key_base64url,
            "query_type": query_type,
            "min_batch_size": t.task_config.min_batch_size,
            "max_batch_size": max_batch_size,
            "time_precision": t.task_config.time_precision,
            "collector_hpke_config": collector_hpke_config_base64url.clone(),
            "task_expiration": t.task_config.not_after,
        });
        let res: InternalTestCommandResult = t
            .helper_post_internal(&add_task_path, &helper_add_task_cmd)
            .await
            .unwrap();
        assert_eq!(
            res.status, "success",
            "response status: {}, error: {:?}",
            res.status, res.error
        );

        let gen_config = || {
            HpkeReceiverConfig::gen(0, HpkeKemId::X25519HkdfSha256)
                .expect("failed to generate receiver config")
        };
        let res: InternalTestCommandResult = t
            .helper_post_internal(
                &format!("{version}/internal/test/add_hpke_config"),
                &gen_config(),
            )
            .await
            .unwrap();

        assert_eq!(
            res.status, "success",
            "response status: {}, error {:?}",
            res.status, res.error
        );

        let res: InternalTestCommandResult = t
            .leader_post_internal(
                &format!("{version}/internal/test/add_hpke_config"),
                &gen_config(),
            )
            .await
            .unwrap();

        assert_eq!(
            res.status, "success",
            "response status: {}, error {:?}",
            res.status, res.error
        );

        println!("############ starting test ############");
        t
    }

    pub fn http_client(&self) -> &reqwest::Client {
        &self.http_client
    }

    pub fn batch_interval(&self) -> Interval {
        let start = self.task_config.quantized_time_lower_bound(self.now);
        Interval {
            start,
            duration: self.task_config.time_precision * 2,
        }
    }

    pub fn report_interval(interval: &Interval) -> Range<u64> {
        const REPORT_STORAGE_MAX_FUTURE_TIME_SKEW: u64 = 300;
        // This is a portion of the interval which is guaranteed to be a valid report time
        // provided that the interval start time is valid.
        interval.start..interval.start + REPORT_STORAGE_MAX_FUTURE_TIME_SKEW
    }

    pub async fn get_hpke_configs(
        &self,
        _version: DapVersion,
        client: &reqwest::Client,
    ) -> anyhow::Result<[HpkeConfig; 2]> {
        let raw_leader_hpke_config = self.leader_get_raw_hpke_config(client).await?;
        let raw_helper_hpke_config = self.helper_get_raw_hpke_config(client).await?;

        let mut leader_hpke_config_list = HpkeConfigList::get_decoded(&raw_leader_hpke_config)?;
        let mut helper_hpke_config_list = HpkeConfigList::get_decoded(&raw_helper_hpke_config)?;
        if leader_hpke_config_list.hpke_configs.len() != 1
            || helper_hpke_config_list.hpke_configs.len() != 1
        {
            panic!("only a length 1 HpkeConfList is currently supported by the test suite")
        }
        Ok([
            leader_hpke_config_list.hpke_configs.pop().unwrap(),
            helper_hpke_config_list.hpke_configs.pop().unwrap(),
        ])
    }

    pub async fn leader_get_raw_hpke_config(
        &self,
        client: &reqwest::Client,
    ) -> anyhow::Result<Vec<u8>> {
        get_raw_hpke_config(client, self.task_id.as_ref(), &self.leader_url, "leader").await
    }

    pub async fn helper_get_raw_hpke_config(
        &self,
        client: &reqwest::Client,
    ) -> anyhow::Result<Vec<u8>> {
        get_raw_hpke_config(client, self.task_id.as_ref(), &self.helper_url, "helper").await
    }

    pub async fn leader_request_expect_ok(
        &self,
        client: &reqwest::Client,
        path: &str,
        method: &http::Method,
        media_type: DapMediaType,
        taskprov: Option<&str>,
        data: Vec<u8>,
    ) -> anyhow::Result<()> {
        let url = self.leader_url.join(path)?;
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::CONTENT_TYPE,
            media_type
                .as_str_for_version(self.version)
                .context("no string for version")?
                .parse()?,
        );
        if let Some(taskprov_advertisement) = taskprov {
            headers.insert(
                reqwest::header::HeaderName::from_static(http_headers::DAP_TASKPROV),
                reqwest::header::HeaderValue::from_str(taskprov_advertisement)?,
            );
        }
        let resp = client
            .request(method.clone(), url.as_str())
            .body(data)
            .headers(headers)
            .send()
            .await
            .context("request failed")?;

        anyhow::ensure!(
            resp.status() == reqwest::StatusCode::OK,
            "unexpected response status. Expected {} got {}: Body is {:?}",
            resp.status(),
            reqwest::StatusCode::OK,
            resp.text().await?,
        );
        Ok(())
    }

    #[expect(clippy::too_many_arguments)]
    pub async fn leader_request_expect_abort(
        &self,
        client: &reqwest::Client,
        dap_auth_token: Option<&str>,
        path: &str,
        method: &http::Method,
        media_type: DapMediaType,
        taskprov: Option<&str>,
        data: Vec<u8>,
        expected_status: u16,
        expected_err_type: &str,
    ) -> anyhow::Result<()> {
        let url = self.leader_url.join(path)?;

        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::CONTENT_TYPE,
            media_type
                .as_str_for_version(self.version)
                .context("no string for version")?
                .parse()?,
        );
        if let Some(token) = dap_auth_token {
            headers.insert(
                reqwest::header::HeaderName::from_static(http_headers::DAP_AUTH_TOKEN),
                reqwest::header::HeaderValue::from_str(token)?,
            );
        }
        if let Some(taskprov_advertisement) = taskprov {
            headers.insert(
                reqwest::header::HeaderName::from_static(http_headers::DAP_TASKPROV),
                reqwest::header::HeaderValue::from_str(taskprov_advertisement)?,
            );
        }

        let resp = client
            .request(method.clone(), url.as_str())
            .body(data)
            .headers(headers)
            .send()
            .await
            .context("request failed")?;

        anyhow::ensure!(
            resp.status() == reqwest::StatusCode::from_u16(expected_status).unwrap(),
            "unexpected response status. Expected {} got {}: Body is {:?}",
            expected_status,
            resp.status(),
            resp.text().await?,
        );

        anyhow::ensure!(
            resp.headers()
                .get("Content-Type")
                .context("no Content-Type header")?
                == "application/problem+json"
        );

        let problem_details: serde_json::Value = resp.json().await?;
        let got = problem_details
            .as_object()
            .context("problem details is not an object")?
            .get("type")
            .context("problem details doesn't have a `type` field")?;
        anyhow::ensure!(got == &format!("urn:ietf:params:ppm:dap:error:{expected_err_type}"));
        Ok(())
    }

    pub async fn leader_post_collect_using_token(
        &self,
        client: &reqwest::Client,
        token: &str,
        taskprov: Option<&TaskprovAdvertisement>,
        task_id: Option<&TaskId>,
        data: Vec<u8>,
    ) -> anyhow::Result<Url> {
        let path = Self::collect_path_for_task(task_id.unwrap_or(&self.task_id));
        let url = self.leader_url.join(&path)?;
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::CONTENT_TYPE,
            reqwest::header::HeaderValue::from_str(
                DapMediaType::CollectionReq
                    .as_str_for_version(self.version)
                    .context("no string for version")?,
            )?,
        );
        headers.insert(
            reqwest::header::HeaderName::from_static(http_headers::DAP_AUTH_TOKEN),
            reqwest::header::HeaderValue::from_str(token)?,
        );
        if let Some(taskprov_advertisement) = taskprov {
            headers.insert(
                reqwest::header::HeaderName::from_static(http_headers::DAP_TASKPROV),
                reqwest::header::HeaderValue::from_str(
                    &taskprov_advertisement.serialize_to_header_value(self.version)?,
                )?,
            );
        }

        let builder = client.put(url.as_str());
        let resp = builder
            .body(data)
            .headers(headers)
            .send()
            .await
            .context("request failed")?;

        let expected_status = 201;
        anyhow::ensure!(
            resp.status() == expected_status,
            "request failed: {:?}",
            resp.text().await?,
        );
        Ok(url)
    }

    pub async fn leader_post_collect(
        &self,
        client: &reqwest::Client,
        data: Vec<u8>,
    ) -> anyhow::Result<Url> {
        self.leader_post_collect_using_token(client, &self.collector_bearer_token, None, None, data)
            .await
    }

    pub async fn internal_process(
        &self,
        client: &reqwest::Client,
    ) -> anyhow::Result<DapLeaderProcessTelemetry> {
        // Replace path "/v09" with "/internal/process".
        let mut url = self.leader_url.clone();
        url.set_path("internal/process");

        let resp = client
            .post(url.as_str())
            .send()
            .await
            .context("request failed")?;
        anyhow::ensure!(
            resp.status() == 200,
            "unexpected response status. Expected {} got {}: Body is {:?}",
            reqwest::StatusCode::OK,
            resp.status(),
            resp.text().await?,
        );
        Ok(resp.json().await?)
    }

    async fn post_internal<I: Serialize, O: for<'a> Deserialize<'a> + Any>(
        &self,
        role: DapAggregatorRole,
        path: &str,
        data: &I,
    ) -> anyhow::Result<O> {
        let client = self.http_client();
        let mut url = match role {
            DapAggregatorRole::Leader => self.leader_url.clone(),
            DapAggregatorRole::Helper => self.helper_url.clone(),
        };
        url.set_path(path); // Overwrites the version path (i.e., "/v09")
        let resp = client
            .post(url.clone())
            .json(data)
            .send()
            .await
            .context("request failed")?;
        anyhow::ensure!(
            resp.status() == 200,
            "request to {url} failed: response: {} {}",
            format!("{resp:?}"), // text() moves so we have to format here
            resp.text().await.unwrap_or("<failed to get body>".into()),
        );
        let t = resp.text().await.context("failed to extract text")?;
        // This is needed so we can have tests that call this expecting nothing and have it work
        // for empty bodies.
        if t.is_empty() && any::TypeId::of::<O>() == any::TypeId::of::<()>() {
            unsafe {
                // SAFETY: we have checked that O is unit, therefore we can transmute a unit into O
                std::mem::transmute_copy(&())
            }
        } else {
            serde_json::from_str(&t).with_context(|| {
                format!(
                    "failed to Deserialize {t:?} into {}",
                    std::any::type_name::<O>()
                )
            })
        }
    }

    pub async fn leader_post_internal<I: Serialize, O: for<'a> Deserialize<'a> + Any>(
        &self,
        path: &str,
        data: &I,
    ) -> anyhow::Result<O> {
        self.post_internal(DapAggregatorRole::Leader, path, data)
            .await
    }

    pub async fn helper_post_internal<I: Serialize, O: for<'a> Deserialize<'a> + Any>(
        &self,
        path: &str,
        data: &I,
    ) -> anyhow::Result<O> {
        self.post_internal(DapAggregatorRole::Helper, path, data)
            .await
    }

    pub async fn internal_delete_all(&self, batch_interval: &Interval) -> anyhow::Result<()> {
        let client = self.http_client();
        post_internal_delete_all(client, &self.leader_url, batch_interval).await?;
        post_internal_delete_all(client, &self.helper_url, batch_interval).await?;
        Ok(())
    }

    pub async fn internal_current_batch(&self, task_id: &TaskId) -> anyhow::Result<BatchId> {
        let client = self.http_client();
        let mut url = self.leader_url.clone();
        url.set_path(&format!(
            "internal/current_batch/task/{}",
            task_id.to_base64url()
        ));
        let resp = client
            .get(url.clone())
            .send()
            .await
            .context("request failed")?;
        if resp.status() == 200 {
            let batch_id_base64url = resp.text().await?;
            BatchId::try_from_base64url(batch_id_base64url)
                .context("Failed to parse URL-safe base64 batch ID")
        } else {
            anyhow::bail!("request to {url} failed: response: {resp:?}");
        }
    }

    pub fn upload_path_for_task(id: &TaskId) -> String {
        format!("tasks/{}/reports", id.to_base64url())
    }

    pub fn collect_path_for_task(task_id: &TaskId) -> String {
        let collection_job_id = CollectionJobId(thread_rng().gen());
        format!(
            "tasks/{}/collection_jobs/{}",
            task_id.to_base64url(),
            collection_job_id.to_base64url()
        )
    }

    pub fn upload_path(&self) -> String {
        Self::upload_path_for_task(&self.task_id)
    }

    pub async fn poll_collection_url(
        &self,
        client: &reqwest::Client,
        url: &Url,
    ) -> anyhow::Result<reqwest::Response> {
        self.poll_collection_url_using_token(client, url, &self.collector_bearer_token)
            .await
    }

    pub async fn poll_collection_url_using_token(
        &self,
        client: &reqwest::Client,
        url: &Url,
        token: &str,
    ) -> anyhow::Result<reqwest::Response> {
        let builder = match self.version {
            DapVersion::Draft09 => client.post(url.as_str()),
            DapVersion::Latest => client.get(url.as_str()),
        };
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::HeaderName::from_static(http_headers::DAP_AUTH_TOKEN),
            reqwest::header::HeaderValue::from_str(token)?,
        );
        Ok(builder.headers(headers).send().await?)
    }
}

async fn get_raw_hpke_config(
    client: &reqwest::Client,
    task_id: &[u8],
    base_url: &Url,
    svc: &str,
) -> anyhow::Result<Vec<u8>> {
    let time_to_wait = std::time::Duration::from_secs(15);
    let max_time_to_wait = std::time::Duration::from_secs(60 * 3);
    let mut elapsed_time = std::time::Duration::default();
    let url = base_url.join("hpke_config")?;
    let query = [("task_id", encode_base64url(task_id))];
    while elapsed_time < max_time_to_wait {
        let req = client.get(url.as_str()).query(&query);
        match req.send().await {
            Ok(resp) => {
                if resp.status() == 200 {
                    println!("{svc} is up.");
                    return Ok(resp.bytes().await?.to_vec());
                }
                anyhow::bail!(
                    "request to {} failed: status = {}, body = {}",
                    url,
                    resp.status(),
                    resp.text().await?,
                );
            }
            Err(e) => {
                println!(
                    "[{elapsed_time:?}/{max_time_to_wait:?}] waiting {time_to_wait:?} for {svc} to be up: error: {e:?}"
                );
                elapsed_time += time_to_wait;
                std::thread::sleep(time_to_wait);
            }
        };
    }
    println!("error: timeout after {elapsed_time:?} waiting for {svc}");
    anyhow::bail!("{svc} at {url} is down.")
}

async fn post_internal_delete_all(
    client: &reqwest::Client,
    base_url: &Url,
    batch_interval: &Interval,
) -> anyhow::Result<()> {
    // Replace path "/v09" with "/internal/delete_all".
    let mut url = base_url.clone();
    url.set_path("internal/delete_all");

    let req = client
        .post(url.as_str())
        .body(serde_json::to_string(batch_interval)?);
    let resp = req.send().await.context("request failed")?;
    anyhow::ensure!(
        resp.status() == 200,
        "request to {url} failed: response {:?}",
        resp.text().await?,
    );
    Ok(())
}
