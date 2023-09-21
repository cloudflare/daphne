// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// TODO Figure out why cargo thinks there is dead code here.

use assert_matches::assert_matches;
use daphne::{
    constants::DapMediaType,
    hpke::{HpkeAeadId, HpkeConfig, HpkeKdfId, HpkeKemId, HpkeReceiverConfig},
    messages::{
        encode_base64url, BatchId, CollectionJobId, Duration, HpkeConfigList, Interval, TaskId,
    },
    taskprov::TaskprovVersion,
    DapGlobalConfig, DapLeaderProcessTelemetry, DapQueryConfig, DapTaskConfig, DapVersion,
    Prio3Config, VdafConfig,
};
use daphne_worker::DaphneWorkerReportSelector;
use hpke_rs::{HpkePrivateKey, HpkePublicKey};
use prio::codec::{Decode, Encode};
use rand::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::ops::Range;
use std::time::SystemTime;
use url::Url;

const VDAF_CONFIG: &VdafConfig = &VdafConfig::Prio3(Prio3Config::Sum { bits: 10 });
pub(crate) const MIN_BATCH_SIZE: u64 = 10;
pub(crate) const MAX_BATCH_SIZE: u64 = 12;
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
}

impl TestRunner {
    pub async fn default_with_version(version: DapVersion) -> Self {
        Self::with(version, &DapQueryConfig::TimeInterval).await
    }

    pub async fn fixed_size(version: DapVersion) -> Self {
        Self::with(
            version,
            &DapQueryConfig::FixedSize {
                max_batch_size: MAX_BATCH_SIZE,
            },
        )
        .await
    }

    async fn with(version: DapVersion, query_config: &DapQueryConfig) -> Self {
        let mut rng = thread_rng();
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let task_id = TaskId(rng.gen());

        // When running in a local development environment, override the hostname of each
        // aggregator URL with 127.0.0.1.
        let version_path = match version {
            DapVersion::Draft02 => "v02",
            DapVersion::Draft05 => "v05",
            _ => panic!("unimplemented DapVersion"),
        };
        let mut leader_url = Url::parse(&format!("http://leader:8787/{}/", version_path)).unwrap();
        let mut helper_url = Url::parse(&format!("http://helper:8788/{}/", version_path)).unwrap();
        println!("leader_url = {}", leader_url);
        if let Ok(env) = std::env::var("DAP_DEPLOYMENT") {
            if env == "dev" {
                leader_url.set_host(Some("127.0.0.1")).unwrap();
                helper_url.set_host(Some("127.0.0.1")).unwrap();
            } else {
                panic!("unrecognized value for DAP_DEPLOYMENT: '{}'", env);
            }
        };

        let collector_hpke_receiver =
            HpkeReceiverConfig::gen(rng.gen(), HpkeKemId::X25519HkdfSha256).unwrap();

        let task_config = DapTaskConfig {
            version,
            leader_url: leader_url.clone(),
            helper_url: helper_url.clone(),
            expiration: now + 604800, // one week from now
            time_precision: TIME_PRECISION,
            min_batch_size: MIN_BATCH_SIZE,
            query: query_config.clone(),
            vdaf: VDAF_CONFIG.clone(),
            vdaf_verify_key: VDAF_CONFIG.gen_verify_key(),
            collector_hpke_config: collector_hpke_receiver.config.clone(),
            taskprov: false,
        };

        // This block needs to be kept in-sync with daphne_worker_test/wrangler.toml.
        let global_config = DapGlobalConfig {
            report_storage_epoch_duration: 604800,
            report_storage_max_future_time_skew: 300,
            max_batch_duration: 360000,
            min_batch_interval_start: 259200,
            max_batch_interval_end: 259200,
            supported_hpke_kems: vec![HpkeKemId::X25519HkdfSha256],
            taskprov_version: Some(TaskprovVersion::Draft02),
        };
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
            task_id: task_id.clone(),
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
        };

        let vdaf_verify_key_base64url = encode_base64url(t.task_config.vdaf_verify_key.as_ref());

        let collector_hpke_config_base64url =
            encode_base64url(t.collector_hpke_receiver.config.get_encoded());

        let vdaf = json!({
            "type": "Prio3Sum",
            "bits": assert_matches!(
                t.task_config.vdaf,
                VdafConfig::Prio3(Prio3Config::Sum{ bits }) => format!("{bits}")
            ),
        });

        let (query_type, max_batch_size) = match t.task_config.query {
            DapQueryConfig::TimeInterval => (1, None),
            DapQueryConfig::FixedSize { max_batch_size } => (2, Some(max_batch_size)),
        };

        // Configure the endpoints.
        //
        // First, delete the data from the previous test.
        t.internal_delete_all(&t.batch_interval()).await;

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
            "task_expiration": t.task_config.expiration,
        });
        let add_task_path = format!("{}/internal/test/add_task", version.as_ref());
        let res: InternalTestCommandResult = t
            .leader_post_internal(&add_task_path, &leader_add_task_cmd)
            .await;
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
            "task_expiration": t.task_config.expiration,
        });
        let res: InternalTestCommandResult = t
            .helper_post_internal(&add_task_path, &helper_add_task_cmd)
            .await;
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
            .await;

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
            .await;

        assert_eq!(
            res.status, "success",
            "response status: {}, error {:?}",
            res.status, res.error
        );

        t
    }

    pub fn http_client(&self) -> reqwest::Client {
        reqwest::ClientBuilder::new()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap()
    }

    pub fn batch_interval(&self) -> Interval {
        let start = self.task_config.quantized_time_lower_bound(self.now);
        Interval {
            start,
            duration: self.task_config.time_precision * 2,
        }
    }

    pub fn report_interval(&self, interval: &Interval) -> Range<u64> {
        // This is a portion of the interval which is guaranteed to be a valid report time
        // provided that the interval start time is valid.
        interval.start..interval.start + self.global_config.report_storage_max_future_time_skew
    }

    pub async fn get_hpke_configs(
        &self,
        version: DapVersion,
        client: &reqwest::Client,
    ) -> [HpkeConfig; 2] {
        let raw_leader_hpke_config = self.leader_get_raw_hpke_config(client).await;
        let raw_helper_hpke_config = self.helper_get_raw_hpke_config(client).await;
        match version {
            DapVersion::Draft02 => [
                HpkeConfig::get_decoded(&raw_leader_hpke_config).unwrap(),
                HpkeConfig::get_decoded(&raw_helper_hpke_config).unwrap(),
            ],
            _ => {
                let mut leader_hpke_config_list =
                    HpkeConfigList::get_decoded(&raw_leader_hpke_config).unwrap();
                let mut helper_hpke_config_list =
                    HpkeConfigList::get_decoded(&raw_helper_hpke_config).unwrap();
                if leader_hpke_config_list.hpke_configs.len() != 1
                    || helper_hpke_config_list.hpke_configs.len() != 1
                {
                    panic!("only a length 1 HpkeConfList is currently supported by the test suite")
                }
                [
                    leader_hpke_config_list.hpke_configs.pop().unwrap(),
                    helper_hpke_config_list.hpke_configs.pop().unwrap(),
                ]
            }
        }
    }

    pub async fn leader_get_raw_hpke_config(&self, client: &reqwest::Client) -> Vec<u8> {
        get_raw_hpke_config(client, self.task_id.as_ref(), &self.leader_url, "leader").await
    }

    pub async fn helper_get_raw_hpke_config(&self, client: &reqwest::Client) -> Vec<u8> {
        get_raw_hpke_config(client, self.task_id.as_ref(), &self.helper_url, "helper").await
    }

    pub async fn leader_post_expect_ok(
        &self,
        client: &reqwest::Client,
        path: &str,
        media_type: DapMediaType,
        data: Vec<u8>,
    ) {
        let url = self.leader_url.join(path).unwrap();
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::CONTENT_TYPE,
            media_type
                .as_str_for_version(self.version)
                .unwrap()
                .parse()
                .unwrap(),
        );
        let resp = client
            .post(url.as_str())
            .body(data)
            .headers(headers)
            .send()
            .await
            .expect("request failed");

        assert_eq!(
            reqwest::StatusCode::from_u16(200).unwrap(),
            resp.status(),
            "unexpected response status: {:?}",
            resp.text().await.unwrap()
        );
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn leader_post_expect_abort(
        &self,
        client: &reqwest::Client,
        dap_auth_token: Option<&str>,
        path: &str,
        media_type: DapMediaType,
        data: Vec<u8>,
        expected_status: u16,
        expected_err_type: &str,
    ) {
        let url = self.leader_url.join(path).unwrap();

        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::CONTENT_TYPE,
            media_type
                .as_str_for_version(self.version)
                .unwrap()
                .parse()
                .unwrap(),
        );
        if let Some(token) = dap_auth_token {
            headers.insert(
                reqwest::header::HeaderName::from_static("dap-auth-token"),
                reqwest::header::HeaderValue::from_str(token).unwrap(),
            );
        }

        let resp = client
            .post(url.as_str())
            .body(data)
            .headers(headers)
            .send()
            .await
            .expect("request failed");

        assert_eq!(
            reqwest::StatusCode::from_u16(expected_status).unwrap(),
            resp.status(),
            "unexpected response status: {:?}",
            resp.text().await.unwrap()
        );

        assert_eq!(
            resp.headers().get("Content-Type").unwrap(),
            "application/problem+json"
        );

        let problem_details: serde_json::Value = resp.json().await.unwrap();
        let got = problem_details.as_object().unwrap().get("type").unwrap();
        assert_eq!(
            got,
            &format!("urn:ietf:params:ppm:dap:error:{}", expected_err_type)
        );
    }

    /// Send a PUT request or, if draft02 is in use, a POST request.
    pub async fn leader_put_expect_ok(
        &self,
        client: &reqwest::Client,
        path: &str,
        media_type: DapMediaType,
        data: Vec<u8>,
    ) {
        // draft02 always POSTs
        if self.version == DapVersion::Draft02 {
            return self
                .leader_post_expect_ok(client, path, media_type, data)
                .await;
        }
        let url = self.leader_url.join(path).unwrap();
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::CONTENT_TYPE,
            media_type
                .as_str_for_version(self.version)
                .unwrap()
                .parse()
                .unwrap(),
        );

        let resp = client
            .put(url.as_str())
            .body(data)
            .headers(headers)
            .send()
            .await
            .expect("request failed");

        assert_eq!(
            reqwest::StatusCode::from_u16(200).unwrap(),
            resp.status(),
            "unexpected response status: {:?}",
            resp.text().await.unwrap()
        );
    }

    /// Send a PUT request or, if draft02 is in use, a POST request, and expect an abort.
    #[allow(clippy::too_many_arguments)]
    pub async fn leader_put_expect_abort(
        &self,
        client: &reqwest::Client,
        dap_auth_token: Option<&str>,
        path: &str,
        media_type: DapMediaType,
        data: Vec<u8>,
        expected_status: u16,
        expected_err_type: &str,
    ) {
        // draft02 always POSTs
        if self.version == DapVersion::Draft02 {
            return self
                .leader_post_expect_abort(
                    client,
                    dap_auth_token,
                    path,
                    media_type,
                    data,
                    expected_status,
                    expected_err_type,
                )
                .await;
        }

        let url = self.leader_url.join(path).unwrap();

        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::CONTENT_TYPE,
            media_type
                .as_str_for_version(self.version)
                .unwrap()
                .parse()
                .unwrap(),
        );
        if let Some(token) = dap_auth_token {
            headers.insert(
                reqwest::header::HeaderName::from_static("dap-auth-token"),
                reqwest::header::HeaderValue::from_str(token).unwrap(),
            );
        }

        let resp = client
            .put(url.as_str())
            .body(data)
            .headers(headers)
            .send()
            .await
            .expect("request failed");

        assert_eq!(
            reqwest::StatusCode::from_u16(expected_status).unwrap(),
            resp.status(),
            "unexpected response status: {:?}",
            resp.text().await.unwrap()
        );

        assert_eq!(
            resp.headers().get("Content-Type").unwrap(),
            "application/problem+json"
        );

        let problem_details: serde_json::Value = resp.json().await.unwrap();
        let got = problem_details.as_object().unwrap().get("type").unwrap();
        assert_eq!(
            got,
            &format!("urn:ietf:params:ppm:dap:error:{}", expected_err_type)
        );
    }

    pub async fn leader_post_collect_using_token(
        &self,
        client: &reqwest::Client,
        data: Vec<u8>,
        token: &str,
    ) -> Url {
        let url_suffix = self.collect_url_suffix();
        let url = self.leader_url.join(&url_suffix).unwrap();
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::CONTENT_TYPE,
            reqwest::header::HeaderValue::from_str(
                DapMediaType::CollectReq
                    .as_str_for_version(self.version)
                    .unwrap(),
            )
            .unwrap(),
        );
        headers.insert(
            reqwest::header::HeaderName::from_static("dap-auth-token"),
            reqwest::header::HeaderValue::from_str(token).unwrap(),
        );
        let builder = if self.version == DapVersion::Draft02 {
            client.post(url.as_str())
        } else {
            client.put(url.as_str())
        };
        let resp = builder
            .body(data)
            .headers(headers)
            .send()
            .await
            .expect("request failed");

        let expected_status = if self.version == DapVersion::Draft02 {
            303
        } else {
            201
        };

        assert_eq!(
            resp.status(),
            expected_status,
            "request failed: {:?}",
            resp.text().await.unwrap()
        );
        if self.version == DapVersion::Draft02 {
            let collect_uri = resp.headers().get("Location").unwrap().to_str().unwrap();
            collect_uri.parse().unwrap()
        } else {
            url
        }
    }

    pub async fn leader_post_collect(&self, client: &reqwest::Client, data: Vec<u8>) -> Url {
        self.leader_post_collect_using_token(client, data, &self.collector_bearer_token)
            .await
    }

    pub async fn internal_process(
        &self,
        client: &reqwest::Client,
        report_sel: &DaphneWorkerReportSelector,
    ) -> DapLeaderProcessTelemetry {
        // Replace path "/v05" with "/internal/process".
        let mut url = self.leader_url.clone();
        url.set_path("internal/process");

        let resp = client
            .post(url.as_str())
            .body(serde_json::to_string(&report_sel).unwrap())
            .send()
            .await
            .expect("request failed");
        assert_eq!(
            200,
            resp.status(),
            "unexpected response status: {:?}",
            resp.text().await.unwrap()
        );
        resp.json().await.unwrap()
    }

    async fn post_internal<I: Serialize, O: for<'a> Deserialize<'a>>(
        &self,
        is_leader: bool,
        path: &str,
        data: &I,
    ) -> O {
        let client = self.http_client();
        let mut url = if is_leader {
            self.leader_url.clone()
        } else {
            self.helper_url.clone()
        };
        url.set_path(path); // Overwrites the version path (i.e., "/v05")
        let resp = client
            .post(url.clone())
            .json(data)
            .send()
            .await
            .expect("request failed");
        if resp.status() != 200 {
            panic!("request to {} failed: response: {:?}", url, resp);
        }
        resp.json().await.expect("failed to parse result")
    }

    pub async fn leader_post_internal<I: Serialize, O: for<'a> Deserialize<'a>>(
        &self,
        path: &str,
        data: &I,
    ) -> O {
        self.post_internal(true /* is_leader */, path, data).await
    }

    pub async fn helper_post_internal<I: Serialize, O: for<'a> Deserialize<'a>>(
        &self,
        path: &str,
        data: &I,
    ) -> O {
        self.post_internal(false /* is_leader */, path, data).await
    }

    pub async fn internal_delete_all(&self, batch_interval: &Interval) {
        let client = self.http_client();
        post_internal_delete_all(&client, &self.leader_url, batch_interval).await;
        post_internal_delete_all(&client, &self.helper_url, batch_interval).await;
    }

    pub async fn internal_current_batch(&self, task_id: &TaskId) -> BatchId {
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
            .expect("request failed");
        if resp.status() == 200 {
            let batch_id_base64url = resp.text().await.unwrap();
            BatchId::try_from_base64url(batch_id_base64url)
                .expect("Failed to parse URL-safe base64 batch ID")
        } else {
            panic!("request to {} failed: response: {:?}", url, resp);
        }
    }

    pub fn upload_path_for_task(&self, id: &TaskId) -> String {
        match self.version {
            DapVersion::Draft02 => "upload".to_string(),
            DapVersion::Draft05 => format!("tasks/{}/reports", id.to_base64url()),
            _ => unreachable!("unknown version"),
        }
    }

    pub fn upload_path(&self) -> String {
        self.upload_path_for_task(&self.task_id)
    }

    pub fn collect_url_suffix(&self) -> String {
        if self.version == DapVersion::Draft02 {
            "collect".to_string()
        } else {
            let mut rng = thread_rng();
            let collect_job_id = CollectionJobId(rng.gen());
            format!(
                "tasks/{}/collection_jobs/{}",
                self.task_id.to_base64url(),
                collect_job_id.to_base64url()
            )
        }
    }

    pub async fn poll_collection_url(
        &self,
        client: &reqwest::Client,
        url: &Url,
    ) -> reqwest::Response {
        let builder = if self.version == DapVersion::Draft02 {
            client.get(url.as_str())
        } else {
            client.post(url.as_str())
        };
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::CONTENT_TYPE,
            reqwest::header::HeaderValue::from_str(
                DapMediaType::CollectReq
                    .as_str_for_version(self.version)
                    .unwrap(),
            )
            .unwrap(),
        );
        builder.headers(headers).send().await.unwrap()
    }

    pub fn collect_task_id_field(&self) -> Option<TaskId> {
        if self.version == DapVersion::Draft02 {
            Some(self.task_id.clone())
        } else {
            None
        }
    }
}

async fn get_raw_hpke_config(
    client: &reqwest::Client,
    task_id: &[u8],
    base_url: &Url,
    svc: &str,
) -> Vec<u8> {
    let time_to_wait = std::time::Duration::from_secs(15);
    let max_time_to_wait = std::time::Duration::from_secs(60 * 3);
    let mut elapsed_time = std::time::Duration::default();
    let url = base_url.join("hpke_config").unwrap();
    let query = [("task_id", encode_base64url(task_id))];
    while elapsed_time < max_time_to_wait {
        let req = client.get(url.as_str()).query(&query);
        match req.send().await {
            Ok(resp) => {
                if resp.status() == 200 {
                    println!("{} is up.", svc);
                    return resp.bytes().await.unwrap().to_vec();
                } else {
                    panic!("request to {} failed: response: {:?}", url, resp);
                }
            }
            Err(e) => {
                println!(
                    "[{:?}/{:?}] waiting {:?} for {} to be up: error: {:?}",
                    elapsed_time, max_time_to_wait, time_to_wait, svc, e
                );
                elapsed_time += time_to_wait;
                std::thread::sleep(time_to_wait);
            }
        };
    }
    println!(
        "error: timeout after {:?} waiting for {}",
        elapsed_time, svc
    );
    panic!("{} at {} is down.", svc, url)
}

async fn post_internal_delete_all(
    client: &reqwest::Client,
    base_url: &Url,
    batch_interval: &Interval,
) {
    // Replace path "/v05" with "/internal/delete_all".
    let mut url = base_url.clone();
    url.set_path("internal/delete_all");

    let req = client
        .post(url.as_str())
        .body(serde_json::to_string(batch_interval).unwrap());
    let resp = req.send().await.expect("request failed");
    assert_eq!(
        200,
        resp.status(),
        "unexpected response status: {:?}",
        resp.text().await.unwrap()
    );
}
