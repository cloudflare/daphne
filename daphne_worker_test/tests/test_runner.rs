// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// TODO Figure out why cargo thinks there is dead code here.

use assert_matches::assert_matches;
use daphne::{
    constants::MEDIA_TYPE_COLLECT_REQ,
    hpke::HpkeReceiverConfig,
    messages::{Duration, HpkeAeadId, HpkeConfig, HpkeKdfId, HpkeKemId, Id, Interval},
    taskprov::TaskprovVersion,
    DapGlobalConfig, DapLeaderProcessTelemetry, DapQueryConfig, DapTaskConfig, DapVersion,
    Prio3Config, VdafConfig,
};
use daphne_worker::DaphneWorkerReportSelector;
#[cfg(feature = "test_janus")]
use futures::channel::oneshot::Sender;
use prio::codec::{Decode, Encode};
use rand::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::time::SystemTime;
#[cfg(feature = "test_janus")]
use tokio::task::JoinHandle;
use url::Url;

const VDAF_CONFIG: &VdafConfig = &VdafConfig::Prio3(Prio3Config::Sum { bits: 10 });
pub(crate) const MIN_BATCH_SIZE: u64 = 10;
pub(crate) const MAX_BATCH_SIZE: u64 = 12;
pub(crate) const TIME_PRECISION: Duration = 3600; // seconds

#[derive(Deserialize)]
struct InternalTestAddTaskResult {
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[allow(dead_code)]
pub struct TestRunner {
    pub global_config: DapGlobalConfig,
    pub task_id: Id,
    pub task_config: DapTaskConfig,
    pub now: u64,
    pub leader_url: Url,
    pub helper_url: Url,
    pub leader_bearer_token: String,
    pub collector_bearer_token: String,
    pub collector_hpke_receiver: HpkeReceiverConfig,
    pub taskprov_vdaf_verify_key_init: Vec<u8>,
    pub taskprov_collector_hpke_receiver: HpkeReceiverConfig,
    pub version: DapVersion,
}

#[allow(dead_code)]
impl TestRunner {
    pub async fn default_with_version(version: DapVersion) -> Self {
        let t = Self::with(version, &DapQueryConfig::TimeInterval).await;
        t
    }

    pub async fn default() -> Self {
        Self::default_with_version(DapVersion::Draft02).await
    }

    pub async fn fixed_size(version: DapVersion) -> Self {
        let t = Self::with(
            version,
            &DapQueryConfig::FixedSize {
                max_batch_size: MAX_BATCH_SIZE,
            },
        )
        .await;
        t
    }

    async fn with(version: DapVersion, query_config: &DapQueryConfig) -> Self {
        let mut rng = thread_rng();
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let task_id = Id(rng.gen());

        // When running in a local development environment, override the hostname of each
        // aggregator URL with 127.0.0.1.
        let version_path = match version {
            DapVersion::Draft02 => "v02",
            DapVersion::Draft03 => "v03",
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
            HpkeReceiverConfig::gen(rng.gen(), HpkeKemId::X25519HkdfSha256);

        let task_config = DapTaskConfig {
            version: version,
            leader_url: leader_url.clone(),
            helper_url: helper_url.clone(),
            expiration: now + 604800, // one week from now
            time_precision: TIME_PRECISION,
            min_batch_size: MIN_BATCH_SIZE,
            query: query_config.clone(),
            vdaf: VDAF_CONFIG.clone(),
            vdaf_verify_key: VDAF_CONFIG.gen_verify_key(),
            collector_hpke_config: collector_hpke_receiver.config.clone(),
        };

        // This block needs to be kept in-sync with daphne_worker_test/wrangler.toml.
        let global_config = DapGlobalConfig {
            report_storage_epoch_duration: 604800,
            max_batch_duration: 360000,
            min_batch_interval_start: 259200,
            max_batch_interval_end: 259200,
            supported_hpke_kems: vec![HpkeKemId::X25519HkdfSha256],
            allow_taskprov: true,
            taskprov_version: TaskprovVersion::Draft02,
        };
        let taskprov_vdaf_verify_key_init =
            hex::decode("0074a5dd6e9dac501f73f7a961193b2b").unwrap();
        let taskprov_collector_hpke_receiver = HpkeReceiverConfig::new(
            HpkeConfig {
                id: 23,
                kem_id: HpkeKemId::P256HkdfSha256,
                kdf_id: HpkeKdfId::HkdfSha256,
                aead_id: HpkeAeadId::Aes128Gcm,
                public_key: hex::decode("047dab625e0d269abcc28c611bebf5a60987ddf7e23df0e0aa343e5774ad81a1d0160d9252b82b4b5c52354205f5ec945645cb79facff8d85c9c31b490cdf35466").unwrap()
            },
            hex::decode("9ce9851512df3ea674b108b305c3f8c424955a94d93fd53ecf3c3f17f7d1df9e").unwrap()
        );

        let leader_bearer_token = hex::encode(&rng.gen::<[u8; 16]>());
        let collector_bearer_token = hex::encode(&rng.gen::<[u8; 16]>());
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

        let vdaf_verify_key_base64url = base64::encode_config(
            &t.task_config.vdaf_verify_key.as_ref(),
            base64::URL_SAFE_NO_PAD,
        );

        let collector_hpke_config_base64url = base64::encode_config(
            &t.collector_hpke_receiver.config.get_encoded(),
            base64::URL_SAFE_NO_PAD,
        );

        let vdaf = json!({
            "type": "Prio3Aes128Sum",
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
            "verify_key": vdaf_verify_key_base64url,
            "query_type": query_type,
            "min_batch_size": t.task_config.min_batch_size,
            "max_batch_size": max_batch_size,
            "time_precision": t.task_config.time_precision,
            "collector_hpke_config": collector_hpke_config_base64url.clone(),
            "task_expiration": t.task_config.expiration,
        });
        let add_task_path = format!("{}/internal/test/add_task", version.as_ref());
        let res: InternalTestAddTaskResult = t
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
            "verify_key": vdaf_verify_key_base64url,
            "query_type": query_type,
            "min_batch_size": t.task_config.min_batch_size,
            "max_batch_size": max_batch_size,
            "time_precision": t.task_config.time_precision,
            "collector_hpke_config": collector_hpke_config_base64url.clone(),
            "task_expiration": t.task_config.expiration,
        });
        let res: InternalTestAddTaskResult = t
            .helper_post_internal(&add_task_path, &helper_add_task_cmd)
            .await;
        assert_eq!(
            res.status, "success",
            "response status: {}, error: {:?}",
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
        let start = self.now - (self.now % self.task_config.time_precision);
        Interval {
            start,
            duration: self.task_config.time_precision * 2,
        }
    }

    pub async fn get_hpke_configs(&self, client: &reqwest::Client) -> [HpkeConfig; 2] {
        let raw_leader_hpke_config = self.leader_get_raw_hpke_config(&client).await;
        let raw_helper_hpke_config = self.helper_get_raw_hpke_config(&client).await;
        [
            HpkeConfig::get_decoded(&raw_leader_hpke_config).unwrap(),
            HpkeConfig::get_decoded(&raw_helper_hpke_config).unwrap(),
        ]
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
        media_type: &str,
        data: Vec<u8>,
    ) {
        let url = self.leader_url.join(path).unwrap();
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(reqwest::header::CONTENT_TYPE, media_type.parse().unwrap());
        let resp = client
            .post(url.as_str())
            .body(data)
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

    pub async fn leader_post_expect_abort(
        &self,
        client: &reqwest::Client,
        dap_auth_token: Option<&str>,
        path: &str,
        media_type: &str,
        data: Vec<u8>,
        expected_status: u16,
        expected_err_type: &str,
    ) {
        let url = self.leader_url.join(path).unwrap();

        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(reqwest::header::CONTENT_TYPE, media_type.parse().unwrap());
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

    pub async fn leader_post_collect_using_token(
        &self,
        client: &reqwest::Client,
        data: Vec<u8>,
        token: &String,
    ) -> Url {
        let url = self.leader_url.join("collect").unwrap();
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::CONTENT_TYPE,
            reqwest::header::HeaderValue::from_static(MEDIA_TYPE_COLLECT_REQ),
        );
        headers.insert(
            reqwest::header::HeaderName::from_static("dap-auth-token"),
            reqwest::header::HeaderValue::from_str(token).unwrap(),
        );
        let resp = client
            .post(url.as_str())
            .body(data)
            .headers(headers)
            .send()
            .await
            .expect("request failed");

        assert_eq!(
            resp.status(),
            303,
            "request failed: {:?}",
            resp.text().await.unwrap()
        );
        let collect_uri = resp.headers().get("Location").unwrap().to_str().unwrap();
        collect_uri.parse().unwrap()
    }

    pub async fn leader_post_collect(&self, client: &reqwest::Client, data: Vec<u8>) -> Url {
        self.leader_post_collect_using_token(client, data, &self.collector_bearer_token)
            .await
    }

    #[allow(dead_code)]
    pub async fn internal_process(
        &self,
        client: &reqwest::Client,
        report_sel: &DaphneWorkerReportSelector,
    ) -> DapLeaderProcessTelemetry {
        // Replace path "/v02" with "/internal/process".
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
        url.set_path(path); // Overwrites the version path (i.e., "/v02")
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

    #[allow(dead_code)]
    pub async fn leader_post_internal<I: Serialize, O: for<'a> Deserialize<'a>>(
        &self,
        path: &str,
        data: &I,
    ) -> O {
        self.post_internal(true /* is_leader */, path, data).await
    }

    #[allow(dead_code)]
    pub async fn helper_post_internal<I: Serialize, O: for<'a> Deserialize<'a>>(
        &self,
        path: &str,
        data: &I,
    ) -> O {
        self.post_internal(false /* is_leader */, path, data).await
    }

    #[allow(dead_code)]
    pub async fn internal_delete_all(&self, batch_interval: &Interval) {
        let client = self.http_client();
        post_internal_delete_all(&client, &self.leader_url, batch_interval).await;
        post_internal_delete_all(&client, &self.helper_url, batch_interval).await;
    }

    #[allow(dead_code)]
    pub async fn internal_current_batch(&self, task_id: &Id) -> Id {
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
            let batch_id = Id::get_decoded(
                &base64::decode_config(&batch_id_base64url, base64::URL_SAFE_NO_PAD)
                    .expect("Failed to parse URL-safe base64 batch ID"),
            )
            .expect("Failed to parse batch ID");
            batch_id
        } else {
            panic!("request to {} failed: response: {:?}", url, resp);
        }
    }
}

#[cfg(feature = "test_janus")]
pub struct JanusServerHandle {
    shutdown_sender: Sender<()>,
    server_handle: JoinHandle<()>,

    // Once `db_handle` goes out of scope, the ephemeral postgres DB is torn down.
    #[allow(dead_code)]
    db_handle: janus_server::datastore::test_util::DbHandle,
}

#[cfg(feature = "test_janus")]
impl JanusServerHandle {
    pub async fn shutdown(self) {
        self.shutdown_sender.send(()).unwrap();
        self.server_handle.await.unwrap();
    }
}

#[cfg(feature = "test_janus")]
impl TestRunner {
    pub async fn janus_helper() -> (Self, JanusServerHandle) {
        let t = Self::with(
            GLOBAL_CONFIG,
            JANUS_HELPER_TASK,
            LEADER_TASK_LIST,
            JANUS_HELPER_TASK_LIST,
        )
        .await;
        post_internal_delete_all(&t.http_client(), &t.leader_url, &t.batch_interval()).await;

        let task_id = janus_core::message::TaskId::get_decoded(t.task_id.as_ref()).unwrap();
        let aggregator_endpoints = vec![t.leader_url.clone(), t.helper_url.clone()];
        let vdaf = assert_matches!(t.task_config.vdaf, daphne::VdafConfig::Prio3(ref prio3_config) => {
            assert_matches!(prio3_config, daphne::Prio3Config::Sum{ bits } =>
                janus_server::task::VdafInstance::Real(janus_core::task::VdafInstance::Prio3Aes128Sum{ bits: *bits }
            ))
        });

        let task_list_object: serde_json::Value =
            serde_json::from_str(JANUS_HELPER_TASK_LIST).unwrap();
        let task_config_object = task_list_object.get(JANUS_HELPER_TASK).unwrap();

        let config: daphne::messages::HpkeConfig = serde_json::from_value(
            task_config_object
                .get("collector_hpke_config")
                .unwrap()
                .clone(),
        )
        .unwrap();
        let collector_hpke_config =
            janus_core::message::HpkeConfig::get_decoded(&config.get_encoded()).unwrap();

        let vdaf_verify_key = hex::decode(
            task_config_object
                .get("vdaf_verify_key")
                .unwrap()
                .as_str()
                .unwrap(),
        )
        .unwrap();

        let leader_bearer_token = janus_server::task::AggregatorAuthenticationToken::from(
            JANUS_HELPER_TASK_LEADER_BEARER_TOKEN.as_bytes().to_vec(),
        );

        let (hpke_config, hpke_sk) =
            janus_core::hpke::test_util::generate_hpke_config_and_private_key();

        let task = janus_server::task::Task::new(
            task_id,
            aggregator_endpoints,
            vdaf,
            janus_core::message::Role::Helper,
            vec![vdaf_verify_key],
            1, // max_batch_lifetime
            t.task_config.min_batch_size,
            janus_core::message::Duration::from_seconds(t.task_config.time_precision),
            janus_core::message::Duration::from_seconds(0), // clock skew tolerance
            collector_hpke_config,
            vec![leader_bearer_token],
            [(hpke_config, hpke_sk)],
        )
        .unwrap();

        let aggregator_clock = janus_core::time::test_util::MockClock::new(
            janus_core::message::Time::from_seconds_since_epoch(t.now),
        );
        let (datastore, db_handle) =
            janus_server::datastore::test_util::ephemeral_datastore(aggregator_clock.clone()).await;
        let datastore = Arc::new(datastore);
        datastore
            .run_tx(|tx| {
                let task = task.clone();
                Box::pin(async move { tx.put_task(&task).await })
            })
            .await
            .unwrap();

        let (shutdown_sender, shutdown_receiver) = futures::channel::oneshot::channel();
        let shutdown_receiver = async move { shutdown_receiver.await.unwrap_or_default() };
        let (_addr, server) = janus_server::aggregator::aggregator_server(
            datastore,
            aggregator_clock,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), JANUS_HELPER_PORT),
            shutdown_receiver,
        )
        .unwrap();

        (
            t,
            JanusServerHandle {
                shutdown_sender,
                server_handle: tokio::spawn(server),
                db_handle,
            },
        )
    }
}

#[allow(dead_code)]
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
    let query = [(
        "task_id",
        base64::encode_config(task_id, base64::URL_SAFE_NO_PAD),
    )];
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

#[allow(dead_code)]
async fn post_internal_delete_all(
    client: &reqwest::Client,
    base_url: &Url,
    batch_interval: &Interval,
) {
    // Replace path "/v02" with "/internal/delete_all".
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
