// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// TODO Figure out why cargo thinks there is dead code here.

use daphne::{
    constants::MEDIA_TYPE_COLLECT_REQ,
    hpke::HpkeReceiverConfig,
    messages::{Duration, HpkeConfig, HpkeKemId, Id, Interval},
    DapGlobalConfig, DapLeaderProcessTelemetry, DapQueryConfig, DapTaskConfig, DapVersion,
    Prio3Config, VdafConfig,
};
use daphne_worker::DaphneWorkerReportSelector;
#[cfg(feature = "test_janus")]
use futures::channel::oneshot::Sender;
use prio::codec::Decode;
use rand::prelude::*;
use serde::Serialize;
use serde_json::json;
use std::time::SystemTime;
#[cfg(feature = "test_janus")]
use tokio::task::JoinHandle;
use url::Url;

const VDAF_CONFIG: &VdafConfig = &VdafConfig::Prio3(Prio3Config::Sum { bits: 10 });
const MIN_BATCH_SIZE: u64 = 10;
const MAX_BATCH_SIZE: u64 = 12;
const TIME_PRECISION: Duration = 3600; // seconds

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
}

#[allow(dead_code)]
impl TestRunner {
    pub async fn default() -> Self {
        let t = Self::with(&DapQueryConfig::TimeInterval).await;
        t
    }

    pub async fn fixed_size() -> Self {
        let t = Self::with(&DapQueryConfig::FixedSize {
            max_batch_size: MAX_BATCH_SIZE,
        })
        .await;
        t
    }

    async fn with(query_config: &DapQueryConfig) -> Self {
        let mut rng = thread_rng();
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let task_id = Id(rng.gen());

        // When running in a local development environment, override the hostname of each
        // aggregator URL with 127.0.0.1.
        let mut leader_url = Url::parse("http://127.0.0.1:8787/v02/").unwrap();
        let mut helper_url = Url::parse("http://127.0.0.1:8788/v02/").unwrap();
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
            version: DapVersion::Draft02,
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

        // This needs to be kept in-sync with daphne_worker_test/wrangler.toml.
        let global_config = DapGlobalConfig {
            report_storage_epoch_duration: 604800,
            max_batch_duration: 360000,
            min_batch_interval_start: 259200,
            max_batch_interval_end: 259200,
            supported_hpke_kems: vec![HpkeKemId::X25519HkdfSha256],
        };

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
        };

        let vdaf_verify_key_base64url = base64::encode_config(
            &t.task_config.vdaf_verify_key.as_ref(),
            base64::URL_SAFE_NO_PAD,
        );

        let add_task_cmd = json!({
            "task_id": t.task_id.to_base64url(),
            "leader_url": t.leader_url,
            "helper_url": t.helper_url,
            "time_precision": t.task_config.time_precision,
            "expiration": t.task_config.expiration,
            "min_batch_size": t.task_config.min_batch_size,
            "query": t.task_config.query,
            "vdaf": t.task_config.vdaf,
            "vdaf_verify_key": vdaf_verify_key_base64url,
            "collector_hpke_config": t.task_config.collector_hpke_config,
        });

        // Configure the endpoints.
        //
        // First, delete the data from the previous test.
        t.internal_delete_all(&t.batch_interval()).await;

        // Configure the Leader with the task.
        t.leader_post_internal("/internal/test/add_task", &add_task_cmd)
            .await;

        // Configure the Helper with the task.
        t.helper_post_internal("/internal/test/add_task", &add_task_cmd)
            .await;

        // Configure the Leader with the Collector's bearer token.
        t.leader_post_internal(
            "/internal/test/add_authentication_token",
            &json!({
                "role": "collector",
                "task_id": t.task_id.to_base64url(),
                "token": t.collector_bearer_token.clone()
            }),
        )
        .await;

        // Configure the Leader with the Leader's bearer token.
        t.leader_post_internal(
            "/internal/test/add_authentication_token",
            &json!({
                "role": "leader",
                "task_id": t.task_id.to_base64url(),
                "token": t.leader_bearer_token.clone()
            }),
        )
        .await;

        // Configure the Helper with the Leader's bearer token.
        t.helper_post_internal(
            "/internal/test/add_authentication_token",
            &json!({
                "role": "leader",
                "task_id": t.task_id.to_base64url(),
                "token": t.leader_bearer_token.clone()
            }),
        )
        .await;

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

    pub async fn leader_post_collect(&self, client: &reqwest::Client, data: Vec<u8>) -> Url {
        let url = self.leader_url.join("collect").unwrap();
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::CONTENT_TYPE,
            reqwest::header::HeaderValue::from_static(MEDIA_TYPE_COLLECT_REQ),
        );
        headers.insert(
            reqwest::header::HeaderName::from_static("dap-auth-token"),
            reqwest::header::HeaderValue::from_str(&self.collector_bearer_token).unwrap(),
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

    async fn post_internal<I: Serialize>(&self, is_leader: bool, path: &str, data: &I) {
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
    }

    #[allow(dead_code)]
    pub async fn leader_post_internal<I: Serialize>(&self, path: &str, data: &I) {
        self.post_internal(true /* is_leader */, path, data).await
    }

    #[allow(dead_code)]
    pub async fn helper_post_internal<I: Serialize>(&self, path: &str, data: &I) {
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
