// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// TODO Figure out why cargo thinks there is dead code here.

use assert_matches::assert_matches;
use daphne::{
    constants::MEDIA_TYPE_COLLECT_REQ,
    messages::{HpkeConfig, Id, Interval},
    DapGlobalConfig, DapLeaderProcessTelemetry, DapTaskConfig, DapVersion, VdafConfig,
};
use daphne_worker::InternalAggregateInfo;
use futures::channel::oneshot::Sender;
use prio::codec::{Decode, Encode};
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::SystemTime,
};
use tokio::task::JoinHandle;
use url::Url;

const JANUS_HELPER_PORT: u16 = 9788;

const DEFAULT_TASK: &str = "f285be3caf948fcfc36b7d32181c14db95c55f04f55a2db2ee439c5879264e1f";

const JANUS_HELPER_TASK: &str = "410d5e0abd94a88b8435a192cc458cc1667da2989827584cbf8a591626d5a61f";

pub const GLOBAL_CONFIG: &str = r#"{
    "max_batch_duration": 360000,
    "min_batch_interval_start": 259200,
    "max_batch_interval_end": 259200,
    "supported_hpke_kems": ["X25519HkdfSha256"]
}"#;

// This value of this JSON string must match DAP_TASK_LIST in tests/backend/leader.env.
//
// TODO De-duplicate this config.
//
// NOTE(nakatsuka-y) The leader_url and helper_url must end with a "/".
// When adding paths, they must not start with a "/".
const LEADER_TASK_LIST: &str = r#"{
    "f285be3caf948fcfc36b7d32181c14db95c55f04f55a2db2ee439c5879264e1f": {
        "version": "v01",
        "leader_url": "http://leader:8787/v01/",
        "helper_url": "http://helper:8788/v01/",
        "collector_hpke_config": {
            "id": 23,
            "kem_id": "X25519HkdfSha256",
            "kdf_id": "HkdfSha256",
            "aead_id": "Aes128Gcm",
            "public_key":"ec6427a49c8e9245307cc757dbdcf5d287c7a74075141af9fa566c293a52ee7c"
        },
        "min_batch_duration": 3600,
        "min_batch_size": 10,
        "vdaf": {
            "prio3": {
                "sum": {
                    "bits": 10
                }
            }
        },
        "vdaf_verify_key": "1fd8d30dc0e0b7ac81f0050fcab0782d"
    },
    "410d5e0abd94a88b8435a192cc458cc1667da2989827584cbf8a591626d5a61f": {
        "version": "v01",
        "leader_url": "http://leader:8787/v01/",
        "helper_url": "http://127.0.0.1:9788/",
        "collector_hpke_config": {
            "id": 23,
            "kem_id": "X25519HkdfSha256",
            "kdf_id": "HkdfSha256",
            "aead_id": "Aes128Gcm",
            "public_key":"ec6427a49c8e9245307cc757dbdcf5d287c7a74075141af9fa566c293a52ee7c"
        },
        "min_batch_duration": 3600,
        "min_batch_size": 10,
        "vdaf": {
            "prio3": {
                "sum": {
                    "bits": 10
                }
            }
        },
        "vdaf_verify_key": "01d6232e33fe7e63b4531e3706efa8cc"
    }
}"#;

// This value of this JSON string must match DAP_TASK_LIST in tests/backend/helper.env.
//
// TODO De-duplicate this config.
//
// NOTE(nakatsuka-y) The leader_url and helper_url must end with a "/".
// When adding paths, they must not start with a "/".
const HELPER_TASK_LIST: &str = r#"{
    "f285be3caf948fcfc36b7d32181c14db95c55f04f55a2db2ee439c5879264e1f": {
        "version": "v01",
        "leader_url": "http://leader:8787/v01/",
        "helper_url": "http://helper:8788/v01/",
        "collector_hpke_config": {
            "id": 23,
            "kem_id": "X25519HkdfSha256",
            "kdf_id": "HkdfSha256",
            "aead_id": "Aes128Gcm",
            "public_key":"ec6427a49c8e9245307cc757dbdcf5d287c7a74075141af9fa566c293a52ee7c"
        },
        "min_batch_duration": 3600,
        "min_batch_size": 10,
        "vdaf": {
            "prio3": {
                "sum": {
                    "bits": 10
                }
            }
        },
        "vdaf_verify_key": "1fd8d30dc0e0b7ac81f0050fcab0782d"
    }
}"#;

pub(crate) const JANUS_HELPER_TASK_LIST: &str = r#"{
    "410d5e0abd94a88b8435a192cc458cc1667da2989827584cbf8a591626d5a61f": {
        "version": "v01",
        "leader_url": "http://leader:8787/v01/",
        "helper_url": "http://127.0.0.1:9788/",
         "collector_hpke_config": {
            "id": 23,
            "kem_id": "X25519HkdfSha256",
            "kdf_id": "HkdfSha256",
            "aead_id": "Aes128Gcm",
            "public_key":"ec6427a49c8e9245307cc757dbdcf5d287c7a74075141af9fa566c293a52ee7c"
        },
        "min_batch_duration": 3600,
        "min_batch_size": 10,
        "vdaf": {
            "prio3": {
                "sum": {
                    "bits": 10
                }
            }
        },
        "vdaf_verify_key": "01d6232e33fe7e63b4531e3706efa8cc"
    }
}"#;

const JANUS_HELPER_TASK_LEADER_BEARER_TOKEN: &str =
    "This is a differnt token 72938088f14b7ef318ef42ba72395a22";

#[allow(dead_code)]
pub(crate) const COLLECTOR_BEARER_TOKEN: &str = "this is the bearer token of the Collector";

#[allow(dead_code)]
pub(crate) const COLLECTOR_HPKE_RECEIVER_CONFIG: &str = r#" {
    "config": {
        "id": 23,
        "kem_id": "X25519HkdfSha256",
        "kdf_id": "HkdfSha256",
        "aead_id": "Aes128Gcm",
        "public_key":"ec6427a49c8e9245307cc757dbdcf5d287c7a74075141af9fa566c293a52ee7c"
    },
    "secret_key": "60890f1e438bf1f0e9ad2bd839acf1341137eee623bf7906972bf1cc80bb5d7b"
}"#;

#[allow(dead_code)]
pub struct TestRunner {
    pub version: DapVersion,
    pub task_id: Id,
    pub now: u64,
    pub min_batch_duration: u64,
    pub min_batch_size: u64,
    pub max_batch_duration: u64,
    pub min_batch_interval_start: u64,
    pub max_batch_interval_end: u64,
    pub vdaf: VdafConfig,
    pub leader_url: Url,
    pub helper_url: Url,
}

#[allow(dead_code)]
impl TestRunner {
    pub async fn default() -> Self {
        let t = Self::with(
            GLOBAL_CONFIG,
            DEFAULT_TASK,
            LEADER_TASK_LIST,
            HELPER_TASK_LIST,
        )
        .await;
        t.internal_delete_all(&t.batch_interval()).await;
        t
    }

    async fn with(
        global_config_obj: &str,
        task_id_hex: &str,
        leader_task_list_obj: &str,
        helper_task_list_obj: &str,
    ) -> Self {
        let global_config: DapGlobalConfig = serde_json::from_str(global_config_obj).unwrap();

        let task_id = Id::get_decoded(&hex::decode(task_id_hex).unwrap()).unwrap();

        let leader_task_list: HashMap<Id, DapTaskConfig> =
            serde_json::from_str(leader_task_list_obj).unwrap();

        let helper_task_list: HashMap<Id, DapTaskConfig> =
            serde_json::from_str(helper_task_list_obj).unwrap();

        let task_config = leader_task_list.get(&task_id).unwrap();

        // When running in a local development environment, override the hostname of each
        // aggregator URL with 127.0.0.1.
        let mut leader_url = task_config.leader_url.clone();
        let mut helper_url = task_config.helper_url.clone();
        if let Ok(env) = std::env::var("DAP_DEPLOYMENT") {
            if env == "dev" {
                leader_url.set_host(Some("127.0.0.1")).unwrap();
                helper_url.set_host(Some("127.0.0.1")).unwrap();
            } else {
                panic!("unrecognized value for DAP_DEPLOYMENT: '{}'", env);
            }
        };

        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let t = Self {
            version: task_config.version.clone(),
            task_id: task_id.clone(),
            now,
            min_batch_duration: task_config.min_batch_duration,
            min_batch_size: task_config.min_batch_size,
            max_batch_duration: global_config.max_batch_duration,
            min_batch_interval_start: global_config.min_batch_interval_start,
            max_batch_interval_end: global_config.max_batch_interval_end,
            vdaf: task_config.vdaf.clone(),
            leader_url,
            helper_url,
        };

        // Ensure the helper has a matching task config.
        if let Some(helper_task_config) = helper_task_list.get(&task_id) {
            assert_eq!(
                helper_task_config.min_batch_duration,
                task_config.min_batch_duration
            );
            assert_eq!(
                helper_task_config.min_batch_size,
                task_config.min_batch_size
            );
            assert_eq!(helper_task_config.vdaf, task_config.vdaf);
        } else {
            panic!("Helper does not have as matching task configuration");
        }

        // Ensure that the VDAF for this test case is Prio3Aes128Sum.
        assert_matches!(task_config.vdaf, daphne::VdafConfig::Prio3(ref prio3_config) => {
            assert_matches!(prio3_config, daphne::Prio3Config::Sum{..})});

        t
    }

    pub fn http_client(&self) -> reqwest::Client {
        reqwest::ClientBuilder::new()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap()
    }

    pub fn batch_interval(&self) -> Interval {
        let start = self.now - (self.now % self.min_batch_duration);
        Interval {
            start,
            duration: self.min_batch_duration * 2,
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
            reqwest::header::HeaderValue::from_static(COLLECTOR_BEARER_TOKEN),
        );
        let resp = client
            .post(url.as_str())
            .body(data)
            .headers(headers)
            .send()
            .await
            .expect("request failed");

        assert_eq!(resp.status(), 303);
        let collect_uri = resp.headers().get("Location").unwrap().to_str().unwrap();
        collect_uri.parse().unwrap()
    }

    #[allow(dead_code)]
    pub async fn internal_process(
        &self,
        client: &reqwest::Client,
        agg_info: &InternalAggregateInfo,
    ) -> DapLeaderProcessTelemetry {
        // Replace path "/v01" with "/internal/process".
        let mut url = self.leader_url.clone();
        url.set_path("internal/process");

        let resp = client
            .post(url.as_str())
            .body(serde_json::to_string(&agg_info).unwrap())
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

    #[allow(dead_code)]
    pub async fn internal_delete_all(&self, batch_interval: &Interval) {
        let client = self.http_client();
        post_internal_delete_all(&client, &self.leader_url, batch_interval).await;
        post_internal_delete_all(&client, &self.helper_url, batch_interval).await;
    }
}

pub struct JanusServerHandle {
    shutdown_sender: Sender<()>,
    server_handle: JoinHandle<()>,

    // Once `db_handle` goes out of scope, the ephemeral postgres DB is torn down.
    #[allow(dead_code)]
    db_handle: janus_server::datastore::test_util::DbHandle,
}

#[allow(dead_code)]
impl JanusServerHandle {
    pub async fn shutdown(self) {
        self.shutdown_sender.send(()).unwrap();
        self.server_handle.await.unwrap();
    }
}

#[allow(dead_code)]
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
        let vdaf = assert_matches!(t.vdaf, daphne::VdafConfig::Prio3(ref prio3_config) => {
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
            t.min_batch_size,
            janus_core::message::Duration::from_seconds(t.min_batch_duration),
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
    // Replace path "/v01" with "/internal/delete_all".
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
