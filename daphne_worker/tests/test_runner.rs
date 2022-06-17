// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// TODO Figure out why cargo thinks there is dead code here.

janus_test_util::define_ephemeral_datastore!();

use assert_matches::assert_matches;
use daphne::{
    messages::{HpkeConfig, Id, Interval},
    DapLeaderProcessTelemetry, DapTaskConfig, VdafConfig,
};
use daphne_worker::InternalAggregateInfo;
use futures::channel::oneshot::Sender;
use janus_server::datastore::{Crypter, Datastore};
use prio::codec::Decode;
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
};
use tokio::task::JoinHandle;
use url::Url;

const JANUS_HELPER_PORT: u16 = 9788;

const DEFAULT_TASK: &str = "f285be3caf948fcfc36b7d32181c14db95c55f04f55a2db2ee439c5879264e1f";

const JANUS_HELPER_TASK: &str = "410d5e0abd94a88b8435a192cc458cc1667da2989827584cbf8a591626d5a61f";

// This value of this JSON string must match DAP_TASK_LIST in tests/backend/leader.env.
//
// TODO De-duplicate this config.
const LEADER_TASK_LIST: &str = r#"{
    "f285be3caf948fcfc36b7d32181c14db95c55f04f55a2db2ee439c5879264e1f": {
        "leader_url": "http://leader:8787",
        "helper_url": "http://helper:8788",
        "collector_hpke_config": "f400200001000100202ea6c9ba7ea64c3e9d09c73b057a009a80a1bf551ffca56c53fc0b8430ded350",
        "min_batch_duration": 3600,
        "min_batch_size": 10,
        "vdaf": {
            "prio3": {
                "sum": {
                    "bits": 10
                }
            }
        },
        "dap_verify_param": {
            "vdaf": "1fd8d30dc0e0b7ac81f0050fcab0782d00",
            "hmac": "4d56ee95444bd853742daa8e0570c6b9ec9d64bbb82f83847b475012e37b01e7"
        }
    },
    "410d5e0abd94a88b8435a192cc458cc1667da2989827584cbf8a591626d5a61f": {
        "leader_url": "http://leader:8787",
        "helper_url": "http://127.0.0.1:9788",
        "collector_hpke_config": "f400200001000100202ea6c9ba7ea64c3e9d09c73b057a009a80a1bf551ffca56c53fc0b8430ded350",
        "min_batch_duration": 3600,
        "min_batch_size": 10,
        "vdaf": {
            "prio3": {
                "sum": {
                    "bits": 10
                }
            }
        },
        "dap_verify_param": {
            "vdaf": "01d6232e33fe7e63b4531e3706efa8cc00",
            "hmac": "c08de02035e2ad0c1a432dfe8a35b31d42cbd39a55da6f71b888fbee47a7ffb7"
        }
    }
}"#;

// This value of this JSON string must match DAP_TASK_LIST in tests/backend/helper.env.
//
// TODO De-duplicate this config.
const HELPER_TASK_LIST: &str = r#"{
    "f285be3caf948fcfc36b7d32181c14db95c55f04f55a2db2ee439c5879264e1f": {
        "leader_url": "http://leader:8787",
        "helper_url": "http://helper:8788",
        "collector_hpke_config": "f400200001000100202ea6c9ba7ea64c3e9d09c73b057a009a80a1bf551ffca56c53fc0b8430ded350",
        "min_batch_duration": 3600,
        "min_batch_size": 10,
        "vdaf": {
            "prio3": {
                "sum": {
                    "bits": 10
                }
            }
        },
        "dap_verify_param": {
            "vdaf": "1fd8d30dc0e0b7ac81f0050fcab0782d01",
            "hmac": "4d56ee95444bd853742daa8e0570c6b9ec9d64bbb82f83847b475012e37b01e7"
        }
    }
}"#;

pub(crate) const JANUS_HELPER_TASK_LIST: &str = r#"{
    "410d5e0abd94a88b8435a192cc458cc1667da2989827584cbf8a591626d5a61f": {
        "leader_url": "http://leader:8787",
        "helper_url": "http://127.0.0.1:9788",
        "collector_hpke_config": "f400200001000100202ea6c9ba7ea64c3e9d09c73b057a009a80a1bf551ffca56c53fc0b8430ded350",
        "min_batch_duration": 3600,
        "min_batch_size": 10,
        "vdaf": {
            "prio3": {
                "sum": {
                    "bits": 10
                }
            }
        },
        "dap_verify_param": {
            "vdaf": "01d6232e33fe7e63b4531e3706efa8cc01",
            "hmac": "c08de02035e2ad0c1a432dfe8a35b31d42cbd39a55da6f71b888fbee47a7ffb7"
        }
    }
}"#;

#[allow(dead_code)]
pub(crate) const COLLECTOR_HPKE_SECRET_KEY: &str = r#"{
    "id": 244,
    "sk": "68db815a534d3f92a6224c4cbbc2dd301be48ef32f112dbfb3709a4cbfe5f372"
}"#;

#[allow(dead_code)]
pub struct TestRunner {
    pub task_id: Id,
    pub now: u64,
    pub min_batch_duration: u64,
    pub min_batch_size: u64,
    pub vdaf: VdafConfig,
    pub leader_url: Url,
    pub helper_url: Url,
}

#[allow(dead_code)]
impl TestRunner {
    pub async fn default() -> Self {
        let t = Self::with(DEFAULT_TASK, LEADER_TASK_LIST, HELPER_TASK_LIST).await;
        t.internal_reset(&t.batch_info()).await;
        t
    }

    async fn with(
        task_id_hex: &str,
        leader_task_list_obj: &str,
        helper_task_list_obj: &str,
    ) -> Self {
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
        if let Ok(env) = std::env::var("DAP_ENV") {
            if env == "dev" {
                println!("DAP_ENV: Hostname override applied");
                leader_url.set_host(Some("127.0.0.1")).unwrap();
                helper_url.set_host(Some("127.0.0.1")).unwrap();
            }
        };

        let t = Self {
            task_id: task_id.clone(),
            now: 1637359200, // Fri 19 Nov 2021 02:00:00 PM PST
            min_batch_duration: task_config.min_batch_duration,
            min_batch_size: task_config.min_batch_size,
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

    pub fn batch_info(&self) -> Option<Interval> {
        let start = self.now - (self.now % self.min_batch_duration);
        Some(Interval {
            start,
            duration: self.min_batch_duration * 2,
        })
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
        path: &str,
        media_type: &str,
        data: Vec<u8>,
        expected_status: u16,
        expected_err_type: &str,
    ) {
        let url = self.leader_url.join(path).unwrap();
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(reqwest::header::CONTENT_TYPE, media_type.parse().unwrap());
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
        assert_eq!(got, expected_err_type);
    }

    #[allow(dead_code)]
    pub async fn internal_process(
        &self,
        client: &reqwest::Client,
        agg_info: &InternalAggregateInfo,
    ) -> DapLeaderProcessTelemetry {
        let url = self
            .leader_url
            .join(&format!(
                "/internal/process/task/{}",
                self.task_id.to_base64url()
            ))
            .unwrap();

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
    pub async fn internal_reset(&self, batch_info: &Option<Interval>) {
        let client = self.http_client();
        post_internal_test_reset(&client, &self.leader_url, &self.task_id, batch_info).await;
        post_internal_test_reset(&client, &self.helper_url, &self.task_id, batch_info).await;
    }
}

pub struct JanusServerHandle {
    shutdown_sender: Sender<()>,
    server_handle: JoinHandle<()>,

    // Once `db_handle` goes out of scope, the ephemeral postgres DB is torn down.
    #[allow(dead_code)]
    db_handle: DbHandle,
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
        let t = Self::with(JANUS_HELPER_TASK, LEADER_TASK_LIST, JANUS_HELPER_TASK_LIST).await;
        post_internal_test_reset(&t.http_client(), &t.leader_url, &t.task_id, &t.batch_info())
            .await;

        // TODO Use the same version of prio for Janus and daphne. (Janus currently points to
        // an unreleased version.)
        let task_id =
            <janus::message::TaskId as janus_prio::codec::Decode>::get_decoded(t.task_id.as_ref())
                .unwrap();
        let aggregator_endpoints = vec![t.leader_url.clone(), t.helper_url.clone()];
        let vdaf = assert_matches!(t.vdaf, daphne::VdafConfig::Prio3(ref prio3_config) => {
            assert_matches!(prio3_config, daphne::Prio3Config::Sum{ bits } =>
                janus_server::task::VdafInstance::Prio3Aes128Sum{ bits: *bits }
            )
        });

        let task_list_object: serde_json::Value =
            serde_json::from_str(JANUS_HELPER_TASK_LIST).unwrap();
        let task_config_object = task_list_object.get(JANUS_HELPER_TASK).unwrap();
        let dap_pverify_param_object = task_config_object.get("dap_verify_param").unwrap();

        // TODO Use the same version of prio for Janus and daphne. (Janus currently points to
        // an unreleased version.)
        let collector_hpke_config =
            <janus::message::HpkeConfig as janus_prio::codec::Decode>::get_decoded(
                &hex::decode(
                    task_config_object
                        .get("collector_hpke_config")
                        .unwrap()
                        .as_str()
                        .unwrap(),
                )
                .unwrap(),
            )
            .unwrap();

        let vdaf_verify_param = hex::decode(
            dap_pverify_param_object
                .get("vdaf")
                .unwrap()
                .as_str()
                .unwrap(),
        )
        .unwrap();

        let agg_auth_key = janus_server::task::AggregatorAuthKey::new(
            &hex::decode(
                dap_pverify_param_object
                    .get("hmac")
                    .unwrap()
                    .as_str()
                    .unwrap(),
            )
            .unwrap(),
        )
        .unwrap();

        let (hpke_config, hpke_sk) = janus::hpke::test_util::generate_hpke_config_and_private_key();

        let task = janus_server::task::Task::new(
            task_id,
            aggregator_endpoints,
            vdaf,
            janus::message::Role::Helper,
            vec![vdaf_verify_param],
            1, // max_batch_lifetime
            t.min_batch_size,
            janus::message::Duration::from_seconds(t.min_batch_duration),
            janus::message::Duration::from_seconds(0), // clock skew tolerance
            collector_hpke_config,
            vec![agg_auth_key],
            [(hpke_config, hpke_sk)],
        )
        .unwrap();

        let (datastore, db_handle) = ephemeral_datastore().await;
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
            janus::time::RealClock::default(),
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
    let url = base_url.join("/hpke_config").unwrap();
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
async fn post_internal_test_reset(
    client: &reqwest::Client,
    base_url: &Url,
    task_id: &Id,
    batch_info: &Option<Interval>,
) {
    let url = base_url
        .join(&format!(
            "/internal/test/reset/task/{}",
            task_id.to_base64url()
        ))
        .unwrap();

    let req = client
        .post(url.as_str())
        .body(serde_json::to_string(batch_info).unwrap());
    let resp = req.send().await.expect("request failed");
    assert_eq!(
        200,
        resp.status(),
        "unexpected response status: {:?}",
        resp.text().await.unwrap()
    );
}
