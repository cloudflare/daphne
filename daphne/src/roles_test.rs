// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use crate::{
    auth::{BearerToken, BearerTokenProvider},
    constants::{MEDIA_TYPE_AGG_INIT_REQ, MEDIA_TYPE_AGG_SHARE_REQ, MEDIA_TYPE_COLLECT_REQ},
    hpke::{HpkeDecrypter, HpkeSecretKey},
    messages::{
        AggregateInitializeReq, AggregateShareReq, AggregateResp, CollectReq, CollectResp, HpkeCiphertext,
        HpkeConfig, Id, Interval, Nonce, Report, ReportShare, TransitionVar, TransitionFailure,
    },
    roles::{DapAggregator, DapAuthorizedSender, DapHelper, DapLeader},
    DapAbort, DapAggregateShare, DapCollectJob, DapError, DapHelperState, DapOutputShare,
    DapRequest, DapResponse, DapTaskConfig,
};
use assert_matches::assert_matches;
use async_trait::async_trait;
use prio::codec::{Encode, Decode};
use rand::prelude::*;
use std::{collections::HashMap, vec};
use url::Url;

const TASK_LIST: &str = r#"{
    "f285be3caf948fcfc36b7d32181c14db95c55f04f55a2db2ee439c5879264e1f": {
        "leader_url": "https://leader.biz/leadver/v1/",
        "helper_url": "http://helper.com:8788",
        "collector_hpke_config": "f40020000100010020a761d90c8c76d3d76349a3794a439a1572ab1fb8f13531d69744c92ea7757d7f",
        "min_batch_duration": 3600,
        "min_batch_size": 100,
        "vdaf": {
            "prio3": {
                "histogram": {
                    "buckets": [77, 999]
                }
            }
        },
        "vdaf_verify_key": "1fd8d30dc0e0b7ac81f0050fcab0782d"
    }
}"#;

const HPKE_CONFIG_LIST: &str = r#"[
    "1700200001000100205dc71373c6aa7b0af67944a370ab96d8b8216832579c19159ca35d10f25a2765"
]"#;

const HPKE_SECRET_KEY_LIST: &str = r#"[
    {
        "id": 23,
        "sk": "888e94344585f44530d03e250268be6c6a5caca5314513dcec488cc431486c69"
    }
]"#;

const LEADER_BEARER_TOKEN: &str = "ivA1e7LpnySDNn1AulaZggFLQ1n7jZ8GWOUO7GY4hgs=";
const COLLECTOR_BEARER_TOKEN: &str = "syfRfvcvNFF5MJk4Y-B7xjRIqD_iNzhaaEB9mYqO9hk=";

struct MockAggregator {
    tasks: HashMap<Id, DapTaskConfig>,
    hpke_config_list: Vec<HpkeConfig>,
    hpke_secret_key_list: Vec<HpkeSecretKey>,
}

impl MockAggregator {
    fn new() -> Self {
        // Task list
        let tasks = serde_json::from_str(TASK_LIST).expect("failed to parse task list");

        // Hpke config List
        let hpke_config_list_hex: Vec<String> = serde_json::from_str(HPKE_CONFIG_LIST).expect("failed to parse HPKE config list");
        let mut hpke_config_list: Vec<HpkeConfig> = Vec::with_capacity(hpke_config_list_hex.len());
        for hex in hpke_config_list_hex {
            let bytes: Vec<u8> = hex::decode(hex).unwrap();
            let hpke_config = HpkeConfig::get_decoded(&bytes).unwrap();
            hpke_config_list.push(hpke_config);
        }

        // Hpke secret key list
        let hpke_secret_key_list: Vec<HpkeSecretKey> = serde_json::from_str(HPKE_SECRET_KEY_LIST).expect("Failed to parse HPKE secret key list");

        Self {
            tasks,
            hpke_config_list, hpke_secret_key_list
        }
    }

    fn get_hpke_secret_key_for(&self, hpke_config_id: u8) -> Option<&HpkeSecretKey> {
        for hpke_secret_key in self.hpke_secret_key_list.iter() {
            if hpke_config_id == hpke_secret_key.id {
                return Some(hpke_secret_key);
            }
        }
        None
    }

    /// Task to use for nominal tests.
    fn nominal_task_id(&self) -> &Id {
        // Just use the first key in the hash map.
        self.tasks.keys().next().as_ref().unwrap()
    }
}

#[async_trait(?Send)]
impl BearerTokenProvider for MockAggregator {
    async fn get_leader_bearer_token_for(
        &self,
        _task_id: &Id,
    ) -> Result<Option<BearerToken>, DapError> {
        Ok(Some(BearerToken::from(LEADER_BEARER_TOKEN.to_string())))
    }

    async fn get_collector_bearer_token_for(
        &self,
        _task_id: &Id,
    ) -> Result<Option<BearerToken>, DapError> {
        Ok(Some(BearerToken::from(COLLECTOR_BEARER_TOKEN.to_string())))
    }
}

impl HpkeDecrypter for MockAggregator {
    fn get_hpke_config_for(&self, _task_id: &Id) -> Option<&HpkeConfig> {
        if self.hpke_config_list.is_empty() {
            return None;
        }

        // Advertise the first HPKE config in the list.
        Some(&self.hpke_config_list[0])
    }

    fn can_hpke_decrypt(&self, _task_id: &Id, config_id: u8) -> bool {
        self.get_hpke_secret_key_for(config_id).is_some()
    }

    fn hpke_decrypt(
        &self,
        _task_id: &Id,
        info: &[u8],
        aad: &[u8],
        ciphertext: &HpkeCiphertext,
    ) -> Result<Vec<u8>, DapError> {
        if let Some(hpke_secret_key) = self.get_hpke_secret_key_for(ciphertext.config_id) {
            match hpke_secret_key.decrypt(info, aad, &ciphertext.enc, &ciphertext.payload) {
                Ok(plaintext) => Ok(plaintext),
                Err(_) => Err(DapError::Transition(TransitionFailure::HpkeDecryptError))
            }
        } else {
            Err(DapError::Transition(TransitionFailure::HpkeUnknownConfigId))
        }
    }
}

#[async_trait(?Send)]
impl DapAuthorizedSender<BearerToken> for MockAggregator {
    async fn authorize(
        &self,
        task_id: &Id,
        media_type: &'static str,
        _payload: &[u8],
    ) -> Result<BearerToken, DapError> {
        self.authorize_with_bearer_token(task_id, media_type).await
    }
}

#[async_trait(?Send)]
impl DapAggregator<BearerToken> for MockAggregator {
    async fn authorized(&self, req: &DapRequest<BearerToken>) -> Result<bool, DapError> {
        self.bearer_token_authorized(req).await
    }

    fn get_task_config_for(&self, task_id: &Id) -> Option<&DapTaskConfig> {
        self.tasks.get(task_id)
    }

    async fn put_out_shares(
        &self,
        _task_id: &Id,
        _out_shares: Vec<DapOutputShare>,
    ) -> Result<(), DapError> {
        unreachable!("not implemented");
    }

    async fn get_agg_share(
        &self,
        _task_id: &Id,
        _batch_interval: &Interval,
    ) -> Result<DapAggregateShare, DapError> {
        unreachable!("not implemented");
    }

    async fn mark_collected(
        &self,
        _task_id: &Id,
        _batch_interval: &Interval,
    ) -> Result<(), DapError> {
        unreachable!("not implemented");
    }
}

#[async_trait(?Send)]
impl DapHelper<BearerToken> for MockAggregator {
    async fn mark_aggregated(
        &self,
        _task_id: &Id,
        _report_shares: &[ReportShare],
    ) -> Result<HashMap<Nonce, TransitionFailure>, DapError> {
        // Return empty HashMap (for now)
        // TODO: Implement correct functionality
        let early_fails: HashMap<Nonce, TransitionFailure> = HashMap::new();
        return Ok(early_fails);
    }

    async fn put_helper_state(
        &self,
        _task_id: &Id,
        _agg_job_id: &Id,
        _helper_state: &DapHelperState,
    ) -> Result<(), DapError> {
        // Return empty Ok
        // TODO: Implement correct functionality
        Ok(())
    }

    async fn get_helper_state(
        &self,
        _task_id: &Id,
        _agg_job_id: &Id,
    ) -> Result<DapHelperState, DapError> {
        unreachable!("not implemented");
    }
}

#[async_trait(?Send)]
impl DapLeader<BearerToken> for MockAggregator {
    type ReportSelector = ();

    async fn put_report(&self, _report: &Report) -> Result<(), DapError> {
        unreachable!("not implemented");
    }

    async fn get_reports(
        &self,
        _task_id: &Id,
        _selector: &Self::ReportSelector,
    ) -> Result<Vec<Report>, DapError> {
        unreachable!("not implemented");
    }

    async fn init_collect_job(&self, _collect_req: &CollectReq) -> Result<Url, DapError> {
        unreachable!("not implemented");
    }

    async fn poll_collect_job(
        &self,
        _task_id: &Id,
        _collect_id: &Id,
    ) -> Result<DapCollectJob, DapError> {
        unreachable!("not implemented");
    }

    async fn get_pending_collect_jobs(
        &self,
        _task_id: &Id,
    ) -> Result<Vec<(Id, CollectReq)>, DapError> {
        unreachable!("not implemented");
    }

    async fn finish_collect_job(
        &self,
        _task_id: &Id,
        _collect_id: &Id,
        _collect_resp: &CollectResp,
    ) -> Result<(), DapError> {
        unreachable!("not implemented");
    }

    async fn send_http_post(&self, _req: DapRequest<BearerToken>) -> Result<DapResponse, DapError> {
        unreachable!("not implemented");
    }
}

#[tokio::test]
async fn http_post_aggregate_unauthorized_request() {
    let mut rng = thread_rng();
    let helper = MockAggregator::new();
    let task_id = helper.nominal_task_id();
    let task_config = helper.get_task_config_for(task_id).unwrap();

    let mut req = DapRequest {
        media_type: Some(MEDIA_TYPE_AGG_INIT_REQ),
        payload: AggregateInitializeReq {
            task_id: task_id.clone(),
            agg_job_id: Id(rng.gen()),
            agg_param: Vec::default(),
            report_shares: Vec::default(),
        }
        .get_encoded(),
        url: task_config.helper_url.join("/aggregate").unwrap(),
        sender_auth: None,
    };

    // Expect failure due to missing bearer token.
    assert_matches!(
        helper.http_post_aggregate(&req).await,
        Err(DapAbort::UnauthorizedRequest)
    );

    // Expect failure due to incorrect bearer token.
    req.sender_auth = Some(BearerToken::from("incorrect auth token!".to_string()));
    assert_matches!(
        helper.http_post_aggregate(&req).await,
        Err(DapAbort::UnauthorizedRequest)
    );
}

#[tokio::test]
async fn http_post_aggregate_share_unauthorized_request() {
    let helper = MockAggregator::new();
    let task_id = helper.nominal_task_id();
    let task_config = helper.get_task_config_for(task_id).unwrap();

    let mut req = DapRequest {
        media_type: Some(MEDIA_TYPE_AGG_SHARE_REQ),
        payload: AggregateShareReq {
            task_id: task_id.clone(),
            batch_interval: Interval::default(),
            agg_param: Vec::default(),
            report_count: 0,
            checksum: [0; 32],
        }
        .get_encoded(),
        url: task_config.helper_url.join("/aggregate_share").unwrap(),
        sender_auth: None,
    };

    // Expect failure due to missing bearer token.
    assert_matches!(
        helper.http_post_aggregate_share(&req).await,
        Err(DapAbort::UnauthorizedRequest)
    );

    // Expect failure due to incorrect bearer token.
    req.sender_auth = Some(BearerToken::from("incorrect auth token!".to_string()));
    assert_matches!(
        helper.http_post_aggregate_share(&req).await,
        Err(DapAbort::UnauthorizedRequest)
    );
}

#[tokio::test]
async fn http_post_collect_unauthorized_request() {
    let leader = MockAggregator::new();
    let task_id = leader.nominal_task_id();
    let task_config = leader.get_task_config_for(task_id).unwrap();

    let mut req = DapRequest {
        media_type: Some(MEDIA_TYPE_COLLECT_REQ),
        payload: CollectReq {
            task_id: task_id.clone(),
            batch_interval: Interval::default(),
            agg_param: Vec::default(),
        }
        .get_encoded(),
        url: task_config.leader_url.join("/collect").unwrap(),
        sender_auth: None,
    };

    // Expect failure due to missing bearer token.
    assert_matches!(
        leader.http_post_collect(&req).await,
        Err(DapAbort::UnauthorizedRequest)
    );

    // Expect failure due to incorrect bearer token.
    req.sender_auth = Some(BearerToken::from("incorrect auth token!".to_string()));
    assert_matches!(
        leader.http_post_collect(&req).await,
        Err(DapAbort::UnauthorizedRequest)
    );
}

#[tokio::test]
async fn http_post_aggregate_fake_ciphertext() {
    let helper = MockAggregator::new();
    let task_id = helper.nominal_task_id();
    let task_config = helper.get_task_config_for(task_id).unwrap();

    let req = DapRequest {
        media_type: Some(MEDIA_TYPE_AGG_INIT_REQ),
        payload: AggregateInitializeReq {
            task_id: task_id.clone(),
            agg_job_id: Id([1; 32]),
            agg_param: b"this is an aggregation parameter".to_vec(),
            report_shares: vec![
                ReportShare {
                    nonce: Nonce {
                        time: 1637361337,
                        rand: 10496152761178246059,
                    },
                    ignored_extensions: b"these are extensions".to_vec(),
                    encrypted_input_share: HpkeCiphertext {
                        config_id: 23,
                        enc: b"fake encapsulated key".to_vec(),
                        payload: b"fake ciphertext".to_vec(),
                    },
                },
            ],
        }
        .get_encoded(),
        url: task_config.helper_url.join("/aggregate").unwrap(),
        sender_auth: Some(BearerToken::from(LEADER_BEARER_TOKEN.to_string())),
    };

    // Get AggregateResp and then extract the transition data from inside
    let agg_resp = AggregateResp::get_decoded(&helper.http_post_aggregate(&req).await.unwrap().payload).unwrap();
    let transition = &agg_resp.transitions[0];

    // Expect failure due to fake ciphertext
    assert_matches!(
        transition.var,
        TransitionVar::Failed(_)
    );
}

// TODO: Create a test case where we return TransitionVar::Continued

#[test]
fn hpke_decrypter() {
    // Construct mock helper
    let helper = MockAggregator::new();
    let task_id = helper.nominal_task_id();

    // Initialize variables for mock report
    let info = b"info string";
    let aad = b"associated data";
    let plaintext = b"plaintext";
    let hpke_config_list_hex: Vec<String> = serde_json::from_str(HPKE_CONFIG_LIST).expect("failed to parse HPKE config list");
    let config_bytes = hex::decode(&hpke_config_list_hex[0]).unwrap();
    let config = HpkeConfig::get_decoded(&config_bytes).unwrap();
    let (enc, ciphertext) = config.encrypt(info, aad, plaintext).unwrap();

    // Construct mock report
    let report = Report {
        task_id: Id([23; 32]),
        nonce: Nonce {
            time: 1637364244,
            rand: 10496152761178246059,
        },
        ignored_extensions: b"some extension".to_vec(),
        encrypted_input_shares: vec![
            HpkeCiphertext {
                config_id: 23,
                enc: enc,
                payload: ciphertext,
            },
        ],
    };

    // Run test

    // Expect false due to non-existing config ID.
    assert_eq!(
        helper.can_hpke_decrypt(&task_id, 0),
        false
    );

    // Expect true due to existing config ID.
    assert_eq!(
        helper.can_hpke_decrypt(&task_id, report.encrypted_input_shares[0].config_id),
        true
    );

    // Expect decryption to fail
    assert_matches!(
        helper.hpke_decrypt(
            &report.task_id,
            info,
            aad,
            &HpkeCiphertext { 
                config_id: 0,
                enc: vec![],
                payload: b"ciphertext".to_vec(),
            }),
        Err(DapError::Transition(TransitionFailure::HpkeUnknownConfigId))
    );

    // Expect decryption to succeed
    assert_eq!(
        helper.hpke_decrypt(&report.task_id, info, aad, &report.encrypted_input_shares[0]).unwrap(),
        plaintext
    );
}
