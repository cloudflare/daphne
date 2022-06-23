// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use crate::{
    auth::{BearerToken, BearerTokenProvider},
    constants::{MEDIA_TYPE_AGG_INIT_REQ, MEDIA_TYPE_AGG_SHARE_REQ, MEDIA_TYPE_COLLECT_REQ},
    hpke::HpkeDecrypter,
    messages::{
        AggregateInitializeReq, AggregateShareReq, CollectReq, CollectResp, HpkeCiphertext,
        HpkeConfig, Id, Interval, Nonce, Report, ReportShare, TransitionFailure,
    },
    roles::{DapAggregator, DapAuthorizedSender, DapHelper, DapLeader},
    DapAbort, DapAggregateShare, DapCollectJob, DapError, DapHelperState, DapOutputShare,
    DapRequest, DapResponse, DapTaskConfig,
};
use assert_matches::assert_matches;
use async_trait::async_trait;
use prio::codec::Encode;
use rand::prelude::*;
use std::collections::HashMap;
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

const LEADER_BEARER_TOKEN: &str = "ivA1e7LpnySDNn1AulaZggFLQ1n7jZ8GWOUO7GY4hgs=";
const COLLECTOR_BEARER_TOKEN: &str = "syfRfvcvNFF5MJk4Y-B7xjRIqD_iNzhaaEB9mYqO9hk=";

struct MockAggregator {
    tasks: HashMap<Id, DapTaskConfig>,
}

impl MockAggregator {
    fn new() -> Self {
        let tasks = serde_json::from_str(TASK_LIST).expect("failed to parse task list");
        Self { tasks }
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
        unreachable!("not implemented");
    }

    fn can_hpke_decrypt(&self, _task_id: &Id, _config_id: u8) -> bool {
        unreachable!("not implemented");
    }

    fn hpke_decrypt(
        &self,
        _task_id: &Id,
        _info: &[u8],
        _aad: &[u8],
        _ciphertext: &HpkeCiphertext,
    ) -> Result<Vec<u8>, DapError> {
        unreachable!("not implemented");
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
        unreachable!("not implemented");
    }

    async fn put_helper_state(
        &self,
        _task_id: &Id,
        _agg_job_id: &Id,
        _helper_state: &DapHelperState,
    ) -> Result<(), DapError> {
        unreachable!("not implemented");
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

    async fn put_reports<I: IntoIterator<Item = Report>>(
        &self,
        _reports: I,
    ) -> Result<(), DapError> {
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
