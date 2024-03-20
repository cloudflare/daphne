// Copyright (c) 2023 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Trait definitions for Daphne backends.

pub mod aggregator;
pub mod helper;
pub mod leader;

use crate::{
    constants::DapMediaType,
    messages::{Base64Encode, Query, TaskId, Time},
    taskprov, DapAbort, DapError, DapQueryConfig, DapRequest, DapTaskConfig,
};
use tracing::warn;

pub use aggregator::{DapAggregator, DapReportInitializer};
pub use helper::DapHelper;
pub use leader::{DapAuthorizedSender, DapLeader};

async fn check_batch<S: Sync>(
    agg: &impl DapAggregator<S>,
    task_config: &DapTaskConfig,
    task_id: &TaskId,
    query: &Query,
    agg_param: &[u8],
    now: Time,
) -> Result<(), DapError> {
    let global_config = agg.get_global_config();

    // Check that the aggregation parameter is suitable for the given VDAF.
    if !task_config.vdaf.is_valid_agg_param(agg_param) {
        // TODO spec: Define this behavior.
        return Err(DapAbort::InvalidMessage {
            detail: "invalid aggregation parameter".into(),
            task_id: Some(*task_id),
        }
        .into());
    }

    // Check that the batch boundaries are valid.
    match (&task_config.query, query) {
        (DapQueryConfig::TimeInterval { .. }, Query::TimeInterval { batch_interval }) => {
            if batch_interval.start % task_config.time_precision != 0
                || batch_interval.duration % task_config.time_precision != 0
                || batch_interval.duration < task_config.time_precision
            {
                return Err(DapAbort::BatchInvalid {
                    detail: format!("The queried batch interval ({batch_interval:?}) is too small or its boundaries are misaligned. The time precision for this task is {}s.", task_config.time_precision),
                    task_id: *task_id,
                }.into());
            }

            if batch_interval.duration > global_config.max_batch_duration {
                return Err(DapAbort::BadRequest("batch interval too large".to_string()).into());
            }

            if now.abs_diff(batch_interval.start) > global_config.min_batch_interval_start {
                return Err(
                    DapAbort::BadRequest("batch interval too far into past".to_string()).into(),
                );
            }

            if now.abs_diff(batch_interval.end()) > global_config.max_batch_interval_end {
                return Err(
                    DapAbort::BadRequest("batch interval too far into future".to_string()).into(),
                );
            }
        }
        (DapQueryConfig::FixedSize { .. }, Query::FixedSizeCurrentBatch) => (), // nothing to do
        (DapQueryConfig::FixedSize { .. }, Query::FixedSizeByBatchId { batch_id }) => {
            if !agg.batch_exists(task_id, batch_id).await? {
                return Err(DapAbort::BatchInvalid {
                    detail: format!(
                        "The queried batch ({}) does not exist.",
                        batch_id.to_base64url()
                    ),
                    task_id: *task_id,
                }
                .into());
            }
        }
        _ => return Err(DapAbort::query_mismatch(task_id, &task_config.query, query).into()),
    };

    // Check that the batch does not overlap with any previously collected batch.
    if let Some(batch_sel) = query.into_batch_sel() {
        if agg.is_batch_overlapping(task_id, &batch_sel).await? {
            return Err(DapAbort::batch_overlap(task_id, query).into());
        }
    }

    Ok(())
}

fn check_request_content_type<S>(
    req: &DapRequest<S>,
    expected: DapMediaType,
) -> Result<(), DapAbort> {
    if req.media_type != Some(expected) {
        Err(DapAbort::content_type(req, expected))
    } else {
        Ok(())
    }
}

async fn resolve_taskprov<S: Sync>(
    agg: &impl DapAggregator<S>,
    task_id: &TaskId,
    req: &DapRequest<S>,
) -> Result<(), DapError> {
    if agg.get_task_config_for(task_id).await?.is_some() {
        // Task already configured, so nothing to do.
        return Ok(());
    }

    let Some(vdaf_verify_key_init) = agg.taskprov_vdaf_verify_key_init() else {
        warn!("Taskprov disabled due to missing VDAF verification key initializer.");
        return Ok(());
    };

    let Some(collector_hpke_config) = agg.taskprov_collector_hpke_config() else {
        warn!("Taskprov disabled due to missing Collector HPKE configuration.");
        return Ok(());
    };

    let Some(task_config) = taskprov::resolve_advertised_task_config(
        req,
        vdaf_verify_key_init,
        collector_hpke_config,
        task_id,
    )?
    else {
        // No task configuration advertised, so nothing to do.
        return Ok(());
    };

    // This is the opt-in / opt-out decision point.
    if let Some(reason) = agg.taskprov_opt_out_reason(&task_config)? {
        return Err(DapError::Abort(DapAbort::InvalidTask {
            detail: reason,
            task_id: *task_id,
        }));
    }

    agg.taskprov_put(req, task_config).await?;
    Ok(())
}

#[cfg(test)]
mod test {
    use super::{aggregator, helper, leader, DapAuthorizedSender, DapLeader};
    use crate::{
        assert_metrics_include, async_test_version, async_test_versions,
        auth::BearerToken,
        constants::DapMediaType,
        hpke::{HpkeKemId, HpkeProvider, HpkeReceiverConfig},
        messages::{
            AggregateShareReq, AggregationJobId, AggregationJobInitReq, AggregationJobResp,
            Base64Encode, BatchId, BatchSelector, Collection, CollectionJobId, CollectionReq,
            Extension, HpkeCiphertext, Interval, PartialBatchSelector, Query, Report, TaskId, Time,
            TransitionFailure, TransitionVar,
        },
        roles::leader::WorkItem,
        testing::InMemoryAggregator,
        vdaf::{mastic::MasticWeight, MasticWeightConfig, Prio3Config, VdafConfig},
        DapAbort, DapAggregationJobState, DapAggregationParam, DapBatchBucket, DapCollectionJob,
        DapError, DapGlobalConfig, DapMeasurement, DapPendingReport, DapQueryConfig, DapRequest,
        DapResource, DapTaskConfig, DapTaskParameters, DapVersion,
    };
    use assert_matches::assert_matches;
    use matchit::Router;
    use prio::{
        codec::{Decode, Encode, ParameterizedEncode},
        idpf::IdpfInput,
        vdaf::poplar1::Poplar1AggregationParam,
    };
    use rand::{thread_rng, Rng};
    use std::{collections::HashMap, sync::Arc, time::SystemTime, vec};
    use url::Url;

    pub(super) struct TestData {
        pub now: Time,
        global_config: DapGlobalConfig,
        collector_token: BearerToken,
        taskprov_collector_token: BearerToken,
        pub time_interval_task_id: TaskId,
        pub fixed_size_task_id: TaskId,
        pub expired_task_id: TaskId,
        pub heavy_hitters_task_id: TaskId,
        helper_registry: prometheus::Registry,
        tasks: HashMap<TaskId, DapTaskConfig>,
        pub leader_token: BearerToken,
        collector_hpke_receiver_config: HpkeReceiverConfig,
        taskprov_vdaf_verify_key_init: [u8; 32],
        taskprov_leader_token: BearerToken,
        leader_registry: prometheus::Registry,
    }

    impl TestData {
        const TASK_TIME_PRECISION: u64 = 3600;

        pub fn new(version: DapVersion) -> Self {
            let now = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let mut rng = thread_rng();

            // Global config. In a real deployment, the Leader and Helper may make different choices
            // here.
            let global_config = DapGlobalConfig {
                max_batch_duration: 360_000,
                min_batch_interval_start: 259_200,
                max_batch_interval_end: 259_200,
                supported_hpke_kems: vec![HpkeKemId::X25519HkdfSha256],
                allow_taskprov: true,
            };

            // Task Parameters that the Leader and Helper must agree on.
            let vdaf_config = VdafConfig::Prio3(Prio3Config::Count);
            let leader_url = Url::parse("https://leader.com/v02/").unwrap();
            let helper_url = Url::parse("http://helper.org:8788/v02/").unwrap();
            let collector_hpke_receiver_config =
                HpkeReceiverConfig::gen(rng.gen(), HpkeKemId::X25519HkdfSha256).unwrap();

            // Create the task list.
            let time_interval_task_id = TaskId(rng.gen());
            let fixed_size_task_id = TaskId(rng.gen());
            let expired_task_id = TaskId(rng.gen());
            let heavy_hitters_task_id = TaskId(rng.gen());
            let mut tasks = HashMap::new();
            tasks.insert(
                time_interval_task_id,
                DapTaskConfig {
                    version,
                    collector_hpke_config: collector_hpke_receiver_config.config.clone(),
                    leader_url: leader_url.clone(),
                    helper_url: helper_url.clone(),
                    time_precision: Self::TASK_TIME_PRECISION,
                    expiration: now + Self::TASK_TIME_PRECISION,
                    min_batch_size: 1,
                    query: DapQueryConfig::TimeInterval,
                    vdaf: vdaf_config,
                    vdaf_verify_key: vdaf_config.gen_verify_key(),
                    method: Default::default(),
                },
            );
            tasks.insert(
                fixed_size_task_id,
                DapTaskConfig {
                    version,
                    collector_hpke_config: collector_hpke_receiver_config.config.clone(),
                    leader_url: leader_url.clone(),
                    helper_url: helper_url.clone(),
                    time_precision: Self::TASK_TIME_PRECISION,
                    expiration: now + Self::TASK_TIME_PRECISION,
                    min_batch_size: 1,
                    query: DapQueryConfig::FixedSize {
                        max_batch_size: Some(2),
                    },
                    vdaf: vdaf_config,
                    vdaf_verify_key: vdaf_config.gen_verify_key(),
                    method: Default::default(),
                },
            );
            tasks.insert(
                expired_task_id,
                DapTaskConfig {
                    version,
                    collector_hpke_config: collector_hpke_receiver_config.config.clone(),
                    leader_url: leader_url.clone(),
                    helper_url: helper_url.clone(),
                    time_precision: Self::TASK_TIME_PRECISION,
                    expiration: now, // Expires this second
                    min_batch_size: 1,
                    query: DapQueryConfig::TimeInterval,
                    vdaf: vdaf_config,
                    vdaf_verify_key: vdaf_config.gen_verify_key(),
                    method: Default::default(),
                },
            );

            let mastic = VdafConfig::Mastic {
                input_size: 1,
                weight_config: MasticWeightConfig::Count,
            };
            tasks.insert(
                heavy_hitters_task_id,
                DapTaskConfig {
                    version,
                    collector_hpke_config: collector_hpke_receiver_config.config.clone(),
                    leader_url,
                    helper_url,
                    time_precision: Self::TASK_TIME_PRECISION,
                    expiration: now + Self::TASK_TIME_PRECISION,
                    min_batch_size: 10,
                    query: DapQueryConfig::TimeInterval,
                    vdaf: mastic,
                    vdaf_verify_key: mastic.gen_verify_key(),
                    method: Default::default(),
                },
            );

            // Authorization tokens. These are normally chosen at random.
            let leader_token = BearerToken::from("leader_token");
            let collector_token = BearerToken::from("collector_token");

            // taskprov
            let taskprov_vdaf_verify_key_init = rng.gen::<[u8; 32]>();
            let taskprov_leader_token = BearerToken::from("taskprov_leader_token");
            let taskprov_collector_token = BearerToken::from("taskprov_collector_token");

            let helper_registry = prometheus::Registry::new_custom(
                Option::None,
                Option::Some(HashMap::from([
                    ("env".to_string(), "test_helper".to_owned()),
                    ("host".to_string(), "helper.org".to_owned()),
                ])),
            )
            .unwrap();
            let leader_registry = prometheus::Registry::new_custom(
                Option::None,
                Option::Some(HashMap::from([
                    ("env".to_string(), "test_leader".to_owned()),
                    ("host".to_string(), "leader.com".to_owned()),
                ])),
            )
            .unwrap();

            Self {
                now,
                global_config,
                collector_token,
                taskprov_collector_token,
                time_interval_task_id,
                fixed_size_task_id,
                expired_task_id,
                heavy_hitters_task_id,
                helper_registry,
                tasks,
                leader_token,
                taskprov_leader_token,
                collector_hpke_receiver_config,
                taskprov_vdaf_verify_key_init,
                leader_registry,
            }
        }

        pub fn new_helper(&self) -> Arc<InMemoryAggregator> {
            Arc::new(InMemoryAggregator::new_helper(
                self.tasks.clone(),
                self.global_config
                    .gen_hpke_receiver_config_list(thread_rng().gen())
                    .expect("failed to generate HPKE receiver config"),
                self.global_config.clone(),
                self.leader_token.clone(),
                self.collector_hpke_receiver_config.config.clone(),
                &self.helper_registry,
                self.taskprov_vdaf_verify_key_init,
                self.taskprov_leader_token.clone(),
            ))
        }

        pub fn with_leader(self, helper: Arc<InMemoryAggregator>) -> Test {
            let leader = Arc::new(InMemoryAggregator::new_leader(
                self.tasks,
                self.global_config
                    .gen_hpke_receiver_config_list(thread_rng().gen())
                    .expect("failed to generate HPKE receiver config"),
                self.global_config,
                self.leader_token,
                self.collector_token.clone(),
                self.collector_hpke_receiver_config.config.clone(),
                &self.leader_registry,
                self.taskprov_vdaf_verify_key_init,
                self.taskprov_leader_token,
                self.taskprov_collector_token.clone(),
                Arc::clone(&helper),
            ));

            Test {
                now: self.now,
                leader,
                helper,
                collector_token: self.collector_token,
                taskprov_collector_token: self.taskprov_collector_token,
                time_interval_task_id: self.time_interval_task_id,
                fixed_size_task_id: self.fixed_size_task_id,
                expired_task_id: self.expired_task_id,
                heavy_hitters_task_id: self.heavy_hitters_task_id,
                helper_registry: self.helper_registry,
                leader_registry: self.leader_registry,
            }
        }
    }

    pub(super) struct Test {
        now: Time,
        leader: Arc<InMemoryAggregator>,
        helper: Arc<InMemoryAggregator>,
        collector_token: BearerToken,
        taskprov_collector_token: BearerToken,
        time_interval_task_id: TaskId,
        fixed_size_task_id: TaskId,
        expired_task_id: TaskId,
        heavy_hitters_task_id: TaskId,
        pub helper_registry: prometheus::Registry,
        pub leader_registry: prometheus::Registry,
    }

    impl Test {
        pub fn new(version: DapVersion) -> Self {
            let data = TestData::new(version);
            let helper = data.new_helper();
            data.with_leader(helper)
        }

        pub async fn gen_test_upload_req(
            &self,
            report: Report,
            task_id: &TaskId,
        ) -> DapRequest<BearerToken> {
            let task_config = self.leader.unchecked_get_task_config(task_id).await;
            let version = task_config.version;

            DapRequest {
                version,
                media_type: Some(DapMediaType::Report),
                task_id: Some(*task_id),
                resource: DapResource::Undefined,
                payload: report.get_encoded_with_param(&version).unwrap(),
                ..Default::default()
            }
        }

        pub async fn gen_test_coll_job_req(
            &self,
            query: Query,
            task_id: &TaskId,
        ) -> DapRequest<BearerToken> {
            self.gen_test_coll_job_req_for_collection(query, DapAggregationParam::Empty, task_id)
                .await
        }

        pub async fn gen_test_coll_job_req_for_collection(
            &self,
            query: Query,
            agg_param: DapAggregationParam,
            task_id: &TaskId,
        ) -> DapRequest<BearerToken> {
            let task_config = self.leader.unchecked_get_task_config(task_id).await;

            self.collector_authorized_req(
                task_id,
                &task_config,
                DapMediaType::CollectReq,
                CollectionReq {
                    query,
                    agg_param: agg_param.get_encoded().unwrap(),
                },
            )
        }

        pub async fn gen_test_agg_job_init_req(
            &self,
            task_id: &TaskId,
            agg_param: DapAggregationParam,
            reports: Vec<DapPendingReport>,
        ) -> (DapAggregationJobState, DapRequest<BearerToken>) {
            let mut rng = thread_rng();
            let task_config = self.leader.unchecked_get_task_config(task_id).await;
            let part_batch_sel = match task_config.query {
                DapQueryConfig::TimeInterval { .. } => PartialBatchSelector::TimeInterval,
                DapQueryConfig::FixedSize { .. } => PartialBatchSelector::FixedSizeByBatchId {
                    batch_id: BatchId(rng.gen()),
                },
            };

            let agg_job_id = AggregationJobId(rng.gen());

            let (leader_state, agg_job_init_req) = task_config
                .produce_agg_job_req(
                    &*self.leader,
                    &*self.leader,
                    task_id,
                    &part_batch_sel,
                    &agg_param,
                    futures::stream::iter(reports),
                    &self.leader.metrics,
                )
                .await
                .unwrap();

            (
                leader_state,
                self.leader_authorized_req(
                    task_id,
                    &task_config,
                    Some(&agg_job_id),
                    DapMediaType::AggregationJobInitReq,
                    agg_job_init_req
                        .get_encoded_with_param(&(task_config.version, false))
                        .unwrap(),
                )
                .await,
            )
        }

        pub async fn gen_test_agg_share_req(
            &self,
            report_count: u64,
            checksum: [u8; 32],
        ) -> DapRequest<BearerToken> {
            let task_id = &self.time_interval_task_id;
            let task_config = self.leader.unchecked_get_task_config(task_id).await;

            self.leader_authorized_req(
                task_id,
                &task_config,
                None,
                DapMediaType::AggregateShareReq,
                AggregateShareReq {
                    batch_sel: BatchSelector::default(),
                    agg_param: Vec::default(),
                    report_count,
                    checksum,
                }
                .get_encoded_with_param(&task_config.version)
                .unwrap(),
            )
            .await
        }

        pub async fn gen_test_report(&self, task_id: &TaskId) -> Report {
            // Construct report. We expect the VDAF to be Prio3Count so that we know what type of
            // measurement to generate. However, we could extend the code to support more VDAFs.
            let task_config = self.leader.unchecked_get_task_config(task_id).await;
            assert_matches!(task_config.vdaf, VdafConfig::Prio3(Prio3Config::Count));

            self.gen_test_report_for_measurement(task_id, DapMeasurement::U64(1))
                .await
        }

        pub async fn gen_test_report_for_measurement(
            &self,
            task_id: &TaskId,
            measurement: DapMeasurement,
        ) -> Report {
            let task_config = self.leader.unchecked_get_task_config(task_id).await;

            // Construct HPKE config list.
            let hpke_config_list = [
                self.leader
                    .get_hpke_config_for(task_config.version, Some(task_id))
                    .await
                    .unwrap()
                    .clone(),
                self.helper
                    .get_hpke_config_for(task_config.version, Some(task_id))
                    .await
                    .unwrap()
                    .clone(),
            ];

            task_config
                .vdaf
                .produce_report(
                    &hpke_config_list,
                    self.now,
                    task_id,
                    measurement,
                    task_config.version,
                )
                .unwrap()
        }

        pub async fn leader_authorized_req(
            &self,
            task_id: &TaskId,
            task_config: &DapTaskConfig,
            agg_job_id: Option<&AggregationJobId>,
            media_type: DapMediaType,
            payload: Vec<u8>,
        ) -> DapRequest<BearerToken> {
            let sender_auth = Some(
                self.leader
                    .authorize(task_id, task_config, &media_type, &payload)
                    .await
                    .unwrap(),
            );
            DapRequest {
                version: task_config.version,
                media_type: Some(media_type),
                task_id: Some(*task_id),
                resource: agg_job_id.map_or(DapResource::Undefined, |id| {
                    DapResource::AggregationJob(*id)
                }),
                payload,
                sender_auth,
                ..Default::default()
            }
        }

        pub fn collector_authorized_req<M: ParameterizedEncode<DapVersion>>(
            &self,
            task_id: &TaskId,
            task_config: &DapTaskConfig,
            media_type: DapMediaType,
            msg: M,
        ) -> DapRequest<BearerToken> {
            let mut rng = thread_rng();
            let coll_job_id = CollectionJobId(rng.gen());
            let sender_auth = if task_config.method_is_taskprov() {
                Some(self.taskprov_collector_token.clone())
            } else {
                Some(self.collector_token.clone())
            };

            DapRequest {
                version: task_config.version,
                media_type: Some(media_type),
                task_id: Some(*task_id),
                resource: DapResource::CollectionJob(coll_job_id),
                payload: msg.get_encoded_with_param(&task_config.version).unwrap(),
                sender_auth,
                ..Default::default()
            }
        }
    }

    // Test that the Helper properly handles the batch parameter in the AggregationJobInitReq.
    async fn handle_agg_job_req_invalid_batch_sel(version: DapVersion) {
        let mut rng = thread_rng();
        let t = Test::new(version);
        let task_id = &t.time_interval_task_id;
        let task_config = t.leader.unchecked_get_task_config(task_id).await;
        let agg_job_id = AggregationJobId(rng.gen());

        // Helper expects "time_interval" query, but Leader indicates "fixed_size".
        let req = t
            .leader_authorized_req(
                task_id,
                &task_config,
                Some(&agg_job_id),
                DapMediaType::AggregationJobInitReq,
                AggregationJobInitReq {
                    agg_param: Vec::default(),
                    part_batch_sel: PartialBatchSelector::FixedSizeByBatchId {
                        batch_id: BatchId(rng.gen()),
                    },
                    prep_inits: Vec::default(),
                }
                .get_encoded_with_param(&(version, false))
                .unwrap(),
            )
            .await;
        assert_matches!(
            helper::handle_agg_job_req(&*t.helper, &req)
                .await
                .unwrap_err(),
            DapError::Abort(DapAbort::QueryMismatch { .. })
        );

        assert_eq!(t.helper.audit_log.invocations(), 0);
    }

    async_test_versions! { handle_agg_job_req_invalid_batch_sel }

    // TODO(cjpatton) Re-enable this test. We need to refactor so that we can produce the
    // AggregationJobInitReq without invoking `produce_agg_job_req()`, which filters reports
    // passed the expiration date.
    //
    //    async fn handle_agg_job_req_init_expired_task(version: DapVersion) {
    //        let t = Test::new(version);
    //
    //        let report = t.gen_test_report(&t.expired_task_id).await;
    //        let report_share = ReportShare {
    //            report_metadata: report.report_metadata,
    //            public_share: report.public_share,
    //            encrypted_input_share: report.encrypted_input_shares[1].clone(),
    //        };
    //        let req = t
    //            .gen_test_agg_job_init_req(&t.expired_task_id, vec![report_share])
    //            .await;
    //
    //        let resp = t.helper.handle_agg_job_req(&req).await.unwrap();
    //        let agg_job_resp = AggregationJobResp::get_decoded(&resp.payload).unwrap();
    //        assert_eq!(agg_job_resp.transitions.len(), 1);
    //        assert_matches!(
    //            agg_job_resp.transitions[0].var,
    //            TransitionVar::Failed(TransitionFailure::TaskExpired)
    //        );
    //
    //        assert_eq!(t.helper.audit_log.invocations(), 1);
    //    }
    //
    //    async_test_versions! { handle_agg_job_req_init_expired_task }

    async fn handle_agg_job_init_req_unauthorized_request(version: DapVersion) {
        let t = Test::new(version);
        let report = t.gen_test_report(&t.time_interval_task_id).await;
        let (_, mut req) = t
            .gen_test_agg_job_init_req(
                &t.time_interval_task_id,
                DapAggregationParam::Empty,
                vec![DapPendingReport::New(report)],
            )
            .await;
        req.sender_auth = None;

        // Expect failure due to missing bearer token.
        assert_matches!(
            helper::handle_agg_job_req(&*t.helper, &req).await,
            Err(DapError::Abort(DapAbort::UnauthorizedRequest { .. }))
        );

        // Expect failure due to incorrect bearer token.
        req.sender_auth = Some(BearerToken::from("incorrect auth token!".to_string()));
        assert_matches!(
            helper::handle_agg_job_req(&*t.helper, &req).await,
            Err(DapError::Abort(DapAbort::UnauthorizedRequest { .. }))
        );

        assert_eq!(t.helper.audit_log.invocations(), 0);
    }

    async_test_versions! { handle_agg_job_init_req_unauthorized_request }

    async fn handle_hpke_config_req_unrecognized_task(version: DapVersion) {
        let t = Test::new(version);
        let mut rng = thread_rng();
        let task_id = TaskId(rng.gen());
        let req = DapRequest {
            version,
            media_type: Some(DapMediaType::HpkeConfigList),
            payload: Vec::new(),
            task_id: Some(task_id),
            resource: DapResource::Undefined,
            ..Default::default()
        };

        assert_matches!(
            aggregator::handle_hpke_config_req(&*t.leader, &req, Some(task_id)).await,
            Err(DapError::Abort(DapAbort::UnrecognizedTask))
        );
    }

    async_test_versions! { handle_hpke_config_req_unrecognized_task }

    async fn handle_hpke_config_req_missing_task_id(version: DapVersion) {
        let t = Test::new(version);
        let req = DapRequest {
            version,
            media_type: Some(DapMediaType::HpkeConfigList),
            task_id: Some(t.time_interval_task_id),
            resource: DapResource::Undefined,
            payload: Vec::new(),
            ..Default::default()
        };

        // An Aggregator is permitted to abort an HPKE config request if the task ID is missing. Note
        // that Daphne-Workder does not implement this behavior. Instead it returns the HPKE config
        // used for all tasks.
        assert_matches!(
            aggregator::handle_hpke_config_req(&*t.leader, &req, None).await,
            Err(DapError::Abort(DapAbort::MissingTaskId))
        );
    }

    async_test_versions! { handle_hpke_config_req_missing_task_id }

    async fn handle_agg_share_req_unauthorized_request(version: DapVersion) {
        let t = Test::new(version);
        let mut req = t.gen_test_agg_share_req(0, [0; 32]).await;
        req.sender_auth = None;

        // Expect failure due to missing bearer token.
        assert_matches!(
            helper::handle_agg_share_req(&*t.helper, &req).await,
            Err(DapError::Abort(DapAbort::UnauthorizedRequest { .. }))
        );

        // Expect failure due to incorrect bearer token.
        req.sender_auth = Some(BearerToken::from("incorrect auth token!".to_string()));
        assert_matches!(
            helper::handle_agg_share_req(&*t.helper, &req).await,
            Err(DapError::Abort(DapAbort::UnauthorizedRequest { .. }))
        );
    }

    async_test_versions! { handle_agg_share_req_unauthorized_request }

    // Test that the Helper handles the batch selector sent from the Leader properly.
    async fn handle_agg_share_req_invalid_batch_sel(version: DapVersion) {
        let mut rng = thread_rng();
        let t = Test::new(version);

        // Helper expects "time_interval" query, but Leader sent "fixed_size".
        let task_config = t
            .leader
            .unchecked_get_task_config(&t.time_interval_task_id)
            .await;
        let req = t
            .leader_authorized_req(
                &t.time_interval_task_id,
                &task_config,
                None,
                DapMediaType::AggregateShareReq,
                AggregateShareReq {
                    batch_sel: BatchSelector::FixedSizeByBatchId {
                        batch_id: BatchId(rng.gen()),
                    },
                    agg_param: Vec::default(),
                    report_count: 0,
                    checksum: [0; 32],
                }
                .get_encoded_with_param(&version)
                .unwrap(),
            )
            .await;
        assert_matches!(
            helper::handle_agg_share_req(&*t.helper, &req)
                .await
                .unwrap_err(),
            DapError::Abort(DapAbort::QueryMismatch { .. })
        );

        // Leader sends aggregate share request for unrecognized batch ID.
        let task_config = t
            .leader
            .unchecked_get_task_config(&t.fixed_size_task_id)
            .await;
        let req = t
            .leader_authorized_req(
                &t.fixed_size_task_id,
                &task_config,
                None,
                DapMediaType::AggregateShareReq,
                AggregateShareReq {
                    batch_sel: BatchSelector::FixedSizeByBatchId {
                        batch_id: BatchId(rng.gen()), // Unrecognized batch ID
                    },
                    agg_param: Vec::default(),
                    report_count: 0,
                    checksum: [0; 32],
                }
                .get_encoded_with_param(&version)
                .unwrap(),
            )
            .await;
        assert_matches!(
            helper::handle_agg_share_req(&*t.helper, &req)
                .await
                .unwrap_err(),
            DapError::Abort(DapAbort::BatchInvalid { .. })
        );
    }

    async_test_versions! { handle_agg_share_req_invalid_batch_sel }

    async fn handle_coll_job_req_unauthorized_request(version: DapVersion) {
        let mut rng = thread_rng();
        let t = Test::new(version);
        let task_id = &t.time_interval_task_id;
        let task_config = t.leader.unchecked_get_task_config(task_id).await;
        let collect_job_id = CollectionJobId(rng.gen());
        let mut req = DapRequest {
            version: task_config.version,
            media_type: Some(DapMediaType::CollectReq),
            task_id: Some(*task_id),
            resource: DapResource::CollectionJob(collect_job_id),
            payload: CollectionReq {
                query: Query::default(),
                agg_param: Vec::default(),
            }
            .get_encoded_with_param(&task_config.version)
            .unwrap(),
            ..Default::default() // Unauthorized request.
        };

        // Expect failure due to missing bearer token.
        assert_matches!(
            leader::handle_coll_job_req(&*t.leader, &req).await,
            Err(DapError::Abort(DapAbort::UnauthorizedRequest { .. }))
        );

        // Expect failure due to incorrect bearer token.
        req.sender_auth = Some(BearerToken::from("incorrect auth token!".to_string()));
        assert_matches!(
            leader::handle_coll_job_req(&*t.leader, &req).await,
            Err(DapError::Abort(DapAbort::UnauthorizedRequest { .. }))
        );
    }

    async_test_versions! { handle_coll_job_req_unauthorized_request }

    async fn handle_agg_job_req_failure_hpke_decrypt_error(version: DapVersion) {
        let t = Test::new(version);
        let task_id = &t.time_interval_task_id;

        let mut report = t.gen_test_report(task_id).await;
        report.encrypted_input_shares[1].payload[0] ^= 0xff; // Cause decryption to fail
        let (_, req) = t
            .gen_test_agg_job_init_req(
                task_id,
                DapAggregationParam::Empty,
                vec![DapPendingReport::New(report)],
            )
            .await;

        // Get AggregationJobResp and then extract the transition data from inside.
        let agg_job_resp = AggregationJobResp::get_decoded(
            &helper::handle_agg_job_req(&*t.helper, &req)
                .await
                .unwrap()
                .payload,
        )
        .unwrap();
        let transition = &agg_job_resp.transitions[0];

        // Expect failure due to invalid ciphertext.
        assert_matches!(
            transition.var,
            TransitionVar::Failed(TransitionFailure::HpkeDecryptError)
        );
    }

    async_test_versions! { handle_agg_job_req_failure_hpke_decrypt_error }

    async fn handle_agg_job_req_transition_continue(version: DapVersion) {
        let t = Test::new(version);
        let task_id = &t.time_interval_task_id;

        let report = t.gen_test_report(task_id).await;
        let (_, req) = t
            .gen_test_agg_job_init_req(
                task_id,
                DapAggregationParam::Empty,
                vec![DapPendingReport::New(report)],
            )
            .await;

        // Get AggregationJobResp and then extract the transition data from inside.
        let agg_job_resp = AggregationJobResp::get_decoded(
            &helper::handle_agg_job_req(&*t.helper, &req)
                .await
                .unwrap()
                .payload,
        )
        .unwrap();
        let transition = &agg_job_resp.transitions[0];

        // Expect success due to valid ciphertext.
        assert_matches!(transition.var, TransitionVar::Continued(_));
    }

    async_test_versions! { handle_agg_job_req_transition_continue }

    async fn handle_agg_job_req_failure_report_replayed(version: DapVersion) {
        let t = Test::new(version);
        let task_id = &t.time_interval_task_id;
        let task_config = t.helper.unchecked_get_task_config(task_id).await;

        let report = t.gen_test_report(task_id).await;
        let req = t.gen_test_upload_req(report.clone(), task_id).await;
        leader::handle_upload_req(&*t.leader, &req).await.unwrap();

        let query = task_config.query_for_current_batch_window(t.now);
        let req = t.gen_test_coll_job_req(query, task_id).await;
        leader::handle_coll_job_req(&*t.leader, &req).await.unwrap();

        // Add dummy data to report store backend. This is done in a new scope so that the lock on the
        // report store is released before running the test.
        {
            let bucket = DapBatchBucket::TimeInterval {
                batch_window: task_config.quantized_time_lower_bound(t.now),
            };
            let mut agg_store = t.helper.agg_store.lock().unwrap();
            agg_store
                .for_bucket(task_id, &bucket, &DapAggregationParam::Empty)
                .unwrap()
                .reports
                .insert(report.report_metadata.id);
        }

        leader::process(&*t.leader, "leader.com", 100)
            .await
            .unwrap();

        assert_metrics_include!(t.leader_registry, {
            r#"report_counter{env="test_leader",host="leader.com",status="rejected_report_replayed"}"#: 1,
        });

        assert_metrics_include!(t.helper_registry, {
            r#"report_counter{env="test_helper",host="helper.org",status="rejected_report_replayed"}"#: 1,
            r#"inbound_request_counter{env="test_helper",host="helper.org",type="aggregate"}"#: 1,
            r#"aggregation_job_counter{env="test_helper",host="helper.org",status="started"}"#: 1,
        });
    }

    async_test_versions! { handle_agg_job_req_failure_report_replayed }

    async fn handle_agg_job_req_failure_batch_collected(version: DapVersion) {
        let t = Test::new(version);
        let task_id = &t.time_interval_task_id;
        let task_config = t.helper.unchecked_get_task_config(task_id).await;

        let report = t.gen_test_report(task_id).await;
        let req = t.gen_test_upload_req(report.clone(), task_id).await;
        leader::handle_upload_req(&*t.leader, &req).await.unwrap();

        // Add mock data to the aggreagte store backend. This is done in its own scope so that the lock
        // is released before running the test. Otherwise the test will deadlock.
        {
            let bucket = DapBatchBucket::TimeInterval {
                batch_window: task_config.quantized_time_lower_bound(t.now),
            };
            let mut agg_store = t.helper.agg_store.lock().unwrap();
            agg_store
                .for_bucket(task_id, &bucket, &DapAggregationParam::Empty)
                .unwrap()
                .collected = true;
        }

        let query = task_config.query_for_current_batch_window(t.now);
        let req = t.gen_test_coll_job_req(query, task_id).await;
        leader::handle_coll_job_req(&*t.leader, &req).await.unwrap();

        leader::process(&*t.leader, "leader.com", 100)
            .await
            .unwrap();

        assert_metrics_include!(t.leader_registry, {
            r#"report_counter{env="test_leader",host="leader.com",status="rejected_batch_collected"}"#: 1,
        });

        assert_metrics_include!(t.helper_registry, {
            r#"report_counter{env="test_helper",host="helper.org",status="rejected_batch_collected"}"#: 1,
            r#"inbound_request_counter{env="test_helper",host="helper.org",type="aggregate"}"#: 1,
            r#"aggregation_job_counter{env="test_helper",host="helper.org",status="started"}"#: 1,
        });
    }

    async_test_versions! { handle_agg_job_req_failure_batch_collected }

    async fn handle_upload_req_fail_send_invalid_report(version: DapVersion) {
        let t = Test::new(version);
        let task_id = &t.time_interval_task_id;
        let task_config = t.leader.unchecked_get_task_config(task_id).await;

        // Construct a report payload with an invalid task ID.
        let report_invalid_task_id = t.gen_test_report(task_id).await;
        let req = DapRequest {
            version: task_config.version,
            media_type: Some(DapMediaType::Report),
            task_id: Some(TaskId([0; 32])),
            resource: DapResource::Undefined,
            payload: report_invalid_task_id
                .get_encoded_with_param(&task_config.version)
                .unwrap(),
            ..Default::default()
        };

        // Expect failure due to invalid task ID in report.
        assert_matches!(
            leader::handle_upload_req(&*t.leader, &req).await,
            Err(DapError::Abort(DapAbort::UnrecognizedTask))
        );
    }

    async_test_versions! { handle_upload_req_fail_send_invalid_report }

    // Test that the Leader rejects reports past the expiration date.
    async fn handle_upload_req_task_expired(version: DapVersion) {
        let t = Test::new(version);
        let task_id = &t.expired_task_id;
        let task_config = t.leader.unchecked_get_task_config(task_id).await;

        let report = t.gen_test_report(task_id).await;
        let req = DapRequest {
            version: task_config.version,
            media_type: Some(DapMediaType::Report),
            task_id: Some(*task_id),
            resource: DapResource::Undefined,
            payload: report.get_encoded_with_param(&version).unwrap(),
            ..Default::default()
        };

        assert_matches!(
            leader::handle_upload_req(&*t.leader, &req)
                .await
                .unwrap_err(),
            DapError::Abort(DapAbort::ReportTooLate)
        );
    }

    async_test_versions! { handle_upload_req_task_expired }

    async fn dequeue_work_empty(version: DapVersion) {
        let t = Test::new(version);
        let task_id = &t.time_interval_task_id;
        let task_config = t.leader.unchecked_get_task_config(task_id).await;

        for _ in 0..10 {
            let report = t.gen_test_report(task_id).await;
            let req = t.gen_test_upload_req(report.clone(), task_id).await;
            leader::handle_upload_req(&*t.leader, &req).await.unwrap();
        }

        let query = task_config.query_for_current_batch_window(t.now);
        let req = t.gen_test_coll_job_req(query, task_id).await;
        leader::handle_coll_job_req(&*t.leader, &req).await.unwrap();

        // Get the next work item. This should be an aggregation job for the reports that were
        // uploaded.
        let mut work_items = t.leader.dequeue_work(1).await.unwrap();
        assert_eq!(work_items.len(), 1);
        let WorkItem::AggregationJob {
            task_id: returned_task_id,
            part_batch_sel: _,
            agg_param: _,
            reports,
        } = work_items.pop().unwrap()
        else {
            panic!("unexpected work item type");
        };
        assert_eq!(reports.len(), 10);
        assert_eq!(&returned_task_id, task_id);

        // Get the next work item. This should be the collection job.
        let mut work_items = t.leader.dequeue_work(1).await.unwrap();
        assert_eq!(work_items.len(), 1);
        let WorkItem::CollectionJob {
            task_id: returned_task_id,
            coll_job_id: _,
            batch_sel: _,
            agg_param: _,
        } = work_items.pop().unwrap()
        else {
            panic!("unexpected work item type");
        };
        assert_eq!(&returned_task_id, task_id);

        // Get the next work item. Expect the return value to be empty because there is no more
        // work to process.
        assert_eq!(t.leader.dequeue_work(1).await.unwrap().len(), 0);
    }

    async_test_versions! { dequeue_work_empty }

    async fn poll_collect_job_test_results(version: DapVersion) {
        let t = Test::new(version);
        let task_id = &t.time_interval_task_id;
        let task_config = t.leader.unchecked_get_task_config(task_id).await;

        // Collector: Create a CollectReq.
        let req = t.collector_authorized_req(
            task_id,
            &task_config,
            DapMediaType::CollectReq,
            CollectionReq {
                query: task_config.query_for_current_batch_window(t.now),
                agg_param: Vec::default(),
            },
        );

        // Leader: Handle the CollectReq received from Collector.
        leader::handle_coll_job_req(&*t.leader, &req).await.unwrap();

        // Expect DapCollectionJob::Unknown due to invalid collect ID.
        assert_eq!(
            t.leader
                .poll_collect_job(task_id, &CollectionJobId::default())
                .await
                .unwrap(),
            DapCollectionJob::Unknown
        );

        // Leader: Get pending collect job to obtain collect_id
        let WorkItem::CollectionJob {
            task_id: _,
            coll_job_id,
            batch_sel: _,
            agg_param: _,
        } = t.leader.dequeue_work(1).await.unwrap().pop().unwrap()
        else {
            panic!("unexpected work item type")
        };
        let collection = Collection {
            part_batch_sel: PartialBatchSelector::TimeInterval,
            report_count: 0,
            interval: Interval {
                start: 0,
                duration: 2_000_000_000,
            },
            encrypted_agg_shares: [
                HpkeCiphertext {
                    config_id: Default::default(),
                    enc: Default::default(),
                    payload: Default::default(),
                },
                HpkeCiphertext {
                    config_id: Default::default(),
                    enc: Default::default(),
                    payload: Default::default(),
                },
            ],
        };

        // Expect DapCollectionJob::Pending due to pending collect job.
        assert_eq!(
            t.leader
                .poll_collect_job(task_id, &coll_job_id)
                .await
                .unwrap(),
            DapCollectionJob::Pending
        );

        // Leader: Complete the collect job by storing CollectResp in LeaderStore.processed.
        t.leader
            .finish_collect_job(task_id, &coll_job_id, &collection)
            .await
            .unwrap();

        // Expect DapCollectionJob::Done due to processed collect job.
        assert_matches!(
            t.leader
                .poll_collect_job(task_id, &coll_job_id)
                .await
                .unwrap(),
            DapCollectionJob::Done(..)
        );
    }

    async_test_versions! { poll_collect_job_test_results }

    async fn handle_coll_job_req_fail_invalid_batch_interval(version: DapVersion) {
        let t = Test::new(version);
        let task_id = &t.time_interval_task_id;
        let task_config = t.leader.unchecked_get_task_config(task_id).await;

        // Collector: Create a CollectReq with a very large batch interval.
        let req = t.collector_authorized_req(
            task_id,
            &task_config,
            DapMediaType::CollectReq,
            CollectionReq {
                query: Query::TimeInterval {
                    batch_interval: Interval {
                        start: task_config.quantized_time_lower_bound(t.now),
                        duration: t.leader.global_config.max_batch_duration
                            + task_config.time_precision,
                    },
                },
                agg_param: Vec::default(),
            },
        );

        // Leader: Handle the CollectReq received from Collector.
        let err = leader::handle_coll_job_req(&*t.leader, &req)
            .await
            .unwrap_err();

        // Fails because the requested batch interval is too large.
        assert_matches!(err, DapError::Abort(DapAbort::BadRequest(s)) => assert_eq!(s, "batch interval too large".to_string()));

        // Collector: Create a CollectReq with a batch interval in the past.
        let req = t.collector_authorized_req(
            task_id,
            &task_config,
            DapMediaType::CollectReq,
            CollectionReq {
                query: Query::TimeInterval {
                    batch_interval: Interval {
                        start: task_config.quantized_time_lower_bound(t.now)
                            - t.leader.global_config.min_batch_interval_start
                            - task_config.time_precision,
                        duration: task_config.time_precision * 2,
                    },
                },
                agg_param: Vec::default(),
            },
        );

        // Leader: Handle the CollectReq received from Collector.
        let err = leader::handle_coll_job_req(&*t.leader, &req)
            .await
            .unwrap_err();

        // Fails because the requested batch interval is too far into the past.
        assert_matches!(err, DapError::Abort(DapAbort::BadRequest(s)) => assert_eq!(s, "batch interval too far into past".to_string()));

        // Collector: Create a CollectReq with a batch interval in the future.
        let req = t.collector_authorized_req(
            task_id,
            &task_config,
            DapMediaType::CollectReq,
            CollectionReq {
                query: Query::TimeInterval {
                    batch_interval: Interval {
                        start: task_config.quantized_time_lower_bound(t.now)
                            + t.leader.global_config.max_batch_interval_end
                            - task_config.time_precision,
                        duration: task_config.time_precision * 2,
                    },
                },
                agg_param: Vec::default(),
            },
        );

        // Leader: Handle the CollectReq received from Collector.
        let err = leader::handle_coll_job_req(&*t.leader, &req)
            .await
            .unwrap_err();

        // Fails because the requested batch interval is too far into the future.
        assert_matches!(err, DapError::Abort(DapAbort::BadRequest(s)) => assert_eq!(s, "batch interval too far into future".to_string()));
    }

    async_test_versions! { handle_coll_job_req_fail_invalid_batch_interval }

    async fn handle_coll_job_req_succeed_max_batch_interval(version: DapVersion) {
        let t = Test::new(version);
        let task_id = &t.time_interval_task_id;
        let task_config = t.leader.unchecked_get_task_config(task_id).await;

        // Collector: Create a CollectReq with a very large batch interval.
        let req = t.collector_authorized_req(
            task_id,
            &task_config,
            DapMediaType::CollectReq,
            CollectionReq {
                query: Query::TimeInterval {
                    batch_interval: Interval {
                        start: task_config.quantized_time_lower_bound(t.now)
                            - t.leader.global_config.max_batch_duration / 2,
                        duration: t.leader.global_config.max_batch_duration,
                    },
                },
                agg_param: Vec::default(),
            },
        );

        // Leader: Handle the CollectReq received from Collector.
        let _collect_uri = leader::handle_coll_job_req(&*t.leader, &req).await.unwrap();
    }

    async_test_versions! { handle_coll_job_req_succeed_max_batch_interval }

    async fn handle_coll_job_req_fail_overlapping_batch_interval(version: DapVersion) {
        let t = Test::new(version);
        let task_id = &t.time_interval_task_id;
        let task_config = t.leader.unchecked_get_task_config(task_id).await;

        let report = t.gen_test_report(task_id).await;
        let req = t.gen_test_upload_req(report.clone(), task_id).await;
        leader::handle_upload_req(&*t.leader, &req).await.unwrap();

        let query = task_config.query_for_current_batch_window(t.now);
        let req = t.gen_test_coll_job_req(query, task_id).await;
        leader::handle_coll_job_req(&*t.leader, &req).await.unwrap();

        leader::process(&*t.leader, "leader.com", 100)
            .await
            .unwrap();

        // Repeat the request. Expect failure due to overlapping batch.
        assert_matches!(
            leader::handle_coll_job_req(&*t.leader, &req)
                .await
                .unwrap_err(),
            DapError::Abort(DapAbort::BatchOverlap { .. })
        );
    }

    async_test_versions! { handle_coll_job_req_fail_overlapping_batch_interval }

    async fn handle_coll_job_req_fail_unrecongized_batch(version: DapVersion) {
        let t = Test::new(version);
        let task_id = &t.fixed_size_task_id;

        let req = t
            .gen_test_coll_job_req(
                Query::FixedSizeByBatchId {
                    batch_id: BatchId(thread_rng().gen()),
                },
                task_id,
            )
            .await;

        // Expect failure due to unrecognized batch
        assert_matches!(
            leader::handle_coll_job_req(&*t.leader, &req)
                .await
                .unwrap_err(),
            DapError::Abort(DapAbort::BatchInvalid { .. })
        );
    }

    async_test_versions! { handle_coll_job_req_fail_unrecongized_batch }

    // Test a successful collect request submission.
    // This checks that the Leader reponds with the collect ID with the ID associated to the request.
    async fn handle_coll_job_req_success(version: DapVersion) {
        let t = Test::new(version);
        let task_id = &t.time_interval_task_id;
        let task_config = t.leader.unchecked_get_task_config(task_id).await;

        // Collector: Create a CollectReq.
        let collector_collect_req = CollectionReq {
            query: task_config.query_for_current_batch_window(t.now),
            agg_param: Vec::default(),
        };
        let req = t.collector_authorized_req(
            task_id,
            &task_config,
            DapMediaType::CollectReq,
            collector_collect_req.clone(),
        );

        // Leader: Handle the CollectReq received from Collector.
        let url = leader::handle_coll_job_req(&*t.leader, &req).await.unwrap();
        let WorkItem::CollectionJob {
            task_id: _,
            coll_job_id: leader_collect_id,
            batch_sel: leader_batch_sel,
            agg_param: leader_agg_param,
        } = t.leader.dequeue_work(1).await.unwrap().pop().unwrap()
        else {
            panic!("unexpected work item type");
        };

        // Check that the CollectReq sent by Collector is the same that is received by Leader.
        assert_eq!(collector_collect_req.query, leader_batch_sel.into());
        assert_eq!(
            collector_collect_req.agg_param,
            leader_agg_param.get_encoded().unwrap()
        );

        // Check that the collect_id included in the URI is the same with the one received
        // by Leader.
        let path = url.path().to_string();
        let mut router = Router::new();
        router
            .insert("/:version/collect/task/:task_id/req/:collect_id", true)
            .unwrap();
        let url_match = router.at(&path).unwrap();
        let collector_collect_id = url_match.params.get("collect_id").unwrap();
        assert_eq!(
            collector_collect_id.to_string(),
            leader_collect_id.to_base64url()
        );
    }

    async_test_versions! { handle_coll_job_req_success }

    // Test that the Leader handles queries from the Collector properly.
    async fn handle_coll_job_req_invalid_query(version: DapVersion) {
        let mut rng = thread_rng();
        let t = Test::new(version);

        // Leader expects "time_interval" query, but Collector sent "fixed_size".
        let task_config = t
            .leader
            .unchecked_get_task_config(&t.time_interval_task_id)
            .await;
        let req = t.collector_authorized_req(
            &t.time_interval_task_id,
            &task_config,
            DapMediaType::CollectReq,
            CollectionReq {
                query: Query::FixedSizeByBatchId {
                    batch_id: BatchId(rng.gen()),
                },
                agg_param: Vec::default(),
            },
        );
        assert_matches!(
            leader::handle_coll_job_req(&*t.leader, &req)
                .await
                .unwrap_err(),
            DapError::Abort(DapAbort::QueryMismatch { .. })
        );

        // Collector indicates unrecognized batch ID.
        let task_config = t
            .leader
            .unchecked_get_task_config(&t.fixed_size_task_id)
            .await;
        let req = t.collector_authorized_req(
            &t.fixed_size_task_id,
            &task_config,
            DapMediaType::CollectReq,
            CollectionReq {
                query: Query::FixedSizeByBatchId {
                    batch_id: BatchId(rng.gen()), // Unrecognized batch ID
                },
                agg_param: Vec::default(),
            },
        );
        assert_matches!(
            leader::handle_coll_job_req(&*t.leader, &req)
                .await
                .unwrap_err(),
            DapError::Abort(DapAbort::BatchInvalid { .. })
        );
    }

    async_test_versions! { handle_coll_job_req_invalid_query }

    async fn handle_upload_req(version: DapVersion) {
        let t = Test::new(version);
        let task_id = &t.time_interval_task_id;

        let report = t.gen_test_report(task_id).await;
        let req = t.gen_test_upload_req(report, task_id).await;

        leader::handle_upload_req(&*t.leader, &req)
            .await
            .expect("upload failed unexpectedly");
    }

    async_test_versions! { handle_upload_req }

    async fn e2e_time_interval(version: DapVersion) {
        let t = Test::new(version);
        let task_id = &t.time_interval_task_id;
        let task_config = t
            .leader
            .unchecked_get_task_config(&t.fixed_size_task_id)
            .await;

        // Client: Send upload request to Leader.
        let report = t.gen_test_report(task_id).await;
        leader::handle_upload_req(&*t.leader, &t.gen_test_upload_req(report, task_id).await)
            .await
            .unwrap();

        // Collector: Request result from the Leader.
        let query = task_config.query_for_current_batch_window(t.now);
        leader::handle_coll_job_req(&*t.leader, &t.gen_test_coll_job_req(query, task_id).await)
            .await
            .unwrap();

        leader::process(&*t.leader, "leader.com", 100)
            .await
            .unwrap();

        assert_metrics_include!(t.helper_registry, {
            r#"inbound_request_counter{env="test_helper",host="helper.org",type="aggregate"}"#: 1,
            r#"inbound_request_counter{env="test_helper",host="helper.org",type="collect"}"#: 1,
            r#"report_counter{env="test_helper",host="helper.org",status="aggregated"}"#: 1,
            r#"report_counter{env="test_helper",host="helper.org",status="collected"}"#: 1,
            r#"aggregation_job_counter{env="test_helper",host="helper.org",status="started"}"#: 1,
            r#"aggregation_job_counter{env="test_helper",host="helper.org",status="completed"}"#: 1,
        });
        assert_metrics_include!(t.leader_registry, {
            r#"report_counter{env="test_leader",host="leader.com",status="aggregated"}"#: 1,
            r#"report_counter{env="test_leader",host="leader.com",status="collected"}"#: 1,
        });
    }

    async_test_versions! { e2e_time_interval }

    async fn e2e_fixed_size(version: DapVersion) {
        let t = Test::new(version);
        let task_id = &t.fixed_size_task_id;

        // Client: Send upload request to Leader.
        let report = t.gen_test_report(task_id).await;
        leader::handle_upload_req(&*t.leader, &t.gen_test_upload_req(report, task_id).await)
            .await
            .unwrap();

        // Collector: Request result from the Leader.
        let query = Query::FixedSizeCurrentBatch;
        leader::handle_coll_job_req(&*t.leader, &t.gen_test_coll_job_req(query, task_id).await)
            .await
            .unwrap();

        leader::process(&*t.leader, "leader.com", 100)
            .await
            .unwrap();

        assert_metrics_include!(t.helper_registry, {
            r#"inbound_request_counter{env="test_helper",host="helper.org",type="aggregate"}"#: 1,
            r#"inbound_request_counter{env="test_helper",host="helper.org",type="collect"}"#: 1,
            r#"report_counter{env="test_helper",host="helper.org",status="aggregated"}"#: 1,
            r#"report_counter{env="test_helper",host="helper.org",status="collected"}"#: 1,
            r#"aggregation_job_counter{env="test_helper",host="helper.org",status="started"}"#: 1,
            r#"aggregation_job_counter{env="test_helper",host="helper.org",status="completed"}"#: 1,
        });
        assert_metrics_include!(t.leader_registry, {
            r#"report_counter{env="test_leader",host="leader.com",status="aggregated"}"#: 1,
            r#"report_counter{env="test_leader",host="leader.com",status="collected"}"#: 1,
        });
    }

    async_test_versions! { e2e_fixed_size }

    async fn e2e_taskprov(
        version: DapVersion,
        vdaf_config: VdafConfig,
        test_measurement: DapMeasurement,
    ) {
        let t = Test::new(version);

        let (task_config, task_id, taskprov_advertisement) = DapTaskParameters {
            version,
            min_batch_size: 1,
            query: DapQueryConfig::FixedSize {
                max_batch_size: Some(2),
            },
            vdaf: vdaf_config,
            ..Default::default()
        }
        .to_config_with_taskprov(
            b"cool task".to_vec(),
            t.now,
            &t.leader.taskprov_vdaf_verify_key_init,
            &t.leader.collector_hpke_config,
        )
        .unwrap();

        // Clients: Send upload request to Leader.
        let hpke_config_list = [
            t.leader
                .get_hpke_config_for(version, Some(&task_id))
                .await
                .unwrap()
                .clone(),
            t.helper
                .get_hpke_config_for(version, Some(&task_id))
                .await
                .unwrap()
                .clone(),
        ];
        for _ in 0..task_config.min_batch_size {
            let report = task_config
                .vdaf
                .produce_report_with_extensions(
                    &hpke_config_list,
                    t.now,
                    &task_id,
                    test_measurement.clone(),
                    vec![Extension::Taskprov],
                    task_config.version,
                )
                .unwrap();

            let req = DapRequest {
                version,
                media_type: Some(DapMediaType::Report),
                task_id: Some(task_id),
                resource: DapResource::Undefined,
                payload: report.get_encoded_with_param(&version).unwrap(),
                taskprov: Some(taskprov_advertisement.clone()),
                ..Default::default()
            };
            leader::handle_upload_req(&*t.leader, &req).await.unwrap();
        }

        // Collector: Request result from the Leader.
        let query = Query::FixedSizeCurrentBatch;
        leader::handle_coll_job_req(&*t.leader, &t.gen_test_coll_job_req(query, &task_id).await)
            .await
            .unwrap();

        leader::process(&*t.leader, "leader.com", 100)
            .await
            .unwrap();

        assert_metrics_include!(t.helper_registry, {
            r#"inbound_request_counter{env="test_helper",host="helper.org",type="aggregate"}"#: 1,
            r#"inbound_request_counter{env="test_helper",host="helper.org",type="collect"}"#: 1,
            r#"report_counter{env="test_helper",host="helper.org",status="aggregated"}"#: 1,
            r#"report_counter{env="test_helper",host="helper.org",status="collected"}"#: 1,
            r#"aggregation_job_counter{env="test_helper",host="helper.org",status="started"}"#: 1,
            r#"aggregation_job_counter{env="test_helper",host="helper.org",status="completed"}"#: 1,
        });
        assert_metrics_include!(t.leader_registry, {
            r#"report_counter{env="test_leader",host="leader.com",status="aggregated"}"#: 1,
            r#"report_counter{env="test_leader",host="leader.com",status="collected"}"#: 1,
        });
    }

    async fn e2e_taskprov_prio2(version: DapVersion) {
        e2e_taskprov(
            version,
            VdafConfig::Prio2 { dimension: 10 },
            DapMeasurement::U32Vec(vec![1; 10]),
        )
        .await;
    }

    async_test_versions! { e2e_taskprov_prio2 }

    async fn e2e_taskprov_prio3_sum_vec_field64_multiproof_hmac_sha256_aes128(version: DapVersion) {
        e2e_taskprov(
            version,
            VdafConfig::Prio3(Prio3Config::SumVecField64MultiproofHmacSha256Aes128 {
                bits: 1,
                length: 10,
                chunk_length: 2,
                num_proofs: 3,
            }),
            DapMeasurement::U64Vec(vec![1; 10]),
        )
        .await;
    }

    async_test_version! { e2e_taskprov_prio3_sum_vec_field64_multiproof_hmac_sha256_aes128, Draft09 }
    async_test_version! { e2e_taskprov_prio3_sum_vec_field64_multiproof_hmac_sha256_aes128, Latest }

    // Test multiple tasks in flight at once.
    async fn multi_task(version: DapVersion) {
        let t = Test::new(version);

        // Requests for the time-interval task.
        {
            let task_id = &t.time_interval_task_id;
            let task_config = t
                .leader
                .unchecked_get_task_config(&t.fixed_size_task_id)
                .await;

            let report = t.gen_test_report(task_id).await;
            leader::handle_upload_req(&*t.leader, &t.gen_test_upload_req(report, task_id).await)
                .await
                .unwrap();

            let query = task_config.query_for_current_batch_window(t.now);
            leader::handle_coll_job_req(&*t.leader, &t.gen_test_coll_job_req(query, task_id).await)
                .await
                .unwrap();
        }

        // Requests for the fixed-length task.
        {
            let task_id = &t.fixed_size_task_id;

            let report = t.gen_test_report(task_id).await;
            leader::handle_upload_req(&*t.leader, &t.gen_test_upload_req(report, task_id).await)
                .await
                .unwrap();

            // Collector: Request result from the Leader.
            let query = Query::FixedSizeCurrentBatch;
            leader::handle_coll_job_req(&*t.leader, &t.gen_test_coll_job_req(query, task_id).await)
                .await
                .unwrap();
        }

        leader::process(&*t.leader, "leader.com", 100)
            .await
            .unwrap();

        assert_metrics_include!(t.helper_registry, {
            r#"inbound_request_counter{env="test_helper",host="helper.org",type="aggregate"}"#: 2,
            r#"inbound_request_counter{env="test_helper",host="helper.org",type="collect"}"#: 2,
            r#"report_counter{env="test_helper",host="helper.org",status="aggregated"}"#: 2,
            r#"report_counter{env="test_helper",host="helper.org",status="collected"}"#: 2,
            r#"aggregation_job_counter{env="test_helper",host="helper.org",status="started"}"#: 2,
            r#"aggregation_job_counter{env="test_helper",host="helper.org",status="completed"}"#: 2,
        });
        assert_metrics_include!(t.leader_registry, {
            r#"report_counter{env="test_leader",host="leader.com",status="aggregated"}"#: 2,
            r#"report_counter{env="test_leader",host="leader.com",status="collected"}"#: 2,
        });
    }

    async_test_versions! { multi_task }

    // TODO(cjpatton) Test collecting the batch multiple times per the "heavy hitters" mode of
    // operation for Mastic.
    //
    // TODO(cjpatton) Create a test for "attribute based metrics" for draft09.
    #[tokio::test]
    async fn heavy_hitters() {
        let t = Test::new(DapVersion::Latest);
        let task_id = &t.heavy_hitters_task_id;
        let task_config = t
            .leader
            .unchecked_get_task_config(&t.fixed_size_task_id)
            .await;

        for i in 0..10 {
            let report = t
                .gen_test_report_for_measurement(
                    task_id,
                    DapMeasurement::Mastic {
                        input: vec![i],
                        weight: MasticWeight::Bool(true),
                    },
                )
                .await;
            leader::handle_upload_req(&*t.leader, &t.gen_test_upload_req(report, task_id).await)
                .await
                .unwrap();
        }

        // Collector: Request result from the Leader.
        let query = task_config.query_for_current_batch_window(t.now);
        let agg_param = DapAggregationParam::Mastic(
            Poplar1AggregationParam::try_from_prefixes(vec![
                IdpfInput::from_bytes(&[0]),
                IdpfInput::from_bytes(&[1]),
                IdpfInput::from_bytes(&[7]),
            ])
            .unwrap(),
        );
        leader::handle_coll_job_req(
            &*t.leader,
            &t.gen_test_coll_job_req_for_collection(query, agg_param, task_id)
                .await,
        )
        .await
        .unwrap();

        leader::process(&*t.leader, "leader.com", 100)
            .await
            .unwrap();

        assert_metrics_include!(t.helper_registry, {
            r#"inbound_request_counter{env="test_helper",host="helper.org",type="aggregate"}"#: 1,
            r#"inbound_request_counter{env="test_helper",host="helper.org",type="collect"}"#: 1,
            r#"report_counter{env="test_helper",host="helper.org",status="aggregated"}"#: 10,
            r#"report_counter{env="test_helper",host="helper.org",status="collected"}"#: 10,
            r#"aggregation_job_counter{env="test_helper",host="helper.org",status="started"}"#: 1,
            r#"aggregation_job_counter{env="test_helper",host="helper.org",status="completed"}"#: 1,
        });
        assert_metrics_include!(t.leader_registry, {
            r#"report_counter{env="test_leader",host="leader.com",status="aggregated"}"#: 10,
            r#"report_counter{env="test_leader",host="leader.com",status="collected"}"#: 10,
        });
    }
}
