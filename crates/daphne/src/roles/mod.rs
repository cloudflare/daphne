// Copyright (c) 2023 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Trait definitions for Daphne backends.

pub mod aggregator;
pub mod helper;
pub mod leader;

use crate::{
    messages::{Base64Encode, Query, TaskId, Time},
    taskprov::DapTaskConfigNeedsOptIn,
    DapAbort, DapBatchMode, DapError, DapGlobalConfig, DapRequestMeta, DapTaskConfig,
};

pub use aggregator::DapAggregator;
pub use helper::DapHelper;
pub use leader::DapLeader;

async fn check_batch(
    agg: &impl DapAggregator,
    task_config: &DapTaskConfig,
    task_id: &TaskId,
    query: &Query,
    agg_param: &[u8],
    now: Time,
    global_config: &DapGlobalConfig,
) -> Result<(), DapError> {
    // Check that the aggregation parameter is suitable for the given VDAF.
    if !task_config.vdaf.is_valid_agg_param(agg_param) {
        // TODO spec: Define this behavior.
        return Err(DapAbort::InvalidMessage {
            detail: "invalid aggregation parameter".into(),
            task_id: *task_id,
        }
        .into());
    }

    // Check that the batch boundaries are valid.
    match (&task_config.query, query) {
        (DapBatchMode::TimeInterval { .. }, Query::TimeInterval { batch_interval }) => {
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
        (DapBatchMode::LeaderSelected { .. }, Query::LeaderSelectedCurrentBatch) => (), // nothing to do
        (DapBatchMode::LeaderSelected { .. }, Query::LeaderSelectedByBatchId { batch_id }) => {
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
        _ => return Err(DapAbort::batch_mode_mismatch(task_id, &task_config.query, query).into()),
    };

    // Check that the batch does not overlap with any previously collected batch.
    if let Some(batch_sel) = query.into_batch_sel() {
        if agg.is_batch_overlapping(task_id, &batch_sel).await? {
            return Err(DapAbort::batch_overlap(task_id, query).into());
        }
    }

    Ok(())
}

async fn resolve_task_config(
    agg: &impl DapAggregator,
    req: &DapRequestMeta,
) -> Result<DapTaskConfig, DapError> {
    let task_config = if let Some(config) = agg.get_task_config_for(&req.task_id).await? {
        config
    } else {
        let taskprov_config = agg.get_taskprov_config();
        let (Some(taskprov_advertisement), Some(taskprov_config)) =
            (&req.taskprov_advertisement, taskprov_config)
        else {
            return Err(DapAbort::UnrecognizedTask {
                task_id: req.task_id,
            }
            .into());
        };
        let task_config = DapTaskConfigNeedsOptIn::try_from_taskprov_advertisement(
            req.version,
            &req.task_id,
            taskprov_advertisement.clone(),
            taskprov_config,
        )?;
        let task_config = agg.taskprov_opt_in(&req.task_id, task_config).await?;
        agg.taskprov_put(&req.task_id, task_config.clone()).await?;
        task_config
    };

    // Check whether the DAP version in the request matches the task config.
    if task_config.version != req.version {
        return Err(DapAbort::version_mismatch(req.version, task_config.version).into());
    }

    Ok(task_config)
}

#[cfg(test)]
mod test {
    use super::{aggregator, helper, leader, DapLeader};
    #[cfg(feature = "experimental")]
    use crate::vdaf::mastic::{MasticConfig, MasticWeight, MasticWeightConfig};
    use crate::{
        assert_metrics_include, async_test_versions,
        constants::DapMediaType,
        hpke::{HpkeKemId, HpkeProvider, HpkeReceiverConfig},
        messages::{
            request::RequestBody, AggregateShareReq, AggregationJobId, AggregationJobInitReq,
            AggregationJobResp, BatchId, BatchSelector, Collection, CollectionJobId, CollectionReq,
            Extension, HpkeCiphertext, Interval, PartialBatchSelector, PrepareRespVar, Query,
            Report, ReportError, TaskId, Time,
        },
        roles::{helper::HashedAggregationJobReq, leader::WorkItem, DapAggregator},
        testing::InMemoryAggregator,
        vdaf::{Prio3Config, VdafConfig},
        DapAbort, DapAggregationJobState, DapAggregationParam, DapBatchBucket, DapBatchMode,
        DapCollectionJob, DapError, DapGlobalConfig, DapMeasurement, DapRequest, DapRequestMeta,
        DapTaskConfig, DapTaskParameters, DapVersion,
    };
    use assert_matches::assert_matches;
    use prio::codec::{Encode, ParameterizedDecode};
    #[cfg(feature = "experimental")]
    use prio::idpf::IdpfInput;
    use rand::{thread_rng, Rng};
    use std::{
        collections::HashMap,
        num::{NonZeroU32, NonZeroUsize},
        sync::Arc,
        time::SystemTime,
        vec,
    };
    use url::Url;

    pub(super) struct TestData {
        pub now: Time,
        global_config: DapGlobalConfig,
        pub time_interval_task_id: TaskId,
        pub leader_selected_task_id: TaskId,
        pub expired_task_id: TaskId,
        #[cfg(feature = "experimental")]
        pub mastic_task_id: TaskId,
        helper_registry: prometheus::Registry,
        tasks: HashMap<TaskId, DapTaskConfig>,
        collector_hpke_receiver_config: HpkeReceiverConfig,
        taskprov_vdaf_verify_key_init: [u8; 32],
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
                default_num_agg_span_shards: NonZeroUsize::new(4).unwrap(),
            };

            // Task Parameters that the Leader and Helper must agree on.
            //
            // We need to use a VDAF that is compatible with all versions of DAP.
            let vdaf_config = VdafConfig::Prio2 { dimension: 10 };
            let leader_url = Url::parse("https://leader.com/v02/").unwrap();
            let helper_url = Url::parse("http://helper.org:8788/v02/").unwrap();
            let collector_hpke_receiver_config =
                HpkeReceiverConfig::gen(rng.gen(), HpkeKemId::X25519HkdfSha256).unwrap();

            // Create the task list.
            let time_interval_task_id = TaskId(rng.gen());
            let leader_selected_task_id = TaskId(rng.gen());
            let expired_task_id = TaskId(rng.gen());
            #[cfg(feature = "experimental")]
            let mastic_task_id = TaskId(rng.gen());
            let mut tasks = HashMap::new();
            tasks.insert(
                time_interval_task_id,
                DapTaskConfig {
                    version,
                    collector_hpke_config: collector_hpke_receiver_config.config.clone(),
                    leader_url: leader_url.clone(),
                    helper_url: helper_url.clone(),
                    time_precision: Self::TASK_TIME_PRECISION,
                    not_before: now,
                    not_after: now + Self::TASK_TIME_PRECISION,
                    min_batch_size: 1,
                    query: DapBatchMode::TimeInterval,
                    vdaf: vdaf_config,
                    vdaf_verify_key: vdaf_config.gen_verify_key(),
                    method: Default::default(),
                    num_agg_span_shards: global_config.default_num_agg_span_shards,
                },
            );
            tasks.insert(
                leader_selected_task_id,
                DapTaskConfig {
                    version,
                    collector_hpke_config: collector_hpke_receiver_config.config.clone(),
                    leader_url: leader_url.clone(),
                    helper_url: helper_url.clone(),
                    time_precision: Self::TASK_TIME_PRECISION,
                    not_before: now,
                    not_after: now + Self::TASK_TIME_PRECISION,
                    min_batch_size: 1,
                    query: DapBatchMode::LeaderSelected {
                        draft09_max_batch_size: match version {
                            DapVersion::Draft09 => Some(NonZeroU32::new(2).unwrap()),
                            DapVersion::Latest => None,
                        },
                    },
                    vdaf: vdaf_config,
                    vdaf_verify_key: vdaf_config.gen_verify_key(),
                    method: Default::default(),
                    num_agg_span_shards: global_config.default_num_agg_span_shards,
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
                    not_before: now,
                    not_after: now, // Expires this second
                    min_batch_size: 1,
                    query: DapBatchMode::TimeInterval,
                    vdaf: vdaf_config,
                    vdaf_verify_key: vdaf_config.gen_verify_key(),
                    method: Default::default(),
                    num_agg_span_shards: global_config.default_num_agg_span_shards,
                },
            );

            #[cfg(feature = "experimental")]
            {
                let mastic = VdafConfig::Mastic(MasticConfig {
                    bits: 8,
                    weight_config: MasticWeightConfig::Count,
                });
                tasks.insert(
                    mastic_task_id,
                    DapTaskConfig {
                        version,
                        collector_hpke_config: collector_hpke_receiver_config.config.clone(),
                        leader_url,
                        helper_url,
                        time_precision: Self::TASK_TIME_PRECISION,
                        not_before: now,
                        not_after: now + Self::TASK_TIME_PRECISION,
                        min_batch_size: 10,
                        query: DapBatchMode::TimeInterval,
                        vdaf: mastic,
                        vdaf_verify_key: mastic.gen_verify_key(),
                        method: Default::default(),
                        num_agg_span_shards: global_config.default_num_agg_span_shards,
                    },
                );
            }

            // taskprov
            let taskprov_vdaf_verify_key_init = rng.gen::<[u8; 32]>();

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
                time_interval_task_id,
                leader_selected_task_id,
                expired_task_id,
                #[cfg(feature = "experimental")]
                mastic_task_id,
                helper_registry,
                tasks,
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
                self.collector_hpke_receiver_config.config.clone(),
                &self.helper_registry,
                self.taskprov_vdaf_verify_key_init,
            ))
        }

        pub fn with_leader(self, helper: Arc<InMemoryAggregator>) -> Test {
            let leader = Arc::new(InMemoryAggregator::new_leader(
                self.tasks,
                self.global_config
                    .gen_hpke_receiver_config_list(thread_rng().gen())
                    .expect("failed to generate HPKE receiver config"),
                self.global_config,
                self.collector_hpke_receiver_config.config.clone(),
                &self.leader_registry,
                self.taskprov_vdaf_verify_key_init,
                Arc::clone(&helper),
            ));

            Test {
                now: self.now,
                leader,
                helper,
                time_interval_task_id: self.time_interval_task_id,
                leader_selected_task_id: self.leader_selected_task_id,
                expired_task_id: self.expired_task_id,
                #[cfg(feature = "experimental")]
                mastic_task_id: self.mastic_task_id,
                helper_registry: self.helper_registry,
                leader_registry: self.leader_registry,
            }
        }
    }

    pub(super) struct Test {
        now: Time,
        leader: Arc<InMemoryAggregator>,
        helper: Arc<InMemoryAggregator>,
        time_interval_task_id: TaskId,
        leader_selected_task_id: TaskId,
        expired_task_id: TaskId,
        #[cfg(feature = "experimental")]
        mastic_task_id: TaskId,
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
        ) -> DapRequest<Report> {
            let task_config = self.leader.unchecked_get_task_config(task_id).await;
            let version = task_config.version;

            DapRequest {
                meta: DapRequestMeta {
                    version,
                    media_type: Some(DapMediaType::Report),
                    task_id: *task_id,
                    ..Default::default()
                },
                resource_id: Default::default(),
                payload: report,
            }
        }

        pub async fn gen_test_coll_job_req(
            &self,
            query: Query,
            task_id: &TaskId,
        ) -> DapRequest<CollectionReq> {
            self.gen_test_coll_job_req_for_collection(query, DapAggregationParam::Empty, task_id)
                .await
        }

        pub async fn gen_test_coll_job_req_for_collection(
            &self,
            query: Query,
            agg_param: DapAggregationParam,
            task_id: &TaskId,
        ) -> DapRequest<CollectionReq> {
            let task_config = self.leader.unchecked_get_task_config(task_id).await;

            Self::collector_req(
                task_id,
                &task_config,
                DapMediaType::CollectionReq,
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
            reports: Vec<Report>,
        ) -> (DapAggregationJobState, DapRequest<AggregationJobInitReq>) {
            let mut rng = thread_rng();
            let task_config = self.leader.unchecked_get_task_config(task_id).await;
            let part_batch_sel = match task_config.query {
                DapBatchMode::TimeInterval { .. } => PartialBatchSelector::TimeInterval,
                DapBatchMode::LeaderSelected { .. } => {
                    PartialBatchSelector::LeaderSelectedByBatchId {
                        batch_id: BatchId(rng.gen()),
                    }
                }
            };

            let agg_job_id = AggregationJobId(rng.gen());

            let (leader_state, agg_job_init_req) = task_config
                .produce_agg_job_req(
                    &*self.leader.hpke_receiver_config_list,
                    self.leader.valid_report_time_range(),
                    task_id,
                    &part_batch_sel,
                    &agg_param,
                    reports.into_iter(),
                    self.leader.metrics(),
                )
                .unwrap();

            (
                leader_state,
                Self::leader_req(
                    task_id,
                    &task_config,
                    agg_job_id,
                    DapMediaType::AggregationJobInitReq,
                    agg_job_init_req,
                ),
            )
        }

        pub async fn gen_test_report(&self, task_id: &TaskId) -> Report {
            // Construct report. We expect the VDAF to be Prio2 because it's supported in all
            // versions of DAP. In the future we might want to test multiple different VDAFs.
            let task_config = self.leader.unchecked_get_task_config(task_id).await;
            assert_matches!(task_config.vdaf, VdafConfig::Prio2 { dimension: 10 });

            self.gen_test_report_for_measurement(task_id, DapMeasurement::U32Vec(vec![1; 10]))
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

        pub fn leader_req<B: RequestBody>(
            task_id: &TaskId,
            task_config: &DapTaskConfig,
            agg_job_id: B::ResourceId,
            media_type: DapMediaType,
            payload: B,
        ) -> DapRequest<B> {
            DapRequest {
                meta: DapRequestMeta {
                    version: task_config.version,
                    media_type: Some(media_type),
                    task_id: *task_id,
                    ..Default::default()
                },
                resource_id: agg_job_id,
                payload,
            }
        }

        pub fn collector_req(
            task_id: &TaskId,
            task_config: &DapTaskConfig,
            media_type: DapMediaType,
            payload: CollectionReq,
        ) -> DapRequest<CollectionReq> {
            let mut rng = thread_rng();
            let coll_job_id = CollectionJobId(rng.gen());

            DapRequest {
                meta: DapRequestMeta {
                    version: task_config.version,
                    media_type: Some(media_type),
                    task_id: *task_id,
                    ..Default::default()
                },
                resource_id: coll_job_id,
                payload,
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

        // Helper expects "time_interval" query, but Leader indicates "leader_selected".
        let req = Test::leader_req(
            task_id,
            &task_config,
            agg_job_id,
            DapMediaType::AggregationJobInitReq,
            HashedAggregationJobReq::from_aggregation_req(
                version,
                AggregationJobInitReq {
                    agg_param: Vec::default(),
                    part_batch_sel: PartialBatchSelector::LeaderSelectedByBatchId {
                        batch_id: BatchId(rng.gen()),
                    },
                    prep_inits: Vec::default(),
                },
            ),
        );
        assert_matches!(
            helper::handle_agg_job_init_req(&*t.helper, req, Default::default())
                .await
                .unwrap_err(),
            DapError::Abort(DapAbort::BatchModeMismatch { .. })
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
    //        assert_eq!(agg_job_resp.prep_resps.len(), 1);
    //        assert_matches!(
    //            agg_job_resp.prep_resps[0].var,
    //            PrepareRespVar::Reject(ReportError::TaskExpired)
    //        );
    //
    //        assert_eq!(t.helper.audit_log.invocations(), 1);
    //    }
    //
    //    async_test_versions! { handle_agg_job_req_init_expired_task }
    #[tokio::test]
    async fn handle_hpke_config_req_unrecognized_task_draft09() {
        let t = Test::new(DapVersion::Draft09);
        let mut rng = thread_rng();
        let task_id = TaskId(rng.gen());

        assert_eq!(
            aggregator::handle_hpke_config_req(&*t.leader, DapVersion::Draft09, Some(task_id))
                .await
                .unwrap_err(),
            DapError::Abort(DapAbort::UnrecognizedTask { task_id })
        );
    }

    #[tokio::test]
    async fn handle_hpke_config_req_task_latest() {
        let t = Test::new(DapVersion::Latest);
        let mut rng = thread_rng();
        let task_id = TaskId(rng.gen());

        assert_eq!(
            aggregator::handle_hpke_config_req(&*t.leader, DapVersion::Latest, Some(task_id))
                .await
                .unwrap_err(),
            DapError::Abort(DapAbort::BadRequest(
                "Task ID may not be specified in draft 12 or later".to_string()
            ))
        );
    }

    async fn handle_hpke_config_req_missing_task_id(version: DapVersion) {
        let t = Test::new(version);

        // An Aggregator is permitted to abort an HPKE config request if the task ID is missing. Note
        // that Daphne-Workder does not implement this behavior. Instead it returns the HPKE config
        // used for all tasks.
        assert_matches!(
            aggregator::handle_hpke_config_req(&*t.leader, version, None).await,
            Err(DapError::Abort(DapAbort::MissingTaskId))
        );
    }

    async_test_versions! { handle_hpke_config_req_missing_task_id }

    // Test that the Helper handles the batch selector sent from the Leader properly.
    async fn handle_agg_share_req_invalid_batch_sel(version: DapVersion) {
        let mut rng = thread_rng();
        let t = Test::new(version);

        // Helper expects "time_interval" query, but Leader sent "leader_selected".
        let task_config = t
            .leader
            .unchecked_get_task_config(&t.time_interval_task_id)
            .await;
        let req = Test::leader_req(
            &t.time_interval_task_id,
            &task_config,
            (),
            DapMediaType::AggregateShareReq,
            AggregateShareReq {
                batch_sel: BatchSelector::LeaderSelectedByBatchId {
                    batch_id: BatchId(rng.gen()),
                },
                agg_param: Vec::default(),
                report_count: 0,
                checksum: [0; 32],
            },
        );
        assert_matches!(
            helper::handle_agg_share_req(&*t.helper, req)
                .await
                .unwrap_err(),
            DapError::Abort(DapAbort::BatchModeMismatch { .. })
        );

        // Leader sends aggregate share request for unrecognized batch ID.
        let task_config = t
            .leader
            .unchecked_get_task_config(&t.leader_selected_task_id)
            .await;
        let req = Test::leader_req(
            &t.leader_selected_task_id,
            &task_config,
            (),
            DapMediaType::AggregateShareReq,
            AggregateShareReq {
                batch_sel: BatchSelector::LeaderSelectedByBatchId {
                    batch_id: BatchId(rng.gen()), // Unrecognized batch ID
                },
                agg_param: Vec::default(),
                report_count: 0,
                checksum: [0; 32],
            },
        );
        assert_matches!(
            helper::handle_agg_share_req(&*t.helper, req)
                .await
                .unwrap_err(),
            DapError::Abort(DapAbort::BatchInvalid { .. })
        );
    }

    async_test_versions! { handle_agg_share_req_invalid_batch_sel }

    async fn handle_agg_job_req_failure_hpke_decrypt_error(version: DapVersion) {
        let t = Test::new(version);
        let task_id = &t.time_interval_task_id;

        let mut report = t.gen_test_report(task_id).await;
        report.encrypted_input_shares[1].payload[0] ^= 0xff; // Cause decryption to fail
        let (_, req) = t
            .gen_test_agg_job_init_req(task_id, DapAggregationParam::Empty, vec![report])
            .await;

        // Get AggregationJobResp and then extract the prep_resp data from inside.
        let agg_job_resp = AggregationJobResp::get_decoded_with_param(
            &version,
            &helper::handle_agg_job_init_req(
                &*t.helper,
                req.map(|req| HashedAggregationJobReq::from_aggregation_req(version, req)),
                Default::default(),
            )
            .await
            .unwrap()
            .payload,
        )
        .unwrap();
        let prep_resp = agg_job_resp.unwrap_ready().prep_resps.remove(0);

        // Expect failure due to invalid ciphertext.
        assert_matches!(
            prep_resp.var,
            PrepareRespVar::Reject(ReportError::HpkeDecryptError)
        );
    }

    async_test_versions! { handle_agg_job_req_failure_hpke_decrypt_error }

    #[tokio::test]
    async fn handle_unknown_public_extensions() {
        let version = DapVersion::Latest;
        let t = Test::new(version);
        let task_id = &t.time_interval_task_id;
        let task_config = t.leader.unchecked_get_task_config(task_id).await;

        // Construct HPKE config list.
        let hpke_config_list = [
            t.leader
                .get_hpke_config_for(task_config.version, Some(task_id))
                .await
                .unwrap()
                .clone(),
            t.helper
                .get_hpke_config_for(task_config.version, Some(task_id))
                .await
                .unwrap()
                .clone(),
        ];

        let report = task_config
            .vdaf
            .produce_report_with_extensions(
                &hpke_config_list,
                t.now,
                task_id,
                DapMeasurement::U32Vec(vec![1; 10]),
                Some(vec![Extension::NotImplemented {
                    typ: 0x01,
                    payload: vec![0x01],
                }]),
                vec![],
                task_config.version,
            )
            .unwrap();

        let req = DapRequest {
            meta: DapRequestMeta {
                version: task_config.version,
                media_type: Some(DapMediaType::Report),
                task_id: *task_id,
                ..Default::default()
            },
            resource_id: (),
            payload: report,
        };
        assert_eq!(
            leader::handle_upload_req(&*t.leader, req).await,
            Err(DapError::Abort(DapAbort::UnsupportedExtension {
                detail: "[1]".into(),
                task_id: *task_id
            }))
        );
    }

    #[tokio::test]
    #[should_panic(expected = "assertion `left == right` failed\n  left: Latest\n right: Draft09")]
    async fn handle_public_extensions_draft09() {
        let version = DapVersion::Draft09;
        let t = Test::new(version);
        let task_id = &t.time_interval_task_id;
        let task_config = t.leader.unchecked_get_task_config(task_id).await;
        let mut report = t.gen_test_report(task_id).await;
        // This change breaks the HPKE decryption, but triggers a failure
        // before the HPKE data is checked.
        report.report_metadata.public_extensions = Some(vec![]);

        let req = DapRequest {
            meta: DapRequestMeta {
                version: task_config.version,
                media_type: Some(DapMediaType::Report),
                task_id: *task_id,
                ..Default::default()
            },
            resource_id: (),
            payload: report,
        };
        _ = leader::handle_upload_req(&*t.leader, req).await;
    }

    async fn handle_agg_job_req_prep_resp_continue(version: DapVersion) {
        let t = Test::new(version);
        let task_id = &t.time_interval_task_id;

        let report = t.gen_test_report(task_id).await;
        let (_, req) = t
            .gen_test_agg_job_init_req(task_id, DapAggregationParam::Empty, vec![report])
            .await;

        // Get AggregationJobResp and then extract the prep_resp data from inside.
        let agg_job_resp = AggregationJobResp::get_decoded_with_param(
            &version,
            &helper::handle_agg_job_init_req(
                &*t.helper,
                req.map(|req| HashedAggregationJobReq::from_aggregation_req(version, req)),
                Default::default(),
            )
            .await
            .unwrap()
            .payload,
        )
        .unwrap();
        let prep_resp = agg_job_resp.unwrap_ready().prep_resps.remove(0);

        // Expect success due to valid ciphertext.
        assert_matches!(prep_resp.var, PrepareRespVar::Continue(_));
    }

    async_test_versions! { handle_agg_job_req_prep_resp_continue }

    async fn handle_agg_job_req_failure_report_replayed(version: DapVersion) {
        let t = Test::new(version);
        let task_id = &t.time_interval_task_id;
        let task_config = t.helper.unchecked_get_task_config(task_id).await;

        let report = t.gen_test_report(task_id).await;
        let req = t.gen_test_upload_req(report.clone(), task_id).await;
        leader::handle_upload_req(&*t.leader, req).await.unwrap();

        let query = task_config.query_for_current_batch_window(t.now);
        let req = t.gen_test_coll_job_req(query, task_id).await;
        leader::handle_coll_job_req(&*t.leader, &req).await.unwrap();

        // Add dummy data to report store backend. This is done in a new scope so that the lock on the
        // report store is released before running the test.
        {
            let bucket = DapBatchBucket::TimeInterval {
                batch_window: task_config.quantized_time_lower_bound(t.now),
                shard: report
                    .report_metadata
                    .id
                    .shard(task_config.num_agg_span_shards),
            };
            let mut agg_store = t.helper.agg_store.lock().unwrap();
            agg_store
                .for_bucket(task_id, &bucket)
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
        leader::handle_upload_req(&*t.leader, req).await.unwrap();

        // Add mock data to the aggreagte store backend. This is done in its own scope so that the lock
        // is released before running the test. Otherwise the test will deadlock.
        {
            let bucket = DapBatchBucket::TimeInterval {
                batch_window: task_config.quantized_time_lower_bound(t.now),
                shard: report
                    .report_metadata
                    .id
                    .shard(task_config.num_agg_span_shards),
            };
            let mut agg_store = t.helper.agg_store.lock().unwrap();
            agg_store.for_bucket(task_id, &bucket).collected = true;
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
            meta: DapRequestMeta {
                version: task_config.version,
                media_type: Some(DapMediaType::Report),
                task_id: TaskId([0; 32]),
                ..Default::default()
            },
            resource_id: (),
            payload: report_invalid_task_id,
        };

        // Expect failure due to invalid task ID in report.
        assert_eq!(
            leader::handle_upload_req(&*t.leader, req).await,
            Err(DapError::Abort(DapAbort::UnrecognizedTask {
                task_id: TaskId([0; 32])
            }))
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
            meta: DapRequestMeta {
                version: task_config.version,
                media_type: Some(DapMediaType::Report),
                task_id: *task_id,
                ..Default::default()
            },
            resource_id: (),
            payload: report.clone(),
        };

        assert_eq!(
            leader::handle_upload_req(&*t.leader, req)
                .await
                .unwrap_err(),
            DapError::Abort(DapAbort::ReportTooLate {
                report_id: report.report_metadata.id
            })
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
            leader::handle_upload_req(&*t.leader, req).await.unwrap();
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
        let req = Test::collector_req(
            task_id,
            &task_config,
            DapMediaType::CollectionReq,
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
        let req = Test::collector_req(
            task_id,
            &task_config,
            DapMediaType::CollectionReq,
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
        let req = Test::collector_req(
            task_id,
            &task_config,
            DapMediaType::CollectionReq,
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
        let req = Test::collector_req(
            task_id,
            &task_config,
            DapMediaType::CollectionReq,
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
        let req = Test::collector_req(
            task_id,
            &task_config,
            DapMediaType::CollectionReq,
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
        leader::handle_coll_job_req(&*t.leader, &req).await.unwrap();
    }

    async_test_versions! { handle_coll_job_req_succeed_max_batch_interval }

    async fn handle_coll_job_req_fail_overlapping_batch_interval(version: DapVersion) {
        let t = Test::new(version);
        let task_id = &t.time_interval_task_id;
        let task_config = t.leader.unchecked_get_task_config(task_id).await;

        let report = t.gen_test_report(task_id).await;
        let req = t.gen_test_upload_req(report.clone(), task_id).await;
        leader::handle_upload_req(&*t.leader, req).await.unwrap();

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
        let task_id = &t.leader_selected_task_id;

        let req = t
            .gen_test_coll_job_req(
                Query::LeaderSelectedByBatchId {
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
        let req = Test::collector_req(
            task_id,
            &task_config,
            DapMediaType::CollectionReq,
            collector_collect_req.clone(),
        );

        // Leader: Handle the CollectReq received from Collector.
        leader::handle_coll_job_req(&*t.leader, &req).await.unwrap();
        let WorkItem::CollectionJob {
            task_id: _,
            coll_job_id: _,
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
    }

    async_test_versions! { handle_coll_job_req_success }

    // Test that the Leader handles queries from the Collector properly.
    async fn handle_coll_job_req_invalid_query(version: DapVersion) {
        let mut rng = thread_rng();
        let t = Test::new(version);

        // Leader expects "time_interval" query, but Collector sent "leader_selected".
        let task_config = t
            .leader
            .unchecked_get_task_config(&t.time_interval_task_id)
            .await;
        let req = Test::collector_req(
            &t.time_interval_task_id,
            &task_config,
            DapMediaType::CollectionReq,
            CollectionReq {
                query: Query::LeaderSelectedByBatchId {
                    batch_id: BatchId(rng.gen()),
                },
                agg_param: Vec::default(),
            },
        );
        assert_matches!(
            leader::handle_coll_job_req(&*t.leader, &req)
                .await
                .unwrap_err(),
            DapError::Abort(DapAbort::BatchModeMismatch { .. })
        );

        // Collector indicates unrecognized batch ID.
        let task_config = t
            .leader
            .unchecked_get_task_config(&t.leader_selected_task_id)
            .await;
        let req = Test::collector_req(
            &t.leader_selected_task_id,
            &task_config,
            DapMediaType::CollectionReq,
            CollectionReq {
                query: Query::LeaderSelectedByBatchId {
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

        leader::handle_upload_req(&*t.leader, req)
            .await
            .expect("upload failed unexpectedly");
    }

    async_test_versions! { handle_upload_req }

    async fn e2e_time_interval(version: DapVersion) {
        let t = Test::new(version);
        let task_id = &t.time_interval_task_id;
        let task_config = t
            .leader
            .unchecked_get_task_config(&t.leader_selected_task_id)
            .await;

        // Client: Send upload request to Leader.
        let report = t.gen_test_report(task_id).await;
        leader::handle_upload_req(&*t.leader, t.gen_test_upload_req(report, task_id).await)
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

    async fn e2e_leader_selected(version: DapVersion) {
        let t = Test::new(version);
        let task_id = &t.leader_selected_task_id;

        // Client: Send upload request to Leader.
        let report = t.gen_test_report(task_id).await;
        leader::handle_upload_req(&*t.leader, t.gen_test_upload_req(report, task_id).await)
            .await
            .unwrap();

        // Collector: Request result from the Leader.
        let query = Query::LeaderSelectedCurrentBatch;
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

    async_test_versions! { e2e_leader_selected }

    async fn e2e_taskprov(
        version: DapVersion,
        vdaf_config: VdafConfig,
        test_measurement: DapMeasurement,
    ) {
        let t = Test::new(version);

        let (task_config, task_id, taskprov_advertisement) = DapTaskParameters {
            version,
            min_batch_size: 1,
            query: DapBatchMode::LeaderSelected {
                draft09_max_batch_size: match version {
                    DapVersion::Draft09 => Some(NonZeroU32::new(2).unwrap()),
                    DapVersion::Latest => None,
                },
            },
            vdaf: vdaf_config,
            ..Default::default()
        }
        .to_config_with_taskprov(
            b"cool task".to_vec(),
            t.now,
            t.leader.get_taskprov_config().unwrap(),
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
                    match version {
                        DapVersion::Draft09 => None,
                        DapVersion::Latest => Some(vec![]),
                    },
                    vec![Extension::Taskprov],
                    task_config.version,
                )
                .unwrap();

            let req = DapRequest {
                meta: DapRequestMeta {
                    version,
                    media_type: Some(DapMediaType::Report),
                    task_id,
                    taskprov_advertisement: Some(taskprov_advertisement.clone()),
                },
                resource_id: (),
                payload: report,
            };
            leader::handle_upload_req(&*t.leader, req).await.unwrap();
        }

        // Collector: Request result from the Leader.
        let query = Query::LeaderSelectedCurrentBatch;
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

    #[tokio::test]
    async fn e2e_taskprov_prio3_draft09_sum_vec_field64_multiproof_hmac_sha256_aes128_draft09() {
        e2e_taskprov(
            DapVersion::Draft09,
            VdafConfig::Prio3(
                Prio3Config::Draft09SumVecField64MultiproofHmacSha256Aes128 {
                    bits: 1,
                    length: 10,
                    chunk_length: 2,
                    num_proofs: 3,
                },
            ),
            DapMeasurement::U64Vec(vec![1; 10]),
        )
        .await;
    }

    #[tokio::test]
    async fn e2e_taskprov_pine32_hmac_sha256_aes128_draft09() {
        use crate::{pine::PineParam, vdaf::pine::PineConfig};
        e2e_taskprov(
            DapVersion::Draft09,
            VdafConfig::Pine(PineConfig::Field32HmacSha256Aes128 {
                param: PineParam {
                    norm_bound: 16,
                    dimension: 10,
                    frac_bits: 4,
                    chunk_len: 10,
                    chunk_len_sq_norm_equal: 10,
                    num_proofs: 5,
                    num_proofs_sq_norm_equal: 1,
                    num_wr_tests: 100,
                    num_wr_successes: 100,
                },
            }),
            DapMeasurement::F64Vec(vec![0.0; 10]),
        )
        .await;
    }

    #[tokio::test]
    async fn e2e_taskprov_pine64_hmac_sha256_aes128_draft09() {
        use crate::{pine::PineParam, vdaf::pine::PineConfig};
        e2e_taskprov(
            DapVersion::Draft09,
            VdafConfig::Pine(PineConfig::Field64HmacSha256Aes128 {
                param: PineParam {
                    norm_bound: 16,
                    dimension: 10,
                    frac_bits: 4,
                    chunk_len: 10,
                    chunk_len_sq_norm_equal: 10,
                    num_proofs: 2,
                    num_proofs_sq_norm_equal: 1,
                    num_wr_tests: 100,
                    num_wr_successes: 100,
                },
            }),
            DapMeasurement::F64Vec(vec![0.0; 10]),
        )
        .await;
    }

    #[tokio::test]
    async fn leader_upload_taskprov_public() {
        let version = DapVersion::Latest;
        let t = Test::new(DapVersion::Latest);

        let (task_config, task_id, taskprov_advertisement) = DapTaskParameters {
            version,
            min_batch_size: 1,
            query: DapBatchMode::LeaderSelected {
                draft09_max_batch_size: None,
            },
            ..Default::default()
        }
        .to_config_with_taskprov(
            b"cool task".to_vec(),
            t.now,
            t.leader.get_taskprov_config().unwrap(),
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
                    t.now + 1,
                    &task_id,
                    DapMeasurement::U32Vec(vec![1; 10]),
                    Some(vec![Extension::Taskprov]),
                    vec![],
                    version,
                )
                .unwrap();
            let req = DapRequest {
                meta: DapRequestMeta {
                    version,
                    media_type: Some(DapMediaType::Report),
                    task_id,
                    taskprov_advertisement: Some(taskprov_advertisement.clone()),
                },
                resource_id: (),
                payload: report,
            };
            leader::handle_upload_req(&*t.leader, req).await.unwrap();
        }
        // Collector: Request result from the Leader.
        let query = Query::LeaderSelectedCurrentBatch;
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

    #[tokio::test]
    async fn leader_upload_taskprov_public_extension_errors() {
        let version = DapVersion::Latest;
        let t = Test::new(DapVersion::Latest);

        let (task_config, task_id, taskprov_advertisement) = DapTaskParameters {
            version,
            min_batch_size: 1,
            query: DapBatchMode::LeaderSelected {
                draft09_max_batch_size: None,
            },
            ..Default::default()
        }
        .to_config_with_taskprov(
            b"cool task".to_vec(),
            t.now,
            t.leader.get_taskprov_config().unwrap(),
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

        let report = task_config
            .vdaf
            .produce_report_with_extensions(
                &hpke_config_list,
                t.now + 1,
                &task_id,
                DapMeasurement::U32Vec(vec![1; 10]),
                Some(vec![Extension::Taskprov, Extension::Taskprov]),
                vec![],
                version,
            )
            .unwrap();
        let req = DapRequest {
            meta: DapRequestMeta {
                version,
                media_type: Some(DapMediaType::Report),
                task_id,
                taskprov_advertisement: Some(taskprov_advertisement.clone()),
            },
            resource_id: (),
            payload: report,
        };
        assert_eq!(
            DapError::Abort(DapAbort::InvalidMessage {
                detail: "Repeated public extension".into(),
                task_id,
            }),
            leader::handle_upload_req(&*t.leader, req)
                .await
                .unwrap_err()
        );

        let report = task_config
            .vdaf
            .produce_report_with_extensions(
                &hpke_config_list,
                t.now + 1,
                &task_id,
                DapMeasurement::U32Vec(vec![1; 10]),
                Some(vec![
                    Extension::Taskprov,
                    Extension::NotImplemented {
                        typ: 14,
                        payload: b"Ignore".into(),
                    },
                    Extension::NotImplemented {
                        typ: 15,
                        payload: b"Ignore".into(),
                    },
                ]),
                vec![],
                version,
            )
            .unwrap();
        let req = DapRequest {
            meta: DapRequestMeta {
                version,
                media_type: Some(DapMediaType::Report),
                task_id,
                taskprov_advertisement: Some(taskprov_advertisement.clone()),
            },
            resource_id: (),
            payload: report,
        };

        assert_eq!(
            DapError::Abort(DapAbort::unsupported_extension(&task_id, &[14, 15]).unwrap()),
            leader::handle_upload_req(&*t.leader, req)
                .await
                .unwrap_err()
        );
    }

    #[tokio::test]
    async fn leader_upload_taskprov_in_public_and_private_extensions() {
        let version = DapVersion::Latest;
        let t = Test::new(DapVersion::Latest);

        let (task_config, task_id, taskprov_advertisement) = DapTaskParameters {
            version,
            min_batch_size: 1,
            query: DapBatchMode::LeaderSelected {
                draft09_max_batch_size: None,
            },
            ..Default::default()
        }
        .to_config_with_taskprov(
            b"cool task".to_vec(),
            t.now,
            t.leader.get_taskprov_config().unwrap(),
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
                    t.now + 1,
                    &task_id,
                    DapMeasurement::U32Vec(vec![1; 10]),
                    Some(vec![Extension::Taskprov]),
                    vec![Extension::Taskprov],
                    version,
                )
                .unwrap();
            let req = DapRequest {
                meta: DapRequestMeta {
                    version,
                    media_type: Some(DapMediaType::Report),
                    task_id,
                    taskprov_advertisement: Some(taskprov_advertisement.clone()),
                },
                resource_id: (),
                payload: report,
            };
            leader::handle_upload_req(&*t.leader, req).await.unwrap();
        }
        // Collector: Request result from the Leader.
        let query = Query::LeaderSelectedCurrentBatch;
        leader::handle_coll_job_req(&*t.leader, &t.gen_test_coll_job_req(query, &task_id).await)
            .await
            .unwrap();

        leader::process(&*t.leader, "leader.com", 100)
            .await
            .unwrap();

        assert_metrics_include!(t.leader_registry, {
            r#"report_counter{env="test_leader",host="leader.com",status="rejected_invalid_message"}"#: 1,
            r#"inbound_request_counter{env="test_leader",host="leader.com",type="upload"}"#: 1,
        });
    }

    // Test multiple tasks in flight at once.
    async fn multi_task(version: DapVersion) {
        let t = Test::new(version);

        // Requests for the time-interval task.
        {
            let task_id = &t.time_interval_task_id;
            let task_config = t
                .leader
                .unchecked_get_task_config(&t.leader_selected_task_id)
                .await;

            let report = t.gen_test_report(task_id).await;
            leader::handle_upload_req(&*t.leader, t.gen_test_upload_req(report, task_id).await)
                .await
                .unwrap();

            let query = task_config.query_for_current_batch_window(t.now);
            leader::handle_coll_job_req(&*t.leader, &t.gen_test_coll_job_req(query, task_id).await)
                .await
                .unwrap();
        }

        // Requests for the fixed-length task.
        {
            let task_id = &t.leader_selected_task_id;

            let report = t.gen_test_report(task_id).await;
            leader::handle_upload_req(&*t.leader, t.gen_test_upload_req(report, task_id).await)
                .await
                .unwrap();

            // Collector: Request result from the Leader.
            let query = Query::LeaderSelectedCurrentBatch;
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

    #[cfg(feature = "experimental")]
    #[tokio::test]
    async fn mastic() {
        use prio::vdaf::mastic::MasticAggregationParam;

        let t = Test::new(DapVersion::Latest);
        let task_id = &t.mastic_task_id;
        let task_config = t
            .leader
            .unchecked_get_task_config(&t.leader_selected_task_id)
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
            leader::handle_upload_req(&*t.leader, t.gen_test_upload_req(report, task_id).await)
                .await
                .unwrap();
        }

        // Collector: Request result from the Leader.
        let query = task_config.query_for_current_batch_window(t.now);
        let agg_param = DapAggregationParam::Mastic(
            MasticAggregationParam::new(
                vec![
                    IdpfInput::from_bytes(&[0]),
                    IdpfInput::from_bytes(&[1]),
                    IdpfInput::from_bytes(&[7]),
                ],
                true,
            )
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
