// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Implementation of the leader side of the protocol

use crate::config::DaphneWorker;
use async_trait::async_trait;
use daphne::{
    auth::BearerTokenProvider,
    constants::DapMediaType,
    error::DapAbort,
    fatal_error,
    messages::{
        Base64Encode, Collection, CollectionJobId, CollectionReq, PartialBatchSelector, Report,
        TaskId, TransitionFailure,
    },
    roles::{DapAuthorizedSender, DapLeader},
    DapCollectJob, DapError, DapQueryConfig, DapRequest, DapResponse, DapTaskConfig,
};
use daphne_service_utils::durable_requests::bindings::{
    BatchCount, CollectQueueRequest, DurableMethod, LeaderAggJobQueue, LeaderBatchQueue,
    LeaderColJobQueue, PendingReport, ReportsPending, ReportsPendingResult,
};
use daphne_service_utils::{auth::DaphneAuth, DaphneServiceReportSelector};
use prio::codec::{ParameterizedDecode, ParameterizedEncode};
use std::collections::HashMap;
use tracing::debug;
use url::Url;

#[async_trait(?Send)]
impl DapAuthorizedSender<DaphneAuth> for DaphneWorker<'_> {
    async fn authorize(
        &self,
        task_id: &TaskId,
        task_config: &DapTaskConfig,
        media_type: &DapMediaType,
        _payload: &[u8],
    ) -> std::result::Result<DaphneAuth, DapError> {
        Ok(DaphneAuth {
            bearer_token: Some(
                self.authorize_with_bearer_token(task_id, task_config, media_type)
                    .await?
                    .value()
                    .clone(),
            ),
            // TODO Consider adding support for authorizing the request with TLS client
            // certificates: https://developers.cloudflare.com/workers/runtime-apis/mtls/
            cf_tls_client_auth: None,
        })
    }
}

#[async_trait(?Send)]
impl<'srv> DapLeader<DaphneAuth> for DaphneWorker<'srv> {
    type ReportSelector = DaphneServiceReportSelector;

    async fn put_report(
        &self,
        report: &Report,
        task_id: &TaskId,
    ) -> std::result::Result<(), DapError> {
        let task_config = self.try_get_task_config(task_id).await?;
        let task_id_hex = task_id.to_hex();
        let version = task_config.as_ref().version;
        let pending_report = PendingReport {
            version,
            task_id: *task_id,
            report_hex: hex::encode(report.get_encoded_with_param(&version)),
        };
        let config = self.config();
        let durable_name = ReportsPending::name((
            task_config.as_ref(),
            &task_id_hex,
            &report.report_metadata.id,
            report.report_metadata.time,
            &config.report_shard_key,
            config.report_shard_count,
            config.report_storage_epoch_duration,
        ))
        .unwrap_from_name();
        let res: ReportsPendingResult = self
            .durable()
            .post(
                ReportsPending::BINDING,
                ReportsPending::Put.to_uri(),
                durable_name,
                &pending_report,
            )
            .await
            .map_err(|e| fatal_error!(err = ?e))?;

        match res {
            ReportsPendingResult::Ok => Ok(()),
            ReportsPendingResult::ErrReportExists => {
                // NOTE This check for report replay is not definitive. It's possible for two
                // reports with the same ID to appear in two different ReportsPending instances.
                // The definitive check is performed by DapAggregator::check_early_reject(), which
                // tracks all report IDs consumed for the task in ReportsProcessed. This check
                // would be too expensive to do during the upload sub-protocol.
                Err(DapError::Transition(TransitionFailure::ReportReplayed))
            }
        }
    }

    async fn get_reports(
        &self,
        report_sel: &Self::ReportSelector,
    ) -> std::result::Result<HashMap<TaskId, HashMap<PartialBatchSelector, Vec<Report>>>, DapError>
    {
        let durable = self.durable();
        // Read at most `report_sel.max_buckets` buckets from the agg job queue. The result is ordered
        // from oldest to newest.
        //
        // NOTE There is only one agg job queue for now (`queue_num == 0`). In the future, work
        // will be sharded across multiple queues.
        let durable_name = LeaderAggJobQueue::name(0).unwrap_from_name();
        let res: Vec<String> = durable
            .post(
                LeaderAggJobQueue::BINDING,
                LeaderAggJobQueue::Get.to_uri(),
                durable_name,
                &report_sel.max_agg_jobs,
            )
            .await
            .map_err(|e| fatal_error!(err = ?e))?;

        // Drain at most `report_sel.max_reports` from each ReportsPending instance and group them
        // by task.
        //
        // TODO Figure out if we can safely handle each instance in parallel.
        let mut reports_per_task: HashMap<TaskId, Vec<Report>> = HashMap::new();
        for reports_pending_id_hex in res {
            let reports_from_durable: Vec<PendingReport> = durable
                .post_by_id_hex(
                    ReportsPending::BINDING,
                    ReportsPending::Get.to_uri(),
                    reports_pending_id_hex,
                    &report_sel.max_reports,
                )
                .await
                .map_err(|e| fatal_error!(err = ?e))?;

            for pending_report in reports_from_durable {
                let report_bytes = hex::decode(&pending_report.report_hex)
                    .map_err(|e| DapAbort::from_hex_error(e, pending_report.task_id))?;

                let version = self
                    .try_get_task_config(&pending_report.task_id)
                    .await?
                    .as_ref()
                    .version;
                let report = Report::get_decoded_with_param(&version, &report_bytes)
                    .map_err(|e| DapAbort::from_codec_error(e, pending_report.task_id))?;
                if let Some(reports) = reports_per_task.get_mut(&pending_report.task_id) {
                    reports.push(report);
                } else {
                    reports_per_task.insert(pending_report.task_id, vec![report]);
                }
            }
        }

        let mut reports_per_task_part: HashMap<TaskId, HashMap<PartialBatchSelector, Vec<Report>>> =
            HashMap::new();
        for (task_id, mut reports) in reports_per_task {
            let task_config = self
                .get_task_config(&task_id)
                .await
                .map_err(|e| fatal_error!(err = ?e))?
                .ok_or_else(|| fatal_error!(err = "unrecognized task"))?;
            let task_id_hex = task_config.key().to_hex();
            let reports_per_part = reports_per_task_part.entry(*task_config.key()).or_default();
            match task_config.as_ref().query {
                DapQueryConfig::TimeInterval => {
                    reports_per_part.insert(PartialBatchSelector::TimeInterval, reports);
                }
                DapQueryConfig::FixedSize { .. } => {
                    let num_unassigned = reports.len();
                    let durable_name =
                        LeaderBatchQueue::name((task_config.as_ref().version, &task_id_hex))
                            .unwrap_from_name();
                    let batch_assignments: Vec<BatchCount> = durable
                        .post(
                            LeaderBatchQueue::BINDING,
                            LeaderBatchQueue::Assign.to_uri(),
                            durable_name,
                            &(task_config.as_ref().min_batch_size, num_unassigned),
                        )
                        .await
                        .map_err(|e| fatal_error!(err = ?e))?;
                    for batch_count in batch_assignments {
                        let BatchCount {
                            batch_id,
                            report_count,
                        } = batch_count;
                        reports_per_part.insert(
                            PartialBatchSelector::FixedSizeByBatchId { batch_id },
                            reports.drain(..report_count).collect(),
                        );
                    }
                    if !reports.is_empty() {
                        return Err(fatal_error!(
                            err = "LeaderBatchQueue returned the wrong number of reports:",
                            got = reports.len() + num_unassigned,
                            want = num_unassigned,
                        ));
                    }
                }
            };
        }

        for (task_id, reports) in &reports_per_task_part {
            let mut report_count = 0;
            for reports in reports.values() {
                report_count += reports.len();
            }
            debug!(
                "got {} reports for task {}",
                report_count,
                task_id.to_base64url()
            );
        }
        Ok(reports_per_task_part)
    }

    async fn init_collect_job(
        &self,
        task_id: &TaskId,
        collect_job_id: &Option<CollectionJobId>,
        collect_req: &CollectionReq,
    ) -> std::result::Result<worker::Url, DapError> {
        let task_config = self.try_get_task_config(task_id).await?;
        // Try to put the request into collection job queue. If the request is overlapping
        // with past requests, then abort.
        let collect_queue_req = CollectQueueRequest {
            collect_req: collect_req.clone(),
            task_id: *task_id,
            collect_job_id: *collect_job_id,
        };
        let durable_name = LeaderColJobQueue::name(0).unwrap_from_name();
        let collect_id: CollectionJobId = self
            .durable()
            .post(
                LeaderColJobQueue::BINDING,
                LeaderColJobQueue::Put.to_uri(),
                durable_name,
                &collect_queue_req,
            )
            .await
            .map_err(|e| fatal_error!(err = ?e))?;
        debug!("assigned collect_id {collect_id}");

        let url = task_config.as_ref().leader_url.clone();

        // Note that we always return the draft02 URI, but the latest draft ignores it.
        let collect_uri = url
            .join(&format!(
                "collect/task/{}/req/{}",
                task_id.to_base64url(),
                collect_id.to_base64url(),
            ))
            .map_err(|e| fatal_error!(err = ?e))?;

        Ok(collect_uri)
    }

    async fn poll_collect_job(
        &self,
        task_id: &TaskId,
        collect_id: &CollectionJobId,
    ) -> std::result::Result<DapCollectJob, DapError> {
        let durable_name = LeaderColJobQueue::name(0).unwrap_from_name();
        let res: DapCollectJob = self
            .durable()
            .post(
                LeaderColJobQueue::BINDING,
                LeaderColJobQueue::GetResult.to_uri(),
                durable_name,
                (&task_id, &collect_id),
            )
            .await
            .map_err(|e| fatal_error!(err = ?e))?;
        Ok(res)
    }

    async fn get_pending_collect_jobs(
        &self,
    ) -> std::result::Result<Vec<(TaskId, CollectionJobId, CollectionReq)>, DapError> {
        let durable_name = LeaderColJobQueue::name(0).unwrap_from_name();
        let res: Vec<(TaskId, CollectionJobId, CollectionReq)> = self
            .durable()
            .get(
                LeaderColJobQueue::BINDING,
                LeaderColJobQueue::Get.to_uri(),
                durable_name,
            )
            .await
            .map_err(|e| fatal_error!(err = ?e))?;
        Ok(res)
    }

    async fn finish_collect_job(
        &self,
        task_id: &TaskId,
        collect_id: &CollectionJobId,
        collect_resp: &Collection,
    ) -> std::result::Result<(), DapError> {
        let task_config = self.try_get_task_config(task_id).await?;
        let durable = self.durable();
        if let PartialBatchSelector::FixedSizeByBatchId { ref batch_id } =
            collect_resp.part_batch_sel
        {
            let durable_name =
                LeaderBatchQueue::name((task_config.as_ref().version, &task_id.to_hex()))
                    .unwrap_from_name();
            durable
                .post(
                    LeaderBatchQueue::BINDING,
                    LeaderBatchQueue::Remove.to_uri(),
                    durable_name,
                    batch_id.to_hex(),
                )
                .await
                .map_err(|e| fatal_error!(err = ?e))?;
        }

        let durable_name = LeaderColJobQueue::name(0).unwrap_from_name();
        durable
            .post(
                LeaderColJobQueue::BINDING,
                LeaderColJobQueue::Finish.to_uri(),
                durable_name,
                (task_id, collect_id, collect_resp),
            )
            .await
            .map_err(|e| fatal_error!(err = ?e))?;
        Ok(())
    }

    async fn send_http_post(
        &self,
        req: DapRequest<DaphneAuth>,
        url: Url,
    ) -> std::result::Result<DapResponse, DapError> {
        self.send_http(req, false, url).await
    }

    async fn send_http_put(
        &self,
        req: DapRequest<DaphneAuth>,
        url: Url,
    ) -> std::result::Result<DapResponse, DapError> {
        self.send_http(req, true, url).await
    }
}
