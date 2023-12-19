// Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

#![allow(unused_variables)]

use std::{collections::HashMap, time::Instant};

use axum::{async_trait, http::Method};
use daphne::{
    auth::BearerTokenProvider,
    constants::DapMediaType,
    error::DapAbort,
    fatal_error,
    messages::{
        Base64Encode, Collection, CollectionJobId, CollectionReq, PartialBatchSelector, Report,
        TaskId, TransitionFailure,
    },
    roles::{DapAggregator, DapAuthorizedSender, DapLeader},
    DapCollectJob, DapError, DapQueryConfig, DapRequest, DapResponse, DapTaskConfig,
};
use daphne_service_utils::{
    auth::DaphneAuth,
    durable_requests::{
        bindings::{self, BatchCount, CollectQueueRequest, PendingReport, ReportsPendingResult},
        ObjectIdFrom,
    },
};
use prio::codec::{ParameterizedDecode, ParameterizedEncode};
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info};
use url::Url;

use crate::storage_proxy_connection::method_http_1_0_to_reqwest_0_11;

/// Parameters used by the Leader to select a set of reports for aggregation.
#[derive(Debug, Deserialize, Serialize)]
pub struct DaphneReportSelector {
    /// Maximum number of aggregation jobs to process at once.
    pub max_agg_jobs: u64,

    /// Maximum number of reports to drain for each aggregation job.
    pub max_reports: u64,
}

#[async_trait]
impl DapAuthorizedSender<DaphneAuth> for crate::App {
    async fn authorize(
        &self,
        task_id: &TaskId,
        task_config: &DapTaskConfig,
        media_type: &DapMediaType,
        _payload: &[u8],
    ) -> Result<DaphneAuth, DapError> {
        Ok(DaphneAuth {
            bearer_token: Some(
                self.authorize_with_bearer_token(task_id, task_config, media_type)
                    .await?
                    .into_owned(),
            ),
            // TODO Consider adding support for authorizing the request with TLS client
            // certificates: https://developers.cloudflare.com/workers/runtime-apis/mtls/
            cf_tls_client_auth: None,
        })
    }
}

#[async_trait]
impl DapLeader<DaphneAuth> for crate::App {
    type ReportSelector = DaphneReportSelector;

    async fn put_report(&self, report: &Report, task_id: &TaskId) -> Result<(), DapError> {
        let task_config = self
            .get_task_config_for(task_id)
            .await?
            .ok_or(DapAbort::UnrecognizedTask)?;
        let task_id_hex = task_id.to_hex();
        let version = task_config.as_ref().version;
        let pending_report = PendingReport {
            version,
            task_id: *task_id,
            report_hex: hex::encode(report.get_encoded_with_param(&version)),
        };
        let res: ReportsPendingResult = self
            .durable()
            .request(
                bindings::ReportsPending::Put,
                (
                    task_config.as_ref(),
                    &task_id_hex,
                    &report.report_metadata.id,
                    report.report_metadata.time,
                    &self.service_config.report_shard_key,
                    self.service_config.report_shard_count,
                    self.service_config.report_storage_epoch_duration,
                ),
            )
            .bin_encoding(pending_report)
            .send()
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
    ) -> Result<HashMap<TaskId, HashMap<PartialBatchSelector, Vec<Report>>>, DapError> {
        //// Read at most `report_sel.max_buckets` buckets from the agg job queue. The result is ordered
        //// from oldest to newest.
        ////
        //// NOTE There is only one agg job queue for now (`queue_num == 0`). In the future, work
        //// will be sharded across multiple queues.
        let res: Vec<String> = self
            .durable()
            .request(bindings::LeaderAggJobQueue::Get, 0)
            .bin_encoding(report_sel.max_agg_jobs)
            .send()
            .await
            .map_err(|e| fatal_error!(err = ?e))?;
        //// Drain at most `report_sel.max_reports` from each ReportsPending instance and group them
        //// by task.
        ////
        //// TODO Figure out if we can safely handle each instance in parallel.
        let mut reports_per_task: HashMap<TaskId, Vec<Report>> = HashMap::new();
        for reports_pending_id_hex in res.into_iter().map(ObjectIdFrom::Hex) {
            let reports_from_durable: Vec<PendingReport> = self
                .durable()
                .request_with_id(bindings::ReportsPending::Get, reports_pending_id_hex)
                .bin_encoding(report_sel.max_reports)
                .send()
                .await
                .map_err(|e| fatal_error!(err = ?e))?;

            for pending_report in reports_from_durable {
                let report_bytes = hex::decode(&pending_report.report_hex)
                    .map_err(|e| DapAbort::from_hex_error(e, pending_report.task_id))?;

                let version = self
                    .get_task_config_for(&pending_report.task_id)
                    .await?
                    .ok_or(DapAbort::UnrecognizedTask)?
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
                .get_task_config_for(&task_id)
                .await
                .map_err(|e| fatal_error!(err = ?e))?
                .ok_or(DapAbort::UnrecognizedTask)?;
            let task_id_hex = task_id.to_hex();
            let reports_per_part = reports_per_task_part.entry(task_id).or_default();
            match task_config.as_ref().query {
                DapQueryConfig::TimeInterval => {
                    reports_per_part.insert(PartialBatchSelector::TimeInterval, reports);
                }
                DapQueryConfig::FixedSize { .. } => {
                    let num_unassigned = reports.len();
                    let batch_assignments: Vec<BatchCount> = self
                        .durable()
                        .request(
                            bindings::LeaderBatchQueue::Assign,
                            (task_config.as_ref().version, &task_id_hex),
                        )
                        .bin_encoding((task_config.as_ref().min_batch_size, num_unassigned))
                        .send()
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
    ) -> Result<url::Url, DapError> {
        let task_config = self
            .get_task_config_for(task_id)
            .await?
            .ok_or(DapAbort::UnrecognizedTask)?;
        // Try to put the request into collection job queue. If the request is overlapping
        // with past requests, then abort.
        let collect_queue_req = CollectQueueRequest {
            collect_req: collect_req.clone(),
            task_id: *task_id,
            collect_job_id: *collect_job_id,
        };
        let collect_id: CollectionJobId = self
            .durable()
            .request(bindings::LeaderColJobQueue::Put, 0)
            .bin_encoding(collect_queue_req)
            .send()
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
    ) -> Result<DapCollectJob, DapError> {
        self.durable()
            .request(bindings::LeaderColJobQueue::GetResult, 0)
            .bin_encoding((&task_id, &collect_id))
            .send()
            .await
            .map_err(|e| fatal_error!(err = ?e))
    }

    async fn get_pending_collect_jobs(
        &self,
    ) -> Result<Vec<(TaskId, CollectionJobId, CollectionReq)>, DapError> {
        self.durable()
            .request(bindings::LeaderColJobQueue::Get, 0)
            .send()
            .await
            .map_err(|e| fatal_error!(err = ?e))
    }

    async fn finish_collect_job(
        &self,
        task_id: &TaskId,
        collect_id: &CollectionJobId,
        collect_resp: &Collection,
    ) -> Result<(), DapError> {
        let task_config = self
            .get_task_config_for(task_id)
            .await?
            .ok_or(DapAbort::UnrecognizedTask)?;

        if let PartialBatchSelector::FixedSizeByBatchId { batch_id } = &collect_resp.part_batch_sel
        {
            self.durable()
                .request(
                    bindings::LeaderBatchQueue::Remove,
                    (task_config.as_ref().version, &task_id.to_hex()),
                )
                .bin_encoding(batch_id.to_hex())
                .send()
                .await
                .map_err(|e| fatal_error!(err = ?e))?;
        }
        self.durable()
            .request(bindings::LeaderColJobQueue::Finish, 0)
            .bin_encoding((task_id, collect_id, collect_resp))
            .send()
            .await
            .map_err(|e| fatal_error!(err = ?e))
    }

    async fn send_http_post(
        &self,
        req: DapRequest<DaphneAuth>,
        url: Url,
    ) -> Result<DapResponse, DapError> {
        self.send_http(req, Method::POST, url).await
    }

    async fn send_http_put(
        &self,
        req: DapRequest<DaphneAuth>,
        url: Url,
    ) -> Result<DapResponse, DapError> {
        self.send_http(req, Method::PUT, url).await
    }
}

impl crate::App {
    async fn send_http(
        &self,
        req: DapRequest<DaphneAuth>,
        method: Method,
        url: Url,
    ) -> Result<DapResponse, DapError> {
        use reqwest::header::{self, HeaderMap, HeaderName, HeaderValue};

        let method = method_http_1_0_to_reqwest_0_11(method);

        let content_type = req
            .media_type
            .as_str_for_version(req.version)
            .ok_or_else(|| {
                fatal_error!(
                    err = "failed to construct content-type",
                    ?req.media_type,
                    ?req.version,
                )
            })?;

        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_str(content_type)
                .map_err(|e| fatal_error!(err = ?e, "failed to construct content-type header"))?,
        );

        if let Some(bearer_token) = req.sender_auth.and_then(|auth| auth.bearer_token) {
            headers.insert(
                HeaderName::from_static("dap-auth-token"),
                HeaderValue::from_str(bearer_token.as_ref()).map_err(
                    |e| fatal_error!(err = ?e, "failed to construct dap-auth-token header"),
                )?,
            );
        }

        if let Some(taskprov_advertisement) = req.taskprov.as_deref() {
            headers.insert(
                HeaderName::from_static("dap-taskprov"),
                HeaderValue::from_str(taskprov_advertisement).map_err(
                    |e| fatal_error!(err = ?e, "failed to construct dap-taskprov header"),
                )?,
            );
        }

        let req_builder = self
            .http
            .request(method, url.clone())
            .body(req.payload)
            .headers(headers);

        let start = Instant::now();
        let reqwest_resp = req_builder
            .send()
            .await
            .map_err(|e| fatal_error!(err = ?e))?;
        info!("request to {} completed in {:?}", url, start.elapsed());
        let status = reqwest_resp.status();

        const INT_ERR_PEER_ABORT: &str = "request aborted by peer";
        const INT_ERR_PEER_RESP_MISSING_MEDIA_TYPE: &str = "peer response is missing media type";

        if status == 200 {
            // Translate the reqwest response into a Worker response.
            let media_type = reqwest_resp
                .headers()
                .get_all(reqwest::header::CONTENT_TYPE)
                .into_iter()
                .filter_map(|h| h.to_str().ok())
                .find_map(|h| DapMediaType::from_str_for_version(req.version, Some(h)))
                .ok_or_else(|| fatal_error!(err = INT_ERR_PEER_RESP_MISSING_MEDIA_TYPE))?;

            let payload = reqwest_resp
                .bytes()
                .await
                .map_err(|e| fatal_error!(err = ?e))?
                .to_vec();

            Ok(DapResponse {
                version: req.version,
                payload,
                media_type,
            })
        } else {
            error!("{}: request failed: {:?}", url, reqwest_resp);
            if status == 400 {
                if let Some(content_type) =
                    reqwest_resp.headers().get(reqwest::header::CONTENT_TYPE)
                {
                    if content_type == "application/problem+json" {
                        error!(
                            "Problem details: {}",
                            reqwest_resp
                                .text()
                                .await
                                .map_err(|e| fatal_error!(err = ?e))?
                        );
                    }
                }
            }
            Err(fatal_error!(err = INT_ERR_PEER_ABORT))
        }
    }
}
