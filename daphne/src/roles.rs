// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Trait definitions for Daphne backends.

use crate::{
    constants::DapMediaType,
    hpke::HpkeDecrypter,
    messages::{
        constant_time_eq, decode_base64url, AggregateShare, AggregateShareReq,
        AggregationJobContinueReq, AggregationJobInitReq, AggregationJobResp, BatchId,
        BatchSelector, Collection, CollectionJobId, CollectionReq, HpkeConfigList, Interval,
        PartialBatchSelector, Query, Report, ReportId, ReportMetadata, TaskId, Time,
        TransitionFailure, TransitionVar,
    },
    metrics::DaphneMetrics,
    DapAbort, DapAggregateShare, DapCollectJob, DapError, DapGlobalConfig, DapHelperState,
    DapHelperTransition, DapLeaderProcessTelemetry, DapLeaderTransition, DapOutputShare,
    DapQueryConfig, DapRequest, DapResource, DapResponse, DapTaskConfig, DapVersion,
    MetaAggregationJobId,
};
use async_trait::async_trait;
use prio::codec::{Decode, Encode, ParameterizedDecode, ParameterizedEncode};
use std::borrow::Cow;
use std::collections::HashMap;
use tracing::debug;
use url::Url;

/// A party in the DAP protocol who is authorized to send requests to another party.
#[async_trait(?Send)]
pub trait DapAuthorizedSender<S> {
    /// Add authorization to an outbound DAP request with the given task ID, media type, and payload.
    async fn authorize(
        &self,
        task_id: &TaskId,
        media_type: &DapMediaType,
        payload: &[u8],
    ) -> Result<S, DapError>;
}

/// DAP Aggregator functionality.
#[async_trait(?Send)]
pub trait DapAggregator<'srv, 'req, S>: HpkeDecrypter<'srv> + Sized
where
    'srv: 'req,
{
    /// A refernce to a task configuration stored by the Aggregator.
    type WrappedDapTaskConfig: AsRef<DapTaskConfig>;

    /// Decide whether the given DAP request is authorized.
    async fn authorized(&self, req: &DapRequest<S>) -> Result<bool, DapError>;

    /// Look up the DAP global configuration.
    fn get_global_config(&self) -> &DapGlobalConfig;

    /// Decide whether to opt-in or out-out of a task provisioned via taskprov.
    ///
    /// If the return value is `None`, then the decision is to opt-in. If the return value is
    /// `Some(reason)`, then the decision is to opt-out; `reason` conveys details about how the
    /// decision was rached (e.g.., the minimum batch size is too smal).
    fn taskprov_opt_out_reason(
        &self,
        task_config: &DapTaskConfig,
    ) -> Result<Option<String>, DapError>;

    /// Look up the DAP task configuration for the given task ID.
    ///
    /// If a `report` has been provided, then look for the draft-wang-ppm-dap-taskprov-<nn> extension
    /// in the report.  If a taskprov task configuration is successfully read from the report,
    /// [`DapAggregator::taskprov_opt_in_decision`] will be called, and if it returns Ok(true) the server will opt-in to the task.
    /// if it returns Ok(false) or an error then the server will opt-out or return an appropriate error.
    ///
    /// The DAP version must be specified because we may create a DapTaskConfig via taskprov, and we want it
    /// to have the same version as the API entry point the client is using.
    async fn get_task_config_considering_taskprov(
        &'srv self,
        version: DapVersion,
        task_id: Cow<'req, TaskId>,
        report: Option<&ReportMetadata>,
    ) -> Result<Option<Self::WrappedDapTaskConfig>, DapError>;

    /// Look up the DAP task configuration for the given task ID.
    async fn get_task_config_for(
        &'srv self,
        task_id: Cow<'req, TaskId>,
    ) -> Result<Option<Self::WrappedDapTaskConfig>, DapError> {
        // We use DapVersion::Unknown here as we don't know it and we don't need to
        // know it as we will not be doing any taskprov task creation.
        self.get_task_config_considering_taskprov(DapVersion::Unknown, task_id, None)
            .await
    }

    /// Get the current time (number of seconds since the beginning of UNIX time).
    fn get_current_time(&self) -> Time;

    /// Check whether the batch determined by the collect request would overlap with a previous
    /// batch.
    async fn is_batch_overlapping(
        &self,
        task_id: &TaskId,
        batch_sel: &BatchSelector,
    ) -> Result<bool, DapError>;

    /// Check whether the given batch ID has been observed before. This is called by the Leader
    /// (resp. Helper) in response to a CollectReq (resp. AggregateShareReq) for fixed-size tasks.
    async fn batch_exists(&self, task_id: &TaskId, batch_id: &BatchId) -> Result<bool, DapError>;

    /// Store a set of output shares.
    async fn put_out_shares(
        &self,
        task_id: &TaskId,
        part_batch_sel: &PartialBatchSelector,
        out_shares: Vec<DapOutputShare>,
    ) -> Result<(), DapError>;

    /// Fetch the aggregate share for the given batch.
    async fn get_agg_share(
        &self,
        task_id: &TaskId,
        batch_sel: &BatchSelector,
    ) -> Result<DapAggregateShare, DapError>;

    /// Ensure a set of reorts can be aggregated. Return a transition failure for each report
    /// that must be rejected early, due to the repot being replayed, the bucket that contains the
    /// report being collected, etc.
    async fn check_early_reject<'b>(
        &self,
        task_id: &TaskId,
        part_batch_sel: &'b PartialBatchSelector,
        report_meta: impl Iterator<Item = &'b ReportMetadata>,
    ) -> Result<HashMap<ReportId, TransitionFailure>, DapError>;

    /// Mark a batch as collected.
    async fn mark_collected(
        &self,
        task_id: &TaskId,
        batch_sel: &BatchSelector,
    ) -> Result<(), DapError>;

    /// Handle HTTP GET to `/hpke_config?task_id=<task_id>`.
    async fn http_get_hpke_config(
        &'srv self,
        req: &DapRequest<S>,
    ) -> Result<DapResponse, DapAbort> {
        // Check whether the DAP version indicated by the sender is supported.
        if req.version == DapVersion::Unknown {
            return Err(DapAbort::version_unknown());
        }

        // Parse the task ID from the query string, ensuring that it is the only query parameter.
        let mut id = None;
        for (k, v) in req.url.query_pairs() {
            if k != "task_id" {
                return Err(DapAbort::BadRequest("unexpected query parameter".into()));
            }

            let bytes = decode_base64url(v.as_bytes()).ok_or(DapAbort::BadRequest(
                "failed to parse query parameter as URL-safe Base64".into(),
            ))?;

            id = Some(TaskId(bytes))
        }

        let hpke_config = self.get_hpke_config_for(req.version, id.as_ref()).await?;

        if let Some(task_id) = id {
            let task_config = self
                .get_task_config_for(Cow::Owned(task_id))
                .await?
                .ok_or(DapAbort::UnrecognizedTask)?;

            // Check whether the DAP version in the request matches the task config.
            if task_config.as_ref().version != req.version {
                return Err(DapAbort::version_mismatch(
                    req.version,
                    task_config.as_ref().version,
                ));
            }
        }

        let payload = match req.version {
            DapVersion::Draft02 => hpke_config.as_ref().get_encoded(),
            DapVersion::Draft04 => {
                let hpke_config_list = HpkeConfigList {
                    hpke_configs: vec![hpke_config.as_ref().clone()],
                };
                hpke_config_list.get_encoded()
            }
            // This is just to keep the compiler happy as we excluded DapVersion::Unknown by
            // aborting at the top of the function.
            _ => unreachable!("unhandled version {:?}", req.version),
        };

        Ok(DapResponse {
            version: req.version,
            media_type: DapMediaType::HpkeConfigList,
            payload,
        })
    }

    async fn current_batch(&self, task_id: &TaskId) -> Result<BatchId, DapError>;

    /// Access the Prometheus metrics.
    fn metrics(&self) -> &DaphneMetrics;
}

macro_rules! leader_post {
    (
        $role:expr,
        $task_id:expr,
        $task_config:expr,
        $path:expr,
        $req_media_type:expr,
        $resp_media_type:expr,
        $resource:expr,
        $req_data:expr,
        $is_put:expr
    ) => {{
        let url = $task_config
            .helper_url
            .join($path)
            .map_err(|e| DapError::Fatal(e.to_string()))?;

        let req = DapRequest {
            version: $task_config.version,
            media_type: $req_media_type,
            task_id: Some($task_id.clone()),
            resource: $resource,
            payload: $req_data,
            url,
            sender_auth: Some(
                $role
                    .authorize(&$task_id, &$req_media_type, &$req_data)
                    .await?,
            ),
        };

        let resp = if $is_put {
            $role.send_http_put(req).await?
        } else {
            $role.send_http_post(req).await?
        };

        check_response_content_type(&resp, $resp_media_type)?;
        resp
    }};
}

/// DAP Leader functionality.
#[async_trait(?Send)]
pub trait DapLeader<'srv, 'req, S>: DapAuthorizedSender<S> + DapAggregator<'srv, 'req, S>
where
    'srv: 'req,
{
    /// Data type used to guide selection of a set of reports for aggregation.
    type ReportSelector;

    /// Store a report for use later on.
    async fn put_report(&self, report: &Report, task_id: &TaskId) -> Result<(), DapError>;

    /// Fetch a sequence of reports to aggregate, grouped by task ID, then by partial batch
    /// selector. The reports returned are removed from persistent storage.
    async fn get_reports(
        &self,
        selector: &Self::ReportSelector,
    ) -> Result<HashMap<TaskId, HashMap<PartialBatchSelector, Vec<Report>>>, DapError>;

    /// Create a collect job.
    //
    // TODO spec: Figure out if the hostname for the collect URI needs to match the Leader.
    async fn init_collect_job(
        &self,
        task_id: &TaskId,
        collect_job_id: &Option<CollectionJobId>,
        collect_req: &CollectionReq,
    ) -> Result<Url, DapError>;

    /// Check the status of a collect job.
    async fn poll_collect_job(
        &self,
        task_id: &TaskId,
        collect_id: &CollectionJobId,
    ) -> Result<DapCollectJob, DapError>;

    /// Fetch the current collect job queue. The result is the sequence of collect ID and request
    /// pairs, in order of priority.
    async fn get_pending_collect_jobs(
        &self,
    ) -> Result<Vec<(TaskId, CollectionJobId, CollectionReq)>, DapError>;

    /// Complete a collect job by assigning it the completed [`CollectResp`](crate::messages::CollectResp).
    async fn finish_collect_job(
        &self,
        task_id: &TaskId,
        collect_id: &CollectionJobId,
        collect_resp: &Collection,
    ) -> Result<(), DapError>;

    /// Send an HTTP POST request.
    async fn send_http_post(&self, req: DapRequest<S>) -> Result<DapResponse, DapError>;

    /// Send an HTTP PUT request.
    async fn send_http_put(&self, req: DapRequest<S>) -> Result<DapResponse, DapError>;

    /// Handle HTTP POST to `/upload`. The input is the encoded report sent in the body of the HTTP
    /// request.
    async fn http_post_upload(&'srv self, req: &'req DapRequest<S>) -> Result<(), DapAbort> {
        debug!("upload for task {}", req.task_id()?);

        // Check whether the DAP version indicated by the sender is supported.
        if req.version == DapVersion::Unknown {
            return Err(DapAbort::version_unknown());
        }

        check_request_content_type(req, DapMediaType::Report)?;

        let report = Report::get_decoded_with_param(&req.version, req.payload.as_ref())?;
        debug!("report id is {}", report.report_metadata.id);
        let task_config = self
            .get_task_config_considering_taskprov(
                req.version,
                Cow::Borrowed(req.task_id()?),
                Some(&report.report_metadata),
            )
            .await?
            .ok_or(DapAbort::UnrecognizedTask)?;

        // Check whether the DAP version in the request matches the task config.
        if task_config.as_ref().version != req.version {
            return Err(DapAbort::version_mismatch(
                req.version,
                task_config.as_ref().version,
            ));
        }

        if report.encrypted_input_shares.len() != 2 {
            // TODO spec: Decide if this behavior should be specified.
            return Err(DapAbort::UnrecognizedMessage);
        }

        // Check that the indicated HpkeConfig is present.
        //
        // TODO spec: It's not clear if this behavior is MUST, SHOULD, or MAY.
        if !self
            .can_hpke_decrypt(req.task_id()?, report.encrypted_input_shares[0].config_id)
            .await?
        {
            return Err(DapAbort::UnrecognizedHpkeConfig);
        }

        // Check that the task has not expired.
        if report.report_metadata.time >= task_config.as_ref().expiration {
            return Err(DapAbort::ReportTooLate);
        }

        // Store the report for future processing. At this point, the report may be rejected if
        // the Leader detects that the report was replayed or pertains to a batch that has already
        // been collected.
        Ok(self.put_report(&report, req.task_id()?).await?)
    }

    /// Handle HTTP POST to `/collect`. The input is a [`CollectReq`](crate::messages::CollectReq).
    /// The return value is a URI that the Collector can poll later on to get the corresponding
    /// [`CollectResp`](crate::messages::CollectResp).
    async fn http_post_collect(&'srv self, req: &'req DapRequest<S>) -> Result<Url, DapAbort> {
        let task_id = req.task_id()?;
        debug!("collect for task {task_id}");
        let now = self.get_current_time();

        // Check whether the DAP version indicated by the sender is supported.
        if req.version == DapVersion::Unknown {
            return Err(DapAbort::version_unknown());
        }

        check_request_content_type(req, DapMediaType::CollectReq)?;

        if !self.authorized(req).await? {
            debug!("aborted unathorized collect request");
            return Err(DapAbort::UnauthorizedRequest);
        }

        let mut collect_req =
            CollectionReq::get_decoded_with_param(&req.version, req.payload.as_ref())?;
        let wrapped_task_config = self
            .get_task_config_for(Cow::Borrowed(req.task_id()?))
            .await?
            .ok_or(DapAbort::UnrecognizedTask)?;
        let task_config = wrapped_task_config.as_ref();

        // Check whether the DAP version in the request matches the task config.
        if task_config.version != req.version {
            return Err(DapAbort::version_mismatch(req.version, task_config.version));
        }

        if collect_req.query == Query::FixedSizeCurrentBatch {
            // This is where we assign the current batch, and convert the
            // Query::FixedSizeCurrentBatch into a Query::FixedSizeByBatchId.
            //
            // TODO(bhalleycf) Note that currently we are just looking at the
            // head of the uncollected batch queue, so there is no parallelism
            // possible for collectors on a given task.  To allow multiple
            // batches for a task to be collected concurrently for the same task,
            // we'd need a more complex DO state that allowed us to have batch
            // state go from unassigned -> in-progress -> complete.
            let batch_id = self.current_batch(task_id).await?;
            debug!("FixedSize batch id is {batch_id}");
            collect_req.query = Query::FixedSizeByBatchId { batch_id };
        }

        // Ensure the batch boundaries are valid and that the batch doesn't overlap with previosuly
        // collected batches.
        let batch_selector = BatchSelector::try_from(collect_req.query.clone())?;
        check_batch(
            self,
            task_config,
            task_id,
            &batch_selector,
            &collect_req.agg_param,
            now,
        )
        .await?;

        // draft02 compatibility: In draft02, the collection job ID is generated as a result of the
        // initial collection request, whereas in the latest draft, the collection job ID is parsed
        // from the request path.
        let collect_job_id = match (req.version, &req.resource) {
            (DapVersion::Draft02, DapResource::Undefined) => None,
            (DapVersion::Draft04, DapResource::CollectionJob(ref collect_job_id)) => {
                Some(collect_job_id.clone())
            }
            (DapVersion::Draft04, DapResource::Undefined) => {
                return Err(DapAbort::BadRequest("undefined resource".into()));
            }
            _ => unreachable!("unhandled resource {:?}", req.resource),
        };

        Ok(self
            .init_collect_job(task_id, &collect_job_id, &collect_req)
            .await?)
    }

    /// Run the aggregation sub-protocol for the given set of reports. Return the number of reports
    /// that were aggregated successfully.
    //
    // TODO Handle non-encodable messages gracefully. The length of `reports` may be too long to
    // encode in `AggregationJobInitReq`, in which case this method will panic. We should increase
    // the capacity of this message in the spec. In the meantime, we should at a minimum log this
    // when it happens.
    async fn run_agg_job(
        &self,
        task_id: &TaskId,
        task_config: &DapTaskConfig,
        part_batch_sel: &PartialBatchSelector,
        reports: Vec<Report>,
    ) -> Result<u64, DapAbort> {
        // Filter out early rejected reports.
        //
        // TODO Add a test similar to http_post_aggregate_init_expired_task() in roles_test.rs that
        // verifies that the Leader properly checks for expiration. This will require extending the
        // test framework to run run_agg_job() directly.
        let early_rejects = self
            .check_early_reject(
                task_id,
                part_batch_sel,
                reports.iter().map(|report| &report.report_metadata),
            )
            .await?;
        let reports = reports
            .into_iter()
            .filter(|report| {
                if let Some(failure) = early_rejects.get(&report.report_metadata.id) {
                    self.metrics()
                        .report_counter
                        .with_label_values(&[&format!("rejected_{failure}")])
                        .inc();
                    return false;
                }
                true
            })
            .collect();

        // Prepare AggregationJobInitReq.
        let agg_job_id = MetaAggregationJobId::gen_for_version(&task_config.version);
        let transition = task_config
            .vdaf
            .produce_agg_job_init_req(
                self,
                task_id,
                task_config,
                &agg_job_id,
                part_batch_sel,
                reports,
                self.metrics(),
            )
            .await?;
        let (state, agg_job_init_req) = match transition {
            DapLeaderTransition::Continue(state, agg_job_init_req) => (state, agg_job_init_req),
            DapLeaderTransition::Skip => return Ok(0),
            DapLeaderTransition::Uncommitted(..) => {
                return Err(DapError::fatal("unexpected state transition (uncommitted)").into())
            }
        };
        let is_put = task_config.version != DapVersion::Draft02;
        let url_path = if task_config.version == DapVersion::Draft02 {
            "aggregate".to_string()
        } else {
            format!(
                "tasks/{}/aggregation_jobs/{}",
                task_id.to_base64url(),
                agg_job_id.to_base64url()
            )
        };

        // Send AggregationJobInitReq and receive AggregationJobResp.
        let resp = leader_post!(
            self,
            task_id,
            task_config,
            &url_path,
            DapMediaType::AggregationJobInitReq,
            DapMediaType::AggregationJobResp,
            agg_job_id.for_request_path(),
            agg_job_init_req.get_encoded_with_param(&task_config.version),
            is_put
        );
        let agg_job_resp = AggregationJobResp::get_decoded(&resp.payload)?;

        // Prepare AggreagteContinueReq.
        let transition = task_config.vdaf.handle_agg_job_resp(
            task_id,
            &agg_job_id,
            state,
            agg_job_resp,
            task_config.version,
            self.metrics(),
        )?;
        let (uncommited, agg_job_cont_req) = match transition {
            DapLeaderTransition::Uncommitted(uncommited, agg_job_cont_req) => {
                (uncommited, agg_job_cont_req)
            }
            DapLeaderTransition::Skip => return Ok(0),
            DapLeaderTransition::Continue(..) => {
                return Err(DapError::fatal("unexpected state transition (continue)").into())
            }
        };

        // Send AggregationJobContinueReq and receive AggregationJobResp.
        let resp = leader_post!(
            self,
            task_id,
            task_config,
            &url_path,
            DapMediaType::AggregationJobContinueReq,
            DapMediaType::agg_job_cont_resp_for_version(task_config.version),
            agg_job_id.for_request_path(),
            agg_job_cont_req.get_encoded_with_param(&task_config.version),
            false
        );
        let agg_job_resp = AggregationJobResp::get_decoded(&resp.payload)?;

        // Commit the output shares.
        let out_shares =
            task_config
                .vdaf
                .handle_final_agg_job_resp(uncommited, agg_job_resp, self.metrics())?;
        let out_shares_count = out_shares.len() as u64;
        self.put_out_shares(task_id, part_batch_sel, out_shares)
            .await?;

        self.metrics()
            .report_counter
            .with_label_values(&["aggregated"])
            .inc_by(out_shares_count);

        Ok(out_shares_count)
    }

    /// Handle a pending collect request. If the results are ready, then compute the aggregate
    /// results and store them to be retrieved by the Collector later. Returns the number of
    /// reports in the batch.
    async fn run_collect_job(
        &self,
        task_id: &TaskId,
        collect_id: &CollectionJobId,
        task_config: &DapTaskConfig,
        collect_req: &CollectionReq,
    ) -> Result<u64, DapAbort> {
        debug!("collecting id {collect_id}");
        let batch_selector = BatchSelector::try_from(collect_req.query.clone())?;
        let leader_agg_share = self.get_agg_share(task_id, &batch_selector).await?;

        // Check the batch size. If not not ready, then return early.
        //
        // TODO Consider logging this error, as it should never happen.
        if !task_config.is_report_count_compatible(leader_agg_share.report_count)? {
            return Ok(0);
        }

        let batch_selector = BatchSelector::try_from(collect_req.query.clone())?;

        // Prepare the Leader's aggregate share.
        let leader_enc_agg_share = task_config.vdaf.produce_leader_encrypted_agg_share(
            &task_config.collector_hpke_config,
            task_id,
            &batch_selector,
            &leader_agg_share,
            task_config.version,
        )?;

        // Prepare AggregateShareReq.
        let agg_share_req = AggregateShareReq {
            draft02_task_id: task_id.for_request_payload(&task_config.version),
            batch_sel: batch_selector.clone(),
            agg_param: collect_req.agg_param.clone(),
            report_count: leader_agg_share.report_count,
            checksum: leader_agg_share.checksum,
        };

        let url_path = if task_config.version == DapVersion::Draft02 {
            "aggregate_share".to_string()
        } else {
            format!("tasks/{}/aggregate_shares", task_id.to_base64url())
        };

        // Send AggregateShareReq and receive AggregateShareResp.
        let resp = leader_post!(
            self,
            task_id,
            task_config,
            &url_path,
            DapMediaType::AggregateShareReq,
            DapMediaType::AggregateShare,
            DapResource::Undefined,
            agg_share_req.get_encoded_with_param(&task_config.version),
            false
        );
        let agg_share_resp = AggregateShare::get_decoded(&resp.payload)?;
        // For draft04 and later, the Collection message includes the smallest quantized time
        // interval containing all reports in the batch.
        let interval = match task_config.version {
            DapVersion::Draft02 => None,
            DapVersion::Draft04 => {
                let low = task_config.quantized_time_lower_bound(leader_agg_share.min_time);
                let high = task_config.quantized_time_upper_bound(leader_agg_share.max_time);
                Some(Interval {
                    start: low,
                    duration: if high > low {
                        high - low
                    } else {
                        // This should never happen!
                        task_config.time_precision
                    },
                })
            }
            _ => unreachable!("unhandled version {}", task_config.version),
        };

        // Complete the collect job.
        let collection = Collection {
            part_batch_sel: batch_selector.into(),
            report_count: leader_agg_share.report_count,
            interval,
            encrypted_agg_shares: vec![leader_enc_agg_share, agg_share_resp.encrypted_agg_share],
        };
        self.finish_collect_job(task_id, collect_id, &collection)
            .await?;

        // Mark reports as collected.
        self.mark_collected(task_id, &agg_share_req.batch_sel)
            .await?;

        self.metrics()
            .report_counter
            .with_label_values(&["collected"])
            .inc_by(agg_share_req.report_count);

        Ok(agg_share_req.report_count)
    }

    /// Fetch a set of reports grouped by task, then run an aggregation job for each task. once all
    /// jobs completed, process the collect job queue. It is not safe to run multiple instances of
    /// this function in parallel.
    ///
    /// This method is geared primarily towards testing. It also demonstrates how to properly
    /// synchronize collect and aggregation jobs. If used in a large DAP deployment, it is likely
    /// create a bottleneck. Such deployments can improve throughput by running many aggregation
    /// jobs in parallel.
    async fn process(
        &'srv self,
        selector: &Self::ReportSelector,
    ) -> Result<DapLeaderProcessTelemetry, DapAbort> {
        let mut telem = DapLeaderProcessTelemetry::default();

        // Fetch reports and run an aggregation job for each task.
        for (task_id, reports) in self.get_reports(selector).await?.into_iter() {
            let task_config = self
                .get_task_config_for(Cow::Owned(task_id.clone()))
                .await?
                .ok_or(DapAbort::UnrecognizedTask)?;

            for (part_batch_sel, reports) in reports.into_iter() {
                // TODO Consider splitting reports into smaller chunks.
                // TODO Consider handling tasks in parallel.
                telem.reports_processed += reports.len() as u64;
                debug!(
                    "process {} reports for task {task_id} with selector {part_batch_sel:?}",
                    reports.len()
                );
                if !reports.is_empty() {
                    telem.reports_aggregated += self
                        .run_agg_job(&task_id, task_config.as_ref(), &part_batch_sel, reports)
                        .await?;
                }
            }
        }
        // Process pending collect jobs. We wait until all aggregation jobs are finished before
        // proceeding to this step. This is to prevent a race condition involving an aggregate
        // share computed during a collect job and any output shares computed during an aggregation
        // job.
        for (task_id, collect_id, collect_req) in self.get_pending_collect_jobs().await? {
            let task_config = self
                .get_task_config_for(Cow::Owned(task_id.clone()))
                .await?
                .ok_or(DapAbort::UnrecognizedTask)?;

            telem.reports_collected += self
                .run_collect_job(&task_id, &collect_id, task_config.as_ref(), &collect_req)
                .await?;
        }

        Ok(telem)
    }
}

/// DAP Helper functionality.
#[async_trait(?Send)]
pub trait DapHelper<'srv, 'req, S>: DapAggregator<'srv, 'req, S>
where
    'srv: 'req,
{
    /// Store the Helper's aggregation-flow state.
    async fn put_helper_state(
        &self,
        task_id: &TaskId,
        agg_job_id: &MetaAggregationJobId,
        helper_state: &DapHelperState,
    ) -> Result<(), DapError>;

    /// Fetch the Helper's aggregation-flow state. `None` is returned if the Helper has no state
    /// associated with the given task and aggregation job.
    async fn get_helper_state(
        &self,
        task_id: &TaskId,
        agg_job_id: &MetaAggregationJobId,
    ) -> Result<Option<DapHelperState>, DapError>;

    /// Handle an HTTP POST to `/aggregate`. The input is either an AggregationJobInitReq or
    /// AggregationJobContinueReq and the response is an AggregationJobResp.
    ///
    /// This is called during the Initialization and Continuation phases.
    async fn http_post_aggregate(
        &'srv self,
        req: &'req DapRequest<S>,
    ) -> Result<DapResponse, DapAbort> {
        // Check whether the DAP version indicated by the sender is supported.
        if req.version == DapVersion::Unknown {
            return Err(DapAbort::version_unknown());
        }

        if !self.authorized(req).await? {
            debug!("aborted unauthorized aggregate request");
            return Err(DapAbort::UnauthorizedRequest);
        }

        let task_id = req.task_id()?;

        match req.media_type {
            DapMediaType::AggregationJobInitReq => {
                let agg_job_init_req =
                    AggregationJobInitReq::get_decoded_with_param(&req.version, &req.payload)?;

                let mut first_metadata: Option<&ReportMetadata> = None;

                // If taskprov is allowed, ensure that either all of the shares have it or none of them
                // do (section 6 of draft-wang-ppm-dap-taskprov-02).
                let global_config = self.get_global_config();
                if global_config.allow_taskprov {
                    let using_taskprov = agg_job_init_req
                        .report_shares
                        .iter()
                        .filter(|share| {
                            share
                                .report_metadata
                                .is_taskprov(global_config.taskprov_version, task_id)
                        })
                        .count();

                    if using_taskprov == agg_job_init_req.report_shares.len() {
                        // All the extensions use taskprov and look ok, so compute first_metadata.
                        // Note this will always be Some().
                        first_metadata = agg_job_init_req
                            .report_shares
                            .first()
                            .map(|report_share| &report_share.report_metadata);
                    } else if using_taskprov != 0 {
                        // It's not all taskprov or no taskprov, so it's an error.
                        return Err(DapAbort::UnrecognizedMessage);
                    }
                }

                let wrapped_task_config = self
                    .get_task_config_considering_taskprov(
                        req.version,
                        Cow::Borrowed(task_id),
                        first_metadata,
                    )
                    .await?
                    .ok_or(DapAbort::UnrecognizedTask)?;
                let task_config = wrapped_task_config.as_ref();

                // draft02 compatibility: In draft02, the aggregation job ID is parsed from the
                // HTTP request payload; in the latest draft, the aggregation job ID is parsed from
                // the request path.
                let agg_job_id = match (
                    req.version,
                    &req.resource,
                    &agg_job_init_req.draft02_agg_job_id,
                ) {
                    (DapVersion::Draft02, DapResource::Undefined, Some(ref agg_job_id)) => {
                        MetaAggregationJobId::Draft02(Cow::Borrowed(agg_job_id))
                    }
                    (DapVersion::Draft04, DapResource::AggregationJob(ref agg_job_id), None) => {
                        MetaAggregationJobId::Draft04(Cow::Borrowed(agg_job_id))
                    }
                    (DapVersion::Draft04, DapResource::Undefined, None) => {
                        return Err(DapAbort::BadRequest("undefined resource".into()));
                    }
                    _ => unreachable!("unhandled resource {:?}", req.resource),
                };

                let helper_state = self.get_helper_state(task_id, &agg_job_id);

                // Check whether the DAP version in the request matches the task config.
                if task_config.version != req.version {
                    return Err(DapAbort::version_mismatch(req.version, task_config.version));
                }

                // Ensure we know which batch the request pertains to.
                check_part_batch(
                    task_config,
                    &agg_job_init_req.part_batch_sel,
                    &agg_job_init_req.agg_param,
                )?;

                let early_rejects_future = self.check_early_reject(
                    task_id,
                    &agg_job_init_req.part_batch_sel,
                    agg_job_init_req
                        .report_shares
                        .iter()
                        .map(|report_share| &report_share.report_metadata),
                );

                let transition = task_config
                    .vdaf
                    .handle_agg_job_init_req(
                        self,
                        task_id,
                        task_config,
                        &agg_job_init_req,
                        self.metrics(),
                    )
                    .await?;

                // Check that helper state with the given task ID and aggregation job ID does not
                // exist.
                if helper_state.await?.is_some() {
                    // TODO spec: Consider an explicit abort for this case.
                    return Err(DapAbort::BadRequest(
                        "unexpected message for aggregation job (already exists)".into(),
                    ));
                }

                let agg_job_resp = match transition {
                    DapHelperTransition::Continue(mut state, mut agg_job_resp) => {
                        // Filter out early rejected reports.
                        let early_rejects = early_rejects_future.await?;
                        let mut state_index = 0;
                        for transition in agg_job_resp.transitions.iter_mut() {
                            let early_failure = early_rejects.get(&transition.report_id);
                            if !matches!(transition.var, TransitionVar::Failed(..))
                                && early_failure.is_some()
                            {
                                // NOTE(cjpatton) Clippy wants us to use and `if let` statement to
                                // unwrap `early_failure`. I don't think this works becauase we
                                // only want to enter this loop if `early_failure.is_some()` and
                                // the current `transition` is not a failure. As far as I know, `if
                                // let` statements can't yet be combined with other conditions.
                                #[allow(clippy::unnecessary_unwrap)]
                                let failure = early_failure.unwrap();
                                transition.var = TransitionVar::Failed(*failure);

                                // Remove VDAF preparation state of reports that were rejected early.
                                if transition.report_id == state.seq[state_index].2 {
                                    let _val = state.seq.remove(state_index);
                                } else {
                                    // The report ID in the Helper state and Aggregate response
                                    // must be aligned. If not, handle as an internal error.
                                    return Err(DapError::fatal("report IDs not aligned").into());
                                }

                                // NOTE(cjpatton) Unlike the Leader, the Helper filters out early
                                // rejects after processing all of the reports. (This is an
                                // optimization intended to reduce latency.) To avoid overcounting
                                // rejection metrics, the latter rejections take precedence. The
                                // Leader has the opposite behavior: Early rejections are resolved
                                // first, so take precedence.
                                self.metrics()
                                    .report_counter
                                    .with_label_values(&[&format!("rejected_{failure}")])
                                    .inc();
                            } else {
                                state_index += 1;
                            }
                        }

                        self.put_helper_state(task_id, &agg_job_id, &state).await?;
                        agg_job_resp
                    }
                    DapHelperTransition::Finish(..) => {
                        return Err(DapError::fatal("unexpected transition (finished)").into());
                    }
                };

                self.metrics().aggregation_job_gauge.inc();

                Ok(DapResponse {
                    version: req.version,
                    media_type: DapMediaType::AggregationJobResp,
                    payload: agg_job_resp.get_encoded(),
                })
            }
            DapMediaType::AggregationJobContinueReq => {
                let agg_job_cont_req =
                    AggregationJobContinueReq::get_decoded_with_param(&req.version, &req.payload)?;
                let wrapped_task_config = self
                    .get_task_config_for(Cow::Borrowed(task_id))
                    .await?
                    .ok_or(DapAbort::UnrecognizedTask)?;
                let task_config = wrapped_task_config.as_ref();

                // Check whether the DAP version in the request matches the task config.
                if task_config.version != req.version {
                    return Err(DapAbort::version_mismatch(req.version, task_config.version));
                }

                // draft02 compatibility: In draft02, the aggregation job ID is parsed from the
                // HTTP request payload; in the latest, the aggregation job ID is parsed from the
                // request path.
                let agg_job_id = match (
                    req.version,
                    &req.resource,
                    &agg_job_cont_req.draft02_agg_job_id,
                ) {
                    (DapVersion::Draft02, DapResource::Undefined, Some(ref agg_job_id)) => {
                        MetaAggregationJobId::Draft02(Cow::Borrowed(agg_job_id))
                    }
                    (DapVersion::Draft04, DapResource::AggregationJob(ref agg_job_id), None) => {
                        MetaAggregationJobId::Draft04(Cow::Borrowed(agg_job_id))
                    }
                    (DapVersion::Draft04, DapResource::Undefined, None) => {
                        return Err(DapAbort::BadRequest("undefined resource".into()));
                    }
                    _ => unreachable!("unhandled resource {:?}", req.resource),
                };

                let state = self
                    .get_helper_state(task_id, &agg_job_id)
                    .await?
                    .ok_or(DapAbort::UnrecognizedAggregationJob)?;
                let part_batch_sel = state.part_batch_sel.clone();
                let transition = task_config.vdaf.handle_agg_job_cont_req(
                    state,
                    &agg_job_cont_req,
                    self.metrics(),
                )?;

                let (agg_job_resp, out_shares_count) = match transition {
                    DapHelperTransition::Continue(..) => {
                        return Err(DapError::fatal("unexpected transition (continued)").into());
                    }
                    DapHelperTransition::Finish(out_shares, agg_job_resp) => {
                        let out_shares_count = u64::try_from(out_shares.len()).unwrap();
                        self.put_out_shares(task_id, &part_batch_sel, out_shares)
                            .await?;
                        (agg_job_resp, out_shares_count)
                    }
                };

                self.metrics()
                    .report_counter
                    .with_label_values(&["aggregated"])
                    .inc_by(out_shares_count);

                self.metrics().aggregation_job_gauge.dec();

                Ok(DapResponse {
                    version: req.version,
                    media_type: DapMediaType::agg_job_cont_resp_for_version(task_config.version),
                    payload: agg_job_resp.get_encoded(),
                })
            }
            //TODO spec: Specify this behavior.
            _ => Err(DapAbort::BadRequest("unexpected media type".into())),
        }
    }

    /// Handle an HTTP POST to `/aggregate_share`. The input is an AggregateShareReq and the
    /// response is an AggregateShareResp.
    ///
    /// This is called during the Collection phase.
    async fn http_post_aggregate_share(
        &'srv self,
        req: &'req DapRequest<S>,
    ) -> Result<DapResponse, DapAbort> {
        let now = self.get_current_time();

        // Check whether the DAP version indicated by the sender is supported.
        if req.version == DapVersion::Unknown {
            return Err(DapAbort::version_unknown());
        }

        check_request_content_type(req, DapMediaType::AggregateShareReq)?;

        if !self.authorized(req).await? {
            return Err(DapAbort::UnauthorizedRequest);
        }

        let task_id = req.task_id()?;

        let agg_share_req = AggregateShareReq::get_decoded_with_param(&req.version, &req.payload)?;
        let wrapped_task_config = self
            .get_task_config_for(Cow::Borrowed(req.task_id()?))
            .await?
            .ok_or(DapAbort::UnrecognizedTask)?;
        let task_config = wrapped_task_config.as_ref();

        // Check whether the DAP version in the request matches the task config.
        if task_config.version != req.version {
            return Err(DapAbort::version_mismatch(req.version, task_config.version));
        }

        // Ensure the batch boundaries are valid and that the batch doesn't overlap with previosuly
        // collected batches.
        check_batch(
            self,
            task_config,
            task_id,
            &agg_share_req.batch_sel,
            &agg_share_req.agg_param,
            now,
        )
        .await?;

        let agg_share = self
            .get_agg_share(task_id, &agg_share_req.batch_sel)
            .await?;

        // Check that we have aggreagted the same set of reports as the Leader.
        if agg_share_req.report_count != agg_share.report_count
            || !constant_time_eq(&agg_share_req.checksum, &agg_share.checksum)
        {
            return Err(DapAbort::BatchMismatch{
                detail: format!("Either the report count or checksum does not match: the Leader computed {} and {}; the Helper computed {} and {}.",
                    agg_share_req.report_count,
                    hex::encode(agg_share_req.checksum),
                    agg_share.report_count,
                    hex::encode(agg_share.checksum)),
                task_id: task_id.clone(),
            });
        }

        // Check the batch size.
        if !task_config
            .is_report_count_compatible(agg_share.report_count)
            .unwrap_or(false)
        {
            return Err(DapAbort::InvalidBatchSize);
        }

        // Mark each aggregated report as collected.
        self.mark_collected(task_id, &agg_share_req.batch_sel)
            .await?;

        let encrypted_agg_share = task_config.vdaf.produce_helper_encrypted_agg_share(
            &task_config.collector_hpke_config,
            task_id,
            &agg_share_req.batch_sel,
            &agg_share,
            task_config.version,
        )?;

        let agg_share_resp = AggregateShare {
            encrypted_agg_share,
        };

        self.metrics()
            .report_counter
            .with_label_values(&["collected"])
            .inc_by(agg_share_req.report_count);

        Ok(DapResponse {
            version: req.version,
            media_type: DapMediaType::AggregateShare,
            payload: agg_share_resp.get_encoded(),
        })
    }
}

fn check_part_batch(
    task_config: &DapTaskConfig,
    part_batch_sel: &PartialBatchSelector,
    agg_param: &[u8],
) -> Result<(), DapAbort> {
    if !task_config.query.is_valid_part_batch_sel(part_batch_sel) {
        return Err(DapAbort::QueryMismatch);
    }

    // Check that the aggreation parameter is suitable for the given VDAF.
    if !task_config.vdaf.is_valid_agg_param(agg_param) {
        // TODO spec: Define this behavior.
        return Err(DapAbort::UnrecognizedMessage);
    }

    Ok(())
}

async fn check_batch<'srv, 'req, S>(
    agg: &impl DapAggregator<'srv, 'req, S>,
    task_config: &DapTaskConfig,
    task_id: &TaskId,
    batch_sel: &BatchSelector,
    agg_param: &[u8],
    now: Time,
) -> Result<(), DapAbort>
where
    'srv: 'req,
{
    let global_config = agg.get_global_config();
    let batch_overlapping = agg.is_batch_overlapping(task_id, batch_sel);

    // Check that the aggreation parameter is suitable for the given VDAF.
    if !task_config.vdaf.is_valid_agg_param(agg_param) {
        // TODO spec: Define this behavior.
        return Err(DapAbort::UnrecognizedMessage);
    }

    // Check that the batch boundaries are valid.
    match (&task_config.query, batch_sel) {
        (DapQueryConfig::TimeInterval { .. }, BatchSelector::TimeInterval { batch_interval }) => {
            if batch_interval.start % task_config.time_precision != 0
                || batch_interval.duration % task_config.time_precision != 0
                || batch_interval.duration < task_config.time_precision
            {
                return Err(DapAbort::BatchInvalid {
                    detail: format!("The queried batch interval ({batch_interval:?}) is too small or its boundaries are misaligned. The time precision for this task is {}s.", task_config.time_precision),
                    task_id: task_id.clone(),
                });
            }

            if batch_interval.duration > global_config.max_batch_duration {
                return Err(DapAbort::BadRequest("batch interval too large".to_string()));
            }

            if now.abs_diff(batch_interval.start) > global_config.min_batch_interval_start {
                return Err(DapAbort::BadRequest(
                    "batch interval too far into past".to_string(),
                ));
            }

            if now.abs_diff(batch_interval.end()) > global_config.max_batch_interval_end {
                return Err(DapAbort::BadRequest(
                    "batch interval too far into future".to_string(),
                ));
            }
        }
        (DapQueryConfig::FixedSize { .. }, BatchSelector::FixedSizeByBatchId { batch_id }) => {
            // TODO(cjpatton) The Helper can avoid this callback by first fetching the aggregate
            // share and aborting with "batchInvalid" if the report count is 0. Depending on how we
            // resolve https://github.com/ietf-wg-ppm/draft-ietf-ppm-dap/issues/342, this check may
            // become unnecessary for the Leader.
            //
            // Consider removing this callback once we resolve DAP issue #342.
            if !agg.batch_exists(task_id, batch_id).await? {
                return Err(DapAbort::BatchInvalid {
                    detail: format!(
                        "The queried batch ({}) does not exist.",
                        batch_id.to_base64url()
                    ),
                    task_id: task_id.clone(),
                });
            }
        }
        _ => return Err(DapAbort::QueryMismatch),
    };

    // Check that the batch does not overlap with any previously collected batch.
    if batch_overlapping.await? {
        return Err(DapAbort::BatchOverlap);
    }

    Ok(())
}

/// Check for transition failures due to:
///
/// * the report having already been processed
/// * the report having already been collected
/// * the report not being within time bounds
///
/// Returns `Some(TransitionFailure)` if there is a problem,
/// or `None` if no transition failure occurred.
pub fn early_metadata_check(
    metadata: &ReportMetadata,
    processed: bool,
    collected: bool,
    min_time: u64,
    max_time: u64,
) -> Option<TransitionFailure> {
    if processed {
        Some(TransitionFailure::ReportReplayed)
    } else if collected {
        Some(TransitionFailure::BatchCollected)
    } else if metadata.time < min_time {
        Some(TransitionFailure::ReportDropped)
    } else if metadata.time > max_time {
        Some(TransitionFailure::ReportTooEarly)
    } else {
        None
    }
}

fn check_response_content_type(resp: &DapResponse, expected: DapMediaType) -> Result<(), DapError> {
    let want_str = expected
        .as_str_for_version(resp.version)
        .expect("could not determine string representation for expected content-type");

    if resp.media_type != expected {
        if let Some(got_str) = resp.media_type.as_str_for_version(resp.version) {
            Err(DapError::Fatal(format!(
                "response from peer has unexpected content-type: got {got_str}; want {want_str}",
            )))
        } else {
            Err(DapError::fatal(
                "response from peer has no content-type: expected {want_str}",
            ))
        }
    } else {
        Ok(())
    }
}

fn check_request_content_type<S>(
    req: &DapRequest<S>,
    expected: DapMediaType,
) -> Result<(), DapAbort> {
    if req.media_type != expected {
        Err(DapAbort::content_type(req, expected))
    } else {
        Ok(())
    }
}
