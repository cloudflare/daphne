// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Trait definitions for Daphne backends.

use crate::{
    constants::{
        MEDIA_TYPE_AGG_CONT_REQ, MEDIA_TYPE_AGG_CONT_RESP, MEDIA_TYPE_AGG_INIT_REQ,
        MEDIA_TYPE_AGG_INIT_RESP, MEDIA_TYPE_AGG_SHARE_REQ, MEDIA_TYPE_AGG_SHARE_RESP,
        MEDIA_TYPE_HPKE_CONFIG,
    },
    hpke::HpkeDecrypter,
    messages::{
        constant_time_eq, AggregateContinueReq, AggregateInitializeReq, AggregateResp,
        AggregateShareReq, AggregateShareResp, BatchParameter, BatchSelector, CollectReq,
        CollectResp, Id, Nonce, Report, ReportShare, Time, TransitionFailure, TransitionVar,
    },
    DapAbort, DapAggregateShare, DapCollectJob, DapError, DapGlobalConfig, DapHelperState,
    DapHelperTransition, DapLeaderProcessTelemetry, DapLeaderTransition, DapOutputShare,
    DapQueryConfig, DapRequest, DapResponse, DapTaskConfig, DapVersion,
};
use async_trait::async_trait;
use prio::codec::{Decode, Encode};
use rand::prelude::*;
use std::collections::HashMap;
use url::Url;

/// A party in the DAP protocol who is authorized to send requests to another party.
#[async_trait(?Send)]
pub trait DapAuthorizedSender<S> {
    /// Add authorization to an outbound DAP request with the given task ID, media type, and payload.
    async fn authorize(
        &self,
        task_id: &Id,
        media_type: &'static str,
        payload: &[u8],
    ) -> Result<S, DapError>;
}

/// DAP Aggregator functionality.
#[async_trait(?Send)]
pub trait DapAggregator<'a, S>: HpkeDecrypter<'a> + Sized {
    /// Return type of `get_task_config_for()`, wraps a reference to task configuration.
    type WrappedDapTaskConfig: AsRef<DapTaskConfig>;

    /// Decide whether the given DAP request is authorized.
    async fn authorized(&self, req: &DapRequest<S>) -> Result<bool, DapError>;

    /// Look up the DAP global configuration.
    fn get_global_config(&self) -> &DapGlobalConfig;

    /// Look up the DAP task configuration for the given task ID.
    async fn get_task_config_for(
        &'a self,
        task_id: &Id,
    ) -> Result<Option<Self::WrappedDapTaskConfig>, DapError>;

    /// Get the current time (number of seconds since the beginning of UNIX time).
    fn get_current_time(&self) -> u64;

    /// Check whether the batch determined by the collect request would overlap with a previous
    /// batch.
    async fn is_batch_overlapping(
        &self,
        task_id: &Id,
        batch_selector: &BatchSelector,
    ) -> Result<bool, DapError>;

    /// Store a set of output shares.
    async fn put_out_shares(
        &self,
        task_id: &Id,
        out_shares: Vec<DapOutputShare>,
    ) -> Result<(), DapError>;

    /// Fetch the aggregate share for the given batch.
    async fn get_agg_share(
        &self,
        task_id: &Id,
        batch_selector: &BatchSelector,
    ) -> Result<DapAggregateShare, DapError>;

    /// Mark a batch as collected.
    async fn mark_collected(
        &self,
        task_id: &Id,
        batch_selector: &BatchSelector,
    ) -> Result<(), DapError>;

    /// Handle HTTP GET to `/hpke_config?task_id=<task_id>`.
    async fn http_get_hpke_config(&'a self, req: &DapRequest<S>) -> Result<DapResponse, DapAbort> {
        // Check whether the DAP version indicated by the sender is supported.
        if req.version == DapVersion::Unknown {
            return Err(DapAbort::InvalidProtocolVersion);
        }

        // Parse the task ID from the query string, ensuring that it is the only query parameter.
        let mut id = None;
        for (k, v) in req.url.query_pairs() {
            if k != "task_id" {
                return Err(DapAbort::BadRequest("unexpected query parameter".into()));
            }

            let bytes =
                base64::decode_config(v.as_ref(), base64::URL_SAFE_NO_PAD).map_err(|_| {
                    DapAbort::BadRequest(
                        "failed to parse query parameter as URL-safe Base64".into(),
                    )
                })?;

            id = Some(Id::get_decoded(&bytes)?);
        }

        if let Some(ref task_id) = id {
            let task_config = self
                .get_task_config_for(task_id)
                .await?
                .ok_or(DapAbort::UnrecognizedTask)?;

            // Check whether the DAP version in the request matches the task config.
            if task_config.as_ref().version != req.version {
                return Err(DapAbort::InvalidProtocolVersion);
            }
        }

        let hpke_config = self.get_hpke_config_for(id.as_ref()).await?;
        Ok(DapResponse {
            media_type: Some(MEDIA_TYPE_HPKE_CONFIG),
            payload: hpke_config.as_ref().get_encoded(),
        })
    }
}

macro_rules! leader_post {
    (
        $role:expr,
        $task_id:expr,
        $task_config:expr,
        $path:expr,
        $media_type:expr,
        $req_data:expr
    ) => {{
        let url = $task_config
            .helper_url
            .join($path)
            .map_err(|e| DapError::Fatal(e.to_string()))?;
        let req = DapRequest {
            version: $task_config.version.clone(),
            media_type: Some($media_type),
            payload: $req_data,
            url,
            sender_auth: Some($role.authorize(&$task_id, $media_type, &$req_data).await?),
        };
        $role.send_http_post(req).await?
    }};
}

/// DAP Leader functionality.
#[async_trait(?Send)]
pub trait DapLeader<'a, S>: DapAuthorizedSender<S> + DapAggregator<'a, S> {
    /// Data type used to guide selection of a set of reports for aggregation.
    type ReportSelector;

    /// Store a report for use later on.
    async fn put_report(&self, report: &Report) -> Result<(), DapError>;

    /// Fetch a sequence of reports to aggregate, grouped by task ID. The reports returned are
    /// removed from persistent storage.
    async fn get_reports(
        &self,
        selector: &Self::ReportSelector,
    ) -> Result<HashMap<Id, Vec<Report>>, DapError>;

    /// Create a collect job.
    //
    // TODO spec: Figure out if the hostname for the collect URI needs to match the Leader.
    async fn init_collect_job(&self, collect_req: &CollectReq) -> Result<Url, DapError>;

    /// Check the status of a collect job.
    async fn poll_collect_job(
        &self,
        task_id: &Id,
        collect_id: &Id,
    ) -> Result<DapCollectJob, DapError>;

    /// Fetch the current collect job queue. The result is the sequence of collect ID and request
    /// pairs, in order of priority.
    async fn get_pending_collect_jobs(&self) -> Result<Vec<(Id, CollectReq)>, DapError>;

    /// Complete a collect job by assigning it the completed [`CollectResp`](crate::messages::CollectResp).
    async fn finish_collect_job(
        &self,
        task_id: &Id,
        collect_id: &Id,
        collect_resp: &CollectResp,
    ) -> Result<(), DapError>;

    /// Send an HTTP POST request.
    async fn send_http_post(&self, req: DapRequest<S>) -> Result<DapResponse, DapError>;

    /// Handle HTTP POST to `/upload`. The input is the encoded report sent in the body of the HTTP
    /// request.
    async fn http_post_upload(&'a self, req: &DapRequest<S>) -> Result<(), DapAbort> {
        // Check whether the DAP version indicated by the sender is supported.
        if req.version == DapVersion::Unknown {
            return Err(DapAbort::InvalidProtocolVersion);
        }

        let report = Report::get_decoded(req.payload.as_ref())?;
        let task_config = self
            .get_task_config_for(&report.task_id)
            .await?
            .ok_or(DapAbort::UnrecognizedTask)?;

        // Check whether the DAP version in the request matches the task config.
        if task_config.as_ref().version != req.version {
            return Err(DapAbort::InvalidProtocolVersion);
        }

        if report.encrypted_input_shares.len() != 2 {
            // TODO spec: Decide if this behavior should be specified.
            return Err(DapAbort::UnrecognizedMessage);
        }

        // Check that the indicated HpkeConfig is present.
        //
        // TODO spec: It's not clear if this behavior is MUST, SHOULD, or MAY.
        if !self
            .can_hpke_decrypt(&report.task_id, report.encrypted_input_shares[0].config_id)
            .await?
        {
            return Err(DapAbort::UnrecognizedHpkeConfig);
        }

        // NOTE spec: Currently it is up to the backend to reject or accept a report.
        Ok(self.put_report(&report).await?)
    }

    /// Handle HTTP POST to `/collect`. The input is a [`CollectReq`](crate::messages::CollectReq).
    /// The return value is a URI that the Collector can poll later on to get the corresponding
    /// [`CollectResp`](crate::messages::CollectResp).
    async fn http_post_collect(&'a self, req: &DapRequest<S>) -> Result<Url, DapAbort> {
        let now = self.get_current_time();

        // Check whether the DAP version indicated by the sender is supported.
        if req.version == DapVersion::Unknown {
            return Err(DapAbort::InvalidProtocolVersion);
        }

        if !self.authorized(req).await? {
            return Err(DapAbort::UnauthorizedRequest);
        }

        let collect_req = CollectReq::get_decoded(req.payload.as_ref())?;
        let wrapped_task_config = self
            .get_task_config_for(&collect_req.task_id)
            .await?
            .ok_or(DapAbort::UnrecognizedTask)?;
        let task_config = wrapped_task_config.as_ref();

        // Check whether the DAP version in the request matches the task config.
        if task_config.version != req.version {
            return Err(DapAbort::InvalidProtocolVersion);
        }

        // Ensure the batch boundaries are valid and that the batch doesn't overlap with previosuly
        // collected batches.
        //
        // TODO(issue #100) For "fixed_size" we need to check if we recognize the batch ID.
        check_batch(
            self,
            task_config,
            &collect_req.task_id,
            &collect_req.query,
            &collect_req.agg_param,
            now,
        )
        .await?;

        Ok(self.init_collect_job(&collect_req).await?)
    }

    /// Run the aggregation sub-protocol for the given set of reports. Return the number of reports
    /// that were aggregated successfully.
    //
    // TODO Handle non-encodable messages gracefully. The length of `reports` may be too long to
    // encode in `AggregateInitializeReq`, in which case this method will panic. We should increase
    // the capacity of this message in the spec. In the meantime, we should at a minimum log this
    // when it happens.
    async fn run_agg_job(
        &self,
        task_id: &Id,
        task_config: &DapTaskConfig,
        reports: Vec<Report>,
    ) -> Result<u64, DapAbort> {
        let mut rng = thread_rng();

        // Prepare AggregateInitializeReq.
        let agg_job_id = Id(rng.gen());
        let transition = task_config
            .vdaf
            .produce_agg_init_req(
                self,
                &task_config.vdaf_verify_key,
                task_id,
                &agg_job_id,
                reports,
            )
            .await?;
        let (state, agg_init_req) = match transition {
            DapLeaderTransition::Continue(state, agg_init_req) => (state, agg_init_req),
            DapLeaderTransition::Skip => return Ok(0),
            DapLeaderTransition::Uncommitted(..) => {
                return Err(DapError::fatal("unexpected state transition (uncommitted)").into())
            }
        };

        // Send AggregateInitializeReq and receive AggregateResp.
        let resp = leader_post!(
            self,
            task_id,
            task_config,
            "aggregate",
            MEDIA_TYPE_AGG_INIT_REQ,
            agg_init_req.get_encoded()
        );
        let agg_resp = AggregateResp::get_decoded(&resp.payload)?;

        // Prepare AggreagteContinueReq.
        let transition = task_config
            .vdaf
            .handle_agg_resp(task_id, &agg_job_id, state, agg_resp)?;
        let (uncommited, agg_cont_req) = match transition {
            DapLeaderTransition::Uncommitted(uncommited, agg_cont_req) => {
                (uncommited, agg_cont_req)
            }
            DapLeaderTransition::Skip => return Ok(0),
            DapLeaderTransition::Continue(..) => {
                return Err(DapError::fatal("unexpected state transition (continue)").into())
            }
        };

        // Send AggregateContinueReq and receive AggregateResp.
        let resp = leader_post!(
            self,
            task_id,
            task_config,
            "aggregate",
            MEDIA_TYPE_AGG_CONT_REQ,
            agg_cont_req.get_encoded()
        );
        let agg_resp = AggregateResp::get_decoded(&resp.payload)?;

        // Commit the output shares.
        let out_shares = task_config
            .vdaf
            .handle_final_agg_resp(uncommited, agg_resp)?;
        let out_shares_count = out_shares.len() as u64;
        self.put_out_shares(task_id, out_shares).await?;
        Ok(out_shares_count)
    }

    /// Handle a pending collect request. If the results are reasdy, then cokmpute the aggregate
    /// results and store them to be retrieved by the Collector later. Returns the number of
    /// reports in the batch.
    async fn run_collect_job(
        &self,
        collect_id: &Id,
        task_config: &DapTaskConfig,
        collect_req: CollectReq,
    ) -> Result<u64, DapAbort> {
        let leader_agg_share = self
            .get_agg_share(&collect_req.task_id, &collect_req.query)
            .await?;

        // Check the batch size. If not not ready, then return early.
        //
        // TODO Consider logging this error, as it shouuld never happen.
        if !task_config
            .query
            .check_batch_size(leader_agg_share.report_count)?
        {
            return Ok(0);
        }

        // Prepare the Leader's aggregate share.
        let leader_enc_agg_share = task_config.vdaf.produce_leader_encrypted_agg_share(
            &task_config.collector_hpke_config,
            &collect_req.task_id,
            &collect_req.query,
            &leader_agg_share,
        )?;

        // Prepare AggregateShareReq.
        let agg_share_req = AggregateShareReq {
            task_id: collect_req.task_id.clone(),
            batch_selector: collect_req.query.clone(),
            agg_param: collect_req.agg_param.clone(),
            report_count: leader_agg_share.report_count,
            checksum: leader_agg_share.checksum,
        };

        // Send AggregateShareReq and receive AggregateShareResp.
        let resp = leader_post!(
            self,
            &collect_req.task_id,
            task_config,
            "aggregate_share",
            MEDIA_TYPE_AGG_SHARE_REQ,
            agg_share_req.get_encoded()
        );
        let agg_share_resp = AggregateShareResp::get_decoded(&resp.payload)?;

        // Complete the collect job.
        let collect_resp = CollectResp {
            report_count: leader_agg_share.report_count,
            encrypted_agg_shares: vec![leader_enc_agg_share, agg_share_resp.encrypted_agg_share],
        };
        self.finish_collect_job(&collect_req.task_id, collect_id, &collect_resp)
            .await?;

        // Mark reports as collected.
        self.mark_collected(&agg_share_req.task_id, &agg_share_req.batch_selector)
            .await?;

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
        &'a self,
        selector: &Self::ReportSelector,
    ) -> Result<DapLeaderProcessTelemetry, DapAbort> {
        let mut telem = DapLeaderProcessTelemetry::default();

        // Fetch reports and run an aggregation job for each task.
        //
        // TODO Handle tasks in parallel.
        for (task_id, reports) in self.get_reports(selector).await?.into_iter() {
            let task_config = self
                .get_task_config_for(&task_id)
                .await?
                .ok_or(DapAbort::UnrecognizedTask)?;

            telem.reports_processed += reports.len() as u64;
            if !reports.is_empty() {
                telem.reports_aggregated += self
                    .run_agg_job(&task_id, task_config.as_ref(), reports)
                    .await?;
            }
        }

        // Process pending collect jobs. We wait until all aggregation jobs are finished before
        // proceeding to this step. This is to prevent a race condition involving an aggregate
        // share computed during a collect job and any output shares computed during an aggregation
        // job.
        for (collect_id, collect_req) in self.get_pending_collect_jobs().await? {
            let task_config = self
                .get_task_config_for(&collect_req.task_id)
                .await?
                .ok_or(DapAbort::UnrecognizedTask)?;

            telem.reports_collected += self
                .run_collect_job(&collect_id, task_config.as_ref(), collect_req)
                .await?;
        }

        Ok(telem)
    }
}

/// DAP Helper functionality.
#[async_trait(?Send)]
pub trait DapHelper<'a, S>: DapAggregator<'a, S> {
    /// Update the metadata for the given set of report shares, marking them as aggregated. The
    /// return value is the subset of the report shares that will not be aggregated due to a
    /// transition failure. This occurs if, for example, the report was previously aggregated, but
    /// not collected, or the report has not been aggregated but pertains to a batch that was
    /// previously collected.
    async fn mark_aggregated(
        &self,
        task_id: &Id,
        report_shares: &[ReportShare],
    ) -> Result<HashMap<Nonce, TransitionFailure>, DapError>;

    /// Store the Helper's aggregation-flow state.
    async fn put_helper_state(
        &self,
        task_id: &Id,
        agg_job_id: &Id,
        helper_state: &DapHelperState,
    ) -> Result<(), DapError>;

    /// Fetch the Helper's aggregation-flow state. `None` is returned if the Helper has no state
    /// associated with the given task and aggregation job.
    async fn get_helper_state(
        &self,
        task_id: &Id,
        agg_job_id: &Id,
    ) -> Result<Option<DapHelperState>, DapError>;

    /// Handle an HTTP POST to `/aggregate`. The input is either an AggregateInitializeReq or
    /// AggregateContinueReq and the response is an AggregateResp.
    ///
    /// This is called during the Initialization and Continuation phases.
    async fn http_post_aggregate(&'a self, req: &DapRequest<S>) -> Result<DapResponse, DapAbort> {
        // Check whether the DAP version indicated by the sender is supported.
        if req.version == DapVersion::Unknown {
            return Err(DapAbort::InvalidProtocolVersion);
        }

        if !self.authorized(req).await? {
            return Err(DapAbort::UnauthorizedRequest);
        }

        match req.media_type {
            Some(MEDIA_TYPE_AGG_INIT_REQ) => {
                let agg_init_req = AggregateInitializeReq::get_decoded(&req.payload)?;
                let wrapped_task_config = self
                    .get_task_config_for(&agg_init_req.task_id)
                    .await?
                    .ok_or(DapAbort::UnrecognizedTask)?;
                let task_config = wrapped_task_config.as_ref();
                let helper_state =
                    self.get_helper_state(&agg_init_req.task_id, &agg_init_req.agg_job_id);

                // Check whether the DAP version in the request matches the task config.
                if task_config.version != req.version {
                    return Err(DapAbort::InvalidProtocolVersion);
                }

                // Ensure we know which batch the request pertains to.
                check_part_batch(
                    task_config,
                    &agg_init_req.batch_param,
                    &agg_init_req.agg_param,
                )?;

                // Run mark_aggregated and handle_agg_init_req concurrently.
                let early_rejects_future =
                    self.mark_aggregated(&agg_init_req.task_id, &agg_init_req.report_shares);

                let transition = task_config
                    .vdaf
                    .handle_agg_init_req(self, &task_config.vdaf_verify_key, &agg_init_req)
                    .await?;

                // Check that helper state with task_id and agg_job_id does not exist.
                if helper_state.await?.is_some() {
                    // TODO spec: Consider an explicit abort for this case.
                    return Err(DapAbort::BadRequest(
                        "unexpected message for aggregation job (already exists)".into(),
                    ));
                }

                // Remove reports that are rejected early.
                let early_rejects = early_rejects_future.await?;
                let agg_resp = match transition {
                    DapHelperTransition::Continue(mut state, mut agg_resp) => {
                        let mut i = 0;
                        while i < state.seq.len() {
                            if let Some(failure) = early_rejects.get(&agg_resp.transitions[i].nonce)
                            {
                                // Mark reports that were rejected early as TransitionVar::Failed.
                                agg_resp.transitions[i].var = TransitionVar::Failed(*failure);

                                // Remove VDAF preparation state of reports that were rejected early.
                                if state.seq[i].2 == agg_resp.transitions[i].nonce {
                                    let _val = state.seq.remove(i);
                                } else {
                                    // The nonce in the Helper state and Aggregate response must be aligned.
                                    // Abort with an internal error if this is not the case.
                                    return Err(DapError::fatal("nonces not aligned").into());
                                }
                            } else {
                                i += 1;
                            }
                        }

                        self.put_helper_state(
                            &agg_init_req.task_id,
                            &agg_init_req.agg_job_id,
                            &state,
                        )
                        .await?;
                        agg_resp
                    }
                    DapHelperTransition::Finish(..) => {
                        return Err(DapError::fatal("unexpected transition (finished)").into());
                    }
                };

                Ok(DapResponse {
                    media_type: Some(MEDIA_TYPE_AGG_INIT_RESP),
                    payload: agg_resp.get_encoded(),
                })
            }
            Some(MEDIA_TYPE_AGG_CONT_REQ) => {
                let agg_cont_req = AggregateContinueReq::get_decoded(&req.payload)?;
                let wrapped_task_config = self
                    .get_task_config_for(&agg_cont_req.task_id)
                    .await?
                    .ok_or(DapAbort::UnrecognizedTask)?;
                let task_config = wrapped_task_config.as_ref();

                // Check whether the DAP version in the request matches the task config.
                if task_config.version != req.version {
                    return Err(DapAbort::InvalidProtocolVersion);
                }

                let state = self
                    .get_helper_state(&agg_cont_req.task_id, &agg_cont_req.agg_job_id)
                    .await?
                    .ok_or(DapAbort::UnrecognizedAggregationJob)?;
                let transition = task_config.vdaf.handle_agg_cont_req(state, &agg_cont_req)?;

                let agg_resp = match transition {
                    DapHelperTransition::Continue(..) => {
                        return Err(DapError::fatal("unexpected transition (continued)").into());
                    }
                    DapHelperTransition::Finish(out_shares, agg_resp) => {
                        self.put_out_shares(&agg_cont_req.task_id, out_shares)
                            .await?;
                        agg_resp
                    }
                };

                Ok(DapResponse {
                    media_type: Some(MEDIA_TYPE_AGG_CONT_RESP),
                    payload: agg_resp.get_encoded(),
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
        &'a self,
        req: &DapRequest<S>,
    ) -> Result<DapResponse, DapAbort> {
        let now = self.get_current_time();

        // Check whether the DAP version indicated by the sender is supported.
        if req.version == DapVersion::Unknown {
            return Err(DapAbort::InvalidProtocolVersion);
        }

        if !self.authorized(req).await? {
            return Err(DapAbort::UnauthorizedRequest);
        }

        let agg_share_req = AggregateShareReq::get_decoded(&req.payload)?;
        let wrapped_task_config = self
            .get_task_config_for(&agg_share_req.task_id)
            .await?
            .ok_or(DapAbort::UnrecognizedTask)?;
        let task_config = wrapped_task_config.as_ref();

        // Check whether the DAP version in the request matches the task config.
        if task_config.version != req.version {
            return Err(DapAbort::InvalidProtocolVersion);
        }

        // Ensure the batch boundaries are valid and that the batch doesn't overlap with previosuly
        // collected batches.
        //
        // TODO(issue #100) For "fixed_size" we need to check if we recognize the batch ID.
        check_batch(
            self,
            task_config,
            &agg_share_req.task_id,
            &agg_share_req.batch_selector,
            &agg_share_req.agg_param,
            now,
        )
        .await?;

        let agg_share = self
            .get_agg_share(&agg_share_req.task_id, &agg_share_req.batch_selector)
            .await?;

        // Check that we have aggreagted the same set of reports as the leader.
        if agg_share_req.report_count != agg_share.report_count
            || !constant_time_eq(&agg_share_req.checksum, &agg_share.checksum)
        {
            return Err(DapAbort::BatchMismatch);
        }

        // Check the batch size.
        if !task_config
            .query
            .check_batch_size(agg_share.report_count)
            .unwrap_or(false)
        {
            return Err(DapAbort::InvalidBatchSize);
        }

        // Mark each aggregated report as collected.
        self.mark_collected(&agg_share_req.task_id, &agg_share_req.batch_selector)
            .await?;

        let encrypted_agg_share = task_config.vdaf.produce_helper_encrypted_agg_share(
            &task_config.collector_hpke_config,
            &agg_share_req.task_id,
            &agg_share_req.batch_selector,
            &agg_share,
        )?;

        let agg_share_resp = AggregateShareResp {
            encrypted_agg_share,
        };

        Ok(DapResponse {
            media_type: Some(MEDIA_TYPE_AGG_SHARE_RESP),
            payload: agg_share_resp.get_encoded(),
        })
    }
}

fn check_part_batch(
    task_config: &DapTaskConfig,
    batch_param: &BatchParameter,
    agg_param: &[u8],
) -> Result<(), DapAbort> {
    match (&task_config.query, batch_param) {
        (DapQueryConfig::TimeInterval { .. }, BatchParameter::TimeInterval)
        | (DapQueryConfig::FixedSize { .. }, BatchParameter::FixedSize { .. }) => (),
        _ => return Err(DapAbort::QueryMismatch),
    };

    // Check that the aggreation parameter is suitable for the given VDAF.
    if !task_config.vdaf.is_valid_agg_param(agg_param) {
        // TODO spec: Define this behavior.
        return Err(DapAbort::UnrecognizedMessage);
    }

    Ok(())
}

async fn check_batch<'a, S>(
    agg: &impl DapAggregator<'a, S>,
    task_config: &DapTaskConfig,
    task_id: &Id,
    batch_sel: &BatchSelector,
    agg_param: &[u8],
    now: Time,
) -> Result<(), DapAbort> {
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
                return Err(DapAbort::BatchInvalid);
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
        (DapQueryConfig::FixedSize { .. }, BatchSelector::FixedSize { .. }) => (),
        _ => return Err(DapAbort::QueryMismatch),
    };

    // Check that the batch does not overlap with any previously collected batch.
    if batch_overlapping.await? {
        return Err(DapAbort::BatchOverlap);
    }

    Ok(())
}
