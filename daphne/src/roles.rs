// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Trait definitions for Daphne backends.

use crate::{
    constants::{
        MEDIA_TYPE_AGG_CONT_REQ, MEDIA_TYPE_AGG_CONT_RESP, MEDIA_TYPE_AGG_INIT_REQ,
        MEDIA_TYPE_AGG_INIT_RESP, MEDIA_TYPE_AGG_SHARE_REQ, MEDIA_TYPE_AGG_SHARE_RESP,
    },
    hpke::HpkeDecrypter,
    messages::{
        constant_time_eq, AggregateContinueReq, AggregateInitializeReq, AggregateResp,
        AggregateShareReq, AggregateShareResp, CollectReq, CollectResp, Id, Interval, Nonce,
        Report, ReportShare, TransitionFailure,
    },
    DapAbort, DapAggregateShare, DapCollectJob, DapError, DapHelperState, DapHelperTransition,
    DapLeaderProcessTelemetry, DapLeaderTransition, DapOutputShare, DapRequest, DapResponse,
    DapTaskConfig,
};
use async_trait::async_trait;
use prio::codec::{Decode, Encode};
use rand::prelude::*;
use std::collections::HashMap;
use url::Url;

macro_rules! check_batch_param {
    (
        $task_config:expr,
        $batch_interval:expr,
        $agg_param:expr
    ) => {{
        if !$batch_interval.is_valid_for($task_config) {
            return Err(DapAbort::InvalidBatchInterval);
        }

        // Check that the aggreation parameter is suitable for the given VDAF.
        if !$task_config.vdaf.is_valid_agg_param(&$agg_param) {
            // TODO spec: Define this behavior.
            return Err(DapAbort::UnrecognizedMessage);
        }
    }};
}

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
pub trait DapAggregator<S>: HpkeDecrypter + Sized {
    /// Decide whether the given DAP request is authorized.
    async fn authorized(&self, req: &DapRequest<S>) -> Result<bool, DapError>;

    /// Look up the DAP task configuration for the given task ID.
    fn get_task_config_for(&self, task_id: &Id) -> Option<&DapTaskConfig>;

    /// Store a set of output shares.
    async fn put_out_shares(
        &self,
        task_id: &Id,
        out_shares: Vec<DapOutputShare>,
    ) -> Result<(), DapError>;

    /// Fetch the aggregate share for the given batch interval.
    async fn get_agg_share(
        &self,
        task_id: &Id,
        batch_interval: &Interval,
    ) -> Result<DapAggregateShare, DapError>;

    /// Mark a batch as collected.
    async fn mark_collected(&self, task_id: &Id, batch_interval: &Interval)
        -> Result<(), DapError>;

    /// Handle HTTP GET to `/hpke_config?task_id=<task_id>`. Returns the encoded HPKE config to put
    /// in the body of the response.
    async fn http_get_hpke_config(&self, req: &DapRequest<S>) -> Result<Vec<u8>, DapAbort> {
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
            let hpke_config = self
                .get_hpke_config_for(task_id)
                .ok_or(DapAbort::UnrecognizedTask)?;
            Ok(hpke_config.get_encoded())
        } else {
            Err(DapAbort::BadRequest("missing query parameter".into()))
        }
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
pub trait DapLeader<S>: DapAuthorizedSender<S> + DapAggregator<S> {
    /// Data type used to guide selection of a set of reports for aggregation.
    type ReportSelector;

    /// Store a sequence of reports to use later on. Each input is the encoded report sent in the
    /// body of an HTTP request.
    //
    // TODO(MVP) Just put one report with this interface.
    async fn put_reports<I: IntoIterator<Item = Report>>(&self, reports: I)
        -> Result<(), DapError>;

    /// Fetch a sequence of reports to aggregate. The reports returned are removed from persistent
    /// storage.
    async fn get_reports(
        &self,
        task_id: &Id,
        selector: &Self::ReportSelector,
    ) -> Result<Vec<Report>, DapError>;

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

    /// Return the sequence of pending collect jobs for a given task, in order of priority.
    async fn get_pending_collect_jobs(
        &self,
        task_id: &Id,
    ) -> Result<Vec<(Id, CollectReq)>, DapError>;

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
    async fn http_post_upload(&self, req: &DapRequest<S>) -> Result<(), DapAbort> {
        let report = Report::get_decoded(req.payload.as_ref())?;
        if self.get_task_config_for(&report.task_id).is_none() {
            return Err(DapAbort::UnrecognizedTask);
        }

        if report.encrypted_input_shares.len() != 2 {
            // TODO spec: Decide if this behavior should be specified.
            return Err(DapAbort::UnrecognizedMessage);
        }

        // Check that the indicated HpkeConfig is present.
        //
        // TODO spec: It's not clear if this behavior is MUST, SHOULD, or MAY.
        if !self.can_hpke_decrypt(&report.task_id, report.encrypted_input_shares[0].config_id) {
            return Err(DapAbort::UnrecognizedHpkeConfig);
        }

        Ok(self.put_reports([report]).await?)
    }

    /// Handle HTTP POST to `/collect`. The input is a [`CollectReq`](crate::messages::CollectReq).
    /// The return value is a URI that the Collector can poll later on to get the corresponding
    /// [`CollectResp`](crate::messages::CollectResp).
    async fn http_post_collect(&self, req: &DapRequest<S>) -> Result<Url, DapAbort> {
        if !self.authorized(req).await? {
            return Err(DapAbort::UnauthorizedRequest);
        }

        let collect_req = CollectReq::get_decoded(req.payload.as_ref())?;
        let task_config = self
            .get_task_config_for(&collect_req.task_id)
            .ok_or(DapAbort::UnrecognizedTask)?;
        check_batch_param!(
            task_config,
            collect_req.batch_interval,
            collect_req.agg_param
        );

        if !collect_req.batch_interval.is_valid_for(task_config) {
            return Err(DapAbort::InvalidBatchInterval);
        }

        // Check that the aggreation parameter is suitable for the given VDAF.
        if !task_config.vdaf.is_valid_agg_param(&collect_req.agg_param) {
            // TODO spec: Define this behavior.
            return Err(DapAbort::UnrecognizedMessage);
        }

        Ok(self.init_collect_job(&collect_req).await?)
    }

    /// Run an aggregation job if there are pending reports and process all pending collect jobs.
    async fn process(
        &self,
        task_id: &Id,
        selector: &Self::ReportSelector,
    ) -> Result<DapLeaderProcessTelemetry, DapAbort> {
        let mut rng = thread_rng();
        let mut telem = DapLeaderProcessTelemetry::default();

        let task_config = self
            .get_task_config_for(task_id)
            .ok_or(DapAbort::UnrecognizedTask)?;

        // Pick the set of candidate reports.
        let reports = self.get_reports(task_id, selector).await?;
        telem.reports_processed += reports.len() as u64;
        if !reports.is_empty() {
            // Prepare AggregateInitializeReq.
            let agg_job_id = Id(rng.gen());
            let transition = task_config.vdaf.produce_agg_init_req(
                self,
                &task_config.vdaf_verify_key,
                task_id,
                &agg_job_id,
                reports,
            )?;
            let (state, agg_init_req) = match transition {
                DapLeaderTransition::Continue(state, agg_init_req) => (state, agg_init_req),
                DapLeaderTransition::Skip => return Ok(telem),
                DapLeaderTransition::Uncommitted(..) => {
                    return Err(DapError::fatal("unexpected state transition (uncommitted)").into())
                }
            };

            // Send AggregateInitializeReq and receive AggregateResp.
            let resp = leader_post!(
                self,
                task_id,
                task_config,
                "/aggregate",
                MEDIA_TYPE_AGG_INIT_REQ,
                agg_init_req.get_encoded()
            );
            let agg_resp = AggregateResp::get_decoded(&resp.payload)?;

            // Prepare AggreagteContinueReq.
            let transition =
                task_config
                    .vdaf
                    .handle_agg_resp(task_id, &agg_job_id, state, agg_resp)?;
            let (uncommited, agg_cont_req) = match transition {
                DapLeaderTransition::Uncommitted(uncommited, agg_cont_req) => {
                    (uncommited, agg_cont_req)
                }
                DapLeaderTransition::Skip => return Ok(telem),
                DapLeaderTransition::Continue(..) => {
                    return Err(DapError::fatal("unexpected state transition (continue)").into())
                }
            };

            // Send AggregateContinueReq and receive AggregateResp.
            let resp = leader_post!(
                self,
                task_id,
                task_config,
                "/aggregate",
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
            telem.reports_aggregated += out_shares_count;
        }

        // Process pending collect jobs.
        let pending = self.get_pending_collect_jobs(task_id).await?;
        for (collect_id, collect_req) in pending.into_iter() {
            let leader_agg_share = self
                .get_agg_share(&collect_req.task_id, &collect_req.batch_interval)
                .await?;

            // Check that the minimum batch size is met.
            if leader_agg_share.report_count < task_config.min_batch_size {
                continue;
            }

            // Prepare the Leader's aggregate share.
            let leader_enc_agg_share = task_config.vdaf.produce_leader_encrypted_agg_share(
                &task_config.collector_hpke_config,
                &collect_req.task_id,
                &collect_req.batch_interval,
                &leader_agg_share,
            )?;

            // Prepare AggregateShareReq.
            let agg_share_req = AggregateShareReq {
                task_id: collect_req.task_id.clone(),
                batch_interval: collect_req.batch_interval.clone(),
                agg_param: collect_req.agg_param.clone(),
                report_count: leader_agg_share.report_count,
                checksum: leader_agg_share.checksum,
            };

            // Send AggregateShareReq and receive AggregateShareResp.
            let resp = leader_post!(
                self,
                task_id,
                task_config,
                "/aggregate_share",
                MEDIA_TYPE_AGG_SHARE_REQ,
                agg_share_req.get_encoded()
            );
            let agg_share_resp = AggregateShareResp::get_decoded(&resp.payload)?;

            // Complete the collect job.
            let collect_resp = CollectResp {
                encrypted_agg_shares: vec![
                    leader_enc_agg_share,
                    agg_share_resp.encrypted_agg_share,
                ],
            };
            self.finish_collect_job(task_id, &collect_id, &collect_resp)
                .await?;

            // Mark reports as collected.
            self.mark_collected(&agg_share_req.task_id, &agg_share_req.batch_interval)
                .await?;
            telem.reports_collected += agg_share_req.report_count;
        }

        Ok(telem)
    }
}

/// DAP Helper functionality.
#[async_trait(?Send)]
pub trait DapHelper<S>: DapAggregator<S> {
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

    /// Fetch the Helper's aggregation-flow state.
    async fn get_helper_state(
        &self,
        task_id: &Id,
        agg_job_id: &Id,
    ) -> Result<DapHelperState, DapError>;

    /// Handle an HTTP POST to `/aggregate`. The input is an AggregateInitializeReq and the
    /// response is an AggregateResp.
    async fn http_post_aggregate(&self, req: &DapRequest<S>) -> Result<DapResponse, DapAbort> {
        if !self.authorized(req).await? {
            return Err(DapAbort::UnauthorizedRequest);
        }

        match req.media_type {
            Some(MEDIA_TYPE_AGG_INIT_REQ) => {
                let agg_init_req = AggregateInitializeReq::get_decoded(&req.payload)?;
                let task_config = self
                    .get_task_config_for(&agg_init_req.task_id)
                    .ok_or(DapAbort::UnrecognizedTask)?;

                let early_fails = self
                    .mark_aggregated(&agg_init_req.task_id, &agg_init_req.report_shares)
                    .await?;

                let transition = task_config.vdaf.handle_agg_init_req(
                    self,
                    &task_config.vdaf_verify_key,
                    &agg_init_req,
                    |nonce| early_fails.get(nonce).copied(),
                )?;

                let agg_resp = match transition {
                    DapHelperTransition::Continue(state, agg_resp) => {
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
                let task_config = self
                    .get_task_config_for(&agg_cont_req.task_id)
                    .ok_or(DapAbort::UnrecognizedTask)?;

                let state = self
                    .get_helper_state(&agg_cont_req.task_id, &agg_cont_req.agg_job_id)
                    .await?;
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
    async fn http_post_aggregate_share(
        &self,
        req: &DapRequest<S>,
    ) -> Result<DapResponse, DapAbort> {
        if !self.authorized(req).await? {
            return Err(DapAbort::UnauthorizedRequest);
        }

        let agg_share_req = AggregateShareReq::get_decoded(&req.payload)?;
        let task_config = self
            .get_task_config_for(&agg_share_req.task_id)
            .ok_or(DapAbort::UnrecognizedTask)?;
        check_batch_param!(
            task_config,
            agg_share_req.batch_interval,
            agg_share_req.agg_param
        );

        let agg_share = self
            .get_agg_share(&agg_share_req.task_id, &agg_share_req.batch_interval)
            .await?;

        // Check that we have aggreagted the same set of reports as the leader.
        if agg_share_req.report_count != agg_share.report_count
            || !constant_time_eq(&agg_share_req.checksum, &agg_share.checksum)
        {
            return Err(DapAbort::BatchMismatch);
        }

        // Check that the minimum batch size is met.
        if agg_share.report_count < task_config.min_batch_size {
            return Err(DapAbort::InsufficientBatchSize);
        }

        // Mark each aggregated report as collected.
        self.mark_collected(&agg_share_req.task_id, &agg_share_req.batch_interval)
            .await?;

        let encrypted_agg_share = task_config.vdaf.produce_helper_encrypted_agg_share(
            &task_config.collector_hpke_config,
            &agg_share_req.task_id,
            &agg_share_req.batch_interval,
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
