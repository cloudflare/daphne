// Copyright (c) 2025 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use crate::aggregator::App;
use daphne::{
    error::DapAbort,
    fatal_error,
    messages::{AggregationJobId, AggregationJobResp, TaskId},
    protocol::ReadyAggregationJobResp,
    roles::{helper::AggregationJobRequestHash, DapHelper},
    DapError, DapVersion,
};
use daphne_service_utils::durable_requests::bindings::{
    agg_job_response_store, aggregation_job_store,
};
use std::borrow::Cow;

#[axum::async_trait]
impl DapHelper for App {
    async fn assert_agg_job_is_legal(
        &self,
        id: AggregationJobId,
        version: DapVersion,
        task_id: &TaskId,
        req_hash: &AggregationJobRequestHash,
    ) -> Result<(), DapError> {
        let response = self
            .durable()
            .with_retry()
            .request(aggregation_job_store::Command::NewJob, (version, task_id))
            .encode(&aggregation_job_store::NewJobRequest {
                id,
                agg_job_hash: Cow::Borrowed(req_hash.get()),
            })
            .send::<aggregation_job_store::NewJobResponse>()
            .await
            .map_err(|e| fatal_error!(err = ?e, "failed to store aggregation job hash"))?;

        match response {
            aggregation_job_store::NewJobResponse::Ok => Ok(()),
            aggregation_job_store::NewJobResponse::IllegalJobParameters => Err(
                DapAbort::BadRequest("aggregation job replay changes parameters".to_string())
                    .into(),
            ),
        }
    }

    async fn poll_aggregated(
        &self,
        version: DapVersion,
        task_id: &TaskId,
        agg_job_id: &AggregationJobId,
    ) -> Result<AggregationJobResp, DapError> {
        let valid_agg_job_id = self
            .durable()
            .with_retry()
            .request(
                aggregation_job_store::Command::ContainsJob,
                (version, task_id),
            )
            .encode(agg_job_id)
            .send::<bool>()
            .await
            .map_err(|e| fatal_error!(err = ?e, "failed to query the validity of the aggregation job id"))?;

        if !valid_agg_job_id {
            return Err(DapError::Abort(DapAbort::UnrecognizedAggregationJob {
                task_id: *task_id,
                agg_job_id: *agg_job_id,
            }));
        }

        let response = self
            .durable()
            .with_retry()
            .request(
                agg_job_response_store::Command::Get,
                (version, task_id, agg_job_id),
            )
            .send::<Option<ReadyAggregationJobResp>>()
            .await
            .map_err(|e| fatal_error!(err = ?e, "failed to poll for aggregation job response"))?;

        match response {
            Some(ready) => Ok(ready.into()),
            None => Ok(AggregationJobResp::Processing),
        }
    }
}
