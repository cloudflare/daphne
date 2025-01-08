// Copyright (c) 2025 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use crate::aggregator::App;
use daphne::{
    error::DapAbort,
    fatal_error,
    messages::{AggregationJobId, AggregationJobInitReq, TaskId},
    roles::DapHelper,
    DapError, DapVersion,
};
use daphne_service_utils::durable_requests::bindings::aggregation_job_store;

#[axum::async_trait]
impl DapHelper for App {
    async fn assert_agg_job_is_immutable(
        &self,
        id: AggregationJobId,
        version: DapVersion,
        task_id: &TaskId,
        req: &AggregationJobInitReq,
    ) -> Result<(), DapError> {
        let response = self
            .durable()
            .with_retry()
            .request(aggregation_job_store::Command::NewJob, (version, task_id))
            .encode(&aggregation_job_store::NewJobRequest {
                id,
                agg_job_hash: req.into(),
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
}
