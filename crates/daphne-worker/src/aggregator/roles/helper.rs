// Copyright (c) 2025 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use crate::aggregator::App;
use daphne::{
    error::DapAbort,
    fatal_error,
    messages::{AggregationJobId, TaskId},
    roles::{helper::AggregationJobRequestHash, DapHelper},
    DapError, DapVersion,
};
use daphne_service_utils::durable_requests::bindings::aggregation_job_store;
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
}
