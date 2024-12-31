// Copyright (c) 2025 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use axum::async_trait;
use daphne::{
    fatal_error,
    messages::{AggregationJobId, AggregationJobResp, TaskId},
    roles::{helper::AggregationJobRequestHash, DapHelper},
    DapError, DapVersion,
};

#[async_trait]
impl DapHelper for crate::App {
    async fn assert_agg_job_is_legal(
        &self,
        _id: AggregationJobId,
        _version: DapVersion,
        _task_id: &TaskId,
        _req_hash: &AggregationJobRequestHash,
    ) -> Result<(), DapError> {
        // the server implementation can't check for this
        Ok(())
    }

    async fn poll_aggregated(
        &self,
        _version: DapVersion,
        _task_id: &TaskId,
        _agg_job_id: &AggregationJobId,
    ) -> Result<AggregationJobResp, DapError> {
        Err(fatal_error!(err = "polling not implemented"))
    }
}
