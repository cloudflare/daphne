// Copyright (c) 2025 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use axum::async_trait;
use daphne::{
    messages::{request::AggregationJobRequestHash, AggregationJobId, TaskId},
    roles::DapHelper,
    DapError, DapVersion,
};

#[async_trait]
impl DapHelper for crate::App {
    async fn assert_agg_job_is_immutable(
        &self,
        _id: AggregationJobId,
        _version: DapVersion,
        _task_id: &TaskId,
        _req: &AggregationJobRequestHash,
    ) -> Result<(), DapError> {
        // the server implementation can't check for this
        Ok(())
    }
}
