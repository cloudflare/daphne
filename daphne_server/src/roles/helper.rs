// Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use axum::async_trait;
use daphne::{
    messages::TaskId, roles::DapHelper, DapAggregationJobState, DapError, MetaAggregationJobId,
};

#[async_trait]
impl<S: Sync> DapHelper<S> for crate::App {
    async fn put_helper_state_if_not_exists<Id>(
        &self,
        task_id: &TaskId,
        agg_job_id: Id,
        helper_state: &DapAggregationJobState,
    ) -> Result<bool, DapError>
    where
        Id: Into<MetaAggregationJobId> + Send,
    {
        self.worker
            .durable_objects()
            .put_helper_state_if_not_exits(task_id, &agg_job_id.into(), helper_state)
            .await
    }

    async fn get_helper_state<Id>(
        &self,
        task_id: &TaskId,
        agg_job_id: Id,
    ) -> Result<Option<DapAggregationJobState>, DapError>
    where
        Id: Into<MetaAggregationJobId> + Send,
    {
        self.worker
            .durable_objects()
            .get_helper_state(task_id, &agg_job_id.into())
            .await
    }
}
