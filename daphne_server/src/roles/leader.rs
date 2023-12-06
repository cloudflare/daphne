// Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

#![allow(unused_variables)]

use std::collections::HashMap;

use axum::async_trait;
use daphne::{
    constants::DapMediaType,
    messages::{Collection, CollectionJobId, CollectionReq, PartialBatchSelector, Report, TaskId},
    roles::{DapAuthorizedSender, DapLeader},
    DapCollectJob, DapError, DapRequest, DapResponse, DapTaskConfig,
};
use daphne_service_utils::auth::DaphneAuth;
use serde::{Deserialize, Serialize};
use url::Url;

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
        todo!()
    }
}

#[async_trait]
impl DapLeader<DaphneAuth> for crate::App {
    type ReportSelector = DaphneReportSelector;

    async fn put_report(&self, report: &Report, task_id: &TaskId) -> Result<(), DapError> {
        todo!()
    }

    async fn get_reports(
        &self,
        report_sel: &Self::ReportSelector,
    ) -> Result<HashMap<TaskId, HashMap<PartialBatchSelector, Vec<Report>>>, DapError> {
        todo!()
    }

    async fn init_collect_job(
        &self,
        task_id: &TaskId,
        collect_job_id: &Option<CollectionJobId>,
        collect_req: &CollectionReq,
    ) -> Result<url::Url, DapError> {
        todo!()
    }

    async fn poll_collect_job(
        &self,
        task_id: &TaskId,
        collect_id: &CollectionJobId,
    ) -> Result<DapCollectJob, DapError> {
        todo!()
    }

    async fn get_pending_collect_jobs(
        &self,
    ) -> Result<Vec<(TaskId, CollectionJobId, CollectionReq)>, DapError> {
        todo!()
    }

    async fn finish_collect_job(
        &self,
        task_id: &TaskId,
        collect_id: &CollectionJobId,
        collect_resp: &Collection,
    ) -> Result<(), DapError> {
        todo!()
    }

    async fn send_http_post(
        &self,
        req: DapRequest<DaphneAuth>,
        url: Url,
    ) -> Result<DapResponse, DapError> {
        todo!()
    }

    async fn send_http_put(
        &self,
        req: DapRequest<DaphneAuth>,
        url: Url,
    ) -> Result<DapResponse, DapError> {
        todo!()
    }
}
