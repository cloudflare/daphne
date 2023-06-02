// Copyright (c) 2023 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use crate::{messages::TaskId, DapTaskConfig};

pub enum AggregationJobAuditAction {
    Init,
    Continue,
}

pub trait AuditLog {
    fn on_aggregation_job(
        &self,
        host: &str,
        task_id: &TaskId,
        task_config: &DapTaskConfig,
        report_count: u64,
        action: AggregationJobAuditAction,
    );
}

/// Default implementation of the trait, which is a no-op.
pub struct NoopAuditLog;

impl AuditLog for NoopAuditLog {
    fn on_aggregation_job(
        &self,
        _host: &str,
        _task_id: &TaskId,
        _task_config: &DapTaskConfig,
        _report_count: u64,
        _action: AggregationJobAuditAction,
    ) {
    }
}
