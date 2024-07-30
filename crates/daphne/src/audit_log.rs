// Copyright (c) 2023 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use crate::{messages::TaskId, DapTaskConfig};

pub trait AuditLog {
    fn on_aggregation_job(
        &self,
        task_id: &TaskId,
        task_config: &DapTaskConfig,
        report_count: u64,
        vdaf_step: u8,
    );
}

/// Default implementation of the trait, which is a no-op.
pub struct NoopAuditLog;

impl AuditLog for NoopAuditLog {
    fn on_aggregation_job(
        &self,
        _task_id: &TaskId,
        _task_config: &DapTaskConfig,
        _report_count: u64,
        _vdaf_step: u8,
    ) {
    }
}
