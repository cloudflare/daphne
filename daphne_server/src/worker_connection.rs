// Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

#![allow(unused_variables)]
#![allow(clippy::unused_async)]
#![allow(dead_code)]

use daphne::{
    messages::{BatchSelector, TaskId},
    roles::aggregator::MergeAggShareError,
    DapAggregateShare, DapAggregateSpan, DapAggregationJobState, DapError, DapTaskConfig,
    MetaAggregationJobId,
};
use serde::{de::DeserializeOwned, Serialize};
use tokio::io;
use url::Url;

pub(crate) enum Error {
    Serde(serde_json::Error),
}

pub(crate) struct WorkerConn {
    url: Url,
}

impl WorkerConn {
    pub fn new(url: Url) -> Self {
        Self { url }
    }

    pub fn kv(&self) -> Kv<'_> {
        Kv { conn: self }
    }

    pub fn durable_objects(&self) -> Do<'_> {
        Do { conn: self }
    }
}

pub(crate) struct Kv<'w> {
    conn: &'w WorkerConn,
}

impl<'w> Kv<'w> {
    pub fn get<T: DeserializeOwned>(&self, key: &str) -> Result<T, Error> {
        todo!()
    }

    pub fn put<T: Serialize>(&self, key: &str, value: T) -> Result<(), Error> {
        todo!()
    }
}

pub(crate) struct Do<'w> {
    conn: &'w WorkerConn,
}

impl<'w> Do<'w> {
    pub async fn try_put_agg_share_span(
        &self,
        task_id: &TaskId,
        task_config: &DapTaskConfig,
        agg_share_span: &DapAggregateSpan<DapAggregateShare>,
    ) -> Result<DapAggregateSpan<Result<(), MergeAggShareError>>, io::Error> {
        todo!()
    }

    pub async fn get_agg_share(
        &self,
        task_id: &TaskId,
        batch_sel: &BatchSelector,
    ) -> Result<DapAggregateShare, DapError> {
        todo!()
    }

    pub async fn mark_collected(
        &self,
        task_id: &TaskId,
        batch_sel: &BatchSelector,
    ) -> Result<(), DapError> {
        todo!()
    }

    pub async fn put_helper_state_if_not_exits(
        &self,
        task_id: &TaskId,
        agg_job_id: &MetaAggregationJobId,
        helper_state: &DapAggregationJobState,
    ) -> Result<bool, DapError> {
        todo!()
    }

    pub async fn get_helper_state(
        &self,
        task_id: &TaskId,
        agg_job_id: &MetaAggregationJobId,
    ) -> Result<Option<DapAggregationJobState>, DapError> {
        todo!()
    }

    pub async fn is_batch_overlapping(
        &self,
        task_id: &TaskId,
        batch_sel: &BatchSelector,
    ) -> Result<bool, DapError> {
        todo!()
    }
}
