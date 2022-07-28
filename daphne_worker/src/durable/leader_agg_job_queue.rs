// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use crate::int_err;
use serde::{Deserialize, Serialize};
use worker::*;

pub(crate) const DURABLE_LEADER_AGG_JOB_QUEUE_DELETE_ALL: &str =
    "/internal/do/agg_job_queue/delete_all";
pub(crate) const DURABLE_LEADER_AGG_JOB_QUEUE_PUT_PENDING: &str =
    "/internal/do/agg_job_queue/put_pending";
pub(crate) const DURABLE_LEADER_AGG_JOB_QUEUE_GET_PENDING: &str =
    "/internal/do/agg_job_queue/get_pending";
pub(crate) const DURABLE_LEADER_AGG_JOB_QUEUE_FINISH: &str = "/internal/do/agg_job_queue/finish";

/// An aggregation job.
#[derive(Serialize, Deserialize)]
pub(crate) struct AggregationJob {
    /// Durable object ID of the [`ReportStore`](crate::durable::ReportStore) instance with reports
    /// to be aggregated.
    pub(crate) report_store_id_hex: String,

    /// The time at which the aggregation job was scheduled. Aggregation jobs are processed in
    /// order of arrival. [`ReportStore`](crate::durable::ReportStore) sets this to the time the
    /// first report arrived in the bucket.
    pub(crate) time: u64,

    /// A random value used to break ties between jobs with the same time stamp.
    pub(crate) rand: u64,
}

/// Durable Object (DO) representing an aggregation job queue.
///
/// An instance of the [`LeaderAggregationJobQueue`] DO is named `/queue/<queue_num>` where
/// `<queue_num>` is an integer idnentifying a specific queue.
#[durable_object]
pub struct LeaderAggregationJobQueue {
    #[allow(dead_code)]
    state: State,
}

#[durable_object]
impl DurableObject for LeaderAggregationJobQueue {
    fn new(state: State, _env: Env) -> Self {
        Self { state }
    }

    async fn fetch(&mut self, mut req: Request) -> Result<Response> {
        match (req.path().as_ref(), req.method()) {
            (DURABLE_LEADER_AGG_JOB_QUEUE_DELETE_ALL, Method::Post) => {
                self.state.storage().delete_all().await?;
                Response::empty()
            }

            (DURABLE_LEADER_AGG_JOB_QUEUE_PUT_PENDING, Method::Post) => {
                let agg_job: AggregationJob = req.json().await?;
                self.state
                    .storage()
                    .put(&bucket_key_for(&agg_job), agg_job.report_store_id_hex)
                    .await?;
                Response::empty()
            }

            (DURABLE_LEADER_AGG_JOB_QUEUE_GET_PENDING, Method::Post) => {
                let num_buckets: usize = req.json().await?;
                let opt = ListOptions::new().prefix("bucket/").limit(num_buckets);
                let iter = self.state.storage().list_with_options(opt).await?.entries();
                let mut item = iter.next()?;
                let mut res = Vec::new();
                while !item.done() {
                    let (_bucket_key, report_store_id_hex): (String, String) =
                        item.value().into_serde()?;
                    res.push(report_store_id_hex);
                    item = iter.next()?;
                }

                // Results are in order of the oldest bucket first.
                Response::from_json(&res)
            }

            (DURABLE_LEADER_AGG_JOB_QUEUE_FINISH, Method::Post) => {
                let agg_job: AggregationJob = req.json().await?;
                self.state
                    .storage()
                    .delete(&bucket_key_for(&agg_job))
                    .await?;
                Response::empty()
            }

            _ => Err(int_err(format!(
                "LeaderAggregationJobQueue: unexpected request: method={:?}; path={:?}",
                req.method(),
                req.path()
            ))),
        }
    }
}

fn bucket_key_for(agg_job: &AggregationJob) -> String {
    // Format the bucket so that they are processed in order of arrival (oldest first). The
    // timestamp is used for this purpose; the randomm value is used for breaking ties.
    format!("bucket/time/{:020}/rand/{:020}", agg_job.time, agg_job.rand)
}
