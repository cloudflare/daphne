// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! This module implements the in memory data structures necessary to implement an in-memory
//! leader. For a real production implementation this should not be used as it means a machine
//! crash or shutdown would cause in progress tasks to be lost.

use std::collections::{HashMap, VecDeque};

use rand::{thread_rng, Rng};
use url::Url;

use crate::{
    error::DapAbort,
    fatal_error,
    messages::{Base64Encode, BatchId, BatchSelector, Collection, CollectionJobId, Report, TaskId},
    roles::leader::WorkItem,
    DapAggregationParam, DapBatchBucket, DapCollectionJob, DapError, DapQueryConfig, DapTaskConfig,
};

#[derive(Default)]
pub struct InMemoryLeaderState {
    work_queue: VecDeque<WorkItem>,
    per_task: HashMap<TaskId, MockLeaderMemoryPerTask>,
}

impl InMemoryLeaderState {
    #[cfg(any(test, feature = "test-utils"))]
    pub fn work_queue(&self) -> &VecDeque<WorkItem> {
        &self.work_queue
    }

    #[cfg(any(test, feature = "test-utils"))]
    pub fn work_queue_mut(&mut self) -> &mut VecDeque<WorkItem> {
        &mut self.work_queue
    }

    #[cfg(any(test, feature = "test-utils"))]
    pub fn contains_queued_task_of_batch(&self, task_id: &TaskId, batch_id: &BatchId) -> bool {
        self.per_task
            .get(task_id)
            .map(|leader_state| {
                leader_state
                    .batch_queue
                    .iter()
                    .any(|(queued_batch_id, _)| queued_batch_id == batch_id)
            })
            .is_some()
    }

    pub fn delete_all(&mut self) {
        self.work_queue.clear();
        self.per_task.clear();
    }

    pub fn put_report(
        &mut self,
        task_id: &TaskId,
        task_config: &DapTaskConfig,
        report: Report,
    ) -> Result<(), DapError> {
        let per_task = self.per_task.entry(*task_id).or_default();
        let bucket = per_task.assign_report_to_bucket(task_config, &report);

        // Store the report until a collection job is initialized for it. Note that, in a
        // production Leader, it will usually be desirable to start aggregating reports immediately
        // (if allowed by the VDAF).
        per_task
            .pending_reports
            .entry(bucket)
            .or_default()
            .push_back(report);
        Ok(())
    }

    pub fn current_batch(
        &self,
        task_id: &TaskId,
        task_config: &DapTaskConfig,
    ) -> std::result::Result<BatchId, DapError> {
        if !matches!(task_config.query, DapQueryConfig::FixedSize { .. }) {
            return Err(DapError::Abort(DapAbort::BadRequest(
                "tried to get current batch from non fixed-size task".into(),
            )));
        }

        let Some(per_task) = self.per_task.get(task_id) else {
            return Err(DapError::Abort(DapAbort::UnrecognizedTask));
        };

        per_task
            .batch_queue
            .front()
            .map(|(batch_id, _report_count)| *batch_id)
            .ok_or_else(|| DapError::Abort(DapAbort::BadRequest("empty batch queue".into())))
    }

    pub fn enqueue_work(&mut self, work_items: Vec<WorkItem>) -> Result<(), DapError> {
        self.work_queue.extend(work_items);
        Ok(())
    }

    pub fn dequeue_work(&mut self, num_items: usize) -> Result<Vec<WorkItem>, DapError> {
        let mut work_items = Vec::with_capacity(num_items);

        // Drain the work queue for each task, in an arbitrary order. Note that a production
        // Leader would likely need to handle tasks in some priority order, e.g., drain the
        // oldest tasks first.
        let n = std::cmp::min(self.work_queue.len(), num_items);
        work_items.extend(self.work_queue.drain(..n));
        Ok(work_items)
    }

    pub fn init_collect_job(
        &mut self,
        task_id: &TaskId,
        task_config: &DapTaskConfig,
        coll_job_id: &Option<CollectionJobId>,
        batch_sel: BatchSelector,
        agg_param: DapAggregationParam,
    ) -> Result<Url, DapError> {
        let per_task = self.per_task.entry(*task_id).or_default();

        // Construct the collection URI for this collection job.
        let coll_job_id = (*coll_job_id).unwrap_or(CollectionJobId(thread_rng().gen()));
        let coll_job_uri = task_config
            .leader_url
            .join(&format!(
                "collect/task/{}/req/{}",
                task_id.to_base64url(),
                coll_job_id.to_base64url(),
            ))
            .map_err(|e| fatal_error!(err = ?e))?;

        // Store the collection job in the pending state.
        if per_task.coll_jobs.get(&coll_job_id).is_some() {
            return Err(DapError::Abort(DapAbort::BadRequest(format!(
                "tried to overwrite collection job {}",
                coll_job_id.to_base64url()
            ))));
        }

        per_task
            .coll_jobs
            .insert(coll_job_id, DapCollectionJob::Pending);

        // Fill the work queue. Queue an aggregation job for each bucket of pending reports
        // incident to the collection job.
        for bucket in task_config.batch_span_for_sel(&batch_sel)? {
            if let Some(reports) = per_task.pending_reports.remove(&bucket) {
                self.work_queue.push_back(WorkItem::AggregationJob {
                    task_id: *task_id,
                    part_batch_sel: batch_sel.clone().into(),
                    agg_param: agg_param.clone(),
                    reports: reports.into(),
                });
            }

            // The batch will be collected, so remove it from the batch queue.
            if let DapBatchBucket::FixedSize { ref batch_id } = bucket {
                per_task
                    .batch_queue
                    .retain(|(queued_batch_id, _batch_count)| batch_id != queued_batch_id);
            }
        }

        // Queue processing of the collection job.
        self.work_queue.push_back(WorkItem::CollectionJob {
            task_id: *task_id,
            coll_job_id,
            batch_sel,
            agg_param,
        });

        Ok(coll_job_uri)
    }

    pub fn poll_collect_job(
        &self,
        task_id: &TaskId,
        coll_job_id: &CollectionJobId,
    ) -> Result<DapCollectionJob, DapError> {
        if let Some(per_task) = self.per_task.get(task_id) {
            Ok(per_task
                .coll_jobs
                .get(coll_job_id)
                .cloned()
                .unwrap_or(DapCollectionJob::Unknown))
        } else {
            Err(DapError::Abort(DapAbort::UnrecognizedTask))
        }
    }

    pub fn finish_collect_job(
        &mut self,
        task_id: &TaskId,
        coll_job_id: &CollectionJobId,
        collection: &Collection,
    ) -> Result<(), DapError> {
        let Some(per_task) = self.per_task.get_mut(task_id) else {
            return Err(fatal_error!(err = "collect job not found for task_id", %task_id));
        };

        let Some(coll_job) = per_task.coll_jobs.get_mut(coll_job_id) else {
            return Err(fatal_error!(err = "collect job not found for collect_id", %task_id))?;
        };

        match coll_job {
            DapCollectionJob::Pending => {
                // Mark collection job as complete.
                *coll_job = DapCollectionJob::Done(collection.clone());
                Ok(())
            }
            DapCollectionJob::Done(_) => Err(fatal_error!(
                err = "tried to overwrite completed collection job"
            )),
            DapCollectionJob::Unknown => Err(fatal_error!(
                err = "tried to overwrite collection job in unkonwn state"
            )),
        }
    }
}

#[derive(Default)]
struct MockLeaderMemoryPerTask {
    pending_reports: HashMap<DapBatchBucket, VecDeque<Report>>,
    coll_jobs: HashMap<CollectionJobId, DapCollectionJob>,
    batch_queue: VecDeque<(BatchId, u64)>, // Batch ID, batch size
}

impl MockLeaderMemoryPerTask {
    fn assign_report_to_bucket(
        &mut self,
        task_config: &DapTaskConfig,
        report: &Report,
    ) -> DapBatchBucket {
        let mut rng = thread_rng();
        match task_config.query {
            // For fixed-size queries, the bucket corresponds to a single batch.
            DapQueryConfig::FixedSize { .. } => {
                // Assign the report to the first unsaturated batch.
                for (batch_id, report_count) in &mut self.batch_queue {
                    if *report_count < task_config.min_batch_size {
                        *report_count += 1;
                        return DapBatchBucket::FixedSize {
                            batch_id: *batch_id,
                        };
                    }
                }

                // No unsaturated batch exists, so create a new batch.
                let batch_id = BatchId(rng.gen());
                self.batch_queue.push_back((batch_id, 1));
                DapBatchBucket::FixedSize { batch_id }
            }

            // For time-interval queries, the bucket is the batch window computed by truncating the
            // report timestamp.
            DapQueryConfig::TimeInterval => DapBatchBucket::TimeInterval {
                batch_window: task_config.quantized_time_lower_bound(report.report_metadata.time),
            },
        }
    }
}
