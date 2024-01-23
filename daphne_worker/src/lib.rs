// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

#![warn(unused_crate_dependencies)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::cast_precision_loss)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::needless_pass_by_value)]
#![allow(clippy::ignored_unit_patterns)]
#![allow(clippy::if_not_else)]
#![allow(clippy::default_trait_access)]
#![allow(clippy::items_after_statements)]
#![allow(clippy::redundant_closure_for_method_calls)]
#![allow(clippy::inconsistent_struct_constructor)]
#![allow(clippy::similar_names)]
#![allow(clippy::inline_always)]

//! Daphne-Worker implements a [Workers](https://developers.cloudflare.com/workers/) backend for
//! Daphne.
//!
//! This software is intended to support experimental
//! [DAP](https://datatracker.ietf.org/doc/draft-ietf-ppm-dap/) deployments and is not yet suitable
//! for use in production.
//!
//! # Using Daphne-Worker
//!
//! The code is intended to be packaged with
//! [workers-rs](https://github.com/cloudflare/workers-rs). See [`DaphneWorkerRouter`] for usage
//! instructions.
//!
//! # Architecture
//!
//! Daphne-Worker uses [Durable Objects
//! (DOs)](https://developers.cloudflare.com/workers/learning/using-durable-objects/) for
//! transactional storage.
//!
//! ## Report Storage (Leader-only)
//!
//! The `ReportsPending` DO is used by the Leader to temporarily store reports uploaded by Clients
//! while they wait to be aggregated. In order to allow the Leader to horizontally scale with the
//! upload rate, reports are mapped to one of a number of DO instances running on the Workers
//! platform simultaneously. Reports are partitioned first by task, then by report storage epoch
//! (see `report_storage_epoch_duration` in [`DapGlobalConfig`](daphne::DapGlobalConfig)), then
//! into one of a number of shards. The naming scheme for `ReportsPending` instances is as follows:
//!
//! ```text
//!    <version>/task/<task_id>/epoch/<epoch>/shard/<shard>
//! ```
//!
//! where `<version>` is the DAP version, `<task_id>` is a task ID, `<epoch>` is the report's epoch
//! (the report timestamp truncated by the report storage epoch duration), and `<shard>` is a an
//! integer in range `[0, DAP_REPORT_SHARD_COUNT)`. The shard is determined by applying a
//! keyed has function to the report's ID. (The key is `DAP_REPORT_SHARD_KEY`.)
//!
//! ## Report Metadata Storage (Leader and Helper)
//!
//! The `ReportsProcessed` DO is used by the Leader and Helper to keep track of the set of reports
//! that have been aggregated for a given task. The naming scheme for `ReportsProcessed` is the
//! same as `ReportsPending`:
//!
//! ```text
//!    <version>/task/<task_id>/epoch/<epoch>/shard/<shard>
//! ```
//!
//! where `<version>` is the DAP version, `<task_id>` the task ID0, `<epoch>` the report's epoch,
//! and `<shard>` is the report's shard.
//!
//! ## Aggregate Storage (Leader and Helper)
//!
//! The `AggregateStore` DO is used by the Leader and Helper to store aggregate shares that are
//! ready to be collected. Aggregate shares are partitioned first by task, then by batch bucket.
//! (See [`DapBatchBucket`](daphne::DapBatchBucket).) Each instance of this DO contains an
//! aggregate share and report count. The naming convention for instances of the `AggregateStore`
//! DO is as follows:
//!
//! ```text
//! [Time-interval tasks] <version>/task/<task_id>/window/<window>
//! [Fixed-size tasks]    <version>/task/<task_id>/batch/<batch_id>
//! ```
//!
//! where `<version>` is the DAP version, `<task_id>` is the task ID, `<window>` is a batch window,
//! and `<batch_id>` is a batch ID. A batch window is a UNIX timestamp (in seconds) truncated by
//! the time precision for the task. (See the `time_precision` paramaeter of
//! [`DapTaskConfig`](daphne::DapTaskConfig).)
//!
//! ## Aggregation Jobs (Leader-only)
//!
//! > NOTE: This scheme is not expected to scale well. Currently it is only suited for driving
//! end-to-end tests.
//!
//! The `LeaderAggregationJobQueue` DO is used by the Leader to queue aggregation jobs. There is
//! just one instance of this DO; once a `ReportsPending` instance becomes non-empty, it sends a
//! message to `LeaderAggregationJobQueue` indicating when the instance was created.
//!
//! Aggregation jobs are driven by the Leader's main processing loop (see
//! [`DapLeader::process()`](daphne::roles::DapLeader::process)). The report selector for
//! Daphne-Worker, [`DaphneServiceReportSelector`], indicates the number of jobs to fetch at once
//! (`max_agg_jobs`) and the number of reports to drain per job (`max_reports`).
//!
//! Jobs are handled roughly in order of creation (oldest jobs are handled first). The time at
//! which an aggregation job was created is used determine the order in which it was processed.
//! Timestamps are truncated to the second; ties are broken by a nonce generated at creation time.
//!
//! ## Collection Jobs (Leader-only)
//!
//! > NOTE: This scheme is not expected to scale well. Currently it is only suited for driving
//! end-to-end tests.
//!
//! The `LeaderCollectionJobQueue` DO is used by the Leader to queue collection jobs. There is just
//! one instance of this DO; once the Leader gets a collect request from the Collector, it adds a
//! job to the queue.
//!
//! A "collection job ID" is computed for each job and incorporated into the collect URI for the
//! Collector to poll later on. The job ID Is derived by applying a keyed hash to the serialized
//! [`CollectionReq`](daphne::messages::CollectionReq) message. (The key is `DAP_COLLECT_ID_KEY`.)
//!
//! They are driven by the Leader's main processing loop. After all aggregation jobs are complete,
//! the entire queue is fetched from `LeaderCollectionJobQueue`. In the order in which they were
//! created, the Leader checksto see if the job can be completed (i.e., the span of batch buckets
//! contains a sufficient number of reports).
//!
//! ## Batch Queue (Leader-only).
//!
//! > NOTE: This scheme is not expected to scale well. Currently it is only suited for driving
//! end-to-end tests.
//!
//! The `LeaderBatchQueue` DO is used for fixed-size tasks in order to assign reports to
//! batches. The naming scheme for instances of this DO is as follows:
//!
//! ```text
//!     <version>/task/<task_id>
//! ```
//!
//! where `<version>` is the DAP version and `<task_id>` is the task ID. Each instance maintains a
//! queue of batch. When a set of reports is drained from a `ReportsPending` instance, the the
//! batch in the front of the queue is filled first; if the batch is saturated (i.e., the target
//! batch size is met) then the batch is removed from the queue and the process is repeated.
//!
//! ## Storage of the Helper's State (Helper-only)
//!
//! The `HelperStateStore` DO is used to store the Helper's state
//! ([`DapHelperState`](daphne::DapHelperState)) during the aggregation sub-protocool. It is used
//! to carry state across HTTP requests. The naming scheme for instances of the DO is as follows:
//!
//! ```text
//!     <version>/task/<task_id>/agg_job/<agg_job_id>
//! ```
//!
//! where `<version>` is the DAP version, `<task_id>` is the task ID, and `<agg_job_id>` is the
//! aggregation job ID.
//!
//! # Environment Variables
//!
//! The runtime behavior of Daphne-Worker is controlled by the environment variables defined in the
//! table below.
//!
//! > NOTE: There are additional, undocumented environment variables. These will be lifted to the
//! documentation once we decide what we need for production.
//!
//! | Name | Type | Secret? | Description |
//! | ---- | ---- | ------- | ----------- |
//! | `DAP_AGGREGATOR_ROLE` | `String` | no | Aggregator role, either "leader" or "helper". |
//! | `DAP_COLLECT_ID_KEY` | `String` | yes | Hex-encoded key used to derive the collection job ID from the collect request |
//! | `DAP_GLOBAL_CONFIG` | [`DapGlobalConfig`](daphne::DapGlobalConfig) | no | DAP global config. |
//! | `DAP_DEPLOYMENT` | `String` | no | Deployment type, only "prod" for now. |
//! | `DAP_REPORT_SHARD_COUNT` | `u64` | no | Number of report shards per storage epoch. |
//! | `DAP_REPORT_SHARD_KEY` | `String` | yes | Hex-encoded key used to hash a report into one of the report shards. |

mod auth;
#[deprecated]
pub mod dap_prototype;
mod durable;
pub mod storage_proxy;
mod tracing_utils;

use tracing::error;
use worker::{Date, Env, Error};

pub use crate::tracing_utils::initialize_tracing;
pub use daphne::DapRequest;

pub(crate) fn int_err<S: ToString>(s: S) -> Error {
    error!("internal error: {}", s.to_string());
    Error::RustError("internalError".to_string())
}

pub(crate) fn now() -> u64 {
    Date::now().as_millis() / 1000
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub enum DapWorkerMode {
    DapPrototype,
    StorageProxy,
}
pub fn get_worker_mode(env: &Env) -> DapWorkerMode {
    match env.var("DAP_WORKER_MODE").map(|v| v.to_string()).as_deref() {
        Ok("storage-proxy") => DapWorkerMode::StorageProxy,
        _ => DapWorkerMode::DapPrototype,
    }
}
