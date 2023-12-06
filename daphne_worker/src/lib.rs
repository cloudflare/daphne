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

mod config;
mod durable;
mod error_reporting;
mod roles;
mod router;
mod tracing_utils;

use crate::config::{DaphneWorkerIsolateState, DaphneWorkerRequestState};
pub use crate::tracing_utils::initialize_tracing;
use daphne::{
    audit_log::{AuditLog, NoopAuditLog},
    DapRequest,
};
pub use error_reporting::ErrorReporter;
use once_cell::sync::OnceCell;
use std::str;
use tracing::{debug, error};
use worker::{Date, Env, Error, Request, Response, Result};

/// HTTP request handler for Daphne-Worker.
pub struct DaphneWorkerRouter<'srv> {
    /// If true, then enable internal test endpoints. These should not be enabled in production.
    pub enable_internal_test: bool,

    /// If true, then respond to unhandled requests with 200 OK instead of 404 Not Found. The
    /// response body can be overrided by setting environment variable DAP_DEFAULT_RESPONSE_HTML.
    pub enable_default_response: bool,

    /// Error reporting for Daphne. By default is a no-op.
    pub error_reporter: &'srv dyn error_reporting::ErrorReporter,

    /// Audit log, used to record statistics of tasks processed.
    pub audit_log: &'srv dyn AuditLog,
}

impl<'srv> Default for DaphneWorkerRouter<'srv> {
    fn default() -> Self {
        Self {
            error_reporter: &error_reporting::NoopErrorReporter {},
            audit_log: &NoopAuditLog,
            enable_internal_test: false,
            enable_default_response: false,
        }
    }
}

/// The response body for unhandled requests when [`DaphneWorkerRouter::enable_default_response`]
/// is set. This value can be overrided by `DAP_DEFAULT_RESPONSE_HTML`.
pub const DEFAULT_RESPONSE_HTML: &str = "<body>Daphne-Worker</body>";

static ISOLATE_STATE: OnceCell<DaphneWorkerIsolateState> = OnceCell::new();

impl DaphneWorkerRouter<'_> {
    /// HTTP request handler for Daphne-Worker.
    ///
    /// This methoed is typically called from the
    /// [workers-rs](https://github.com/cloudflare/workers-rs) `main` function. For example:
    ///
    /// ```ignore
    /// use daphne_worker::DaphneWorkerRouter;
    /// use worker::*;
    ///
    /// #[event(fetch)]
    /// pub async fn main(req: Request, env: Env, _ctx: worker::Context) -> Result<Response> {
    ///     let router = DaphneWorkerRouter::default();
    ///     router.handle_request(req, env).await
    /// }
    /// ```
    //
    // TODO Document endpoints that aren't defined in the DAP spec
    pub async fn handle_request(&self, req: Request, env: Env) -> Result<Response> {
        // Ensure that tracing is initialized. Some callers may choose to initialize earlier,
        // but it's safe and cheap to call initialize_tracing() more than once, and this ensures
        // it's definitely ready for use even if the caller hasn't done anything.
        initialize_tracing(&env);

        #[allow(unused_assignments)]
        let mut uncached_isolate_state: Option<DaphneWorkerIsolateState> = None;
        let shared_state = if env.var("DAP_NO_CACHE").is_ok() {
            debug!("isolate state caching is disabled");
            uncached_isolate_state = Some(DaphneWorkerIsolateState::from_worker_env(&env)?);
            uncached_isolate_state.as_ref().unwrap()
        } else {
            ISOLATE_STATE.get_or_try_init(|| DaphneWorkerIsolateState::from_worker_env(&env))?
        };
        let state =
            DaphneWorkerRequestState::new(shared_state, &req, self.error_reporter, self.audit_log)?;

        let router = router::create_router(
            &state,
            router::RouterOptions {
                enable_internal_test: self.enable_internal_test,
                enable_default_response: self.enable_default_response,
                role: env
                    .var("DAP_AGGREGATOR_ROLE")?
                    .to_string()
                    .parse()
                    .map_err(|role| {
                        worker::Error::RustError(format!("Unhandled DAP role: {role}"))
                    })?,
            },
        );

        // NOTE that we do not have a tracing span for the whole request because it typically
        // reports the same times as the span covering the specific API entry point that the
        // router creates. If curious, you can add .instrument(info_span!("http")) just before
        // the await and see.
        let result = router.run(req, env).await;

        state
            .metrics
            .http_status_code_counter
            .with_label_values(&[&format!(
                "{}",
                result.as_ref().map_or(500, |resp| resp.status_code())
            )])
            .inc();

        // Push metrics to Prometheus metrics server, if configured.
        //
        // TODO(cjpatton) Figure out how to do this step only after we have responded to the client
        // so that the request to the metrics server isn't on the hot path. This should be possible
        // in theory, but I don't know if workers-rs supports it.
        state.maybe_push_metrics().await?;

        result
    }
}

pub(crate) fn now() -> u64 {
    Date::now().as_millis() / 1000
}

pub(crate) fn int_err<S: ToString>(s: S) -> Error {
    error!("internal error: {}", s.to_string());
    Error::RustError("internalError".to_string())
}
