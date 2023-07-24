// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

#![warn(unused_crate_dependencies)]

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
//! Daphne-Worker, [`DaphneWorkerReportSelector`], indicates the number of jobs to fetch at once
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
mod config;
mod dap;
mod durable;
mod error_reporting;
mod metrics;
mod tracing_utils;

pub use crate::tracing_utils::initialize_tracing;
use crate::{
    config::{DaphneWorkerIsolateState, DaphneWorkerRequestState},
    dap::dap_response_to_worker,
    tracing_utils::MeasuredSpanName,
};
use daphne::{
    audit_log::{AuditLog, NoopAuditLog},
    auth::BearerToken,
    constants::DapMediaType,
    error::DapAbort,
    hpke::HpkeReceiverConfig,
    messages::{CollectionJobId, Duration, TaskId, Time},
    roles::{DapAggregator, DapHelper, DapLeader},
    DapCollectJob, DapError, DapRequest, DapResponse, DapVersion,
};
pub use error_reporting::ErrorReporter;
use once_cell::sync::OnceCell;
use prio::codec::ParameterizedEncode;
use serde::{Deserialize, Serialize};
use std::str;
use tracing::{debug, error, info_span, Instrument};
use worker::*;

/// Parameters used by the Leader to select a set of reports for aggregation.
#[derive(Debug, Deserialize, Serialize)]
pub struct DaphneWorkerReportSelector {
    /// Maximum number of aggregation jobs to process at once.
    pub max_agg_jobs: u64,

    /// Maximum number of reports to drain for each aggregation job.
    pub max_reports: u64,
}

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
/// is set. This value can be overrided by DAP_DEFAULT_RESPONSE_HTML.
pub const DEFAULT_RESPONSE_HTML: &str = "<body>Daphne-Worker</body>";

static ISOLATE_STATE: OnceCell<DaphneWorkerIsolateState> = OnceCell::new();

macro_rules! info_span_from_dap_request {
    ($span_name:expr, $req:expr) => {{
        let req: &DapRequest<_> = &$req;
        let task_id = req
            .task_id
            .clone()
            .map(|v| v.to_string())
            .unwrap_or_else(|| "unknown".to_owned());

        info_span!(
            $span_name,
            dap.task_id = task_id,
            version = req.version.to_string()
        )
    }};
}

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

        let router = Router::with_data(&state)
            .get_async("/:version/hpke_config", |req, ctx| async move {
                let daph = ctx.data.handler(&ctx.env);
                let req = daph.worker_request_to_dap(req, &ctx).await?;

                let span = info_span_from_dap_request!("hpke_config", req);

                match daph.handle_hpke_config_req(&req).instrument(span).await {
                    Ok(req) => dap_response_to_worker(req),
                    Err(e) => daph.state.dap_abort_to_worker_response(e),
                }
            })
            .post_async("/task", |mut req, ctx| async move {
                let daph = ctx.data.handler(&ctx.env);
                let admin_token = req
                    .headers()
                    .get("X-Daphne-Worker-Admin-Bearer-Token")?
                    .map(BearerToken::from);

                if daph.config().admin_token.is_none() {
                    return Response::error("admin not configured", 400);
                }

                if admin_token.is_none() || admin_token != daph.config().admin_token {
                    return Response::error("missing or invalid bearer token for admin", 401);
                }

                let cmd: InternalTestAddTask = req.json().await?;
                daph.internal_add_task(daph.config().default_version, cmd)
                    .instrument(info_span!("task"))
                    .await?;
                Response::empty()
            });

        let router = match env.var("DAP_AGGREGATOR_ROLE")?.to_string().as_ref() {
            "leader" => {
                router
                    .post_async("/v02/upload", put_report_into_task) // draft02
                    .put_async("/:version/tasks/:task_id/reports", put_report_into_task)
                    .post_async("/v02/collect", |req, ctx| async move {
                        let daph = ctx.data.handler(&ctx.env);
                        let req = daph.worker_request_to_dap(req, &ctx).await?;

                        let span = info_span_from_dap_request!("collect", req);

                        match daph.handle_collect_job_req(&req).instrument(span).await {
                            Ok(collect_uri) => {
                                let mut headers = Headers::new();
                                headers.set("Location", collect_uri.as_str())?;
                                Ok(Response::empty()
                                    .unwrap()
                                    .with_status(303)
                                    .with_headers(headers))
                            }
                            Err(e) => daph.state.dap_abort_to_worker_response(e),
                        }
                    }) // draft02
                    .get_async(
                        "/v02/collect/task/:task_id/req/:collect_id",
                        |req, ctx| async move {
                            let task_id =
                                match ctx.param("task_id").and_then(TaskId::try_from_base64url) {
                                    Some(id) => id,
                                    None => {
                                        return ctx.data.dap_abort_to_worker_response(
                                            DapAbort::BadRequest(
                                                "missing task_id parameter".to_string(),
                                            ),
                                        )
                                    }
                                };
                            let collect_id = match ctx
                                .param("collect_id")
                                .and_then(CollectionJobId::try_from_base64url)
                            {
                                Some(id) => id,
                                None => {
                                    return ctx.data.dap_abort_to_worker_response(
                                        DapAbort::BadRequest(
                                            "missing collect_id parameter".to_string(),
                                        ),
                                    )
                                }
                            };
                            let daph = ctx.data.handler(&ctx.env);
                            let version = daph.extract_version_parameter(&req)?;
                            match daph
                                .poll_collect_job(&task_id, &collect_id)
                                .instrument(info_span!("poll_collect_job (draft02)"))
                                .await
                            {
                                Ok(DapCollectJob::Done(collect_resp)) => {
                                    dap_response_to_worker(DapResponse {
                                        version: DapVersion::Draft02,
                                        media_type: DapMediaType::Collection,
                                        payload: collect_resp.get_encoded_with_param(&version),
                                    })
                                }
                                Ok(DapCollectJob::Pending) => {
                                    Ok(Response::empty().unwrap().with_status(202))
                                }
                                // TODO spec: Decide whether to define this behavior.
                                Ok(DapCollectJob::Unknown) => daph
                                    .state
                                    .dap_abort_to_worker_response(DapAbort::BadRequest(
                                        "unknown collect id".into(),
                                    )),
                                Err(e) => daph.state.dap_abort_to_worker_response(e.into()),
                            }
                        },
                    ) // draft02
                    .put_async(
                        "/:version/tasks/:task_id/collection_jobs/:collect_job_id",
                        |req, ctx| async move {
                            let daph = ctx.data.handler(&ctx.env);
                            let req = daph.worker_request_to_dap(req, &ctx).await?;

                            let span = info_span_from_dap_request!("collect (PUT)", req);

                            match daph.handle_collect_job_req(&req).instrument(span).await {
                                Ok(_) => Ok(Response::empty().unwrap().with_status(201)),
                                Err(e) => daph.state.dap_abort_to_worker_response(e),
                            }
                        },
                    )
                    .post_async(
                        "/:version/tasks/:task_id/collection_jobs/:collect_job_id",
                        |req, ctx| async move {
                            let daph = ctx.data.handler(&ctx.env);
                            let req = daph.worker_request_to_dap(req, &ctx).await?;
                            let task_id = match req.task_id() {
                                Ok(id) => id,
                                Err(e) => return daph.state.dap_abort_to_worker_response(e),
                            };
                            // We cannot check a resource here as the resource is set via
                            // media type, and there is no media type when polling.
                            //
                            // We can unwrap() here as the parameter really must exist.
                            let collect_job_id_base64url = ctx.param("collect_job_id").unwrap();
                            let collect_job_id =
                                match CollectionJobId::try_from_base64url(collect_job_id_base64url)
                                {
                                    Some(id) => id,
                                    None => {
                                        return daph.state.dap_abort_to_worker_response(
                                            DapAbort::BadRequest("malformed collect id".into()),
                                        )
                                    }
                                };

                            let span = info_span!(
                                "poll_collect_job",
                                dap.task_id = %task_id,
                                version = req.version.to_string()
                            );

                            match daph
                                .poll_collect_job(task_id, &collect_job_id)
                                .instrument(span)
                                .await
                            {
                                Ok(DapCollectJob::Done(collect_resp)) => {
                                    dap_response_to_worker(DapResponse {
                                        version: req.version,
                                        media_type: DapMediaType::Collection,
                                        payload: collect_resp.get_encoded_with_param(&req.version),
                                    })
                                }
                                Ok(DapCollectJob::Pending) => {
                                    Ok(Response::empty().unwrap().with_status(202))
                                }
                                // TODO spec: Decide whether to define this behavior.
                                Ok(DapCollectJob::Unknown) => daph
                                    .state
                                    .dap_abort_to_worker_response(DapAbort::BadRequest(
                                        "unknown collect id".into(),
                                    )),
                                Err(e) => daph.state.dap_abort_to_worker_response(e.into()),
                            }
                        },
                    )
                    .post_async("/internal/process", |mut req, ctx| async move {
                        // TODO(cjpatton) Only enable this if `self.enable_internal_test` is set.
                        let daph = ctx.data.handler(&ctx.env);
                        let report_sel: DaphneWorkerReportSelector = req.json().await?;
                        match daph
                            .process(&report_sel, &daph.state.host)
                            .instrument(info_span!("process"))
                            .await
                        {
                            Ok(telem) => {
                                debug!("{:?}", telem);
                                Response::from_json(&telem)
                            }
                            Err(e) => daph.state.dap_abort_to_worker_response(e),
                        }
                    })
                    .get_async(
                        "/internal/current_batch/task/:task_id",
                        |_req, ctx| async move {
                            // Return the ID of the oldest, not-yet-collecgted batch for the specified
                            // task. The task ID and batch ID are both encoded in URL-safe base64.
                            //
                            // TODO(cjpatton) Only enable this if `self.enable_internal_test` is set.
                            let daph = ctx.data.handler(&ctx.env);
                            let task_id = match ctx
                                .param("task_id")
                                .and_then(TaskId::try_from_base64url)
                            {
                                Some(id) => id,
                                None => {
                                    return daph.state.dap_abort_to_worker_response(
                                        DapAbort::BadRequest("missing or malformed task ID".into()),
                                    )
                                }
                            };
                            match daph
                                .internal_current_batch(&task_id)
                                .instrument(info_span!("current_batch"))
                                .await
                            {
                                Ok(batch_id) => Response::from_bytes(
                                    batch_id.to_base64url().as_bytes().to_owned(),
                                ),
                                Err(e) => daph.state.dap_abort_to_worker_response(e.into()),
                            }
                        },
                    )
            }

            "helper" => router
                .post_async("/:version/aggregate", handle_agg_job) // draft02
                .post_async("/:version/aggregate_share", handle_agg_share_req) // draft02
                .put_async(
                    "/:version/tasks/:task_id/aggregation_jobs/:agg_job_id",
                    handle_agg_job,
                )
                .post_async(
                    "/:version/tasks/:task_id/aggregation_jobs/:agg_job_id",
                    handle_agg_job,
                )
                .post_async(
                    "/:version/tasks/:task_id/aggregate_shares",
                    handle_agg_share_req,
                ),

            role => return Err(Error::RustError(format!("Unhandled DAP role: {role}"))),
        };

        let router = if self.enable_internal_test {
            router
                .post_async("/internal/delete_all", |_req, ctx| async move {
                    let daph = ctx.data.handler(&ctx.env);
                    match daph
                        .internal_delete_all()
                        .instrument(info_span!("delete_all"))
                        .await
                    {
                        Ok(()) => Response::empty(),
                        Err(e) => daph.state.dap_abort_to_worker_response(e.into()),
                    }
                })
                // Endpoints for draft-dcook-ppm-dap-interop-test-design-02
                .post_async("/internal/test/ready", |_req, _ctx| async move {
                    Response::from_json(&())
                })
                .post_async(
                    "/internal/test/endpoint_for_task",
                    |mut req, ctx| async move {
                        let daph = ctx.data.handler(&ctx.env);
                        let cmd: InternalTestEndpointForTask = req.json().await?;
                        daph.internal_endpoint_for_task(daph.config().default_version, cmd)
                            .instrument(info_span!("endpoint_for_task"))
                            .await
                    },
                )
                .post_async(
                    "/:version/internal/test/endpoint_for_task",
                    |mut req, ctx| async move {
                        let daph = ctx.data.handler(&ctx.env);
                        let cmd: InternalTestEndpointForTask = req.json().await?;
                        let version = daph.extract_version_parameter(&req)?;
                        daph.internal_endpoint_for_task(version, cmd)
                            .instrument(info_span!("endpoint_for_task"))
                            .await
                    },
                )
                .post_async("/internal/test/add_task", |mut req, ctx| async move {
                    let daph = ctx.data.handler(&ctx.env);
                    let cmd: InternalTestAddTask = req.json().await?;
                    daph.internal_add_task(daph.config().default_version, cmd)
                        .instrument(info_span!("add_task"))
                        .await?;
                    Response::from_json(&serde_json::json!({
                        "status": "success",
                    }))
                })
                .post_async(
                    "/:version/internal/test/add_task",
                    |mut req, ctx| async move {
                        let daph = ctx.data.handler(&ctx.env);
                        let cmd: InternalTestAddTask = req.json().await?;
                        let version = daph.extract_version_parameter(&req)?;
                        daph.internal_add_task(version, cmd)
                            .instrument(info_span!("add_task"))
                            .await?;
                        Response::from_json(&serde_json::json!({
                            "status": "success",
                        }))
                    },
                )
                .post_async(
                    "/:version/internal/test/add_hpke_config",
                    |mut req, ctx| async move {
                        let daph = ctx.data.handler(&ctx.env);
                        let hpke: HpkeReceiverConfig = req.json().await?;
                        let version = daph.extract_version_parameter(&req)?;
                        daph.internal_add_hpke_config(version, hpke)
                            .instrument(info_span!("add_hpke_config"))
                            .await?;
                        Response::from_json(&serde_json::json!({
                            "status": "success",
                        }))
                    },
                )
        } else {
            router
        };

        let router = if self.enable_default_response {
            router.or_else_any_method_async("/*catchall", |_req, ctx| async move {
                match ctx.var("DAP_DEFAULT_RESPONSE_HTML") {
                    Ok(text) => Response::from_html(text.to_string()),
                    Err(..) => Response::from_html(DEFAULT_RESPONSE_HTML),
                }
            })
        } else {
            router
        };

        // NOTE that we do not have a tracing span for the whole request because it typically
        // reports the same times as the span covering the specific API entry point that the
        // router creates. If curious, you can add .instrument(info_span!("http")) just before
        // the await and see.
        let result = router.run(req, env).await;

        state
            .metrics
            .http_status_code_counter
            .with_label_values(&[
                &state.host,
                &format!("{}", result.as_ref().map_or(500, |resp| resp.status_code())),
            ])
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

async fn put_report_into_task(
    req: Request,
    ctx: RouteContext<&DaphneWorkerRequestState<'_>>,
) -> Result<Response> {
    let daph = ctx.data.handler(&ctx.env);
    let req = daph.worker_request_to_dap(req, &ctx).await?;

    let span = info_span_from_dap_request!("upload", req);

    match daph.handle_upload_req(&req).instrument(span).await {
        Ok(()) => Response::empty(),
        Err(e) => daph.state.dap_abort_to_worker_response(e),
    }
}

async fn handle_agg_job(
    req: Request,
    ctx: RouteContext<&DaphneWorkerRequestState<'_>>,
) -> Result<Response> {
    let daph = ctx.data.handler(&ctx.env);
    let req = daph.worker_request_to_dap(req, &ctx).await?;

    let span = match req.media_type {
        DapMediaType::AggregationJobInitReq => {
            info_span_from_dap_request!(MeasuredSpanName::AggregateInit.as_str(), req)
        }
        DapMediaType::AggregationJobContinueReq => {
            info_span_from_dap_request!(MeasuredSpanName::AggregateContinue.as_str(), req)
        }
        _ => info_span_from_dap_request!("aggregate", req),
    };

    match daph.handle_agg_job_req(&req).instrument(span).await {
        Ok(resp) => dap_response_to_worker(resp),
        Err(e) => daph.state.dap_abort_to_worker_response(e),
    }
}

async fn handle_agg_share_req(
    req: Request,
    ctx: RouteContext<&DaphneWorkerRequestState<'_>>,
) -> Result<Response> {
    let daph = ctx.data.handler(&ctx.env);
    let req = daph.worker_request_to_dap(req, &ctx).await?;

    let span = info_span_from_dap_request!(MeasuredSpanName::AggregateShares.as_str(), req);

    match daph.handle_agg_share_req(&req).instrument(span).await {
        Ok(resp) => dap_response_to_worker(resp),
        Err(e) => daph.state.dap_abort_to_worker_response(e),
    }
}

pub(crate) fn now() -> u64 {
    Date::now().as_millis() / 1000
}

pub(crate) fn int_err<S: ToString>(s: S) -> Error {
    error!("internal error: {}", s.to_string());
    Error::RustError("internalError".to_string())
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum InternalTestRole {
    Leader,
    Helper,
}
#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) struct InternalTestEndpointForTask {
    role: InternalTestRole,
}

#[derive(Deserialize)]
pub(crate) struct InternalTestVdaf {
    #[serde(rename = "type")]
    typ: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    bits: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    length: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) struct InternalTestAddTask {
    task_id: String, // base64url
    leader: Url,
    helper: Url,
    vdaf: InternalTestVdaf,
    leader_authentication_token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    collector_authentication_token: Option<String>,
    role: InternalTestRole,
    vdaf_verify_key: String, // base64url
    query_type: u8,
    min_batch_size: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_batch_size: Option<u64>,
    time_precision: Duration,
    collector_hpke_config: String, // base64url
    task_expiration: Time,
}
