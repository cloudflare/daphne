// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

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
//! where <version> is the DAP version, `<task_id>` is the task ID, `<window>` is a batch window,
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
//! [`CollectReq`](daphne::messages::CollectReq) message. (The key is `DAP_COLLECT_ID_KEY`.)
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
use crate::{config::DaphneWorkerConfig, dap::dap_response_to_worker};
use daphne::{
    constants,
    messages::{Duration, Id, Time},
    roles::{DapAggregator, DapHelper, DapLeader},
    DapAbort, DapCollectJob, DapError, DapResponse,
};
use prio::codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
use worker::*;

/// Parameters used by the Leader to select a set of reports for aggregation.
#[derive(Debug, Deserialize, Serialize)]
pub struct DaphneWorkerReportSelector {
    /// Maximum number of aggregation jobs to process at once.
    pub max_agg_jobs: u64,

    /// Maximum number of reports to drain for each aggregation job.
    pub max_reports: u64,
}

macro_rules! parse_id {
    (
        $option_str:expr
    ) => {
        match $option_str {
            Some(ref id_base64url) => {
                match base64::decode_config(id_base64url, base64::URL_SAFE_NO_PAD) {
                    Ok(ref id_raw) => match Id::get_decoded(id_raw) {
                        Ok(id) => id,
                        Err(_) => return Response::error("Bad Request", 400),
                    },
                    Err(_) => return Response::error("Bad Request", 400),
                }
            }
            None => return Response::error("Bad Request", 400),
        }
    };
}

/// HTTP request handler for Daphne-Worker.
#[derive(Default)]
pub struct DaphneWorkerRouter {
    /// If true, then enable internal test endpoints. These should not be enabled in production.
    pub enable_internal_test: bool,
}

impl DaphneWorkerRouter {
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
        let router = Router::new().get_async("/:version/hpke_config", |req, ctx| async move {
            let config = DaphneWorkerConfig::from_worker_context(ctx)?;
            let req = config.worker_request_to_dap(req).await?;

            // TODO(cjpatton) Have this method return a DapResponse.
            match config.http_get_hpke_config(&req).await {
                Ok(req) => dap_response_to_worker(req),
                Err(e) => abort(e),
            }
        });

        let router = match env.var("DAP_AGGREGATOR_ROLE")?.to_string().as_ref() {
            "leader" => {
                router
                    .post_async("/:version/upload", |req, ctx| async move {
                        let config = DaphneWorkerConfig::from_worker_context(ctx)?;
                        let req = config.worker_request_to_dap(req).await?;

                        match config.http_post_upload(&req).await {
                            Ok(()) => Response::empty(),
                            Err(e) => abort(e),
                        }
                    })
                    .post_async("/:version/collect", |req, ctx| async move {
                        let config = DaphneWorkerConfig::from_worker_context(ctx)?;
                        let req = config.worker_request_to_dap(req).await?;

                        match config.http_post_collect(&req).await {
                            Ok(collect_uri) => {
                                let mut headers = Headers::new();
                                headers.set("Location", collect_uri.as_str())?;
                                Ok(Response::empty()
                                    .unwrap()
                                    .with_status(303)
                                    .with_headers(headers))
                            }
                            Err(e) => abort(e),
                        }
                    })
                    .get_async(
                        "/:version/collect/task/:task_id/req/:collect_id",
                        |_req, ctx| async move {
                            let task_id = parse_id!(ctx.param("task_id"));
                            let collect_id = parse_id!(ctx.param("collect_id"));
                            let config = DaphneWorkerConfig::from_worker_context(ctx)?;
                            match config.poll_collect_job(&task_id, &collect_id).await {
                                Ok(DapCollectJob::Done(collect_resp)) => {
                                    dap_response_to_worker(DapResponse {
                                        media_type: Some(constants::MEDIA_TYPE_COLLECT_RESP),
                                        payload: collect_resp.get_encoded(),
                                    })
                                }
                                Ok(DapCollectJob::Pending) => {
                                    Ok(Response::empty().unwrap().with_status(202))
                                }
                                // TODO spec: Decide whether to define this behavior.
                                Ok(DapCollectJob::Unknown) => {
                                    abort(DapAbort::BadRequest("unknown collect id".into()))
                                }
                                Err(e) => abort(e.into()),
                            }
                        },
                    )
                    .post_async("/internal/process", |mut req, ctx| async move {
                        // TODO(cjpatton) Only enable this if `self.enable_internal_test` is set.
                        let config = DaphneWorkerConfig::from_worker_context(ctx)?;
                        let report_sel: DaphneWorkerReportSelector = req.json().await?;
                        match config.process(&report_sel).await {
                            Ok(telem) => {
                                console_debug!("{:?}", telem);
                                Response::from_json(&telem)
                            }
                            Err(e) => abort(e),
                        }
                    })
                    .get_async(
                        "/internal/current_batch/task/:task_id",
                        |_req, ctx| async move {
                            // Return the ID of the oldest, not-yet-collecgted batch for the specified
                            // task. The task ID and batch ID are both encoded in URL-safe base64.
                            //
                            // TODO(cjpatton) Only enable this if `self.enable_internal_test` is set.
                            let task_id = parse_id!(ctx.param("task_id"));
                            let config = DaphneWorkerConfig::from_worker_context(ctx)?;
                            match config.internal_current_batch(&task_id).await {
                                Ok(batch_id) => Response::from_bytes(
                                    batch_id.to_base64url().as_bytes().to_owned(),
                                ),
                                Err(e) => abort(e.into()),
                            }
                        },
                    )
            }

            "helper" => router
                .post_async("/:version/aggregate", |req, ctx| async move {
                    let config = DaphneWorkerConfig::from_worker_context(ctx)?;
                    let req = config.worker_request_to_dap(req).await?;

                    match config.http_post_aggregate(&req).await {
                        Ok(resp) => dap_response_to_worker(resp),
                        Err(e) => abort(e),
                    }
                })
                .post_async("/:version/aggregate_share", |req, ctx| async move {
                    let config = DaphneWorkerConfig::from_worker_context(ctx)?;
                    let req = config.worker_request_to_dap(req).await?;

                    match config.http_post_aggregate_share(&req).await {
                        Ok(resp) => dap_response_to_worker(resp),
                        Err(e) => abort(e),
                    }
                }),

            _ => return abort(DapError::fatal("unexpected role").into()),
        };

        let router = if self.enable_internal_test {
            router
                .post_async("/internal/delete_all", |_req, ctx| async move {
                    let config = DaphneWorkerConfig::from_worker_context(ctx)?;
                    match config.internal_delete_all().await {
                        Ok(()) => Response::empty(),
                        Err(e) => abort(e.into()),
                    }
                })
                // Endpoints for draft-dcook-ppm-dap-interop-test-design-02
                .post_async("/internal/test/ready", |_req, _ctx| async move {
                    Response::from_json(&())
                })
                .post_async(
                    "/internal/test/endpoint_for_task",
                    |mut req, ctx| async move {
                        let config = DaphneWorkerConfig::from_worker_context(ctx)?;
                        let cmd: InternalTestEndpointForTask = req.json().await?;
                        config
                            .internal_endpoint_for_task(config.default_version, cmd)
                            .await
                    },
                )
                .post_async(
                    "/:version/internal/test/endpoint_for_task",
                    |mut req, ctx| async move {
                        let config = DaphneWorkerConfig::from_worker_context(ctx)?;
                        let cmd: InternalTestEndpointForTask = req.json().await?;
                        let version = config.extract_version_parameter(&req)?;
                        config.internal_endpoint_for_task(version, cmd).await
                    },
                )
                .post_async("/internal/test/add_task", |mut req, ctx| async move {
                    let config = DaphneWorkerConfig::from_worker_context(ctx)?;
                    let cmd: InternalTestAddTask = req.json().await?;
                    config
                        .internal_add_task(config.default_version, cmd)
                        .await?;
                    Response::from_json(&serde_json::json!({
                        "status": "success",
                    }))
                })
                .post_async(
                    "/:version/internal/test/add_task",
                    |mut req, ctx| async move {
                        let config = DaphneWorkerConfig::from_worker_context(ctx)?;
                        let cmd: InternalTestAddTask = req.json().await?;
                        let version = config.extract_version_parameter(&req)?;
                        config.internal_add_task(version, cmd).await?;
                        Response::from_json(&serde_json::json!({
                            "status": "success",
                        }))
                    },
                )
        } else {
            router
        };

        let start = Date::now().as_millis();
        let resp = router.run(req, env).await?;
        let end = Date::now().as_millis();
        console_log!("request completed in {}ms", end - start);
        Ok(resp)
    }
}

pub(crate) fn now() -> u64 {
    Date::now().as_millis() / 1000
}

pub(crate) fn int_err<S: ToString>(s: S) -> Error {
    console_error!("internal error: {}", s.to_string());
    Error::RustError("internalError".to_string())
}

/// Convert a [`worker::Error`] into a [`daphne::DapError`].
///
/// NOTE Alternatively, we could implement `From<worker::Error>` for `daphne::DapError` in the
/// `daphne` crate. This requires synchronizing the version of the `worker` crate used here and by
/// `daphne`. However, The `worker` crate is still under active development, and we often need
/// changes that are on the main branch but not yet released. Thus, synchronizing this dependency
/// between both crates is not currently feasible.
pub(crate) fn dap_err(e: Error) -> DapError {
    DapError::Fatal(format!("worker: {}", e))
}

fn abort(e: DapAbort) -> Result<Response> {
    match &e {
        DapAbort::Internal(..) => {
            console_error!("internal error: {}", e.to_string());
            Err(Error::RustError("internalError".to_string()))
        }
        _ => {
            let mut headers = Headers::new();
            headers.set("Content-Type", "application/problem+json")?;
            Ok(Response::from_json(&e.to_problem_details())?
                .with_status(400)
                .with_headers(headers))
        }
    }
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
    verify_key: String, // base64url
    query_type: u8,
    min_batch_size: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_batch_size: Option<u64>,
    time_precision: Duration,
    collector_hpke_config: String, // base64url
    task_expiration: Time,
}

mod config;
mod dap;
mod durable;
