// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Daphne-Worker implements a Workers backend for Daphne.

use crate::{config::DaphneWorkerConfig, dap::dap_response_to_worker};
use daphne::{
    constants,
    messages::Id,
    roles::{DapAggregator, DapHelper, DapLeader},
    DapAbort, DapCollectJob, DapError, DapResponse,
};
use prio::codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
use worker::*;

/// Parameters used by the Leader to select a set of reports for aggregation.
#[derive(Debug, Deserialize, Serialize)]
pub struct InternalAggregateInfo {
    /// Maximum number of buckets to process at once.
    pub max_buckets: u64,

    /// Maximum number of reports to drain from each bucket.
    pub max_reports: u64,
}

macro_rules! durable_get {
    (
            $stub:expr,
            $path:expr
    ) => {{
        let req = Request::new_with_init(
            &format!("https://fake-host{}", $path),
            RequestInit::new().with_method(Method::Get),
        )?;

        $stub.fetch_with_request(req)
    }};
}

macro_rules! durable_post {
    (
        $stub:expr,
        $path:expr,
        $serializable:expr
    ) => {{
        use wasm_bindgen::JsValue;
        let req = Request::new_with_init(
            &format!("https://fake-host{}", $path),
            RequestInit::new().with_method(Method::Post).with_body(Some(
                // TODO Figure out how to send raw bytes to DOs rather than a JSON blob.
                JsValue::from_str(&serde_json::to_string($serializable)?),
            )),
        )?;

        $stub.fetch_with_request(req)
    }};
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
                        let agg_info: InternalAggregateInfo = req.json().await?;
                        match config.process(&agg_info).await {
                            Ok(telem) => {
                                console_debug!("{:?}", telem);
                                Response::from_json(&telem)
                            }
                            Err(e) => abort(e),
                        }
                    })
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
            router.post_async("/internal/delete_all", |_req, ctx| async move {
                let config = DaphneWorkerConfig::from_worker_context(ctx)?;
                match config.internal_delete_all().await {
                    Ok(()) => Response::empty(),
                    Err(e) => abort(e.into()),
                }
            })
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

fn abort(e: DapAbort) -> Result<Response> {
    match &e {
        DapAbort::Internal(..) => {
            console_error!("internal error: {}", e.to_string());
            Err(Error::RustError("internalError".to_string()))
        }
        _ => {
            console_warn!("request aborted: {}", e.to_string());
            let mut headers = Headers::new();
            headers.set("Content-Type", "application/problem+json")?;
            Ok(Response::from_json(&e.to_problem_details())?
                .with_status(400)
                .with_headers(headers))
        }
    }
}

mod config;
mod dap;
mod durable;

#[cfg(test)]
mod config_test;
