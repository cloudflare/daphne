// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Daphne-Worker implements a Workers backend for Daphne.

use crate::{
    config::DaphneWorkerConfig,
    dap::{dap_response_to_worker, worker_request_to_dap},
};
use daphne::{
    constants,
    messages::{Id, Interval},
    roles::{DapAggregator, DapHelper, DapLeader},
    DapAbort, DapCollectJob, DapError, DapResponse,
};
use prio::codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
use worker::*;

/// Parameters used by the Leader to select a set of reports for aggregation.
#[derive(Debug, Deserialize, Serialize)]
pub struct InternalAggregateInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub batch_info: Option<Interval>,

    /// The number of reports to aggregate in one execution of the aggregation flow.
    pub agg_rate: u64,
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

#[event(fetch, respond_with_errors)]
pub async fn main(req: Request, env: Env, _ctx: worker::Context) -> Result<Response> {
    log_request(&req);

    // Optionally, get more helpful error messages written to the console in the case of a panic.
    utils::set_panic_hook();

    let router = Router::new()
        .get_async("/hpke_config", |req, ctx| async move {
            let req = worker_request_to_dap(req).await?;
            let config = DaphneWorkerConfig::from_worker_context(ctx)?;
            // TODO(MVP) Have this method return a DapResponse.
            match config.http_get_hpke_config(&req).await {
                Ok(hpke_config_data) => dap_response_to_worker(DapResponse {
                    media_type: Some(constants::MEDIA_TYPE_HPKE_CONFIG),
                    payload: hpke_config_data,
                }),
                Err(e) => abort(e),
            }
        })
        .post_async(
            "/internal/test/reset/task/:task_id",
            |mut req, ctx| async move {
                let task_id = parse_id!(ctx.param("task_id"));
                let config = DaphneWorkerConfig::from_worker_context(ctx)?;
                let batch_info: Option<Interval> = req.json().await?;
                match config.internal_reset(&task_id, &batch_info).await {
                    Ok(()) => Response::empty(),
                    Err(e) => abort(e.into()),
                }
            },
        );

    let router = match env.var("DAP_AGGREGATOR_ROLE")?.to_string().as_ref() {
        "leader" => {
            router
                .post_async("/upload", |req, ctx| async move {
                    let req = worker_request_to_dap(req).await?;
                    let config = DaphneWorkerConfig::from_worker_context(ctx)?;
                    match config.http_post_upload(&req).await {
                        Ok(()) => Response::empty(),
                        Err(e) => abort(e),
                    }
                })
                .post_async("/collect", |req, ctx| async move {
                    let req = worker_request_to_dap(req).await?;
                    let config = DaphneWorkerConfig::from_worker_context(ctx)?;
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
                    "/collect/task/:task_id/req/:collect_id",
                    |_req, ctx| async move {
                        let task_id = parse_id!(ctx.param("task_id"));
                        let collect_id = parse_id!(ctx.param("collect_id"));
                        let config = DaphneWorkerConfig::from_worker_context(ctx)?;
                        // TODO(MVP) Consider deriving the logic below.
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
                .post_async(
                    "/internal/process/task/:task_id",
                    |mut req, ctx| async move {
                        let task_id = parse_id!(ctx.param("task_id"));
                        let config = DaphneWorkerConfig::from_worker_context(ctx)?;
                        let agg_info: InternalAggregateInfo = req.json().await?;
                        match config.process(&task_id, &agg_info).await {
                            Ok(telem) => Response::from_json(&telem),
                            Err(e) => abort(e),
                        }
                    },
                )
        }

        "helper" => router
            .post_async("/aggregate", |req, ctx| async move {
                let req = worker_request_to_dap(req).await?;
                let config = DaphneWorkerConfig::from_worker_context(ctx)?;
                match config.http_post_aggregate(&req).await {
                    Ok(resp) => dap_response_to_worker(resp),
                    Err(e) => abort(e),
                }
            })
            .post_async("/aggregate_share", |req, ctx| async move {
                let req = worker_request_to_dap(req).await?;
                let config = DaphneWorkerConfig::from_worker_context(ctx)?;
                match config.http_post_aggregate_share(&req).await {
                    Ok(resp) => dap_response_to_worker(resp),
                    Err(e) => abort(e),
                }
            }),

        role => return abort(DapError::Fatal(format!("unexpected role '{}'", role)).into()),
    };

    router.run(req, env).await
}

fn log_request(req: &Request) {
    console_log!(
        "{} - [{}], located at: {:?}, within: {}",
        Date::now().to_string(),
        req.path(),
        req.cf().coordinates().unwrap_or_default(),
        req.cf().region().unwrap_or_else(|| "unknown region".into())
    );
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

mod config;
mod dap;
mod durable;
mod utils;

#[cfg(test)]
mod config_test;
