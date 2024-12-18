// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use daphne::constants::DapAggregatorRole;
use daphne_worker::{aggregator::App, initialize_tracing};
use futures::stream;
use std::convert::Infallible;
use tracing::info;
use worker::{event, Env, HttpRequest, ResponseBody};

mod durable;
mod utils;

#[global_allocator]
static CAP: cap::Cap<std::alloc::System> = cap::Cap::new(std::alloc::System, 65_000_000);

#[event(fetch, respond_with_errors)]
pub async fn main(
    req: HttpRequest,
    env: Env,
    _ctx: worker::Context,
) -> worker::Result<daphne_worker::Response> {
    // Optionally, get more helpful error messages written to the console in the case of a panic.
    utils::set_panic_hook();

    // We set up logging as soon as possible so that logging can be estabished and functional
    // before we do anything likely to fail.
    initialize_tracing(&env);

    info!(method = ?req.method(), "{}", req.uri().path());

    let registry = prometheus::Registry::new();
    let response = match env
        .var("DAP_WORKER_MODE")
        .map(|t| t.to_string())
        .ok()
        .as_deref()
    {
        Some("storage-proxy") | None => {
            daphne_worker::storage_proxy::handle_request(req, env, &registry).await
        }
        Some("aggregator") => {
            let role = match env
                .var("DAP_AGGREGATOR_ROLE")
                .map(|t| t.to_string())
                .ok()
                .as_deref()
            {
                Some("leader") => DapAggregatorRole::Leader,
                Some("helper") | None => DapAggregatorRole::Helper,
                Some(bad_role) => panic!("'{bad_role}' is not a valid role"),
            };
            daphne_worker::aggregator::handle_dap_request(
                App::new(env, &registry, None, Box::new(CpuOffload)).unwrap(),
                req,
                role,
            )
            .await
        }
        Some(invalid) => {
            return Err(worker::Error::RustError(format!(
                "{invalid} is not a valid DAP_WORKER_MODE"
            )))
        }
    };

    Ok(response)
}

struct CpuOffload;

#[async_trait::async_trait(?Send)]
impl daphne_worker::aggregator::CpuOffload for CpuOffload {
    async fn request(
        &self,
        mut req: HttpRequest,
    ) -> worker::Result<daphne_worker::Response<worker::Body>> {
        let url = format!("http://localhost:8787{}", req.uri().path())
            .parse()
            .unwrap();
        *req.uri_mut() = url;
        let response: worker::Response =
            worker::Fetch::Request(req.try_into().expect("invalid request"))
                .send()
                .await?;

        Ok(daphne_worker::Response::builder()
            .status(response.status_code())
            .body(match response.into_parts().1 {
                ResponseBody::Empty => worker::Body::empty(),
                ResponseBody::Body(vec) => {
                    worker::Body::from_stream(stream::iter([Ok::<_, Infallible>(vec)])).unwrap()
                }
                ResponseBody::Stream(readable_stream) => worker::Body::new(readable_stream),
            })
            .unwrap())
    }
}
