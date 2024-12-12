// Copyright (c) 2025 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use daphne_worker::{aggregator::App, initialize_tracing};
use tracing::info;
use worker::{event, Env, HttpRequest};

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
            daphne_worker::aggregator::handle_dap_request(
                App::new(env, &registry, None).unwrap(),
                req,
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
