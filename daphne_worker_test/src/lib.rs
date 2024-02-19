// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use daphne_worker::{initialize_tracing, DapWorkerMode};
use tracing::info;
use worker::{event, Env, Request, Response, Result};

mod utils;

fn log_request(req: &Request) {
    info!(
        coordinates = ?req.cf().coordinates().unwrap_or_default(),
        region = req.cf().region().unwrap_or_else(|| "unknown region".into()),
        "{}",
        req.path(),
    );
}

#[global_allocator]
static CAP: cap::Cap<std::alloc::System> = cap::Cap::new(std::alloc::System, 65_000_000);

#[event(fetch, respond_with_errors)]
pub async fn main(req: Request, env: Env, ctx: worker::Context) -> Result<Response> {
    // Optionally, get more helpful error messages written to the console in the case of a panic.
    utils::set_panic_hook();

    // We set up logging as soon as possible so that logging can be estabished and functional
    // before we do anything likely to fail.
    initialize_tracing(&env);

    log_request(&req);

    match daphne_worker::get_worker_mode(&env) {
        DapWorkerMode::StorageProxy => {
            info!("starting storage proxy");
            daphne_worker::storage_proxy::handle_request(req, env, ctx).await
        }
    }
}
