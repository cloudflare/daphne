// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use daphne_worker::initialize_tracing;
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

    Ok(daphne_worker::storage_proxy::handle_request(req, env, &prometheus::Registry::new()).await)
}
