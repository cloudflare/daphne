// Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! This is the old worker implementation that was 100% implemented in workers.

pub mod config;
mod error_reporting;
mod roles;
mod router;

use super::initialize_tracing;
use config::{DaphneWorkerIsolateState, DaphneWorkerRequestState};
use daphne::audit_log::{AuditLog, NoopAuditLog};
use once_cell::sync::OnceCell;
use std::str;
use tracing::debug;
use worker::{Env, Request, Response, Result};

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
