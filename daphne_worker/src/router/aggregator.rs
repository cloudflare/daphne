use daphne::{auth::BearerToken, roles::DapAggregator};
use tracing::{info_span, Instrument};
use worker::Response;

use crate::info_span_from_dap_request;

use super::{dap_response_to_worker, test_routes, DapRouter};

pub(super) fn add_aggregator_routes(router: DapRouter<'_>) -> DapRouter<'_> {
    router
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

            let cmd: test_routes::InternalTestAddTask = req.json().await?;
            daph.internal_add_task(daph.config().default_version, cmd)
                .instrument(info_span!("task"))
                .await?;
            Response::empty()
        })
}
