use daphne::roles::DapAggregator;
use tracing::Instrument;

use crate::info_span_from_dap_request;

use super::{dap_response_to_worker, DapRouter};

pub(super) fn add_aggregator_routes(router: DapRouter<'_>) -> DapRouter<'_> {
    router.get_async("/:version/hpke_config", |req, ctx| async move {
        let daph = ctx.data.handler(&ctx.env);
        let req = match daph.worker_request_to_dap(req, &ctx).await {
            Ok(req) => req,
            Err(e) => return daph.state.dap_abort_to_worker_response(e.into()),
        };

        let span = info_span_from_dap_request!("hpke_config", req);

        match daph.handle_hpke_config_req(&req).instrument(span).await {
            Ok(req) => dap_response_to_worker(req),
            Err(e) => daph.state.dap_abort_to_worker_response(e),
        }
    })
}
