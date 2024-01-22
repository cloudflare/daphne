use daphne::{
    error::DapAbort,
    messages::{decode_base64url, TaskId},
    roles::aggregator,
};
use tracing::Instrument;

use crate::info_span_from_dap_request;

use super::{dap_response_to_worker, DapRouter};

pub(super) fn add_aggregator_routes(router: DapRouter<'_>) -> DapRouter<'_> {
    router.get_async("/:version/hpke_config", |req, ctx| async move {
        let daph = ctx.data.handler(&ctx.env);

        // Parse the task ID from the query string, ensuring that it is the only query parameter.
        let task_id = {
            let url = req.url()?;
            let mut query = url.query_pairs();
            let id = match (query.next(), query.next()) {
                (Some((k, v)), None) if k == "task_id" => decode_base64url(v.as_bytes())
                    .map(|bytes| Some(TaskId(bytes)))
                    .ok_or_else(|| {
                        DapAbort::BadRequest(
                            "failed to parse query parameter as URL-safe Base64".into(),
                        )
                    }),
                (None, None) => Ok(None),
                _ => Err(DapAbort::BadRequest("unexpected query parameter".into())),
            };
            match id {
                Ok(maybe_id) => maybe_id,
                Err(e) => return daph.state.dap_abort_to_worker_response(e),
            }
        };

        let req = match daph.worker_request_to_dap(req, &ctx).await {
            Ok(req) => req,
            Err(e) => return daph.state.dap_abort_to_worker_response(e),
        };

        let span = info_span_from_dap_request!("hpke_config", req);

        match aggregator::handle_hpke_config_req(&daph, &req, task_id)
            .instrument(span)
            .await
        {
            Ok(req) => dap_response_to_worker(req),
            Err(e) => daph.state.dap_abort_to_worker_response(e),
        }
    })
}
