// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use super::{dap_response_to_worker, DapRouter};
use daphne::{constants::DapMediaType, roles::DapHelper};
use tracing::Instrument;
use worker::{Request, Response, Result, RouteContext};

use crate::{
    config::DaphneWorkerRequestState, info_span_from_dap_request, tracing_utils::MeasuredSpanName,
};

pub(super) fn add_helper_routes(router: DapRouter<'_>) -> DapRouter<'_> {
    router
        .post_async("/:version/aggregate", handle_agg_job) // draft02
        .post_async("/:version/aggregate_share", handle_agg_share_req) // draft02
        .put_async(
            "/:version/tasks/:task_id/aggregation_jobs/:agg_job_id",
            handle_agg_job,
        )
        .post_async(
            "/:version/tasks/:task_id/aggregation_jobs/:agg_job_id",
            handle_agg_job,
        )
        .post_async(
            "/:version/tasks/:task_id/aggregate_shares",
            handle_agg_share_req,
        )
}

async fn handle_agg_job(
    req: Request,
    ctx: RouteContext<&DaphneWorkerRequestState<'_>>,
) -> Result<Response> {
    let daph = ctx.data.handler(&ctx.env);
    let req = match daph.worker_request_to_dap(req, &ctx).await {
        Ok(req) => req,
        Err(e) => return daph.state.dap_abort_to_worker_response(e.into()),
    };

    let span = match req.media_type {
        DapMediaType::AggregationJobInitReq => {
            info_span_from_dap_request!(MeasuredSpanName::AggregateInit.as_str(), req)
        }
        DapMediaType::AggregationJobContinueReq => {
            info_span_from_dap_request!(MeasuredSpanName::AggregateContinue.as_str(), req)
        }
        _ => info_span_from_dap_request!("aggregate", req),
    };

    match daph.handle_agg_job_req(&req).instrument(span).await {
        Ok(resp) => dap_response_to_worker(resp),
        Err(e) => daph.state.dap_abort_to_worker_response(e),
    }
}

async fn handle_agg_share_req(
    req: Request,
    ctx: RouteContext<&DaphneWorkerRequestState<'_>>,
) -> Result<Response> {
    let daph = ctx.data.handler(&ctx.env);
    let req = match daph.worker_request_to_dap(req, &ctx).await {
        Ok(req) => req,
        Err(e) => return daph.state.dap_abort_to_worker_response(e.into()),
    };

    let span = info_span_from_dap_request!(MeasuredSpanName::AggregateShares.as_str(), req);

    match daph.handle_agg_share_req(&req).instrument(span).await {
        Ok(resp) => dap_response_to_worker(resp),
        Err(e) => daph.state.dap_abort_to_worker_response(e),
    }
}
