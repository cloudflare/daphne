// Copyright (c) 2025 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use super::{
    super::roles::fetch_replay_protection_override, extractor::dap_sender::FROM_LEADER, App,
    AxumDapResponse, DapRequestExtractor, DaphneService,
};
use crate::{aggregator::queues, elapsed};
use axum::{
    extract::State,
    routing::{post, put},
};
use daphne::{
    error::DapAbort,
    fatal_error,
    hpke::HpkeProvider,
    messages::{request::PollAggregationJob, AggregateShareReq, AggregationJobResp},
    roles::{
        helper::{self, HashedAggregationJobReq},
        DapAggregator, DapHelper,
    },
    DapAggregationParam, DapError, DapResponse, DapVersion,
};
use daphne_service_utils::compute_offload;
use http::StatusCode;
use prio::codec::{ParameterizedDecode, ParameterizedEncode};
use std::{borrow::Cow, sync::Arc};

pub(super) fn add_helper_routes(router: super::Router<App>) -> super::Router<App> {
    router
        .route(
            "/:version/tasks/:task_id/aggregation_jobs/:agg_job_id",
            put(agg_job).get(poll_agg_job),
        )
        .route("/:version/tasks/:task_id/aggregate_shares", post(agg_share))
}

#[tracing::instrument(
    skip_all,
    fields(
        media_type = ?req.0.media_type,
        task_id = ?req.0.task_id,
        version = ?req.0.version,
    )
)]
#[worker::send]
async fn agg_job(
    state: State<Arc<App>>,
    req: DapRequestExtractor<FROM_LEADER, HashedAggregationJobReq>,
) -> AxumDapResponse {
    match req.0.version {
        DapVersion::Draft09 => agg_job_draft9(state, req).await,
        DapVersion::Latest => agg_job_draft_latest(state, req).await,
    }
}

async fn agg_job_draft_latest(
    State(app): State<Arc<App>>,
    DapRequestExtractor(req): DapRequestExtractor<FROM_LEADER, HashedAggregationJobReq>,
) -> AxumDapResponse {
    let now = worker::Date::now();
    let version = req.version;

    let queue_result = async {
        let (transition, req) = helper::handle_agg_job::start(req)
            .check_aggregation_job_legality(&*app)
            .await?
            .resolve_task_config(&*app)
            .await?
            .into_parts(fetch_replay_protection_override(app.kv()).await)?;

        let hpke_receiver_configs = app.get_hpke_receiver_configs(req.version).await?;

        app.async_aggregation_queue()
            .send(&queues::AsyncAggregationMessage {
                version,
                part_batch_sel: transition.part_batch_sel,
                agg_job_id: req.resource_id,
                taskprov_advertisement: req
                    .taskprov_advertisement
                    .as_ref()
                    .map(|t| t.serialize_to_header_value(version))
                    .transpose()?,
                initialize_reports: compute_offload::InitializeReports {
                    hpke_keys: Cow::Borrowed(hpke_receiver_configs.as_ref()),
                    valid_report_range: app.valid_report_time_range(),
                    task_id: req.task_id,
                    task_config: (&transition.task_config).into(),
                    agg_param: Cow::Borrowed(&req.payload.agg_param),
                    prep_inits: req.payload.prep_inits,
                },
            })
            .await
            .map_err(|e| fatal_error!(err = ?e, "failed to queue response"))
    }
    .await;

    let elapsed = elapsed(&now);

    app.server_metrics().aggregate_job_latency(elapsed);

    AxumDapResponse::from_result_with_success_code(
        queue_result.and_then(|()| {
            Ok(DapResponse {
                version,
                media_type: daphne::constants::DapMediaType::AggregationJobResp,
                payload: AggregationJobResp::Processing
                    .get_encoded_with_param(&version)
                    .map_err(DapError::encoding)?,
            })
        }),
        app.server_metrics(),
        StatusCode::CREATED,
    )
}

async fn agg_job_draft9(
    State(app): State<Arc<App>>,
    DapRequestExtractor(req): DapRequestExtractor<FROM_LEADER, HashedAggregationJobReq>,
) -> AxumDapResponse {
    let now = worker::Date::now();
    let version = req.version;

    let agg_job_resp = async {
        let (transition, req) = helper::handle_agg_job::start(req)
            .check_aggregation_job_legality(&*app)
            .await?
            .resolve_task_config(&*app)
            .await?
            .into_parts(fetch_replay_protection_override(app.kv()).await)?;

        let hpke_receiver_configs = app.get_hpke_receiver_configs(req.version).await?;

        let agg_param = DapAggregationParam::get_decoded_with_param(
            &transition.task_config.vdaf,
            &req.payload.agg_param,
        )
        .map_err(|e| DapAbort::from_codec_error(e, req.task_id))?;

        let initialized_reports: compute_offload::InitializedReports = app
            .compute_offload
            .compute(
                "/compute_offload/initialize_reports",
                &compute_offload::InitializeReports {
                    hpke_keys: Cow::Borrowed(hpke_receiver_configs.as_ref()),
                    valid_report_range: app.valid_report_time_range(),
                    task_id: req.task_id,
                    task_config: (&transition.task_config).into(),
                    agg_param: Cow::Borrowed(&req.payload.agg_param),
                    prep_inits: req.payload.prep_inits,
                },
            )
            .await
            .map_err(|e| fatal_error!(err = ?e, "failed to offload report initialization"))?;

        transition
            .with_initialized_reports(agg_param, initialized_reports.reports)
            .finish_and_aggregate(&*app)
            .await
    }
    .await;

    let elapsed = elapsed(&now);

    app.server_metrics().aggregate_job_latency(elapsed);

    AxumDapResponse::from_result_with_success_code(
        agg_job_resp.and_then(|agg_job_resp| {
            Ok(DapResponse {
                version,
                media_type: daphne::constants::DapMediaType::AggregationJobResp,
                payload: agg_job_resp
                    .get_encoded_with_param(&version)
                    .map_err(DapError::encoding)?,
            })
        }),
        app.server_metrics(),
        StatusCode::CREATED,
    )
}

#[tracing::instrument(
    skip_all,
    fields(
        media_type = ?req.media_type,
        task_id = ?req.task_id,
        version = ?req.version,
    )
)]
async fn poll_agg_job<A>(
    State(app): State<Arc<A>>,
    DapRequestExtractor(req): DapRequestExtractor<FROM_LEADER, PollAggregationJob>,
) -> AxumDapResponse
where
    A: DapHelper + DaphneService + Send + Sync,
{
    AxumDapResponse::from_result(
        helper::handle_agg_job_poll_req(&*app, req).await,
        app.server_metrics(),
    )
}

#[tracing::instrument(
    skip_all,
    fields(
        media_type = ?req.media_type,
        task_id = ?req.task_id,
        version = ?req.version,
    )
)]
async fn agg_share<A>(
    State(app): State<Arc<A>>,
    DapRequestExtractor(req): DapRequestExtractor<FROM_LEADER, AggregateShareReq>,
) -> AxumDapResponse
where
    A: DapHelper + DaphneService + Send + Sync,
{
    AxumDapResponse::from_result(
        helper::handle_agg_share_req(&*app, req).await,
        app.server_metrics(),
    )
}
