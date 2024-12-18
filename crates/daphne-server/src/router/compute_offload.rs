// Copyright (c) 2025 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use crate::App;
use axum::{async_trait, extract::FromRequest, response::IntoResponse, routing::post};
use daphne::{error::DapAbort, InitializedReport};
use daphne_service_utils::{
    capnproto::{CapnprotoPayloadDecode, CapnprotoPayloadDecodeExt, CapnprotoPayloadEncodeExt},
    compute_offload::{InitializeReports, InitializedReports},
};
use http::StatusCode;
use prio::codec::ParameterizedDecode;
use rayon::iter::{IntoParallelIterator as _, ParallelIterator};

pub(super) fn add_routes(router: super::Router<App>) -> super::Router<App> {
    router.route(
        "/compute_offload/initialize_reports",
        post(initialize_reports),
    )
}

struct CapnprotoExtractor<T>(T);

#[async_trait]
impl<S, T> FromRequest<S> for CapnprotoExtractor<T>
where
    T: CapnprotoPayloadDecode,
{
    type Rejection = StatusCode;

    async fn from_request(
        req: http::Request<axum::body::Body>,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        let bytes = axum::body::to_bytes(req.into_body(), usize::MAX)
            .await
            .map_err(|_| StatusCode::BAD_REQUEST)?;
        let t = T::decode_from_bytes(&bytes).map_err(|_| StatusCode::BAD_REQUEST)?;

        Ok(CapnprotoExtractor(t))
    }
}

#[tracing::instrument(skip_all, fields(%task_id, report_count = prep_inits.len()))]
async fn initialize_reports(
    CapnprotoExtractor(InitializeReports {
        hpke_keys,
        valid_report_range,
        task_id,
        task_config,
        agg_param,
        prep_inits,
    }): CapnprotoExtractor<InitializeReports<'static>>,
) -> impl IntoResponse {
    tracing::info!("initializing reports");
    let initialized_reports = prep_inits
        .into_par_iter()
        .map(|prep_init| {
            InitializedReport::from_leader(
                &hpke_keys.as_ref(),
                valid_report_range.clone(),
                &task_id,
                &task_config,
                prep_init.report_share,
                prep_init.payload,
                &daphne::DapAggregationParam::get_decoded_with_param(&task_config.vdaf, &agg_param)
                    .map_err(|e| DapAbort::from_codec_error(e, task_id))?,
            )
        })
        .collect::<Result<Vec<_>, _>>();

    match initialized_reports {
        Ok(reports) => {
            let body = InitializedReports {
                vdaf: task_config.vdaf.into_owned(),
                reports,
            }
            .encode_to_bytes();

            (StatusCode::OK, body).into_response()
        }
        Err(error) => (StatusCode::BAD_REQUEST, axum::Json(error)).into_response(),
    }
}
