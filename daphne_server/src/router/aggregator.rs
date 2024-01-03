// Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use std::sync::Arc;

use axum::{
    body::HttpBody,
    extract::{Query, State},
    routing::get,
};
use daphne::{
    messages::TaskId,
    roles::{aggregator, DapAggregator},
};
use daphne_service_utils::auth::DaphneAuth;
use serde::Deserialize;

use super::{AxumDapResponse, DapRequestExtractor, DaphneService};

pub fn add_aggregator_routes<A, B>(router: super::Router<A, B>) -> super::Router<A, B>
where
    A: DapAggregator<DaphneAuth> + DaphneService + Send + Sync + 'static,
    B: Send + HttpBody + 'static,
    B::Data: Send,
    B::Error: Send + Sync,
{
    router.route("/:version/hpke_config", get(hpke_config))
}

#[derive(Deserialize)]
struct QueryTaskId {
    #[serde(
        default,
        deserialize_with = "daphne::messages::base64url::deserialize_opt"
    )]
    task_id: Option<TaskId>,
}

#[tracing::instrument(skip(app, req), fields(version = ?req.version))]
async fn hpke_config<A>(
    State(app): State<Arc<A>>,
    Query(QueryTaskId { task_id }): Query<QueryTaskId>,
    DapRequestExtractor(req): DapRequestExtractor,
) -> AxumDapResponse
where
    A: DapAggregator<DaphneAuth> + DaphneService,
{
    AxumDapResponse::from_result(
        aggregator::handle_hpke_config_req(&*app, &req, task_id).await,
        app.server_metrics(),
    )
}

#[cfg(test)]
mod test {
    use axum::{
        body::Body,
        extract::Query,
        http::{Request, StatusCode},
        routing::get,
        Router,
    };
    use daphne::messages::{Base64Encode, TaskId};
    use rand::{thread_rng, Rng};
    use tower::ServiceExt;

    use super::QueryTaskId;

    #[tokio::test]
    async fn can_parse_task_id() {
        let task_id = TaskId(thread_rng().gen());
        let router: Router = Router::new().route(
            "/",
            get(move |Query(QueryTaskId { task_id: tid })| async move {
                assert_eq!(tid, Some(task_id));
            }),
        );

        let status = router
            .oneshot(
                Request::builder()
                    .uri(format!("/?task_id={}", task_id.to_base64url()))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
            .status();

        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn accepts_missing_task_id() {
        let router: Router = Router::new().route(
            "/",
            get(move |Query(QueryTaskId { task_id: tid })| async move {
                assert_eq!(tid, None);
            }),
        );

        let status = router
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap()
            .status();

        assert_eq!(status, StatusCode::OK);
    }
}
