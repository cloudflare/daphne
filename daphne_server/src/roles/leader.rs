// Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

#![allow(unused_variables)]

use std::time::Instant;

use axum::{async_trait, http::Method};
use daphne::{
    auth::BearerTokenProvider,
    constants::DapMediaType,
    error::DapAbort,
    fatal_error,
    messages::{BatchId, BatchSelector, Collection, CollectionJobId, Report, TaskId},
    roles::{leader::WorkItem, DapAggregator, DapAuthorizedSender, DapLeader},
    DapAggregationParam, DapCollectionJob, DapError, DapRequest, DapResponse, DapTaskConfig,
};
use daphne_service_utils::auth::DaphneAuth;
use tracing::{error, info};
use url::Url;

use crate::storage_proxy_connection::method_http_1_0_to_reqwest_0_11;

#[async_trait]
impl DapAuthorizedSender<DaphneAuth> for crate::App {
    async fn authorize(
        &self,
        task_id: &TaskId,
        task_config: &DapTaskConfig,
        media_type: &DapMediaType,
        _payload: &[u8],
    ) -> Result<DaphneAuth, DapError> {
        Ok(DaphneAuth {
            bearer_token: Some(
                self.authorize_with_bearer_token(task_id, task_config, media_type)
                    .await?
                    .into_owned(),
            ),
            // TODO Consider adding support for authorizing the request with TLS client
            // certificates: https://developers.cloudflare.com/workers/runtime-apis/mtls/
            cf_tls_client_auth: None,
        })
    }
}

#[async_trait]
impl DapLeader<DaphneAuth> for crate::App {
    async fn put_report(&self, report: &Report, task_id: &TaskId) -> Result<(), DapError> {
        let task_config = self
            .get_task_config_for(task_id)
            .await?
            .ok_or(DapAbort::UnrecognizedTask)?;

        self.test_leader_state
            .lock()
            .await
            .put_report(task_id, &task_config, report.clone())
    }

    async fn current_batch(&self, task_id: &TaskId) -> Result<BatchId, DapError> {
        let task_config = self
            .get_task_config_for(task_id)
            .await?
            .ok_or(DapError::Abort(DapAbort::UnrecognizedTask))?;

        self.test_leader_state
            .lock()
            .await
            .current_batch(task_id, &task_config)
    }

    async fn init_collect_job(
        &self,
        task_id: &TaskId,
        coll_job_id: &Option<CollectionJobId>,
        batch_sel: BatchSelector,
        agg_param: DapAggregationParam,
    ) -> Result<url::Url, DapError> {
        let task_config = self
            .get_task_config_for(task_id)
            .await?
            .ok_or(DapAbort::UnrecognizedTask)?;

        self.test_leader_state.lock().await.init_collect_job(
            task_id,
            &task_config,
            coll_job_id,
            batch_sel,
            agg_param,
        )
    }

    async fn poll_collect_job(
        &self,
        task_id: &TaskId,
        coll_job_id: &CollectionJobId,
    ) -> Result<DapCollectionJob, DapError> {
        self.test_leader_state
            .lock()
            .await
            .poll_collect_job(task_id, coll_job_id)
    }

    async fn finish_collect_job(
        &self,
        task_id: &TaskId,
        coll_job_id: &CollectionJobId,
        collection: &Collection,
    ) -> Result<(), DapError> {
        self.test_leader_state
            .lock()
            .await
            .finish_collect_job(task_id, coll_job_id, collection)
    }

    async fn dequeue_work(&self, num_items: usize) -> Result<Vec<WorkItem>, DapError> {
        self.test_leader_state.lock().await.dequeue_work(num_items)
    }

    async fn enqueue_work(&self, items: Vec<WorkItem>) -> Result<(), DapError> {
        self.test_leader_state.lock().await.enqueue_work(items)
    }

    async fn send_http_post(
        &self,
        req: DapRequest<DaphneAuth>,
        url: Url,
    ) -> Result<DapResponse, DapError> {
        self.send_http(req, Method::POST, url).await
    }

    async fn send_http_put(
        &self,
        req: DapRequest<DaphneAuth>,
        url: Url,
    ) -> Result<DapResponse, DapError> {
        self.send_http(req, Method::PUT, url).await
    }
}

impl crate::App {
    async fn send_http(
        &self,
        req: DapRequest<DaphneAuth>,
        method: Method,
        url: Url,
    ) -> Result<DapResponse, DapError> {
        use reqwest::header::{self, HeaderMap, HeaderName, HeaderValue};

        let method = method_http_1_0_to_reqwest_0_11(method);

        let content_type = req
            .media_type
            .as_str_for_version(req.version)
            .ok_or_else(|| {
                fatal_error!(
                    err = "failed to construct content-type",
                    ?req.media_type,
                    ?req.version,
                )
            })?;

        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_str(content_type)
                .map_err(|e| fatal_error!(err = ?e, "failed to construct content-type header"))?,
        );

        if let Some(bearer_token) = req.sender_auth.and_then(|auth| auth.bearer_token) {
            headers.insert(
                HeaderName::from_static("dap-auth-token"),
                HeaderValue::from_str(bearer_token.as_ref()).map_err(
                    |e| fatal_error!(err = ?e, "failed to construct dap-auth-token header"),
                )?,
            );
        }

        if let Some(taskprov_advertisement) = req.taskprov.as_deref() {
            headers.insert(
                HeaderName::from_static("dap-taskprov"),
                HeaderValue::from_str(taskprov_advertisement).map_err(
                    |e| fatal_error!(err = ?e, "failed to construct dap-taskprov header"),
                )?,
            );
        }

        let req_builder = self
            .http
            .request(method, url.clone())
            .body(req.payload)
            .headers(headers);

        let start = Instant::now();
        let reqwest_resp = req_builder
            .send()
            .await
            .map_err(|e| fatal_error!(err = ?e))?;
        info!("request to {} completed in {:?}", url, start.elapsed());
        let status = reqwest_resp.status();

        const INT_ERR_PEER_ABORT: &str = "request aborted by peer";
        const INT_ERR_PEER_RESP_MISSING_MEDIA_TYPE: &str = "peer response is missing media type";

        if status == 200 {
            // Translate the reqwest response into a Worker response.
            let media_type = reqwest_resp
                .headers()
                .get_all(reqwest::header::CONTENT_TYPE)
                .into_iter()
                .filter_map(|h| h.to_str().ok())
                .find_map(|h| DapMediaType::from_str_for_version(req.version, Some(h)))
                .ok_or_else(|| fatal_error!(err = INT_ERR_PEER_RESP_MISSING_MEDIA_TYPE))?;

            let payload = reqwest_resp
                .bytes()
                .await
                .map_err(|e| fatal_error!(err = ?e))?
                .to_vec();

            Ok(DapResponse {
                version: req.version,
                payload,
                media_type,
            })
        } else {
            error!("{}: request failed: {:?}", url, reqwest_resp);
            if status == 400 {
                if let Some(content_type) =
                    reqwest_resp.headers().get(reqwest::header::CONTENT_TYPE)
                {
                    if content_type == "application/problem+json" {
                        error!(
                            "Problem details: {}",
                            reqwest_resp
                                .text()
                                .await
                                .map_err(|e| fatal_error!(err = ?e))?
                        );
                    }
                }
            }
            Err(fatal_error!(err = INT_ERR_PEER_ABORT))
        }
    }
}
