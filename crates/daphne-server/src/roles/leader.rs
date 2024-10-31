// Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use std::{borrow::Cow, time::Instant};

use axum::{async_trait, http::Method};
use daphne::{
    constants::DapMediaType,
    error::DapAbort,
    fatal_error,
    messages::{BatchId, BatchSelector, Collection, CollectionJobId, Report, TaskId},
    roles::{leader::WorkItem, DapAggregator, DapLeader},
    DapAggregationParam, DapCollectionJob, DapError, DapRequestMeta, DapResponse, DapVersion,
};
use daphne_service_utils::http_headers;
use http::StatusCode;
use prio::codec::ParameterizedEncode;
use tracing::{error, info};
use url::Url;

#[async_trait]
impl DapLeader for crate::App {
    async fn put_report(&self, report: &Report, task_id: &TaskId) -> Result<(), DapError> {
        let task_config = self
            .get_task_config_for(task_id)
            .await?
            .ok_or(DapAbort::UnrecognizedTask { task_id: *task_id })?;

        self.test_leader_state
            .lock()
            .await
            .put_report(task_id, &task_config, report.clone())
    }

    async fn current_batch(&self, task_id: &TaskId) -> Result<BatchId, DapError> {
        let task_config = self
            .get_task_config_for(task_id)
            .await?
            .ok_or(DapError::Abort(DapAbort::UnrecognizedTask {
                task_id: *task_id,
            }))?;

        self.test_leader_state
            .lock()
            .await
            .current_batch(task_id, &task_config)
    }

    async fn init_collect_job(
        &self,
        task_id: &TaskId,
        coll_job_id: &CollectionJobId,
        batch_sel: BatchSelector,
        agg_param: DapAggregationParam,
    ) -> Result<(), DapError> {
        let task_config = self
            .get_task_config_for(task_id)
            .await?
            .ok_or(DapAbort::UnrecognizedTask { task_id: *task_id })?;

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

    async fn send_http_post<P>(
        &self,
        meta: DapRequestMeta,
        url: Url,
        payload: P,
    ) -> Result<DapResponse, DapError>
    where
        P: Send + ParameterizedEncode<DapVersion>,
    {
        self.send_http(meta, Method::POST, url, payload).await
    }

    async fn send_http_put<P>(
        &self,
        meta: DapRequestMeta,
        url: Url,
        payload: P,
    ) -> Result<DapResponse, DapError>
    where
        P: Send + ParameterizedEncode<DapVersion>,
    {
        self.send_http(meta, Method::PUT, url, payload).await
    }
}

impl crate::App {
    async fn send_http<P>(
        &self,
        meta: DapRequestMeta,
        method: Method,
        url: Url,
        payload: P,
    ) -> Result<DapResponse, DapError>
    where
        P: Send + ParameterizedEncode<DapVersion>,
    {
        use reqwest::header::{self, HeaderMap, HeaderName, HeaderValue};
        let content_type = meta
            .media_type
            .and_then(|mt| mt.as_str_for_version(meta.version))
            .ok_or_else(|| {
                fatal_error!(
                    err = "failed to construct content-type",
                    ?meta.media_type,
                    ?meta.version,
                )
            })?;

        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_str(content_type)
                .map_err(|e| fatal_error!(err = ?e, "failed to construct content-type header"))?,
        );

        let bearer_token = if meta.taskprov_advertisement.is_some() {
            if let Some(bearer_token) = self
                .service_config
                .taskprov
                .as_ref()
                .and_then(|t| t.self_bearer_token.as_ref())
            {
                Cow::Borrowed(bearer_token)
            } else {
                return Err(DapError::Abort(DapAbort::UnauthorizedRequest {
                    detail: format!(
                        "taskprov authentication not setup for authentication with peer at {url}",
                    ),
                    task_id: meta.task_id,
                }));
            }
        } else if let Some(bearer_token) = self
            .bearer_tokens()
            .get(daphne::DapSender::Leader, meta.task_id)
            .await
            .map_err(|e| fatal_error!(err = ?e, "failed to get leader bearer token"))?
        {
            Cow::Owned(bearer_token)
        } else {
            return Err(DapError::Abort(DapAbort::UnauthorizedRequest {
                detail: format!(
                    "no suitable authentication method found for authenticating with peer at {url}",
                ),
                task_id: meta.task_id,
            }));
        };

        headers.insert(
            HeaderName::from_static(http_headers::DAP_AUTH_TOKEN),
            HeaderValue::from_str(bearer_token.as_str())
                .map_err(|e| fatal_error!(err = ?e, "failed to construct authentication header"))?,
        );

        if let Some(taskprov_advertisement) = meta.taskprov_advertisement.as_deref() {
            headers.insert(
                HeaderName::from_static(http_headers::DAP_TASKPROV),
                HeaderValue::from_str(taskprov_advertisement).map_err(
                    |e| fatal_error!(err = ?e, "failed to construct dap-taskprov header"),
                )?,
            );
        }

        let req_builder = self
            .http
            .request(method, url.clone())
            .body(
                payload
                    .get_encoded_with_param(&meta.version)
                    .map_err(|e| DapAbort::from_codec_error(e, meta.task_id))?,
            )
            .headers(headers);

        let start = Instant::now();
        let reqwest_resp = req_builder
            .send()
            .await
            .map_err(|e| fatal_error!(err = ?e, "failed to send request to the helper"))?;
        info!("request to {} completed in {:?}", url, start.elapsed());
        let status = reqwest_resp.status();

        if status.is_success() {
            // Translate the reqwest response into a Worker response.
            let media_type = reqwest_resp
                .headers()
                .get_all(reqwest::header::CONTENT_TYPE)
                .into_iter()
                .filter_map(|h| h.to_str().ok())
                .find_map(|h| DapMediaType::from_str_for_version(meta.version, h))
                .ok_or_else(|| fatal_error!(err = "peer response is missing media type"))?;

            let payload = reqwest_resp
                .bytes()
                .await
                .map_err(|e| fatal_error!(err = ?e, "failed to read body of helper response"))?
                .to_vec();

            Ok(DapResponse {
                version: meta.version,
                payload,
                media_type,
            })
        } else {
            error!("{}: request failed: {:?}", url, reqwest_resp);
            match status {
                StatusCode::BAD_REQUEST => {
                    if let Some(content_type) =
                        reqwest_resp.headers().get(reqwest::header::CONTENT_TYPE)
                    {
                        if content_type == "application/problem+json" {
                            error!(
                                "Problem details: {}",
                                reqwest_resp.text().await.map_err(
                                    |e| fatal_error!(err = ?e, "failed to read body of helper error response")
                                )?
                            );
                        }
                    }
                }
                StatusCode::UNAUTHORIZED => {
                    return Err(DapAbort::UnauthorizedRequest {
                        detail: format!("helper at {url} didn't authorize our request"),
                        task_id: meta.task_id,
                    }
                    .into())
                }
                _ => {}
            }
            Err(fatal_error!(err = "request aborted by peer"))
        }
    }
}
