// Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use anyhow::{anyhow, Context};
use daphne::{
    constants::DapMediaType,
    messages::{Collection, CollectionJobId, CollectionReq, Report, TaskId},
    DapVersion,
};
use daphne_service_utils::{bearer_token::BearerToken, http_headers};
use prio::codec::{ParameterizedDecode as _, ParameterizedEncode as _};
use rand::{thread_rng, Rng};
use reqwest::StatusCode;
use url::Url;

use crate::HttpClient;

use super::{retry, retry_and_decode};

impl HttpClient {
    pub async fn upload(
        &self,
        url: &Url,
        task_id: &TaskId,
        report: Report,
        version: DapVersion,
    ) -> anyhow::Result<()> {
        // Post the report to the Leader.
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::CONTENT_TYPE,
            reqwest::header::HeaderValue::from_str(
                DapMediaType::Report
                    .as_str_for_version(version)
                    .ok_or_else(|| anyhow!("invalid content-type for dap version"))?,
            )
            .expect("failecd to construct content-type header"),
        );
        retry_and_decode(&(), || async {
            self.put(url.join(&format!("tasks/{task_id}/reports")).unwrap())
                .body(report.get_encoded_with_param(&version).unwrap())
                .headers(headers.clone())
                .send()
                .await
                .context("uploading a report")
        })
        .await
    }

    pub async fn start_collection_job(
        &self,
        url: &Url,
        task_id: &TaskId,
        collect_req: &CollectionReq,
        version: DapVersion,
        collector_auth_token: Option<&BearerToken>,
    ) -> anyhow::Result<CollectionJobId> {
        let collect_job_id = CollectionJobId(thread_rng().gen());
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::CONTENT_TYPE,
            reqwest::header::HeaderValue::from_str(
                DapMediaType::CollectionReq
                    .as_str_for_version(version)
                    .ok_or_else(|| anyhow!("invalid content-type for dap version"))?,
            )
            .expect("failed to construct content-type hader"),
        );
        if let Some(collector_auth_token) = collector_auth_token {
            headers.insert(
                reqwest::header::HeaderName::from_static(http_headers::DAP_AUTH_TOKEN),
                reqwest::header::HeaderValue::from_str(collector_auth_token.as_str())?,
            );
        }
        let () = retry_and_decode(&(), || async {
            self.put(url.join(&format!("tasks/{task_id}/collection_jobs/{collect_job_id}"))?)
                .body(collect_req.get_encoded_with_param(&version)?)
                .headers(headers.clone())
                .send()
                .await
                .context("starting a collection job ")
        })
        .await?;

        Ok(collect_job_id)
    }

    pub async fn poll_collection_job(
        &self,
        url: &Url,
        task_id: &TaskId,
        collect_job_id: &CollectionJobId,
        version: DapVersion,
        collector_auth_token: Option<&BearerToken>,
    ) -> anyhow::Result<Option<Collection>> {
        let mut headers = reqwest::header::HeaderMap::new();
        if let Some(collector_auth_token) = collector_auth_token {
            headers.insert(
                reqwest::header::HeaderName::from_static(http_headers::DAP_AUTH_TOKEN),
                reqwest::header::HeaderValue::from_str(collector_auth_token.as_str())?,
            );
        }
        retry(
            || async {
                self.post(url.join(&format!("tasks/{task_id}/collection_jobs/{collect_job_id}"))?)
                    .headers(headers.clone())
                    .send()
                    .await
                    .context("polling collection job")
            },
            |resp| async {
                if resp.status() == StatusCode::ACCEPTED {
                    Ok(None)
                } else {
                    let bytes = resp.bytes().await.context("reading bytes from wire")?;
                    Ok(Some(
                        Collection::get_decoded_with_param(&version, &bytes)
                            .context("decoding Collection body")?,
                    ))
                }
            },
        )
        .await
    }
}
