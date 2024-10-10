// Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use anyhow::{anyhow, Context as _};
use daphne::{
    constants::DapMediaType,
    error::aborts::ProblemDetails,
    messages::{AggregateShareReq, AggregationJobInitReq, AggregationJobResp},
    DapVersion,
};
use daphne_service_utils::{bearer_token::BearerToken, http_headers};
use prio::codec::{Decode as _, ParameterizedEncode as _};
use reqwest::header;
use url::Url;

use crate::HttpClient;

use super::response_to_anyhow;

impl HttpClient {
    pub async fn submit_aggregation_job_init_req(
        &self,
        url: Url,
        agg_job_init_req: AggregationJobInitReq,
        version: DapVersion,
        opts: Options<'_>,
    ) -> anyhow::Result<AggregationJobResp> {
        let resp = self
            .put(url)
            .body(agg_job_init_req.get_encoded_with_param(&version).unwrap())
            .headers(construct_request_headers(
                DapMediaType::AggregationJobInitReq
                    .as_str_for_version(version)
                    .with_context(|| {
                        format!("AggregationJobInitReq media type is not defined for {version}")
                    })?,
                opts,
            )?)
            .send()
            .await
            .context("sending AggregationJobInitReq")?;
        if resp.status() == 400 {
            let text = resp.text().await?;
            let problem_details: ProblemDetails =
                serde_json::from_str(&text).with_context(|| {
                    format!("400 Bad Request: failed to parse problem details document: {text:?}")
                })?;
            Err(anyhow!("400 Bad Request: {problem_details:?}"))
        } else if resp.status() == 500 {
            Err(anyhow::anyhow!(
                "500 Internal Server Error: {}",
                resp.text().await?
            ))
        } else if !resp.status().is_success() {
            Err(response_to_anyhow(resp).await).context("while running an AggregationJobInitReq")
        } else {
            AggregationJobResp::get_decoded(
                &resp
                    .bytes()
                    .await
                    .context("transfering bytes from the AggregateInitReq")?,
            )
            .with_context(|| "failed to parse response to AggregateInitReq from Helper")
        }
    }

    pub async fn get_aggregate_share(
        &self,
        url: Url,
        agg_share_req: AggregateShareReq,
        version: DapVersion,
        opts: Options<'_>,
    ) -> anyhow::Result<()> {
        let resp = self
            .post(url)
            .body(agg_share_req.get_encoded_with_param(&version).unwrap())
            .headers(construct_request_headers(
                DapMediaType::AggregateShareReq
                    .as_str_for_version(version)
                    .with_context(|| {
                        format!("AggregateShareReq media type is not defined for {version}")
                    })?,
                opts,
            )?)
            .send()
            .await
            .context("sending AggregateShareReq")?;
        if resp.status() == 400 {
            let problem_details: ProblemDetails = serde_json::from_slice(
                &resp
                    .bytes()
                    .await
                    .context("transfering bytes for AggregateShareReq")?,
            )
            .with_context(|| "400 Bad Request: failed to parse problem details document")?;
            Err(anyhow!("400 Bad Request: {problem_details:?}"))
        } else if resp.status() == 500 {
            Err(anyhow!("500 Internal Server Error: {}", resp.text().await?))
        } else if !resp.status().is_success() {
            Err(response_to_anyhow(resp).await).context("while running an AggregateShareReq")
        } else {
            Ok(())
        }
    }
}

#[derive(Default, Debug)]
pub struct Options<'s> {
    pub taskprov_advertisement: Option<&'s str>,
    pub bearer_token: Option<&'s BearerToken>,
}

fn construct_request_headers(
    media_type: &str,
    options: Options<'_>,
) -> Result<header::HeaderMap, header::InvalidHeaderValue> {
    let mut headers = header::HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_str(media_type)?,
    );
    let Options {
        taskprov_advertisement,
        bearer_token,
    } = options;
    if let Some(taskprov) = taskprov_advertisement {
        headers.insert(
            const { header::HeaderName::from_static(http_headers::DAP_TASKPROV) },
            header::HeaderValue::from_str(taskprov)?,
        );
    }
    if let Some(token) = bearer_token {
        headers.insert(
            const { header::HeaderName::from_static(http_headers::DAP_AUTH_TOKEN) },
            header::HeaderValue::from_str(token.as_str())?,
        );
    }
    Ok(headers)
}
