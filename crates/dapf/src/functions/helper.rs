// Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use anyhow::Context as _;
use daphne::{
    constants::DapMediaType,
    messages::{
        taskprov::TaskprovAdvertisement, AggregateShare, AggregateShareReq, AggregationJobInitReq,
        AggregationJobResp,
    },
    DapVersion,
};
use daphne_service_utils::{bearer_token::BearerToken, http_headers};
use prio::codec::ParameterizedEncode as _;
use reqwest::header;
use url::Url;

use crate::HttpClient;

use super::retry_and_decode;

impl HttpClient {
    pub async fn submit_aggregation_job_init_req(
        &self,
        url: Url,
        agg_job_init_req: AggregationJobInitReq,
        version: DapVersion,
        opts: Options<'_>,
    ) -> anyhow::Result<AggregationJobResp> {
        retry_and_decode(&version, || async {
            self.put(url.clone())
                .body(agg_job_init_req.get_encoded_with_param(&version).unwrap())
                .headers(construct_request_headers(
                    DapMediaType::AggregationJobInitReq
                        .as_str_for_version(version)
                        .with_context(|| {
                            format!("AggregationJobInitReq media type is not defined for {version}")
                        })?,
                    version,
                    opts,
                )?)
                .send()
                .await
                .context("sending AggregationJobInitReq")
        })
        .await
    }

    pub async fn poll_aggregation_job_init(
        &self,
        url: Url,
        version: DapVersion,
        opts: Options<'_>,
    ) -> anyhow::Result<AggregationJobResp> {
        retry_and_decode(&version, || async {
            self.get(url.clone())
                .headers(construct_request_headers(
                    DapMediaType::AggregationJobInitReq
                        .as_str_for_version(version)
                        .with_context(|| {
                            format!("AggregationJobInitReq media type is not defined for {version}")
                        })?,
                    version,
                    opts,
                )?)
                .send()
                .await
                .context("polling aggregation job init req")
        })
        .await
    }

    pub async fn get_aggregate_share(
        &self,
        url: Url,
        agg_share_req: AggregateShareReq,
        version: DapVersion,
        opts: Options<'_>,
    ) -> anyhow::Result<AggregateShare> {
        retry_and_decode(&(), || async {
            self.post(url.clone())
                .body(agg_share_req.get_encoded_with_param(&version).unwrap())
                .headers(construct_request_headers(
                    DapMediaType::AggregateShareReq
                        .as_str_for_version(version)
                        .with_context(|| {
                            format!("AggregateShareReq media type is not defined for {version}")
                        })?,
                    version,
                    opts,
                )?)
                .send()
                .await
                .context("sending AggregateShareReq")
        })
        .await
    }
}

#[derive(Default, Debug, Clone, Copy)]
pub struct Options<'s> {
    pub taskprov_advertisement: Option<&'s TaskprovAdvertisement>,
    pub bearer_token: Option<&'s BearerToken>,
}

fn construct_request_headers(
    media_type: &str,
    version: DapVersion,
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
            header::HeaderValue::from_str(&taskprov.serialize_to_header_value(version).unwrap())?,
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
