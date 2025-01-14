// Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! The various DAP functions dapf can perform.

use anyhow::{anyhow, bail, Context as _};
use daphne::error::aborts::ProblemDetails;
use prio::codec::ParameterizedDecode;
use reqwest::StatusCode;
use std::future::Future;

pub mod decrypt;
pub mod helper;
pub mod hpke;
pub mod leader;
pub mod test_routes;

async fn response_to_anyhow(resp: reqwest::Response) -> anyhow::Error {
    anyhow::anyhow!(
        "unexpected response: {}\n{}",
        format!("{resp:?}"),
        match resp
            .text()
            .await
            .context("reading body while processing error")
            .map_err(|e| e.to_string())
        {
            Ok(body) => format!("body: {body}"),
            Err(error) => format!("{error:?}"),
        }
    )
}

async fn retry<F, Fut, FutH, H, O>(mut request: F, handle_status: H) -> anyhow::Result<O>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = anyhow::Result<reqwest::Response>>,
    H: FnOnce(reqwest::Response) -> FutH,
    FutH: Future<Output = anyhow::Result<O>>,
{
    const RETRY_COUNT: usize = 5;
    for i in 1..=RETRY_COUNT {
        let resp = request().await?;

        return match resp.status() {
            StatusCode::BAD_REQUEST => {
                let text = resp.text().await?;
                let problem_details: ProblemDetails =
                    serde_json::from_str(&text).with_context(|| {
                        format!(
                            "400 Bad Request: failed to parse problem details document: {text:?}"
                        )
                    })?;
                Err(anyhow!("400 Bad Request: {problem_details:?}"))
            }
            StatusCode::INTERNAL_SERVER_ERROR => Err(anyhow::anyhow!(
                "500 Internal Server Error: {}",
                resp.text().await?
            )),
            StatusCode::SERVICE_UNAVAILABLE if i == RETRY_COUNT => bail!("service unavailable"),
            StatusCode::SERVICE_UNAVAILABLE => {
                tracing::info!("retrying....");
                continue;
            }
            s if !s.is_success() => Err(response_to_anyhow(resp).await),
            _ => handle_status(resp).await,
        };
    }
    unreachable!()
}

async fn retry_and_decode<F, Fut, R, P>(params: &P, request: F) -> anyhow::Result<R>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = anyhow::Result<reqwest::Response>>,
    R: ParameterizedDecode<P>,
{
    retry(request, |resp| async {
        let output_type = std::any::type_name::<R>();
        let bytes = resp
            .bytes()
            .await
            .with_context(|| format!("transfering bytes from the {output_type}"))?;

        R::get_decoded_with_param(params, &bytes)
            .with_context(|| format!("failed to parse response to {output_type} from Helper"))
            .with_context(|| format!("faulty bytes: {bytes:?}"))
    })
    .await
}
