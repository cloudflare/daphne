// Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

pub mod acceptance;
pub mod cli_parsers;
pub mod functions;
pub mod http_client;
mod test_durations;

use anyhow::{anyhow, Context};
use daphne::DapVersion;
use url::Url;

pub use http_client::HttpClient;

pub fn deduce_dap_version_from_url(url: &Url) -> anyhow::Result<DapVersion> {
    url.path_segments()
        .context("no version specified in leader url")?
        .next()
        .unwrap() // when path_segments returns Some it's guaranteed to contain at least one segment
        .parse()
        .context("failed to parse version parameter from url")
}

pub async fn response_to_anyhow(resp: reqwest::Response) -> anyhow::Error {
    anyhow!(
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
