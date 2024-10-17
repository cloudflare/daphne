// Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! The various DAP functions dapf can perform.

use anyhow::Context as _;

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
