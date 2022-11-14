// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use daphne::{
    constants,
    hpke::HpkeReceiverConfig,
    messages::{BatchSelector, CollectReq, CollectResp, HpkeConfig, Id, Query},
    DapMeasurement, DapVersion, ProblemDetails, VdafConfig,
};
use prio::codec::{Decode, Encode, ParameterizedEncode};
use reqwest::blocking::{Client, ClientBuilder};
use std::{
    io::{stdin, Read},
    time::SystemTime,
};
use url::Url;

/// DAP Functions, a utility for interacting with DAP deployments.
#[derive(Parser, Debug)]
#[clap(version, about, long_about = None)]
struct Cli {
    #[clap(subcommand)]
    action: Action,

    /// DAP task ID (base64, URL-safe encoding)
    #[clap(short, long, action)]
    task_id: String,

    /// Bearer token for authorizing request
    #[clap(short, long, action)]
    bearer_token: Option<String>,

    /// HPKE receiver configuration for decrypting response
    #[clap(long, action)]
    hpke_receiver: Option<HpkeReceiverConfig>,
}

#[derive(Debug, Subcommand)]
enum Action {
    /// Upload a report to a DAP Leader using the JSON-formatted measurement provided on stdin.
    Upload {
        /// Base URL of the Leader
        #[clap(long, action)]
        leader_url: String,

        /// Base URL of the Helper
        #[clap(long, action)]
        helper_url: String,

        /// JSON-formatted VDAF config
        #[clap(short, long, action)]
        vdaf: VdafConfig,
    },
    /// Collect an aggregate result from the DAP Leader using the JSON-formatted batch selector
    /// provided on stdin.
    Collect {
        /// Base URL of the Leader
        #[clap(long, action)]
        leader_url: String,
    },
    /// Poll the given collect URI for the aggregate result.
    CollectPoll {
        /// The collect URI
        #[clap(short, long, action)]
        uri: String,

        /// JSON-formatted VDAF config
        #[clap(short, long, action)]
        vdaf: VdafConfig,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let version = DapVersion::Draft02; // TODO(bhalleycf) make a parameter
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)?
        .as_secs();

    let cli = Cli::parse();
    let task_id = parse_id(&cli.task_id).with_context(|| "failed to parse task ID")?;

    // HTTP client should not handle redirects automatically.
    let http_client = ClientBuilder::new()
        .redirect(reqwest::redirect::Policy::none())
        .build()?;

    match &cli.action {
        Action::Upload {
            leader_url,
            helper_url,
            vdaf,
        } => {
            // Read the measurement from stdin.
            let mut buf = String::new();
            stdin()
                .lock()
                .read_to_string(&mut buf)
                .with_context(|| "failed to read measurement from stdin")?;
            let measurement: DapMeasurement =
                serde_json::from_str(&buf).with_context(|| "failed to parse JSON from stdin")?;

            // Get the Aggregators' HPKE configs.
            let leader_hpke_config = get_hpke_config(&http_client, &task_id, leader_url)
                .with_context(|| "failed to fetch the Leader's HPKE config")?;
            let helper_hpke_config = get_hpke_config(&http_client, &task_id, helper_url)
                .with_context(|| "failed to fetch the Helper's HPKE config")?;

            // Generate a report for the measurement.
            let report = vdaf
                .produce_report(
                    &[leader_hpke_config, helper_hpke_config],
                    now,
                    &task_id,
                    measurement,
                )
                .with_context(|| "failed to produce report")?;

            // Post the report to the Leader.
            let mut headers = reqwest::header::HeaderMap::new();
            headers.insert(
                reqwest::header::CONTENT_TYPE,
                reqwest::header::HeaderValue::from_static(constants::MEDIA_TYPE_REPORT),
            );
            let resp = http_client
                .post(Url::parse(leader_url)?.join("upload")?)
                .body(report.get_encoded())
                .headers(headers)
                .send()?;
            if resp.status() == 400 {
                let problem_details: ProblemDetails =
                    serde_json::from_str(&resp.text()?).with_context(|| "unexpected response")?;
                return Err(anyhow!(serde_json::to_string(&problem_details)?));
            } else if resp.status() != 200 {
                return Err(anyhow!("unexpected response: {:?}", resp));
            }

            Ok(())
        }
        Action::Collect { leader_url } => {
            // Read the batch selector from stdin.
            let mut buf = String::new();
            stdin()
                .lock()
                .read_to_string(&mut buf)
                .with_context(|| "failed to read measurement from stdin")?;
            let query: Query =
                serde_json::from_str(&buf).with_context(|| "failed to parse JSON from stdin")?;

            // Construct collect request.
            let collect_req = CollectReq {
                task_id,
                query,
                agg_param: Vec::default(),
            };

            let mut headers = reqwest::header::HeaderMap::new();
            headers.insert(
                reqwest::header::CONTENT_TYPE,
                reqwest::header::HeaderValue::from_static(constants::MEDIA_TYPE_COLLECT_REQ),
            );
            if let Some(ref token) = cli.bearer_token {
                headers.insert(
                    reqwest::header::HeaderName::from_static("dap-auth-token"),
                    reqwest::header::HeaderValue::from_str(token)?,
                );
            }

            let resp = http_client
                .post(Url::parse(leader_url)?.join("collect")?)
                .body(collect_req.get_encoded_with_param(&version))
                .headers(headers)
                .send()?;
            if resp.status() == 400 {
                let problem_details: ProblemDetails =
                    serde_json::from_str(&resp.text()?).with_context(|| "unexpected response")?;
                return Err(anyhow!(serde_json::to_string(&problem_details)?));
            } else if resp.status() != 303 {
                return Err(anyhow!("unexpected response: {:?}", resp));
            }

            let uri_str = resp
                .headers()
                .get("Location")
                .ok_or_else(|| anyhow!("response is missing Location header"))?
                .to_str()?;
            let uri =
                Url::parse(uri_str).with_context(|| "Leader did not respond with valid URI")?;

            println!("{}", uri);
            Ok(())
        }
        Action::CollectPoll { uri, vdaf } => {
            // Read the batch selector from stdin.
            let mut buf = String::new();
            stdin()
                .lock()
                .read_to_string(&mut buf)
                .with_context(|| "failed to read measurement from stdin")?;
            let batch_selector: BatchSelector =
                serde_json::from_str(&buf).with_context(|| "failed to parse JSON from stdin")?;

            let resp = http_client.get(uri).send()?;
            if resp.status() == 202 {
                return Err(anyhow!("aggregate result not ready"));
            } else if resp.status() != 200 {
                return Err(anyhow!("unexpected response: {:?}", resp));
            }
            let receiver = cli.hpke_receiver.as_ref().ok_or_else(|| {
                anyhow!("received response, but cannot decrypt without HPKE receiver config")
            })?;
            let collect_resp = CollectResp::get_decoded(&resp.bytes()?)?;
            let agg_res = vdaf
                .consume_encrypted_agg_shares(
                    receiver,
                    &task_id,
                    &batch_selector,
                    collect_resp.report_count,
                    collect_resp.encrypted_agg_shares,
                )
                .await?;

            print!("{}", serde_json::to_string(&agg_res)?);
            Ok(())
        }
    }
}

fn parse_id(id_str: &str) -> Result<Id> {
    let id_bytes = base64::decode_config(id_str, base64::URL_SAFE_NO_PAD)
        .with_context(|| "expected URL-safe, base64 string")?;
    Ok(Id::get_decoded(&id_bytes)?)
}

// TODO(cjpatton) Refactor integration tests to use this method.
fn get_hpke_config(http_client: &Client, task_id: &Id, base_url: &str) -> Result<HpkeConfig> {
    let url = Url::parse(base_url)
        .with_context(|| "failed to parse base URL")?
        .join("hpke_config")?;

    let resp = http_client
        .get(url.as_str())
        .query(&[("task_id", task_id.to_base64url())])
        .send()
        .with_context(|| "request failed")?;
    if !resp.status().is_success() {
        return Err(anyhow!("unexpected response: {:?}", resp));
    }

    let hpke_config_bytes = resp.bytes().with_context(|| "failed to read response")?;
    Ok(HpkeConfig::get_decoded(&hpke_config_bytes)?)
}
