// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use anyhow::{anyhow, Context, Result};
use clap::{builder::PossibleValue, Parser, Subcommand, ValueEnum};
use daphne::{
    constants::DapMediaType,
    error::aborts::ProblemDetails,
    hpke::{HpkeConfig, HpkeKemId, HpkeReceiverConfig},
    messages::{Base64Encode, BatchSelector, Collection, CollectionReq, Query, TaskId},
    vdaf::VdafConfig,
    DapMeasurement, DapVersion,
};
use prio::codec::{Decode, ParameterizedDecode, ParameterizedEncode};
use rand::prelude::*;
use reqwest::{Client, ClientBuilder};
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
    task_id: Option<String>,

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
    GenerateHpkeReceiverConfig {
        kem_alg: KemAlg,
    },
}

#[derive(Clone, Debug)]
struct KemAlg(HpkeKemId);

impl ValueEnum for KemAlg {
    fn value_variants<'a>() -> &'a [Self] {
        &[
            Self(HpkeKemId::X25519HkdfSha256),
            Self(HpkeKemId::P256HkdfSha256),
        ]
    }

    fn to_possible_value(&self) -> Option<PossibleValue> {
        Some(match self.0 {
            HpkeKemId::X25519HkdfSha256 => PossibleValue::new("x25519_hkdf_sha256"),
            HpkeKemId::P256HkdfSha256 => PossibleValue::new("p256_hkdf_sha256"),
            HpkeKemId::NotImplemented(id) => unreachable!("unhandled HPKE KEM ID {id}"),
        })
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let mut rng = thread_rng();
    let version = DapVersion::Draft02; // TODO(bhalleycf) make a parameter
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)?
        .as_secs();

    let cli = Cli::parse();

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
            let task_id = parse_id(&cli.task_id).with_context(|| "failed to parse task ID")?;

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
                .await
                .with_context(|| "failed to fetch the Leader's HPKE config")?;
            let helper_hpke_config = get_hpke_config(&http_client, &task_id, helper_url)
                .await
                .with_context(|| "failed to fetch the Helper's HPKE config")?;

            // Generate a report for the measurement.
            let report = vdaf
                .produce_report(
                    &[leader_hpke_config, helper_hpke_config],
                    now,
                    &task_id,
                    measurement,
                    version,
                )
                .with_context(|| "failed to produce report")?;

            // Post the report to the Leader.
            let mut headers = reqwest::header::HeaderMap::new();
            headers.insert(
                reqwest::header::CONTENT_TYPE,
                reqwest::header::HeaderValue::from_str(
                    DapMediaType::Report
                        .as_str_for_version(version)
                        .expect("failed to construct content-type value"),
                )
                .expect("failecd to construct content-type header"),
            );
            let resp = http_client
                .post(Url::parse(leader_url)?.join("upload")?)
                .body(report.get_encoded_with_param(&version)?)
                .headers(headers)
                .send()
                .await?;
            if resp.status() == 400 {
                let problem_details: ProblemDetails = serde_json::from_str(&resp.text().await?)
                    .with_context(|| "unexpected response")?;
                return Err(anyhow!(serde_json::to_string(&problem_details)?));
            } else if resp.status() != 200 {
                return Err(anyhow!("unexpected response: {:?}", resp));
            }

            Ok(())
        }
        Action::Collect { leader_url } => {
            let task_id = parse_id(&cli.task_id).with_context(|| "failed to parse task ID")?;

            // Read the batch selector from stdin.
            let mut buf = String::new();
            stdin()
                .lock()
                .read_to_string(&mut buf)
                .with_context(|| "failed to read measurement from stdin")?;
            let query: Query =
                serde_json::from_str(&buf).with_context(|| "failed to parse JSON from stdin")?;

            // Construct collect request.
            let collect_req = CollectionReq {
                draft02_task_id: if version == DapVersion::Draft02 {
                    Some(task_id)
                } else {
                    None
                },
                query,
                agg_param: Vec::default(),
            };

            let mut headers = reqwest::header::HeaderMap::new();
            headers.insert(
                reqwest::header::CONTENT_TYPE,
                reqwest::header::HeaderValue::from_str(
                    DapMediaType::CollectReq
                        .as_str_for_version(version)
                        .expect("failed to construct content-type value"),
                )
                .expect("failed to construct content-type hader"),
            );
            if let Some(ref token) = cli.bearer_token {
                headers.insert(
                    reqwest::header::HeaderName::from_static("dap-auth-token"),
                    reqwest::header::HeaderValue::from_str(token)?,
                );
            }

            let resp = http_client
                .post(Url::parse(leader_url)?.join("collect")?)
                .body(collect_req.get_encoded_with_param(&version)?)
                .headers(headers)
                .send()
                .await?;
            if resp.status() == 400 {
                let problem_details: ProblemDetails = serde_json::from_str(&resp.text().await?)
                    .with_context(|| "unexpected response")?;
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

            println!("{uri}");
            Ok(())
        }
        Action::CollectPoll { uri, vdaf } => {
            let task_id = parse_id(&cli.task_id).with_context(|| "failed to parse task ID")?;

            // Read the batch selector from stdin.
            let mut buf = String::new();
            stdin()
                .lock()
                .read_to_string(&mut buf)
                .with_context(|| "failed to read measurement from stdin")?;
            let batch_selector: BatchSelector =
                serde_json::from_str(&buf).with_context(|| "failed to parse JSON from stdin")?;

            let resp = http_client.get(uri).send().await?;
            if resp.status() == 202 {
                return Err(anyhow!("aggregate result not ready"));
            } else if resp.status() != 200 {
                return Err(anyhow!("unexpected response: {:?}", resp));
            }
            let receiver = cli.hpke_receiver.as_ref().ok_or_else(|| {
                anyhow!("received response, but cannot decrypt without HPKE receiver config")
            })?;
            let collect_resp = Collection::get_decoded_with_param(&version, &resp.bytes().await?)?;
            let agg_res = vdaf
                .consume_encrypted_agg_shares(
                    receiver,
                    &task_id,
                    &batch_selector,
                    collect_resp.report_count,
                    &[],
                    collect_resp.encrypted_agg_shares.to_vec(),
                    version,
                )
                .await?;

            print!("{}", serde_json::to_string(&agg_res)?);
            Ok(())
        }
        Action::GenerateHpkeReceiverConfig { kem_alg } => {
            let receiver_config = HpkeReceiverConfig::gen(rng.gen(), kem_alg.0)
                .with_context(|| "failed to generate HPKE receiver config")?;
            println!(
                "{}",
                serde_json::to_string(&receiver_config)
                    .with_context(|| "failed to JSON-encode the HPKE receiver config")?
            );
            Ok(())
        }
    }
}

fn parse_id(id_str: &Option<String>) -> Result<TaskId> {
    TaskId::try_from_base64url(
        id_str
            .as_deref()
            .ok_or_else(|| anyhow!("expected task ID argument"))?,
    )
    .ok_or_else(|| anyhow!("failed to decode ID"))
    .with_context(|| "expected URL-safe, base64 string")
}

// TODO(cjpatton) Refactor integration tests to use this method.
async fn get_hpke_config(
    http_client: &Client,
    task_id: &TaskId,
    base_url: &str,
) -> Result<HpkeConfig> {
    let url = Url::parse(base_url)
        .with_context(|| "failed to parse base URL")?
        .join("hpke_config")?;

    let resp = http_client
        .get(url.as_str())
        .query(&[("task_id", task_id.to_base64url())])
        .send()
        .await
        .with_context(|| "request failed")?;
    if !resp.status().is_success() {
        return Err(anyhow!("unexpected response: {:?}", resp));
    }

    let hpke_config_bytes = resp
        .bytes()
        .await
        .with_context(|| "failed to read response")?;
    Ok(HpkeConfig::get_decoded(&hpke_config_bytes)?)
}
