// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use anyhow::{anyhow, Context, Result};
use clap::{builder::PossibleValue, Parser, Subcommand, ValueEnum};
use daphne::{
    constants::DapMediaType,
    error::aborts::ProblemDetails,
    hpke::{HpkeConfig, HpkeKemId, HpkeReceiverConfig},
    messages::{
        decode_base64url_vec, Base64Encode, BatchSelector, Collection, CollectionReq,
        HpkeConfigList, Query, TaskId,
    },
    vdaf::VdafConfig,
    DapAggregationParam, DapMeasurement, DapVersion,
};
use daphne_service_utils::http_headers;
use prio::codec::{Decode, ParameterizedDecode, ParameterizedEncode};
use rand::prelude::*;
use reqwest::{Client, ClientBuilder};
use std::{
    io::{stdin, Cursor, Read},
    path::{Path, PathBuf},
    process::Command,
    time::SystemTime,
};
use webpki::{EndEntityCert, ECDSA_P256_SHA256};
use x509_parser::pem::Pem;

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
    /// Get the Aggregator's HPKE config and write the JSON-formatted output to stdout.
    GetHpkeConfig {
        aggregator_url: Url,
        /// Path to the certificate file to use to verify the signature of the hpke config
        #[arg(short, long)]
        certificate_file: Option<PathBuf>,
    },
    /// Upload a report to a DAP Leader using the JSON-formatted measurement provided on stdin.
    Upload {
        /// Base URL of the Leader
        #[clap(long, action)]
        leader_url: Url,

        /// Base URL of the Helper
        #[clap(long, action)]
        helper_url: Url,

        /// JSON-formatted VDAF config
        #[clap(short, long, action)]
        vdaf: VdafConfig,

        /// Path to the certificate file to use to verify the signature of the hpke config
        #[arg(short, long)]
        certificate_file: Option<PathBuf>,
    },
    /// Collect an aggregate result from the DAP Leader using the JSON-formatted batch selector
    /// provided on stdin.
    Collect {
        /// Base URL of the Leader
        #[clap(long, action)]
        leader_url: Url,
    },
    /// Poll the given collect URI for the aggregate result.
    CollectPoll {
        /// The collect URI
        #[clap(short, long, action)]
        uri: Url,

        /// JSON-formatted VDAF config
        #[clap(short, long, action)]
        vdaf: VdafConfig,
    },
    GenerateHpkeReceiverConfig {
        kem_alg: KemAlg,
    },
    /// Rotate the HPKE config advertised by the Aggregator.
    DaphneWorkerRotateHpkeConfig {
        wrangler_config: String,
        wrangler_env: String,
        dap_version: DapVersion,
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
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)?
        .as_secs();

    let cli = Cli::parse();

    // HTTP client should not handle redirects automatically.
    let http_client = ClientBuilder::new()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .with_context(|| "failed to create HTTP client")?;

    match &cli.action {
        Action::GetHpkeConfig {
            aggregator_url,
            certificate_file,
        } => {
            let hpke_config =
                get_hpke_config(&http_client, aggregator_url, certificate_file.as_deref())
                    .await
                    .with_context(|| "failed to fetch the HPKE config")?;
            println!(
                "{}",
                serde_json::to_string(&hpke_config)
                    .with_context(|| "failed to encode HPKE config")?
            );

            Ok(())
        }
        Action::Upload {
            leader_url,
            helper_url,
            vdaf,
            certificate_file,
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
            let leader_hpke_config =
                get_hpke_config(&http_client, leader_url, certificate_file.as_deref())
                    .await
                    .with_context(|| "failed to fetch the Leader's HPKE config")?;
            let helper_hpke_config =
                get_hpke_config(&http_client, helper_url, certificate_file.as_deref())
                    .await
                    .with_context(|| "failed to fetch the Helper's HPKE config")?;

            let version = deduce_dap_version_from_url(leader_url)?;
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
                .post(leader_url.join("upload")?)
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

            let version = deduce_dap_version_from_url(leader_url)?;
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
                .post(leader_url.join("collect")?)
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

            let resp = http_client.get(uri.clone()).send().await?;
            if resp.status() == 202 {
                return Err(anyhow!("aggregate result not ready"));
            } else if resp.status() != 200 {
                return Err(anyhow!("unexpected response: {:?}", resp));
            }
            let receiver = cli.hpke_receiver.as_ref().ok_or_else(|| {
                anyhow!("received response, but cannot decrypt without HPKE receiver config")
            })?;
            let version = deduce_dap_version_from_url(uri)?;
            let collect_resp = Collection::get_decoded_with_param(&version, &resp.bytes().await?)?;
            let agg_res = vdaf
                .consume_encrypted_agg_shares(
                    receiver,
                    &task_id,
                    &batch_selector,
                    collect_resp.report_count,
                    &DapAggregationParam::Empty,
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
        Action::DaphneWorkerRotateHpkeConfig {
            wrangler_config,
            wrangler_env,
            dap_version,
            kem_alg,
        } => {
            let hpke_receiver_config_list_key = format!("hpke_receiver_config_set/{dap_version}");
            let current_hpke_receiver_config_list_value = {
                let get_current_hpke_receiver_config_list_result = Command::new("wrangler")
                    .args([
                        "kv:key",
                        "get",
                        &hpke_receiver_config_list_key,
                        "-c",
                        wrangler_config,
                        "-e",
                        wrangler_env,
                        "--binding",
                        "DAP_CONFIG",
                    ])
                    .output()
                    .with_context(|| "wrangler kv:key get failed")?;
                if !get_current_hpke_receiver_config_list_result
                    .status
                    .success()
                {
                    println!(
                        "{}",
                        String::from_utf8_lossy(
                            &get_current_hpke_receiver_config_list_result.stderr
                        )
                    );
                    return Err(anyhow!(
                        "Failed to get current HPKE receiver config list (return status {})",
                        get_current_hpke_receiver_config_list_result.status
                    ));
                }
                get_current_hpke_receiver_config_list_result.stdout
            };

            let mut hpke_receiver_config_list = serde_json::from_slice::<Vec<HpkeReceiverConfig>>(
                &current_hpke_receiver_config_list_value,
            )
            .with_context(|| "failed to parse the current HPKE receiver config list")?;

            // Choose a fresh config ID.
            let hpke_config_id = loop {
                let id = rng.gen::<u8>();
                if !hpke_receiver_config_list
                    .iter()
                    .any(|receiver_config| receiver_config.config.id == id)
                {
                    break id;
                }
            };

            let new_hpke_receiver_config = HpkeReceiverConfig::gen(hpke_config_id, kem_alg.0)
                .with_context(|| "failed to generate HPKE receiver config")?;

            // Insert the new config at the front of the list. We expect that Daphne-Worker always
            // advertises the first config in the list.
            hpke_receiver_config_list.insert(0, new_hpke_receiver_config);

            let updated_hpke_receiver_config_list_value =
                serde_json::to_string(&hpke_receiver_config_list)
                    .with_context(|| "failed to encode the updated HPKE receiver config list")?;

            let put_updated_hpke_receiver_config_list_result = Command::new("wrangler")
                .args([
                    "kv:key",
                    "put",
                    &hpke_receiver_config_list_key,
                    &updated_hpke_receiver_config_list_value,
                    "-c",
                    wrangler_config,
                    "-e",
                    wrangler_env,
                    "--binding",
                    "DAP_CONFIG",
                ])
                .output()
                .with_context(|| "wrangler kv:key get failed")?;
            if !put_updated_hpke_receiver_config_list_result
                .status
                .success()
            {
                println!(
                    "{}",
                    String::from_utf8_lossy(&put_updated_hpke_receiver_config_list_result.stderr)
                );
                return Err(anyhow!(
                    "Failed to put updatedt HPKE receiver config list (return status {})",
                    put_updated_hpke_receiver_config_list_result.status
                ));
            }

            println!("ID of the new HPKE config: {hpke_config_id}");
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

async fn get_hpke_config(
    http_client: &Client,
    base_url: &Url,
    certificate_file: Option<&Path>,
) -> Result<HpkeConfig> {
    let url = base_url.join("hpke_config")?;

    let resp = http_client
        .get(url.as_str())
        .send()
        .await
        .with_context(|| "request failed")?;
    if !resp.status().is_success() {
        return Err(anyhow!("unexpected response: {:?}", resp));
    }
    let maybe_signature = resp.headers().get(http_headers::HPKE_SIGNATURE).cloned();
    let hpke_config_bytes = resp.bytes().await.context("failed to read hpke config")?;
    if let Some(cert_path) = certificate_file {
        let cert = std::fs::read_to_string(cert_path).context("reading the certificate")?;
        let Some(signature) = maybe_signature else {
            anyhow::bail!("Helper did not provide a signature");
        };
        let signature_bytes = decode_base64url_vec(signature.as_bytes()).unwrap();
        let (cert_pem, _bytes_read) = Pem::read(Cursor::new(cert.as_bytes())).unwrap();
        let cert = EndEntityCert::try_from(cert_pem.contents.as_ref()).unwrap();

        cert.verify_signature(
            &ECDSA_P256_SHA256,
            &hpke_config_bytes,
            signature_bytes.as_ref(),
        )
        .map_err(|e| anyhow!("signature not verified: {}", e.to_string()))?;
    }

    match deduce_dap_version_from_url(base_url)? {
        DapVersion::Draft02 => Ok(HpkeConfig::get_decoded(&hpke_config_bytes)?),
        DapVersion::Latest | DapVersion::Draft09 => {
            Ok(HpkeConfigList::get_decoded(&hpke_config_bytes)?
                .hpke_configs
                .swap_remove(0))
        }
    }
}

fn deduce_dap_version_from_url(url: &Url) -> anyhow::Result<DapVersion> {
    url.path_segments()
        .context("no version specified in leader url")?
        .next()
        .unwrap()
        .parse()
        .context("failed to parse version parameter from url")
}
