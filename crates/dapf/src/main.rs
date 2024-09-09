// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use anyhow::{anyhow, Context, Result};
use clap::{builder::PossibleValue, Parser, Subcommand, ValueEnum};
use dapf::{
    acceptance::{load_testing, LoadControlParams, LoadControlStride, TestOptions},
    deduce_dap_version_from_url, response_to_anyhow, HttpClient,
};
use daphne::{
    constants::DapMediaType,
    error::aborts::ProblemDetails,
    hpke::{HpkeKemId, HpkeReceiverConfig},
    messages::{Base64Encode, BatchSelector, Collection, CollectionReq, Query, TaskId},
    vdaf::VdafConfig,
    DapAggregationParam, DapMeasurement, DapVersion,
};
use daphne_service_utils::http_headers;
use prio::codec::{ParameterizedDecode, ParameterizedEncode};
use rand::{thread_rng, Rng};
use std::{
    io::{stdin, Read},
    path::PathBuf,
    process::Command,
    str::FromStr,
    time::{Duration, SystemTime},
};
use tracing::level_filters::LevelFilter;
use tracing_subscriber::EnvFilter;
use url::Url;

#[derive(Debug, Clone, Copy)]
enum DefaultVdafConfigs {
    Prio2Dimension99k,
    Prio3NumProofs2,
    Prio3NumProofs3,
}

impl ValueEnum for DefaultVdafConfigs {
    fn value_variants<'a>() -> &'a [Self] {
        &[
            Self::Prio2Dimension99k,
            Self::Prio3NumProofs2,
            Self::Prio3NumProofs3,
        ]
    }

    fn to_possible_value(&self) -> Option<PossibleValue> {
        match self {
            Self::Prio2Dimension99k => Some(PossibleValue::new("prio2-dimension-99k")),
            Self::Prio3NumProofs2 => Some(PossibleValue::new("prio3-num-proofs-2")),
            Self::Prio3NumProofs3 => Some(PossibleValue::new("prio3-num-proofs-3")),
        }
    }
}

impl DefaultVdafConfigs {
    fn into_vdaf(self) -> VdafConfig {
        match self {
            Self::Prio2Dimension99k => VdafConfig::Prio2 { dimension: 99_992 },
            Self::Prio3NumProofs2 => VdafConfig::Prio3(
                daphne::vdaf::Prio3Config::SumVecField64MultiproofHmacSha256Aes128 {
                    bits: 1,
                    length: 100_000,
                    chunk_length: 320,
                    num_proofs: 2,
                },
            ),
            Self::Prio3NumProofs3 => VdafConfig::Prio3(
                daphne::vdaf::Prio3Config::SumVecField64MultiproofHmacSha256Aes128 {
                    bits: 1,
                    length: 100_000,
                    chunk_length: 320,
                    num_proofs: 3,
                },
            ),
        }
    }
}

#[derive(Clone, Debug)]
enum CliVdafConfig {
    Default(DefaultVdafConfigs),
    Custom(VdafConfig),
}

impl FromStr for CliVdafConfig {
    type Err = String;
    fn from_str(s: &str) -> std::prelude::v1::Result<Self, Self::Err> {
        DefaultVdafConfigs::from_str(s, false)
            .map(Self::Default)
            .or_else(|default_err| {
                serde_json::from_str(s)
                    .map(Self::Custom)
                    .map_err(|json_err| {
                        if s.contains('{') {
                            json_err.to_string()
                        } else {
                            default_err
                        }
                    })
            })
    }
}

impl CliVdafConfig {
    fn into_vdaf(self) -> VdafConfig {
        match self {
            Self::Default(d) => d.into_vdaf(),
            Self::Custom(v) => v,
        }
    }
}

/// DAP Functions, a utility for interacting with DAP deployments.
#[derive(Parser, Debug)]
#[clap(version, about, long_about = None)]
struct Cli {
    #[clap(subcommand)]
    action: Action,
    #[arg(env, long)]
    sentry_dsn: Option<sentry::types::Dsn>,
    #[arg(long, env)]
    no_reuse_http_client: bool,
    #[arg(long)]
    enable_ssl_key_log_file: bool,
}

#[derive(Debug, Subcommand)]
enum LeaderAction {
    /// Upload a report to a DAP Leader using the JSON-formatted measurement provided on stdin.
    Upload {
        /// Base URL of the Leader
        #[clap(long, env)]
        leader_url: Url,

        /// Base URL of the Helper
        #[clap(long, env)]
        helper_url: Url,

        /// JSON-formatted VDAF config
        #[clap(short, long, env)]
        vdaf_config: CliVdafConfig,

        /// Path to the certificate file to use to verify the signature of the hpke config
        #[arg(short, long, env)]
        certificate_file: Option<PathBuf>,

        /// DAP task ID (base64, URL-safe encoding)
        #[arg(short, long, env, value_parser = parse_id)]
        task_id: TaskId,
    },
    /// Collect an aggregate result from the DAP Leader using the JSON-formatted batch selector
    /// provided on stdin.
    Collect {
        /// Base URL of the Leader
        #[clap(long, env)]
        leader_url: Url,

        /// DAP task ID (base64, URL-safe encoding)
        #[clap(short, long, env, value_parser = parse_id)]
        task_id: TaskId,
    },
    /// Poll the given collect URI for the aggregate result.
    CollectPoll {
        /// The collect URI
        #[clap(short, long, env)]
        uri: Url,

        /// JSON-formatted VDAF config
        #[clap(short, long, env)]
        vdaf_config: CliVdafConfig,

        /// HPKE receiver configuration for decrypting response
        #[clap(long, env)]
        hpke_receiver: Option<HpkeReceiverConfig>,

        /// DAP task ID (base64, URL-safe encoding)
        #[clap(short, long, env, value_parser = parse_id)]
        task_id: TaskId,
    },
}
#[derive(Debug, Subcommand)]
enum HelperAction {
    /// Perform one full aggregation job against a helper using taskprov to provide the task.
    ///
    /// This command requires `VDAF_VERIFY_INIT` to be exported to the environment containing the
    /// hex encoded VDAF verification key initializer, as specified in the Task prov extension.
    ///
    /// In addition to this an authentication method must be used:
    ///
    /// - Bearer Token: Export `LEADER_BEARER_TOKEN` containing the bearer token to use.
    ///
    /// - Mutual TLS: Export `LEADER_TLS_CLIENT_CERT` containing a client certificate and
    ///   `LEADER_TLS_CLIENT_KEY` containing the certificate's private key.
    Aggregate {
        #[arg(env)]
        helper_url: Url,
        #[arg(long, env)]
        vdaf_config: CliVdafConfig,
        #[arg(long, env)]
        hpke_signing_certificate_path: Option<PathBuf>,
        #[arg(env, default_value_t = 50)]
        reports_per_batch: usize,
        #[arg(env, default_value_t = 10)]
        reports_per_agg_job: usize,
        #[command(flatten)]
        load_control: LoadControlParamsCli,
    },
    /// Perform multiple aggregation jobs against a helper.
    ///
    /// This command requires `VDAF_VERIFY_INIT` to be exported to the environment containing the
    /// hex encoded VDAF verification key initializer, as specified in the Task prov extension.
    ///
    /// In addition to this an authentication method must be used:
    ///
    /// - Bearer Token: Export `LEADER_BEARER_TOKEN` containing the bearer token to use.
    ///
    /// - Mutual TLS: Export `LEADER_TLS_CLIENT_CERT` containing a client certificate and
    ///   `LEADER_TLS_CLIENT_KEY` containing the certificate's private key.
    LoadTest {
        #[arg(env)]
        helper_url: Url,
        #[command(flatten)]
        load_control: LoadControlParamsCli,
        #[command(subcommand)]
        params: LoadTestParameters,
    },
}

#[derive(Debug, Subcommand)]
enum HpkeAction {
    /// Get the Aggregator's HPKE config and write the JSON-formatted output to stdout.
    Get {
        #[clap(short = 'u', long, env)]
        aggregator_url: Url,
        /// Path to the certificate file to use to verify the signature of the hpke config
        #[arg(short, long, env)]
        certificate_file: Option<PathBuf>,
    },
    /// Get the Aggregator's HPKE receiver config, including the private key.
    GetReceiverConfig {
        #[arg(short = 'c', long)]
        wrangler_config: String,
        #[arg(short = 'e', long)]
        wrangler_env: Option<String>,
        #[arg(default_value_t, long)]
        dap_version: DapVersion,
    },
    /// Generate an hpke receiver config.
    GenerateReceiverConfig { kem_alg: KemAlg },
    /// Rotate the HPKE config advertised by the Aggregator.
    RotateReceiverConfig {
        #[arg(short = 'c', long)]
        wrangler_config: String,
        #[arg(short = 'e', long)]
        wrangler_env: Option<String>,
        #[arg(default_value_t, long)]
        dap_version: DapVersion,
        kem_alg: KemAlg,
    },
}

#[derive(Debug, Subcommand)]
enum TestAction {
    /// Add an hpke config to a test-utils enabled `daphne-server`.
    AddHpkeConfig {
        aggregator_url: Url,
        #[arg(short, long, default_value = "x25519_hkdf_sha256")]
        kem_alg: KemAlg,
    },
    /// Clear all storage of an aggregator.
    ClearStorage {
        aggregator_url: Url,
        /// If a new hpke config should be inserted after clearing all storage, use this flag to
        /// specify the key algorithm to use for the new hpke config
        #[arg(short, long)]
        set_hpke_key: Option<KemAlg>,
    },
}

#[derive(Debug, Subcommand)]
enum Action {
    /// Perform actions on the leader.
    #[command(subcommand)]
    Leader(LeaderAction),
    /// Perform actions on the helper.
    #[command(subcommand)]
    Helper(HelperAction),
    /// Perform actions on the hpke configuration of a storage proxy
    #[command(subcommand)]
    Hpke(HpkeAction),
    /// Interact with test routes behind `test-utils` feature flags.
    #[command(subcommand)]
    TestRoutes(TestAction),
}

#[derive(Debug, Clone, Subcommand)]
enum LoadTestParameters {
    /// Test multiple sets of parameters.
    Multiple,
    /// Test a single set of parameters multiple times.
    Single {
        #[arg(env)]
        reports_per_batch: usize,
        #[arg(env)]
        reports_per_agg_job: usize,
        #[arg(short, long, env)]
        vdaf_config: CliVdafConfig,
    },
}

#[derive(Debug, Clone, Parser)]
struct LoadControlParamsCli {
    #[arg(long, env)]
    stride_wait_time: Option<u64>,
    #[arg(long, env)]
    stride_len: Option<usize>,
    #[arg(long, env)]
    min_requests_before_starting: Option<usize>,
    #[arg(long, env)]
    max_concurrent_requests: Option<usize>,
}

impl LoadControlParamsCli {
    fn into_params(
        self,
        reports_per_agg_job: usize,
        reports_per_batch: usize,
    ) -> LoadControlParams {
        LoadControlParams::new(
            self.max_concurrent_requests,
            self.min_requests_before_starting.unwrap_or_else(|| {
                LoadControlParams::max_requests_before_starting(
                    reports_per_batch,
                    reports_per_agg_job,
                )
            }),
            match (self.stride_len, self.stride_wait_time) {
                (Some(len), Some(wait_time)) => Some(LoadControlStride {
                    len,
                    wait_time: Duration::from_millis(wait_time),
                }),
                (Some(len), None) => Some(LoadControlStride {
                    len,
                    wait_time: Duration::from_secs(1),
                }),
                (None, _) => None,
            },
        )
    }
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
    let mut cli = Cli::parse();
    let _sentry = cli.sentry_dsn.take().map(|dsn| {
        sentry::init((
            dsn,
            sentry::ClientOptions {
                release: sentry::release_name!(),
                ..Default::default()
            },
        ))
    });
    tracing_subscriber::fmt()
        .compact()
        .with_writer(std::io::stderr)
        .with_env_filter(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .init();

    let http_client = if cli.no_reuse_http_client {
        HttpClient::new(cli.enable_ssl_key_log_file)?
    } else {
        HttpClient::new_no_reuse(cli.enable_ssl_key_log_file)?
    };

    match cli.action {
        Action::Leader(leader) => handle_leader_actions(leader, http_client).await,
        Action::Hpke(hpke) => handle_hpke_actions(hpke, http_client).await,
        Action::Helper(helper) => handle_helper_actions(helper, http_client).await,
        Action::TestRoutes(TestAction::AddHpkeConfig {
            aggregator_url,
            kem_alg,
        }) => dapf::test_routes::add_hpke_config(&http_client, &aggregator_url, kem_alg.0).await,
        Action::TestRoutes(TestAction::ClearStorage {
            aggregator_url,
            set_hpke_key,
        }) => {
            dapf::test_routes::delete_all_storage(
                &http_client,
                &aggregator_url,
                set_hpke_key.map(|k| k.0),
            )
            .await
        }
    }
}

async fn handle_leader_actions(
    leader: LeaderAction,
    http_client: HttpClient,
) -> anyhow::Result<()> {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)?
        .as_secs();

    match leader {
        LeaderAction::Upload {
            leader_url,
            helper_url,
            vdaf_config,
            certificate_file,
            task_id,
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
            let leader_hpke_config = http_client
                .get_hpke_config(&leader_url, certificate_file.as_deref())
                .await
                .with_context(|| "failed to fetch the Leader's HPKE config")?
                .hpke_configs
                .swap_remove(0);
            let helper_hpke_config = http_client
                .get_hpke_config(&helper_url, certificate_file.as_deref())
                .await
                .with_context(|| "failed to fetch the Helper's HPKE config")?
                .hpke_configs
                .swap_remove(0);

            let version = deduce_dap_version_from_url(&leader_url)?;
            // Generate a report for the measurement.
            let report = vdaf_config
                .into_vdaf()
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
                        .ok_or_else(|| anyhow!("invalid content-type for dap version"))?,
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
                return Err(response_to_anyhow(resp).await);
            }

            Ok(())
        }
        LeaderAction::Collect {
            leader_url,
            task_id: _,
        } => {
            // Read the batch selector from stdin.
            let mut buf = String::new();
            stdin()
                .lock()
                .read_to_string(&mut buf)
                .with_context(|| "failed to read measurement from stdin")?;
            let query: Query =
                serde_json::from_str(&buf).with_context(|| "failed to parse JSON from stdin")?;

            let version = deduce_dap_version_from_url(&leader_url)?;
            // Construct collect request.
            let collect_req = CollectionReq {
                query,
                agg_param: Vec::default(),
            };

            let mut headers = reqwest::header::HeaderMap::new();
            headers.insert(
                reqwest::header::CONTENT_TYPE,
                reqwest::header::HeaderValue::from_str(
                    DapMediaType::CollectReq
                        .as_str_for_version(version)
                        .ok_or_else(|| anyhow!("invalid content-type for dap version"))?,
                )
                .expect("failed to construct content-type hader"),
            );
            if let Ok(token) = std::env::var("LEADER_BEARER_TOKEN") {
                headers.insert(
                    reqwest::header::HeaderName::from_static(http_headers::DAP_AUTH_TOKEN),
                    reqwest::header::HeaderValue::from_str(&token)?,
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
                return Err(response_to_anyhow(resp).await);
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
        LeaderAction::CollectPoll {
            uri,
            vdaf_config,
            hpke_receiver,
            task_id,
        } => {
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
                return Err(response_to_anyhow(resp).await);
            }
            let receiver = hpke_receiver.as_ref().ok_or_else(|| {
                anyhow!("received response, but cannot decrypt without HPKE receiver config")
            })?;
            let version = deduce_dap_version_from_url(&uri)?;
            let collect_resp = Collection::get_decoded_with_param(&version, &resp.bytes().await?)?;
            let agg_res = vdaf_config
                .into_vdaf()
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
    }
}

async fn handle_helper_actions(
    helper: HelperAction,
    http_client: HttpClient,
) -> anyhow::Result<()> {
    match helper {
        HelperAction::Aggregate {
            helper_url,
            vdaf_config,
            hpke_signing_certificate_path,
            reports_per_batch,
            reports_per_agg_job,
            load_control,
        } => {
            tracing::info!("using vdaf: {:?}", vdaf_config);
            let load_control = load_control.into_params(reports_per_agg_job, reports_per_batch);
            tracing::info!("using load params: {load_control:?}");

            let t = dapf::acceptance::Test::from_env(
                helper_url,
                vdaf_config.into_vdaf(),
                hpke_signing_certificate_path,
                http_client,
                load_control,
            )?;

            let res = t
                .test_helper(&TestOptions {
                    reports_per_agg_job,
                    reports_per_batch,
                    ..Default::default()
                })
                .await
                .map(|_| ());
            println!("{}", t.encode_metrics());
            res
        }
        HelperAction::LoadTest {
            helper_url,
            load_control,
            params: LoadTestParameters::Multiple,
        } => {
            load_testing::execute_multiple_combinations(
                helper_url,
                http_client,
                load_control.into_params(usize::MAX, 1),
            )
            .await;
            Ok(())
        }
        HelperAction::LoadTest {
            helper_url,
            load_control,
            params:
                LoadTestParameters::Single {
                    reports_per_batch,
                    reports_per_agg_job,
                    vdaf_config,
                },
        } => {
            load_testing::execute_single_combination_from_env(
                helper_url,
                vdaf_config.into_vdaf(),
                reports_per_batch,
                reports_per_agg_job,
                http_client,
                load_control.into_params(reports_per_agg_job, reports_per_batch),
            )
            .await;
            Ok(())
        }
    }
}

async fn handle_hpke_actions(hpke: HpkeAction, http_client: HttpClient) -> anyhow::Result<()> {
    let mut rng = thread_rng();
    fn kv_key_of(dap_version: DapVersion) -> String {
        format!("hpke_receiver_config_set/{dap_version}")
    }
    async fn get_receiver_config(
        wrangler_config: &str,
        wrangler_env: Option<&str>,
        dap_version: DapVersion,
    ) -> anyhow::Result<Vec<HpkeReceiverConfig>> {
        let hpke_receiver_config_list_key = kv_key_of(dap_version);
        let current_hpke_receiver_config_list_value = {
            let mut get_hpke_config_process = Command::new("wrangler");
            get_hpke_config_process.args([
                "kv:key",
                "get",
                &hpke_receiver_config_list_key,
                "-c",
                wrangler_config,
                "--binding",
                "DAP_CONFIG",
            ]);
            if let Some(env) = wrangler_env {
                get_hpke_config_process.args(["-e", env]);
            }
            let get_hpke_config_process_output = get_hpke_config_process
                .output()
                .with_context(|| "wrangler kv:key get failed")?;
            if !get_hpke_config_process_output.status.success() {
                println!(
                    "{}",
                    String::from_utf8_lossy(&get_hpke_config_process_output.stderr)
                );
                return Err(anyhow!(
                    "Failed to get current HPKE receiver config list (return status {})",
                    get_hpke_config_process_output.status
                ));
            }
            get_hpke_config_process_output.stdout
        };

        serde_json::from_slice::<Vec<HpkeReceiverConfig>>(&current_hpke_receiver_config_list_value)
            .with_context(|| "failed to parse the current HPKE receiver config list")
    }
    match hpke {
        HpkeAction::Get {
            aggregator_url,
            certificate_file,
        } => {
            let hpke_config = http_client
                .get_hpke_config(&aggregator_url, certificate_file.as_deref())
                .await
                .with_context(|| "failed to fetch the HPKE config")?;
            println!(
                "{}",
                serde_json::to_string(&hpke_config.hpke_configs)
                    .with_context(|| "failed to encode HPKE config")?
            );

            Ok(())
        }
        HpkeAction::GetReceiverConfig {
            wrangler_config,
            wrangler_env,
            dap_version,
        } => {
            let config =
                get_receiver_config(&wrangler_config, wrangler_env.as_deref(), dap_version).await?;
            println!("{}", serde_json::to_string_pretty(&config)?);
            Ok(())
        }
        HpkeAction::GenerateReceiverConfig { kem_alg } => {
            let receiver_config = HpkeReceiverConfig::gen(rng.gen(), kem_alg.0)
                .with_context(|| "failed to generate HPKE receiver config")?;
            println!(
                "{}",
                serde_json::to_string(&receiver_config)
                    .with_context(|| "failed to JSON-encode the HPKE receiver config")?
            );
            Ok(())
        }
        HpkeAction::RotateReceiverConfig {
            wrangler_config,
            wrangler_env,
            dap_version,
            kem_alg,
        } => {
            eprintln!("Getting current config...");
            let mut hpke_receiver_config_list =
                get_receiver_config(&wrangler_config, wrangler_env.as_deref(), dap_version).await?;
            eprint!("Choosing a new id: ");
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
            eprintln!("{hpke_config_id}");

            eprintln!("Generating new key pair of {kem_alg:?}");
            let new_hpke_receiver_config = HpkeReceiverConfig::gen(hpke_config_id, kem_alg.0)
                .with_context(|| "failed to generate HPKE receiver config")?;

            // Insert the new config at the front of the list. We expect that Daphne-Worker always
            // advertises the first config in the list.
            hpke_receiver_config_list.insert(0, new_hpke_receiver_config);

            let updated_hpke_receiver_config_list_value =
                serde_json::to_string(&hpke_receiver_config_list)
                    .with_context(|| "failed to encode the updated HPKE receiver config list")?;

            eprintln!("Updating list of configs....");
            let mut put_updated_hpke_process = Command::new("wrangler");
            put_updated_hpke_process.args([
                "kv:key",
                "put",
                &kv_key_of(dap_version),
                &updated_hpke_receiver_config_list_value,
                "-c",
                &wrangler_config,
                "--binding",
                "DAP_CONFIG",
            ]);
            if let Some(env) = wrangler_env {
                put_updated_hpke_process.args(["-e", &env]);
            }
            let put_updated_hpke_process_output = put_updated_hpke_process
                .output()
                .with_context(|| "wrangler kv:key get failed")?;
            if !put_updated_hpke_process_output.status.success() {
                eprintln!(
                    "{}",
                    String::from_utf8_lossy(&put_updated_hpke_process_output.stderr)
                );
                return Err(anyhow!(
                    "Failed to put updatedt HPKE receiver config list (return status {})",
                    put_updated_hpke_process_output.status
                ));
            }

            eprintln!("Done");
            Ok(())
        }
    }
}

fn parse_id(id_str: &str) -> Result<TaskId> {
    TaskId::try_from_base64url(id_str)
        .ok_or_else(|| anyhow!("failed to decode ID"))
        .context("expected URL-safe, base64 string")
}
