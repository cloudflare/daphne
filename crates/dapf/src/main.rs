// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use anyhow::{anyhow, bail, Context, Result};
use clap::{Args, Parser, Subcommand};
use dapf::{
    acceptance::{load_testing, LoadControlParams, LoadControlStride, TestOptions},
    cli_parsers::{
        use_or_request_from_user, use_or_request_from_user_or_default, CliDapQueryConfig,
        CliHpkeKemId, CliTaskId, CliVdafConfig,
    },
    deduce_dap_version_from_url, response_to_anyhow, HttpClient,
};
use daphne::{
    constants::DapMediaType,
    error::aborts::ProblemDetails,
    hpke::HpkeReceiverConfig,
    messages::{self, encode_base64url, BatchSelector, Collection, CollectionReq, Query, TaskId},
    vdaf::{Prio3Config, VdafConfig},
    DapAggregationParam, DapMeasurement, DapQueryConfig, DapVersion,
};
use daphne_service_utils::{
    http_headers,
    test_route_types::{InternalTestAddTask, InternalTestVdaf},
    DapRole,
};
use prio::codec::{ParameterizedDecode, ParameterizedEncode};
use rand::{thread_rng, Rng};
use std::{
    io::{stdin, IsTerminal, Read},
    path::PathBuf,
    process::Command,
    time::{Duration, SystemTime},
};
use tracing::level_filters::LevelFilter;
use tracing_subscriber::EnvFilter;
use url::Url;

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
        #[arg(short, long, env)]
        task_id: CliTaskId,
    },
    /// Collect an aggregate result from the DAP Leader using the JSON-formatted batch selector
    /// provided on stdin.
    Collect {
        /// Base URL of the Leader
        #[clap(long, env)]
        leader_url: Url,

        /// DAP task ID (base64, URL-safe encoding)
        #[clap(short, long, env)]
        task_id: CliTaskId,
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
        #[clap(short, long, env)]
        task_id: CliTaskId,
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
    ///
    /// This command outputs to stdout the hpke config in json and to stderr the config encoded
    /// first by prio and then in base64. This version can later be used when TODO
    Generate {
        #[arg(default_value_t)]
        kem_alg: CliHpkeKemId,
    },
    /// Rotate the HPKE config advertised by the Aggregator.
    RotateReceiverConfig {
        #[arg(short = 'c', long)]
        wrangler_config: String,
        #[arg(short = 'e', long)]
        wrangler_env: Option<String>,
        #[arg(default_value_t, long)]
        dap_version: DapVersion,
        #[arg(default_value_t, long)]
        kem_alg: CliHpkeKemId,
    },
}

#[derive(Debug, Subcommand)]
#[allow(clippy::large_enum_variant)]
enum TestAction {
    /// Add an hpke config to a test-utils enabled `daphne-server`.
    AddHpkeConfig {
        aggregator_url: Url,
        #[arg(short, long, default_value_t)]
        kem_alg: CliHpkeKemId,
    },
    CreateAddTaskJson {
        #[arg(long)]
        task_id: Option<CliTaskId>,
        #[arg(long)]
        leader_url: Option<Url>,
        #[arg(long)]
        helper_url: Option<Url>,
        #[arg(long)]
        vdaf: Option<CliVdafConfig>,
        #[arg(long)]
        leader_auth_token: Option<String>,
        #[arg(long)]
        collector_auth_token: Option<String>,
        #[arg(long)]
        role: Option<DapRole>,
        #[arg(long)]
        query: Option<CliDapQueryConfig>,
        #[arg(long)]
        min_batch_size: Option<u64>,
        #[arg(long)]
        collector_hpke_config: Option<String>,
        #[arg(long)]
        time_precision: Option<u64>,
        #[arg(long)]
        expires_in_seconds: Option<u64>,
    },
    /// Clear all storage of an aggregator.
    ClearStorage {
        aggregator_url: Url,
        /// If a new hpke config should be inserted after clearing all storage, use this flag to
        /// specify the key algorithm to use for the new hpke config
        #[arg(short, long)]
        set_hpke_key: Option<CliHpkeKemId>,
    },
}

#[derive(Debug, Subcommand)]
enum CliDapMediaType {
    AggregationJobResp,
    AggregateShare,
    /// Decode a [DapMediaType::Collection].
    ///
    /// If the `--vdaf-config`, `--task-id` and `--hpke-config-path` are supplied, then the
    /// aggregate share will also be decrypted and unsharded, presenting the final result of the
    /// vdaf.
    Collection {
        #[clap(long, env)]
        vdaf_config: Option<CliVdafConfig>,
        #[clap(long, env)]
        task_id: Option<CliTaskId>,
        #[clap(long, env)]
        hpke_config_path: Option<PathBuf>,
    },
    HpkeConfigList,
}

#[derive(Debug, Args)]
struct DecodeAction {
    input: Option<PathBuf>,
    #[arg(long = "dap-version", env, default_value_t = DapVersion::Latest)]
    version: DapVersion,
    #[command(subcommand)]
    media_type: CliDapMediaType,
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
    /// Decode payloads returned by dap requests.
    Decode(DecodeAction),
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
        Action::Decode(decode) => handle_decode_actions(decode).await,
        Action::TestRoutes(test) => handle_test_routes(test, http_client).await,
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
                    &task_id.into(),
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
                    DapMediaType::CollectionReq
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
            let agg_res = vdaf_config.into_vdaf().consume_encrypted_agg_shares(
                receiver,
                &task_id.into(),
                &batch_selector,
                collect_resp.report_count,
                &DapAggregationParam::Empty,
                collect_resp.encrypted_agg_shares.to_vec(),
                version,
            )?;

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
        HpkeAction::Generate { kem_alg } => {
            let receiver_config = HpkeReceiverConfig::gen(rng.gen(), kem_alg.0)
                .with_context(|| "failed to generate HPKE receiver config")?;
            if std::io::stdout().is_terminal() {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&receiver_config).unwrap()
                );
            } else {
                print!("{}", serde_json::to_string(&receiver_config).unwrap())
            }
            let encoded = encode_base64url(
                receiver_config
                    .config
                    .get_encoded_with_param(&DapVersion::Latest)
                    .unwrap(),
            );
            if std::io::stderr().is_terminal() {
                eprintln!("DAP and base64 encoded hpke config: {encoded}");
            } else {
                eprint!("{encoded}");
            }
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

async fn handle_decode_actions(action: DecodeAction) -> anyhow::Result<()> {
    let mut buf = Vec::new();
    match action.input.map(std::fs::File::open).transpose()? {
        Some(mut file) => file.read_to_end(&mut buf)?,
        None => std::io::stdin().read_to_end(&mut buf)?,
    };
    let s = match action.media_type {
        CliDapMediaType::AggregationJobResp => serde_json::to_string_pretty(
            &messages::AggregationJobResp::get_decoded_with_param(&action.version, &buf)?,
        ),
        CliDapMediaType::AggregateShare => serde_json::to_string_pretty(
            &messages::AggregateShare::get_decoded_with_param(&action.version, &buf)?,
        ),
        CliDapMediaType::Collection {
            vdaf_config,
            task_id,
            hpke_config_path,
        } => {
            let message = messages::Collection::get_decoded_with_param(&action.version, &buf)
                .context("decoding collection payload")?;
            let agg_shares = match (vdaf_config, task_id, hpke_config_path) {
                (Some(vdaf_config), Some(task_id), Some(hpke_config_path)) => {
                    let hpke_config: HpkeReceiverConfig = serde_json::from_reader(
                        std::fs::File::open(&hpke_config_path)
                            .with_context(|| format!("opening {}", hpke_config_path.display()))?,
                    )
                    .with_context(|| {
                        format!("deserializing the config at {}", hpke_config_path.display())
                    })?;
                    let batch_selector = match message.part_batch_sel {
                        messages::PartialBatchSelector::TimeInterval => todo!(),
                        messages::PartialBatchSelector::FixedSizeByBatchId { batch_id } => {
                            BatchSelector::FixedSizeByBatchId { batch_id }
                        }
                    };
                    let agg_shares = vdaf_config
                        .into_vdaf()
                        .consume_encrypted_agg_shares(
                            &hpke_config,
                            &task_id.into(),
                            &batch_selector,
                            message.report_count,
                            &DapAggregationParam::Empty,
                            message.encrypted_agg_shares.to_vec(),
                            action.version,
                        )?;
                    Some(agg_shares)
                }
                (None, None, None) => None,
                _ => bail!("to decrypt the collection job please provide the vdaf, task_id and hpke receiver config path"),
            };

            serde_json::to_string_pretty(&serde_json::json!({
                "original": &message,
                "decrypted": &agg_shares,
            }))
        }
        CliDapMediaType::HpkeConfigList => serde_json::to_string_pretty(
            &messages::HpkeConfigList::get_decoded_with_param(&action.version, &buf)?,
        ),
    };
    println!("{}", s.unwrap());
    Ok(())
}

async fn handle_test_routes(action: TestAction, http_client: HttpClient) -> anyhow::Result<()> {
    match action {
        TestAction::AddHpkeConfig {
            aggregator_url,
            kem_alg,
        } => dapf::test_routes::add_hpke_config(&http_client, &aggregator_url, kem_alg.0).await,
        TestAction::ClearStorage {
            aggregator_url,
            set_hpke_key,
        } => {
            dapf::test_routes::delete_all_storage(
                &http_client,
                &aggregator_url,
                set_hpke_key.map(|k| k.0),
            )
            .await
        }
        TestAction::CreateAddTaskJson {
            task_id,
            leader_url,
            helper_url,
            vdaf,
            leader_auth_token,
            collector_auth_token,
            role,
            query,
            min_batch_size,
            collector_hpke_config,
            time_precision,
            expires_in_seconds: task_expiration,
        } => {
            let (vdaf_verify_key, vdaf) =
                use_or_request_from_user_or_default(vdaf, CliVdafConfig::default, "vdaf").map(
                    |vdaf| {
                        let vdaf = vdaf.into_vdaf();
                        let vdaf_verify_key = vdaf.gen_verify_key();
                        let (typ, bits, length, chunk_length) = match vdaf {
                            VdafConfig::Prio3(prio3) => match prio3 {
                                Prio3Config::Count => ("Prio3Count", None, None, None),
                                Prio3Config::Sum { bits } => ("Prio3Sum", Some(bits), None, None),
                                Prio3Config::Histogram {
                                    length,
                                    chunk_length,
                                } => ("Prio3Histogram", None, Some(length), Some(chunk_length)),
                                Prio3Config::SumVec {
                                    bits,
                                    length,
                                    chunk_length,
                                } => ("Prio3SumVec", Some(bits), Some(length), Some(chunk_length)),
                                Prio3Config::SumVecField64MultiproofHmacSha256Aes128 {
                                    bits,
                                    length,
                                    chunk_length,
                                    num_proofs: _,
                                } => (
                                    "Prio3SumVecField64MultiproofHmacSha256Aes128",
                                    Some(bits),
                                    Some(length),
                                    Some(chunk_length),
                                ),
                            },
                            VdafConfig::Prio2 { .. } => ("Prio2", None, None, None),
                            VdafConfig::Pine(_) => ("Pine", None, None, None),
                            #[cfg(feature = "experimental")]
                            VdafConfig::Mastic { .. } => todo!(),
                        };
                        (
                            encode_base64url(vdaf_verify_key),
                            InternalTestVdaf {
                                typ: typ.into(),
                                bits: bits.map(|a| a.to_string()),
                                length: length.map(|a| a.to_string()),
                                chunk_length: chunk_length.map(|a| a.to_string()),
                            },
                        )
                    },
                )?;
            let CliDapQueryConfig(query) = use_or_request_from_user_or_default(
                query,
                || DapQueryConfig::FixedSize {
                    max_batch_size: None,
                },
                "query",
            )?;
            let role = use_or_request_from_user(role, "role")?;
            let internal_task = InternalTestAddTask {
                task_id: use_or_request_from_user_or_default(
                    task_id,
                    {
                        let t = TaskId(thread_rng().gen());
                        move || t
                    },
                    "task id",
                )?
                .into(),
                leader: use_or_request_from_user(leader_url, "leader url")?,
                helper: use_or_request_from_user(helper_url, "helper url")?,
                vdaf,
                leader_authentication_token: use_or_request_from_user(
                    leader_auth_token,
                    "leader auth token",
                )?,
                collector_authentication_token: match role {
                    DapRole::Leader => Some(use_or_request_from_user(
                        collector_auth_token,
                        "collector auth token",
                    )?),
                    DapRole::Helper => None,
                },
                role,
                vdaf_verify_key,
                query_type: match query {
                    DapQueryConfig::TimeInterval => 1,
                    DapQueryConfig::FixedSize { .. } => 2,
                },
                min_batch_size: use_or_request_from_user_or_default(
                    min_batch_size,
                    || 10u64,
                    "min batch size",
                )?,
                max_batch_size: match query {
                    DapQueryConfig::TimeInterval => None,
                    DapQueryConfig::FixedSize { max_batch_size } => max_batch_size,
                },
                time_precision: use_or_request_from_user_or_default(
                    time_precision,
                    || 3600u64,
                    "time precision",
                )?,
                collector_hpke_config: use_or_request_from_user(
                    collector_hpke_config,
                    "collector hpke config",
                )?,
                task_expiration: SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
                    + use_or_request_from_user_or_default(
                        task_expiration,
                        || 604_800u64,
                        "task should expire in",
                    )?,
            };

            if std::io::stdout().is_terminal() {
                println!("{}", serde_json::to_string_pretty(&internal_task).unwrap())
            } else {
                print!("{}", serde_json::to_string(&internal_task).unwrap())
            };

            Ok(())
        }
    }
}
