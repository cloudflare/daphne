// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use anyhow::{anyhow, bail, Context, Result};
use clap::{Args, Parser, Subcommand};
use dapf::{
    acceptance::{load_testing, LoadControlParams, LoadControlStride, TestOptions},
    cli_parsers::{
        self, use_or_request_from_user, use_or_request_from_user_or_default, CliCollectionJobId,
        CliDapBatchMode, CliHpkeKemId, CliTaskId, CliVdafConfig,
    },
    deduce_dap_version_from_url,
    functions::decrypt,
    HttpClient,
};
use daphne::{
    constants::DapAggregatorRole,
    hpke::HpkeReceiverConfig,
    messages::{
        self, encode_base64url, BatchSelector, CollectionReq, PartialBatchSelector, Query, TaskId,
    },
    DapBatchMode, DapMeasurement, DapVersion,
};
use daphne_service_utils::{
    bearer_token::BearerToken,
    test_route_types::{InternalTestAddTask, InternalTestVdaf},
};
use prio::codec::{ParameterizedDecode, ParameterizedEncode};
use rand::{thread_rng, Rng};
use serde::Serialize;
use std::{
    io::{IsTerminal, Read},
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
        vdaf: CliVdafConfig,

        /// Path to the certificate file to use to verify the signature of the hpke config
        #[arg(short, long, env)]
        certificate_file: Option<PathBuf>,

        /// DAP task ID (base64, URL-safe encoding)
        #[arg(short, long, env)]
        task_id: CliTaskId,

        #[arg(value_parser = cli_parsers::from_json_str::<DapMeasurement>)]
        measurement: DapMeasurement,
    },
    /// Collect an aggregate result from the DAP Leader using the JSON-formatted batch selector
    /// provided on stdin.
    Collect {
        /// Base URL of the Leader
        #[arg(long, env)]
        leader_url: Url,

        /// DAP task ID (base64, URL-safe encoding)
        #[arg(long, env)]
        task_id: CliTaskId,

        #[arg(long, env)]
        collector_auth_token: Option<BearerToken>,

        #[arg(env, value_parser = cli_parsers::from_json_str::<Query>)]
        query: Query,
    },
    /// Poll the given collect URI for the aggregate result.
    CollectPoll {
        /// The collect URI
        #[arg(long, env)]
        leader_url: Url,

        /// JSON-formatted VDAF config
        #[arg(long, env)]
        vdaf: Option<CliVdafConfig>,

        /// HPKE receiver configuration for decrypting response
        #[arg(long, env)]
        hpke_config_path: Option<PathBuf>,

        /// DAP task ID (base64, URL-safe encoding)
        #[arg(long, env)]
        task_id: CliTaskId,

        #[arg(long, env)]
        collect_job_id: CliCollectionJobId,

        #[arg(long, env)]
        collector_auth_token: Option<BearerToken>,

        /// batch selector.
        #[arg(long, env, value_parser = cli_parsers::from_json_str::<BatchSelector>)]
        batch_selector: Option<BatchSelector>,
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
        role: Option<DapAggregatorRole>,
        #[arg(long)]
        query: Option<CliDapBatchMode>,
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
        #[arg(long, env, value_parser = cli_parsers::from_json_str::<BatchSelector>)]
        batch_selector: Option<BatchSelector>,
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
            vdaf: vdaf_config,
            certificate_file,
            task_id,
            measurement,
        } => {
            let task_id = task_id.into();
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
                .into_vdaf_config()
                .produce_report(
                    &[leader_hpke_config, helper_hpke_config],
                    now,
                    &task_id,
                    measurement,
                    version,
                )
                .with_context(|| "failed to produce report")?;

            http_client
                .upload(&leader_url, &task_id, report, version)
                .await?;

            Ok(())
        }
        LeaderAction::Collect {
            leader_url,
            task_id,
            collector_auth_token,
            query,
        } => {
            let collect_job_id = http_client
                .start_collection_job(
                    &leader_url,
                    &task_id.into(),
                    &CollectionReq {
                        query,
                        agg_param: Vec::default(),
                    },
                    deduce_dap_version_from_url(&leader_url)?,
                    collector_auth_token.as_ref(),
                )
                .await?;
            if std::io::stdout().is_terminal() {
                println!("collection job started with job id: {collect_job_id}");
            } else {
                print!("{collect_job_id}");
            }
            Ok(())
        }
        LeaderAction::CollectPoll {
            leader_url,
            vdaf: vdaf_config,
            hpke_config_path,
            task_id,
            collect_job_id,
            collector_auth_token,
            batch_selector,
        } => {
            let version = deduce_dap_version_from_url(&leader_url)?;
            let collection = http_client
                .poll_collection_job(
                    &leader_url,
                    &task_id.into(),
                    &collect_job_id.into(),
                    version,
                    collector_auth_token.as_ref(),
                )
                .await?;
            let Some(collection) = collection else {
                bail!("collection job not finished");
            };
            match (hpke_config_path, vdaf_config, batch_selector) {
                (Some(hpke_config_path), Some(vdaf_config), Some(batch_selector)) => {
                    let agg_shares = decrypt::collection(
                        &task_id.into(),
                        &hpke_config_path,
                        &vdaf_config.into_vdaf_config(),
                        batch_selector,
                        version,
                        &collection,
                    )?;
                    print_json(&agg_shares);
                },
                (None, None, None) => {},
                _ => bail!("to decrypt the collection job please provide the vdaf, task_id and hpke receiver config path"),
            };

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
                vdaf_config.into_vdaf_config(),
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
                vdaf_config.into_vdaf_config(),
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
            print_json(&hpke_config.hpke_configs);

            Ok(())
        }
        HpkeAction::GetReceiverConfig {
            wrangler_config,
            wrangler_env,
            dap_version,
        } => {
            let config =
                get_receiver_config(&wrangler_config, wrangler_env.as_deref(), dap_version).await?;
            print_json(&config);
            Ok(())
        }
        HpkeAction::Generate { kem_alg } => {
            let receiver_config = HpkeReceiverConfig::gen(rng.gen(), kem_alg.0)
                .with_context(|| "failed to generate HPKE receiver config")?;
            print_json(&receiver_config);
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
    match action.media_type {
        CliDapMediaType::AggregationJobResp => print_json(
            &messages::AggregationJobResp::get_decoded_with_param(&action.version, &buf)?,
        ),
        CliDapMediaType::AggregateShare => print_json(
            &messages::AggregateShare::get_decoded_with_param(&action.version, &buf)?,
        ),
        CliDapMediaType::Collection {
            vdaf_config,
            task_id,
            hpke_config_path,
            batch_selector,
        } => {
            let message = messages::Collection::get_decoded_with_param(&action.version, &buf)
                .context("decoding collection payload")?;
            let agg_shares = match (vdaf_config, task_id, hpke_config_path, batch_selector) {
                (Some(vdaf_config), Some(task_id), Some(hpke_config_path), batch_selector) => {
                    let batch_selector = batch_selector.unwrap_or_else(||
                        match message.part_batch_sel {
                            PartialBatchSelector::TimeInterval => panic!("can't deduce the time interval, please provide a batch selector"),
                            PartialBatchSelector::LeaderSelectedByBatchId { batch_id } => {
                                BatchSelector::LeaderSelectedByBatchId { batch_id }
                            }
                        }
                    );
                    Some(decrypt::collection(
                        &task_id.into(),
                        &hpke_config_path ,
                        &vdaf_config.into_vdaf_config(),
                        batch_selector,
                        action.version,
                        &message,
                    )?)
                }
                (None, None, None, _) => None,
                _ => bail!("to decrypt the collection job please provide the vdaf, task_id and hpke receiver config path"),
            };

            print_json(&serde_json::json!({
                "original": &message,
                "decrypted": &agg_shares,
            }));
        }
        CliDapMediaType::HpkeConfigList => print_json(
            &messages::HpkeConfigList::get_decoded_with_param(&action.version, &buf)?,
        ),
    };
    Ok(())
}

async fn handle_test_routes(action: TestAction, http_client: HttpClient) -> anyhow::Result<()> {
    match action {
        TestAction::AddHpkeConfig {
            aggregator_url,
            kem_alg,
        } => {
            http_client
                .add_hpke_config(&aggregator_url, kem_alg.0)
                .await?;
            println!("config added");
            Ok(())
        }
        TestAction::ClearStorage {
            aggregator_url,
            set_hpke_key,
        } => {
            http_client.delete_all_storage(&aggregator_url).await?;
            if let Some(CliHpkeKemId(kem_alg)) = set_hpke_key {
                http_client
                    .add_hpke_config(&aggregator_url, kem_alg)
                    .await?;
            }
            Ok(())
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
            let vdaf = use_or_request_from_user_or_default(vdaf, CliVdafConfig::default, "vdaf")?
                .into_vdaf_config();
            let vdaf_verify_key = encode_base64url(vdaf.gen_verify_key());
            let CliDapBatchMode(query) = use_or_request_from_user_or_default(
                query,
                || DapBatchMode::LeaderSelected {
                    draft09_max_batch_size: None,
                },
                "query",
            )?;
            let role = use_or_request_from_user(role, "role")?;
            let default_task_id = TaskId(thread_rng().gen());
            let internal_task = InternalTestAddTask {
                task_id: use_or_request_from_user_or_default(
                    task_id,
                    || default_task_id,
                    "task id",
                )?
                .into(),
                leader: use_or_request_from_user(leader_url, "leader url")?,
                helper: use_or_request_from_user(helper_url, "helper url")?,
                vdaf: InternalTestVdaf::from(vdaf),
                leader_authentication_token: use_or_request_from_user(
                    leader_auth_token,
                    "leader auth token",
                )?,
                collector_authentication_token: match role {
                    DapAggregatorRole::Leader => Some(use_or_request_from_user(
                        collector_auth_token,
                        "collector auth token",
                    )?),
                    DapAggregatorRole::Helper => None,
                },
                role,
                vdaf_verify_key,
                batch_mode: match query {
                    DapBatchMode::TimeInterval => 1,
                    DapBatchMode::LeaderSelected { .. } => 2,
                },
                min_batch_size: use_or_request_from_user_or_default(
                    min_batch_size,
                    || 10u64,
                    "min batch size",
                )?,
                max_batch_size: match query {
                    DapBatchMode::TimeInterval => None,
                    DapBatchMode::LeaderSelected {
                        draft09_max_batch_size,
                    } => draft09_max_batch_size,
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

            print_json(&internal_task);

            Ok(())
        }
    }
}

fn print_json<T: Serialize>(t: &T) {
    if std::io::stdout().is_terminal() {
        println!("{}", serde_json::to_string_pretty(&t).unwrap())
    } else {
        print!("{}", serde_json::to_string(&t).unwrap())
    };
}
