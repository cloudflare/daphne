// Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Acceptance tests for live Daphne deployments. These tests assume the following
//! environment variables are defined:
//!
//! * `$VDAF_VERIFY_INIT`: The hex encoded VDAF verification key initializer, as specified in the
//!   Task prov extension.
//!
//! * either:
//!     - `$LEADER_BEARER_TOKEN`: The bearer token (a string)
//!     - `$LEADER_TLS_CLIENT_CERT` and `$LEADER_TLS_CLIENT_KEY`: The client certificate and client
//!     private key.
//!
//! Optionally the following variables can also be defined to override default values:
//! * `$VDAF_CONFIG`: A json serialized vdaf configuration to run.
//!

pub mod load_testing;
pub mod report_generator;

use crate::{test_durations::TestDurations, HttpClientExt};
use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use daphne::{
    auth::BearerToken,
    constants::DapMediaType,
    error::aborts::ProblemDetails,
    hpke::{HpkeConfig, HpkeKemId, HpkeReceiverConfig},
    messages::{
        AggregateShareReq, AggregationJobId, AggregationJobResp, Base64Encode, BatchId,
        BatchSelector, PartialBatchSelector, ReportId, TaskId,
    },
    metrics::{prometheus::DaphnePromMetrics, DaphneMetrics},
    roles::DapReportInitializer,
    vdaf::VdafConfig,
    DapAggregateShare, DapAggregateSpan, DapAggregationParam, DapBatchBucket, DapError,
    DapLeaderAggregationJobTransition, DapMeasurement, DapQueryConfig, DapTaskConfig,
    DapTaskParameters, DapVersion, EarlyReportStateConsumed, EarlyReportStateInitialized,
};
use futures::{StreamExt, TryStreamExt};
use prio::codec::{Decode, ParameterizedEncode};
use prometheus::{Encoder, Registry, TextEncoder};
use rand::{thread_rng, Rng};
use rayon::prelude::{IntoParallelIterator, ParallelIterator};
use reqwest::Client;
use std::{
    convert::TryFrom,
    env,
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime},
};
use tokio::sync::Barrier;
use tracing::{info, instrument};
use url::Url;

use self::report_generator::ReportGenerator;

pub struct Test {
    pub helper_url: Url,
    pub leader_bearer_token: Option<BearerToken>,
    vdaf_verify_init: [u8; 32],
    http_client: Client,
    prometheus_registry: Registry,
    daphne_metrics: DaphnePromMetrics,
    pub vdaf_config: VdafConfig,
    /// The path to the hpke signing certificate, which can be used to verify the hpke config
    /// signature.
    pub hpke_signing_certificate_path: Option<PathBuf>,
}

pub struct TestOptions {
    /// Bearer token to offer the Helper. If not provided, then only mutual TLS is used.
    pub bearer_token: Option<BearerToken>,

    /// The number of reports to aggregate.
    pub reports_per_batch: usize,

    /// The maximum number of reports per aggregation job. If this is less than
    /// `reports_per_batch`, then multiple aggregation jobs will be issued.
    pub reports_per_agg_job: usize,

    /// The synthetic measurement to generate. Each mock Client will upload this value. The
    /// measurement type must be compatible with `vdaf_config`.
    ///
    /// If the measurement is `None` a default one will be used.
    pub measurement: Option<DapMeasurement>,

    /// The helper's prefetched hpke config. If it's `None` a request to the helper shall be made
    /// to fetch it.
    pub helper_hpke_config: Option<HpkeConfig>,
}

impl Default for TestOptions {
    fn default() -> Self {
        Self {
            bearer_token: None,
            reports_per_batch: 50,
            reports_per_agg_job: 17,
            measurement: None,
            helper_hpke_config: None,
        }
    }
}

struct TestTaskConfig {
    pub task_id: TaskId,
    pub hpke_config_list: [HpkeConfig; 2],
    pub fake_leader_hpke_receiver_config: HpkeReceiverConfig,
    pub task_config: DapTaskConfig,
    pub taskprov_advertisement: Option<String>,
}

impl Test {
    pub fn new(
        http_client: reqwest::Client,
        helper_url: Url,
        leader_bearer_token: Option<String>,
        vdaf_verify_init: &str,
        vdaf_config: VdafConfig,
        hpke_signing_certificate_path: Option<PathBuf>,
    ) -> Result<Self> {
        let leader_bearer_token = leader_bearer_token.map(BearerToken::from);

        let vdaf_verify_init =
            <[u8; 32]>::try_from(hex::decode(vdaf_verify_init)?).map_err(|v| {
                anyhow!(
                    "incorrect length of vdaf verify init: got {}; want 32",
                    v.len()
                )
            })?;

        // Register Prometheus metrics.
        let prometheus_registry = prometheus::Registry::new();
        let daphne_metrics = DaphnePromMetrics::register(&prometheus_registry)
            .with_context(|| "failed to register Prometheus metrics")?;

        Ok(Self {
            helper_url,
            leader_bearer_token,
            vdaf_verify_init,
            http_client,
            prometheus_registry,
            daphne_metrics,
            vdaf_config,
            hpke_signing_certificate_path,
        })
    }

    pub fn from_env(
        helper_url: Url,
        vdaf_config: VdafConfig,
        hpke_signing_certificate_path: Option<PathBuf>,
    ) -> Result<Self> {
        const LEADER_BEARER_TOKEN_VAR: &str = "LEADER_BEARER_TOKEN";
        const LEADER_TLS_CLIENT_CERT_VAR: &str = "LEADER_TLS_CLIENT_CERT";
        const LEADER_TLS_CLIENT_KEY_VAR: &str = "LEADER_TLS_CLIENT_KEY";
        const VDAF_VERIFY_INIT_VAR: &str = "VDAF_VERIFY_INIT";

        let leader_bearer_token = env::var(LEADER_BEARER_TOKEN_VAR).ok();
        let leader_tls_client_cert = env::var(LEADER_TLS_CLIENT_CERT_VAR).ok();
        let leader_tls_client_key = env::var(LEADER_TLS_CLIENT_KEY_VAR).ok();
        if leader_bearer_token.is_none()
            && (leader_tls_client_cert.is_none() || leader_tls_client_key.is_none())
        {
            println!("leader client authorization not configured");
        }

        let vdaf_verify_init = env::var(VDAF_VERIFY_INIT_VAR)
            .with_context(|| format!("failed to load {VDAF_VERIFY_INIT_VAR}"))?;

        let leader_tls_identity = match (leader_tls_client_cert, leader_tls_client_key) {
            (Some(cert), Some(key)) => Some(
                reqwest::tls::Identity::from_pem((cert + "\n" + &key).as_bytes())
                    .with_context(|| "failed to parse Leader TLS client certificate")?,
            ),
            (None, None) => None,
            (Some(_), None) => bail!("{LEADER_TLS_CLIENT_KEY_VAR} is not set"),
            (None, Some(_)) => bail!("{LEADER_TLS_CLIENT_CERT_VAR} is not set"),
        };

        // Build the HTTP client.
        let mut http_client_builder = reqwest::Client::builder()
            // it takes too long to generate reports for larger dimensions, causing the worker
            // to drop idle connections
            .pool_max_idle_per_host(0)
            // Don't handle redirects automatically so that we can control the client behavior.
            .redirect(reqwest::redirect::Policy::none())
            // We might as well use rustls because we already need the feature for
            // `Identity::from_pem()`.
            .use_rustls_tls();
        if let Some(identity) = leader_tls_identity {
            // Configure TLS certificate, if available.
            http_client_builder = http_client_builder.identity(identity);
        }
        let http_client = http_client_builder
            .build()
            .with_context(|| "failed to build HTTP client")?;

        Test::new(
            http_client,
            helper_url,
            leader_bearer_token,
            &vdaf_verify_init,
            vdaf_config,
            hpke_signing_certificate_path,
        )
    }

    pub fn metrics(&self) -> &dyn DaphneMetrics {
        &self.daphne_metrics
    }

    pub fn encode_metrics(&self) -> String {
        let mut buf = Vec::new();
        let encoder = TextEncoder::new();
        encoder
            .encode(&self.prometheus_registry.gather(), &mut buf)
            .unwrap();
        String::from_utf8(buf).unwrap()
    }

    pub fn gen_measurement(&self) -> Result<DapMeasurement> {
        gen_measurement_for(&self.vdaf_config)
    }

    pub async fn get_hpke_config(
        &self,
        aggregator: &Url,
        hpke_signing_certificate_path: Option<&Path>,
    ) -> anyhow::Result<HpkeConfig> {
        Ok(self
            .http_client
            .get_hpke_config(aggregator, hpke_signing_certificate_path)
            .await?
            .hpke_configs
            .swap_remove(0))
    }

    async fn generate_task_config(
        &self,
        version: DapVersion,
        helper_hpke_config: Option<&HpkeConfig>,
        reports_per_batch: usize,
        now: Now,
    ) -> anyhow::Result<(TestTaskConfig, TestDurations)> {
        // We generate a fake Leader and Collector HPKE configs for testing purposes. In practice
        // the Collector HPKE config used by the Leader needs to match the one useed by the Helper.
        // The Helper's is configured by the DAP_TASKPROV_HPKE_COLLECTOR_CONFIG variable in the
        // wrangler.toml file.
        let fake_leader_hpke_receiver_config =
            HpkeReceiverConfig::gen(17, HpkeKemId::P256HkdfSha256)
                .with_context(|| "failed to generate Leader HPKE receiver config")?;
        let fake_collector_hpke_receiver_config =
            HpkeReceiverConfig::gen(23, HpkeKemId::P256HkdfSha256)
                .with_context(|| "failed to generate Leader HPKE receiver config")?;

        let (helper_hpke_config, hpke_config_fetch_time) = if let Some(c) = helper_hpke_config {
            info!("Using passed in hpke config");
            (c.clone(), Duration::ZERO)
        } else {
            let start = Instant::now();
            let helper_hpke_config = self
                .http_client
                .get_hpke_config(
                    &self.helper_url,
                    self.hpke_signing_certificate_path.as_deref(),
                )
                .await
                .context("failed to fetch Helper's HPKE confitg")?
                .hpke_configs
                .swap_remove(0);
            let duration = start.elapsed();
            info!("fetched HPKE config from Helper in {duration:#?}");

            (helper_hpke_config, duration)
        };

        let hpke_config_list = [
            fake_leader_hpke_receiver_config.config.clone(),
            helper_hpke_config,
        ];

        let (task_config, task_id, taskprov_advertisement) = DapTaskParameters {
            version,
            leader_url: Url::parse("https://exampe.com/").unwrap(),
            helper_url: self.helper_url.clone(),
            time_precision: 3600,
            lifetime: 60,
            min_batch_size: reports_per_batch.try_into().unwrap(),
            query: DapQueryConfig::FixedSize {
                max_batch_size: Some(reports_per_batch.try_into().unwrap()),
            },
            vdaf: self.vdaf_config,
        }
        .to_config_with_taskprov(
            b"cool task".to_vec(),
            now.0,
            &self.vdaf_verify_init,
            &fake_collector_hpke_receiver_config.config,
        )?;

        Ok((
            TestTaskConfig {
                task_id,
                hpke_config_list,
                fake_leader_hpke_receiver_config,
                task_config,
                taskprov_advertisement: Some(taskprov_advertisement),
            },
            TestDurations {
                hpke_config_fetch: hpke_config_fetch_time,
                ..Default::default()
            },
        ))
    }

    async fn run_agg_jobs<F>(
        &self,
        report_count: usize,
        test_task_config: &TestTaskConfig,
        part_batch_sel: &PartialBatchSelector,
        reports_per_agg_job: usize,
        bearer_token: Option<&BearerToken>,
        report_generator: F,
    ) -> anyhow::Result<(
        Vec<(DapBatchBucket, (DapAggregateShare, Vec<(ReportId, u64)>))>,
        TestDurations,
    )>
    where
        F: Fn(usize) -> ReportGenerator,
    {
        let job_count = report_count / reports_per_agg_job
            + usize::from(report_count % reports_per_agg_job != 0);
        let barrier = Barrier::new(job_count);
        let (count, out_shares_for_batch, agg_job_durations) = futures::stream::iter(
            distribute_reports_in_chunks(report_count, reports_per_agg_job),
        )
        .enumerate()
        .map(|(agg_job_index, reports_for_agg_job)| {
            self.run_agg_job(
                test_task_config,
                agg_job_index,
                report_generator(reports_for_agg_job),
                part_batch_sel,
                bearer_token,
                &barrier,
            )
        })
        .buffer_unordered((report_count / reports_per_agg_job) + 1)
        .try_fold(
            (0, Vec::new(), TestDurations::default()),
            |(count, mut out_shares, durations), (new_shares, new_durations)| async move {
                out_shares.extend(new_shares);
                Ok((count + 1, out_shares, durations + new_durations))
            },
        )
        .await?;
        Ok((out_shares_for_batch, agg_job_durations / count))
    }

    #[instrument(skip(
        self,
        test_task_config,
        // agg_job_index is kept
        reports_for_agg_job,
        part_batch_sel,
        bearer_token,
        barrier,
    ))]
    pub async fn run_agg_job(
        &self,
        test_task_config: &TestTaskConfig,
        agg_job_index: usize,
        reports_for_agg_job: ReportGenerator,
        part_batch_sel: &PartialBatchSelector,
        bearer_token: Option<&BearerToken>,
        barrier: &Barrier,
    ) -> anyhow::Result<(DapAggregateSpan<DapAggregateShare>, TestDurations)> {
        let report_count = reports_for_agg_job.len();
        info!(report_count, "Starting aggregation job");
        let TestTaskConfig {
            task_config,
            fake_leader_hpke_receiver_config,
            task_id,
            taskprov_advertisement,
            ..
        } = test_task_config;
        let mut durations = TestDurations::default();
        let mut rng = thread_rng();

        // Prepare AggregationJobInitReq.
        let agg_job_id = AggregationJobId(rng.gen());
        let transition = task_config
            .produce_agg_job_init_req(
                fake_leader_hpke_receiver_config,
                self,
                task_id,
                part_batch_sel,
                &DapAggregationParam::Empty,
                reports_for_agg_job,
                self.metrics(),
            )
            .await
            .context("producing agg job init request")?;

        let (state, agg_init_req) = match transition {
            DapLeaderAggregationJobTransition::Continued(state, agg_init_req) => {
                (state, agg_init_req)
            }

            DapLeaderAggregationJobTransition::Finished(..) => {
                return Err(anyhow!("unexpected state transition (finished)"));
            }
        };

        // Send AggregationJobInitReq.
        let headers = construct_request_headers(
            DapMediaType::AggregationJobInitReq.as_str_for_version(task_config.version),
            taskprov_advertisement.as_deref(),
            bearer_token,
        )
        .context("constructing request headers for AggregationJobInitReq")?;
        let url = self.helper_url.join(&format!(
            "tasks/{}/aggregation_jobs/{}",
            task_id.to_base64url(),
            agg_job_id.to_base64url()
        ))?;

        // wait for all agg jobs to be ready to fire.
        barrier.wait().await;
        info!("Starting AggregationJobInitReq");
        let start = Instant::now();
        let resp = send(
            self.http_client
                .post(url)
                .body(
                    agg_init_req
                        .get_encoded_with_param(&task_config.version)
                        .unwrap(),
                )
                .headers(headers),
        )
        .await?;
        {
            let duration = start.elapsed();
            info!("Finished AggregationJobInitReq in {duration:#?}");
            durations.aggregate_init_req = duration;
        }
        if resp.status() == 400 {
            let text = resp.text().await?;
            let problem_details: ProblemDetails =
                serde_json::from_str(&text).with_context(|| {
                    format!("400 Bad Request: failed to parse problem details document: {text:?}")
                })?;
            return Err(anyhow!("400 Bad Request: {problem_details:?}"));
        } else if resp.status() == 500 {
            return Err(anyhow::anyhow!(
                "500 Internal Server Error: {}",
                resp.text().await?
            ));
        } else if !resp.status().is_success() {
            return Err(anyhow!(
                "unexpected response while running an AggregateInitReq: {resp:?}"
            ));
        }

        // Handle AggregationJobResp..
        let agg_resp = AggregationJobResp::get_decoded(
            &resp
                .bytes()
                .await
                .context("transfering bytes from the AggregateInitReq")?,
        )
        .with_context(|| "failed to parse response to AggregateInitReq from Helper")?;
        let transition =
            task_config.handle_agg_job_resp(task_id, state, agg_resp, self.metrics())?;

        let DapLeaderAggregationJobTransition::Finished(agg_share_span) = transition else {
            bail!("unexpected transition");
        };

        let aggregated_report_count = agg_share_span
            .iter()
            .map(|(_bucket, (_agg_share, report_ids))| report_ids.len())
            .sum::<usize>();

        if aggregated_report_count < report_count {
            bail!("aggregated report count ({aggregated_report_count}) < expected count ({report_count})");
        }

        Ok((agg_share_span, durations))
    }

    /// Mock the Leader aggregating and collecting a batch.
    //
    // TODO(cpatton) See if we can de-duplicate this code and the `DapLeader::run_agg_job()`
    // method, since they overlap significantly. We could use `MockAggregator`, but it doesn't
    // support HTTP right now. (HTTP is mocked by the testing framework.)
    pub async fn test_helper(
        &self,
        opt: &TestOptions,
        version: DapVersion,
    ) -> Result<TestDurations> {
        let mut rng = thread_rng();
        let now = now();

        let (test_task_config, mut durations) = self
            .generate_task_config(version, None, opt.reports_per_batch, now)
            .await?;

        let TestTaskConfig {
            task_id,
            taskprov_advertisement,
            ..
        } = &test_task_config;

        info!("task id: {}", task_id.to_hex());

        // Generate enough reports to complete a batch.
        let measurement = match &opt.measurement {
            Some(m) => std::borrow::Cow::Borrowed(m),
            None => std::borrow::Cow::Owned(self.gen_measurement().unwrap()),
        };

        ////

        let batch_id = BatchId(rng.gen());
        let part_batch_sel = PartialBatchSelector::FixedSizeByBatchId { batch_id };

        let (out_shares_for_batch, agg_job_duration) = self
            .run_agg_jobs(
                opt.reports_per_batch,
                &test_task_config,
                &part_batch_sel,
                opt.reports_per_agg_job,
                opt.bearer_token.as_ref(),
                |reports_per_agg_job| {
                    ReportGenerator::new(
                        &test_task_config,
                        reports_per_agg_job,
                        measurement.as_ref(),
                        version,
                        now,
                    )
                },
            )
            .await?;

        durations = durations + agg_job_duration;

        // Prepare AggregateShareReq.
        let leader_agg_share = out_shares_for_batch
            .into_iter()
            .map(|(_, share)| share.0)
            .reduce(|mut acc, other| {
                acc.merge(other).unwrap();
                acc
            })
            .unwrap();
        let agg_share_req = AggregateShareReq {
            batch_sel: BatchSelector::FixedSizeByBatchId { batch_id },
            agg_param: Vec::new(),
            report_count: leader_agg_share.report_count,
            checksum: leader_agg_share.checksum,
        };

        // Send AggregateShareReq.
        let start = Instant::now();
        let headers = construct_request_headers(
            DapMediaType::AggregateShareReq.as_str_for_version(version),
            taskprov_advertisement.as_deref(),
            opt.bearer_token.as_ref(),
        )?;
        let url = self.helper_url.join(&format!(
            "tasks/{}/aggregate_shares",
            task_id.to_base64url()
        ))?;
        let resp = send(
            self.http_client
                .post(url)
                .body(agg_share_req.get_encoded_with_param(&version).unwrap())
                .headers(headers),
        )
        .await?;
        {
            let duration = start.elapsed();
            info!("Finished AggregateShareReq in {duration:#?}");
            durations.aggregate_share_req = duration;
        }
        if resp.status() == 400 {
            let problem_details: ProblemDetails = serde_json::from_slice(
                &resp
                    .bytes()
                    .await
                    .context("transfering bytes for AggregateShareReq")?,
            )
            .with_context(|| "400 Bad Request: failed to parse problem details document")?;
            return Err(anyhow!("400 Bad Request: {problem_details:?}"));
        } else if resp.status() == 500 {
            return Err(anyhow::anyhow!(
                "500 Internal Server Error: {}",
                resp.text().await?
            ));
        } else if !resp.status().is_success() {
            return Err(anyhow!(
                "unexpected response while running an AggregateInitReq: {resp:?}"
            ));
        }
        {
            let duration = start.elapsed();
            info!("Finished AggregateInitReq in {duration:#?}");
            durations.aggregate_init_req = duration;
        }
        Ok(durations)
    }
}

#[async_trait]
impl DapReportInitializer for Test {
    async fn initialize_reports(
        &self,
        is_leader: bool,
        task_config: &DapTaskConfig,
        agg_param: &DapAggregationParam,
        consumed_reports: Vec<EarlyReportStateConsumed>,
    ) -> Result<Vec<EarlyReportStateInitialized>, DapError> {
        tokio::task::spawn_blocking({
            let vdaf_verify_key = task_config.vdaf_verify_key.clone();
            let vdaf = task_config.vdaf;
            let agg_param = agg_param.clone();
            move || {
                consumed_reports
                    .into_par_iter()
                    .map(|consumed| {
                        EarlyReportStateInitialized::initialize(
                            is_leader,
                            &vdaf_verify_key,
                            &vdaf,
                            &agg_param,
                            consumed,
                        )
                    })
                    .collect::<Result<Vec<_>, _>>()
            }
        })
        .await
        .unwrap()
    }
}

fn construct_request_headers<'a, M, T, B>(
    media_type: M,
    taskprov: T,
    bearer_token: B,
) -> Result<reqwest::header::HeaderMap>
where
    M: Into<Option<&'a str>>,
    T: Into<Option<&'a str>>,
    B: Into<Option<&'a BearerToken>>,
{
    let mut headers = reqwest::header::HeaderMap::new();
    if let Some(media_type) = media_type.into() {
        headers.insert(
            reqwest::header::CONTENT_TYPE,
            reqwest::header::HeaderValue::from_str(media_type)?,
        );
    }
    if let Some(taskprov) = taskprov.into() {
        headers.insert(
            reqwest::header::HeaderName::from_static("dap-taskprov"),
            reqwest::header::HeaderValue::from_str(taskprov)?,
        );
    }
    if let Some(token) = bearer_token.into() {
        headers.insert(
            reqwest::header::HeaderName::from_static("dap-auth-token"),
            reqwest::header::HeaderValue::from_str(token.as_ref())?,
        );
    }
    Ok(headers)
}

async fn send(req: reqwest::RequestBuilder) -> reqwest::Result<reqwest::Response> {
    for i in 0..4 {
        let resp = req.try_clone().unwrap().send().await;
        match &resp {
            Ok(r) if r.status() != reqwest::StatusCode::BAD_GATEWAY => {
                return resp;
            }
            Ok(r) if r.status().is_client_error() => {
                return resp;
            }
            Ok(_) => {}
            Err(e) => {
                tracing::error!("request failed: {e:?}");
            }
        }
        if i == 3 {
            return resp;
        }
    }
    unreachable!()
}

pub fn gen_measurement_for(vdaf_config: &VdafConfig) -> Result<DapMeasurement> {
    match vdaf_config {
        VdafConfig::Prio2 { dimension } => Ok(DapMeasurement::U32Vec(vec![1; *dimension])),
        VdafConfig::Prio3(daphne::vdaf::Prio3Config::SumVecField64MultiproofHmacSha256Aes128 {
            length,
            ..
        }) => Ok(DapMeasurement::U64Vec(vec![0; *length])),
        _ => Err(anyhow!(
            "VDAF config {vdaf_config:?} not currently supported"
        )),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Now(u64);
pub fn now() -> Now {
    Now(SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs())
}

/// An iterator that yields the size of chunks based on a length and a maximum chunk size.
///
/// # Example
/// ```ignore
/// assert_eq!(
///     distribute_reports_in_chunks(200, 51).collect::<Vec<_>>(),
///     [51, 51, 51, 47]
/// );
/// ```
fn distribute_reports_in_chunks(total: usize, chunk_length: usize) -> impl Iterator<Item = usize> {
    assert!(total >= chunk_length);
    (0..(total / chunk_length))
        .map(move |_| chunk_length)
        .chain(Some(total % chunk_length).filter(|t| *t > 0))
}

#[cfg(test)]
mod tests {
    #[test]
    fn distribute_reports_in_chunks() {
        for total in 0..400 {
            for len in 1..total {
                let expected = (0..total)
                    .collect::<Vec<_>>()
                    .chunks(len)
                    .map(|c| c.len())
                    .collect::<Vec<_>>();

                let iter = super::distribute_reports_in_chunks(total, len);

                let (len, _) = iter.size_hint();
                let collected = iter.collect::<Vec<_>>();
                assert_eq!(
                    collected, expected,
                    "collected values don't match expected values"
                );
                assert_eq!(
                    collected.len(),
                    len,
                    "collected len don't match expected len"
                );
                assert_eq!(
                    collected.into_iter().sum::<usize>(),
                    expected.into_iter().sum::<usize>(),
                    "collected sum doesn't match expected sum"
                );
            }
        }
    }
}
