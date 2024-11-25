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
//!        private key.
//!
//! Optionally the following variables can also be defined to override default values:
//! * `$VDAF_CONFIG`: A json serialized vdaf configuration to run.
//!

pub mod load_testing;

use crate::{deduce_dap_version_from_url, functions, test_durations::TestDurations, HttpClient};
use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use daphne::{
    hpke::{HpkeConfig, HpkeKemId, HpkeReceiverConfig},
    messages::{
        self, taskprov::TaskprovAdvertisement, AggregateShareReq, AggregationJobId, Base64Encode,
        BatchId, BatchSelector, PartialBatchSelector, TaskId,
    },
    metrics::DaphneMetrics,
    roles::DapReportInitializer,
    testing::report_generator::ReportGenerator,
    vdaf::VdafConfig,
    DapAggregateShare, DapAggregateSpan, DapAggregationParam, DapMeasurement, DapQueryConfig,
    DapTaskConfig, DapTaskParameters, DapVersion, ReplayProtection,
};
use daphne_service_utils::bearer_token::BearerToken;
use futures::{future::OptionFuture, StreamExt, TryStreamExt};
use prometheus::{Encoder, HistogramVec, IntCounterVec, IntGaugeVec, TextEncoder};
use rand::{rngs, Rng};
use std::{
    convert::TryFrom,
    env,
    ops::Range,
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
    time::{Duration, Instant, SystemTime},
};
use tokio::sync::{Barrier, Semaphore};
use tracing::{info, instrument};
use url::Url;

/// Stride controls the rate at which requests are made during an aggregation job.
///
/// For example, for `len` = 10 and `wait_time` = 1s, every one second 10 requests will be made
/// simultaneously.
#[derive(Clone, Copy, Debug)]
pub struct LoadControlStride {
    pub len: usize,
    pub wait_time: Duration,
}

#[derive(Clone, Copy, Debug)]
pub struct LoadControlParams {
    max_concurrent_requests: Option<usize>,
    min_requests_before_starting: usize,
    stride: Option<LoadControlStride>,
}

impl LoadControlParams {
    pub fn new<M, B>(
        max_concurrent_requests: M,
        min_requests_before_starting: usize,
        stride: B,
    ) -> Self
    where
        M: Into<Option<usize>>,
        B: Into<Option<LoadControlStride>>,
    {
        Self {
            max_concurrent_requests: max_concurrent_requests.into(),
            min_requests_before_starting,
            stride: stride.into(),
        }
    }

    pub fn max_requests_before_starting(
        reports_per_batch: usize,
        reports_per_agg_job: usize,
    ) -> usize {
        // total reports / job + (0 if reports divide by reports_per_agg_job else 1)
        reports_per_batch / reports_per_agg_job
            + usize::from(reports_per_batch % reports_per_agg_job != 0)
    }
}

struct LoadControl {
    max_concurrent_requests: Option<Semaphore>,
    min_requests_before_starting: Barrier,
    stride: Option<LoadControlStride>,
    current_batch_len: AtomicUsize,
}

impl From<LoadControlParams> for LoadControl {
    fn from(params: LoadControlParams) -> Self {
        Self {
            max_concurrent_requests: params.max_concurrent_requests.map(Semaphore::new),
            min_requests_before_starting: Barrier::new(params.min_requests_before_starting),
            stride: params.stride,
            current_batch_len: AtomicUsize::default(),
        }
    }
}

impl LoadControl {
    #[must_use]
    pub async fn wait(&self) -> Option<tokio::sync::SemaphorePermit> {
        let id = self.current_batch_len.fetch_add(1, Ordering::SeqCst);
        self.min_requests_before_starting.wait().await;
        if let Some(LoadControlStride { len, wait_time }) = self.stride {
            let batch_number = u32::try_from(id.checked_div(len).unwrap()).unwrap();
            tokio::time::sleep(wait_time * batch_number).await;
        }
        OptionFuture::from(
            self.max_concurrent_requests
                .as_ref()
                .map(|s| async { s.acquire().await.unwrap() }),
        )
        .await
    }
}

struct TestMetrics {
    test_success: IntGaugeVec,
    test_durations: HistogramVec,
    report_counter: IntCounterVec,
}

// we only implement the metrics we actually want from acceptante tests
impl DaphneMetrics for TestMetrics {
    fn report_inc_by(&self, status: daphne::metrics::ReportStatus, val: u64) {
        self.report_counter
            .with_label_values(&[&status.to_string()])
            .inc_by(val);
    }
    fn inbound_req_inc(&self, _: daphne::metrics::DaphneRequestType) {}
    fn agg_job_observe_batch_size(&self, _: usize) {}
    fn agg_job_started_inc(&self) {}
    fn agg_job_completed_inc(&self) {}
    fn agg_job_put_span_retry_inc(&self) {}
}

pub struct Test {
    pub helper_url: Url,
    bearer_token: Option<BearerToken>,
    vdaf_verify_init: [u8; 32],
    http_client: HttpClient,
    metrics: TestMetrics,
    vdaf_config: VdafConfig,
    /// The path to the hpke signing certificate, which can be used to verify the hpke config
    /// signature.
    hpke_signing_certificate_path: Option<PathBuf>,
    load_control: LoadControlParams,
    /// Replay reports when generating the test aggregation. This improves test speed but requires
    /// the test target to have replay protection disabled.
    replay_reports: bool,
}

pub struct TestOptions {
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
    pub taskprov_advertisement: Option<TaskprovAdvertisement>,
}

impl Test {
    pub fn new(
        http_client: HttpClient,
        helper_url: Url,
        vdaf_verify_init: &str,
        vdaf_config: VdafConfig,
        load_control: LoadControlParams,
        replay_reports: bool,
    ) -> Result<Self> {
        let vdaf_verify_init = <[u8; 32]>::try_from(
            hex::decode(vdaf_verify_init)
                .context("vdaf_verify_init is not encoded in valid hex")?,
        )
        .map_err(|v| {
            anyhow!(
                "incorrect length of vdaf verify init: got {}; want 32",
                v.len()
            )
        })?;

        // Register Prometheus metrics.

        let metrics = TestMetrics {
            test_success: prometheus::register_int_gauge_vec!(
                "daphne_server_acceptance_test",
                "Counts the number of times tests ran",
                &["using_mtls", "using_bearer_token"],
            )?,
            test_durations: prometheus::register_histogram_vec!(
                "daphne_server_acceptance_test_durations",
                "The time tests take in milliseconds",
                &["section"],
                prometheus::exponential_buckets(100., 2., 12).unwrap(),
            )?,
            report_counter: prometheus::register_int_counter_vec!(
                "daphne_server_acceptance_report_counter",
                "Total number reports rejected, aggregated, and collected.",
                &["status"],
            )?,
        };

        Ok(Self {
            helper_url,
            bearer_token: None,
            vdaf_verify_init,
            http_client,
            metrics,
            vdaf_config,
            hpke_signing_certificate_path: None,
            load_control,
            replay_reports,
        })
    }

    pub fn from_env(
        helper_url: Url,
        vdaf_config: VdafConfig,
        hpke_signing_certificate_path: Option<PathBuf>,
        http_client: HttpClient,
        load_control: LoadControlParams,
    ) -> Result<Self> {
        const LEADER_BEARER_TOKEN_VAR: &str = "LEADER_BEARER_TOKEN";
        const VDAF_VERIFY_INIT_VAR: &str = "VDAF_VERIFY_INIT";
        let replay_reports = std::env::var("REPLAY_REPORTS").unwrap_or_default() == "1";

        let leader_bearer_token = env::var(LEADER_BEARER_TOKEN_VAR).ok();

        let vdaf_verify_init = env::var(VDAF_VERIFY_INIT_VAR)
            .with_context(|| format!("failed to load {VDAF_VERIFY_INIT_VAR}"))?;

        let mut test = Test::new(
            http_client,
            helper_url,
            &vdaf_verify_init,
            vdaf_config,
            load_control,
            replay_reports,
        )?;
        if let Some(token) = leader_bearer_token {
            test = test.with_bearer_token(token);
        }
        if let Some(path) = hpke_signing_certificate_path {
            test = test.with_hpke_signing_certificate_path(path);
        }
        Ok(test)
    }

    pub fn with_bearer_token(self, bearer_token: String) -> Self {
        Self {
            bearer_token: Some(BearerToken::from(bearer_token)),
            ..self
        }
    }

    pub fn with_hpke_signing_certificate_path<P: Into<PathBuf>>(self, path: P) -> Self {
        Self {
            hpke_signing_certificate_path: Some(path.into()),
            ..self
        }
    }

    pub fn metrics(&self) -> &dyn DaphneMetrics {
        &self.metrics
    }

    pub fn encode_metrics(&self) -> String {
        let mut buf = Vec::new();
        let encoder = TextEncoder::new();
        encoder.encode(&prometheus::gather(), &mut buf).unwrap();
        String::from_utf8(buf).unwrap()
    }

    pub fn gen_measurement(&self) -> Result<DapMeasurement> {
        self.vdaf_config
            .gen_measurement()
            .context("failed to generate a measurement")
    }

    pub async fn get_hpke_config(&self, aggregator: &Url) -> anyhow::Result<HpkeConfig> {
        Ok(self
            .http_client
            .get_hpke_config(aggregator, self.hpke_signing_certificate_path.as_deref())
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
    ) -> anyhow::Result<(TestTaskConfig, Duration)> {
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
            ..Default::default()
        }
        .to_config_with_taskprov(
            b"cool task".to_vec(),
            now.0,
            daphne::roles::aggregator::TaskprovConfig {
                hpke_collector_config: &fake_collector_hpke_receiver_config.config,
                vdaf_verify_key_init: &self.vdaf_verify_init,
            },
        )?;

        Ok((
            TestTaskConfig {
                task_id,
                hpke_config_list,
                fake_leader_hpke_receiver_config,
                task_config,
                taskprov_advertisement: Some(taskprov_advertisement),
            },
            hpke_config_fetch_time,
        ))
    }

    async fn run_agg_jobs<F>(
        &self,
        report_count: usize,
        test_task_config: &TestTaskConfig,
        part_batch_sel: &PartialBatchSelector,
        reports_per_agg_job: usize,
        report_generator: F,
    ) -> anyhow::Result<(DapAggregateShare, Duration)>
    where
        F: Fn(usize) -> ReportGenerator,
    {
        let load_control = LoadControl::from(self.load_control);
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
                &load_control,
            )
        })
        .buffer_unordered((report_count / reports_per_agg_job) + 1)
        .try_fold(
            (0, Vec::new(), Duration::ZERO),
            |(count, mut out_shares, durations), (new_shares, new_durations)| async move {
                out_shares.extend(new_shares);
                Ok((count + 1, out_shares, durations + new_durations))
            },
        )
        .await?;
        Ok((
            out_shares_for_batch
                .into_iter()
                .map(|(_, share)| share.0)
                .reduce(|mut acc, other| {
                    acc.merge(other).unwrap();
                    acc
                })
                .unwrap(),
            agg_job_durations / count,
        ))
    }

    #[instrument(skip(
        self,
        test_task_config,
        // agg_job_index is kept
        reports_for_agg_job,
        part_batch_sel,
        load_control,
    ))]
    pub async fn run_agg_job(
        &self,
        test_task_config: &TestTaskConfig,
        agg_job_index: usize,
        reports_for_agg_job: ReportGenerator,
        part_batch_sel: &PartialBatchSelector,
        load_control: &LoadControl,
    ) -> anyhow::Result<(DapAggregateSpan<DapAggregateShare>, Duration)> {
        let report_count = reports_for_agg_job.len();
        info!(report_count, "Starting aggregation job");
        let TestTaskConfig {
            task_config,
            fake_leader_hpke_receiver_config,
            task_id,
            taskprov_advertisement,
            ..
        } = test_task_config;

        // Prepare AggregationJobInitReq.
        let agg_job_id = AggregationJobId(rngs::OsRng.gen());
        let report_count = reports_for_agg_job.len();
        let (agg_job_state, agg_job_init_req) = task_config
            .test_produce_agg_job_req(
                fake_leader_hpke_receiver_config,
                self,
                task_id,
                part_batch_sel,
                &DapAggregationParam::Empty,
                reports_for_agg_job,
                self.metrics(),
                if self.replay_reports {
                    ReplayProtection::InsecureDisabled
                } else {
                    ReplayProtection::Enabled
                },
            )
            .context("producing agg job init request")?;

        // Send AggregationJobInitReq.
        // wait for all agg jobs to be ready to fire.
        info!("Reports generated, waiting for other tasks...");
        let _guard = load_control.wait().await;
        info!("Starting AggregationJobInitReq");
        let start = Instant::now();
        let agg_job_resp = self
            .http_client
            .submit_aggregation_job_init_req(
                self.helper_url.join(&format!(
                    "tasks/{}/aggregation_jobs/{}",
                    task_id.to_base64url(),
                    agg_job_id.to_base64url()
                ))?,
                agg_job_init_req,
                task_config.version,
                functions::helper::Options {
                    taskprov_advertisement: taskprov_advertisement.as_ref(),
                    bearer_token: self.bearer_token.as_ref(),
                },
            )
            .await?;
        let duration = start.elapsed();
        info!("Finished AggregationJobInitReq in {duration:#?}");

        let agg_share_span = task_config.consume_agg_job_resp(
            task_id,
            agg_job_state,
            agg_job_resp,
            self.metrics(),
        )?;

        let aggregated_report_count = agg_share_span
            .iter()
            .map(|(_bucket, (_agg_share, report_ids))| report_ids.len())
            .sum::<usize>();

        if aggregated_report_count < report_count {
            bail!("aggregated report count ({aggregated_report_count}) < expected count ({report_count})");
        }

        Ok((agg_share_span, duration))
    }

    pub async fn get_aggregate_share(
        &self,
        leader_agg_share: DapAggregateShare,
        batch_id: BatchId,
        version: DapVersion,
        taskprov_advertisement: Option<&TaskprovAdvertisement>,
        task_id: TaskId,
    ) -> Result<Duration> {
        // Prepare AggregateShareReq.
        let agg_share_req = AggregateShareReq {
            batch_sel: BatchSelector::FixedSizeByBatchId { batch_id },
            agg_param: Vec::new(),
            report_count: leader_agg_share.report_count,
            checksum: leader_agg_share.checksum,
        };

        // Send AggregateShareReq.
        info!("Starting AggregationJobInitReq");
        let start = Instant::now();
        self.http_client
            .get_aggregate_share(
                self.helper_url.join(&format!(
                    "tasks/{}/aggregate_shares",
                    task_id.to_base64url()
                ))?,
                agg_share_req,
                version,
                functions::helper::Options {
                    taskprov_advertisement,
                    bearer_token: self.bearer_token.as_ref(),
                },
            )
            .await?;
        Ok(start.elapsed())
    }

    pub async fn test_helper(&self, opt: &TestOptions) -> Result<TestDurations> {
        let res = self.test_helper_impl(opt).await;
        self.set_sucess_metric_to(res.is_ok());

        if let Ok(TestDurations {
            hpke_config_fetch,
            aggregate_init_req,
            aggregate_share_req,
        }) = &res
        {
            for (name, value) in [
                ("hpke_config_fetch", hpke_config_fetch),
                ("aggregate_init_req", aggregate_init_req),
                ("aggregate_share_req", aggregate_share_req),
            ] {
                self.metrics
                    .test_durations
                    .with_label_values(&[name])
                    .observe(value.as_millis() as f64);
            }
        }
        res
    }

    /// Mock the Leader aggregating and collecting a batch.
    //
    // TODO(cpatton) See if we can de-duplicate this code and the `DapLeader::run_agg_job()`
    // method, since they overlap significantly. We could use `MockAggregator`, but it doesn't
    // support HTTP right now. (HTTP is mocked by the testing framework.)
    async fn test_helper_impl(&self, opt: &TestOptions) -> Result<TestDurations> {
        let version = deduce_dap_version_from_url(&self.helper_url)?;
        let now = now();

        let mut durations = TestDurations::default();
        let (test_task_config, hpke_config_fetch_time) = self
            .generate_task_config(version, None, opt.reports_per_batch, now)
            .await?;
        durations.hpke_config_fetch = hpke_config_fetch_time;

        let TestTaskConfig {
            task_id,
            taskprov_advertisement,
            ..
        } = &test_task_config;

        info!("task id: {task_id}");

        // Generate enough reports to complete a batch.
        let measurement = match &opt.measurement {
            Some(m) => std::borrow::Cow::Borrowed(m),
            None => std::borrow::Cow::Owned(self.gen_measurement().unwrap()),
        };

        ////

        let batch_id = BatchId(rngs::OsRng.gen());
        let part_batch_sel = PartialBatchSelector::FixedSizeByBatchId { batch_id };

        let (leader_agg_share, agg_job_duration) = self
            .run_agg_jobs(
                opt.reports_per_batch,
                &test_task_config,
                &part_batch_sel,
                opt.reports_per_agg_job,
                |reports_per_agg_job| {
                    ReportGenerator::new(
                        &test_task_config.task_config.vdaf,
                        &test_task_config.hpke_config_list,
                        test_task_config.task_id,
                        reports_per_agg_job,
                        measurement.as_ref(),
                        version,
                        now.0,
                        vec![messages::Extension::Taskprov],
                        self.replay_reports,
                    )
                },
            )
            .await?;

        durations.aggregate_init_req = agg_job_duration;

        durations.aggregate_share_req = self
            .get_aggregate_share(
                leader_agg_share,
                batch_id,
                version,
                taskprov_advertisement.as_ref(),
                *task_id,
            )
            .await?;
        Ok(durations)
    }

    pub fn mock_success(&self) {
        self.set_sucess_metric_to(true);
    }

    pub fn mock_failure(&self) {
        self.set_sucess_metric_to(false);
    }

    fn set_sucess_metric_to(&self, success: bool) {
        let c = |b: bool| ["F", "T"][usize::from(b)];
        self.metrics
            .test_success
            .with_label_values(&[
                c(self.http_client.using_mtls()),
                c(self.bearer_token.is_some()),
            ])
            .set(i64::from(success));
    }
}

#[async_trait]
impl DapReportInitializer for Test {
    fn valid_report_time_range(&self) -> Range<messages::Time> {
        // Accept reports with any timestmap.
        0..u64::MAX
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
    assert!(
        total >= chunk_length,
        "total: {total} | chunk_length: {chunk_length}"
    );
    (0..(total / chunk_length))
        .map(move |_| chunk_length)
        .chain(Some(total % chunk_length).filter(|t| *t > 0))
}

#[cfg(test)]
mod tests {
    use crate::acceptance::Test;

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

    #[test]
    fn test_helper_is_send() {
        #![allow(unused_variables, unreachable_code, clippy::diverging_sub_expression)]
        fn is_send<T: Send>(_t: T) {}
        let _never_run = || {
            let t: Test = todo!();
            is_send(t.test_helper(todo!()));
            is_send(t.run_agg_job(todo!(), todo!(), todo!(), todo!(), todo!()));
            is_send(t.run_agg_jobs(todo!(), todo!(), todo!(), todo!(), |_| todo!()));
            is_send(t.get_hpke_config(todo!()));
            is_send(t.generate_task_config(todo!(), todo!(), todo!(), todo!()));
        };
    }
}
