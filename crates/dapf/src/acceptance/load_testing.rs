// Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use std::{
    collections::HashMap,
    fmt::Display,
    time::{Duration, Instant},
};

use crate::{
    acceptance::{now, Test, TestOptions},
    test_durations::TestDurations,
};
use chrono::{DateTime, Utc};
use daphne::{
    messages::{BatchId, PartialBatchSelector},
    testing::report_generator::ReportGenerator,
    vdaf::VdafConfig,
};
use futures::StreamExt;
use rand::{thread_rng, Rng};
use url::Url;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct MeasurementParameters {
    reports_per_batch: usize,
    reports_per_agg_job: usize,
    vdaf_config: VdafConfig,
}

impl MeasurementParameters {
    fn headers() -> &'static str {
        "reports p/ batch;reports p/ job;dimension"
    }
}

impl Display for MeasurementParameters {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{};{};{:?}",
            self.reports_per_batch, self.reports_per_agg_job, self.vdaf_config
        )
    }
}

fn reports_per_batch_params() -> impl Iterator<Item = usize> {
    [500, 1_000, 10_000].into_iter()
}

fn jobs_per_batch() -> impl Iterator<Item = usize> {
    [1, 10, 20, 30, 40, 50, 100].into_iter()
}

fn vdaf_config_params() -> impl Iterator<Item = VdafConfig> {
    [
        VdafConfig::Prio2 { dimension: 99_992 },
        VdafConfig::Prio3(
            daphne::vdaf::Prio3Config::SumVecField64MultiproofHmacSha256Aes128 {
                bits: 1,
                length: 100_000,
                chunk_length: 320,
                num_proofs: 2,
            },
        ),
        VdafConfig::Prio3(
            daphne::vdaf::Prio3Config::SumVecField64MultiproofHmacSha256Aes128 {
                bits: 1,
                length: 100_000,
                chunk_length: 320,
                num_proofs: 3,
            },
        ),
    ]
    .into_iter()
}

fn measurement_parameters() -> impl Iterator<Item = MeasurementParameters> {
    vdaf_config_params()
        .flat_map(|vdaf_config| {
            reports_per_batch_params()
                .map(move |reports_per_batch| (reports_per_batch, vdaf_config))
        })
        .flat_map(|(reports_per_batch, vdaf_config)| {
            jobs_per_batch().map(move |jobs_per_batch| MeasurementParameters {
                reports_per_batch,
                reports_per_agg_job: reports_per_batch / jobs_per_batch,
                vdaf_config,
            })
        })
        .filter(|params| params.reports_per_batch >= params.reports_per_agg_job)
}

fn average<I, T>(d: I) -> Option<TestDurations>
where
    I: IntoIterator<Item = T>,
    T: AsRef<TestDurations>,
{
    let (total, count) = d
        .into_iter()
        .fold((TestDurations::default(), 0), |(avg, count), t| {
            (avg + t.as_ref(), count + 1)
        });

    (count > 0).then(|| total / count)
}

#[derive(Debug)]
struct TestError {
    when: DateTime<Utc>,
    error: anyhow::Error,
}

#[derive(Debug)]
struct TestResults {
    success_rate: u32,
    tests: Vec<Result<TestDurations, TestError>>,
}

impl TestResults {
    const RUNS: u32 = 1;
    fn average_duration(&self) -> Option<TestDurations> {
        average(self.tests.iter().flatten())
    }

    fn measurements_of(
        &self,
        mapper: impl FnMut(&TestDurations) -> Duration,
    ) -> (Duration, Duration, Duration) {
        let (min, sum, max, count) = self
            .tests
            .iter()
            .filter_map(|r| r.as_ref().ok())
            .map(mapper)
            .fold(
                (None, Duration::ZERO, Duration::ZERO, 0u32),
                |(min, sum, max, count), time| {
                    (
                        Some(Duration::min(time, min.unwrap_or(time))),
                        sum + time,
                        Duration::max(max, time),
                        count + 1,
                    )
                },
            );
        (
            min.unwrap_or_default(),
            sum.checked_div(count).unwrap_or_default(),
            max,
        )
    }

    fn agg_init(&self) -> (Duration, Duration, Duration) {
        self.measurements_of(|d| d.aggregate_init_req)
    }
    fn agg_share(&self) -> (Duration, Duration, Duration) {
        self.measurements_of(|d| d.aggregate_share_req)
    }
}

fn print_perf_report(measurments: &HashMap<MeasurementParameters, TestResults>) {
    println!("#### Final Performance Report ####");
    {
        println!("Scaling based on reports per batch:");
        let mut reports_per_batch = measurments
            .iter()
            .map(|(m, _)| m.reports_per_batch)
            .collect::<Vec<_>>();
        reports_per_batch.sort_unstable();
        reports_per_batch.dedup();
        for r in reports_per_batch {
            let avg = average(measurments.iter().filter_map(move |(params, results)| {
                (params.reports_per_batch == r)
                    .then_some(results.average_duration())
                    .flatten()
            }));
            println!("\t- {r} => {avg:?}");
        }
    }

    {
        println!("Scaling based on reports per aggregation job:");
        let mut reports_per_agg_job = measurments
            .iter()
            .map(|(m, _)| m.reports_per_agg_job)
            .collect::<Vec<_>>();
        reports_per_agg_job.sort_unstable();
        reports_per_agg_job.dedup();
        for r in reports_per_agg_job {
            let avg = average(measurments.iter().filter_map(move |(params, results)| {
                (params.reports_per_agg_job == r)
                    .then_some(results.average_duration())
                    .flatten()
            }));
            println!("\t- {r} => {avg:?}");
        }
    }
    {
        let mut vdaf_configs = measurments
            .iter()
            .map(|(m, _)| m.vdaf_config)
            .collect::<Vec<_>>();
        vdaf_configs.sort();
        vdaf_configs.dedup();
        println!("Scaling based on dimension:");
        for r in vdaf_configs {
            let avg = average(measurments.iter().filter_map(move |(params, results)| {
                (params.vdaf_config == r)
                    .then_some(results.average_duration())
                    .flatten()
            }));
            println!("\t- {r} => {avg:?}");
        }
    }

    fn tabularize_durations((min, avg, max): (Duration, Duration, Duration)) -> impl Display {
        struct T(Duration, Duration, Duration);
        impl Display for T {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(
                    f,
                    "{};{};{}",
                    self.0.as_millis() as f64 / 1000.0,
                    self.1.as_millis() as f64 / 1000.0,
                    self.2.as_millis() as f64 / 1000.0,
                )
            }
        }
        T(min, avg, max)
    }
    println!("====== FAILURES ======");
    for (param, results) in measurments {
        let error_map = results.tests.iter().filter_map(|r| r.as_ref().err()).fold(
            HashMap::<_, Vec<_>>::new(),
            |mut acc, TestError { when, error }| {
                acc.entry(format!("{error:?}")).or_default().push(when);
                acc
            },
        );
        for (error, whens) in error_map {
            print!("{param:?};{error};");
            for when in whens {
                print!("{when};");
            }
            println!();
        }
    }
    println!("====== SUCCESS RATE ======");
    println!(";;;;;agg_init;;;agg_share");
    print!("{}", MeasurementParameters::headers());
    println!(";success;runs;min;avg;max;min;avg;max;reports/sec");
    for (param, results) in measurments {
        println!(
            "{param};{};{};{};{};{}",
            results.success_rate,
            results.tests.len(),
            tabularize_durations(results.agg_init()),
            tabularize_durations(results.agg_share()),
            {
                let (sum, c) = results
                    .tests
                    .iter()
                    .filter_map(|r| r.as_ref().ok())
                    .map(|d| d.total_service_time())
                    .fold((Duration::ZERO, 0), |(d, c), d0| (d + d0, c + 1));

                sum.checked_div(c)
                    .map(|avg| {
                        let seconds = avg.as_millis() as f64 / 1000.0;
                        param.reports_per_batch as f64 / seconds
                    })
                    .unwrap_or_default()
            }
        );
    }
}

async fn execute(t: &Test, test_config: &TestOptions) -> TestResults {
    let tests = futures::stream::iter(0..TestResults::RUNS)
        .map(|i| async move {
            let r = tokio::time::timeout(
                Duration::from_secs(60) * 30, // 30 min
                t.test_helper(test_config),
            )
            .await;
            match r {
                Ok(r) => r.map_err(|error| TestError {
                    when: Utc::now(),
                    error,
                }),
                Err(_timed_out) => Err(TestError {
                    when: Utc::now(),
                    error: anyhow::anyhow!("job {i} timedout"),
                }),
            }
        })
        .buffer_unordered(16)
        .collect::<Vec<_>>()
        .await;

    TestResults {
        success_rate: tests
            .iter()
            .filter(|x| x.is_ok())
            .count()
            .try_into()
            .unwrap(),
        tests,
    }
}

pub async fn execute_multiple_combinations(helper_url: Url) {
    // This vdaf config is later replaced on each of the runs
    let mut t = Test::from_env(helper_url, VdafConfig::Prio2 { dimension: 44 }, None)
        .expect("env to be present");

    let config = t.get_hpke_config(&t.helper_url).await.expect("test failed");
    let mut test_config = TestOptions {
        helper_hpke_config: Some(config),
        ..Default::default()
    };

    let mut measurments = HashMap::new();

    loop {
        for params @ MeasurementParameters {
            reports_per_batch,
            reports_per_agg_job,
            vdaf_config,
        } in measurement_parameters()
        {
            // configure the test
            test_config.reports_per_batch = reports_per_batch;
            test_config.reports_per_agg_job = reports_per_agg_job;
            t.vdaf_config = vdaf_config;
            test_config.measurement = Some(t.gen_measurement().unwrap());

            println!("===== Performance Report =====");
            println!("parameters:");
            println!("\t- reports_per_batch:   {reports_per_batch}");
            println!("\t- reports_per_agg_job: {reports_per_agg_job}");
            println!("\t- vdaf_config:         {vdaf_config:?}");

            let results = execute(&t, &test_config).await;

            println!("durations:\n{results:#?}");

            let old_results = measurments.entry(params).or_insert_with(|| TestResults {
                success_rate: 0,
                tests: vec![],
            });
            old_results.success_rate += results.success_rate;
            old_results.tests.extend(results.tests);

            print_perf_report(&measurments);
        }
    }
}

pub async fn execute_single_combination_from_env(
    helper_url: Url,
    vdaf_config: VdafConfig,
    reports_per_batch: usize,
    reports_per_agg_job: usize,
) {
    const VERSION: daphne::DapVersion = daphne::DapVersion::Latest;

    let t = Test::from_env(helper_url, vdaf_config, None).expect("env to be present");

    let system_now = now();
    let (test_task_config, hpke_config_fetch_time) = t
        .generate_task_config(VERSION, None, reports_per_batch, system_now)
        .await
        .expect("failed to generate task config");

    println!("Generating reports");

    let measurment = t.gen_measurement().unwrap();

    let mut success_count = 0;
    let mut run_count = 0;
    loop {
        println!("STARTED WITH");
        println!("\t- reports_per_batch:   {reports_per_batch}");
        println!("\t- reports_per_agg_job: {reports_per_agg_job}");
        println!("\t- vdaf_config:         {:?}", t.vdaf_config);

        let batch_id = BatchId(thread_rng().gen());
        let part_batch_sel = PartialBatchSelector::FixedSizeByBatchId { batch_id };

        let now = Instant::now();
        let r = t
            .run_agg_jobs(
                reports_per_batch,
                &test_task_config,
                &part_batch_sel,
                reports_per_agg_job,
                |reports_per_job| {
                    ReportGenerator::new(
                        &test_task_config.task_config.vdaf,
                        &test_task_config.hpke_config_list,
                        test_task_config.task_id,
                        reports_per_job,
                        &measurment,
                        VERSION,
                        system_now.0,
                    )
                },
            )
            .await;

        println!("Agg jobs took {:?}", now.elapsed());
        run_count += 1;
        match r {
            Ok((_, times)) => {
                success_count += 1;
                println!("durations: {:?}", times + hpke_config_fetch_time);
            }
            Err(e) => {
                println!("run failed: {e:?}");
            }
        }
        println!("running count: {success_count}/{run_count}");
    }
}

// async fn main() {
//     tracing_subscriber::fmt()
//         .compact()
//         .with_writer(std::io::stderr)
//         .init();
//     match std::env::args().nth(1) {
//         Some(arg) if arg == "bench" => execute_multiple_combinations().await,
//         Some(arg) => eprintln!("invalid arg {arg}. Only nothing and 'bench' are supported"),
//         None => match std::env::var("TARGET").as_deref() {
//             Ok("bench") => execute_multiple_combinations().await,
//             _ => loop {
//                 execute_single_combination_from_env().await;
//             },
//         },
//     }
// }
