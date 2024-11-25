// Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        mpsc, Mutex, OnceLock,
    },
    time::Instant,
};

use crate::{
    fatal_error,
    hpke::HpkeConfig,
    messages::{self, Report, TaskId, Time},
    vdaf::VdafConfig,
    DapError, DapMeasurement, DapVersion,
};
use deepsize::DeepSizeOf;
use rand::{
    distributions::{Distribution, Uniform},
    thread_rng,
};

pub struct ReportGenerator {
    len: usize,
    ch: mpsc::Receiver<messages::Report>,
}

impl Iterator for ReportGenerator {
    type Item = messages::Report;

    fn next(&mut self) -> Option<Self::Item> {
        self.ch.recv().ok()
    }
}

impl ReportGenerator {
    #[expect(clippy::too_many_arguments)]
    pub fn new(
        vdaf: &VdafConfig,
        hpke_config_list: &[HpkeConfig; 2],
        task_id: TaskId,
        reports_per_batch: usize,
        measurement: &DapMeasurement,
        version: DapVersion,
        now: Time,
        extensions: Vec<messages::Extension>,
        replay_reports: bool,
    ) -> Self {
        let (tx, rx) = mpsc::channel();
        rayon::spawn({
            let hpke_config_list = hpke_config_list.clone();
            let measurement = measurement.clone();
            let vdaf = *vdaf;
            move || {
                // perf measurements
                static GENERATED_REPORT_COUNTER: AtomicUsize = AtomicUsize::new(0);
                static LAST_INSTANT: Mutex<Option<Instant>> = Mutex::new(None);
                // --

                let report_time_dist = Uniform::from(now - (60 * 60 * 36)..now - (60 * 60 * 24));
                let error = (0..reports_per_batch).try_for_each(move |_| {
                    // perf measurements
                    let last_instant = *LAST_INSTANT
                        .lock()
                        .unwrap()
                        .get_or_insert_with(Instant::now);
                    let now = Instant::now();
                    // ----

                    static LAST_REPORT: OnceLock<Report> = OnceLock::new();
                    let report = if replay_reports {
                        LAST_REPORT
                            .get_or_init(|| {
                                vdaf.produce_report_with_extensions(
                                    &hpke_config_list,
                                    report_time_dist.sample(&mut thread_rng()),
                                    &task_id,
                                    measurement.clone(),
                                    extensions.clone(),
                                    version,
                                )
                                .expect("we have to panic here since we can't return the error")
                            })
                            .clone()
                    } else {
                        vdaf.produce_report_with_extensions(
                            &hpke_config_list,
                            report_time_dist.sample(&mut thread_rng()),
                            &task_id,
                            measurement.clone(),
                            extensions.clone(),
                            version,
                        )?
                    };

                    // perf measurements
                    let count = GENERATED_REPORT_COUNTER.fetch_add(1, Ordering::SeqCst) + 1;
                    if count % 1000 == 0 {
                        tracing::debug!(
                            "generated {count} reports in {:?}. Each of size {}. Last one in {:?}",
                            last_instant.elapsed(),
                            report.deep_size_of() as f64 / 1000.,
                            now.elapsed(),
                        );
                        *LAST_INSTANT.lock().unwrap() = Some(Instant::now());
                    }
                    // --

                    tx.send(report)
                        .map_err(|_| fatal_error!(err = "failed to send report, channel closed"))?;
                    Ok::<_, DapError>(())
                });
                if let Err(error) = error {
                    tracing::error!(?error, "failed to generate a report");
                }
            }
        });

        Self {
            len: reports_per_batch,
            ch: rx,
        }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
