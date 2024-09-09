// Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use std::{
    pin::Pin,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Mutex, OnceLock,
    },
    task::Context,
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
use futures::Stream;
use pin_project::pin_project;
use rand::{
    distributions::{Distribution, Uniform},
    thread_rng,
};
use tokio::sync::mpsc;

#[pin_project]
pub struct ReportGenerator {
    len: usize,
    #[pin]
    ch: mpsc::Receiver<messages::Report>,
}

impl Stream for ReportGenerator {
    type Item = messages::Report;

    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        let mut this = self.project();
        match this.ch.poll_recv(cx) {
            std::task::Poll::Ready(report) => {
                *this.len = this.len.saturating_sub(1);
                std::task::Poll::Ready(report)
            }
            poll @ std::task::Poll::Pending => poll,
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.len, Some(self.len))
    }
}

impl ReportGenerator {
    #[allow(clippy::too_many_arguments)]
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
        let (tx, rx) = mpsc::channel(4);
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

                    tx.blocking_send(report)
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
