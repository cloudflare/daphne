use arc_swap::ArcSwapOption;
use daphne::{fatal_error, DapError};
use prometheus::{register_histogram_with_registry, Histogram, Registry};
use std::{str, sync::Arc};
use tracing::{event, Level, Subscriber};
use tracing_core::span;
use tracing_subscriber::{layer::Context as LayerContext, registry, Layer};
use worker::Date;

#[derive(Debug)]
#[allow(clippy::enum_variant_names)] // the common prefix makes sense, we just don't have more
                                     // spans we want to measure yet.
pub(crate) enum MeasuredSpanName {
    AggregateInit,
    AggregateContinue,
    AggregateShares,
}

impl MeasuredSpanName {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::AggregateInit => "aggregate_init",
            Self::AggregateContinue => "aggregate_continue",
            Self::AggregateShares => "aggregate_shares",
        }
    }
}

impl TryFrom<&str> for MeasuredSpanName {
    type Error = &'static str;

    fn try_from(value: &str) -> std::result::Result<Self, Self::Error> {
        match value {
            "aggregate_init" => Ok(Self::AggregateInit),
            "aggregate_continue" => Ok(Self::AggregateContinue),
            "aggregate_shares" => Ok(Self::AggregateShares),
            _ => Err("invalid request type"),
        }
    }
}

struct RequestTimeHistograms {
    /// Helper: Aggregate request times
    pub aggregation_init_request_times: Histogram,

    /// Helper: Aggregate request times
    pub aggregation_continue_request_times: Histogram,

    /// Helper: Aggregate shares request times
    pub aggregate_shares_request_times: Histogram,
}

static REQUEST_TIME_HISTOGRAMS: ArcSwapOption<RequestTimeHistograms> = ArcSwapOption::const_empty();

pub(crate) fn initialize_timing_histograms(
    registry: &Registry,
    prefix: Option<&str>,
) -> Result<(), DapError> {
    let front = if let Some(prefix) = prefix {
        format!("{prefix}_")
    } else {
        "".into()
    };
    let aggregation_init_request_times = register_histogram_with_registry!(
        format!("{front}aggregation_init_request_times"),
        "Time taken to process an aggregation",
        prometheus::DEFAULT_BUCKETS
            .iter()
            .map(|i| i * 1000.0)
            .collect(),
        registry,
    )
    .map_err(|e| fatal_error!(err = e, "failed to register aggregation_request_times"))?;

    let aggregation_continue_request_times = register_histogram_with_registry!(
        format!("{front}aggregation_continue_request_times"),
        "Time taken to process an aggregation",
        prometheus::DEFAULT_BUCKETS
            .iter()
            .map(|i| i * 1000.0)
            .collect(),
        registry,
    )
    .map_err(|e| fatal_error!(err = e, "failed to register aggregate_shares_request_times"))?;

    let aggregate_shares_request_times = register_histogram_with_registry!(
        format!("{front}aggregate_shares_request_times"),
        "Time taken to process an aggregation",
        prometheus::DEFAULT_BUCKETS
            .iter()
            .map(|i| i * 1000.0)
            .collect(),
        registry,
    )
    .map_err(|e| fatal_error!(err = e, "failed to register upload_request_times"))?;

    REQUEST_TIME_HISTOGRAMS.store(Some(Arc::new(RequestTimeHistograms {
        aggregation_init_request_times,
        aggregation_continue_request_times,
        aggregate_shares_request_times,
    })));
    Ok(())
}

/// WasmTimingLayer provides a span's elapsed time.
pub(super) struct WasmTimingLayer;

fn milli_now() -> i64 {
    Date::now().as_millis() as i64
}

struct Timestamps {
    busy: i64,
    entered_at: i64,
    started_at: i64,
}

impl Timestamps {
    fn new() -> Self {
        Timestamps {
            busy: 0,
            entered_at: 0,
            started_at: milli_now(),
        }
    }
}

impl<S> Layer<S> for WasmTimingLayer
where
    S: Subscriber + for<'a> registry::LookupSpan<'a>,
{
    fn on_new_span(&self, _attrs: &span::Attributes<'_>, id: &span::Id, ctx: LayerContext<'_, S>) {
        let span = ctx.span(id).expect("span should exist!");
        let mut extensions = span.extensions_mut();
        if extensions.get_mut::<Timestamps>().is_none() {
            extensions.insert(Timestamps::new());
        }
    }

    fn on_enter(&self, id: &span::Id, ctx: LayerContext<'_, S>) {
        let span = ctx.span(id).expect("span should exist!");
        let mut extensions = span.extensions_mut();
        if let Some(timestamps) = extensions.get_mut::<Timestamps>() {
            timestamps.entered_at = milli_now();
        }
    }

    fn on_exit(&self, id: &span::Id, ctx: LayerContext<'_, S>) {
        let span = ctx.span(id).expect("span should exist!");
        let mut extensions = span.extensions_mut();
        if let Some(timestamps) = extensions.get_mut::<Timestamps>() {
            timestamps.busy += milli_now().saturating_sub(timestamps.entered_at);
        }
    }

    fn on_close(&self, id: span::Id, ctx: LayerContext<'_, S>) {
        let span = ctx.span(&id).expect("span should exist!");
        let extensions = span.extensions();
        if let Some(timestamps) = extensions.get::<Timestamps>() {
            let elapsed = milli_now().saturating_sub(timestamps.started_at);
            if let Some(histograms) = &*REQUEST_TIME_HISTOGRAMS.load() {
                match span.name().try_into() {
                    Ok(ty) => match ty {
                        MeasuredSpanName::AggregateInit => histograms
                            .aggregation_init_request_times
                            .observe(elapsed as _),
                        MeasuredSpanName::AggregateContinue => histograms
                            .aggregation_continue_request_times
                            .observe(elapsed as _),
                        MeasuredSpanName::AggregateShares => histograms
                            .aggregate_shares_request_times
                            .observe(elapsed as _),
                    },
                    Err(_ignored) => {}
                }
            }
            event!(
                parent: id,
                Level::INFO,
                busy = timestamps.busy,
                elapsed,
                unit = "ms",
                "{} finished",
                span.name(),
            );
        }
    }
}
