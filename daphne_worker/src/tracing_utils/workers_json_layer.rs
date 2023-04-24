// Copyright (c) 2023 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use std::collections::HashMap;

use tracing::{field::Visit, span::Attributes, Id, Subscriber};
use tracing_core::Field;
use tracing_subscriber::{layer::Context as LayerContext, registry, Layer};
use worker::console_log;

pub struct JsonVisitor<'a>(&'a mut JsonFields);

impl<'a> Visit for JsonVisitor<'a> {
    fn record_f64(&mut self, field: &Field, value: f64) {
        if let Ok(value) = serde_json::to_value(value) {
            self.0.insert(field.name().to_string(), value);
        }
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        if let Ok(value) = serde_json::to_value(value) {
            self.0.insert(field.name().to_string(), value);
        }
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        if let Ok(value) = serde_json::to_value(value) {
            self.0.insert(field.name().to_string(), value);
        }
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        if let Ok(value) = serde_json::to_value(value) {
            self.0.insert(field.name().to_string(), value);
        }
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        if let Ok(value) = serde_json::to_value(value) {
            self.0.insert(field.name().to_string(), value);
        }
    }

    fn record_error(&mut self, field: &Field, value: &(dyn std::error::Error + 'static)) {
        if let Ok(value) = serde_json::to_value(value.to_string()) {
            self.0.insert(field.name().to_string(), value);
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if let Ok(value) = serde_json::to_value(format!("{:?}", value)) {
            self.0.insert(field.name().to_string(), value);
        }
    }
}

#[derive(serde::Serialize)]
struct LogLine {
    timestamp: u64,
    log_level: &'static str,
    #[serde(flatten)]
    fields: HashMap<String, serde_json::Value>,
}

/// Tracing subscriber layer that writes JSON to Cloudflare Workers console.
///
/// Fields from spans are flattened into the JSON, duplicates are prioritized by their closeness to
/// the leaf (e.g. leaf field overrides root field).
///
/// Timestamps are derived from calling `Date.now()`. In the Workers runtime, time only progresses
/// when IO occurs.
///
/// Logs all messages to `console.log` with their tracing log level in a `level` field of the JSON.
pub struct WorkersJsonLayer;

// Type used to store formatted JSON span fields within span extensions.
type JsonFields = HashMap<String, serde_json::Value>;

impl<S> Layer<S> for WorkersJsonLayer
where
    S: Subscriber + for<'a> registry::LookupSpan<'a>,
{
    fn on_new_span(&self, attrs: &Attributes<'_>, id: &Id, ctx: LayerContext<'_, S>) {
        let span = ctx.span(id).expect("span should exist");
        let mut fields = HashMap::new();
        let mut visitor = JsonVisitor(&mut fields);
        attrs.record(&mut visitor);

        let mut extensions = span.extensions_mut();
        if extensions.get_mut::<JsonFields>().is_none() {
            extensions.insert(fields);
        }
    }

    fn on_event(&self, event: &tracing::Event<'_>, ctx: LayerContext<'_, S>) {
        let timestamp = worker::Date::now().as_millis();

        let mut fields = HashMap::new();
        let mut visitor = JsonVisitor(&mut fields);

        // Prioritize any fields in the message itself over those in the span tree.
        event.record(&mut visitor);

        if let Some(current) = ctx.event_span(event) {
            // current context --> root context
            if let Some(spans) = ctx.span_scope(&current.id()) {
                for span in spans {
                    let ext = span.extensions();
                    let data = ext.get::<JsonFields>();

                    fields
                        .entry("current_span".to_owned())
                        .or_insert(serde_json::json!(span.name()));

                    for f in span.fields().iter() {
                        if let Some(value) = data.and_then(|d| d.get(f.name())) {
                            // As we are going from current span to root, prioritize existing values.
                            fields.entry(f.name().to_owned()).or_insert(value.clone());
                        }
                    }
                }
            }
        }

        let log_line = LogLine {
            timestamp,
            log_level: event.metadata().level().as_str(),
            fields,
        };

        if let Ok(log) = serde_json::to_string(&log_line) {
            console_log!("{}", log);
        }
    }
}
