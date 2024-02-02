// Copyright (c) 2023 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

pub mod fields_recording_layer;
mod workers_json_layer;

use chrono::{SecondsFormat, Utc};
use std::{collections::HashMap, fmt::Result as FmtResult, io, path::PathBuf, str, sync::Once};
use tracing::field::Visit;
use tracing_core::Field;
use tracing_subscriber::{
    fmt,
    fmt::{format::Writer, time::FormatTime},
    layer::{Layered, SubscriberExt},
    prelude::*,
    registry, EnvFilter, Layer,
};
use worker::{console_log, Env};

use self::workers_json_layer::WorkersJsonLayer;

// Type used to store formatted JSON span fields within span extensions.
pub type JsonFields = HashMap<String, serde_json::Value>;

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
        if let Ok(value) = serde_json::to_value(format!("{value:?}")) {
            self.0.insert(field.name().to_string(), value);
        }
    }
}

/// `WasmTime` provides a `tracing_subscriber::fmt::time::FormatTime` implementation that works
/// using the clock available to WASM code, as the default `FormatTime` implementation does not
/// work.
struct WasmTime {}

impl WasmTime {
    fn new() -> Self {
        WasmTime {}
    }
}

impl FormatTime for WasmTime {
    fn format_time(&self, w: &mut Writer<'_>) -> FmtResult {
        // Chrono is smart and knows how to read the time on everything, including WASM!
        let now = Utc::now();
        // We will format the time as ISO-8601 with milliseconds precision and a Z timezone.
        write!(w, "{}", now.to_rfc3339_opts(SecondsFormat::Millis, true))
    }
}

/// `LogWriter` helps us write to the worker console.
///
/// It provides and `io::Write` implementation that provides line buffering. It also takes care of
/// emitting a timestamp as the timestamp code in the tracing library tries to use standard clock
/// code, which does not work in a worker.
struct LogWriter {
    buffer: String,
}

impl LogWriter {
    fn new() -> Self {
        LogWriter {
            buffer: String::new(),
        }
    }
}

impl io::Write for LogWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let s = str::from_utf8(buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        self.buffer.push_str(s);
        // We assume the caller is doing line buffering and that any write containing a NL will have
        // it at the end.
        if self.buffer.ends_with('\n') {
            console_log!("{}", &self.buffer[..self.buffer.len() - 1]);
            self.buffer.clear();
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

static INITIALIZE_TRACING: Once = Once::new();

// pub(crate) type DaphneSubscriber = Layered<
//     Vec<Box<dyn Layer<tracing_subscriber::Registry> + Send + Sync>>,
//     tracing_subscriber::Registry,
// >;
pub(crate) type DaphneSubscriber = Layered<
    Box<
        dyn Layer<
                Layered<
                    Vec<Box<dyn Layer<tracing_subscriber::Registry> + Send + Sync>>,
                    tracing_subscriber::Registry,
                >,
            > + Send
            + Sync,
    >,
    Layered<
        Vec<Box<dyn Layer<tracing_subscriber::Registry> + Send + Sync>>,
        tracing_subscriber::Registry,
    >,
>;

/// Utility function that takes a path (ex: `path/to/something`) and shortens it in by preserving
/// only the first letter of each segment except the last word, which is kept as is.
pub(crate) fn shorten_paths<'s, I>(segments: I) -> PathBuf
where
    I: IntoIterator<Item = &'s str>,
{
    struct LastItemIter<I: Iterator> {
        iter: std::iter::Peekable<I>,
    }

    impl<I: Iterator> Iterator for LastItemIter<I> {
        type Item = (bool, I::Item);

        fn next(&mut self) -> Option<Self::Item> {
            let next = self.iter.next()?;
            Some((self.iter.peek().is_none(), next))
        }
    }

    LastItemIter {
        iter: segments.into_iter().peekable(),
    }
    .map(|(is_last, s)| {
        if is_last {
            s
        } else if let Some((first_char_idx, _)) = s.char_indices().nth(2) {
            &s[0..first_char_idx]
        } else {
            s
        }
    })
    .collect::<PathBuf>()
}

/// Setup logging.
///
/// Initialize tracing using configuration from `DAP_TRACING` in the environment
/// if present, otherwise using a default level of `info` and more severe.
///
/// Panics if the log handler cannot be installed.
///
/// Logging will only be initialized once, no matter how many times this
/// function is called.
pub fn initialize_tracing(env: &Env) {
    // We have to do this in a once block as the worker instance can get multiple invocations of
    // main() within its lifetime.
    INITIALIZE_TRACING.call_once(|| {
        let filter = match env.var("DAP_TRACING") {
            Ok(var) => var.to_string(),
            Err(_) => "info".to_string(),
        };

        let (ansi, json) = match env.var("DAP_DEPLOYMENT") {
            Ok(format) if format.to_string() == "prod" => {
                // JSON output
                (None, Some(WorkersJsonLayer))
            }
            Ok(_) | Err(_) => {
                // Console output
                let ansi = fmt::layer()
                    .with_ansi(true)
                    .with_writer(LogWriter::new)
                    .with_timer(WasmTime::new());
                (Some(ansi), None)
            }
        };

        // NOTE: this type alias is important as it allows us to fetch the subscriber at runtime in
        // order to pass the fields in a request to a DO.
        //
        // Hence all the boxing in order to erase the types as much as possible.
        let x: DaphneSubscriber = registry()
            .with(vec![
                fields_recording_layer::SpanFieldsRecorderLayer.boxed(),
                ansi.boxed(),
                json.boxed(),
            ])
            .with(
                // EnvFilter must seperate from the other layers in order to provide global
                // filtering
                EnvFilter::new(filter).boxed(),
            );
        x.init();
    });
}

#[cfg(test)]
mod test {
    use std::path::PathBuf;

    use super::shorten_paths;

    #[test]
    fn shorten_paths_simple() {
        let got = shorten_paths("path/to/object".split('/'));
        let expect = ["pa", "to", "object"].into_iter().collect::<PathBuf>();

        assert_eq!(got, expect);
    }

    #[test]
    fn shorten_paths_single_segment() {
        let got = shorten_paths("object".split('/'));
        let expect = PathBuf::from("object");

        assert_eq!(got, expect);
    }
}
