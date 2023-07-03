// Copyright (c) 2023 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use chrono::{SecondsFormat, Utc};
use std::{fmt::Result as FmtResult, io, str, sync::Once};
use tracing_subscriber::{
    fmt,
    fmt::{format::Writer, time::FormatTime},
    layer::*,
    prelude::*,
    registry, EnvFilter, Layer,
};
use worker::{console_log, Env};

use wasm_timing::WasmTimingLayer;
pub(crate) use wasm_timing::{initialize_timing_histograms, MeasuredSpanName};

use self::workers_json_layer::WorkersJsonLayer;

/// WasmTime provides a `tracing_subscriber::fmt::time::FormatTime` implementation that works
/// using the clock available to WASM code, as the default FormatTime implementation does not
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

/// LogWriter helps us write to the worker console.
///
/// It provides and io::Write implementation that provides line buffering. It also takes care of
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

/// Setup logging.
///
/// Initialize tracing using configuration from DAP_TRACING in the environment
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
                let json = WorkersJsonLayer.and_then(WasmTimingLayer);
                (None, Some(json))
            }
            Ok(_) | Err(_) => {
                // Console output
                let ansi = fmt::layer()
                    .with_ansi(true)
                    .with_writer(LogWriter::new)
                    .with_timer(WasmTime::new())
                    .and_then(WasmTimingLayer);

                (Some(ansi), None)
            }
        };

        registry()
            .with(ansi)
            .with(json)
            .with(EnvFilter::new(filter))
            .init();
    });
}

mod wasm_timing;
mod workers_json_layer;
