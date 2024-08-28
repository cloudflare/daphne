// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Durable Object (DO) for storing aggregate shares for a bucket of reports.
//!
//! This object defines the following API endpoints:
//!
//! - `DURABLE_AGGREGATE_STORE_GET`: Return the current value of the aggregate share.
//! - `DURABLE_AGGREGATE_STORE_MERGE`: Update the aggregate share.
//! - `DURABLE_AGGREGATE_STORE_MARK_COLLECTED`: Mark the bucket as having been collected.
//! - `DURABLE_AGGREGATE_STORE_CHECK_COLLECTED`: Return a boolean indicating if the bucket has been
//!   collected.
//!
//! The schema for the data stored by this DO is as follows:
//!
//! ```text
//! [Aggregate share]
//!     meta                -> DapAggregateShareMetadata
//!     chunk_v2_{000..008} -> slice of VdafAggregateShare
//! [Seen Report Ids]
//!     aggregated_report_ids_{000..002} -> slice of ReportId
//! [Collected flag]
//!     collected -> bool
//! ```

use std::{collections::HashSet, io::Cursor, mem::size_of, sync::OnceLock, time::Duration};

use crate::int_err;
use daphne::{
    messages::{ReportId, Time},
    vdaf::VdafAggregateShare,
    DapAggregateShare,
};
use daphne_service_utils::durable_requests::bindings::{
    self, AggregateStoreMergeOptions, AggregateStoreMergeReq, AggregateStoreMergeResp,
    DurableMethod,
};
use prio::{
    codec::{Decode, Encode},
    field::FieldElement,
    vdaf::AggregateShare,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use worker::{
    js_sys, wasm_bindgen::JsValue, Env, Error, Request, Response, Result, ScheduledTime, State,
};

use super::{req_parse, GcDurableObject};

/// Minimum number of chunks needed to store 1Mb of aggregate share data.
const MAX_AGG_SHARE_CHUNK_KEY_COUNT: usize = 8;

/// Minimum number of chunks needed to store `40_000` report ids.
const DEFAULT_REPORT_ID_CHUNK_KEY_COUNT: u8 = 5;

/// The maximum chunk size as documented in
/// [the public docs](https://developers.cloudflare.com/durable-objects/platform/limits/)
const MAX_CHUNK_SIZE: usize = 128_000;

/// Key used to store metadata under.
const METADATA_KEY: &str = "meta";

/// Key used to store where this share has been collected
const COLLECTED_KEY: &str = "collected";

#[derive(Debug, Serialize, Deserialize, Clone, Copy)]
#[serde(rename_all = "snake_case")]
enum VdafKind {
    Field32,
    Field64,
    Field128,
}

#[derive(Debug, Serialize, Deserialize)]
struct DapAggregateShareMetadata {
    report_count: u64,
    min_time: Time,
    max_time: Time,
    checksum: [u8; 32],
    kind: Option<VdafKind>,
}

impl DapAggregateShareMetadata {
    fn from_agg_share(share: &DapAggregateShare) -> Self {
        Self {
            report_count: share.report_count,
            min_time: share.min_time,
            max_time: share.max_time,
            checksum: share.checksum,
            kind: share.data.as_ref().map(|data| match data {
                daphne::vdaf::VdafAggregateShare::Field32(_) => VdafKind::Field32,
                daphne::vdaf::VdafAggregateShare::Field64(_) => VdafKind::Field64,
                daphne::vdaf::VdafAggregateShare::Field128(_) => VdafKind::Field128,
            }),
        }
    }

    fn into_agg_share_with_data(self, data: daphne::vdaf::VdafAggregateShare) -> DapAggregateShare {
        DapAggregateShare {
            data: Some(data),
            ..self.into_agg_share_without_data()
        }
    }

    fn into_agg_share_without_data(self) -> DapAggregateShare {
        DapAggregateShare {
            report_count: self.report_count,
            min_time: self.min_time,
            max_time: self.max_time,
            checksum: self.checksum,
            data: None,
        }
    }
}

fn js_map_to_chunks<'s, T: DeserializeOwned + 's>(
    keys: &'s [impl AsRef<str>],
    map: &'s js_sys::Map,
) -> impl Iterator<Item = Vec<T>> + 's {
    keys.iter()
        .map(|k| JsValue::from_str(k.as_ref()))
        .filter(|k| map.has(k))
        .map(|k| map.get(&k))
        .map(|js_v| {
            serde_wasm_bindgen::from_value::<Vec<T>>(js_v).expect("expect an array of bytes")
        })
}

fn shard_bytes_to_object(
    keys: &[impl AsRef<str>],
    bytes: Vec<u8>,
    object_to_fill: &js_sys::Object,
) -> Result<()> {
    let num_chunks: usize = number_of_chunks_needed_for(&bytes).into();
    assert!(
        num_chunks <= keys.len(),
        "number of keys ({}) is lower than the required number of chunks ({num_chunks})",
        keys.len()
    );

    let mut base_idx = 0;
    for key in &keys[..num_chunks] {
        let end = usize::min(base_idx + MAX_CHUNK_SIZE, bytes.len());
        let chunk = &bytes[base_idx..end];

        // unwrap cannot fail because chunk len is bounded by MAX_CHUNK_SIZE which is smaller than
        // u32::MAX
        let value = js_sys::Uint8Array::new_with_length(u32::try_from(chunk.len()).unwrap());
        value.copy_from(chunk);

        js_sys::Reflect::set(
            object_to_fill,
            &JsValue::from_str(key.as_ref()),
            &value.into(),
        )?;

        base_idx = end;
    }
    Ok(())
}

super::mk_durable_object! {
    /// Where the aggregate share is stored. For the binding name see its
    /// [`BINDING`](bindings::AggregateStore::BINDING)
    struct AggregateStore {
        state: State,
        env: Env,
        report_ids: Option<HashSet<ReportId>>,
        agg_share: Option<DapAggregateShare>,
        collected: Option<bool>,
        report_id_chunk_key_count: Option<u8>,
    }
}

fn number_of_chunks_needed_for(bytes: &[u8]) -> u8 {
    // stolen from
    // https://doc.rust-lang.org/std/primitive.usize.html#method.div_ceil
    // because it's nightly only
    fn div_ceil(lhs: usize, rhs: usize) -> usize {
        let d = lhs / rhs;
        let r = lhs % rhs;
        if r > 0 && rhs > 0 {
            d + 1
        } else {
            d
        }
    }

    div_ceil(bytes.len(), MAX_CHUNK_SIZE)
        .try_into()
        .expect("number of chunks must be below u8::MAX")
}

impl AggregateStore {
    const fn agg_share_shard_keys() -> &'static [&'static str; MAX_AGG_SHARE_CHUNK_KEY_COUNT] {
        &[
            "chunk_v2_000",
            "chunk_v2_001",
            "chunk_v2_002",
            "chunk_v2_003",
            "chunk_v2_004",
            "chunk_v2_005",
            "chunk_v2_006",
            "chunk_v2_007",
        ]
    }

    async fn aggregated_reports_keys(&mut self) -> Result<Vec<String>> {
        let key_count = if let Some(key_count) = self.report_id_chunk_key_count {
            key_count
        } else {
            let key_count = self
                .get("report_id_chunk_key_count")
                .await?
                .unwrap_or(DEFAULT_REPORT_ID_CHUNK_KEY_COUNT);
            self.report_id_chunk_key_count = Some(key_count);
            key_count
        };
        Ok((0..key_count)
            .map(|n| format!("aggregated_report_ids_{n:03}"))
            .collect())
    }

    async fn set_report_id_chunk_key_count(&mut self, count: u8) -> Result<()> {
        if Some(count) == self.report_id_chunk_key_count {
            return Ok(());
        }
        self.state
            .storage()
            .put("report_id_chunk_key_count", count)
            .await?;

        self.report_id_chunk_key_count = Some(count);
        Ok(())
    }

    async fn get_agg_share(&mut self) -> Result<&mut DapAggregateShare> {
        let keys = Self::agg_share_shard_keys();
        let agg_share = if let Some(agg_share) = self.agg_share.take() {
            agg_share
        } else {
            let all_keys = keys
                .iter()
                .copied()
                .chain([METADATA_KEY])
                .collect::<Vec<_>>();
            let values = self.state.storage().get_multiple(all_keys).await?;

            if values.size() == 0 {
                DapAggregateShare::default()
            } else {
                let meta_key = JsValue::from_str(METADATA_KEY);
                let meta = serde_wasm_bindgen::from_value::<DapAggregateShareMetadata>(
                    values.get(&meta_key),
                )
                .unwrap_or_else(|e| {
                    tracing::error!("failed to deser DapAggregateShareMeta: {e:?}");
                    panic!("{e}")
                });

                let mut chunks = js_map_to_chunks(keys, &values).peekable();

                if chunks.peek().is_none() {
                    meta.into_agg_share_without_data()
                } else {
                    let kind = meta.kind.expect("if there is data there should be a type");

                    fn from_slices<F, I>(chunks: I) -> Result<AggregateShare<F>>
                    where
                        F: FieldElement,
                        I: Iterator<Item = Vec<u8>>,
                    {
                        let mut share = Vec::new();
                        for chunk in chunks {
                            let len = u64::try_from(chunk.len()).unwrap();
                            let mut bytes = Cursor::new(chunk.as_slice());
                            while bytes.position() < len {
                                let x = F::decode(&mut bytes).map_err(|e| {
                                    worker::Error::Internal(
                                        serde_wasm_bindgen::to_value(&format!(
                                            "failed to decode aggregate share: {e}"
                                        ))
                                        .expect("string never fails to convert to JsValue"),
                                    )
                                })?;
                                share.push(x);
                            }
                            if bytes.position() < len {
                                return Err(worker::Error::Internal(
                                serde_wasm_bindgen::to_value(
                                    "failed to decode aggregate share: bytes remaining in buffer",
                                )
                                .expect("string never fails to convert to JsValue"),
                            ));
                            }
                        }

                        Ok(AggregateShare::from(share))
                    }

                    let data = match kind {
                        VdafKind::Field32 => VdafAggregateShare::Field32(from_slices(chunks)?),
                        VdafKind::Field64 => VdafAggregateShare::Field64(from_slices(chunks)?),
                        VdafKind::Field128 => VdafAggregateShare::Field128(from_slices(chunks)?),
                    };

                    meta.into_agg_share_with_data(data)
                }
            }
        };

        self.agg_share = Some(agg_share);
        Ok(self.agg_share.as_mut().unwrap())
    }

    async fn load_aggregated_report_ids(&mut self) -> Result<&mut HashSet<ReportId>> {
        if self.report_ids.is_none() {
            self.cold_load_aggregated_report_ids().await?;
        }

        Ok(self.report_ids.as_mut().unwrap())
    }

    async fn cold_load_aggregated_report_ids(&mut self) -> Result<()> {
        let report_keys = self.aggregated_reports_keys().await?;
        let chunks_map = self
            .state
            .storage()
            .get_multiple(report_keys.clone())
            .await?;

        let bytes = js_map_to_chunks::<u8>(&report_keys, &chunks_map);

        let report_count_estimate = {
            let (lower, _) = bytes.size_hint();
            (lower * MAX_CHUNK_SIZE) / size_of::<ReportId>()
        };
        let mut ids = HashSet::with_capacity(report_count_estimate);
        for chunk in bytes {
            for id in chunk.chunks_exact(size_of::<ReportId>()) {
                ids.insert(ReportId::get_decoded(id).map_err(|_| Error::BadEncoding)?);
            }
        }

        self.report_ids = Some(ids);

        Ok(())
    }

    async fn is_collected(&mut self) -> Result<bool> {
        Ok(if let Some(collected) = self.collected {
            collected
        } else {
            let collected = self.get_or_default(COLLECTED_KEY).await?;
            self.collected = Some(collected);
            collected
        })
    }
}

impl GcDurableObject for AggregateStore {
    type DurableMethod = bindings::AggregateStore;

    fn with_state_and_env(state: State, env: Env) -> Self {
        Self {
            state,
            env,
            report_ids: None,
            agg_share: None,
            collected: None,
            report_id_chunk_key_count: None,
        }
    }

    async fn handle(&mut self, mut req: Request) -> Result<Response> {
        match bindings::AggregateStore::try_from_uri(&req.path()) {
            Some(bindings::AggregateStore::GetMerged) => {
                Response::from_json(&self.load_aggregated_report_ids().await?)
            }
            // Merge an aggregate share into the stored aggregate.
            //
            // Non-idempotent (do not retry)
            // Input: `agg_share_dellta: DapAggregateShare`
            // Output: `()`
            Some(bindings::AggregateStore::Merge) => {
                let AggregateStoreMergeReq {
                    contained_reports,
                    agg_share_delta,
                    options:
                        AggregateStoreMergeOptions {
                            skip_replay_protection,
                        },
                } = req_parse(&mut req).await?;

                let chunks_map = js_sys::Object::default();

                if self.is_collected().await? {
                    return Response::from_json(&AggregateStoreMergeResp::AlreadyCollected);
                }

                if !skip_replay_protection {
                    // check for replays
                    let merged_report_ids = self.load_aggregated_report_ids().await?;
                    let repeat_ids = contained_reports
                        .iter()
                        .filter(|id| merged_report_ids.contains(id))
                        .copied()
                        .collect::<HashSet<_>>();
                    if !repeat_ids.is_empty() {
                        if repeat_ids.len()
                            == usize::try_from(agg_share_delta.report_count).unwrap()
                        {
                            // If all reports in the aggregation job are already
                            // aggregated, then allow processing to continue, but don't aggregate
                            // them so that they're not double counted.
                            //
                            // This condition is triggered when a failed aggregation job is retried
                            // by the Leader. For example, if a request to durable objects times
                            // out (this is not uncommon at all), the Helper might aggregate the
                            // reports but return a 500 anyway; if the Leader retries, the reports
                            // will incorrectly be treated as replayed.
                            return Response::from_json(&AggregateStoreMergeResp::Ok);
                        }

                        return Response::from_json(&AggregateStoreMergeResp::ReplaysDetected(
                            repeat_ids,
                        ));
                    }

                    merged_report_ids.extend(contained_reports);
                    let mut as_bytes =
                        Vec::with_capacity(merged_report_ids.len() * size_of::<ReportId>());
                    merged_report_ids.iter().try_for_each(|id| {
                        id.encode(&mut as_bytes).map_err(|e| {
                            Error::RustError(format!("failed to encode report ID: {e}"))
                        })
                    })?;
                    self.set_report_id_chunk_key_count(number_of_chunks_needed_for(&as_bytes))
                        .await?;
                    shard_bytes_to_object(
                        &self.aggregated_reports_keys().await?,
                        as_bytes,
                        &chunks_map,
                    )?;
                };

                let agg_share = self.get_agg_share().await?;
                agg_share.merge(agg_share_delta).map_err(int_err)?;

                let meta = DapAggregateShareMetadata::from_agg_share(agg_share);

                if let Some(data) = &agg_share.data {
                    let as_bytes = data.get_encoded().map_err(|e| {
                        Error::RustError(format!("failed to encode agg share: {e}"))
                    })?;
                    shard_bytes_to_object(Self::agg_share_shard_keys(), as_bytes, &chunks_map)?;
                }

                js_sys::Reflect::set(
                    &chunks_map,
                    &JsValue::from_str(METADATA_KEY),
                    &serde_wasm_bindgen::to_value(&meta)
                        .expect("serialization should always succeed"),
                )?;

                self.state.storage().put_multiple_raw(chunks_map).await?;

                Response::from_json(&AggregateStoreMergeResp::Ok)
            }

            // Get the current aggregate share.
            //
            // Idempotent
            // Output: `DapAggregateShare`
            Some(bindings::AggregateStore::Get) => {
                let agg_share = self.get_agg_share().await?;
                Response::from_json(&agg_share)
            }

            // Mark this bucket as collected.
            //
            // Non-idempotent (do not retry)
            // Output: `()`
            Some(bindings::AggregateStore::MarkCollected) => {
                self.state.storage().put(COLLECTED_KEY, true).await?;
                self.collected = Some(true);
                Response::from_json(&())
            }

            // Get the value of the flag indicating whether this bucket has been collected.
            //
            // Idempotent
            // Output: `bool`
            Some(bindings::AggregateStore::CheckCollected) => {
                Response::from_json(&self.is_collected().await?)
            }

            _ => Err(int_err(format!(
                "AggregatesStore: unexpected request: method={:?}; path={:?}",
                req.method(),
                req.path()
            ))),
        }
    }

    fn should_cleanup_at(&self) -> Option<ScheduledTime> {
        const VAR_NAME: &str = "DAP_DURABLE_AGGREGATE_STORE_GC_AFTER_SECS";
        static SELF_DELETE_AFTER: OnceLock<Duration> = OnceLock::new();

        let duration = SELF_DELETE_AFTER.get_or_init(|| {
            Duration::from_secs(
                self.env
                    .var(VAR_NAME)
                    .map(|v| {
                        v.to_string().parse().unwrap_or_else(|e| {
                            panic!("{VAR_NAME} could not be parsed as a number of seconds: {e}")
                        })
                    })
                    .unwrap_or(60 * 60 * 24 * 7), // one week
            )
        });

        Some(ScheduledTime::from(*duration))
    }
}
