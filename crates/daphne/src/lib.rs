// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! This crate implements the core protocol logic for the Distributed Aggregation Protocol
//! ([DAP](https://datatracker.ietf.org/doc/draft-ietf-ppm-dap/)) standard under development in the
//! PPM working group of the IETF. See [`VdafConfig`] for a listing of supported
//! [VDAFs](https://github.com/cfrg/draft-irtf-cfrg-vdaf).
//!
//! Daphne implements:
//! * draft-ietf-ppm-dap-02
//!    * VDAF: draft-irtf-cfrg-vdaf-03
//!    * Taskprov extension: draft-wang-ppm-dap-taskprov-02
//! * draft-ietf-ppm-dap-09
//!    * VDAF: draft-irtf-cfrg-vdaf-08
//!    * Taskprov extension: draft-wang-ppm-dap-taskprov-06
//!
//! Daphne does not provide the complete, end-to-end functionality of any party in the protocol.
//! Instead, it defines traits for the functionalities that a concrete instantiation of the
//! protocol is required to implement. For example, the `daphne-worker` crate implements a backend
//! for the DAP Leader and Helper. See the [`roles`] module for details.
//!
//! Daphne is not yet feature complete. Known issues include:
//!
//! * The collect sub-protocol has not yet been fully implemented. In particular, Daphne Aggreators
//!   do not check properly if batch intervals overlap across collect requests. Note that this
//!   feature is privacy-critical and implementation is planned. See
//!   <https://github.com/cloudflare/daphne/issues/45> for details.
//!
//! * Daphne is not compatible with DAP tasks whose maximum batch lifetime is longer than one.
//!
//! * Aborts are not handled precisely as specified. In particular, some fields in the "Problem
//!   Details" document are omitted.
//!
//! * Daphne does not implement a complete DAP Client or Collector. However, methods are provided
//!   on [`VdafConfig`] for producing reports and consuming aggregate results.
//!
//! * Daphne does not yet support deletion of collection jobs:
//!
//!     > The leader MUST remove a collect job's results when the collector sends an HTTP DELETE
//!     > request to the collect job  URI. The leader responds with HTTP status 204 No Content for
//!     > requests to a collect job URI whose results have been removed.

pub mod audit_log;
pub mod constants;
pub mod error;
pub mod hpke;
pub mod messages;
pub mod metrics;
pub mod pine;
pub(crate) mod protocol;
pub mod roles;
pub mod taskprov;
#[cfg(any(test, feature = "test-utils"))]
pub mod testing;
pub mod vdaf;

use crate::{
    error::DapAbort,
    hpke::HpkeReceiverConfig,
    messages::{
        BatchId, BatchSelector, Collection, Duration, Interval, PartialBatchSelector, ReportId,
        TaskId, Time,
    },
    vdaf::{
        Prio3Config, VdafAggregateShare, VdafConfig, VdafPrepShare, VdafPrepState, VdafVerifyKey,
    },
};
use constants::DapMediaType;
pub use error::DapError;
use error::FatalDapError;
use hpke::{HpkeConfig, HpkeKemId};
use messages::encode_base64url;
#[cfg(feature = "experimental")]
use prio::codec::Decode;
#[cfg(feature = "experimental")]
use prio::vdaf::poplar1::Poplar1AggregationParam;
use prio::{
    codec::{CodecError, Encode, ParameterizedDecode, ParameterizedEncode},
    vdaf::Aggregatable as AggregatableTrait,
};
pub use protocol::aggregator::ReplayProtection;
use serde::{Deserialize, Serialize};
use std::{
    cmp::{max, min},
    collections::{HashMap, HashSet},
    fmt::Debug,
    num::NonZeroUsize,
    str::FromStr,
};
use url::Url;
#[cfg(feature = "experimental")]
use vdaf::mastic::MasticWeight;

pub use messages::request::{DapRequest, DapResource, DapResponse};
pub use protocol::aggregator::{
    EarlyReportState, EarlyReportStateConsumed, EarlyReportStateInitialized,
};

/// DAP version used for a task.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[cfg_attr(any(test, feature = "test-utils"), derive(deepsize::DeepSizeOf))]
pub enum DapVersion {
    #[serde(rename = "v09")]
    #[default]
    Draft09,

    #[serde(rename = "v10")]
    Latest,
}

impl FromStr for DapVersion {
    type Err = DapAbort;
    fn from_str(version: &str) -> Result<Self, Self::Err> {
        match version {
            "v09" => Ok(DapVersion::Draft09),
            "v10" => Ok(DapVersion::Latest),
            _ => Err(DapAbort::version_unknown()),
        }
    }
}

impl AsRef<str> for DapVersion {
    fn as_ref(&self) -> &str {
        match self {
            DapVersion::Draft09 => "v09",
            DapVersion::Latest => "v10",
        }
    }
}

impl std::fmt::Display for DapVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_ref())
    }
}

/// Global DAP parameters common across tasks.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[cfg_attr(any(test, feature = "test-utils"), derive(deepsize::DeepSizeOf))]
pub struct DapGlobalConfig {
    /// Maximum interval duration permitted in [`CollectionReq`](messages::CollectionReq).
    ///
    /// Prevents Collectors from requesting wide range or reports.
    pub max_batch_duration: Duration,

    /// Lower bound of an acceptable batch interval for collect requests.
    /// Batch intervals cannot start more than `min_batch_interval_start`
    /// apart from the current batch interval.
    pub min_batch_interval_start: Duration,

    /// Upper bound of an acceptable batch interval for collect requests.
    /// Batch intervals cannot end more than `max_batch_interval_end`
    /// apart from the current batch interval.
    pub max_batch_interval_end: Duration,

    /// HPKE KEM types that are supported. Used when generating HPKE
    /// receiver config.
    pub supported_hpke_kems: Vec<HpkeKemId>,

    /// draft-wang-ppm-dap-taskprov: Indicates if the taskprov extension is enabled.
    #[serde(default)]
    pub allow_taskprov: bool,

    /// Default number of aggregate span shards for a task.
    ///
    /// At the end of an aggregation job, each Aggregator produces a [`DapAggregateSpan`] that maps
    /// buckets to aggregate shares. A bucket consists of a batch window (either the batch ID or a
    /// window of time, depending on the DAP query type) and a shard. Sharding is intended to allow
    /// an implementation to spread transactions across multiple instances of the backend storage
    /// mechanism (e.g., durable objects in the case of Cloudflare Workers).
    ///
    /// # Notes
    ///
    /// 1. The default number of shards is 1; the number of shards MUST NOT be 0.
    ///
    /// 2. Currently [`taskprov`] uses the default for choosing the number of shards for a task.
    ///
    /// 3. WARNING: decreasing the number of shards for a task may result on data loss, as
    ///    collection may fail to collect aggregate shares for some shards.
    ///
    /// 4. WARNING: increasing the number of shards for a task breaks replay protection for reports
    ///    that have already been aggregated.
    #[serde(default = "default_num_agg_span_shards")]
    pub default_num_agg_span_shards: NonZeroUsize,
}

fn default_num_agg_span_shards() -> NonZeroUsize {
    NonZeroUsize::new(1).unwrap()
}

#[cfg(test)]
impl Default for DapGlobalConfig {
    fn default() -> Self {
        Self {
            max_batch_duration: 60,
            min_batch_interval_start: 60,
            max_batch_interval_end: 60,
            supported_hpke_kems: vec![HpkeKemId::X25519HkdfSha256],
            allow_taskprov: false,
            default_num_agg_span_shards: NonZeroUsize::new(1).unwrap(),
        }
    }
}

impl DapGlobalConfig {
    /// Generate a list of HPKE receiver configurations, one for each element of supported KEM
    /// algorithm. `first_config_id` is used as the first config ID; subsequent IDs are chosen by
    /// incrementing `first_config_id`.
    pub fn gen_hpke_receiver_config_list(
        &self,
        first_config_id: u8,
    ) -> Result<Vec<HpkeReceiverConfig>, DapError> {
        if u8::try_from(self.supported_hpke_kems.len()).is_err() {
            return Err(DapError::Fatal(FatalDapError(format!(
                "maximum config list length is 256: got {}",
                self.supported_hpke_kems.len()
            ))));
        }

        self.supported_hpke_kems
            .iter()
            .enumerate()
            .map(move |(i, kem_id)| {
                let (config_id, _overflowed) = first_config_id.overflowing_add(
                    i.try_into()
                        .expect("there shouldn't be more than 256 KEM ids"),
                );
                HpkeReceiverConfig::gen(config_id, *kem_id)
            })
            .collect()
    }
}

/// DAP Query configuration.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(any(test, feature = "test-utils"), derive(deepsize::DeepSizeOf))]
pub enum DapQueryConfig {
    /// The "time-interval" query type. Each report in the batch must fall into the time interval
    /// specified by the query.
    TimeInterval,

    /// The "fixed-size" query type where by the Leader assigns reports to arbitrary batches
    /// identified by batch IDs. This type includes an optional maximum batch size: if set, then
    /// Aggregators are meant to stop aggregating reports when this limit is reached.
    FixedSize {
        #[serde(default)]
        max_batch_size: Option<u64>,
    },
}

impl DapQueryConfig {
    pub(crate) fn is_valid_part_batch_sel(&self, part_batch_sel: &PartialBatchSelector) -> bool {
        matches!(
            (&self, part_batch_sel),
            (
                Self::TimeInterval { .. },
                PartialBatchSelector::TimeInterval
            ) | (
                Self::FixedSize { .. },
                PartialBatchSelector::FixedSizeByBatchId { .. }
            )
        )
    }

    pub(crate) fn is_valid_batch_sel(&self, batch_sel: &BatchSelector) -> bool {
        matches!(
            (&self, batch_sel),
            (
                Self::TimeInterval { .. },
                BatchSelector::TimeInterval { .. }
            ) | (
                Self::FixedSize { .. },
                BatchSelector::FixedSizeByBatchId { .. }
            )
        )
    }
}

impl std::fmt::Display for DapQueryConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TimeInterval => write!(f, "time_interval"),
            Self::FixedSize { .. } => write!(f, "fixed_size"),
        }
    }
}

/// A batch bucket.
///
/// A bucket is the smallest, disjoint set of reports that can be queried: For time-interval
/// queries, the bucket to which a report is assigned is determined by truncating its timestamp by
/// the task's `time_precision` parameter; for fixed-size queries, the span consists of a single
/// bucket, which is the batch determined by the batch ID (i.e., the partial batch selector).
#[derive(Debug, Clone, Eq, Hash, PartialEq)]
#[cfg_attr(any(test, feature = "test-utils"), derive(deepsize::DeepSizeOf))]
pub enum DapBatchBucket {
    FixedSize { batch_id: BatchId, shard: usize },
    TimeInterval { batch_window: Time, shard: usize },
}

impl DapBatchBucket {
    fn shard(&self) -> usize {
        match self {
            Self::TimeInterval {
                batch_window: _,
                shard,
            }
            | Self::FixedSize { batch_id: _, shard } => *shard,
        }
    }
}

impl std::fmt::Display for DapBatchBucket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TimeInterval { batch_window, .. } => write!(f, "window/{batch_window}")?,
            Self::FixedSize { batch_id, .. } => write!(f, "batch/{}", batch_id.to_hex())?,
        };

        let shard = self.shard();

        // Append the shard number to the string for all shards but the first. This is for
        // backwards compatibility with already deployed tasks.
        if shard > 0 {
            write!(f, "/shard/{shard}")?;
        }

        Ok(())
    }
}

/// A set of values related to reports in the same bucket.
#[derive(Debug)]
pub struct DapAggregateSpan<T> {
    span: HashMap<DapBatchBucket, (T, Vec<(ReportId, Time)>)>,
}

// We can't derive default because it will require T to be Default, which we don't need.
impl<T> Default for DapAggregateSpan<T> {
    fn default() -> Self {
        Self {
            span: Default::default(),
        }
    }
}

impl<T> IntoIterator for DapAggregateSpan<T> {
    type IntoIter = <HashMap<DapBatchBucket, (T, Vec<(ReportId, Time)>)> as IntoIterator>::IntoIter;

    type Item = <Self::IntoIter as Iterator>::Item;

    fn into_iter(self) -> Self::IntoIter {
        self.span.into_iter()
    }
}

impl ReportId {
    fn shard(&self, num_shards: NonZeroUsize) -> usize {
        // NOTE This sharding scheme does not evenly distribute reports across all shards.
        //
        // First, the clients are supposed to choose the report ID at random; by finding collisions
        // on the first 8 bytes of SHA256, a coalition of clients can try to overwhelm a single
        // shard. This could be addressed in the future by replacing SHA256 with HMAC-SHA256 with a
        // securely provisioned key.
        //
        // Second, unless the number of shards is a power of 2 (4, 8, 16, 32, ..., 128, ...),
        // dividing the index by the number of shards and taking the remainder will result in some
        // shards getting more reports than others.
        let index = u32::from_le_bytes(
            ring::digest::digest(&ring::digest::SHA256, self.as_ref()).as_ref()[..4]
                .try_into()
                .unwrap(),
        );
        usize::try_from(index).unwrap() % num_shards
    }
}

impl DapAggregateSpan<DapAggregateShare> {
    pub(crate) fn add_out_share(
        &mut self,
        task_config: &DapTaskConfig,
        part_batch_sel: &PartialBatchSelector,
        report_id: ReportId,
        time: Time,
        data: VdafAggregateShare,
    ) -> Result<(), DapError> {
        if !task_config.query.is_valid_part_batch_sel(part_batch_sel) {
            return Err(fatal_error!(
                err = "partial batch selector not compatible with task",
            ));
        }

        let shard = report_id.shard(task_config.num_agg_span_shards);
        let bucket = match part_batch_sel {
            PartialBatchSelector::TimeInterval => DapBatchBucket::TimeInterval {
                batch_window: task_config.quantized_time_lower_bound(time),
                shard,
            },
            PartialBatchSelector::FixedSizeByBatchId { batch_id } => DapBatchBucket::FixedSize {
                batch_id: *batch_id,
                shard,
            },
        };

        let (agg_share, reports) = self.span.entry(bucket).or_default();
        agg_share.add_out_share(&report_id, time, data)?;
        reports.push((report_id, time));
        Ok(())
    }

    /// Merge each aggregate share in the span into one aggregate share.
    ///
    /// # Panics
    ///
    /// Panics if two aggregates shares in the span have incompatible types.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn collapsed(self) -> DapAggregateShare {
        self.span
            .into_iter()
            .map(|(_bucket, (agg_share_for_bucket, _reports))| agg_share_for_bucket)
            .reduce(|mut agg_share, agg_share_for_bucket| {
                agg_share.merge(agg_share_for_bucket).unwrap();
                agg_share
            })
            .unwrap_or_default()
    }

    /// Merge the span with another.
    pub fn merge(&mut self, other: Self) -> Result<(), DapError> {
        for (bucket, (other_agg_share, mut other_reports)) in other {
            let (agg_share, reports) = self.span.entry(bucket).or_default();
            agg_share.merge(other_agg_share)?;
            reports.append(&mut other_reports);
        }
        Ok(())
    }
}

impl<T> DapAggregateSpan<T> {
    pub(crate) fn report_count(&self) -> usize {
        self.span
            .iter()
            .map(|(_bucket, (_agg_share, report_ids))| report_ids.len())
            .sum()
    }

    /// Return an iterator over the aggregate span.
    pub fn iter(&self) -> impl Iterator<Item = (&DapBatchBucket, &(T, Vec<(ReportId, Time)>))> {
        self.span.iter()
    }
}

impl<T> FromIterator<(DapBatchBucket, (T, Vec<(ReportId, Time)>))> for DapAggregateSpan<T> {
    fn from_iter<I>(iter: I) -> Self
    where
        I: IntoIterator<Item = (DapBatchBucket, (T, Vec<(ReportId, Time)>))>,
    {
        Self {
            span: iter.into_iter().collect(),
        }
    }
}

impl<T> Extend<(DapBatchBucket, (T, Vec<(ReportId, Time)>))> for DapAggregateSpan<T> {
    fn extend<I>(&mut self, iter: I)
    where
        I: IntoIterator<Item = (DapBatchBucket, (T, Vec<(ReportId, Time)>))>,
    {
        self.span.extend(iter);
    }
}

impl FromIterator<(DapBatchBucket, (ReportId, Time))> for DapAggregateSpan<()> {
    fn from_iter<I>(iter: I) -> Self
    where
        I: IntoIterator<Item = (DapBatchBucket, (ReportId, Time))>,
    {
        let mut this = Self::default();
        this.extend(iter);
        this
    }
}

impl Extend<(DapBatchBucket, (ReportId, Time))> for DapAggregateSpan<()> {
    fn extend<I>(&mut self, iter: I)
    where
        I: IntoIterator<Item = (DapBatchBucket, (ReportId, Time))>,
    {
        for (k, v) in iter {
            self.span
                .entry(k)
                .or_insert_with(|| ((), Vec::new()))
                .1
                .push(v);
        }
    }
}

/// Method for configuring tasks.
#[derive(Clone, Default, Deserialize, Serialize)]
#[cfg_attr(any(test, feature = "test-utils"), derive(PartialEq, Debug))]
pub enum DapTaskConfigMethod {
    /// draft-wang-ppm-dap-taskprov
    Taskprov {
        /// `TaskConfig.task_info`. If not set, then the task info is unknown.
        info: Option<Vec<u8>>,
    },

    #[default]
    Unknown,
}

/// Base parameters used to configure a DAP task.
#[derive(Debug)]
pub struct DapTaskParameters {
    /// The protocol version (i.e., which draft).
    pub version: DapVersion,

    /// Base URL of the Leader.
    pub leader_url: Url,

    /// Base URL of the Helper.
    pub helper_url: Url,

    /// Report granularity. Used by the Client to truncate the timestamp and by the Aggregators to
    /// constrain the batch interval of time=interval queries.
    pub time_precision: Duration,

    /// The amount of time before the task should expire.
    pub lifetime: Duration,

    /// The smallest batch permitted for this task.
    pub min_batch_size: u64,

    /// The query configuration for this task.
    pub query: DapQueryConfig,

    /// The VDAF configuration for this task.
    pub vdaf: VdafConfig,

    /// Number of aggregate span shards. See [`DapGlobalConfig`] for details.
    pub num_agg_span_shards: NonZeroUsize,
}

#[cfg(any(test, feature = "test-utils"))]
impl DapTaskParameters {
    /// Construct a new task config using the taskprov extension. Return the task ID and the
    /// taskprov advertisement encoded as a base64url string.
    #[allow(clippy::type_complexity)]
    pub fn to_config_with_taskprov(
        &self,
        task_info: Vec<u8>,
        now: Time,
        vdaf_verify_key_init: &[u8; 32],
        collector_hpke_config: &HpkeConfig,
    ) -> Result<(DapTaskConfig, TaskId, String), DapError> {
        let taskprov_config = messages::taskprov::TaskConfig {
            task_info,
            leader_url: messages::taskprov::UrlBytes {
                bytes: self.leader_url.to_string().into_bytes(),
            },
            helper_url: messages::taskprov::UrlBytes {
                bytes: self.helper_url.to_string().into_bytes(),
            },
            query_config: messages::taskprov::QueryConfig {
                time_precision: self.time_precision,
                max_batch_query_count: 1,
                min_batch_size: self.min_batch_size.try_into().unwrap(),
                var: (&self.query).try_into()?,
            },
            task_expiration: now + 86400 * 14, // expires in two weeks
            vdaf_config: messages::taskprov::VdafConfig {
                dp_config: messages::taskprov::DpConfig::None,
                var: (&self.vdaf).try_into()?,
            },
        };

        let encoded_taskprov_config = taskprov_config
            .get_encoded_with_param(&self.version)
            .map_err(DapError::encoding)?;
        let task_id = taskprov::compute_task_id(&encoded_taskprov_config);

        // Compute the DAP task config.
        let task_config = taskprov::DapTaskConfigNeedsOptIn::try_from_taskprov(
            self.version,
            &task_id,
            taskprov_config,
            vdaf_verify_key_init,
            collector_hpke_config,
        )
        .unwrap()
        .into_opted_in(&taskprov::OptInParam {
            not_before: now,
            num_agg_span_shards: self.num_agg_span_shards,
        });

        let taskprov_advertisement = encode_base64url(&encoded_taskprov_config);

        Ok((task_config, task_id, taskprov_advertisement))
    }
}

#[cfg(any(test, feature = "test-utils"))]
impl Default for DapTaskParameters {
    fn default() -> Self {
        Self {
            version: Default::default(),
            leader_url: "https://leader.example.com/".parse().unwrap(),
            helper_url: "https://helper.example.com/".parse().unwrap(),
            time_precision: 3600, // 1 hour
            lifetime: 86400 * 14, // two weeks
            min_batch_size: 10,
            query: DapQueryConfig::TimeInterval,
            vdaf: VdafConfig::Prio2 { dimension: 10 },
            num_agg_span_shards: NonZeroUsize::new(1).unwrap(),
        }
    }
}

/// Per-task DAP parameters.
#[derive(Clone, Deserialize, Serialize)]
#[cfg_attr(any(test, feature = "test-utils"), derive(PartialEq, Debug))]
#[serde(try_from = "ShadowDapTaskConfig")]
pub struct DapTaskConfig {
    /// Same as [`DapTaskParameters`].
    pub version: DapVersion,
    pub leader_url: Url,
    pub helper_url: Url,
    pub time_precision: Duration,
    pub min_batch_size: u64,
    pub query: DapQueryConfig,
    pub vdaf: VdafConfig,

    /// The time at which the task first became valid.
    pub not_before: Time,

    /// The time at which the task expires.
    pub not_after: Time,

    /// VDAF verification key shared by the Aggregators. Used to aggregate reports.
    pub vdaf_verify_key: VdafVerifyKey,

    /// The Collector's HPKE configuration for this task.
    pub collector_hpke_config: HpkeConfig,

    /// Method by which the task was configured.
    pub method: DapTaskConfigMethod,

    /// Number of aggregate span shards for this task. See [`DapGlobalConfig`] for details.
    #[serde(default = "default_num_agg_span_shards")]
    pub num_agg_span_shards: NonZeroUsize,
}

#[derive(Deserialize, Serialize)]
struct ShadowDapTaskConfig {
    version: DapVersion,
    leader_url: Url,
    helper_url: Url,
    time_precision: Duration,
    min_batch_size: u64,
    query: DapQueryConfig,
    vdaf: VdafConfig,
    not_after: Time,
    not_before: Time,
    vdaf_verify_key: VdafVerifyKey,
    collector_hpke_config: HpkeConfig,
    #[serde(default)]
    method: DapTaskConfigMethod,

    // Deprecated. Indicates that the task was configured via draft-wang-ppm-taskprov. This flag
    // was replaced by `method`.
    #[serde(default, rename = "taskprov")]
    deprecated_taskprov: bool,

    num_agg_span_shards: NonZeroUsize,
}

impl TryFrom<ShadowDapTaskConfig> for DapTaskConfig {
    type Error = DapError;

    fn try_from(shadow: ShadowDapTaskConfig) -> Result<Self, DapError> {
        Ok(Self {
            version: shadow.version,
            leader_url: shadow.leader_url,
            helper_url: shadow.helper_url,
            time_precision: shadow.time_precision,
            min_batch_size: shadow.min_batch_size,
            query: shadow.query,
            vdaf: shadow.vdaf,
            not_before: shadow.not_before,
            not_after: shadow.not_after,
            vdaf_verify_key: shadow.vdaf_verify_key,
            collector_hpke_config: shadow.collector_hpke_config,
            method: match shadow.method {
                // If the configuration method is unknown or unspecified, but the deprecated
                // taskprov flag is set, then set the method to taskprov with unknown info.
                DapTaskConfigMethod::Unknown if shadow.deprecated_taskprov => {
                    DapTaskConfigMethod::Taskprov { info: None }
                }
                method => method,
            },
            num_agg_span_shards: shadow.num_agg_span_shards,
        })
    }
}

#[cfg(any(test, feature = "test-utils"))]
impl deepsize::DeepSizeOf for DapTaskConfig {
    fn deep_size_of_children(&self, context: &mut deepsize::Context) -> usize {
        self.version.deep_size_of_children(context)
            + std::mem::size_of_val(self.leader_url.as_str())
            + std::mem::size_of_val(self.helper_url.as_str())
            + self.time_precision.deep_size_of_children(context)
            + self.not_before.deep_size_of_children(context)
            + self.not_after.deep_size_of_children(context)
            + self.min_batch_size.deep_size_of_children(context)
            + self.query.deep_size_of_children(context)
            + self.vdaf.deep_size_of_children(context)
            + self.vdaf_verify_key.deep_size_of_children(context)
            + self.collector_hpke_config.deep_size_of_children(context)
    }
}

impl DapTaskConfig {
    /// Convert at timestamp `now` into an [`Interval`] that contains it. The timestamp is the
    /// numbre of seconds since the beginning of UNIX time.
    #[cfg(test)]
    pub fn query_for_current_batch_window(&self, now: u64) -> crate::messages::Query {
        let start = self.quantized_time_lower_bound(now);
        crate::messages::Query::TimeInterval {
            batch_interval: crate::messages::Interval {
                start,
                duration: self.time_precision,
            },
        }
    }

    /// Return the greatest multiple of the `time_precision` which is less than or equal to the
    /// specified time.
    pub fn quantized_time_lower_bound(&self, time: Time) -> Time {
        time - (time % self.time_precision)
    }

    /// Return the least multiple of the `time_precision` which is greater than the specified time.
    pub fn quantized_time_upper_bound(&self, time: Time) -> Time {
        self.quantized_time_lower_bound(time) + self.time_precision
    }

    /// Return the batch span determined by the given batch selector. The span includes every
    /// bucket to which a report that matches the batch selector could be assigned.
    pub fn batch_span_for_sel(
        &self,
        batch_sel: &BatchSelector,
    ) -> Result<HashSet<DapBatchBucket>, DapError> {
        if !self.query.is_valid_batch_sel(batch_sel) {
            return Err(fatal_error!(
                err = "batch selector not compatible with task"
            ));
        }

        let num_agg_span_shards = usize::from(self.num_agg_span_shards);
        match batch_sel {
            BatchSelector::TimeInterval {
                batch_interval: Interval { start, duration },
            } => {
                let windows = duration / self.time_precision;
                let mut span =
                    HashSet::with_capacity(usize::try_from(windows).unwrap() * num_agg_span_shards);
                for i in 0..windows {
                    for shard in 0..num_agg_span_shards {
                        span.insert(DapBatchBucket::TimeInterval {
                            batch_window: start + i * self.time_precision,
                            shard,
                        });
                    }
                }
                Ok(span)
            }
            BatchSelector::FixedSizeByBatchId { batch_id } => {
                let mut span = HashSet::with_capacity(num_agg_span_shards);
                for shard in 0..num_agg_span_shards {
                    span.insert(DapBatchBucket::FixedSize {
                        batch_id: *batch_id,
                        shard,
                    });
                }
                Ok(span)
            }
        }
    }

    /// Check if the batch size is too small. Returns an error if the report count is too large.
    pub(crate) fn is_report_count_compatible(
        &self,
        task_id: &TaskId,
        report_count: u64,
    ) -> Result<bool, DapAbort> {
        match self.query {
            DapQueryConfig::FixedSize {
                max_batch_size: Some(max_batch_size),
            } => {
                if report_count > max_batch_size {
                    return Err(DapAbort::InvalidBatchSize {
                        detail: format!(
                            "Report count ({report_count}) exceeds maximum ({max_batch_size})"
                        ),
                        task_id: *task_id,
                    });
                }
            }
            DapQueryConfig::TimeInterval
            | DapQueryConfig::FixedSize {
                max_batch_size: None,
            } => (),
        };

        Ok(report_count >= self.min_batch_size)
    }

    /// Leader: Resolve taskprov advertisement to send in a request to the Helper.
    pub(crate) fn resolve_taskprove_advertisement(&self) -> Result<Option<String>, DapError> {
        if let DapTaskConfigMethod::Taskprov { info } = &self.method {
            if info.is_none() {
                // The task config indicates that the configuration method was taskprov, but we
                // don't have enough information to construct the advertisement.
                return Err(fatal_error!(
                    err = "not enough information to resolve taskprov advertisement"
                ));
            }

            let encoded_taskprov_config = messages::taskprov::TaskConfig::try_from(self)?
                .get_encoded_with_param(&self.version)
                .map_err(DapError::encoding)?;
            Ok(Some(encode_base64url(encoded_taskprov_config)))
        } else {
            Ok(None)
        }
    }

    /// Returns true if the task configuration method is taskprov.
    pub fn method_is_taskprov(&self) -> bool {
        matches!(self.method, DapTaskConfigMethod::Taskprov { .. })
    }
}

impl AsRef<DapTaskConfig> for DapTaskConfig {
    fn as_ref(&self) -> &Self {
        self
    }
}

/// A measurement from which a Client generates a report.
#[derive(Clone, Deserialize, Serialize)]
#[cfg_attr(any(test, feature = "test-utils"), derive(Debug))]
#[serde(rename_all = "snake_case")]
pub enum DapMeasurement {
    U64(u64),
    U32Vec(Vec<u32>),
    U64Vec(Vec<u64>),
    U128Vec(Vec<u128>),
    #[cfg(feature = "experimental")]
    Mastic {
        input: Vec<u8>,
        weight: MasticWeight,
    },
    F64Vec(Vec<f64>),
}

/// An aggregation parameter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DapAggregationParam {
    Empty,
    #[cfg(feature = "experimental")]
    Mastic(Poplar1AggregationParam),
}

#[cfg(any(test, feature = "test-utils"))]
impl deepsize::DeepSizeOf for DapAggregationParam {
    fn deep_size_of(&self) -> usize {
        0
    }

    fn deep_size_of_children(&self, _context: &mut deepsize::Context) -> usize {
        0
    }
}

impl Encode for DapAggregationParam {
    fn encode(&self, bytes: &mut Vec<u8>) -> Result<(), CodecError> {
        let _ = bytes;
        match self {
            Self::Empty => Ok(()),
            #[cfg(feature = "experimental")]
            Self::Mastic(agg_param) => agg_param.encode(bytes),
        }
    }
}

impl ParameterizedDecode<VdafConfig> for DapAggregationParam {
    fn decode_with_param(
        vdaf_config: &VdafConfig,
        bytes: &mut std::io::Cursor<&[u8]>,
    ) -> Result<Self, CodecError> {
        let _ = bytes;
        match vdaf_config {
            #[cfg(feature = "experimental")]
            VdafConfig::Mastic { .. } => Ok(Self::Mastic(Poplar1AggregationParam::decode(bytes)?)),
            _ => Ok(Self::Empty),
        }
    }
}

/// The aggregate result computed by the Collector.
#[derive(Debug, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DapAggregateResult {
    U32Vec(Vec<u32>),
    U64(u64),
    U64Vec(Vec<u64>),
    U128(u128),
    U128Vec(Vec<u128>),
    F64Vec(Vec<f64>),
}

#[derive(Clone)]
#[cfg_attr(any(test, feature = "test-utils"), derive(Debug, deepsize::DeepSizeOf))]
pub(crate) struct AggregationJobReportState {
    prep_state: VdafPrepState,
    time: Time,
    report_id: ReportId,
}

/// Aggregator state during an aggregation job.
#[derive(Clone)]
#[cfg_attr(any(test, feature = "test-utils"), derive(Debug, deepsize::DeepSizeOf))]
pub struct DapAggregationJobState {
    pub(crate) seq: Vec<AggregationJobReportState>,
    part_batch_sel: PartialBatchSelector,
}

impl DapAggregationJobState {
    /// Count the number of reports that can still be aggregated.
    pub fn report_count(&self) -> usize {
        self.seq.len()
    }
}

/// An aggregate share computed by combining a set of output shares.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[cfg_attr(any(test, feature = "test-utils"), derive(deepsize::DeepSizeOf))]
pub struct DapAggregateShare {
    /// Number of reports in the batch.
    pub report_count: u64,
    pub min_time: Time,
    pub max_time: Time,
    /// Batch checkusm.
    pub checksum: [u8; 32],
    pub data: Option<VdafAggregateShare>,
}

impl DapAggregateShare {
    /// Merge two aggregate shares. This method is run by an Aggregator.
    pub fn merge(&mut self, other: DapAggregateShare) -> Result<(), DapError> {
        // Update the aggregate share data.
        match (self.data.as_mut(), other.data) {
            (_, None) => (),
            (None, Some(data)) => {
                self.data = Some(data);
            }
            (Some(VdafAggregateShare::Field64(left)), Some(VdafAggregateShare::Field64(right))) => {
                left.merge(&right).map_err(
                    |e| fatal_error!(err = ?e, "failed to merge 64bit wide vdaf shares"),
                )?;
            }
            (
                Some(VdafAggregateShare::Field128(left)),
                Some(VdafAggregateShare::Field128(right)),
            ) => {
                left.merge(&right).map_err(
                    |e| fatal_error!(err = ?e, "failed to merge 128bit wide vdaf shares"),
                )?;
            }
            (Some(VdafAggregateShare::Field32(left)), Some(VdafAggregateShare::Field32(right))) => {
                left.merge(&right)
                    .map_err(|e| fatal_error!(err = ?e, "failed to merge prio2 vdaf shares"))?;
            }

            _ => return Err(fatal_error!(err = "invalid aggregate share merge")),
        };

        if self.report_count == 0 {
            // No interval yet, just copy other's interval
            self.min_time = other.min_time;
            self.max_time = other.max_time;
        } else if other.report_count > 0 {
            // Note that we don't merge if other.report_count == 0, as in that case the timestamps
            // are 0 too, and thus bad to merge!
            self.min_time = min(self.min_time, other.min_time);
            self.max_time = max(self.max_time, other.max_time);
        } else {
            // Do nothing!
        }
        self.report_count += other.report_count;
        for (x, y) in self.checksum.iter_mut().zip(other.checksum) {
            *x ^= y;
        }
        Ok(())
    }

    /// Return `true` if the aggregate share contains no reports.
    pub fn empty(&self) -> bool {
        self.report_count == 0
    }

    /// Set the aggregate share to zero.
    pub fn reset(&mut self) {
        self.report_count = 0;
        self.min_time = 0;
        self.max_time = 0;
        self.checksum = [0; 32];
        self.data = None;
    }

    pub(crate) fn add_out_share(
        &mut self,
        report_id: &ReportId,
        time: Time,
        data: VdafAggregateShare,
    ) -> Result<(), DapError> {
        let checksum = ring::digest::digest(&ring::digest::SHA256, report_id.as_ref());
        self.merge(DapAggregateShare {
            report_count: 1,
            min_time: time,
            max_time: time,
            checksum: checksum.as_ref().try_into().unwrap(),
            data: Some(data),
        })?;
        Ok(())
    }
}

/// DAP sender role.
#[derive(Clone, Copy, Debug)]
pub enum DapSender {
    Client,
    Collector,
    Helper,
    Leader,
}

/// Status of a collect job.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(any(test, feature = "test-utils"), derive(deepsize::DeepSizeOf))]
pub enum DapCollectionJob {
    Done(Collection),
    Pending,
    Unknown,
}

/// Telemetry information for the leader's processing loop.
//
// TODO This is used for tests. Perhaps Prometheus metrics would be sufficient?
#[derive(Debug, Default, Deserialize, Serialize)]
pub struct DapLeaderProcessTelemetry {
    /// Number of collect requests completed.
    pub reports_collected: u64,

    /// The number of reports aggregated.
    pub reports_aggregated: u64,

    /// The number of reports processed.
    pub reports_processed: u64,
}
