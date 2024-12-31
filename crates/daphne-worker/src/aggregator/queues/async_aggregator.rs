// Copyright (c) 2025 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use crate::{
    aggregator::App,
    elapsed, queue_messages_capnp,
    storage::{self, Do},
};
use daphne::{
    messages::{
        taskprov::TaskprovAdvertisement, AggregationJobId, PartialBatchSelector, ReportId,
        ReportMetadata, TaskId, Time,
    },
    roles::helper::handle_agg_job::ToInitializedReportsTransition,
    DapVersion,
};
use daphne_service_utils::{
    capnproto::{CapnprotoPayloadDecode, CapnprotoPayloadDecodeExt, CapnprotoPayloadEncode},
    compute_offload,
    durable_requests::bindings::{
        agg_job_response_store, aggregate_store_v2,
        replay_checker::{self, Command},
    },
};
use futures::{stream::FuturesUnordered, StreamExt, TryStreamExt};
use prio::codec::ParameterizedDecode;
use std::{
    collections::{HashMap, HashSet},
    future::Future,
    num::NonZeroUsize,
    time::Duration,
};
use worker::{MessageBatch, MessageExt, RawMessage};

fn deserialize<T: CapnprotoPayloadDecode>(message: &RawMessage) -> worker::Result<T> {
    let buf: worker::js_sys::Uint8Array = message.body().into();
    T::decode_from_bytes(&buf.to_vec()).map_err(|e| worker::Error::RustError(e.to_string()))
}

pub struct AsyncAggregationMessage<'s> {
    pub version: DapVersion,
    pub part_batch_sel: PartialBatchSelector,
    pub agg_job_id: AggregationJobId,
    pub initialize_reports: compute_offload::InitializeReports<'s>,
    pub taskprov_advertisement: Option<String>,
}

impl CapnprotoPayloadEncode for AsyncAggregationMessage<'_> {
    type Builder<'a> = queue_messages_capnp::async_aggregation_message::Builder<'a>;

    fn encode_to_builder(&self, mut builder: Self::Builder<'_>) {
        let Self {
            version,
            part_batch_sel,
            agg_job_id,
            initialize_reports,
            taskprov_advertisement,
        } = self;
        builder.set_version((*version).into());
        part_batch_sel.encode_to_builder(builder.reborrow().init_partial_batch_selector());
        agg_job_id.encode_to_builder(builder.reborrow().init_aggregation_job_id());
        initialize_reports.encode_to_builder(builder.reborrow().init_initialize_reports());
        match taskprov_advertisement.as_deref() {
            Some(ta) => builder
                .init_taskprov_advertisement()
                .set_some(ta.into())
                .unwrap(),
            None => builder.init_taskprov_advertisement().set_none(()),
        }
    }
}

impl CapnprotoPayloadDecode for AsyncAggregationMessage<'static> {
    type Reader<'a> = queue_messages_capnp::async_aggregation_message::Reader<'a>;

    fn decode_from_reader(reader: Self::Reader<'_>) -> capnp::Result<Self>
    where
        Self: Sized,
    {
        Ok(Self {
            version: reader.get_version()?.into(),
            agg_job_id: <_>::decode_from_reader(reader.get_aggregation_job_id()?)?,
            part_batch_sel: <_>::decode_from_reader(reader.get_partial_batch_selector()?)?,
            initialize_reports: <_>::decode_from_reader(reader.get_initialize_reports()?)?,
            taskprov_advertisement: match reader.get_taskprov_advertisement()?.which()? {
                queue_messages_capnp::option::Which::None(()) => None,
                queue_messages_capnp::option::Which::Some(text) => Some(text?.to_string()?),
            },
        })
    }
}

async fn shard_reports(
    durable: Do<'_>,
    task_id: &TaskId,
    time_precision: Time,
    agg_job_id: AggregationJobId,
    reports: impl Iterator<Item = ReportMetadata>,
) -> Result<HashSet<ReportId>, storage::Error> {
    let mut shards = HashMap::<_, Vec<_>>::new();
    for r in reports {
        let epoch = r.time - (r.time % time_precision);
        let shard = r.id.shard(NonZeroUsize::new(1024).unwrap());
        shards.entry((epoch, shard)).or_default().push(r.id);
    }

    futures::stream::iter(shards)
        .map(|((epoch, shard), report_ids)| async move {
            durable
                .with_retry()
                .request(Command::Check, (task_id, epoch, shard))
                .encode(&replay_checker::Request {
                    report_ids: report_ids.into(),
                    agg_job_id,
                })
                .send::<replay_checker::Response>()
                .await
                .map(|r| r.duplicates)
        })
        .buffer_unordered(usize::MAX)
        .try_fold(HashSet::new(), |mut acc, dups| async move {
            acc.extend(dups);
            Ok(acc)
        })
        .await
}

macro_rules! give_up {
    (retry $m:ident, err = $error:expr, $msg:literal) => {{
        $m.retry();
        give_up!(err = $error, $msg)
    }};
    (err = $error:expr, $msg:literal) => {{
        tracing::error!(error = ?$error, $msg);
        return;
    }}
}

/// Perform an aggregation job.
///
/// ## Note
/// There is a worst case scenario that this handler can't deal with.
///
/// Messages will be replayed if they fail, but the workers runtime will eventually give up on a
/// message after it's been retried a bunch of times, in that case the helper will never respond
/// positively to the poll request, possibly leaving the leader in an infinite loop state. The
/// leader can resubmit the work as many times as it wants to get out of this situation, but
/// implementers of the leader must be made aware of this.
//
// -----
//
// All of the IO in this function is idempotent. They can be spotted by looking at the `.await`
// expressions. The explanation is as follows:
//  1. Getting a task config. No writes performed.
//  2. Initializing the reports. Stateless.
//  3. The same aggregation job may replay it's own reports, this means replay checking is
//     idempotent. See the [ReplayChecker] durable object for more details.
//  4. Storing the aggregate share does not merge with any other aggregate share and simply
//     replaces the previous one, which will be identical.
//  5. Storing the aggregate response simply overwrites the previous response, which will be
//     identical.
//
#[tracing::instrument(skip_all, fields(?version, ?part_batch_sel, ?agg_job_id))]
pub async fn async_aggregate_one(
    app: &App,
    message: &RawMessage,
    AsyncAggregationMessage {
        version,
        part_batch_sel,
        agg_job_id,
        initialize_reports,
        taskprov_advertisement,
    }: AsyncAggregationMessage<'_>,
) {
    let task_id = &initialize_reports.task_id;
    tracing::debug!("getting task config");
    let taskprov_advertisement = match taskprov_advertisement
        .map(|s| TaskprovAdvertisement::parse_taskprov_advertisement(&s, task_id, version))
        .transpose()
    {
        Ok(taskprov_advertisement) => taskprov_advertisement,
        Err(e) => give_up!(err = e, "taskprov advertisement was malformed"),
    };

    // 1.
    let (task_config, get_task_config_duration) = timed(daphne::roles::resolve_task_config(
        app,
        &daphne::DapRequestMeta {
            version,
            media_type: None,
            task_id: *task_id,
            taskprov_advertisement,
        },
    ))
    .await;

    let task_config = match task_config {
        Ok(t) => t,
        Err(e) => give_up!(retry message, err = e, "not such task config"),
    };

    let agg_param = match daphne::DapAggregationParam::get_decoded_with_param(
        &task_config.vdaf,
        &initialize_reports.agg_param,
    ) {
        Ok(param) => param,
        Err(e) => give_up!(err = e, "dap aggregation parameter was illformed"),
    };

    // 2.
    tracing::debug!("initializing reports");
    let (initialized_reports, initialize_reports_duration) = match timed(
        app.compute_offload
            .compute::<_, compute_offload::InitializedReports>(
                "/compute_offload/initialize_reports",
                &initialize_reports,
            ),
    )
    .await
    {
        (Ok(init), duration) => (init, duration),
        (Err(e), _) => give_up!(retry message, err = e, "failed to initialize reports"),
    };

    let time_precision = task_config.time_precision;
    let state_machine = ToInitializedReportsTransition {
        task_id: *task_id,
        part_batch_sel,
        task_config,
    }
    .with_initialized_reports(agg_param, initialized_reports.reports);

    // 3.
    tracing::debug!("checking replays");
    let (state_machine, check_for_replays_duration) =
        timed(state_machine.check_for_replays(|report_ids| {
            let report_ids = report_ids.cloned().collect::<Vec<_>>();
            shard_reports(
                app.durable(),
                &initialize_reports.task_id,
                time_precision,
                agg_job_id,
                report_ids.into_iter(),
            )
        }))
        .await;

    let state_machine = match state_machine {
        Ok(st) => st,
        Err(e) => give_up!(retry message, err = e, "failed to check replays"),
    };

    let (span, agg_job_response) = match state_machine.finish() {
        Ok(output) => output,
        // this error is always caused by a bug in the code, it's not recoverable
        Err(e) => give_up!(err = e, "failed to finish aggregation"),
    };

    let ((), store_aggregate_share_duration) = timed(async {
        for (bucket, (share, _)) in span {
            let request = aggregate_store_v2::PutRequest {
                agg_job_id,
                agg_share_delta: share,
            };
            // 4.
            tracing::debug!("storing aggregate shares");
            let response = app
                .durable()
                .with_retry()
                .request(
                    aggregate_store_v2::Command::Put,
                    (version, task_id, &bucket),
                )
                .encode(&request)
                .send::<()>()
                .await;
            match response {
                Ok(()) => {}
                Err(e) => give_up!(retry message, err = e, "failed to store aggregate share"),
            }
        }
    })
    .await;

    // 5.
    tracing::debug!("storing aggregate job response");
    let (result, store_aggregate_job_response_duration) = timed(
        app.durable()
            .with_retry()
            .request(
                agg_job_response_store::Command::Put,
                (version, task_id, &agg_job_id),
            )
            .encode(&agg_job_response)
            .send::<()>(),
    )
    .await;

    match result {
        Ok(()) => {}
        Err(e) => give_up!(retry message, err = e, "failed to store aggregation response"),
    }

    tracing::info!(
        ?get_task_config_duration,
        ?initialize_reports_duration,
        ?check_for_replays_duration,
        ?store_aggregate_share_duration,
        ?store_aggregate_job_response_duration,
        "successfully aggregated"
    );
}

#[tracing::instrument(skip_all)]
pub async fn async_aggregate_batch(app: App, message_batch: MessageBatch<()>) {
    tracing::info!(
        count = message_batch.raw_iter().count(),
        "handling message batch"
    );
    let app = &app;
    message_batch
        .raw_iter()
        .map(|m| async move {
            let message = match deserialize(&m) {
                Ok(m) => m,
                Err(e) => give_up!(err = e, "failed to deserialize replay queue message"),
            };
            async_aggregate_one(app, &m, message).await
        })
        .collect::<FuturesUnordered<_>>()
        .collect::<()>()
        .await;
}

async fn timed<F>(future: F) -> (F::Output, Duration)
where
    F: Future,
{
    let now = worker::Date::now();
    let result = future.await;
    (result, elapsed(&now))
}
