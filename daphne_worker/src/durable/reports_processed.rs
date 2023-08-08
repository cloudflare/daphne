// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use crate::{
    config::DaphneWorkerConfig,
    durable::{create_span_from_request, state_get, BINDING_DAP_REPORTS_PROCESSED},
    initialize_tracing, int_err,
};
use daphne::{
    messages::{ReportId, ReportMetadata, TransitionFailure},
    vdaf::{
        EarlyReportState, EarlyReportStateConsumed, EarlyReportStateInitialized, VdafPrepMessage,
        VdafPrepState, VdafVerifyKey,
    },
    DapError, VdafConfig,
};
use futures::{future::ready, StreamExt, TryStreamExt};
use prio::codec::{CodecError, Decode, Encode, ParameterizedDecode};
use serde::{Deserialize, Serialize};
use std::{borrow::Cow, collections::HashSet, ops::ControlFlow, time::Duration};
use tracing::Instrument;
use worker::{js_sys::Uint8Array, *};

use super::{req_parse, Alarmed, DapDurableObject, GarbageCollectable};

pub(crate) const DURABLE_REPORTS_PROCESSED_INITIALIZE: &str =
    "/internal/do/reports_processed/initialize";
pub(crate) const DURABLE_REPORTS_PROCESSED_MARK_AGGREGATED: &str =
    "/internal/do/reports_processed/mark_aggregated";

/// Durable Object (DO) for tracking which reports have been processed.
///
/// This object defines a single API endpoint, `DURABLE_REPORTS_PROCESSED_MARK_AGGREGATED`, which
/// is used to mark a set of reports as aggregated. It returns the set of reports in that have
/// already been aggregated (and thus need to be rejected by the caller).
///
/// The schema for stored report IDs is as follows:
///
/// ```text
///     processed/<report_id> -> bool
/// ```
///
/// where `<report_id>` is the hex-encoded report ID.
#[durable_object]
pub struct ReportsProcessed {
    state: State,
    env: Env,
    config: DaphneWorkerConfig,
    touched: bool,
    alarmed: bool,
    reports_processed: Option<HashSet<ReportId>>,
}

// This is the maximum size of a value in durable object storage.
const MAX_DURABLE_OBJECT_VALUE_SIZE: usize = 131_072;

// The maximum number of reports we can support per DO instance. After this limit we start dropping
// reports
const MAX_REPORT_COUNT: usize =
    (MAX_DURABLE_OBJECT_VALUE_SIZE / std::mem::size_of::<ReportId>()) * 3;

impl ReportsProcessed {
    async fn load_processed_reports(&mut self) -> Result<&mut HashSet<ReportId>> {
        let reps = &mut self.reports_processed;
        match reps {
            Some(p) => Ok(p),
            None => {
                let processed = futures::stream::iter(0..)
                    .then(|i| {
                        let state_ref = &self.state;
                        async move {
                            state_get::<Vec<u8>>(state_ref, &format!("processed_reports/{i}"))
                                .await
                                .transpose()
                        }
                    })
                    .take_while(|reports| ready(reports.is_some()))
                    .map(|reports| reports.unwrap())
                    .try_fold(HashSet::new(), |mut set, reports| async move {
                        reports
                            .chunks(std::mem::size_of::<ReportId>())
                            .map(ReportId::get_decoded)
                            .try_for_each(|r| {
                                set.insert(r?);
                                Ok(())
                            })
                            .map_err(|e: CodecError| {
                                Error::RustError(format!("failed to deserialize report id: {e:?}"))
                            })
                            .map(|_| set)
                    })
                    .await?;

                Ok(reps.insert(processed))
            }
        }
    }

    async fn store_processed_reports(&self) -> Result<()> {
        let Some(reports) = &self.reports_processed else {
            return Ok(())
        };
        tracing::debug!("Storing {} reports", reports.len());
        let mut encoded_reports =
            Vec::with_capacity(reports.len() * std::mem::size_of::<ReportId>());
        for r in reports {
            r.encode(&mut encoded_reports);
        }
        for (i, chunk) in encoded_reports
            .chunks(MAX_DURABLE_OBJECT_VALUE_SIZE)
            .enumerate()
        {
            let array = Uint8Array::new_with_length(chunk.len() as _);
            array.copy_from(chunk);
            self.state
                .storage()
                .put_raw(&format!("processed_reports/{i}"), array)
                .await?;
        }
        Ok(())
    }
}

#[durable_object]
impl DurableObject for ReportsProcessed {
    fn new(state: State, env: Env) -> Self {
        initialize_tracing(&env);
        let config =
            DaphneWorkerConfig::from_worker_env(&env).expect("failed to load configuration");
        Self {
            state,
            env,
            config,
            touched: false,
            alarmed: false,
            reports_processed: None,
        }
    }

    async fn fetch(&mut self, req: Request) -> Result<Response> {
        let span = create_span_from_request(&req);
        self.handle(req).instrument(span).await
    }

    async fn alarm(&mut self) -> Result<Response> {
        self.state.storage().delete_all().await?;
        self.alarmed = false;
        self.touched = false;
        Response::from_json(&())
    }
}

impl ReportsProcessed {
    async fn handle(&mut self, req: Request) -> Result<Response> {
        let mut req = match self
            .schedule_for_garbage_collection(req, BINDING_DAP_REPORTS_PROCESSED)
            .await?
        {
            ControlFlow::Continue(req) => req,
            // This req was a GC request and as such we must return from this function.
            ControlFlow::Break(_) => return Response::from_json(&()),
        };

        self.ensure_alarmed(
            Duration::from_secs(self.config.global.report_storage_epoch_duration)
                .saturating_add(self.config.processed_alarm_safety_interval),
        )
        .await?;

        match (req.path().as_ref(), req.method()) {
            // Initialize a report:
            //  * Ensure the report wasn't replayed
            //  * Ensure the report won't be included in a batch that was already collected
            //  * Initialize VDAF preparation.
            //
            // Idempotent
            // Input: `ReportsProcessedReq`
            // Output: `ReportsProcessedResp`
            (DURABLE_REPORTS_PROCESSED_INITIALIZE, Method::Post) => {
                let reports_processed_request: ReportsProcessedReq = req_parse(&mut req).await?;

                let processed = self.load_processed_reports().await?;

                let is_replay = |report: &EarlyReportStateConsumed| {
                    !report.is_ready() || processed.contains(&report.metadata().id)
                };

                let initialized_reports = reports_processed_request
                    .consumed_reports
                    .into_iter()
                    .map(|consumed_report| {
                        if is_replay(&consumed_report) {
                            Ok(EarlyReportStateInitialized::Rejected {
                                metadata: Cow::Owned(consumed_report.metadata().clone()),
                                failure: TransitionFailure::ReportReplayed,
                            })
                        } else {
                            EarlyReportStateInitialized::initialize(
                                reports_processed_request.is_leader,
                                &reports_processed_request.vdaf_verify_key,
                                &reports_processed_request.vdaf_config,
                                consumed_report,
                            )
                        }
                    })
                    .collect::<std::result::Result<Vec<EarlyReportStateInitialized>, DapError>>()
                    .map_err(|e| {
                        int_err(format!(
                            "ReportsProcessed: failed to initialize a report: {e}"
                        ))
                    })?;

                Response::from_json(&ReportsProcessedResp {
                    is_leader: reports_processed_request.is_leader,
                    vdaf_config: reports_processed_request.vdaf_config,
                    initialized_reports,
                })
            }

            // Mark reports as aggregated. Return the subset that were already aggregated.
            //
            // Non-idempotent
            // Input: `Vec<ReportId>`
            // Output: `Vec<ReportId>`
            (DURABLE_REPORTS_PROCESSED_MARK_AGGREGATED, Method::Post) => {
                let report_ids: Vec<ReportId> = req_parse(&mut req).await?;
                let processed = self.load_processed_reports().await?;
                let processed_count = processed.len();

                let replayed_or_dropped =
                    report_ids.into_iter().try_fold(vec![], |mut replayed, id| {
                        if processed.len() >= MAX_REPORT_COUNT {
                            if !processed.contains(&id) {
                                return Err(id);
                            }
                        } else if let Some(replayed_id) = processed.replace(id) {
                            replayed.push(replayed_id)
                        }
                        Ok(replayed)
                    });

                if processed.len() > processed_count {
                    self.store_processed_reports().await?;
                }

                match replayed_or_dropped {
                    Ok(replayed) => Response::from_json(&MarkAggregatedResp::Replayed(replayed)),
                    Err(dropped) => Response::from_json(&MarkAggregatedResp::Dropped(dropped)),
                }
            }

            _ => Err(int_err(format!(
                "ReportsProcessed: unexpected request: method={:?}; path={:?}",
                req.method(),
                req.path()
            ))),
        }
    }
}

impl DapDurableObject for ReportsProcessed {
    #[inline(always)]
    fn state(&self) -> &State {
        &self.state
    }

    #[inline(always)]
    fn deployment(&self) -> crate::config::DaphneWorkerDeployment {
        self.config.deployment
    }
}

#[async_trait::async_trait]
impl Alarmed for ReportsProcessed {
    #[inline(always)]
    fn alarmed(&mut self) -> &mut bool {
        &mut self.alarmed
    }
}

#[async_trait::async_trait(?Send)]
impl GarbageCollectable for ReportsProcessed {
    #[inline(always)]
    fn touched(&mut self) -> &mut bool {
        &mut self.touched
    }

    #[inline(always)]
    fn env(&self) -> &Env {
        &self.env
    }
}

#[derive(Serialize, Deserialize)]
pub(crate) struct ReportsProcessedReq<'req> {
    pub(crate) is_leader: bool,
    pub(crate) vdaf_verify_key: VdafVerifyKey,
    pub(crate) vdaf_config: VdafConfig,
    pub(crate) consumed_reports: Vec<EarlyReportStateConsumed<'req>>,
}

#[derive(Serialize, Deserialize)]
#[serde(try_from = "ShadowReportsProcessedResp")]
pub(crate) struct ReportsProcessedResp<'req> {
    pub(crate) is_leader: bool,
    pub(crate) vdaf_config: VdafConfig,
    pub(crate) initialized_reports: Vec<EarlyReportStateInitialized<'req>>,
}

#[derive(Serialize, Deserialize)]
pub(crate) enum MarkAggregatedResp {
    Replayed(Vec<ReportId>),
    Dropped(ReportId),
}

// we need this custom deserializer because VdafPrepState and VdafPrepMessage don't implement
// Decode, only ParameterizedDecode.
#[derive(Deserialize)]
struct ShadowReportsProcessedResp {
    pub(crate) is_leader: bool,
    pub(crate) vdaf_config: VdafConfig,
    pub(crate) initialized_reports: Vec<EarlyReportStateInitializedOwned>,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EarlyReportStateInitializedOwned {
    Ready {
        metadata: ReportMetadata,
        #[serde(with = "hex")]
        public_share: Vec<u8>,
        #[serde(with = "hex")]
        state: Vec<u8>,
        #[serde(with = "hex")]
        message: Vec<u8>,
    },
    Rejected {
        metadata: ReportMetadata,
        failure: TransitionFailure,
    },
}

impl TryFrom<ShadowReportsProcessedResp> for ReportsProcessedResp<'_> {
    type Error = CodecError;

    fn try_from(other: ShadowReportsProcessedResp) -> std::result::Result<Self, CodecError> {
        let initialized_reports = other
            .initialized_reports
            .into_iter()
            .map(|initialized_report| match initialized_report {
                EarlyReportStateInitializedOwned::Ready {
                    metadata,
                    public_share,
                    state,
                    message,
                } => {
                    let state = VdafPrepState::get_decoded_with_param(
                        &(&other.vdaf_config, other.is_leader),
                        &state,
                    )?;
                    let message = VdafPrepMessage::get_decoded_with_param(&state, &message)?;

                    Ok(EarlyReportStateInitialized::Ready {
                        metadata: Cow::Owned(metadata),
                        public_share: Cow::Owned(public_share),
                        state,
                        message,
                    })
                }
                EarlyReportStateInitializedOwned::Rejected { metadata, failure } => {
                    Ok(EarlyReportStateInitialized::Rejected {
                        metadata: Cow::Owned(metadata),
                        failure,
                    })
                }
            })
            .collect::<std::result::Result<Vec<EarlyReportStateInitialized>, CodecError>>()?;
        Ok(Self {
            is_leader: other.is_leader,
            vdaf_config: other.vdaf_config,
            initialized_reports,
        })
    }
}
