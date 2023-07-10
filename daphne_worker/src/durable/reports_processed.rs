// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use crate::{
    config::DaphneWorkerConfig,
    durable::{state_set_if_not_exists, BINDING_DAP_REPORTS_PROCESSED},
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
use futures::future::try_join_all;
use prio::codec::{CodecError, Decode, ParameterizedDecode};
use serde::{Deserialize, Serialize};
use std::{borrow::Cow, collections::HashSet, time::Duration};
use tracing::warn;
use worker::*;

pub(crate) const DURABLE_REPORTS_PROCESSED_INITIALIZE: &str =
    "/internal/do/reports_processed/initialize";

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
    #[allow(dead_code)]
    state: State,
    env: Env,
    config: DaphneWorkerConfig,
    touched: bool,
    alarmed: bool,
}

impl ReportsProcessed {
    /// Check if the report has been processed. If not, return None; otherwise, return the ID.
    async fn to_checked(&self, report_id_hex: String) -> Result<Option<String>> {
        let key = format!("processed/{report_id_hex}");
        let processed: bool = state_set_if_not_exists(&self.state, &key, &true)
            .await?
            .unwrap_or(false);
        if processed {
            Ok(Some(report_id_hex))
        } else {
            Ok(None)
        }
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
        }
    }

    async fn fetch(&mut self, mut req: Request) -> Result<Response> {
        let id_hex = self.state.id().to_string();
        ensure_garbage_collected!(req, self, id_hex.clone(), BINDING_DAP_REPORTS_PROCESSED);
        ensure_alarmed!(
            self,
            Duration::from_secs(self.config.global.report_storage_epoch_duration)
                .saturating_add(self.config.processed_alarm_safety_interval)
        );

        match (req.path().as_ref(), req.method()) {
            // Initialize a report:
            //  * Ensure the report wasn't replayed
            //  * Ensure the report won't be included in a batch that was already collected
            //  * Initialize VDAF preparation.
            //
            // Non-idempotent
            // Input: `ReportsProcessedReq`
            // Output: `ReportsProcessedResp`
            (DURABLE_REPORTS_PROCESSED_INITIALIZE, Method::Post) => {
                let reports_processed_request: ReportsProcessedReq = req.json().await?;
                let replayed_reports = try_join_all(
                    reports_processed_request
                        .consumed_reports
                        .iter()
                        .filter(|consumed_report| consumed_report.is_ready())
                        .map(|consumed_report| {
                            self.to_checked(consumed_report.metadata().id.to_hex())
                        }),
                )
                .await?
                .into_iter()
                .flatten()
                .map(|report_id_hex| {
                    hex::decode(report_id_hex)
                        .map_err(|e| format!("Failed to hex decode ReportId: {e}"))
                        .and_then(|report_id_data| {
                            ReportId::get_decoded(&report_id_data)
                                .map_err(|e| format!("Failed to decode ReportId: {e}"))
                        })
                })
                .collect::<std::result::Result<HashSet<ReportId>, String>>()
                .map_err(|e| int_err(format!("ReportsProcessed: {e}")))?;

                let initialized_reports = reports_processed_request
                    .consumed_reports
                    .into_iter()
                    .map(|consumed_report| {
                        if replayed_reports.contains(&consumed_report.metadata().id) {
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

            _ => Err(int_err(format!(
                "ReportsProcessed: unexpected request: method={:?}; path={:?}",
                req.method(),
                req.path()
            ))),
        }
    }

    async fn alarm(&mut self) -> Result<Response> {
        self.state.storage().delete_all().await?;
        self.alarmed = false;
        self.touched = false;
        Response::from_json(&())
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
