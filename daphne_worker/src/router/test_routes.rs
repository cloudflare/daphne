// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use daphne::{
    error::DapAbort,
    hpke::HpkeReceiverConfig,
    messages::{Duration, TaskId, Time},
    roles::DapLeader,
};
use serde::Deserialize;
use tracing::{debug, info_span, Instrument};
use worker::{Response, Url};

use crate::DaphneWorkerReportSelector;

use super::{DapRouter, Role};

pub(super) fn add_internal_test_routes(router: DapRouter<'_>, role: Role) -> DapRouter<'_> {
    let router = if role.is_leader() {
        router
            .post_async("/internal/process", |mut req, ctx| async move {
                let daph = ctx.data.handler(&ctx.env);
                let report_sel: DaphneWorkerReportSelector = req.json().await?;
                match daph
                    .process(&report_sel, &daph.state.host)
                    .instrument(info_span!("process"))
                    .await
                {
                    Ok(telem) => {
                        debug!("{:?}", telem);
                        Response::from_json(&telem)
                    }
                    Err(e) => daph.state.dap_abort_to_worker_response(e),
                }
            })
            .get_async(
                "/internal/current_batch/task/:task_id",
                |_req, ctx| async move {
                    // Return the ID of the oldest, not-yet-collecgted batch for the specified
                    // task. The task ID and batch ID are both encoded in URL-safe base64.
                    let daph = ctx.data.handler(&ctx.env);
                    let task_id =
                        match ctx.param("task_id").and_then(TaskId::try_from_base64url) {
                            Some(id) => id,
                            None => {
                                return daph.state.dap_abort_to_worker_response(
                                    DapAbort::BadRequest("missing or malformed task ID".into()),
                                )
                            }
                        };
                    match daph
                        .internal_current_batch(&task_id)
                        .instrument(info_span!("current_batch"))
                        .await
                    {
                        Ok(batch_id) => {
                            Response::from_bytes(batch_id.to_base64url().as_bytes().to_owned())
                        }
                        Err(e) => daph.state.dap_abort_to_worker_response(e.into()),
                    }
                },
            )
    } else {
        router
    };
    router
        .post_async("/internal/delete_all", |_req, ctx| async move {
            let daph = ctx.data.handler(&ctx.env);
            match daph
                .internal_delete_all()
                .instrument(info_span!("delete_all"))
                .await
            {
                Ok(()) => Response::empty(),
                Err(e) => daph.state.dap_abort_to_worker_response(e.into()),
            }
        })
        // Endpoints for draft-dcook-ppm-dap-interop-test-design-02
        .post_async("/internal/test/ready", |_req, _ctx| async move {
            Response::from_json(&())
        })
        .post_async(
            "/internal/test/endpoint_for_task",
            |mut req, ctx| async move {
                let daph = ctx.data.handler(&ctx.env);
                let cmd: InternalTestEndpointForTask = req.json().await?;
                daph.internal_endpoint_for_task(daph.config().default_version, cmd)
                    .instrument(info_span!("endpoint_for_task"))
                    .await
            },
        )
        .post_async(
            "/:version/internal/test/endpoint_for_task",
            |mut req, ctx| async move {
                let daph = ctx.data.handler(&ctx.env);
                let cmd: InternalTestEndpointForTask = req.json().await?;
                let version = daph.extract_version_parameter(&req)?;
                daph.internal_endpoint_for_task(version, cmd)
                    .instrument(info_span!("endpoint_for_task"))
                    .await
            },
        )
        .post_async("/internal/test/add_task", |mut req, ctx| async move {
            let daph = ctx.data.handler(&ctx.env);
            let cmd: InternalTestAddTask = req.json().await?;
            daph.internal_add_task(daph.config().default_version, cmd)
                .instrument(info_span!("add_task"))
                .await?;
            Response::from_json(&serde_json::json!({
                "status": "success",
            }))
        })
        .post_async(
            "/:version/internal/test/add_task",
            |mut req, ctx| async move {
                let daph = ctx.data.handler(&ctx.env);
                let cmd: InternalTestAddTask = req.json().await?;
                let version = daph.extract_version_parameter(&req)?;
                daph.internal_add_task(version, cmd)
                    .instrument(info_span!("add_task"))
                    .await?;
                Response::from_json(&serde_json::json!({
                    "status": "success",
                }))
            },
        )
        .post_async(
            "/:version/internal/test/add_hpke_config",
            |mut req, ctx| async move {
                let daph = ctx.data.handler(&ctx.env);
                let hpke: HpkeReceiverConfig = req.json().await?;
                let version = daph.extract_version_parameter(&req)?;
                daph.internal_add_hpke_config(version, hpke)
                    .instrument(info_span!("add_hpke_config"))
                    .await?;
                Response::from_json(&serde_json::json!({
                    "status": "success",
                }))
            },
        )
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) struct InternalTestEndpointForTask {
    pub role: super::Role,
}

#[derive(Deserialize)]
pub(crate) struct InternalTestVdaf {
    #[serde(rename = "type")]
    pub typ: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bits: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub length: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chunk_length: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) struct InternalTestAddTask {
    pub task_id: String, // base64url
    pub leader: Url,
    pub helper: Url,
    pub vdaf: InternalTestVdaf,
    pub leader_authentication_token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub collector_authentication_token: Option<String>,
    pub role: super::Role,
    pub vdaf_verify_key: String, // base64url
    pub query_type: u8,
    pub min_batch_size: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_batch_size: Option<u64>,
    pub time_precision: Duration,
    pub collector_hpke_config: String, // base64url
    pub task_expiration: Time,
}
