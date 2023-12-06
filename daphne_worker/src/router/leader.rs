// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use daphne::{
    constants::DapMediaType,
    error::DapAbort,
    messages::{Base64Encode, CollectionJobId, TaskId},
    roles::{leader, DapLeader},
    DapCollectJob, DapRequest, DapResponse, DapVersion,
};
use daphne_service_utils::auth::DaphneAuth;
use prio::codec::ParameterizedEncode;
use tracing::{info_span, Instrument};
use worker::{Headers, Response, Result};

use crate::{config::DaphneWorker, info_span_from_dap_request};

use super::{dap_response_to_worker, DapRouter};

pub(super) fn add_leader_routes(router: DapRouter<'_>) -> DapRouter<'_> {
    router
        .post_async("/:version/upload", |req, ctx| async move {
            let daph = ctx.data.handler(&ctx.env);
            let req = match daph.worker_request_to_dap(req, &ctx).await {
                Ok(req) => req,
                Err(e) => return daph.state.dap_abort_to_worker_response(e),
            };
            if req.version != DapVersion::Draft02 {
                return Response::error("not implemented", 404);
            }
            put_report_into_task(req, daph).await
        }) // draft02
        .put_async("/:version/tasks/:task_id/reports", |req, ctx| async move {
            let daph = ctx.data.handler(&ctx.env);
            let req = match daph.worker_request_to_dap(req, &ctx).await {
                Ok(req) => req,
                Err(e) => return daph.state.dap_abort_to_worker_response(e),
            };
            put_report_into_task(req, daph).await
        })
        .post_async("/:version/collect", |req, ctx| async move {
            let daph = ctx.data.handler(&ctx.env);
            let req = match daph.worker_request_to_dap(req, &ctx).await {
                Ok(req) => req,
                Err(e) => return daph.state.dap_abort_to_worker_response(e),
            };

            if req.version != DapVersion::Draft02 {
                return Response::error("not implemented", 404);
            }

            let span = info_span_from_dap_request!("collect", req);

            match leader::handle_collect_job_req(&daph, &req)
                .instrument(span)
                .await
            {
                Ok(collect_uri) => {
                    let mut headers = Headers::new();
                    headers.set("Location", collect_uri.as_str())?;
                    Ok(Response::empty()
                        .unwrap()
                        .with_status(303)
                        .with_headers(headers))
                }
                Err(e) => daph.state.dap_abort_to_worker_response(e),
            }
        }) // draft02
        .get_async(
            "/:version/collect/task/:task_id/req/:collect_id",
            |_, ctx| async move {
                let version = DaphneWorker::parse_version_param(&ctx)
                    .map_err(|e| worker::Error::RustError(e.to_string()))?;
                if version != DapVersion::Draft02 {
                    return Response::error("not implemented", 404);
                }
                let Some(task_id) = ctx.param("task_id").and_then(TaskId::try_from_base64url)
                else {
                    return ctx.data.dap_abort_to_worker_response(DapAbort::BadRequest(
                        "missing task_id parameter".to_string(),
                    ));
                };
                let Some(collect_id) = ctx
                    .param("collect_id")
                    .and_then(CollectionJobId::try_from_base64url)
                else {
                    return ctx.data.dap_abort_to_worker_response(DapAbort::BadRequest(
                        "missing collect_id parameter".to_string(),
                    ));
                };
                let daph = ctx.data.handler(&ctx.env);
                match daph
                    .poll_collect_job(&task_id, &collect_id)
                    .instrument(info_span!("poll_collect_job (draft02)"))
                    .await
                {
                    Ok(DapCollectJob::Done(collect_resp)) => dap_response_to_worker(DapResponse {
                        version: DapVersion::Draft02,
                        media_type: DapMediaType::Collection,
                        payload: collect_resp.get_encoded_with_param(&version),
                    }),
                    Ok(DapCollectJob::Pending) => Ok(Response::empty().unwrap().with_status(202)),
                    // TODO spec: Decide whether to define this behavior.
                    Ok(DapCollectJob::Unknown) => {
                        daph.state
                            .dap_abort_to_worker_response(DapAbort::BadRequest(
                                "unknown collect id".into(),
                            ))
                    }
                    Err(e) => daph.state.dap_abort_to_worker_response(e),
                }
            },
        ) // draft02
        .put_async(
            "/:version/tasks/:task_id/collection_jobs/:collect_job_id",
            |req, ctx| async move {
                let daph = ctx.data.handler(&ctx.env);
                let req = match daph.worker_request_to_dap(req, &ctx).await {
                    Ok(req) => req,
                    Err(e) => return daph.state.dap_abort_to_worker_response(e),
                };

                let span = info_span_from_dap_request!("collect (PUT)", req);

                match leader::handle_collect_job_req(&daph, &req)
                    .instrument(span)
                    .await
                {
                    Ok(_) => Ok(Response::empty().unwrap().with_status(201)),
                    Err(e) => daph.state.dap_abort_to_worker_response(e),
                }
            },
        )
        .post_async(
            "/:version/tasks/:task_id/collection_jobs/:collect_job_id",
            |req, ctx| async move {
                let daph = ctx.data.handler(&ctx.env);
                let req = match daph.worker_request_to_dap(req, &ctx).await {
                    Ok(req) => req,
                    Err(e) => return daph.state.dap_abort_to_worker_response(e),
                };
                let task_id = match req.task_id() {
                    Ok(id) => id,
                    Err(e) => return daph.state.dap_abort_to_worker_response(e),
                };
                // We cannot check a resource here as the resource is set via
                // media type, and there is no media type when polling.
                //
                // We can unwrap() here as the parameter really must exist.
                let collect_job_id_base64url = ctx.param("collect_job_id").unwrap();
                let Some(collect_job_id) =
                    CollectionJobId::try_from_base64url(collect_job_id_base64url)
                else {
                    return daph
                        .state
                        .dap_abort_to_worker_response(DapAbort::BadRequest(
                            "malformed collect id".into(),
                        ));
                };

                let span = info_span!(
                    "poll_collect_job",
                    dap.task_id = %task_id,
                    version = req.version.to_string()
                );

                match daph
                    .poll_collect_job(task_id, &collect_job_id)
                    .instrument(span)
                    .await
                {
                    Ok(DapCollectJob::Done(collect_resp)) => dap_response_to_worker(DapResponse {
                        version: req.version,
                        media_type: DapMediaType::Collection,
                        payload: collect_resp.get_encoded_with_param(&req.version),
                    }),
                    Ok(DapCollectJob::Pending) => Ok(Response::empty().unwrap().with_status(202)),
                    // TODO spec: Decide whether to define this behavior.
                    Ok(DapCollectJob::Unknown) => {
                        daph.state
                            .dap_abort_to_worker_response(DapAbort::BadRequest(
                                "unknown collect id".into(),
                            ))
                    }
                    Err(e) => daph.state.dap_abort_to_worker_response(e),
                }
            },
        )
}

async fn put_report_into_task(
    req: DapRequest<DaphneAuth>,
    daph: DaphneWorker<'_>,
) -> Result<Response> {
    let span = info_span_from_dap_request!("upload", req);

    match leader::handle_upload_req(&daph, &req)
        .instrument(span)
        .await
    {
        Ok(()) => Response::empty(),
        Err(e) => daph.state.dap_abort_to_worker_response(e),
    }
}
