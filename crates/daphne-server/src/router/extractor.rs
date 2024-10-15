// Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use std::io::Cursor;

use axum::{
    async_trait,
    body::{Bytes, HttpBody},
    extract::{FromRequest, FromRequestParts, Path},
};
use daphne::{
    constants::DapMediaType,
    error::DapAbort,
    fatal_error,
    messages::{
        request::resource, AggregateShareReq, AggregationJobInitReq, CollectionReq, Report, TaskId,
    },
    DapError, DapRequest, DapRequestMeta, DapVersion,
};
use daphne_service_utils::{bearer_token::BearerToken, http_headers};
use http::{header::CONTENT_TYPE, HeaderMap, Request};
use prio::codec::ParameterizedDecode;
use serde::Deserialize;

use crate::metrics;

use super::{AxumDapResponse, DaphneService};

/// Trait used to decode a DAP http body.
pub trait DecodeFromDapHttpBody: Sized {
    fn decode_from_http_body(bytes: Bytes, meta: &DapRequestMeta) -> Result<Self, DapAbort>;
}

macro_rules! impl_decode_from_dap_http_body {
    ($($type:ident),*$(,)?) => {
        $(
            impl DecodeFromDapHttpBody for $type {
                fn decode_from_http_body(
                    bytes: Bytes,
                    meta: &DapRequestMeta,
                ) -> Result<Self, DapAbort> {
                    let mut cursor = Cursor::new(bytes.as_ref());
                    // Check that media type matches.
                    meta.get_checked_media_type(DapMediaType::$type)?;
                    // Decode the body
                    $type::decode_with_param(&meta.version, &mut cursor)
                        .map_err(|e| DapAbort::from_codec_error(e, meta.task_id))
                }
            }
        )*
    };
}

impl_decode_from_dap_http_body!(
    AggregationJobInitReq,
    AggregateShareReq,
    Report,
    CollectionReq,
);

/// Using `()` ignores the body of a request.
impl DecodeFromDapHttpBody for () {
    fn decode_from_http_body(_bytes: Bytes, _meta: &DapRequestMeta) -> Result<Self, DapAbort> {
        Ok(())
    }
}

/// Parsers that allow us to have to deduce the resource parser to use based on the resource passed
/// in through the `R` type parameter in [`DapRequestExtractor`] and
/// [`UnauthenticatedDapRequestExtractor`].
mod resource_parsers {
    use daphne::messages::request::resource;
    use serde::{de::DeserializeOwned, Deserialize};

    #[derive(Deserialize)]
    pub struct AggregationJobIdParser {
        /// This field name defines the parameter name in the route matcher because we use
        /// `#[serde(flatten)]` in the
        /// `UnauthenticatedDapRequestExtractor::from_request::PathParams::resource_parser` field.
        agg_job_id: resource::AggregationJobId,
    }

    #[derive(Deserialize)]
    pub struct CollectionJobIdParser {
        /// This field name defines the parameter name in the route matcher because we use
        /// `#[serde(flatten)]` in the
        /// `UnauthenticatedDapRequestExtractor::from_request::PathParams::resource_parser` field.
        collect_job_id: resource::CollectionJobId,
    }

    /// This parser has no fields, so `#[serde(flatten)]` correctly omits this field from the
    /// fields it requires.
    #[derive(Deserialize)]
    pub struct NoneParser;

    /// Trait that lets us go from resource to resource parser.
    pub trait Resource: Sized + Send + Sync {
        type Parser: Into<Self> + Send + Sync + DeserializeOwned;
    }

    macro_rules! impl_parser {
        ($from:ty => $to:ty |$source:pat_param| $conv:expr) => {
            impl Resource for $to {
                type Parser = $from;
            }

            impl ::core::convert::From<$from> for $to {
                fn from($source: $from) -> Self {
                    $conv
                }
            }
        };
    }

    impl_parser!(AggregationJobIdParser => resource::AggregationJobId |value| value.agg_job_id);
    impl_parser!(CollectionJobIdParser  => resource::CollectionJobId  |value| value.collect_job_id);
    impl_parser!(NoneParser             => resource::None             |_| resource::None);
}

/// An axum extractor capable of parsing a [`DapRequest`]. See [`DapRequest`] for an explanation on
/// the type parameters.
#[derive(Debug)]
pub(super) struct UnauthenticatedDapRequestExtractor<P, R>(pub DapRequest<P, R>);

#[async_trait]
impl<S, B, P, R> FromRequest<S, B, P> for UnauthenticatedDapRequestExtractor<P, R>
where
    P: DecodeFromDapHttpBody,
    S: DaphneService + Send + Sync,
    B: HttpBody + Send + 'static,
    <B as HttpBody>::Data: Send,
    R: resource_parsers::Resource,
{
    type Rejection = AxumDapResponse;

    async fn from_request(req: Request<B>, state: &S) -> Result<Self, Self::Rejection> {
        #[derive(Debug, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct PathParams<R: resource_parsers::Resource> {
            version: DapVersion,
            task_id: TaskId,
            #[serde(flatten)]
            resource_parser: R::Parser,
        }

        let (mut parts, body) = req.into_parts();
        let Path(PathParams::<R> {
            version,
            task_id,
            resource_parser,
        }) = Path::from_request_parts(&mut parts, state)
            .await
            .map_err(|_| {
                AxumDapResponse::new_error(
                    DapAbort::BadRequest("invalid path".into()),
                    state.server_metrics(),
                )
            })?;

        let media_type = if let Some(content_type) = parts.headers.get(CONTENT_TYPE) {
            let content_type = content_type.to_str().map_err(|_| {
                let msg = "header value contains non ascii or invisible characters".into();
                AxumDapResponse::new_error(DapAbort::BadRequest(msg), state.server_metrics())
            })?;
            let media_type =
                DapMediaType::from_str_for_version(version, content_type).ok_or_else(|| {
                    AxumDapResponse::new_error(
                        DapAbort::BadRequest("invalid media type".into()),
                        state.server_metrics(),
                    )
                })?;
            Some(media_type)
        } else {
            None
        };

        // TODO(mendess): this allocates needlessly, if prio supported some kind of
        // AsyncParameterizedDecode we could avoid this allocation
        let payload = hyper::body::to_bytes(body).await;

        let Ok(payload) = payload else {
            return Err(AxumDapResponse::new_error(
                fatal_error!(err = "failed to get payload"),
                state.server_metrics(),
            ));
        };

        let meta = DapRequestMeta {
            version,
            task_id,
            taskprov: extract_header_as_string(&parts.headers, http_headers::DAP_TASKPROV),
            media_type,
        };

        let payload = P::decode_from_http_body(payload, &meta)
            .map_err(|e| AxumDapResponse::new_error(e, state.server_metrics()))?;

        let request = DapRequest {
            meta,
            resource_id: resource_parser.into(),
            payload,
        };

        Ok(UnauthenticatedDapRequestExtractor(request))
    }
}

pub mod dap_sender {
    pub type DapSender = u8;

    pub const FROM_CLIENT: DapSender = 0;
    pub const FROM_COLLECTOR: DapSender = 1 << 1;
    pub const FROM_HELPER: DapSender = 1 << 2;
    pub const FROM_LEADER: DapSender = 1 << 3;

    pub const fn to_enum(id: DapSender) -> daphne::DapSender {
        match id {
            FROM_CLIENT => daphne::DapSender::Client,
            FROM_COLLECTOR => daphne::DapSender::Collector,
            FROM_HELPER => daphne::DapSender::Helper,
            FROM_LEADER => daphne::DapSender::Leader,
            _ => panic!("invalid dap sender. Please specify a valid dap_sender from the crate::extractor::dap_sender module"),
        }
    }
}

/// An axum extractor capable of parsing a [`DapRequest`].
///
/// This extractor asserts that the request is authenticated.
///
/// # Type and const parameters
/// - `SENDER`: The role that is expected to send this request. See [`dap_sender`] for possible values.
/// - `P` and `R`: See [`DapRequest`] for an explanation these type parameters.
#[derive(Debug)]
pub(super) struct DapRequestExtractor<const SENDER: dap_sender::DapSender, P, R = resource::None>(
    pub DapRequest<P, R>,
);

#[async_trait]
impl<const SENDER: dap_sender::DapSender, S, B, P, R> FromRequest<S, B, P>
    for DapRequestExtractor<SENDER, P, R>
where
    P: DecodeFromDapHttpBody + Send + Sync,
    S: DaphneService + Send + Sync,
    B: HttpBody + Send + 'static,
    <B as HttpBody>::Data: Send,
    R: resource_parsers::Resource,
{
    type Rejection = AxumDapResponse;

    async fn from_request(req: Request<B>, state: &S) -> Result<Self, Self::Rejection> {
        let bearer_token = extract_header_as_string(req.headers(), http_headers::DAP_AUTH_TOKEN)
            .map(BearerToken::from);
        let cf_tls_client_auth = extract_header_as_string(req.headers(), "X-Client-Cert-Verified");

        let request = UnauthenticatedDapRequestExtractor::from_request(req, state)
            .await?
            .0;

        let error_to_response = |error| AxumDapResponse::new_error(error, state.server_metrics());
        let auth_error = |detail| {
            error_to_response(DapError::from(DapAbort::UnauthorizedRequest {
                detail,
                task_id: request.task_id,
            }))
        };

        let is_taskprov = state
            .is_using_taskprov(&request)
            .await
            .map_err(
                |e| fatal_error!(err = ?e, "failed to determine if request was using taskprov"),
            )
            .map_err(error_to_response)?;

        let bearer_authed = if let Some(token) = bearer_token {
            state
                .server_metrics()
                .auth_method_inc(metrics::AuthMethod::BearerToken);
            state
                .check_bearer_token(
                    &token,
                    const { dap_sender::to_enum(SENDER) },
                    request.task_id,
                    is_taskprov,
                )
                .await
                .map_err(|reason| reason.either(auth_error, error_to_response))?;
            true
        } else {
            false
        };
        let mtls_authed = if let Some(verification_result) = cf_tls_client_auth {
            state
                .server_metrics()
                .auth_method_inc(metrics::AuthMethod::TlsClientAuth);
            // we always check if mtls succedded even if ...
            if verification_result != "SUCCESS" {
                return Err(auth_error(format!(
                    "Invalid TLS certificate ({verification_result})"
                )));
            }
            // ... we only allow mtls auth for taskprov tasks
            is_taskprov
        } else {
            false
        };

        if bearer_authed || mtls_authed {
            Ok(Self(request))
        } else {
            Err(auth_error(
                "No suitable authorization method was found".into(),
            ))
        }
    }
}

fn extract_header_as_string(headers: &HeaderMap, header: &'static str) -> Option<String> {
    headers.get(header)?.to_str().ok().map(ToString::to_string)
}

#[cfg(test)]
mod test {
    use std::{
        sync::{Arc, OnceLock},
        time::Duration,
    };

    use axum::{
        body::{Body, HttpBody},
        extract::State,
        http::{header::CONTENT_TYPE, Request, StatusCode},
        response::IntoResponse,
        routing::get,
        Router,
    };
    use daphne::{
        async_test_versions,
        constants::DapMediaType,
        messages::{request::resource, AggregationJobId, Base64Encode, CollectionJobId, TaskId},
        DapError, DapRequestMeta, DapSender, DapVersion,
    };
    use daphne_service_utils::{bearer_token::BearerToken, http_headers};
    use either::Either::{self, Left};
    use futures::FutureExt;
    use rand::{thread_rng, Rng};
    use tokio::{
        sync::mpsc::{self, Sender},
        time::timeout,
    };
    use tower::ServiceExt;

    use crate::metrics::{DaphnePromServiceMetrics, DaphneServiceMetrics};

    use super::{dap_sender::FROM_LEADER, resource_parsers};

    const BEARER_TOKEN: &str = "test-token";

    // In these tests we don't care about the body, so we can type alias it away.
    type DapRequest<R = resource::None> = daphne::DapRequest<(), R>;
    type UnauthenticatedDapRequestExtractor<R = resource::None> =
        super::UnauthenticatedDapRequestExtractor<(), R>;
    type DapRequestExtractor<R = resource::None> = super::DapRequestExtractor<FROM_LEADER, (), R>;

    /// Return a function that will parse a request using the [`DapRequestExtractor`] or
    /// [`UnauthenticatedDapRequestExtractor`] and return the parsed request.
    ///
    /// The possible request URIs that are supported by this parser are:
    ///  - `/:version/:task_id/auth` uses the [`DapRequestExtractor`]
    ///  - `/:version/:task_id/parse-mandatory-fields` uses the [`UnauthenticatedDapRequestExtractor`]
    ///  - `/:version/:agg_job_id/parse-agg-job-id` uses the [`UnauthenticatedDapRequestExtractor`]
    ///  - `/:version/:collect_job_id/parse-collect-job-id` uses the [`UnauthenticatedDapRequestExtractor`]
    async fn test<B, R>(req: Request<B>) -> Result<DapRequest<R>, StatusCode>
    where
        B: Send + Sync + 'static + HttpBody,
        B::Data: Send,
        B::Error: Send + Sync + std::error::Error,
        R: resource_parsers::Resource + 'static,
    {
        type Channel<R> = Sender<DapRequest<R>>;

        #[axum::async_trait]
        impl<R: Send> super::DaphneService for Channel<R> {
            fn server_metrics(&self) -> &dyn DaphneServiceMetrics {
                // These tests don't care about metrics so we just store a static instance here so I
                // can implement the DaphneService trait for Channel.
                static METRICS: OnceLock<DaphnePromServiceMetrics> = OnceLock::new();
                METRICS.get_or_init(|| {
                    DaphnePromServiceMetrics::register(prometheus::default_registry()).unwrap()
                })
            }

            fn signing_key(&self) -> Option<&p256::ecdsa::SigningKey> {
                None
            }

            async fn check_bearer_token(
                &self,
                token: &BearerToken,
                _sender: DapSender,
                _task_id: TaskId,
                _is_taskprov: bool,
            ) -> Result<(), Either<String, DapError>> {
                (token.as_str() == BEARER_TOKEN)
                    .then_some(())
                    .ok_or_else(|| Left("invalid token".into()))
            }

            async fn is_using_taskprov(&self, req: &DapRequestMeta) -> Result<bool, DapError> {
                Ok(req.taskprov.is_some())
            }
        }

        // setup a channel to "smuggle" the parsed request out of a handler
        let (tx, mut rx) = mpsc::channel(1);

        // create a router that takes the send end of the channel as state
        let router = Router::new()
            .route("/:version/:task_id/auth", get(auth_handler::<R>))
            .route(
                "/:version/:task_id/parse-mandatory-fields",
                get(handler::<R>),
            )
            .route(
                "/:version/:task_id/:agg_job_id/parse-agg-job-id",
                get(handler::<R>),
            )
            .route(
                "/:version/:task_id/:collect_job_id/parse-collect-job-id",
                get(handler::<R>),
            )
            .with_state(Arc::new(tx));

        // unauthenticated handler that simply sends the received request through the channel
        async fn handler<R>(
            State(ch): State<Arc<Channel<R>>>,
            req: UnauthenticatedDapRequestExtractor<R>,
        ) -> impl IntoResponse {
            ch.send(req.0).await.unwrap();
        }

        // unauthenticated handler that simply sends the received request through the channel
        async fn auth_handler<R>(
            State(ch): State<Arc<Channel<R>>>,
            req: DapRequestExtractor<R>,
        ) -> impl IntoResponse {
            ch.send(req.0).await.unwrap();
        }

        let resp = match timeout(Duration::from_secs(1), router.oneshot(req))
            .await
            .unwrap()
        {
            Ok(resp) => resp,
            Err(i) => match i {},
        };

        match resp.status() {
            StatusCode::NOT_FOUND => panic!("unsuported uri"),
            // get the request sent through the channel in the handler
            StatusCode::OK => Ok(rx.recv().now_or_never().unwrap().unwrap()),
            code => Err(code),
        }
    }

    fn mk_task_id() -> TaskId {
        TaskId(thread_rng().gen())
    }

    async fn parse_mandatory_fields(version: DapVersion) {
        let task_id = mk_task_id();
        let req = test::<_, resource::None>(
            Request::builder()
                .uri(format!(
                    "/{version}/{}/parse-mandatory-fields",
                    task_id.to_base64url()
                ))
                .header(
                    CONTENT_TYPE,
                    DapMediaType::AggregateShareReq
                        .as_str_for_version(version)
                        .unwrap(),
                )
                .header(http_headers::DAP_AUTH_TOKEN, BEARER_TOKEN)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

        assert_eq!(req.version, version);
        assert_eq!(req.task_id, task_id);
    }

    async_test_versions! { parse_mandatory_fields }

    async fn parse_agg_job_id(version: DapVersion) {
        let task_id = mk_task_id();
        let agg_job_id = AggregationJobId(thread_rng().gen());

        let req = test::<_, resource::AggregationJobId>(
            Request::builder()
                .uri(format!(
                    "/{version}/{}/{}/parse-agg-job-id",
                    task_id.to_base64url(),
                    agg_job_id.to_base64url(),
                ))
                .header(http_headers::DAP_AUTH_TOKEN, BEARER_TOKEN)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

        assert_eq!(req.resource_id, agg_job_id);
        assert_eq!(req.task_id, task_id);
    }

    async_test_versions! { parse_agg_job_id }

    async fn parse_collect_job_id(version: DapVersion) {
        let task_id = mk_task_id();
        let collect_job_id = CollectionJobId(thread_rng().gen());

        let req = test::<_, resource::CollectionJobId>(
            Request::builder()
                .uri(format!(
                    "/{version}/{}/{}/parse-collect-job-id",
                    task_id.to_base64url(),
                    collect_job_id.to_base64url(),
                ))
                .header(http_headers::DAP_AUTH_TOKEN, BEARER_TOKEN)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

        assert_eq!(req.resource_id, collect_job_id);
        assert_eq!(req.task_id, task_id);
    }

    async_test_versions! { parse_collect_job_id }

    async fn incorrect_bearer_tokens_are_rejected(version: DapVersion) {
        let status_code = test::<_, resource::None>(
            Request::builder()
                .uri(format!("/{version}/{}/auth", mk_task_id().to_base64url()))
                .header(http_headers::DAP_AUTH_TOKEN, "something incorrect")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap_err();

        assert_eq!(status_code, StatusCode::UNAUTHORIZED);
    }

    async_test_versions! { incorrect_bearer_tokens_are_rejected }

    async fn missing_auth_is_rejected(version: DapVersion) {
        let status_code = test::<_, resource::None>(
            Request::builder()
                .uri(format!("/{version}/{}/auth", mk_task_id().to_base64url()))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap_err();

        assert_eq!(status_code, StatusCode::UNAUTHORIZED);
    }

    async_test_versions! { missing_auth_is_rejected }

    async fn mtls_auth_is_enough(version: DapVersion) {
        let req = test::<_, resource::None>(
            Request::builder()
                .uri(format!("/{version}/{}/auth", mk_task_id().to_base64url()))
                .header("X-Client-Cert-Verified", "SUCCESS")
                .header(http_headers::DAP_TASKPROV, "some-taskprov-string")
                .body(Body::empty())
                .unwrap(),
        )
        .await;

        req.unwrap();
    }

    async_test_versions! { mtls_auth_is_enough }

    async fn incorrect_bearer_tokens_are_rejected_even_with_mtls_auth(version: DapVersion) {
        let code = test::<_, resource::None>(
            Request::builder()
                .uri(format!("/{version}/{}/auth", mk_task_id().to_base64url()))
                .header(http_headers::DAP_AUTH_TOKEN, "something incorrect")
                .header("X-Client-Cert-Verified", "SUCCESS")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap_err();

        assert_eq!(code, StatusCode::UNAUTHORIZED);
    }

    async_test_versions! { incorrect_bearer_tokens_are_rejected_even_with_mtls_auth }

    async fn invalid_mtls_auth_is_rejected_despite_correct_bearer_token(version: DapVersion) {
        let code = test::<_, resource::None>(
            Request::builder()
                .uri(format!("/{version}/{}/auth", mk_task_id().to_base64url()))
                .header(http_headers::DAP_AUTH_TOKEN, BEARER_TOKEN)
                .header("X-Client-Cert-Verified", "FAILED")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap_err();

        assert_eq!(code, StatusCode::UNAUTHORIZED);
    }

    async_test_versions! { invalid_mtls_auth_is_rejected_despite_correct_bearer_token }
}
