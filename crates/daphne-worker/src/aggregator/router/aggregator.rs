// Copyright (c) 2025 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    response::{AppendHeaders, IntoResponse},
    routing::get,
};
use daphne::{
    constants::DapMediaType,
    fatal_error,
    messages::{encode_base64url, TaskId},
    roles::{aggregator, DapAggregator},
    DapError, DapResponse, DapVersion,
};
use daphne_service_utils::http_headers;
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use serde::Deserialize;

use super::{AxumDapResponse, DaphneService};

pub fn add_aggregator_routes<A>(router: super::Router<A>) -> super::Router<A>
where
    A: DapAggregator + DaphneService + Send + Sync + 'static,
{
    router.route("/:version/hpke_config", get(hpke_config))
}

#[derive(Deserialize)]
struct QueryTaskId {
    task_id: Option<TaskId>,
}

#[tracing::instrument(skip(app), fields(version, task_id))]
async fn hpke_config<A>(
    State(app): State<Arc<A>>,
    Query(QueryTaskId { task_id }): Query<QueryTaskId>,
    Path(version): Path<DapVersion>,
) -> impl IntoResponse
where
    A: DapAggregator + DaphneService,
{
    match aggregator::handle_hpke_config_req(&*app, version, task_id).await {
        Ok(resp) => match app.signing_key().map(|k| sign_dap_response(k, &resp)) {
            None => AxumDapResponse::new_success(resp, app.server_metrics()).into_response(),
            Some(Ok(signed)) => (
                AppendHeaders([(http_headers::HPKE_SIGNATURE, &signed)]),
                AxumDapResponse::new_success(resp, app.server_metrics()),
            )
                .into_response(),
            Some(Err(e)) => AxumDapResponse::new_error(e, app.server_metrics()).into_response(),
        },
        Err(e) => AxumDapResponse::new_error(e, app.server_metrics()).into_response(),
    }
}

pub(crate) fn sign_dap_response(
    signing_key: &SigningKey,
    resp: &DapResponse,
) -> Result<String, DapError> {
    match resp.media_type {
        DapMediaType::HpkeConfigList => {
            let signature: Signature = signing_key.sign(&resp.payload);
            Ok(encode_base64url(signature.to_der().as_bytes()))
        }
        _ => Err(fatal_error!(
            err = "tried to sign invalid response",
            ?resp.media_type
        )),
    }
}

#[cfg(test)]
mod test {
    use axum::{
        body::Body,
        extract::Query,
        http::{Request, StatusCode},
        routing::get,
        Router,
    };
    use daphne::messages::{Base64Encode, TaskId};
    use daphne::{
        constants::DapMediaType, messages::decode_base64url_vec, DapResponse, DapVersion,
    };
    use p256::pkcs8::EncodePrivateKey;
    use rand::{thread_rng, Rng};
    use rcgen::CertificateParams;
    use tower::ServiceExt;
    use webpki::{EndEntityCert, ECDSA_P256_SHA256};

    use super::{sign_dap_response, QueryTaskId};

    #[tokio::test]
    async fn can_parse_task_id() {
        let task_id = TaskId(thread_rng().gen());
        let router: Router = Router::new().route(
            "/",
            get(move |Query(QueryTaskId { task_id: tid })| async move {
                assert_eq!(tid, Some(task_id));
            }),
        );

        let status = router
            .oneshot(
                Request::builder()
                    .uri(format!("/?task_id={}", task_id.to_base64url()))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
            .status();

        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn accepts_missing_task_id() {
        let router: Router = Router::new().route(
            "/",
            get(move |Query(QueryTaskId { task_id: tid })| async move {
                assert_eq!(tid, None);
            }),
        );

        let status = router
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap()
            .status();

        assert_eq!(status, StatusCode::OK);
    }

    // Check that a signature produced by Daphne-Worker will be verified properly by the Clients.
    #[test]
    fn rondtrip_sign_hpke_config() {
        let signing_key =
            p256::ecdsa::SigningKey::from(p256::SecretKey::random(&mut rand::rngs::OsRng));

        // Create a self-signed certificate for the signing key.
        let cert_der = {
            let mut params = CertificateParams::new(["test-aggregator.example.com".to_string()]);
            params.key_pair = Some(
                rcgen::KeyPair::from_der(signing_key.to_pkcs8_der().unwrap().to_bytes().as_ref())
                    .unwrap(),
            );
            params
                .distinguished_name
                .push(rcgen::DnType::LocalityName, "Braga");
            params
                .distinguished_name
                .push(rcgen::DnType::OrganizationName, "Cloudflare Lda");

            let cert = rcgen::Certificate::from_params(params).unwrap();
            cert.serialize_der().unwrap()
        };

        const PAYLOAD: &[u8] = b"dummy HPKE configuration";
        let resp = DapResponse {
            version: DapVersion::default(),
            media_type: DapMediaType::HpkeConfigList,
            payload: PAYLOAD.to_vec(),
        };

        let signature = sign_dap_response(&signing_key, &resp).unwrap();

        // Verify the signature.
        let signature_bytes = decode_base64url_vec(signature.as_bytes()).unwrap();

        let cert = EndEntityCert::try_from(cert_der.as_ref()).unwrap();
        cert.verify_signature(&ECDSA_P256_SHA256, PAYLOAD, signature_bytes.as_ref())
            .unwrap();
    }
}
