// Copyright (c) 2023 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use crate::auth::{DaphneWorkerAuthMethod, TlsCertInfo};
use daphne::auth::BearerToken;

#[test]
fn daphne_worker_auth_method_json_serialiation() {
    let daphne_worker_auth_method: DaphneWorkerAuthMethod =
        serde_json::from_str(r#"{"bearer_token":"the bearer token"}"#).unwrap();
    assert_eq!(
        daphne_worker_auth_method.bearer_token,
        Some(BearerToken::from("the bearer token".to_string()))
    );
    assert!(daphne_worker_auth_method.cf_tls_client_auth.is_none());

    let trusted_certs = vec![
        TlsCertInfo {
            issuer: "CN=Steve Kille,O=Isode Limited,C=GB".into(),
            subject: "OU=Sales+CN=J. Smith,O=Widget Inc.,C=US".into(),
        },
        TlsCertInfo {
            issuer: "CN=Steve Kille,O=Isode Limited,C=GB".into(),
            subject: "CN=L. Eagle,O=Sue\\, Grabbit and Runn,C=GB".into(),
        },
    ];

    let daphne_worker_auth_method: DaphneWorkerAuthMethod = serde_json::from_str(
        r#"{
            "cf_tls_client_auth": [
                {
                  "issuer": "CN=Steve Kille,O=Isode Limited,C=GB",
                  "subject": "OU=Sales+CN=J. Smith,O=Widget Inc.,C=US"
                },
                {
                  "issuer": "CN=Steve Kille,O=Isode Limited,C=GB",
                  "subject": "CN=L. Eagle,O=Sue\\, Grabbit and Runn,C=GB"
                }
              ]
        }"#,
    )
    .unwrap();
    assert_eq!(
        daphne_worker_auth_method.cf_tls_client_auth,
        Some(trusted_certs.clone()),
    );
    assert!(daphne_worker_auth_method.bearer_token.is_none());

    let daphne_worker_auth_method: DaphneWorkerAuthMethod = serde_json::from_str(
        r#"{
            "bearer_token": "the bearer token",
            "cf_tls_client_auth": [
                {
                  "issuer": "CN=Steve Kille,O=Isode Limited,C=GB",
                  "subject": "OU=Sales+CN=J. Smith,O=Widget Inc.,C=US"
                },
                {
                  "issuer": "CN=Steve Kille,O=Isode Limited,C=GB",
                  "subject": "CN=L. Eagle,O=Sue\\, Grabbit and Runn,C=GB"
                }
             ]
        }"#,
    )
    .unwrap();
    assert_eq!(
        daphne_worker_auth_method.bearer_token,
        Some(BearerToken::from("the bearer token".to_string()))
    );
    assert_eq!(
        daphne_worker_auth_method.cf_tls_client_auth,
        Some(trusted_certs),
    );
}
