// Copyright (c) 2023 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use crate::auth::DaphneWorkerAuthMethod;
use assert_matches::assert_matches;
use daphne::auth::BearerToken;

#[test]
fn daphne_worker_auth_method_json_serialiation() {
    let daphne_worker_auth_method: DaphneWorkerAuthMethod =
        serde_json::from_str(r#"{"bearer_token":"the bearer token"}"#).unwrap();
    assert_matches!(daphne_worker_auth_method,
        DaphneWorkerAuthMethod::BearerToken(bearer_token) => {
            bearer_token == BearerToken::from("the bearer token".to_string())
        }
    );

    let daphne_worker_auth_method: DaphneWorkerAuthMethod = serde_json::from_str(
        r#"{
            "cf_tls_client_auth": {
                "valid_cert_issuer": "CN=Steve Kille,O=Isode Limited,C=GB",
                "valid_cert_subjects": [
                    "OU=Sales+CN=J. Smith,O=Widget Inc.,C=US",
                    "CN=L. Eagle,O=Sue\\, Grabbit and Runn,C=GB"
                ]
            }
        }"#,
    )
    .unwrap();
    assert_matches!(daphne_worker_auth_method,
        DaphneWorkerAuthMethod::CfTlsClientAuth{ valid_cert_issuer, valid_cert_subjects } => {
            valid_cert_issuer == "CN=Steve Kille,O=Isode Limited,C=GB" &&
                valid_cert_subjects == [
                    "OU=Sales+CN=J. Smith,O=Widget Inc.,C=US",
                    "CN=L. Eagle,O=Sue\\, Grabbit and Runn,C=GB"
                ]
        }
    );
}
