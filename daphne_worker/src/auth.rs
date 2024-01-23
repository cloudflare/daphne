// Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use daphne::auth::BearerToken;
use daphne_service_utils::auth::{DaphneAuth, TlsClientAuth};
use worker::Request;

pub(crate) fn auth_from_request(req: &Request) -> DaphneAuth {
    DaphneAuth {
        bearer_token: req
            .headers()
            .get("DAP-Auth-Token")
            .expect("The header value is never invalid")
            .map(BearerToken::from),

        // The runtime gives us a cf_tls_client_auth whether the communication was secured by
        // it or not, so if a certificate wasn't presented, treat it as if it weren't there.
        // Literal "1" indicates that a certificate was presented.
        cf_tls_client_auth: req
            .cf()
            .tls_client_auth()
            .filter(|auth| auth.cert_presented() == "1")
            .map(|cert| {
                let verified = cert.cert_verified();
                let issuer = cert.cert_issuer_dn_rfc2253();
                let subject = cert.cert_subject_dn_rfc2253();
                TlsClientAuth {
                    verified,
                    issuer,
                    subject,
                }
            }),
    }
}
