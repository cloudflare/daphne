// Copyright (c) 2023 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Authorization methods for Daphne-Worker.

use daphne::auth::BearerToken;
use serde::{Deserialize, Serialize};

/// HTTP client authorization for Daphne-Worker.
pub(crate) enum DaphneWorkerAuth {
    /// Bearer token, expected to appear in the "dap-auth-token" header.
    BearerToken(BearerToken),

    /// TLS client authentication. The client uses a certificate when establishing the TLS
    /// connection with the expected issuer and subject. This authorization method is
    /// Cloudflare-specific: Verifying the certificate itself is handled by the process that
    /// invoked this Worker. The customer zone is also expected to be configured to require mutual
    /// TLS for the route on which this Worker is listening.
    ///
    /// When this authorization method is used, we verify that the subject of the end-entity
    /// certificate is one of a set of allowed subjects. We expect there to be one and only one
    /// issuer for the end-entity certificate.
    ///
    /// # Caveats
    ///
    /// * For now, only the Helper supports TLS client auth; the Leader still expects a bearer
    ///   token to be configured for the task.
    ///
    /// * For now, TLS client auth is only enabled if the taskprov extension is configured.
    ///   Enabling this feature for other tasks will require a bit plumbing.
    ///
    /// # Zone configuration
    ///
    /// 1. SSL/TLS -> Client Certificates -> Create Client Certificate: Configure a certificate with
    ///   either by signing a CSR (using Cloudflare's managed CA) or generating a fresh certificate
    ///   (with the desired subject name) and secret key.
    ///
    /// 2. SSL/TLS -> Client Certificates -> Hosts: Add the hostname of the route on which the
    ///    Worker is listening.
    ///
    /// 3. Security -> WAF -> Create mTLS Rule: Create the firewall rule. Since we only require
    ///    authentication for POST request, the following rule is sufficient:
    ///
    ///    When incoming requests match…
    ///
    ///    ```text
    ///        (http.host in {"<HOSTNAME>"}
    ///          and (
    ///           (cf.tls_client_auth.cert_verified and http.request.method eq "POST")
    ///             or http.request.method eq "GET"
    ///          )
    ///        )
    ///    ```
    ///
    ///    Then... Allow
    CfTlsClientAuth {
        /// Issuer of the end-entity certificate, a distignuished name formatted in compliance with
        /// RFC2253. Set to the value of the "certIssuerDNRFC2253" field from the "tlsCli:wqentAuth"
        /// structure of the incoming request:
        /// https://developers.cloudflare.com/workers/runtime-apis/request/#incomingrequestcfproperties
        cert_issuer: String,

        /// Subject of the end-entity certificate, a distinguished name formatted in
        /// compliance with RFC2253. Set to the "certSubjectDNRFC2253" field from the request's
        /// "tlsClientAuth" structure.
        cert_subject: String,
    },
}

impl AsRef<BearerToken> for DaphneWorkerAuth {
    fn as_ref(&self) -> &BearerToken {
        match self {
            Self::BearerToken(bearer_token) => bearer_token,
            Self::CfTlsClientAuth { .. } => {
                panic!("tried to use TLS client authorization as bearer token")
            }
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(try_from = "SerializedDaphneWorkerAuthMethod")]
pub(crate) enum DaphneWorkerAuthMethod {
    /// Expected bearer token.
    BearerToken(BearerToken),

    /// Valid issuer and subjects of the ent-entity certificate.
    CfTlsClientAuth {
        valid_cert_issuer: String,
        valid_cert_subjects: Vec<String>,
    },
}

impl AsRef<BearerToken> for DaphneWorkerAuthMethod {
    fn as_ref(&self) -> &BearerToken {
        match self {
            Self::BearerToken(bearer_token) => bearer_token,
            Self::CfTlsClientAuth { .. } => {
                panic!("tried to use TLS client authorization as bearer token")
            }
        }
    }
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum SerializedDaphneWorkerAuthMethod {
    BearerToken(String),
    CfTlsClientAuth {
        valid_cert_issuer: String,
        valid_cert_subjects: Vec<String>,
    },
}

impl From<SerializedDaphneWorkerAuthMethod> for DaphneWorkerAuthMethod {
    fn from(serialized: SerializedDaphneWorkerAuthMethod) -> Self {
        match serialized {
            SerializedDaphneWorkerAuthMethod::BearerToken(bearer_token) => {
                Self::BearerToken(BearerToken::from(bearer_token))
            }
            SerializedDaphneWorkerAuthMethod::CfTlsClientAuth {
                valid_cert_issuer,
                valid_cert_subjects,
            } => Self::CfTlsClientAuth {
                valid_cert_issuer,
                valid_cert_subjects,
            },
        }
    }
}
