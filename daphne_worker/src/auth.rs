// Copyright (c) 2023 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Authorization methods for Daphne-Worker.

use daphne::auth::BearerToken;
use serde::{Deserialize, Serialize};

pub(crate) struct TlsClientAuth {
    pub verified: String,
    pub issuer: String,
    pub subject: String,
}

impl From<worker::TlsClientAuth> for TlsClientAuth {
    fn from(value: worker::TlsClientAuth) -> Self {
        let verified: String = value.cert_verified();
        let issuer: String = value.cert_issuer_dn_rfc2253();
        let subject: String = value.cert_subject_dn_rfc2253();
        Self {
            verified,
            issuer,
            subject,
        }
    }
}

/// HTTP client authorization for Daphne-Worker.
///
/// Multiple authorization methods can be configured. The sender may present multiple authorization
/// methods; the request is authorized if validation of all presented methods succeed. If an
/// authorization method is presented, but the server is not configured to validate it, then
/// validation of that method will fail.
//
// TODO(cjpatton) Add an authorization method for Cloudflare Access
// (https://www.cloudflare.com/products/zero-trust/access/). This allows us to delegate access
// control to that service; Daphne-Worker would just need to verify that Access granted access.
pub(crate) struct DaphneWorkerAuth {
    /// Bearer token, expected to appear in the "dap-auth-token" header.
    pub(crate) bearer_token: Option<BearerToken>,

    /// TLS client authentication. The client uses a certificate when establishing the TLS
    /// connection with the expected issuer and subject. This authorization method is
    /// Cloudflare-specific: Verifying the certificate itself is handled by the process that
    /// invoked this Worker. The customer zone is also expected to be configured to require mutual
    /// TLS for the route on which this Worker is listening.
    ///
    /// When this authorization method is used, we verify that the following:
    ///
    /// * A certificate was presented and was successfully verified by the TLS server
    ///
    /// * The certificate details match those of one of a preconfigured set of trusted
    /// certificates.
    ///
    /// # Caveats
    ///
    /// * For now, only the Helper supports TLS client auth; the Leader still expects a bearer
    ///   token to be configured for the task.
    ///
    /// * For now, TLS client auth is only enabled if the taskprov extension is configured.
    ///   Enabling this feature for other tasks will require a bit plumbing.
    pub(crate) cf_tls_client_auth: Option<TlsClientAuth>,
}

impl AsRef<BearerToken> for DaphneWorkerAuth {
    fn as_ref(&self) -> &BearerToken {
        if let Some(ref bearer_token) = self.bearer_token {
            bearer_token
        } else {
            // We would only try this method if we previously resolved to use a bearer token for
            // authorization.
            unreachable!("no bearer token provided by sender")
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(try_from = "SerializedDaphneWorkerAuthMethod")]
pub(crate) struct DaphneWorkerAuthMethod {
    /// Expected bearer token.
    pub(crate) bearer_token: Option<BearerToken>,

    /// Details of trusted TLS client certificates.
    pub(crate) cf_tls_client_auth: Option<Vec<TlsCertInfo>>,
}

/// TLS certificate details related to authorization.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct TlsCertInfo {
    /// Certificate issuer. Checked against the value of the "certIssuerDNRFC2253" field from the
    /// "tlsClientAuth" object passed by the Workers runtime to the request handler.
    /// https://developers.cloudflare.com/workers/runtime-apis/request/#incomingrequestcfproperties
    pub(crate) issuer: String,

    /// Certificate subject. Checked against the value of the "certSubjectDNRFC2253" field from the
    /// "tlsClientAuth" object passed by the Workers runtime to the request handler.
    pub(crate) subject: String,
}

impl AsRef<BearerToken> for DaphneWorkerAuthMethod {
    fn as_ref(&self) -> &BearerToken {
        if let Some(ref bearer_token) = self.bearer_token {
            bearer_token
        } else {
            // We would only try this method if we previously resolved to use a bearer token for
            // authorization.
            unreachable!("no bearer token provided by sender")
        }
    }
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
struct SerializedDaphneWorkerAuthMethod {
    #[serde(skip_serializing_if = "Option::is_none")]
    bearer_token: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    cf_tls_client_auth: Option<Vec<TlsCertInfo>>,
}

impl From<SerializedDaphneWorkerAuthMethod> for DaphneWorkerAuthMethod {
    fn from(serialized: SerializedDaphneWorkerAuthMethod) -> Self {
        Self {
            bearer_token: serialized.bearer_token.map(BearerToken::from),
            cf_tls_client_auth: serialized.cf_tls_client_auth,
        }
    }
}

#[cfg(test)]
mod test {
    use super::{BearerToken, DaphneWorkerAuthMethod, TlsCertInfo};

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
}
