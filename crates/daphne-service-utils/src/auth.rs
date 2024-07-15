// Copyright (c) 2023 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Authorization methods for Daphne-Worker.

use std::fmt::Debug;

use daphne::auth::BearerToken;
use serde::{Deserialize, Serialize};

#[derive(PartialEq, Eq)]
pub struct TlsClientAuth {
    pub verified: String,
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
#[derive(PartialEq)]
pub struct DaphneAuth {
    /// Bearer token, expected to appear in the
    /// [`DAP_AUTH_TOKEN`](crate::http_headers::DAP_AUTH_TOKEN) header.
    pub bearer_token: Option<BearerToken>,

    /// TLS client authentication. The client uses a certificate when establishing the TLS
    /// connection. This authorization method is Cloudflare-specific: Verifying the certificate
    /// itself is handled by the process that invoked this Worker. The customer zone is also
    /// expected to be configured to require mutual TLS for the route on which this Worker is
    /// listening.
    ///
    /// When this authorization method is used, we verify that a certificate was presented and was
    /// successfully verified by the TLS server.
    ///
    /// # Caveats
    ///
    /// * For now, only the Helper supports TLS client auth; the Leader still expects a bearer
    ///   token to be configured for the task.
    ///
    /// * For now, TLS client auth is only enabled if the taskprov extension is configured.
    ///   Enabling this feature for other tasks will require a bit plumbing.
    pub cf_tls_client_auth: Option<TlsClientAuth>,
}

// Custom debug implementation to avoid exposing sensitive information.
impl Debug for DaphneAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // pattern match on self to get a compiler error if the struct changes
        let Self {
            bearer_token,
            cf_tls_client_auth,
        } = self;

        fn opt_to_str<T>(o: &Option<T>) -> &dyn Debug {
            if o.is_some() {
                &"is-present"
            } else {
                &"is-missing"
            }
        }

        f.debug_struct("DaphneAuth")
            .field("bearer_token", opt_to_str(bearer_token))
            .field("cf_tls_client_auth", opt_to_str(cf_tls_client_auth))
            .finish()
    }
}

// TODO(mendess): remove this implementation. Implementations of AsRef should never panic
impl AsRef<BearerToken> for DaphneAuth {
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

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct DaphneWorkerAuthMethod {
    /// Expected bearer token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bearer_token: Option<BearerToken>,
}

// TODO(mendess): remove this implementation. Implementations of AsRef should never panic
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

#[cfg(test)]
mod test {
    use super::{BearerToken, DaphneWorkerAuthMethod};

    #[test]
    fn daphne_worker_auth_method_json_serialization() {
        let daphne_worker_auth_method: DaphneWorkerAuthMethod =
            serde_json::from_str(r#"{"bearer_token":"the bearer token"}"#).unwrap();
        assert_eq!(
            daphne_worker_auth_method.bearer_token,
            Some(BearerToken::from("the bearer token".to_string()))
        );

        let daphne_worker_auth_method: DaphneWorkerAuthMethod = serde_json::from_str("{}").unwrap();
        assert!(daphne_worker_auth_method.bearer_token.is_none());
    }
}
