// Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use std::{borrow::Cow, env, io::Cursor, path::Path};

use anyhow::{anyhow, bail, Context};
use daphne::messages::{decode_base64url_vec, HpkeConfigList};
use daphne_service_utils::http_headers;
use prio::codec::Decode;
use reqwest::{Client, Identity, IntoUrl, RequestBuilder};
use url::Url;
use webpki::{EndEntityCert, ECDSA_P256_SHA256};
use x509_parser::pem::Pem;

use crate::response_to_anyhow;

pub struct HttpClient {
    using_mtls: bool,
    inner: HttpClientInner,
}

enum HttpClientInner {
    /// Never reuse the same reqwest client for two different http requests. Usefull for specific
    /// debugging or load testing scenarios.
    NoReuse(Option<Identity>),
    /// Always use the same reqwest client when making requests, this is faster and probably what
    /// you want.
    Reuse(Client),
}

fn load_identity() -> anyhow::Result<Option<Identity>> {
    // LEADER_ variables left here for backwards compatibility
    const TLS_CLIENT_CERT_VAR: [&str; 2] = ["TLS_CLIENT_CERT", "LEADER_TLS_CLIENT_CERT"];
    const TLS_CLIENT_KEY_VAR: [&str; 2] = ["TLS_CLIENT_KEY", "LEADER_TLS_CLIENT_KEY"];

    let leader_tls_client_cert = TLS_CLIENT_CERT_VAR
        .iter()
        .find_map(|key| env::var(key).ok());
    let leader_tls_client_key = TLS_CLIENT_KEY_VAR.iter().find_map(|key| env::var(key).ok());
    match (leader_tls_client_cert, leader_tls_client_key) {
        (Some(cert), Some(key)) => Ok(Some(
            Identity::from_pem((cert + "\n" + &key).as_bytes())
                .with_context(|| "failed to parse Leader TLS client certificate")?,
        )),
        (None, None) => Ok(None),
        (Some(_), None) => bail!("{TLS_CLIENT_KEY_VAR:?} is not set"),
        (None, Some(_)) => bail!("{TLS_CLIENT_CERT_VAR:?} is not set"),
    }
}

fn init_reqwest_client(identity: Option<Identity>) -> reqwest::Client {
    let mut tls = rustls::ClientConfig::builder_with_provider(
        rustls::crypto::aws_lc_rs::default_provider().into(),
    )
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates({
        let mut store = rustls::RootCertStore::empty();
        store.add_parsable_certificates(rustls_native_certs::load_native_certs().unwrap());
        store
    })
    .with_no_client_auth();
    tls.key_log = std::sync::Arc::new(rustls::KeyLogFile::new());

    // Build the HTTP client.
    let mut http_client_builder = reqwest::Client::builder()
        // it takes too long to generate reports for larger dimensions, causing the worker
        // to drop idle connections
        .pool_max_idle_per_host(0)
        // Don't handle redirects automatically so that we can control the client behavior.
        .redirect(reqwest::redirect::Policy::none())
        // We might as well use rustls because we already need the feature for
        // `Identity::from_pem()`.
        .use_preconfigured_tls(tls);

    if let Some(identity) = identity {
        // Configure TLS certificate, if available.
        http_client_builder = http_client_builder.identity(identity);
    }
    http_client_builder
        .build()
        .expect("failed to build http client")
}

impl HttpClient {
    pub fn new() -> anyhow::Result<Self> {
        let identity = load_identity()?;
        Ok(Self {
            using_mtls: identity.is_some(),
            inner: HttpClientInner::Reuse(init_reqwest_client(identity)),
        })
    }

    /// Create an http client that never reuses the same client for two requests.
    pub fn new_no_reuse() -> anyhow::Result<Self> {
        let identity = load_identity()?;
        Ok(Self {
            using_mtls: identity.is_some(),
            inner: HttpClientInner::NoReuse(identity),
        })
    }

    fn client(&self) -> Cow<'_, Client> {
        match &self.inner {
            HttpClientInner::Reuse(c) => Cow::Borrowed(c),
            HttpClientInner::NoReuse(identity) => Cow::Owned(init_reqwest_client(identity.clone())),
        }
    }

    pub fn using_mtls(&self) -> bool {
        self.using_mtls
    }

    pub fn get<U: IntoUrl>(&self, url: U) -> RequestBuilder {
        self.client().get(url)
    }

    pub fn post<U: IntoUrl>(&self, url: U) -> RequestBuilder {
        self.client().post(url)
    }

    pub fn put<U: IntoUrl>(&self, url: U) -> RequestBuilder {
        self.client().post(url)
    }

    pub async fn get_hpke_config(
        &self,
        base_url: &Url,
        certificate_file: Option<&Path>,
    ) -> anyhow::Result<HpkeConfigList> {
        let url = base_url.join("hpke_config")?;
        let resp = self
            .get(url.as_str())
            .send()
            .await
            .with_context(|| "request failed")?;
        if !resp.status().is_success() {
            return Err(response_to_anyhow(resp).await);
        }
        let maybe_signature = resp.headers().get(http_headers::HPKE_SIGNATURE).cloned();
        let hpke_config_bytes = resp.bytes().await.context("failed to read hpke config")?;
        if let Some(cert_path) = certificate_file {
            let cert = std::fs::read_to_string(cert_path).context("reading the certificate")?;
            let Some(signature) = maybe_signature else {
                anyhow::bail!("Aggregator did not sign its response");
            };
            let signature_bytes =
                decode_base64url_vec(signature.as_bytes()).context("decoding the signature")?;
            let (cert_pem, _bytes_read) =
                Pem::read(Cursor::new(cert.as_bytes())).context("reading PEM certificate")?;
            let cert = EndEntityCert::try_from(cert_pem.contents.as_ref())
                .map_err(|e| anyhow!("{e:?}")) // webpki::Error does not implement std::error::Error
                .context("parsing PEM certificate")?;

            cert.verify_signature(
                &ECDSA_P256_SHA256,
                &hpke_config_bytes,
                signature_bytes.as_ref(),
            )
            .map_err(|e| anyhow!("signature not verified: {}", e.to_string()))?;
        }
        Ok(HpkeConfigList::get_decoded(&hpke_config_bytes)?)
    }
}
