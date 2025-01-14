// Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use std::{borrow::Cow, env};

use anyhow::{anyhow, bail};
use reqwest::{Client, IntoUrl, RequestBuilder};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls_pemfile::Item;

pub struct HttpClient {
    using_mtls: bool,
    inner: HttpClientInner,
}

#[allow(clippy::large_enum_variant)]
enum HttpClientInner {
    /// Never reuse the same reqwest client for two different http requests. Usefull for specific
    /// debugging or load testing scenarios.
    NoReuse { tls: rustls::ClientConfig },
    /// Always use the same reqwest client when making requests, this is faster and probably what
    /// you want.
    Reuse(Client),
}

fn load_identity() -> anyhow::Result<Option<(CertificateDer<'static>, PrivateKeyDer<'static>)>> {
    // LEADER_ variables left here for backwards compatibility
    const TLS_CLIENT_CERT_VAR: [&str; 2] = ["TLS_CLIENT_CERT", "LEADER_TLS_CLIENT_CERT"];
    const TLS_CLIENT_KEY_VAR: [&str; 2] = ["TLS_CLIENT_KEY", "LEADER_TLS_CLIENT_KEY"];

    let leader_tls_client_cert = TLS_CLIENT_CERT_VAR
        .iter()
        .find_map(|key| env::var(key).ok());
    let leader_tls_client_key = TLS_CLIENT_KEY_VAR.iter().find_map(|key| env::var(key).ok());
    match (leader_tls_client_cert, leader_tls_client_key) {
        (Some(mut cert), Some(mut key)) => {
            for pem in [&mut cert, &mut key] {
                if !pem.ends_with('\n') {
                    pem.push('\n');
                }
            }
            let Some((Item::X509Certificate(cert), _)) =
                rustls_pemfile::read_one_from_slice(cert.as_bytes())
                    .map_err(|e| anyhow!("failed to read cert: {e:?}. Cert was {cert:?}"))?
            else {
                panic!("invalid certificate in TLS_CLIENT_CERT")
            };
            let key = match rustls_pemfile::read_one_from_slice(key.as_bytes())
                .map_err(|e| anyhow!("failed to read key: {e:?}"))?
            {
                Some((Item::Pkcs1Key(key), _)) => PrivateKeyDer::from(key),
                Some((Item::Pkcs8Key(key), _)) => PrivateKeyDer::from(key),
                Some((Item::Sec1Key(key), _)) => PrivateKeyDer::from(key),
                _ => panic!("invalid private key in TLS_CLIENT_KEY"),
            };
            Ok(Some((cert, key)))
        }
        (None, None) => Ok(None),
        (Some(_), None) => bail!("{TLS_CLIENT_KEY_VAR:?} is not set"),
        (None, Some(_)) => bail!("{TLS_CLIENT_CERT_VAR:?} is not set"),
    }
}

type UsingMtls = bool;

fn setup_tls(enable_ssl_key_log_file: bool) -> anyhow::Result<(rustls::ClientConfig, UsingMtls)> {
    tracing::warn!("enabling SSLKEYLOGFILE");
    let tls = rustls::ClientConfig::builder_with_provider(
        rustls::crypto::aws_lc_rs::default_provider().into(),
    )
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates({
        let mut store = rustls::RootCertStore::empty();
        store.add_parsable_certificates(rustls_native_certs::load_native_certs().unwrap());
        store
    });
    let identity = load_identity()?;
    let using_mtls = identity.is_some();
    let mut tls = match identity {
        Some((cert, key)) => {
            tracing::info!("setting up mtls client certificate");
            tls.with_client_auth_cert(vec![cert], key)?
        }
        None => tls.with_no_client_auth(),
    };
    if enable_ssl_key_log_file {
        tls.key_log = std::sync::Arc::new(rustls::KeyLogFile::new());
    }
    Ok((tls, using_mtls))
}

fn init_reqwest_client(tls: rustls::ClientConfig) -> reqwest::Client {
    // Build the HTTP client.
    reqwest::Client::builder()
        // it takes too long to generate reports for larger dimensions, causing the worker
        // to drop idle connections
        .pool_max_idle_per_host(0)
        // Don't handle redirects automatically so that we can control the client behavior.
        .redirect(reqwest::redirect::Policy::none())
        .use_preconfigured_tls(tls)
        .build()
        .expect("failed to build http client")
}

impl HttpClient {
    pub fn new(enable_ssl_key_log_file: bool) -> anyhow::Result<Self> {
        let (tls, using_mtls) = setup_tls(enable_ssl_key_log_file)?;
        Ok(Self {
            using_mtls,
            inner: HttpClientInner::Reuse(init_reqwest_client(tls)),
        })
    }

    /// Create an http client that never reuses the same client for two requests.
    pub fn new_no_reuse(enable_ssl_key_log_file: bool) -> anyhow::Result<Self> {
        let (tls, using_mtls) = setup_tls(enable_ssl_key_log_file)?;
        Ok(Self {
            using_mtls,
            inner: HttpClientInner::NoReuse { tls },
        })
    }

    fn client(&self) -> Cow<'_, Client> {
        match &self.inner {
            HttpClientInner::Reuse(c) => Cow::Borrowed(c),
            HttpClientInner::NoReuse { tls } => Cow::Owned(init_reqwest_client(tls.clone())),
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
        self.client().put(url)
    }
}
