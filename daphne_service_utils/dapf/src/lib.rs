// Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

pub mod acceptance;
mod test_durations;

use std::{io::Cursor, path::Path};

use anyhow::{anyhow, Context};
use daphne::{
    hpke::HpkeConfig,
    messages::{decode_base64url_vec, HpkeConfigList},
    DapVersion,
};
use daphne_service_utils::http_headers;
use prio::codec::Decode;
use reqwest::Client;
use url::Url;
use webpki::{EndEntityCert, ECDSA_P256_SHA256};
use x509_parser::pem::Pem;

pub trait HttpClientExt {
    fn get_hpke_config(
        &self,
        base_url: &Url,
        certificate_file: Option<&Path>,
    ) -> impl std::future::Future<Output = anyhow::Result<HpkeConfigList>> + Send;
}

impl HttpClientExt for Client {
    async fn get_hpke_config(
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
            return Err(anyhow!("unexpected response: {:?}", resp));
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

        match deduce_dap_version_from_url(base_url)? {
            DapVersion::Draft02 => Ok(HpkeConfigList {
                hpke_configs: vec![HpkeConfig::get_decoded(&hpke_config_bytes)?],
            }),
            DapVersion::Latest | DapVersion::Draft09 => {
                Ok(HpkeConfigList::get_decoded(&hpke_config_bytes)?)
            }
        }
    }
}

pub fn deduce_dap_version_from_url(url: &Url) -> anyhow::Result<DapVersion> {
    url.path_segments()
        .context("no version specified in leader url")?
        .next()
        .unwrap() // when path_segments returns Some it's guaranteed to contain at least one segment
        .parse()
        .context("failed to parse version parameter from url")
}
