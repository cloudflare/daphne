// Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use std::{io::Cursor, path::Path};

use anyhow::{anyhow, Context as _};
use daphne::messages::{decode_base64url_vec, HpkeConfigList};
use daphne_service_utils::http_headers;
use prio::codec::Decode as _;
use url::Url;
use webpki::{EndEntityCert, ECDSA_P256_SHA256};
use x509_parser::pem::Pem;

use crate::HttpClient;

use super::retry;

impl HttpClient {
    pub async fn get_hpke_config(
        &self,
        base_url: &Url,
        certificate_file: Option<&Path>,
    ) -> anyhow::Result<HpkeConfigList> {
        let url = base_url.join("hpke_config")?;
        retry(
            || async {
                self.get(url.as_str())
                    .send()
                    .await
                    .with_context(|| "request failed")
            },
            |resp| async {
                let maybe_signature = resp.headers().get(http_headers::HPKE_SIGNATURE).cloned();
                let hpke_config_bytes = resp.bytes().await.context("failed to read hpke config")?;
                if let Some(cert_path) = certificate_file {
                    let cert =
                        std::fs::read_to_string(cert_path).context("reading the certificate")?;
                    let Some(signature) = maybe_signature else {
                        anyhow::bail!("Aggregator did not sign its response");
                    };
                    let signature_bytes = decode_base64url_vec(signature.as_bytes())
                        .context("decoding the signature")?;
                    let (cert_pem, _bytes_read) = Pem::read(Cursor::new(cert.as_bytes()))
                        .context("reading PEM certificate")?;
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
            },
        )
        .await
    }
}
