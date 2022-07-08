// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Hybrid Public-Key Encryption ([HPKE](https://datatracker.ietf.org/doc/rfc9180/)).

use crate::{
    messages::{HpkeAeadId, HpkeCiphertext, HpkeConfig, HpkeKdfId, HpkeKemId, Id},
    DapError,
};
use hpke::{aead, kdf, kem, Deserializable, HpkeError, Kem, OpModeR};
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;

impl HpkeConfig {
    /// Encrypt `plaintext` with info string `info` and associated data `aad` using this HPKE
    /// configuration. The return values are the encapsulated key and the ciphertext.
    pub fn encrypt(
        &self,
        info: &[u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), DapError> {
        use hpke::{OpModeS, Serializable};

        check_suite(self)?;
        let pk = <kem::X25519HkdfSha256 as Kem>::PublicKey::from_bytes(&self.public_key)?;
        let (enc, mut sender) = hpke::setup_sender::<
            aead::AesGcm128,
            kdf::HkdfSha256,
            kem::X25519HkdfSha256,
            _,
        >(&OpModeS::Base, &pk, info, &mut rand::thread_rng())?;

        Ok((enc.to_bytes().to_vec(), sender.seal(plaintext, aad)?))
    }
}

/// An HPKE configuration and corresponding secret key.
#[derive(Deserialize, Serialize)]
#[serde(try_from = "ShadowHpkeSecretKey")]
pub struct HpkeSecretKey {
    pub id: u8,
    sk: <kem::X25519HkdfSha256 as Kem>::PrivateKey,
}

// Workaround struct for allowing the secret key to be encoded in hex.
#[derive(Deserialize, Serialize)]
struct ShadowHpkeSecretKey {
    id: u8,
    #[serde(with = "hex")]
    sk: Vec<u8>,
}

impl TryFrom<ShadowHpkeSecretKey> for HpkeSecretKey {
    type Error = HpkeError;

    fn try_from(shadow: ShadowHpkeSecretKey) -> Result<Self, Self::Error> {
        let sk = <kem::X25519HkdfSha256 as Kem>::PrivateKey::from_bytes(&shadow.sk)?;
        Ok(HpkeSecretKey { id: shadow.id, sk })
    }
}

impl HpkeSecretKey {
    /// Decrypt `ciphertext` with info string `info` and associated data `aad` using this HPKE
    /// configuration and corresponding secret key. The return value is the plaintext.
    #[allow(dead_code)]
    pub fn decrypt(
        &self,
        info: &[u8],
        aad: &[u8],
        enc: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, HpkeError> {
        let enc = <kem::X25519HkdfSha256 as Kem>::EncappedKey::from_bytes(enc)?;
        let mut receiver = hpke::setup_receiver::<
            aead::AesGcm128,
            kdf::HkdfSha256,
            kem::X25519HkdfSha256,
        >(&OpModeR::Base, &self.sk, &enc, info)?;
        receiver.open(ciphertext, aad)
    }

    #[cfg(test)]
    pub(crate) fn gen(id: u8) -> (HpkeConfig, Self) {
        use hpke::Serializable;
        let (sk, pk) = kem::X25519HkdfSha256::gen_keypair(&mut rand::thread_rng());
        (
            HpkeConfig {
                id,
                kem_id: HpkeKemId::X25519HkdfSha256,
                kdf_id: HpkeKdfId::HkdfSha256,
                aead_id: HpkeAeadId::Aes128Gcm,
                public_key: pk.to_bytes().to_vec(),
            },
            Self { id, sk },
        )
    }
}

impl HpkeDecrypter for HpkeSecretKey {
    fn get_hpke_config_for(&self, _task_id: &Id) -> Option<&HpkeConfig> {
        // TODO(issue#12) Have HpkeSecretKey subsume the config.
        unreachable!("not implemented");
    }

    fn can_hpke_decrypt(&self, _task_id: &Id, config_id: u8) -> bool {
        config_id == self.id
    }

    fn hpke_decrypt(
        &self,
        _task_id: &Id,
        info: &[u8],
        aad: &[u8],
        ciphertext: &HpkeCiphertext,
    ) -> std::result::Result<Vec<u8>, DapError> {
        Ok(self.decrypt(info, aad, &ciphertext.enc, &ciphertext.payload)?)
    }
}

// Check that the cipher suite is the one we support.
fn check_suite(config: &HpkeConfig) -> Result<(), DapError> {
    match (config.kem_id, config.kdf_id, config.aead_id) {
        (HpkeKemId::X25519HkdfSha256, HpkeKdfId::HkdfSha256, HpkeAeadId::Aes128Gcm) => Ok(()),
        (kem_id, kdf_id, aead_id) => Err(DapError::Fatal(format!(
            "HPKE ciphersuite not implemented ({}, {}, {})",
            u16::from(kem_id),
            u16::from(kdf_id),
            u16::from(aead_id)
        ))),
    }
}

/// HPKE decrypter functionality.
pub trait HpkeDecrypter {
    /// Look up the HPKE configuration to use for the given task ID.
    fn get_hpke_config_for(&self, task_id: &Id) -> Option<&HpkeConfig>;

    /// Returns `true` if a ciphertext with the HPKE config ID can be consumed in the current task.
    fn can_hpke_decrypt(&self, task_id: &Id, config_id: u8) -> bool;

    /// Decrypt the given HPKE ciphertext using the given info and AAD string.
    fn hpke_decrypt(
        &self,
        task_id: &Id,
        info: &[u8],
        aad: &[u8],
        ciphertext: &HpkeCiphertext,
    ) -> Result<Vec<u8>, DapError>;
}

/// Struct that combines HpkeConfig and HpkeSecretKey
#[derive(Deserialize, Serialize)]
pub struct HpkeReceiverConfig {
    pub config: HpkeConfig,
    pub secret_key: HpkeSecretKey,
}
