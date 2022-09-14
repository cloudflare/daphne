// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Hybrid Public-Key Encryption ([HPKE](https://datatracker.ietf.org/doc/rfc9180/)).

use hpke_rs::{Hpke, HpkeError, HpkePrivateKey, HpkePublicKey, Mode};
use hpke_rs_crypto::{
    error::Error,
    types::{AeadAlgorithm, KdfAlgorithm, KemAlgorithm},
    HpkeCrypto,
};
use hpke_rs_rust_crypto::HpkeRustCrypto as ImplHpkeCrypto;

use crate::{
    messages::{
        decode_u16_bytes, encode_u16_bytes, HpkeAeadId, HpkeCiphertext, HpkeConfig, HpkeKdfId,
        HpkeKemId, Id, TransitionFailure,
    },
    DapError,
};
use async_trait::async_trait;
use prio::codec::{CodecError, Decode, Encode};
use serde::{Deserialize, Serialize};
use std::io::Cursor;

impl From<HpkeError> for DapError {
    fn from(_e: HpkeError) -> Self {
        Self::Transition(TransitionFailure::HpkeDecryptError)
    }
}

impl From<Error> for DapError {
    fn from(_e: Error) -> Self {
        Self::Transition(TransitionFailure::HpkeDecryptError)
    }
}

fn check_suite<T: HpkeCrypto>(
    kem_id: HpkeKemId,
    kdf_id: HpkeKdfId,
    aead_id: HpkeAeadId,
) -> Result<Hpke<T>, DapError> {
    let s = format!(
        "HPKE ciphersuite not implemented ({}, {}, {})",
        u16::from(kem_id),
        u16::from(kdf_id),
        u16::from(aead_id)
    );
    let maperr = |_| DapError::Fatal(s.clone());
    let kem = KemAlgorithm::try_from(u16::from(kem_id)).map_err(maperr)?;
    let kdf = KdfAlgorithm::try_from(u16::from(kdf_id)).map_err(maperr)?;
    let aead = AeadAlgorithm::try_from(u16::from(aead_id)).map_err(maperr)?;
    match (kem, kdf, aead) {
        (KemAlgorithm::DhKemP256, KdfAlgorithm::HkdfSha256, AeadAlgorithm::Aes128Gcm)
        | (KemAlgorithm::DhKem25519, KdfAlgorithm::HkdfSha256, AeadAlgorithm::Aes128Gcm) => {
            Ok(Hpke::new(Mode::Base, kem, kdf, aead))
        }
        _ => Err(DapError::Fatal(s)),
    }
}

impl HpkeConfig {
    /// Encrypt `plaintext` with info string `info` and associated data `aad` using this HPKE
    /// configuration. The return values are the encapsulated key and the ciphertext.
    pub fn encrypt(
        &self,
        info: &[u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), DapError> {
        let sender: Hpke<ImplHpkeCrypto> = check_suite(self.kem_id, self.kdf_id, self.aead_id)?;
        let pk = HpkePublicKey::new(self.public_key.clone());
        let (enc, mut ctx) = sender.setup_sender(&pk, info, None, None, None)?;
        let ciphertext = ctx.seal(aad, plaintext)?;
        Ok((enc, ciphertext))
    }

    pub(crate) fn decrypt(
        &self,
        secret_key: &[u8],
        info: &[u8],
        aad: &[u8],
        enc: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, DapError> {
        let receiver: Hpke<ImplHpkeCrypto> = check_suite(self.kem_id, self.kdf_id, self.aead_id)?;
        let sk = HpkePrivateKey::new(secret_key.to_vec());
        let mut ctx = receiver.setup_receiver(enc, &sk, info, None, None, None)?;
        let plaintext = ctx.open(aad, ciphertext)?;
        Ok(plaintext)
    }
}

/// HPKE decrypter functionality.
#[async_trait(?Send)]
pub trait HpkeDecrypter<'a> {
    /// Return type of `get_hpke_config_for()`, wraps a reference to an HPKE config.
    type WrappedHpkeConfig: AsRef<HpkeConfig>;

    /// Look up the HPKE configuration to use for the given task ID (if specified).
    async fn get_hpke_config_for(
        &'a self,
        task_id: Option<&Id>,
    ) -> Result<Self::WrappedHpkeConfig, DapError>;

    /// Returns `true` if a ciphertext with the HPKE config ID can be consumed in the current task.
    async fn can_hpke_decrypt(&self, task_id: &Id, config_id: u8) -> Result<bool, DapError>;

    /// Decrypt the given HPKE ciphertext using the given info and AAD string.
    async fn hpke_decrypt(
        &self,
        task_id: &Id,
        info: &[u8],
        aad: &[u8],
        ciphertext: &HpkeCiphertext,
    ) -> Result<Vec<u8>, DapError>;
}

/// Struct that combines HpkeConfig and HpkeSecretKey
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct HpkeReceiverConfig {
    pub config: HpkeConfig,
    #[serde(with = "hex")]
    secret_key: Vec<u8>,
}

impl HpkeReceiverConfig {
    pub fn encrypt(
        &self,
        info: &[u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), DapError> {
        self.config.encrypt(info, aad, plaintext)
    }

    /// Decrypt `ciphertext` with info string `info` and associated data `aad` using this HPKE
    /// configuration and corresponding secret key. The return value is the plaintext.
    pub fn decrypt(
        &self,
        info: &[u8],
        aad: &[u8],
        enc: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, DapError> {
        self.config
            .decrypt(&self.secret_key, info, aad, enc, ciphertext)
    }

    /// Generate and return a new HPKE receiver context given a HPKE config ID and HPKE KEM.
    pub fn gen(id: u8, kem_id: HpkeKemId) -> Result<Self, DapError> {
        let kem = match kem_id {
            HpkeKemId::P256HkdfSha256 => KemAlgorithm::DhKemP256,
            HpkeKemId::X25519HkdfSha256 => KemAlgorithm::DhKem25519,
            HpkeKemId::NotImplemented(x) => {
                return Err(DapError::Fatal(format!("Unsupported KEM ({:?})", x)))
            }
        };
        let kdf = KdfAlgorithm::HkdfSha256;
        let aead = AeadAlgorithm::Aes128Gcm;
        let generator = Hpke::<ImplHpkeCrypto>::new(Mode::Base, kem, kdf, aead);
        match generator.generate_key_pair() {
            Ok(keypair) => {
                let pk = keypair.public_key();
                let sk = keypair.private_key();
                Ok(HpkeReceiverConfig {
                    config: HpkeConfig {
                        id,
                        kem_id,
                        kdf_id: HpkeKdfId::HkdfSha256,
                        aead_id: HpkeAeadId::Aes128Gcm,
                        public_key: Vec::from(pk.as_slice()),
                    },
                    secret_key: Vec::from(sk.as_slice()),
                })
            }
            Err(e) => Err(DapError::Fatal(format!(
                "bad key generation for KEM ({:?}) caused by {:?}",
                kem_id, e
            ))),
        }
    }

    /// Create a new HPKE receiver context given an HpkeConfig and a corresponding secret key.
    pub fn new(config: HpkeConfig, secret_key: Vec<u8>) -> Self {
        HpkeReceiverConfig { config, secret_key }
    }
}

#[async_trait(?Send)]
impl<'a> HpkeDecrypter<'a> for HpkeReceiverConfig {
    type WrappedHpkeConfig = HpkeConfig;

    async fn get_hpke_config_for(
        &'a self,
        _task_id: Option<&Id>,
    ) -> Result<Self::WrappedHpkeConfig, DapError> {
        unreachable!("not implemented");
    }

    async fn can_hpke_decrypt(&self, _task_id: &Id, config_id: u8) -> Result<bool, DapError> {
        Ok(config_id == self.config.id)
    }

    async fn hpke_decrypt(
        &self,
        _task_id: &Id,
        info: &[u8],
        aad: &[u8],
        ciphertext: &HpkeCiphertext,
    ) -> Result<Vec<u8>, DapError> {
        if ciphertext.config_id != self.config.id {
            return Err(DapError::Transition(TransitionFailure::HpkeUnknownConfigId));
        }
        self.decrypt(info, aad, &ciphertext.enc, &ciphertext.payload)
    }
}

impl Encode for HpkeReceiverConfig {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.config.encode(bytes);
        encode_u16_bytes(bytes, &self.secret_key);
    }
}

impl Decode for HpkeReceiverConfig {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        Ok(Self {
            config: HpkeConfig::decode(bytes)?,
            secret_key: decode_u16_bytes(bytes)?,
        })
    }
}

impl std::str::FromStr for HpkeReceiverConfig {
    type Err = serde_json::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        serde_json::from_str(s)
    }
}
