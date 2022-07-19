// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Hybrid Public-Key Encryption ([HPKE](https://datatracker.ietf.org/doc/rfc9180/)).

use crate::{
    messages::{
        decode_u16_bytes, encode_u16_bytes, HpkeAeadId, HpkeCiphertext, HpkeConfig, HpkeKdfId,
        HpkeKemId, Id,
    },
    DapError,
};
use hpke::{aead, kdf, kem, Deserializable, HpkeError, Kem, OpModeR};
use prio::codec::{CodecError, Decode, Encode};
use serde::{Deserialize, Serialize};
use std::io::Cursor;

impl HpkeConfig {
    fn check_suite(&self) -> Result<(), DapError> {
        match (self.kem_id, self.kdf_id, self.aead_id) {
            (HpkeKemId::X25519HkdfSha256, HpkeKdfId::HkdfSha256, HpkeAeadId::Aes128Gcm) => Ok(()),
            (kem_id, kdf_id, aead_id) => Err(DapError::Fatal(format!(
                "HPKE ciphersuite not implemented ({}, {}, {})",
                u16::from(kem_id),
                u16::from(kdf_id),
                u16::from(aead_id)
            ))),
        }
    }

    /// Encrypt `plaintext` with info string `info` and associated data `aad` using this HPKE
    /// configuration. The return values are the encapsulated key and the ciphertext.
    pub fn encrypt(
        &self,
        info: &[u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), DapError> {
        use hpke::{OpModeS, Serializable};

        self.check_suite()?;
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
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct HpkeReceiverConfig {
    pub config: HpkeConfig,
    #[serde(with = "hex")]
    secret_key: Vec<u8>,
}

impl HpkeReceiverConfig {
    // Check that the cipher suite is the one we support.
    fn check_suite(&self) -> Result<(), DapError> {
        match (self.config.kem_id, self.config.kdf_id, self.config.aead_id) {
            (HpkeKemId::X25519HkdfSha256, HpkeKdfId::HkdfSha256, HpkeAeadId::Aes128Gcm) => Ok(()),
            (kem_id, kdf_id, aead_id) => Err(DapError::Fatal(format!(
                "HPKE ciphersuite not implemented ({}, {}, {})",
                u16::from(kem_id),
                u16::from(kdf_id),
                u16::from(aead_id)
            ))),
        }
    }

    pub fn encrypt(
        &self,
        info: &[u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), DapError> {
        use hpke::{OpModeS, Serializable};

        self.check_suite()?;
        let pk = <kem::X25519HkdfSha256 as Kem>::PublicKey::from_bytes(&self.config.public_key)?;
        let (enc, mut sender) = hpke::setup_sender::<
            aead::AesGcm128,
            kdf::HkdfSha256,
            kem::X25519HkdfSha256,
            _,
        >(&OpModeS::Base, &pk, info, &mut rand::thread_rng())?;

        Ok((enc.to_bytes().to_vec(), sender.seal(plaintext, aad)?))
    }

    /// Decrypt `ciphertext` with info string `info` and associated data `aad` using this HPKE
    /// configuration and corresponding secret key. The return value is the plaintext.
    pub fn decrypt(
        &self,
        info: &[u8],
        aad: &[u8],
        enc: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, HpkeError> {
        let sk = <kem::X25519HkdfSha256 as Kem>::PrivateKey::from_bytes(&self.secret_key)?;
        let enc = <kem::X25519HkdfSha256 as Kem>::EncappedKey::from_bytes(enc)?;
        let mut receiver = hpke::setup_receiver::<
            aead::AesGcm128,
            kdf::HkdfSha256,
            kem::X25519HkdfSha256,
        >(&OpModeR::Base, &sk, &enc, info)?;
        receiver.open(ciphertext, aad)
    }

    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) fn gen(id: u8) -> Self {
        use hpke::Serializable;
        let (sk, pk) = kem::X25519HkdfSha256::gen_keypair(&mut rand::thread_rng());
        HpkeReceiverConfig {
            config: HpkeConfig {
                id: id,
                kem_id: HpkeKemId::X25519HkdfSha256,
                kdf_id: HpkeKdfId::HkdfSha256,
                aead_id: HpkeAeadId::Aes128Gcm,
                public_key: pk.to_bytes().to_vec(),
            },
            secret_key: sk.to_bytes().to_vec(),
        }
    }
}

impl HpkeDecrypter for HpkeReceiverConfig {
    fn get_hpke_config_for(&self, _task_id: &Id) -> Option<&HpkeConfig> {
        unreachable!("not implemented");
    }

    fn can_hpke_decrypt(&self, _task_id: &Id, config_id: u8) -> bool {
        config_id == self.config.id
    }

    fn hpke_decrypt(
        &self,
        _task_id: &Id,
        info: &[u8],
        aad: &[u8],
        ciphertext: &HpkeCiphertext,
    ) -> Result<Vec<u8>, DapError> {
        Ok(self.decrypt(info, aad, &ciphertext.enc, &ciphertext.payload)?)
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
