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
    fatal_error,
    messages::{decode_u16_bytes, encode_u16_bytes, HpkeCiphertext, TaskId, TransitionFailure},
    DapError, DapVersion,
};
use async_trait::async_trait;
use prio::codec::{CodecError, Decode, Encode};
use serde::{Deserialize, Serialize};
use std::io::Cursor;

// Various algorithm constants
const KEM_ID_X25519_HKDF_SHA256: u16 = 0x0020;
const KEM_ID_P256_HKDF_SHA256: u16 = 0x0010;
const KDF_ID_HKDF_SHA256: u16 = 0x0001;
const AEAD_ID_AES128GCM: u16 = 0x0001;

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
    let maperr = |_| fatal_error!(err = s);
    let kem = KemAlgorithm::try_from(u16::from(kem_id)).map_err(maperr)?;
    let kdf = KdfAlgorithm::try_from(u16::from(kdf_id)).map_err(maperr)?;
    let aead = AeadAlgorithm::try_from(u16::from(aead_id)).map_err(maperr)?;
    match (kem, kdf, aead) {
        (
            KemAlgorithm::DhKemP256 | KemAlgorithm::DhKem25519,
            KdfAlgorithm::HkdfSha256,
            AeadAlgorithm::Aes128Gcm,
        ) => Ok(Hpke::new(Mode::Base, kem, kdf, aead)),
        _ => Err(fatal_error!(err = s)),
    }
}

/// Codepoint for KEM schemes compatible with HPKE.
#[derive(Clone, Copy, Deserialize, Serialize, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(any(test, feature = "test-utils"), derive(deepsize::DeepSizeOf))]
pub enum HpkeKemId {
    P256HkdfSha256,
    X25519HkdfSha256,
    NotImplemented(u16),
}

impl From<HpkeKemId> for u16 {
    fn from(kem_id: HpkeKemId) -> Self {
        match kem_id {
            HpkeKemId::P256HkdfSha256 => KEM_ID_P256_HKDF_SHA256,
            HpkeKemId::X25519HkdfSha256 => KEM_ID_X25519_HKDF_SHA256,
            HpkeKemId::NotImplemented(x) => x,
        }
    }
}

impl From<u16> for HpkeKemId {
    fn from(value: u16) -> Self {
        match value {
            KEM_ID_P256_HKDF_SHA256 => Self::P256HkdfSha256,
            KEM_ID_X25519_HKDF_SHA256 => Self::X25519HkdfSha256,
            x => Self::NotImplemented(x),
        }
    }
}

/// Codepoint for KDF schemes compatible with HPKE.
#[derive(Clone, Copy, Deserialize, Serialize, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(any(test, feature = "test-utils"), derive(deepsize::DeepSizeOf))]
pub enum HpkeKdfId {
    HkdfSha256,
    NotImplemented(u16),
}

impl From<HpkeKdfId> for u16 {
    fn from(kdf_id: HpkeKdfId) -> Self {
        match kdf_id {
            HpkeKdfId::HkdfSha256 => KDF_ID_HKDF_SHA256,
            HpkeKdfId::NotImplemented(x) => x,
        }
    }
}

impl From<u16> for HpkeKdfId {
    fn from(value: u16) -> Self {
        match value {
            KDF_ID_HKDF_SHA256 => Self::HkdfSha256,
            x => Self::NotImplemented(x),
        }
    }
}

/// Codepoint for AEAD schemes compatible with HPKE.
#[derive(Clone, Copy, Deserialize, Serialize, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(any(test, feature = "test-utils"), derive(deepsize::DeepSizeOf))]
pub enum HpkeAeadId {
    Aes128Gcm,
    NotImplemented(u16),
}

impl From<HpkeAeadId> for u16 {
    fn from(aead_id: HpkeAeadId) -> Self {
        match aead_id {
            HpkeAeadId::Aes128Gcm => AEAD_ID_AES128GCM,
            HpkeAeadId::NotImplemented(x) => x,
        }
    }
}

impl From<u16> for HpkeAeadId {
    fn from(value: u16) -> Self {
        match value {
            AEAD_ID_AES128GCM => Self::Aes128Gcm,
            x => Self::NotImplemented(x),
        }
    }
}

/// The HPKE public key configuration of a Server.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct HpkeConfig {
    pub id: u8,
    pub kem_id: HpkeKemId,
    pub kdf_id: HpkeKdfId,
    pub aead_id: HpkeAeadId,
    #[serde(with = "HpkePublicKeySerde")]
    pub public_key: HpkePublicKey,
}

#[cfg(any(test, feature = "test-utils"))]
impl deepsize::DeepSizeOf for HpkeConfig {
    fn deep_size_of_children(&self, context: &mut deepsize::Context) -> usize {
        self.kem_id.deep_size_of_children(context)
            + self.kdf_id.deep_size_of_children(context)
            + self.aead_id.deep_size_of_children(context)
            + std::mem::size_of_val(self.public_key.as_slice())
    }
}

impl AsRef<HpkeConfig> for HpkeConfig {
    fn as_ref(&self) -> &Self {
        self
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
        let mut sender: Hpke<ImplHpkeCrypto> = check_suite(self.kem_id, self.kdf_id, self.aead_id)?;
        let (enc, mut ctx) = sender.setup_sender(&self.public_key, info, None, None, None)?;
        let ciphertext = ctx.seal(aad, plaintext)?;
        Ok((enc, ciphertext))
    }

    pub(crate) fn decrypt(
        &self,
        private_key: &HpkePrivateKey,
        info: &[u8],
        aad: &[u8],
        enc: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, DapError> {
        let receiver: Hpke<ImplHpkeCrypto> = check_suite(self.kem_id, self.kdf_id, self.aead_id)?;
        let mut ctx = receiver.setup_receiver(enc, private_key, info, None, None, None)?;
        let plaintext = ctx.open(aad, ciphertext)?;
        Ok(plaintext)
    }
}

/// HPKE decrypter functionality.
#[cfg_attr(not(feature = "send-traits"), async_trait(?Send))]
#[cfg_attr(feature = "send-traits", async_trait)]
pub trait HpkeDecrypter {
    /// Return type of `get_hpke_config_for()`, wraps a reference to an HPKE config.
    type WrappedHpkeConfig<'a>: AsRef<HpkeConfig> + Send
    where
        Self: 'a;

    /// Look up the HPKE configuration to use for the given task ID (if specified).
    async fn get_hpke_config_for<'s>(
        &'s self,
        version: DapVersion,
        task_id: Option<&TaskId>,
    ) -> Result<Self::WrappedHpkeConfig<'s>, DapError>;

    /// Returns `true` if a ciphertext with the HPKE config ID can be consumed in the current task.
    async fn can_hpke_decrypt(&self, task_id: &TaskId, config_id: u8) -> Result<bool, DapError>;

    /// Decrypt the given HPKE ciphertext using the given info and AAD string.
    async fn hpke_decrypt(
        &self,
        task_id: &TaskId,
        info: &[u8],
        aad: &[u8],
        ciphertext: &HpkeCiphertext,
    ) -> Result<Vec<u8>, DapError>;
}

/// Struct that combines `HpkeConfig` and `HpkeSecretKey`
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct HpkeReceiverConfig {
    pub config: HpkeConfig,
    #[serde(with = "HpkePrivateKeySerde")]
    private_key: HpkePrivateKey,
}

#[cfg(any(test, feature = "test-utils"))]
impl deepsize::DeepSizeOf for HpkeReceiverConfig {
    fn deep_size_of_children(&self, context: &mut deepsize::Context) -> usize {
        self.config.deep_size_of_children(context)
            + std::mem::size_of_val(self.private_key.as_slice())
    }
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
            .decrypt(&self.private_key, info, aad, enc, ciphertext)
    }

    /// Generate and return a new HPKE receiver context given a HPKE config ID and HPKE KEM.
    pub fn gen(id: u8, kem_id: HpkeKemId) -> Result<Self, DapError> {
        let kem = match kem_id {
            HpkeKemId::P256HkdfSha256 => KemAlgorithm::DhKemP256,
            HpkeKemId::X25519HkdfSha256 => KemAlgorithm::DhKem25519,
            HpkeKemId::NotImplemented(x) => {
                return Err(fatal_error!(err = "Unsupported KEM", kem = ?x))
            }
        };
        let kdf = KdfAlgorithm::HkdfSha256;
        let aead = AeadAlgorithm::Aes128Gcm;
        let mut generator = Hpke::<ImplHpkeCrypto>::new(Mode::Base, kem, kdf, aead);
        match generator.generate_key_pair() {
            Ok(keypair) => {
                let (private_key, public_key) = keypair.into_keys();
                Ok(HpkeReceiverConfig {
                    config: HpkeConfig {
                        id,
                        kem_id,
                        kdf_id: HpkeKdfId::HkdfSha256,
                        aead_id: HpkeAeadId::Aes128Gcm,
                        public_key,
                    },
                    private_key,
                })
            }
            Err(e) => Err(fatal_error!(
                err = format!("{e:?}"), // `HpkeError` doesn't implement Display or Error :(
                ?kem_id,
                "bad key generation for KEM",
            )),
        }
    }
}

impl TryFrom<(HpkeConfig, HpkePrivateKey)> for HpkeReceiverConfig {
    type Error = DapError;
    /// Create a new HPKE receiver context given an `HpkeConfig` and a corresponding private key.
    /// Returns an error if the public key does not correspond to the `private_key`.
    fn try_from((config, private_key): (HpkeConfig, HpkePrivateKey)) -> Result<Self, Self::Error> {
        let kem_id_u16: u16 = config.kem_id.into();
        let kem_id: KemAlgorithm = kem_id_u16.try_into().unwrap();
        let public_key = HpkePublicKey::from(ImplHpkeCrypto::kem_derive_base(
            kem_id,
            private_key.as_slice(),
        )?);
        if public_key == config.public_key {
            Ok(Self {
                config,
                private_key,
            })
        } else {
            Err(fatal_error!(err = "public key does not match private key"))
        }
    }
}

#[cfg_attr(not(feature = "send-traits"), async_trait(?Send))]
#[cfg_attr(feature = "send-traits", async_trait)]
impl HpkeDecrypter for HpkeReceiverConfig {
    type WrappedHpkeConfig<'a> = HpkeConfig;

    async fn get_hpke_config_for<'s>(
        &'s self,
        _version: DapVersion,
        _task_id: Option<&TaskId>,
    ) -> Result<Self::WrappedHpkeConfig<'s>, DapError> {
        unreachable!("not implemented");
    }

    async fn can_hpke_decrypt(&self, _task_id: &TaskId, config_id: u8) -> Result<bool, DapError> {
        Ok(config_id == self.config.id)
    }

    async fn hpke_decrypt(
        &self,
        _task_id: &TaskId,
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
        encode_u16_bytes(bytes, self.private_key.as_slice());
    }
}

impl Decode for HpkeReceiverConfig {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        Ok(Self {
            config: HpkeConfig::decode(bytes)?,
            private_key: HpkePrivateKey::from(decode_u16_bytes(bytes)?),
        })
    }
}

impl std::str::FromStr for HpkeReceiverConfig {
    type Err = serde_json::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        serde_json::from_str(s)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(remote = "HpkePublicKey")]
pub(crate) struct HpkePublicKeySerde(
    #[serde(getter = "HpkePublicKeySerde::to_vec", with = "hex")] Vec<u8>,
);

impl HpkePublicKeySerde {
    fn to_vec(public_key: &HpkePublicKey) -> Vec<u8> {
        public_key.as_slice().into()
    }
}

impl From<HpkePublicKeySerde> for HpkePublicKey {
    fn from(public_key_serde: HpkePublicKeySerde) -> HpkePublicKey {
        HpkePublicKey::new(public_key_serde.0)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(remote = "HpkePrivateKey")]
struct HpkePrivateKeySerde(#[serde(getter = "HpkePrivateKeySerde::to_vec", with = "hex")] Vec<u8>);

impl HpkePrivateKeySerde {
    fn to_vec(private_key: &HpkePrivateKey) -> Vec<u8> {
        private_key.as_slice().into()
    }
}

impl From<HpkePrivateKeySerde> for HpkePrivateKey {
    fn from(private_key_serde: HpkePrivateKeySerde) -> HpkePrivateKey {
        HpkePrivateKey::new(private_key_serde.0)
    }
}

#[cfg(test)]
mod test {
    use crate::hpke::{HpkeAeadId, HpkeConfig, HpkeKdfId, HpkeKemId, HpkeReceiverConfig};
    use hpke_rs::{Hpke, HpkePrivateKey, HpkePublicKey, Mode};
    use hpke_rs_crypto::types::{AeadAlgorithm, KdfAlgorithm, KemAlgorithm};
    use hpke_rs_rust_crypto::HpkeRustCrypto as ImplHpkeCrypto;

    #[test]
    fn encrypt_roundtrip_x25519_hkdf_sha256() {
        let info = b"info string";
        let aad = b"associated data";
        let plaintext = b"plaintext";
        let config = HpkeReceiverConfig::gen(23, HpkeKemId::X25519HkdfSha256).unwrap();
        println!("{}", serde_json::to_string(&config).unwrap());
        let (enc, ciphertext) = config.encrypt(info, aad, plaintext).unwrap();
        assert_eq!(
            config.decrypt(info, aad, &enc, &ciphertext).unwrap(),
            plaintext
        );
    }

    #[test]
    fn encrypt_roundtrip_p256_hkdf_sha256() {
        let info = b"info string";
        let aad = b"associated data";
        let plaintext = b"plaintext";
        let config = HpkeReceiverConfig::gen(23, HpkeKemId::P256HkdfSha256).unwrap();
        println!("{}", serde_json::to_string(&config).unwrap());
        let (enc, ciphertext) = config.encrypt(info, aad, plaintext).unwrap();
        assert_eq!(
            config.decrypt(info, aad, &enc, &ciphertext).unwrap(),
            plaintext
        );
    }

    #[test]
    fn hpke_receiver_config_try_from() {
        let (private_key, public_key) = Hpke::<ImplHpkeCrypto>::new(
            Mode::Base,
            KemAlgorithm::DhKemP256,
            KdfAlgorithm::HkdfSha256,
            AeadAlgorithm::Aes128Gcm,
        )
        .generate_key_pair()
        .unwrap()
        .into_keys();

        let config = HpkeConfig {
            id: 0,
            kem_id: HpkeKemId::P256HkdfSha256,
            kdf_id: HpkeKdfId::HkdfSha256,
            aead_id: HpkeAeadId::Aes128Gcm,
            public_key,
        };
        assert!(HpkeReceiverConfig::try_from((config.clone(), private_key.clone())).is_ok());

        let bad_config = HpkeConfig {
            public_key: HpkePublicKey::from(vec![0; 20]),
            ..config
        };
        assert!(HpkeReceiverConfig::try_from((bad_config, private_key)).is_err());

        let bad_private_key = HpkePrivateKey::from(vec![0; 20]);
        assert!(HpkeReceiverConfig::try_from((config, bad_private_key)).is_err());
    }
}
