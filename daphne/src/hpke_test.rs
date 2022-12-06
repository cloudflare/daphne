// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use crate::hpke::HpkeReceiverConfig;
use crate::messages::{HpkeAeadId, HpkeConfig, HpkeKdfId, HpkeKemId};
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
