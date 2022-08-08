// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use crate::hpke::HpkeReceiverConfig;
use crate::messages::HpkeKemId;

#[test]
fn encrypt_roundtrip_x25519_hkdf_sha256() {
    let info = b"info string";
    let aad = b"associated data";
    let plaintext = b"plaintext";
    let config = HpkeReceiverConfig::gen(23, HpkeKemId::X25519HkdfSha256);
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
    let config = HpkeReceiverConfig::gen(23, HpkeKemId::P256HkdfSha256);
    println!("{}", serde_json::to_string(&config).unwrap());
    let (enc, ciphertext) = config.encrypt(info, aad, plaintext).unwrap();
    assert_eq!(
        config.decrypt(info, aad, &enc, &ciphertext).unwrap(),
        plaintext
    );
}
