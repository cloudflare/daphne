// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use crate::hpke::HpkeReceiverConfig;

#[test]
fn encrypt_roundtrip() {
    let info = b"info string";
    let aad = b"associated data";
    let plaintext = b"plaintext";
    let config = HpkeReceiverConfig::gen(23);
    let (enc, ciphertext) = config.encrypt(info, aad, plaintext).unwrap();
    assert_eq!(
        config.decrypt(info, aad, &enc, &ciphertext).unwrap(),
        plaintext
    );
}
