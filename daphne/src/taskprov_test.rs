// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use crate::{
    messages::taskprov::VdafType,
    messages::TaskId,
    taskprov::{compute_vdaf_verify_key, TaskprovVersion},
    vdaf::VdafVerifyKey,
};

#[test]
fn check_vdaf_key_computation() {
    let task_id = TaskId([
        0xb4, 0x76, 0x9b, 0xb0, 0x63, 0xa8, 0xb3, 0x31, 0x2a, 0xf7, 0x42, 0x97, 0xf3, 0x0f, 0xdb,
        0xf8, 0xe0, 0xb7, 0x1c, 0x2e, 0xb2, 0x48, 0x1f, 0x59, 0x1d, 0x1d, 0x7d, 0xe6, 0x6a, 0x4c,
        0xe3, 0x4f,
    ]);
    let verify_key_init: [u8; 32] = [
        0x1a, 0x2a, 0x3f, 0x1b, 0xeb, 0xb4, 0xbb, 0xe4, 0x55, 0xea, 0xac, 0xee, 0x29, 0x1a, 0x0f,
        0x32, 0xd7, 0xe1, 0xbc, 0x6c, 0x75, 0x10, 0x05, 0x60, 0x7b, 0x81, 0xda, 0xc3, 0xa7, 0xda,
        0x76, 0x1d,
    ];
    let vk = compute_vdaf_verify_key(
        TaskprovVersion::Draft02,
        &verify_key_init,
        &task_id,
        VdafType::Prio3Aes128Count,
    );
    let expected: [u8; 16] = [
        0xfb, 0xd1, 0x7d, 0xb5, 0x39, 0x0f, 0x94, 0x9e, 0xe3, 0x2d, 0x26, 0x34, 0xdc, 0x49, 0x9f,
        0x5b,
    ];
    match &vk {
        VdafVerifyKey::Prio3(bytes) => assert_eq!(*bytes, expected),
        _ => unreachable!(),
    }
}
