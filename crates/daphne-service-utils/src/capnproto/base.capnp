# Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause

@0xba869f168ff63e77;

enum DapVersion @0xb5b2c8705a8b22d5 {
    draft09 @0;
    draftLatest @1;
}

# [u8; 32]
struct U8L32 @0x9e42cda292792294 {
    fst @0 :UInt64;
    snd @1 :UInt64;
    thr @2 :UInt64;
    frh @3 :UInt64;
}

# [u8; 16]
struct U8L16 @0x9e3f65b13f71cfcb {
    fst @0 :UInt64;
    snd @1 :UInt64;
}

struct PartialBatchSelector {
    union {
        timeInterval @0 :Void;
        leaderSelectedByBatchId @1 :BatchId;
    }
}

using ReportId = U8L16;
using BatchId = U8L32;
using TaskId = U8L32;
using AggregationJobId = U8L16;
using Time = UInt64;
