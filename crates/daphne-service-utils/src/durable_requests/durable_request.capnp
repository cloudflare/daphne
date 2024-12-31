# Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause

@0xd076f8051f8de41a;

using Base = import "../capnproto/base.capnp";

enum Method @0xdd078556311145a1 {
    get @0;
    post @1;
    put @2;
    patch @3;
    delete @4;
    options @5;
    head @6;
    trace @7;
    connect @8;
}

struct DurableRequest @0xfbd55b93d47690b9 {
    binding @0 :Text;
    id :union {
        name @1 :Text;
        hex @2 :Text;
    }
    retry @3 :Bool;
}

struct DapAggregateShare @0xb34ce529a4a66aed {
    reportCount @0 :UInt64;
    minTime @1 :UInt64;
    maxTime @2 :UInt64;
    checksum @3 :Data;
    data :union {
        field64Draft09@4 :Data;
        field128Draft09@5 :Data;
        fieldPrio2Draft09@6 :Data;
        none @7 :Void;
        field64 @8 :Data;
        field128 @9 :Data;
        fieldPrio2 @10 :Data;
    }
}

struct AggregateStoreMergeReq @0xbaad7bdeb4b06161 {
    containedReports @0 :List(Base.ReportId);
    aggShareDelta @1 :DapAggregateShare;
    options @2 :MergeReqOptions;
}

struct MergeReqOptions @0x9e03186eae71ca92 {
    skipReplayProtection @0 :Bool;
}

