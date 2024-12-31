# Copyright (c) 2025 Cloudflare, Inc. All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause

@0x822b0e344bf68531;

using Base = import "../../capnproto/base.capnp";

struct PutRequest @0xbabd9e0f2a99569a {
    aggShareDelta @0 :import "../durable_request.capnp".DapAggregateShare;
    aggJobId @1 :Base.AggregationJobId;
}
