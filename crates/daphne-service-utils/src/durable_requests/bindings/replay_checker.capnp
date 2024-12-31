# Copyright (c) 2025 Cloudflare, Inc. All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause

@0xaaa529cce40f45d7;

using Base = import "../../capnproto/base.capnp";

struct CheckReplaysFor @0xe1e6a4a1695238ca {
    reports @0 :List(Base.ReportId);
    aggJobId @1 :Base.AggregationJobId;
}
