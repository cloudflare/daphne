# Copyright (c) 2025 Cloudflare, Inc. All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause

@0xa11edd1197dbcf0b;

using Base = import "../../capnproto/base.capnp";

struct NewJobRequest @0xdd285ccdbb2cd14e {
    id @0 :Base.AggregationJobId;
    aggJobHash @1 :Data;
}
