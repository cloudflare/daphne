# Copyright (c) 2025 Cloudflare, Inc. All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause

@0xd30da336463f3205;

using Base = import "../../capnproto/base.capnp";

struct AggregationJobResponse @0xebda3ce03fce7e72 {
    struct PrepareRespVar @0xc41a0ca7156794f0 {
        union {
            continue @0 :Data;
            reject @1 :Base.ReportError;
        }
    }

    struct PrepareResp @0xc8b6a95ad17a2152 {
        reportId @0 :Base.ReportId;
        var @1 :PrepareRespVar;
    }

    prepResps @0 :List(PrepareResp);
}

