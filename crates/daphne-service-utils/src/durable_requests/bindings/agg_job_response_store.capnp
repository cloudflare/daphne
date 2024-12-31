# Copyright (c) 2025 Cloudflare, Inc. All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause

@0xd30da336463f3205;

using Base = import "../../capnproto/base.capnp";

struct AggregationJobResponse @0xebda3ce03fce7e72 {
    struct TransitionVar @0xc41a0ca7156794f0 {
        union {
            continued @0 :Data;
            failed @1 :Base.ReportError;
        }
    }

    struct Transition @0xc8b6a95ad17a2152 {
        reportId @0 :Base.ReportId;
        var @1 :TransitionVar;
    }

    transitions @0 :List(Transition);
}

