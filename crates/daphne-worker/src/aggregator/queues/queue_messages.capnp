# Copyright (c) 2025 Cloudflare, Inc. All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause

@0x8240fbeac47031a3;

using Base = import "/capnproto/base.capnp";
using ComputeOffload = import "/compute_offload/compute_offload.capnp";

struct Option(T) {
    union {
        none @0 :Void;
        some @1 :T;
    }
}

struct AsyncAggregationMessage @0xbe3d785aff491226 {
    version @0 :Base.DapVersion;
    reports @1 :List(Base.ReportId);
    aggregationJobId @2 :Base.AggregationJobId;
    partialBatchSelector @3 :Base.PartialBatchSelector;
    initializeReports @4 :ComputeOffload.InitializeReports;
    taskprovAdvertisement @5 :Option(Text);
}
