// Copyright (c) 2023 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use crate::{constants::DapMediaType, DapVersion};

#[test]
fn from_str_for_version() {
    // draft02, Section 8.1
    assert_eq!(
        DapMediaType::from_str_for_version(
            DapVersion::Draft02,
            Some("application/dap-hpke-config")
        ),
        DapMediaType::HpkeConfigList
    );
    assert_eq!(
        DapMediaType::from_str_for_version(
            DapVersion::Draft02,
            Some("application/dap-aggregate-initialize-req")
        ),
        DapMediaType::AggregationJobInitReq,
    );
    assert_eq!(
        DapMediaType::from_str_for_version(
            DapVersion::Draft02,
            Some("application/dap-aggregate-initialize-resp")
        ),
        DapMediaType::AggregationJobResp,
    );
    assert_eq!(
        DapMediaType::from_str_for_version(
            DapVersion::Draft02,
            Some("application/dap-aggregate-continue-req")
        ),
        DapMediaType::AggregationJobContinueReq,
    );
    assert_eq!(
        DapMediaType::from_str_for_version(
            DapVersion::Draft02,
            Some("application/dap-aggregate-continue-resp")
        ),
        DapMediaType::Draft02AggregateContinueResp,
    );
    assert_eq!(
        DapMediaType::from_str_for_version(
            DapVersion::Draft02,
            Some("application/dap-aggregate-share-req")
        ),
        DapMediaType::AggregateShareReq,
    );
    assert_eq!(
        DapMediaType::from_str_for_version(
            DapVersion::Draft02,
            Some("application/dap-aggregate-share-resp")
        ),
        DapMediaType::AggregateShare,
    );
    assert_eq!(
        DapMediaType::from_str_for_version(
            DapVersion::Draft02,
            Some("application/dap-collect-req")
        ),
        DapMediaType::CollectReq,
    );
    assert_eq!(
        DapMediaType::from_str_for_version(
            DapVersion::Draft02,
            Some("application/dap-collect-resp")
        ),
        DapMediaType::Collection,
    );

    // draft04, Section 8.1
    assert_eq!(
        DapMediaType::from_str_for_version(
            DapVersion::Draft04,
            Some("application/dap-hpke-config-list")
        ),
        DapMediaType::HpkeConfigList
    );
    assert_eq!(
        DapMediaType::from_str_for_version(
            DapVersion::Draft04,
            Some("application/dap-aggregation-job-init-req")
        ),
        DapMediaType::AggregationJobInitReq,
    );
    assert_eq!(
        DapMediaType::from_str_for_version(
            DapVersion::Draft04,
            Some("application/dap-aggregation-job-resp")
        ),
        DapMediaType::AggregationJobResp,
    );
    assert_eq!(
        DapMediaType::from_str_for_version(
            DapVersion::Draft04,
            Some("application/dap-aggregation-job-continue-req")
        ),
        DapMediaType::AggregationJobContinueReq,
    );
    assert_eq!(
        DapMediaType::from_str_for_version(
            DapVersion::Draft04,
            Some("application/dap-aggregate-share-req")
        ),
        DapMediaType::AggregateShareReq,
    );
    assert_eq!(
        DapMediaType::from_str_for_version(
            DapVersion::Draft04,
            Some("application/dap-aggregate-share")
        ),
        DapMediaType::AggregateShare,
    );
    assert_eq!(
        DapMediaType::from_str_for_version(
            DapVersion::Draft04,
            Some("application/dap-collect-req")
        ),
        DapMediaType::CollectReq,
    );
    assert_eq!(
        DapMediaType::from_str_for_version(DapVersion::Draft04, Some("application/dap-collection")),
        DapMediaType::Collection,
    );

    // Invalid media type
    assert_eq!(
        DapMediaType::from_str_for_version(DapVersion::Draft04, Some("blah-blah-blah")),
        DapMediaType::Invalid("blah-blah-blah".into()),
    );

    // Missing media type
    assert_eq!(
        DapMediaType::from_str_for_version(DapVersion::Draft04, None),
        DapMediaType::Missing,
    );
}

#[test]
fn round_trip() {
    for (version, media_type) in [
        (DapVersion::Draft02, DapMediaType::AggregationJobInitReq),
        (DapVersion::Draft04, DapMediaType::AggregationJobInitReq),
        (DapVersion::Draft02, DapMediaType::AggregationJobResp),
        (DapVersion::Draft04, DapMediaType::AggregationJobResp),
        (DapVersion::Draft02, DapMediaType::AggregationJobContinueReq),
        (DapVersion::Draft04, DapMediaType::AggregationJobContinueReq),
        (
            DapVersion::Draft02,
            DapMediaType::Draft02AggregateContinueResp,
        ),
        (DapVersion::Draft02, DapMediaType::AggregateShareReq),
        (DapVersion::Draft04, DapMediaType::AggregateShareReq),
        (DapVersion::Draft02, DapMediaType::AggregateShare),
        (DapVersion::Draft04, DapMediaType::AggregateShare),
        (DapVersion::Draft02, DapMediaType::CollectReq),
        (DapVersion::Draft04, DapMediaType::CollectReq),
        (DapVersion::Draft02, DapMediaType::Collection),
        (DapVersion::Draft04, DapMediaType::Collection),
        (DapVersion::Draft02, DapMediaType::HpkeConfigList),
        (DapVersion::Draft04, DapMediaType::HpkeConfigList),
        (DapVersion::Draft02, DapMediaType::Report),
        (DapVersion::Draft04, DapMediaType::Report),
    ] {
        assert_eq!(
            DapMediaType::from_str_for_version(version, media_type.as_str_for_version(version)),
            media_type,
            "round trip test failed for {version:?} and {media_type:?}"
        );
    }
}

// Issue #269: Ensure the media type included with the AggregateContinueResp in draft02 is not
// overwritten by the media type for AggregationJobResp.
#[test]
fn media_type_for_agg_cont_req() {
    assert_eq!(
        DapMediaType::Draft02AggregateContinueResp,
        DapMediaType::agg_job_cont_resp_for_version(DapVersion::Draft02)
    );

    assert_eq!(
        DapMediaType::AggregationJobResp,
        DapMediaType::agg_job_cont_resp_for_version(DapVersion::Draft04)
    );
}
