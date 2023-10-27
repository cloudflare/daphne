// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Constants used in the DAP protocol.

use crate::{DapSender, DapVersion};

// Media types for HTTP requests.
const DRAFT02_MEDIA_TYPE_AGG_CONT_REQ: &str = "application/dap-aggregate-continue-req";
const DRAFT02_MEDIA_TYPE_AGG_CONT_RESP: &str = "application/dap-aggregate-continue-resp";
const DRAFT02_MEDIA_TYPE_AGG_INIT_REQ: &str = "application/dap-aggregate-initialize-req";
const DRAFT02_MEDIA_TYPE_AGG_INIT_RESP: &str = "application/dap-aggregate-initialize-resp";
const DRAFT02_MEDIA_TYPE_AGG_SHARE_RESP: &str = "application/dap-aggregate-share-resp";
const DRAFT02_MEDIA_TYPE_COLLECT_RESP: &str = "application/dap-collect-resp";
const DRAFT02_MEDIA_TYPE_HPKE_CONFIG: &str = "application/dap-hpke-config";
const MEDIA_TYPE_AGG_JOB_CONT_REQ: &str = "application/dap-aggregation-job-continue-req";
const MEDIA_TYPE_AGG_JOB_INIT_REQ: &str = "application/dap-aggregation-job-init-req";
const MEDIA_TYPE_AGG_JOB_RESP: &str = "application/dap-aggregation-job-resp";
const MEDIA_TYPE_AGG_SHARE_REQ: &str = "application/dap-aggregate-share-req";
const MEDIA_TYPE_AGG_SHARE: &str = "application/dap-aggregate-share";
const MEDIA_TYPE_COLLECTION: &str = "application/dap-collection";
const MEDIA_TYPE_COLLECT_REQ: &str = "application/dap-collect-req";
const MEDIA_TYPE_HPKE_CONFIG_LIST: &str = "application/dap-hpke-config-list";
const MEDIA_TYPE_REPORT: &str = "application/dap-report";

/// Media type for each DAP request. This is included in the "content-type" HTTP header.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub enum DapMediaType {
    AggregationJobInitReq,
    AggregationJobResp,
    AggregationJobContinueReq,
    /// draft02 compatibility: the latest draft doesn't define a separate media type for initialize
    /// and continue responses, but draft02 does.
    Draft02AggregateContinueResp,
    AggregateShareReq,
    AggregateShare,
    CollectReq,
    Collection,
    HpkeConfigList,
    Report,
    /// The content-type does not match a known media type.
    Invalid(String),
    /// No content-type header found.
    #[default]
    Missing,
}

impl DapMediaType {
    /// Return the sender that would send a DAP request or response with the given media type (or
    /// none if the sender can't be determined).
    pub fn sender(&self) -> Option<DapSender> {
        match self {
            Self::AggregationJobInitReq
            | Self::AggregationJobContinueReq
            | Self::AggregateShareReq
            | Self::Collection
            | Self::HpkeConfigList => Some(DapSender::Leader),
            Self::AggregationJobResp
            | Self::Draft02AggregateContinueResp
            | Self::AggregateShare => Some(DapSender::Helper),
            Self::Report => Some(DapSender::Client),
            Self::CollectReq => Some(DapSender::Collector),
            Self::Invalid(..) | Self::Missing => None,
        }
    }

    /// Parse the media type from the content-type HTTP header.
    pub fn from_str_for_version(version: DapVersion, content_type: Option<&str>) -> Self {
        match (version, content_type) {
            (DapVersion::Draft02, Some(DRAFT02_MEDIA_TYPE_AGG_CONT_REQ))
            | (DapVersion::Draft07, Some(MEDIA_TYPE_AGG_JOB_CONT_REQ)) => {
                Self::AggregationJobContinueReq
            }
            (DapVersion::Draft02, Some(DRAFT02_MEDIA_TYPE_AGG_CONT_RESP)) => {
                Self::Draft02AggregateContinueResp
            }
            (DapVersion::Draft02, Some(DRAFT02_MEDIA_TYPE_AGG_INIT_REQ))
            | (DapVersion::Draft07, Some(MEDIA_TYPE_AGG_JOB_INIT_REQ)) => {
                Self::AggregationJobInitReq
            }
            (DapVersion::Draft02, Some(DRAFT02_MEDIA_TYPE_AGG_INIT_RESP))
            | (DapVersion::Draft07, Some(MEDIA_TYPE_AGG_JOB_RESP)) => Self::AggregationJobResp,
            (DapVersion::Draft02, Some(DRAFT02_MEDIA_TYPE_AGG_SHARE_RESP))
            | (DapVersion::Draft07, Some(MEDIA_TYPE_AGG_SHARE)) => Self::AggregateShare,
            (DapVersion::Draft02, Some(DRAFT02_MEDIA_TYPE_COLLECT_RESP))
            | (DapVersion::Draft07, Some(MEDIA_TYPE_COLLECTION)) => Self::Collection,
            (DapVersion::Draft02, Some(DRAFT02_MEDIA_TYPE_HPKE_CONFIG))
            | (DapVersion::Draft07, Some(MEDIA_TYPE_HPKE_CONFIG_LIST)) => Self::HpkeConfigList,
            (DapVersion::Draft02, Some(MEDIA_TYPE_AGG_SHARE_REQ))
            | (DapVersion::Draft07, Some(MEDIA_TYPE_AGG_SHARE_REQ)) => Self::AggregateShareReq,
            (DapVersion::Draft02, Some(MEDIA_TYPE_COLLECT_REQ))
            | (DapVersion::Draft07, Some(MEDIA_TYPE_COLLECT_REQ)) => Self::CollectReq,
            (DapVersion::Draft02, Some(MEDIA_TYPE_REPORT))
            | (DapVersion::Draft07, Some(MEDIA_TYPE_REPORT)) => Self::Report,
            (_, Some(content_type)) => Self::Invalid(content_type.to_string()),
            (_, None) => Self::Missing,
        }
    }

    /// Get the content-type representation of the media type.
    pub fn as_str_for_version(&self, version: DapVersion) -> Option<&str> {
        match (version, self) {
            (DapVersion::Draft02, Self::AggregationJobInitReq) => {
                Some(DRAFT02_MEDIA_TYPE_AGG_INIT_REQ)
            }
            (DapVersion::Draft07, Self::AggregationJobInitReq) => Some(MEDIA_TYPE_AGG_JOB_INIT_REQ),
            (DapVersion::Draft02, Self::AggregationJobResp) => {
                Some(DRAFT02_MEDIA_TYPE_AGG_INIT_RESP)
            }
            (DapVersion::Draft07, Self::AggregationJobResp) => Some(MEDIA_TYPE_AGG_JOB_RESP),
            (DapVersion::Draft02, Self::AggregationJobContinueReq) => {
                Some(DRAFT02_MEDIA_TYPE_AGG_CONT_REQ)
            }
            (DapVersion::Draft07, Self::AggregationJobContinueReq) => {
                Some(MEDIA_TYPE_AGG_JOB_CONT_REQ)
            }
            (DapVersion::Draft02, Self::Draft02AggregateContinueResp) => {
                Some(DRAFT02_MEDIA_TYPE_AGG_CONT_RESP)
            }
            (_, Self::Draft02AggregateContinueResp) => None,
            (DapVersion::Draft02, Self::AggregateShareReq)
            | (DapVersion::Draft07, Self::AggregateShareReq) => Some(MEDIA_TYPE_AGG_SHARE_REQ),
            (DapVersion::Draft02, Self::AggregateShare) => Some(DRAFT02_MEDIA_TYPE_AGG_SHARE_RESP),
            (DapVersion::Draft07, Self::AggregateShare) => Some(MEDIA_TYPE_AGG_SHARE),
            (DapVersion::Draft02, Self::CollectReq) | (DapVersion::Draft07, Self::CollectReq) => {
                Some(MEDIA_TYPE_COLLECT_REQ)
            }
            (DapVersion::Draft02, Self::Collection) => Some(DRAFT02_MEDIA_TYPE_COLLECT_RESP),
            (DapVersion::Draft07, Self::Collection) => Some(MEDIA_TYPE_COLLECTION),
            (DapVersion::Draft02, Self::HpkeConfigList) => Some(DRAFT02_MEDIA_TYPE_HPKE_CONFIG),
            (DapVersion::Draft07, Self::HpkeConfigList) => Some(MEDIA_TYPE_HPKE_CONFIG_LIST),
            (DapVersion::Draft02, Self::Report) | (DapVersion::Draft07, Self::Report) => {
                Some(MEDIA_TYPE_REPORT)
            }
            (_, Self::Invalid(ref content_type)) => Some(content_type),
            (_, Self::Missing) => None,
        }
    }

    /// draft02 compatibility: Construct the media type for the response to an
    /// AggregatecontinueResp. This various depending upon the version used.
    pub(crate) fn agg_job_cont_resp_for_version(version: DapVersion) -> Self {
        match version {
            DapVersion::Draft02 => Self::Draft02AggregateContinueResp,
            DapVersion::Draft07 => Self::AggregationJobResp,
        }
    }
}

#[cfg(test)]
mod test {
    use super::DapMediaType;
    use crate::DapVersion;

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

        // draft07, Section 8.1
        assert_eq!(
            DapMediaType::from_str_for_version(
                DapVersion::Draft07,
                Some("application/dap-hpke-config-list")
            ),
            DapMediaType::HpkeConfigList
        );
        assert_eq!(
            DapMediaType::from_str_for_version(
                DapVersion::Draft07,
                Some("application/dap-aggregation-job-init-req")
            ),
            DapMediaType::AggregationJobInitReq,
        );
        assert_eq!(
            DapMediaType::from_str_for_version(
                DapVersion::Draft07,
                Some("application/dap-aggregation-job-resp")
            ),
            DapMediaType::AggregationJobResp,
        );
        assert_eq!(
            DapMediaType::from_str_for_version(
                DapVersion::Draft07,
                Some("application/dap-aggregation-job-continue-req")
            ),
            DapMediaType::AggregationJobContinueReq,
        );
        assert_eq!(
            DapMediaType::from_str_for_version(
                DapVersion::Draft07,
                Some("application/dap-aggregate-share-req")
            ),
            DapMediaType::AggregateShareReq,
        );
        assert_eq!(
            DapMediaType::from_str_for_version(
                DapVersion::Draft07,
                Some("application/dap-aggregate-share")
            ),
            DapMediaType::AggregateShare,
        );
        assert_eq!(
            DapMediaType::from_str_for_version(
                DapVersion::Draft07,
                Some("application/dap-collect-req")
            ),
            DapMediaType::CollectReq,
        );
        assert_eq!(
            DapMediaType::from_str_for_version(
                DapVersion::Draft07,
                Some("application/dap-collection")
            ),
            DapMediaType::Collection,
        );

        // Invalid media type
        assert_eq!(
            DapMediaType::from_str_for_version(DapVersion::Draft07, Some("blah-blah-blah")),
            DapMediaType::Invalid("blah-blah-blah".into()),
        );

        // Missing media type
        assert_eq!(
            DapMediaType::from_str_for_version(DapVersion::Draft07, None),
            DapMediaType::Missing,
        );
    }

    #[test]
    fn round_trip() {
        for (version, media_type) in [
            (DapVersion::Draft02, DapMediaType::AggregationJobInitReq),
            (DapVersion::Draft07, DapMediaType::AggregationJobInitReq),
            (DapVersion::Draft02, DapMediaType::AggregationJobResp),
            (DapVersion::Draft07, DapMediaType::AggregationJobResp),
            (DapVersion::Draft02, DapMediaType::AggregationJobContinueReq),
            (DapVersion::Draft07, DapMediaType::AggregationJobContinueReq),
            (
                DapVersion::Draft02,
                DapMediaType::Draft02AggregateContinueResp,
            ),
            (DapVersion::Draft02, DapMediaType::AggregateShareReq),
            (DapVersion::Draft07, DapMediaType::AggregateShareReq),
            (DapVersion::Draft02, DapMediaType::AggregateShare),
            (DapVersion::Draft07, DapMediaType::AggregateShare),
            (DapVersion::Draft02, DapMediaType::CollectReq),
            (DapVersion::Draft07, DapMediaType::CollectReq),
            (DapVersion::Draft02, DapMediaType::Collection),
            (DapVersion::Draft07, DapMediaType::Collection),
            (DapVersion::Draft02, DapMediaType::HpkeConfigList),
            (DapVersion::Draft07, DapMediaType::HpkeConfigList),
            (DapVersion::Draft02, DapMediaType::Report),
            (DapVersion::Draft07, DapMediaType::Report),
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
            DapMediaType::agg_job_cont_resp_for_version(DapVersion::Draft07)
        );
    }
}
