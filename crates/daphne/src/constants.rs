// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Constants used in the DAP protocol.

use core::fmt;
use std::str::FromStr;

use crate::DapSender;

// Media types for HTTP requests.
const MEDIA_TYPE_AGG_JOB_INIT_REQ: &str = "application/dap-aggregation-job-init-req";
const MEDIA_TYPE_AGG_JOB_RESP: &str = "application/dap-aggregation-job-resp";
const MEDIA_TYPE_AGG_SHARE_REQ: &str = "application/dap-aggregate-share-req";
const MEDIA_TYPE_AGG_SHARE: &str = "application/dap-aggregate-share";
const MEDIA_TYPE_COLLECTION: &str = "application/dap-collection";
const MEDIA_TYPE_COLLECT_REQ: &str = "application/dap-collect-req";
const MEDIA_TYPE_HPKE_CONFIG_LIST: &str = "application/dap-hpke-config-list";
const MEDIA_TYPE_REPORT: &str = "application/dap-report";

/// Media type for each DAP request. This is included in the "content-type" HTTP header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(test, derive(strum::EnumIter))]
pub enum DapMediaType {
    AggregationJobInitReq,
    AggregationJobResp,
    AggregateShareReq,
    AggregateShare,
    CollectReq,
    Collection,
    HpkeConfigList,
    Report,
}

impl DapMediaType {
    /// Return the sender that would send a DAP request or response with the given media type (or
    /// none if the sender can't be determined).
    pub fn sender(&self) -> DapSender {
        match self {
            Self::AggregationJobInitReq
            | Self::AggregateShareReq
            | Self::Collection
            | Self::HpkeConfigList => DapSender::Leader,
            Self::AggregationJobResp | Self::AggregateShare => DapSender::Helper,
            Self::Report => DapSender::Client,
            Self::CollectReq => DapSender::Collector,
        }
    }

    /// Parse the media type from the content-type HTTP header.
    pub fn from_http_content_type(content_type: &str) -> Option<Self> {
        let (content_type, _) = content_type.split_once(';').unwrap_or((content_type, ""));
        content_type.parse().ok()
    }

    /// If the media type is used with the current DAP version, then return its representation as
    /// an HTTP content type.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::AggregationJobInitReq => MEDIA_TYPE_AGG_JOB_INIT_REQ,
            Self::AggregationJobResp => MEDIA_TYPE_AGG_JOB_RESP,
            Self::AggregateShareReq => MEDIA_TYPE_AGG_SHARE_REQ,
            Self::AggregateShare => MEDIA_TYPE_AGG_SHARE,
            Self::CollectReq => MEDIA_TYPE_COLLECT_REQ,
            Self::Collection => MEDIA_TYPE_COLLECTION,
            Self::HpkeConfigList => MEDIA_TYPE_HPKE_CONFIG_LIST,
            Self::Report => MEDIA_TYPE_REPORT,
        }
    }
}

impl FromStr for DapMediaType {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let media_type = match s {
            MEDIA_TYPE_AGG_JOB_INIT_REQ => Self::AggregationJobInitReq,
            MEDIA_TYPE_AGG_JOB_RESP => Self::AggregationJobResp,
            MEDIA_TYPE_AGG_SHARE => Self::AggregateShare,
            MEDIA_TYPE_COLLECTION => Self::Collection,
            MEDIA_TYPE_HPKE_CONFIG_LIST => Self::HpkeConfigList,
            MEDIA_TYPE_AGG_SHARE_REQ => Self::AggregateShareReq,
            MEDIA_TYPE_COLLECT_REQ => Self::CollectReq,
            MEDIA_TYPE_REPORT => Self::Report,
            _ => return Err(format!("invalid media type: {s}")),
        };
        Ok(media_type)
    }
}

impl fmt::Display for DapMediaType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[cfg(test)]
mod test {
    use super::DapMediaType;
    use crate::{test_versions, DapVersion};
    use strum::IntoEnumIterator;

    #[test]
    fn from_str_for_version() {
        assert_eq!(
            DapMediaType::from_http_content_type("application/dap-hpke-config-list",),
            Some(DapMediaType::HpkeConfigList)
        );
        assert_eq!(
            DapMediaType::from_http_content_type("application/dap-aggregation-job-init-req"),
            Some(DapMediaType::AggregationJobInitReq),
        );
        assert_eq!(
            DapMediaType::from_http_content_type("application/dap-aggregation-job-resp"),
            Some(DapMediaType::AggregationJobResp),
        );
        assert_eq!(
            DapMediaType::from_http_content_type("application/dap-aggregate-share-req"),
            Some(DapMediaType::AggregateShareReq),
        );
        assert_eq!(
            DapMediaType::from_http_content_type("application/dap-aggregate-share"),
            Some(DapMediaType::AggregateShare),
        );
        assert_eq!(
            DapMediaType::from_http_content_type("application/dap-collect-req"),
            Some(DapMediaType::CollectReq),
        );
        assert_eq!(
            DapMediaType::from_http_content_type("application/dap-collection"),
            Some(DapMediaType::Collection),
        );

        // Invalid media type
        assert_eq!(DapMediaType::from_http_content_type("blah-blah-blah"), None,);
    }

    // Test conversion of DAP media types to and from the content-type HTTP header.
    fn round_trip(version: DapVersion) {
        for media_type in DapMediaType::iter() {
            let content_type = media_type.as_str();
            assert_eq!(
                DapMediaType::from_http_content_type(content_type).unwrap(),
                media_type,
                "round trip test failed for {version:?} and {media_type:?}"
            );
        }
    }

    test_versions! { round_trip }

    #[test]
    fn media_type_parsing_ignores_content_type_paramters() {
        assert_eq!(
            DapMediaType::from_http_content_type(
                "application/dap-aggregation-job-init-req;version=09",
            ),
            Some(DapMediaType::AggregationJobInitReq),
        );
    }
}
