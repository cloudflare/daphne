// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Constants used in the DAP protocol.

use crate::DapVersion;
use serde::{Deserialize, Serialize};
use std::{fmt, str::FromStr};

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
    CollectionReq,
    Collection,
    HpkeConfigList,
    Report,
}

impl DapMediaType {
    /// Parse the media type from the content-type HTTP header.
    pub fn from_str_for_version(_version: DapVersion, content_type: &str) -> Option<Self> {
        let (content_type, _) = content_type.split_once(';').unwrap_or((content_type, ""));
        let media_type = match content_type {
            MEDIA_TYPE_AGG_JOB_INIT_REQ => Self::AggregationJobInitReq,
            MEDIA_TYPE_AGG_JOB_RESP => Self::AggregationJobResp,
            MEDIA_TYPE_AGG_SHARE => Self::AggregateShare,
            MEDIA_TYPE_COLLECTION => Self::Collection,
            MEDIA_TYPE_HPKE_CONFIG_LIST => Self::HpkeConfigList,
            MEDIA_TYPE_AGG_SHARE_REQ => Self::AggregateShareReq,
            MEDIA_TYPE_COLLECT_REQ => Self::CollectionReq,
            MEDIA_TYPE_REPORT => Self::Report,
            _ => return None,
        };
        Some(media_type)
    }

    /// If the media type is used with the current DAP version, then return its representation as
    /// an HTTP content type.
    pub fn as_str_for_version(&self, _version: DapVersion) -> Option<&'static str> {
        match self {
            Self::AggregationJobInitReq => Some(MEDIA_TYPE_AGG_JOB_INIT_REQ),
            Self::AggregationJobResp => Some(MEDIA_TYPE_AGG_JOB_RESP),
            Self::AggregateShareReq => Some(MEDIA_TYPE_AGG_SHARE_REQ),
            Self::AggregateShare => Some(MEDIA_TYPE_AGG_SHARE),
            Self::CollectionReq => Some(MEDIA_TYPE_COLLECT_REQ),
            Self::Collection => Some(MEDIA_TYPE_COLLECTION),
            Self::HpkeConfigList => Some(MEDIA_TYPE_HPKE_CONFIG_LIST),
            Self::Report => Some(MEDIA_TYPE_REPORT),
        }
    }
}

/// A role in the DAP aggregation protocol.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DapRole {
    Collector,
    Client,
    Leader,
    Helper,
}

impl FromStr for DapRole {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "leader" => Ok(Self::Leader),
            "helper" => Ok(Self::Helper),
            "collector" => Ok(Self::Collector),
            "client" => Ok(Self::Client),
            _ => Err(s.to_string()),
        }
    }
}

impl fmt::Display for DapRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Client => "client",
            Self::Collector => "collector",
            Self::Helper => "helper",
            Self::Leader => "leader",
        })
    }
}

/// A role in the DAP aggregation protocol. See [`DapRole`] for an explanation of the numeric values
/// associated with each variant.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DapAggregatorRole {
    Leader,
    Helper,
}

impl FromStr for DapAggregatorRole {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "leader" => Ok(Self::Leader),
            "helper" => Ok(Self::Helper),
            _ => Err(s.to_string()),
        }
    }
}

impl fmt::Display for DapAggregatorRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Helper => "helper",
            Self::Leader => "leader",
        })
    }
}

impl From<DapAggregatorRole> for DapRole {
    fn from(value: DapAggregatorRole) -> Self {
        match value {
            DapAggregatorRole::Leader => DapRole::Leader,
            DapAggregatorRole::Helper => DapRole::Helper,
        }
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
            DapMediaType::from_str_for_version(
                DapVersion::Draft09,
                "application/dap-hpke-config-list",
            ),
            Some(DapMediaType::HpkeConfigList)
        );
        assert_eq!(
            DapMediaType::from_str_for_version(
                DapVersion::Draft09,
                "application/dap-aggregation-job-init-req"
            ),
            Some(DapMediaType::AggregationJobInitReq),
        );
        assert_eq!(
            DapMediaType::from_str_for_version(
                DapVersion::Draft09,
                "application/dap-aggregation-job-resp"
            ),
            Some(DapMediaType::AggregationJobResp),
        );
        assert_eq!(
            DapMediaType::from_str_for_version(
                DapVersion::Draft09,
                "application/dap-aggregate-share-req"
            ),
            Some(DapMediaType::AggregateShareReq),
        );
        assert_eq!(
            DapMediaType::from_str_for_version(
                DapVersion::Draft09,
                "application/dap-aggregate-share"
            ),
            Some(DapMediaType::AggregateShare),
        );
        assert_eq!(
            DapMediaType::from_str_for_version(DapVersion::Draft09, "application/dap-collect-req"),
            Some(DapMediaType::CollectionReq),
        );
        assert_eq!(
            DapMediaType::from_str_for_version(DapVersion::Draft09, "application/dap-collection"),
            Some(DapMediaType::Collection),
        );

        // Invalid media type
        assert_eq!(
            DapMediaType::from_str_for_version(DapVersion::Draft09, "blah-blah-blah"),
            None,
        );
    }

    // Test conversion of DAP media types to and from the content-type HTTP header.
    fn round_trip(version: DapVersion) {
        for media_type in DapMediaType::iter() {
            if let Some(content_type) = media_type.as_str_for_version(version) {
                // If the DAP media type is used for this version of DAP, then expect decoding the
                // content-type should result in the same DAP media type.
                assert_eq!(
                    DapMediaType::from_str_for_version(version, content_type).unwrap(),
                    media_type,
                    "round trip test failed for {version:?} and {media_type:?}"
                );
            }
        }
    }

    test_versions! { round_trip }

    fn media_type_parsing_ignores_content_type_paramters(version: DapVersion) {
        assert_eq!(
            DapMediaType::from_str_for_version(
                version,
                "application/dap-aggregation-job-init-req;version=09",
            ),
            Some(DapMediaType::AggregationJobInitReq),
        );
    }

    test_versions! { media_type_parsing_ignores_content_type_paramters }
}
