// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Constants used in the DAP protocol.

use crate::DapSender;

// Media types for HTTP requests.
//
// TODO spec: Decide if media type should be enforced. (We currently don't.) In any case, it may be
// useful to enforce this for testing purposes.
pub const DRAFT02_MEDIA_TYPE_HPKE_CONFIG: &str = "application/dap-hpke-config";
pub const MEDIA_TYPE_HPKE_CONFIG_LIST: &str = "application/dap-hpke-config-list";
pub const MEDIA_TYPE_REPORT: &str = "application/dap-report";
pub const MEDIA_TYPE_AGG_INIT_REQ: &str = "application/dap-aggregate-initialize-req";
pub const MEDIA_TYPE_AGG_INIT_RESP: &str = "application/dap-aggregate-initialize-resp";
pub const MEDIA_TYPE_AGG_CONT_REQ: &str = "application/dap-aggregate-continue-req";
pub const MEDIA_TYPE_AGG_CONT_RESP: &str = "application/dap-aggregate-continue-resp";
pub const MEDIA_TYPE_AGG_SHARE_REQ: &str = "application/dap-aggregate-share-req";
pub const MEDIA_TYPE_AGG_SHARE_RESP: &str = "application/dap-aggregate-share-resp";
pub const MEDIA_TYPE_COLLECT_REQ: &str = "application/dap-collect-req";
pub const MEDIA_TYPE_COLLECT_RESP: &str = "application/dap-collect-resp";

/// Check if the provided value for the HTTP Content-Type is valid media type for DAP. If so, then
/// return a static reference to the media type.
pub fn media_type_for(content_type: &str) -> Option<&'static str> {
    match content_type {
        DRAFT02_MEDIA_TYPE_HPKE_CONFIG => Some(DRAFT02_MEDIA_TYPE_HPKE_CONFIG),
        MEDIA_TYPE_REPORT => Some(MEDIA_TYPE_REPORT),
        MEDIA_TYPE_AGG_INIT_REQ => Some(MEDIA_TYPE_AGG_INIT_REQ),
        MEDIA_TYPE_AGG_INIT_RESP => Some(MEDIA_TYPE_AGG_INIT_RESP),
        MEDIA_TYPE_AGG_CONT_REQ => Some(MEDIA_TYPE_AGG_CONT_REQ),
        MEDIA_TYPE_AGG_CONT_RESP => Some(MEDIA_TYPE_AGG_CONT_RESP),
        MEDIA_TYPE_AGG_SHARE_REQ => Some(MEDIA_TYPE_AGG_SHARE_REQ),
        MEDIA_TYPE_AGG_SHARE_RESP => Some(MEDIA_TYPE_AGG_SHARE_RESP),
        MEDIA_TYPE_COLLECT_REQ => Some(MEDIA_TYPE_COLLECT_REQ),
        MEDIA_TYPE_COLLECT_RESP => Some(MEDIA_TYPE_COLLECT_RESP),
        _ => None,
    }
}

/// Return the sender that would send a message with the given media type (or none if the sender
/// can't be determined).
pub fn sender_for_media_type(media_type: &'static str) -> Option<DapSender> {
    match media_type {
        DRAFT02_MEDIA_TYPE_HPKE_CONFIG | MEDIA_TYPE_REPORT => Some(DapSender::Client),
        MEDIA_TYPE_COLLECT_REQ => Some(DapSender::Collector),
        MEDIA_TYPE_AGG_INIT_REQ | MEDIA_TYPE_AGG_CONT_REQ | MEDIA_TYPE_AGG_SHARE_REQ => {
            Some(DapSender::Leader)
        }
        _ => None,
    }
}
