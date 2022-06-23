// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! DAP request authorization.

use crate::{
    constants,
    messages::{constant_time_eq, Id},
    DapError, DapRequest,
};
use async_trait::async_trait;
use prio::codec::Decode;
use serde::{Deserialize, Serialize};
use std::io::Cursor;

/// A bearer token used for authorizing DAP requests as specified in draft-ietf-ppm-dap-01.
#[derive(Clone, Deserialize, Serialize)]
pub struct BearerToken(String);

impl AsRef<str> for BearerToken {
    fn as_ref(&self) -> &str {
        self.0.as_str()
    }
}

impl PartialEq for BearerToken {
    fn eq(&self, other: &Self) -> bool {
        constant_time_eq(self.0.as_bytes(), other.0.as_bytes())
    }
}

impl From<String> for BearerToken {
    fn from(token: String) -> Self {
        Self(token)
    }
}

/// A source of bearer tokens used for authorizing DAP requests.
#[async_trait(?Send)]
pub trait BearerTokenProvider {
    /// Fetch the Leader's bearer token for the given task, if the task is recognized.
    async fn get_leader_bearer_token_for(
        &self,
        task_id: &Id,
    ) -> Result<Option<BearerToken>, DapError>;

    /// Return a bearer token that can be used to authorize a request with the given task ID and
    /// media type.
    async fn authorize_with_bearer_token(
        &self,
        task_id: &Id,
        media_type: &'static str,
    ) -> Result<BearerToken, DapError> {
        if constants::media_type_from_leader(media_type) {
            let token = self
                .get_leader_bearer_token_for(task_id)
                .await?
                .ok_or(DapError::Fatal(
                    "attempted to authorize request with unknown task ID".into(),
                ))?;
            return Ok(token.clone());
        }

        Err(DapError::Fatal(format!(
            "attempted to authorize request of type '{}'",
            media_type
        )))
    }

    /// Check that the bearer token carried by a request can be used to authorize that request.
    async fn bearer_token_authorized(
        &self,
        req: &DapRequest<BearerToken>,
    ) -> Result<bool, DapError> {
        // TODO spec: Decide whether to check that the bearer token has the right format, say,
        // following RFC 6750, Section 2.1. Note that we would also need to replace `From<String>
        // for BearerToken` with `TryFrom<String>` so that a `DapError` can be returned if the
        // token is not formatted properly.
        if req.from_leader() {
            if let Some(ref got) = req.sender_auth {
                // Parse the task ID from the front of the request payload and use it to look up
                // the epxected bearer token.
                let mut r = Cursor::new(req.payload.as_ref());
                if let Ok(task_id) = Id::decode(&mut r) {
                    if let Some(expected) = self.get_leader_bearer_token_for(&task_id).await? {
                        return Ok(got == &expected);
                    }
                }
            }
        }

        // Deny request with unhandled or unknown media type.
        Ok(false)
    }
}
