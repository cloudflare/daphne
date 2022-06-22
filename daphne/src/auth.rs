// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! DAP request authorization.

use crate::messages::constant_time_eq;
use serde::{Deserialize, Serialize};

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
        // TODO spec: Decide whether to check that the bearer token has the right format, say,
        // following RFC 6750, Section 2.1. Note that we would also need to replace `From<String>
        // for BearerToken` below with `TryFrom<String>` so that a `DapError` can be returned if
        // the token is not formatted properly.
        constant_time_eq(self.0.as_bytes(), other.0.as_bytes())
    }
}

impl From<String> for BearerToken {
    fn from(token: String) -> Self {
        Self(token)
    }
}
