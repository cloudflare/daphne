// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! DAP request authorization.

use core::fmt;

use daphne::messages::constant_time_eq;
use serde::{Deserialize, Serialize};

/// A bearer token used for authorizing DAP requests.
#[derive(Clone, Deserialize, Serialize, Eq)]
#[serde(transparent)]
pub struct BearerToken {
    raw: String,
}

impl BearerToken {
    pub fn as_str(&self) -> &str {
        self.raw.as_str()
    }
}

impl fmt::Debug for BearerToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        #[cfg(feature = "test-utils")]
        {
            write!(f, "BearerToken({})", self.raw)
        }
        #[cfg(not(feature = "test-utils"))]
        write!(f, "BearerToken(REDACTED)")
    }
}

impl AsRef<str> for BearerToken {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl PartialEq for BearerToken {
    fn eq(&self, other: &Self) -> bool {
        constant_time_eq(self.raw.as_bytes(), other.raw.as_bytes())
    }
}

impl From<String> for BearerToken {
    fn from(raw: String) -> Self {
        Self { raw }
    }
}

impl From<&str> for BearerToken {
    fn from(raw: &str) -> Self {
        Self::from(raw.to_string())
    }
}
