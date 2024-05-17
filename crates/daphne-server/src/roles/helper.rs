// Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use axum::async_trait;
use daphne::roles::DapHelper;
use daphne_service_utils::auth::DaphneAuth;

#[async_trait]
impl DapHelper<DaphneAuth> for crate::App {}
