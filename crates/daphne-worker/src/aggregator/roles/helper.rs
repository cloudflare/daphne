// Copyright (c) 2025 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use crate::aggregator::App;
use daphne::roles::DapHelper;

impl DapHelper for App {}
