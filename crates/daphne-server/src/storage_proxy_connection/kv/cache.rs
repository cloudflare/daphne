// Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use std::{
    any::Any,
    collections::HashMap,
    time::{Duration, Instant},
};

use mappable_rc::Marc;

use super::KvPrefix;

const CACHE_VALUE_LIFETIME: Duration = Duration::from_secs(60 * 5);

struct CacheLine {
    /// Time at which the cache item was set.
    ts: Instant,

    /// Either the value or an indication that no value was found.
    entry: Option<Marc<dyn Any + Send + Sync + 'static>>,
}

#[derive(Default)]
pub struct Cache {
    /// This map follows the same structure of KV queries.
    /// The first key (&'static str) is a [`KvPrefix::PREFIX`]
    /// The second key (String) is the key that is associated with this value
    kv: HashMap<&'static str, HashMap<String, CacheLine>>,
}

pub enum GetResult<T: 'static> {
    NotFound {
        /// Whether the caller should check KV for the value.
        read_through: bool,
    },
    MismatchedType,
    Found(Marc<T>),
}

impl Cache {
    pub fn get<P>(&self, key: &str) -> GetResult<P::Value>
    where
        P: KvPrefix,
    {
        match self.kv.get(P::PREFIX) {
            Some(cache) => match cache.get(key) {
                // Cache hit
                Some(CacheLine { ts, entry }) if ts.elapsed() < CACHE_VALUE_LIFETIME => {
                    if let Some(value) = entry {
                        // There is a value in KV, and its value isn't stale.
                        Marc::try_map(entry.clone().unwrap(), |value| {
                            value.downcast_ref::<P::Value>()
                        })
                        .map_or(GetResult::MismatchedType, GetResult::Found)
                    } else {
                        // There is no value in KV, but we shouldn't read through to KV.
                        GetResult::NotFound {
                            read_through: false,
                        }
                    }
                }

                // Cache miss or the cached value is stale.
                Some(_) | None => GetResult::NotFound { read_through: true },
            },

            // Cache miss
            None => GetResult::NotFound { read_through: true },
        }
    }

    pub(super) fn put<P>(&mut self, key: String, entry: Option<Marc<P::Value>>)
    where
        P: KvPrefix,
    {
        self.kv.entry(P::PREFIX).or_default().insert(
            key,
            CacheLine {
                ts: Instant::now(),
                entry: entry.map(|value| Marc::map(value, |v| v as &(dyn Any + Send + Sync))),
            },
        );
    }

    pub fn delete<P>(&mut self, key: &str) -> GetResult<P::Value>
    where
        P: KvPrefix,
    {
        match self.kv.get_mut(P::PREFIX) {
            Some(cache) => match cache.remove(key) {
                // Cache hit
                Some(CacheLine { ts: _, entry }) => {
                    if let Some(value) = entry {
                        Marc::try_map(value, |value| value.downcast_ref::<P::Value>())
                            .map_or(GetResult::MismatchedType, GetResult::Found)
                    } else {
                        GetResult::NotFound { read_through: true }
                    }
                }

                None => GetResult::NotFound { read_through: true },
            },

            // Cache miss
            None => GetResult::NotFound { read_through: true },
        }
    }
}
