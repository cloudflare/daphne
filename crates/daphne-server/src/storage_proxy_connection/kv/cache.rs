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

pub enum CacheResult<T: 'static> {
    /// Cache hit.
    ///
    /// `None` indicates that the value is known to not exist.
    Hit(Option<Marc<T>>),
    /// Cache Miss. It was never cached or it has expired.
    Miss,
    /// There is a value associated with this key, but it's type is not [`T`].
    MismatchedType,
}

impl Cache {
    pub fn get<P>(&self, key: &str) -> CacheResult<P::Value>
    where
        P: KvPrefix,
    {
        match self.kv.get(P::PREFIX) {
            Some(cache) => match cache.get(key) {
                // Cache hit
                Some(CacheLine { ts, entry }) if ts.elapsed() < CACHE_VALUE_LIFETIME => entry
                    .as_ref()
                    .map(|entry| Marc::try_map(entry.clone(), |v| v.downcast_ref::<P::Value>()))
                    .transpose() // bring out the try_map error
                    .map_or(CacheResult::MismatchedType, CacheResult::Hit),

                // Cache miss or the cached value is stale.
                Some(_) | None => CacheResult::Miss,
            },

            // Cache miss
            None => CacheResult::Miss,
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

    pub fn delete<P>(&mut self, key: &str) -> CacheResult<P::Value>
    where
        P: KvPrefix,
    {
        match self.kv.get_mut(P::PREFIX) {
            Some(cache) => match cache.remove(key) {
                // Cache hit
                Some(CacheLine { ts: _, entry }) => entry
                    .map(|entry| Marc::try_map(entry, |v| v.downcast_ref::<P::Value>()))
                    .transpose() // bring out the try_map error
                    .map_or(CacheResult::MismatchedType, CacheResult::Hit),

                None => CacheResult::Miss,
            },

            // Cache miss
            None => CacheResult::Miss,
        }
    }
}
