// Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use std::{any::Any, collections::HashMap};

use super::KvPrefix;

#[derive(Default, Debug)]
pub struct Cache {
    /// This map follows the same structure of KV queries.
    /// The first key (&'static str) is a KvPrefix::PREFIX
    /// The second key (String) is the key that is associated with this value
    kv: HashMap<&'static str, HashMap<String, Box<dyn Any + Send + Sync + 'static>>>,
}

pub enum GetResult<T> {
    NoFound,
    MismatchedType,
    Found(T),
}

impl Cache {
    pub fn get<'s, P>(&'s self, key: &str) -> GetResult<&'s P::Value>
    where
        P: KvPrefix,
    {
        match self.kv.get(P::PREFIX) {
            Some(cache) => match cache.get(key).map(|t| t.downcast_ref::<P::Value>()) {
                Some(Some(t)) => GetResult::Found(t),
                Some(None) => GetResult::MismatchedType,
                None => GetResult::NoFound,
            },
            None => GetResult::NoFound,
        }
    }

    pub fn put<P>(&mut self, key: String, value: P::Value)
    where
        P: KvPrefix,
    {
        self.kv
            .entry(P::PREFIX)
            .or_default()
            .insert(key, Box::new(value));
    }

    pub fn delete<P>(&mut self, key: &str) -> GetResult<P::Value>
    where
        P: KvPrefix,
    {
        match self.kv.get_mut(P::PREFIX) {
            Some(cache) => match cache.remove(key).map(|t| t.downcast::<P::Value>().ok()) {
                Some(Some(t)) => GetResult::Found(*t),
                Some(None) => GetResult::MismatchedType,
                None => GetResult::NoFound,
            },
            None => GetResult::NoFound,
        }
    }
}
