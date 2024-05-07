// Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use std::{any::Any, collections::HashMap};

use mappable_rc::Marc;

use super::KvPrefix;

#[derive(Default, Debug)]
pub struct Cache {
    /// This map follows the same structure of KV queries.
    /// The first key (&'static str) is a [`KvPrefix::PREFIX`]
    /// The second key (String) is the key that is associated with this value
    kv: HashMap<&'static str, HashMap<String, Marc<dyn Any + Send + Sync + 'static>>>,
}

pub enum GetResult<T: 'static> {
    NoFound,
    MismatchedType,
    Found(Marc<T>),
}

impl Cache {
    pub fn get<P>(&self, key: &str) -> GetResult<P::Value>
    where
        P: KvPrefix,
    {
        match self.kv.get(P::PREFIX) {
            Some(cache) => match cache
                .get(key)
                .map(|t| Marc::try_map(t.clone(), |t| t.downcast_ref::<P::Value>()).ok())
            {
                Some(Some(t)) => GetResult::Found(t),
                Some(None) => GetResult::MismatchedType,
                None => GetResult::NoFound,
            },
            None => GetResult::NoFound,
        }
    }

    pub(super) fn put<P>(&mut self, key: String, value: Marc<P::Value>)
    where
        P: KvPrefix,
    {
        self.kv
            .entry(P::PREFIX)
            .or_default()
            .insert(key, Marc::map(value, |v| v as &(dyn Any + Send + Sync)));
    }

    pub fn delete<P>(&mut self, key: &str) -> GetResult<P::Value>
    where
        P: KvPrefix,
    {
        match self.kv.get_mut(P::PREFIX) {
            Some(cache) => match cache
                .remove(key)
                .map(|t| Marc::try_map(t, |t| t.downcast_ref::<P::Value>()).ok())
            {
                Some(Some(t)) => GetResult::Found(t),
                Some(None) => GetResult::MismatchedType,
                None => GetResult::NoFound,
            },
            None => GetResult::NoFound,
        }
    }
}
