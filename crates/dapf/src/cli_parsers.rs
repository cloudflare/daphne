// Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Human friendly parsers for common types of parameters to DAP functions.

use std::{
    fmt,
    io::{self, IsTerminal as _},
    ops::ControlFlow,
    str::FromStr,
};

use anyhow::{anyhow, Context};
use clap::{builder::PossibleValue, ValueEnum};
use daphne::{
    hpke::HpkeKemId,
    messages::{Base64Encode, CollectionJobId, TaskId},
    vdaf::{Prio3Config, VdafConfig},
    DapBatchMode,
};

/// Some defaults for ease of use from the CLI. Instead of specifying the entire vdaf config json
/// these names can be used. Check the [`ValueEnum::to_possible_value`] implementation for the
/// names of these in the commandline.
#[derive(Debug, Clone, Copy, Default)]
pub enum DefaultVdafConfigs {
    Prio2Dimension99k,
    #[default]
    Prio3Draft09NumProofs2,
    Prio3Draft09NumProofs3,
}

impl fmt::Display for DefaultVdafConfigs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.to_possible_value().unwrap().get_name())
    }
}

impl ValueEnum for DefaultVdafConfigs {
    fn value_variants<'a>() -> &'a [Self] {
        &[
            Self::Prio2Dimension99k,
            Self::Prio3Draft09NumProofs2,
            Self::Prio3Draft09NumProofs3,
        ]
    }

    fn to_possible_value(&self) -> Option<PossibleValue> {
        match self {
            Self::Prio2Dimension99k => Some(PossibleValue::new("prio2-dimension-99k")),
            Self::Prio3Draft09NumProofs2 => Some(PossibleValue::new("prio3-draft-09-num-proofs-2")),
            Self::Prio3Draft09NumProofs3 => Some(PossibleValue::new("prio3-draft-09-num-proofs-3")),
        }
    }
}

impl DefaultVdafConfigs {
    fn into_vdaf_config(self) -> VdafConfig {
        match self {
            Self::Prio2Dimension99k => VdafConfig::Prio2 { dimension: 99_992 },
            Self::Prio3Draft09NumProofs2 => {
                VdafConfig::Prio3(Prio3Config::SumVecField64MultiproofHmacSha256Aes128 {
                    bits: 1,
                    length: 100_000,
                    chunk_length: 320,
                    num_proofs: 2,
                })
            }
            Self::Prio3Draft09NumProofs3 => {
                VdafConfig::Prio3(Prio3Config::SumVecField64MultiproofHmacSha256Aes128 {
                    bits: 1,
                    length: 100_000,
                    chunk_length: 320,
                    num_proofs: 3,
                })
            }
        }
    }
}

#[derive(Clone, Debug)]
pub enum CliVdafConfig {
    Default(DefaultVdafConfigs),
    Custom(VdafConfig),
}

impl Default for CliVdafConfig {
    fn default() -> Self {
        Self::Default(Default::default())
    }
}

impl fmt::Display for CliVdafConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Default(default) => write!(f, "{default}"),
            Self::Custom(custom) => write!(f, "{custom}"),
        }
    }
}

impl FromStr for CliVdafConfig {
    type Err = String;
    fn from_str(s: &str) -> std::prelude::v1::Result<Self, Self::Err> {
        DefaultVdafConfigs::from_str(s, false)
            .map(Self::Default)
            .or_else(|default_err| {
                serde_json::from_str(s)
                    .map(Self::Custom)
                    .map_err(|json_err| {
                        if s.contains('{') {
                            json_err.to_string()
                        } else {
                            default_err
                        }
                    })
            })
    }
}

impl CliVdafConfig {
    pub fn into_vdaf_config(self) -> VdafConfig {
        match self {
            Self::Default(d) => d.into_vdaf_config(),
            Self::Custom(v) => v,
        }
    }
}

#[derive(Clone, Debug)]
pub struct CliDapBatchMode(pub DapBatchMode);

impl fmt::Display for CliDapBatchMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        <DapBatchMode as fmt::Display>::fmt(&self.0, f)
    }
}

impl From<CliDapBatchMode> for DapBatchMode {
    fn from(CliDapBatchMode(val): CliDapBatchMode) -> Self {
        val
    }
}

impl From<DapBatchMode> for CliDapBatchMode {
    fn from(value: DapBatchMode) -> Self {
        Self(value)
    }
}

impl FromStr for CliDapBatchMode {
    type Err = String;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        if s == "time-interval" {
            Ok(Self(DapBatchMode::TimeInterval))
        } else if let Some(size) = s.strip_prefix("leader-selected") {
            Ok(Self(DapBatchMode::LeaderSelected {
                max_batch_size: if let Some(size) = size.strip_prefix("-") {
                    Some(
                        size.parse()
                            .map_err(|e| format!("{s} is an invalid max batch size: {e:?}"))?,
                    )
                } else if size.is_empty() {
                    None
                } else {
                    return Err(format!(
                        "{size} is an invalid leader selected max batch size"
                    ));
                },
            }))
        } else {
            Err(format!("{s} is an invalid query config"))
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct CliTaskId(pub TaskId);

impl fmt::Display for CliTaskId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        <TaskId as fmt::Display>::fmt(&self.0, f)
    }
}

impl From<TaskId> for CliTaskId {
    fn from(id: TaskId) -> Self {
        Self(id)
    }
}

impl From<CliTaskId> for TaskId {
    fn from(CliTaskId(id): CliTaskId) -> Self {
        id
    }
}

impl FromStr for CliTaskId {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        TaskId::try_from_base64url(s)
            .ok_or_else(|| anyhow!("failed to decode ID"))
            .context("expected URL-safe, base64 string")
            .map(Self)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct CliCollectionJobId(pub CollectionJobId);

impl fmt::Display for CliCollectionJobId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        <CollectionJobId as fmt::Display>::fmt(&self.0, f)
    }
}

impl From<CollectionJobId> for CliCollectionJobId {
    fn from(id: CollectionJobId) -> Self {
        Self(id)
    }
}

impl From<CliCollectionJobId> for CollectionJobId {
    fn from(CliCollectionJobId(id): CliCollectionJobId) -> Self {
        id
    }
}

impl FromStr for CliCollectionJobId {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        CollectionJobId::try_from_base64url(s)
            .ok_or_else(|| anyhow!("failed to decode ID"))
            .context("expected URL-safe, base64 string")
            .map(Self)
    }
}

#[derive(Clone, Debug)]
pub struct CliHpkeKemId(pub HpkeKemId);

impl Default for CliHpkeKemId {
    fn default() -> Self {
        Self(HpkeKemId::X25519HkdfSha256)
    }
}

impl fmt::Display for CliHpkeKemId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_possible_value().unwrap().get_name())
    }
}

impl ValueEnum for CliHpkeKemId {
    fn value_variants<'a>() -> &'a [Self] {
        &[
            Self(HpkeKemId::X25519HkdfSha256),
            Self(HpkeKemId::P256HkdfSha256),
        ]
    }

    fn to_possible_value(&self) -> Option<PossibleValue> {
        Some(match self.0 {
            HpkeKemId::X25519HkdfSha256 => PossibleValue::new("x25519_hkdf_sha256"),
            HpkeKemId::P256HkdfSha256 => PossibleValue::new("p256_hkdf_sha256"),
            HpkeKemId::NotImplemented(id) => unreachable!("unhandled HPKE KEM ID {id}"),
        })
    }
}

pub fn use_or_request_from_user_or_default<T, U>(
    value: Option<T>,
    mut default: impl FnMut() -> U,
    field: &'static str,
) -> io::Result<T>
where
    U: Into<T>,
    T: FromStr + fmt::Display,
    T::Err: fmt::Debug,
{
    match value {
        Some(v) => Ok(v),
        None => Ok(request_from_user::<T>(
            field,
            format!("leave empty to default: {}", default().into()).as_str(),
            || ControlFlow::Break(Some(default().into())),
        )?
        .unwrap()),
    }
}

pub fn use_or_request_from_user<T>(value: Option<T>, field: &'static str) -> io::Result<T>
where
    T: FromStr + fmt::Display,
    T::Err: fmt::Debug,
{
    match value {
        Some(v) => Ok(v),
        None => request_from_user::<T>(field, None, || ControlFlow::Continue(()))
            .transpose()
            .unwrap()
            .map(Into::into),
    }
}

pub fn request_from_user<'e, T>(
    field: &'static str,
    extra_info: impl Into<Option<&'e str>>,
    mut on_empty: impl FnMut() -> ControlFlow<Option<T>>,
) -> io::Result<Option<T>>
where
    T: FromStr + fmt::Display,
    T::Err: fmt::Debug,
{
    if !std::io::stdin().is_terminal() {
        return match on_empty() {
            ControlFlow::Break(b) => {
                eprintln!(
                    "defaulting {field} to {}",
                    b.as_ref()
                        .map(|b| format!("{b}"))
                        .unwrap_or_else(|| "None".into())
                );
                Ok(b)
            }
            ControlFlow::Continue(()) => Err(io::Error::other(format!(
                "{field:?} is required. use command line options to specify it"
            ))),
        };
    }
    let extra_info = extra_info.into();
    loop {
        eprint!(
            "{field}{}?: ",
            extra_info.map(|e| format!(" ({e})")).unwrap_or_default()
        );
        let mut buf = String::new();
        std::io::stdin().read_line(&mut buf)?;

        if buf.is_empty() {
            // <C-d>
            break Err(io::ErrorKind::UnexpectedEof.into());
        }

        buf.pop();

        if buf.is_empty() {
            match on_empty() {
                ControlFlow::Continue(()) => continue,
                ControlFlow::Break(b) => break Ok(b),
            }
        }

        match buf.parse::<T>() {
            Ok(t) => break Ok(Some(t)),
            Err(e) => {
                eprintln!("{buf} is not a valid {field}: {e:?}");
            }
        }
    }
}

pub fn from_json_str<T>(s: &str) -> serde_json::Result<T>
where
    T: serde::de::DeserializeOwned,
{
    serde_json::from_str(s)
}
