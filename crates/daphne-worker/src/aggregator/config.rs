// Copyright (c) 2025 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use daphne::{
    constants::DapAggregatorRole, fatal_error, hpke::HpkeConfig, DapError, DapGlobalConfig,
    DapVersion,
};
use daphne_service_utils::bearer_token::BearerToken;
use p256::ecdsa::SigningKey;
use serde::{Deserialize, Serialize};
use url::Url;

/// draft-wang-ppm-dap-taskprov: Long-lived parameters for the taskprov extension.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TaskprovConfig {
    /// HPKE collector configuration for all taskprov tasks.
    pub hpke_collector_config: HpkeConfig,

    /// VDAF verify key init secret, used to generate the VDAF verification key for a taskprov task.
    #[serde(with = "hex")]
    pub vdaf_verify_key_init: [u8; 32],

    /// Peer's bearer token.
    pub peer_auth: PeerBearerToken,

    /// Bearer token used when trying to communicate with an aggregator using taskprov.
    pub self_bearer_token: Option<BearerToken>,
}

/// Peer authentication tokens for incomming requests. Different roles have different peers.
/// - Helpers have a Leader peer.
/// - Leaders have a Collector peer.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "lowercase")]
pub enum PeerBearerToken {
    Leader { expected_token: BearerToken },
    Collector { expected_token: BearerToken },
}

/// Daphne service configuration, including long-lived parameters used across DAP tasks.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DaphneServiceConfig {
    /// Indicates the role the service should play.
    pub role: DapAggregatorRole,

    /// Global DAP configuration.
    #[serde(flatten)]
    pub global: DapGlobalConfig,

    /// draft-dcook-ppm-dap-interop-test-design: Base URL of the Aggregator (unversioned). If set,
    /// this field is used for endpoint configuration for interop testing.
    pub base_url: Option<Url>,

    /// draft-wang-ppm-dap-taskprov: Long-lived parameters for the taskprov extension. If not set,
    /// then taskprov will be disabled.
    pub taskprov: Option<TaskprovConfig>,

    /// Default DAP version to use if not specified by the API URL
    pub default_version: DapVersion,

    /// The report storage epoch duration. This value is used to control the period of time for
    /// which an Aggregator guarantees storage of reports and/or report metadata.
    ///
    /// A report will be accepted if its timestamp is no more than the specified number of seconds
    /// before the current time.
    pub report_storage_epoch_duration: daphne::messages::Duration,

    /// The report storage maximum future time skew. Reports with timestamps greater than the
    /// current time plus this value will be rejected.
    #[serde(default = "default_report_storage_max_future_time_skew")]
    pub report_storage_max_future_time_skew: daphne::messages::Duration,

    /// ECDSA signing key for signing messages. If set, then every response to HPKE
    /// configuration endpoint will include a header "x-hpke-config-signature" with a
    /// URL-safe, base64-encoded signature of the HPKE config.
    ///
    /// The expected payload is a is standard DER-encoded EC private key for use with
    /// ECDSA-P256-SHA256, i.e., the output of
    ///
    /// ```text
    /// $ openssl ecparam -name prime256v1 -genkey -noout -out private-key.pem
    /// ```
    #[serde(
        default,
        deserialize_with = "signing_key_serializer::deserialize_opt",
        skip_serializing
    )]
    pub signing_key: Option<SigningKey>,
}

fn default_report_storage_max_future_time_skew() -> daphne::messages::Duration {
    300
}

mod signing_key_serializer {
    use p256::ecdsa::SigningKey;
    use serde::{de, Deserialize, Deserializer};

    fn deserialize<'de, D>(deserializer: D) -> Result<SigningKey, D::Error>
    where
        D: Deserializer<'de>,
        D::Error: serde::de::Error,
    {
        struct Visitor;
        impl de::Visitor<'_> for Visitor {
            type Value = SigningKey;
            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a sec1 pem key")
            }
            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(SigningKey::from(
                    p256::SecretKey::from_sec1_pem(v).map_err(E::custom)?,
                ))
            }

            fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                self.visit_str(&v)
            }
        }
        deserializer.deserialize_str(Visitor)
    }

    pub(super) fn deserialize_opt<'de, D>(deserializer: D) -> Result<Option<SigningKey>, D::Error>
    where
        D: Deserializer<'de>,
        D::Error: serde::de::Error,
    {
        #[derive(Deserialize)]
        struct Wrapper(#[serde(deserialize_with = "deserialize")] SigningKey);
        Option::<Wrapper>::deserialize(deserializer).map(|w| w.map(|w| w.0))
    }

    #[cfg(test)]
    mod test {
        use p256::ecdsa::SigningKey;
        use serde::Deserialize;

        #[test]
        fn deserialize() {
            #[derive(Deserialize)]
            struct F {
                #[serde(deserialize_with = "super::deserialize")]
                key: SigningKey,
            }

            let test_key = p256::SecretKey::random(&mut rand::rngs::OsRng);
            let F { key } = serde_json::from_value(
                serde_json::json!({ "key": &*test_key.to_sec1_pem(Default::default()).unwrap() }),
            )
            .unwrap();
            assert_eq!(key, SigningKey::from(test_key));
        }

        #[test]
        fn deserialize_opt_some() {
            #[derive(Deserialize)]
            struct F {
                #[serde(deserialize_with = "super::deserialize_opt")]
                key: Option<SigningKey>,
            }

            let test_key = p256::SecretKey::random(&mut rand::rngs::OsRng);
            let F { key } = serde_json::from_value(
                serde_json::json!({ "key": &*test_key.to_sec1_pem(Default::default()).unwrap() }),
            )
            .unwrap();
            assert_eq!(key.unwrap(), SigningKey::from(test_key));
        }

        #[test]
        fn deserialize_opt_none() {
            #[derive(Deserialize)]
            struct F {
                #[serde(default, deserialize_with = "super::deserialize_opt")]
                key: Option<SigningKey>,
            }

            let F { key } = serde_json::from_value(serde_json::json!({})).unwrap();
            assert_eq!(key, None);

            let F { key } = serde_json::from_value(serde_json::json!({ "key": null })).unwrap();
            assert_eq!(key, None);
        }
    }
}

pub fn load_config_from_env(env: &worker::Env) -> Result<DaphneServiceConfig, DapError> {
    const SERVICE_CONFIG: &str = "SERVICE_CONFIG";
    const SIGNING_KEY: &str = "SIGNING_KEY";

    // due to a bug where JsValue::UNDEFINED is not considered nullish in serde-wasm-bindgen we
    // have to deserialize to serde_json::Value first and DaphneServiceConfig later.
    let config = env
        .object_var::<serde_json::Value>(SERVICE_CONFIG)
        .map_err(|e| fatal_error!(err = ?e, "failed to load SERVICE_CONFIG variable"))?;

    let mut config = serde_json::from_value::<DaphneServiceConfig>(config).unwrap();

    if config.taskprov.is_some() {
        tracing::warn!("taskprov secrets are defined in plain text. Prefer using wrangler secrets");
    } else if matches!(env.var(taskprov_secrets::ENABLED), Ok(s) if s.to_string() == "true") {
        config.taskprov = Some(taskprov_secrets::load(env)?);
    }

    if config.signing_key.is_some() {
        tracing::warn!("signing key is defined in plain text. Prefer using wrangler secrets");
    } else {
        config.signing_key = env
            .var(SIGNING_KEY)
            .ok()
            .map(|s| p256::SecretKey::from_sec1_pem(&s.to_string()).map(SigningKey::from))
            .transpose()
            .map_err(|e| fatal_error!(err = ?e, "failed to deserialize SIGNING_KEY"))?
    }
    Ok(config)
}

mod taskprov_secrets {
    use super::{PeerBearerToken, TaskprovConfig};
    use daphne::{fatal_error, DapError};
    use daphne_service_utils::bearer_token::BearerToken;

    pub const ENABLED: &str = constcat::concat!(TASKPROV_SECRETS, "_", "ENABLED");

    const TASKPROV_SECRETS: &str = "TASKPROV_SECRETS";
    const VDAF_VERIFY_KEY_INIT: &str =
        constcat::concat!(TASKPROV_SECRETS, "_", "VDAF_VERIFY_KEY_INIT");
    const PEER_AUTH_LEADER_EXPECTED_TOKEN: &str =
        constcat::concat!(TASKPROV_SECRETS, "_", "PEER_AUTH_EXPECT_LEADER_TOKEN");
    const PEER_AUTH_COLLECTOR_EXPECTED_TOKEN: &str =
        constcat::concat!(TASKPROV_SECRETS, "_", "PEER_AUTH_EXPECT_COLLECTOR_TOKEN");
    const SELF_BEARER_TOKEN: &str = constcat::concat!(TASKPROV_SECRETS, "_", "SELF_BEARER_TOKEN");
    const TASKPROV_HPKE_COLLECTOR_CONFIG: &str = "TASKPROV_HPKE_COLLECTOR_CONFIG";

    pub fn load(env: &worker::Env) -> Result<TaskprovConfig, DapError> {
        Ok(super::TaskprovConfig {
            hpke_collector_config: env
                .object_var::<serde_json::Value>(TASKPROV_HPKE_COLLECTOR_CONFIG)
                .map_err(
                    |e| fatal_error!(err = ?e, "failed to load TASKPROV_HPKE_COLLECTOR_CONFIG"),
                )
                .and_then(|v| {
                    serde_json::from_value(v).map_err(
                        |e| fatal_error!(err = ?e, "failed to load TASKPROV_HPKE_COLLECTOR_CONFIG"),
                    )
                })?,
            vdaf_verify_key_init: {
                let key = VDAF_VERIFY_KEY_INIT;
                hex::decode(
                    env.var(key)
                        .map(|t| t.to_string())
                        .map_err(|e| fatal_error!(err = ?e, "failed to load {key}"))?,
                )
                .map_err(|e| fatal_error!(err = ?e, "invalid {key}"))?
                .try_into()
                .map_err(|e: Vec<_>| {
                    fatal_error!(
                        err = format!("{key} of invalid length. Got {} expected 32", e.len())
                    )
                })?
            },
            peer_auth: match (
                env.var(PEER_AUTH_LEADER_EXPECTED_TOKEN),
                env.var(PEER_AUTH_COLLECTOR_EXPECTED_TOKEN),
            ) {
                (Ok(_), Ok(_)) => {
                    return Err(fatal_error!(
                        err = format!(
                            "{} and {} were defined simultaneously, this is not allowed",
                            PEER_AUTH_LEADER_EXPECTED_TOKEN, PEER_AUTH_COLLECTOR_EXPECTED_TOKEN
                        )
                    ))
                }
                (Ok(leader), _) => PeerBearerToken::Leader {
                    expected_token: leader.to_string().into(),
                },
                (_, Ok(collector)) => PeerBearerToken::Collector {
                    expected_token: collector.to_string().into(),
                },
                (Err(e), _) => {
                    return Err(fatal_error!(
                        err = ?e,
                        "failed to load {} or {}",
                        PEER_AUTH_LEADER_EXPECTED_TOKEN,
                        PEER_AUTH_COLLECTOR_EXPECTED_TOKEN
                    ))
                }
            },
            self_bearer_token: env
                .var(SELF_BEARER_TOKEN)
                .ok()
                .map(|t| BearerToken::from(t.to_string())),
        })
    }
}
