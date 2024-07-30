// Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use daphne::{
    hpke::{HpkeConfig, HpkeReceiverConfig},
    DapGlobalConfig, DapVersion,
};
use p256::ecdsa::SigningKey;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::{auth::DaphneWorkerAuthMethod, DapRole};

/// draft-wang-ppm-dap-taskprov: Long-lived parameters for the taskprov extension.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TaskprovConfig {
    /// HPKE collector configuration for all taskprov tasks.
    #[serde(with = "from_raw_string")]
    pub hpke_collector_config: HpkeConfig,

    /// VDAF verify key init secret, used to generate the VDAF verification key for a taskprov task.
    #[serde(with = "hex")]
    pub vdaf_verify_key_init: [u8; 32],

    /// Leader, Helper: Method for authorizing Leader requests.
    #[serde(with = "from_raw_string")]
    pub leader_auth: DaphneWorkerAuthMethod,

    /// Leader: Method for authorizing Collector requests.
    #[serde(default, with = "from_raw_string")]
    pub collector_auth: Option<DaphneWorkerAuthMethod>,
}

pub type HpkeRecieverConfigList = Vec<HpkeReceiverConfig>;

/// Daphne service configuration, including long-lived parameters used across DAP tasks.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DaphneServiceConfig {
    /// Indicates the role the service should play.
    pub role: DapRole,

    /// Global DAP configuration.
    #[serde(flatten)]
    pub global: DapGlobalConfig,

    /// draft-dcook-ppm-dap-interop-test-design: Base URL of the Aggregator (unversioned). If set,
    /// this field is used for endpoint configuration for interop testing.
    #[serde(default)]
    pub base_url: Option<Url>,

    /// draft-wang-ppm-dap-taskprov: Long-lived parameters for the taskprov extension. If not set,
    /// then taskprov will be disabled.
    #[serde(default)]
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
        impl<'de> de::Visitor<'de> for Visitor {
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

/// Deployment types for Daphne-Worker. This defines overrides used to control inter-Aggregator
/// communication.
#[derive(Serialize, Deserialize, Debug, Default, Clone, Copy)]
#[serde(rename_all = "snake_case")]
pub enum DaphneWorkerDeployment {
    /// Daphne-Worker is running in a production environment. No behavior overrides are applied.
    #[default]
    Prod,
    /// Daphne-Worker is running in a development environment. Any durable objects that are created
    /// will be registered by the garbage collector so that they can be deleted manually using the
    /// internal test API.
    Dev,
}

mod from_raw_string {
    //! This is used to deserialize secrets, which are stored in as raw strings. As such they need
    //! a custom deserializer.

    use serde::{
        de::{self, DeserializeOwned},
        ser, Deserialize, Deserializer, Serialize, Serializer,
    };

    pub fn serialize<T, S>(value: &T, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
        S::Error: ser::Error,
        T: Serialize,
    {
        serde_json::to_string(value)
            .map_err(<S::Error as ser::Error>::custom)
            .and_then(|s| serializer.serialize_str(&s))
    }

    pub fn deserialize<'de, D, T>(deserializer: D) -> Result<T, D::Error>
    where
        D: Deserializer<'de>,
        D::Error: de::Error,
        T: DeserializeOwned,
    {
        let s = String::deserialize(deserializer)?;
        serde_json::from_str(&s).map_err(<D::Error as de::Error>::custom)
    }
}
