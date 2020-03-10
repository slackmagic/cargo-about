use serde::{de, Deserialize};
use std::{collections::BTreeMap, fmt, path::PathBuf};

fn deserialize_spdx_id<'de, D>(deserializer: D) -> std::result::Result<spdx::LicenseId, D::Error>
where
    D: de::Deserializer<'de>,
{
    struct Visitor;

    impl<'de> de::Visitor<'de> for Visitor {
        type Value = spdx::LicenseId;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("SPDX short-identifier")
        }

        fn visit_str<E>(self, v: &str) -> std::result::Result<Self::Value, E>
        where
            E: de::Error,
        {
            spdx::license_id(v).ok_or_else(|| {
                E::custom(format!(
                    "'{}' is not a valid SPDX short-identifier in v{}",
                    v,
                    spdx::license_version()
                ))
            })
        }
    }

    deserializer.deserialize_any(Visitor)
}

fn deserialize_spdx_expr<'de, D>(deserializer: D) -> std::result::Result<spdx::Expression, D::Error>
where
    D: de::Deserializer<'de>,
{
    struct Visitor;

    impl<'de> de::Visitor<'de> for Visitor {
        type Value = spdx::Expression;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("SPDX expression")
        }

        fn visit_str<E>(self, v: &str) -> std::result::Result<Self::Value, E>
        where
            E: de::Error,
        {
            spdx::Expression::parse_mode(v, spdx::ParseMode::Lax)
                .map_err(|e| E::custom(format!("'{}' is not a valid SPDX expression: {}", v, e)))
        }
    }

    deserializer.deserialize_any(Visitor)
}

#[derive(Deserialize)]
pub struct LicenseFile {
    /// SPDX license identifier for the license text
    #[serde(deserialize_with = "deserialize_spdx_id")]
    pub license: spdx::LicenseId,
    /// SHA256 of the license text, each license is content addressed with a hash
    pub hash: String,
}

#[derive(Deserialize)]
pub struct Clarification {
    /// Crate relative path to the file being clarified
    pub path: String,
    /// SHA256 of the original file
    pub hash: String,
    /// The SPDX expression for the file
    #[serde(deserialize_with = "deserialize_spdx_expr")]
    pub expression: spdx::Expression,
    /// List of licenses contained within the file
    pub licenses: Vec<LicenseFile>,
}

#[derive(Deserialize)]
pub struct Package {
    pub name: String,
    pub clarifications: Vec<Clarification>,
}

#[derive(Deserialize)]
pub struct Item {
    pub package: Package,
}
