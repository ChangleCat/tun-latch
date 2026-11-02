//! Strict, versioned configuration parsing. No configuration is applied by this module.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Current configuration format. Unknown versions are rejected rather than migrated implicitly.
pub const CONFIG_VERSION: u16 = 1;
/// Maximum UTF-8 configuration size accepted by the parser and file reader.
pub const MAX_CONFIG_BYTES: usize = 64 * 1024;

/// User intent, independent of committed policy and observed enforcement.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DesiredProtection {
    /// No request to enable protection.
    #[default]
    Disabled,
    /// Protection is requested; this alone does not establish protection.
    Enabled,
}

/// Validated settings. Deserialization uses the same validation as TOML import.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(try_from = "RawConfig")]
pub struct Config {
    schema_version: u16,
    desired: DesiredProtection,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    schema_version: u16,
    desired: DesiredProtection,
}

/// Invalid configuration cannot replace a valid in-memory value.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// Input exceeded the size limit.
    #[error("configuration exceeds {MAX_CONFIG_BYTES} bytes")]
    TooLarge,
    /// Input does not conform to the current schema.
    #[error("invalid TOML configuration: {0}")]
    Parse(#[from] toml::de::Error),
    /// A future or obsolete schema was provided.
    #[error("unsupported configuration version {0}; expected {CONFIG_VERSION}")]
    Version(u16),
}

impl TryFrom<RawConfig> for Config {
    type Error = ConfigError;

    fn try_from(raw: RawConfig) -> Result<Self, Self::Error> {
        if raw.schema_version != CONFIG_VERSION {
            return Err(ConfigError::Version(raw.schema_version));
        }
        Ok(Self {
            schema_version: raw.schema_version,
            desired: raw.desired,
        })
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            schema_version: CONFIG_VERSION,
            desired: DesiredProtection::Disabled,
        }
    }
}

impl Config {
    /// Parse a complete configuration; unknown fields and unsupported versions are errors.
    pub fn parse(input: &str) -> Result<Self, ConfigError> {
        if input.len() > MAX_CONFIG_BYTES {
            return Err(ConfigError::TooLarge);
        }
        Ok(toml::from_str(input)?)
    }

    /// Return the user's requested protection mode, without implying it was applied.
    pub fn desired(&self) -> DesiredProtection {
        self.desired
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_incomplete_unknown_and_future_configuration() {
        for text in [
            "desired = 'enabled'",
            "schema_version = 2\ndesired = 'enabled'",
            "schema_version = 1\ndesired = 'enabled'\nallow_all = true",
            "schema_version = 1\ndesired = 'maybe'",
        ] {
            assert!(Config::parse(text).is_err(), "accepted {text}");
        }
    }

    #[test]
    fn rejects_oversized_configuration() {
        assert!(matches!(
            Config::parse(&" ".repeat(MAX_CONFIG_BYTES + 1)),
            Err(ConfigError::TooLarge)
        ));
    }

    #[test]
    fn deserialization_cannot_bypass_validation() {
        assert!(
            serde_json::from_str::<Config>(r#"{"schema_version":2,"desired":"enabled"}"#).is_err()
        );
    }

    #[test]
    fn example_round_trips() -> Result<(), Box<dyn std::error::Error>> {
        let config = Config::parse(include_str!("../../../examples/config.toml"))?;
        assert_eq!(config.desired(), DesiredProtection::Disabled);
        assert_eq!(Config::parse(&toml::to_string(&config)?)?, config);
        Ok(())
    }
}
