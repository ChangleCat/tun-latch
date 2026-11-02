//! Closed operation set. Wire compatibility is explicit and unknown operations are rejected.

use serde::{Deserialize, Serialize};
use tunlatch_core::status::Status;

/// Current wire schema. A future version must negotiate or fail explicitly.
pub const PROTOCOL_VERSION: u16 = 1;

/// One request per connection; no arbitrary paths, commands or policy writes cross this boundary.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RequestEnvelope {
    /// Protocol version requested by the client.
    pub version: u16,
    /// Typed, read-only operation.
    pub request: Request,
}

/// Operations exposed by the initial framework.
#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    /// Return a fresh status snapshot.
    // Serde unit variants ignore extra fields even with deny_unknown_fields. An empty
    // struct variant enforces the closed request schema.
    Status {},
}

/// A response always identifies its wire version.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseEnvelope {
    /// Version used for this response.
    pub version: u16,
    /// Status or explicit failure.
    pub reply: Reply,
}

/// Application-level result.
#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Reply {
    /// Fresh status with no inferred protection claim.
    Status {
        /// Observed service state.
        status: Status,
    },
    /// Failure without disclosing internal data or pretending the service is healthy.
    Error {
        /// Stable code usable without parsing error strings.
        code: ErrorCode,
    },
}

/// Errors returned by the service.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// No compatible protocol version.
    UnsupportedVersion,
    /// A required observation could not be completed.
    ObservationFailed,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_mutations_and_extra_fields() {
        for request in [
            r#"{"version":1,"request":{"type":"disable"}}"#,
            r#"{"version":1,"request":{"type":"status","command":"pfctl -d"}}"#,
            r#"{"version":1,"request":{"type":"status"},"path":"/etc/pf.conf"}"#,
        ] {
            assert!(serde_json::from_str::<RequestEnvelope>(request).is_err());
        }
    }
}
