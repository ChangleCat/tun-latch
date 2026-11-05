//! Closed operation set. Wire compatibility is explicit and unknown operations are rejected.

use serde::{Deserialize, Serialize};
use tunlatch_core::control::{SimulationError, SimulationRequest, SimulationStatus};
use tunlatch_core::status::{NetworkObservation, Status};

/// Current wire schema. A future version must negotiate or fail explicitly.
pub const PROTOCOL_VERSION: u16 = 1;

/// One request per connection; no arbitrary paths, commands or actual policy writes cross it.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RequestEnvelope {
    /// Protocol version requested by the client.
    pub version: u16,
    /// Typed observer query or isolated simulation operation.
    pub request: Request,
}

/// Operations exposed by the observer and opt-in simulation framework.
#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    /// Return a fresh status snapshot.
    // Serde unit variants ignore extra fields even with deny_unknown_fields. An empty
    // struct variant enforces the closed request schema.
    Status {},
    /// Explicitly request scan diagnostics without extending the original status response.
    NetworkStatus {},
    /// Submit to the explicitly enabled in-memory simulation only.
    Simulate {
        /// Bounded typed simulation intent, never an actual PF command.
        operation: SimulationRequest,
    },
    /// Query isolated simulation state. Ordinary observer mode rejects this.
    SimulationStatus {},
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
    /// Extended observation, returned only for an explicit network status request.
    NetworkStatus {
        /// Actual status, retaining the original wire shape.
        status: Status,
        /// Diagnostic generation and collection method, never a trust assertion.
        network_observation: NetworkObservation,
    },
    /// State of the isolated simulation, with no actual protection claim.
    Simulation {
        /// The simulation snapshot.
        status: SimulationStatus,
    },
    /// A rejected or uncertain simulated operation.
    SimulationError {
        /// Closed simulation failure code.
        error: SimulationError,
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
    /// The ordinary observer does not expose the simulation controller.
    SimulationUnavailable,
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
