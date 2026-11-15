//! Closed operation set. Wire compatibility is explicit and unknown operations are rejected.

use serde::{Deserialize, Serialize};
use tunlatch_core::control::{SimulationError, SimulationRequest, SimulationStatus};
use tunlatch_core::status::{NetworkObservation, Status};

/// Current wire schema. A future version must negotiate or fail explicitly.
pub const PROTOCOL_VERSION: u16 = 1;

/// One request per connection; no arbitrary paths, commands or rule text cross it.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RequestEnvelope {
    /// Protocol version requested by the client.
    pub version: u16,
    /// Typed query, isolated simulation, or privileged PF-session operation.
    pub request: Request,
}

/// Operations are available only on their designated service and endpoint.
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
    /// Read the privileged block-only session's last locally verified phase.
    PfSessionStatus {},
    /// Start the same preconfigured block-only session after its verified stop.
    PfStart {},
    /// Ask the root-only control endpoint to stop the live block-only session.
    PfStop {},
}

/// Last locally verified session phase. This is not current PF or protection evidence.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PfSessionPhase {
    /// Startup is in progress and may have made PF changes.
    Starting,
    /// The initial hook was verified at startup.
    Attached,
    /// A stop request has been accepted and may be changing PF.
    Stopping,
    /// Hook removal was verified; anchor clearing remains.
    Detached,
    /// Anchor clearing was verified; reference release remains.
    Cleared,
    /// Reference release was verified; local record retirement remains.
    Retiring,
    /// Hook removal may have been submitted but could not be verified.
    DetachUnconfirmed,
    /// Anchor clearing may have been submitted but could not be verified.
    ClearUnconfirmed,
    /// Reference release may have been submitted but could not be verified.
    ReleaseUnconfirmed,
    /// Startup failed while retaining a live handle for diagnosis.
    StartupInterrupted,
    /// Startup failed without a retained handle; records may still require diagnosis.
    StartupFailed,
    /// The live session's shutdown and local record retirement completed.
    Stopped,
    /// The worker is unavailable, so no conclusion about PF can be made.
    Unavailable,
}

/// Result of the most recent stop request, independently of the current PF state.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PfStopOutcome {
    /// The locally verified shutdown and record retirement completed.
    Completed,
    /// A step failed; the phase indicates whether an explicit retry may be possible.
    Failed,
}

/// Actual protection assessment for the initial block-only backend.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PfProtection {
    /// There is not enough evidence to claim protection.
    Unknown,
}

/// The daemon's last local checkpoint; actual protection is always unknown.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PfSessionStatus {
    /// Explicit assessment, independent of the session's operation checkpoint.
    pub actual_protection: PfProtection,
    /// Local checkpoint, which can become stale after publication.
    pub phase: PfSessionPhase,
    /// The last stop result in this process, if any.
    pub last_stop: Option<PfStopOutcome>,
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
    /// A block-only session's local checkpoint, not a protection claim.
    PfSessionStatus {
        /// Last local phase and stop result.
        status: PfSessionStatus,
    },
    /// Start was accepted for asynchronous execution; poll the session status for its result.
    PfStartAccepted {},
    /// The same live session's last verified phase is already attached.
    PfAlreadyAttached {},
    /// Stop was accepted for asynchronous execution; poll the session status for its result.
    PfStopAccepted {},
    /// The same live session had already completed its verified shutdown.
    PfAlreadyStopped {},
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
    /// This service or endpoint does not offer the PF operation.
    PfOperationUnavailable,
    /// A PF operation is already running; no second operation was queued.
    PfOperationBusy,
    /// A previous PF operation has an unconfirmed outcome and cannot be repeated.
    PfOperationUnconfirmed,
    /// The daemon is closing and accepts no new PF operations.
    ServiceShuttingDown,
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

    #[test]
    fn pf_session_wire_is_closed_and_never_accepts_commands_or_paths() {
        for request in [
            r#"{"version":1,"request":{"type":"pf_stop","interface":"en0"}}"#,
            r#"{"version":1,"request":{"type":"pf_stop","command":"pfctl -d"}}"#,
            r#"{"version":1,"request":{"type":"pf_start","interface":"en0"}}"#,
            r#"{"version":1,"request":{"type":"pf_session_status","path":"/etc/pf.conf"}}"#,
        ] {
            assert!(serde_json::from_str::<RequestEnvelope>(request).is_err());
        }
        for request in [
            r#"{"version":1,"request":{"type":"pf_stop"}}"#,
            r#"{"version":1,"request":{"type":"pf_start"}}"#,
            r#"{"version":1,"request":{"type":"pf_session_status"}}"#,
        ] {
            assert!(serde_json::from_str::<RequestEnvelope>(request).is_ok());
        }
    }

    #[test]
    fn pf_phase_never_implies_a_protected_assessment() -> Result<(), serde_json::Error> {
        let status = PfSessionStatus {
            actual_protection: PfProtection::Unknown,
            phase: PfSessionPhase::Attached,
            last_stop: None,
        };
        let value = serde_json::to_value(status)?;
        assert_eq!(value["actual_protection"], "unknown");
        assert!(
            serde_json::from_value::<PfSessionStatus>(serde_json::json!({
                "actual_protection": "protected", "phase": "attached", "last_stop": null
            }))
            .is_err()
        );
        Ok(())
    }
}
