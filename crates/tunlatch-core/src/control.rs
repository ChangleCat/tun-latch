//! Data contracts for an isolated, in-memory simulation, not system protection.

use serde::{Deserialize, Serialize};

use crate::config::DesiredProtection;

/// A version-checked simulation request. Operation identifiers must be nonzero.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SimulationRequest {
    /// Identifier retained for idempotent retries during this process lifetime.
    pub operation_id: u64,
    /// Generation the caller expects before this request.
    pub expected_generation: u64,
    /// Requested simulated intent.
    pub desired: DesiredProtection,
}

/// Identifies the isolated simulation domain.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SimulationMode {
    /// No system settings are modified.
    Simulation,
}

/// A simulated backend commit, which is not evidence of actual protection.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SimulatedCommit {
    /// Generation assigned to the simulated commit.
    pub generation: u64,
    /// Intent recorded by the simulated backend.
    pub desired: DesiredProtection,
}

/// Result of independently reading the simulated backend.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum SimulationObservation {
    /// No simulated transaction has been submitted.
    NotSubmitted,
    /// The simulated backend was read and matched this generation.
    Verified {
        /// Generation observed in the simulated backend.
        generation: u64,
    },
    /// Submission or independent verification did not establish an outcome.
    Unknown,
}

/// Current simulation snapshot; no field asserts real protection.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SimulationStatus {
    /// Always the simulation domain.
    pub mode: SimulationMode,
    /// Current accepted simulated operation generation.
    pub generation: u64,
    /// Most recently accepted intent.
    pub desired: DesiredProtection,
    /// Last commit that the simulated backend acknowledged.
    pub committed: Option<SimulatedCommit>,
    /// Independent observation of the simulated backend.
    pub observed: SimulationObservation,
}

/// Closed set of simulation errors.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SimulationError {
    /// Operation identifier was zero.
    InvalidOperationId,
    /// Expected generation did not match.
    Conflict,
    /// Another operation currently owns the coordinator.
    Busy,
    /// An existing operation identifier was used with different contents.
    OperationIdReused,
    /// The bounded history or generation space is exhausted.
    CapacityExceeded,
    /// The simulated backend rejected the submission before committing.
    BackendFailed,
    /// The outcome or independent verification could not be established.
    OutcomeUnknown,
}
