//! Isolated synchronous simulation coordinator. It performs no system operations.

use std::collections::HashMap;

use tokio::sync::Mutex;
use tunlatch_core::config::DesiredProtection;
use tunlatch_core::control::{
    SimulatedCommit, SimulationError, SimulationMode, SimulationObservation, SimulationRequest,
    SimulationStatus,
};

/// Maximum number of accepted operations retained until the coordinator is dropped.
pub const MAX_SIMULATION_OPERATIONS: usize = 256;

/// Result of a simulated submission. Unknown must be used for ambiguous outcomes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackendSubmission {
    /// The backend accepted the exact simulated commit.
    Committed,
    /// The backend definitively rejected it without committing.
    Rejected,
    /// The backend cannot establish whether it committed.
    Unknown,
}

/// A synchronous, bounded in-memory simulation backend. Implementations must not perform
/// system operations, block, or yield. This keeps operation ownership within the caller's poll.
pub trait SimulationBackend: Send {
    /// Submit a candidate to the simulated backend.
    fn submit(&mut self, commit: SimulatedCommit) -> BackendSubmission;
    /// Independently read the simulated backend. `None` means the outcome is unknown.
    fn observe(&mut self) -> Option<SimulatedCommit>;
}

#[derive(Default)]
struct MemoryBackend(Option<SimulatedCommit>);

impl SimulationBackend for MemoryBackend {
    fn submit(&mut self, commit: SimulatedCommit) -> BackendSubmission {
        self.0 = Some(commit);
        BackendSubmission::Committed
    }

    fn observe(&mut self) -> Option<SimulatedCommit> {
        self.0
    }
}

struct State {
    status: SimulationStatus,
    history: HashMap<u64, (SimulationRequest, Result<SimulationStatus, SimulationError>)>,
    backend: Box<dyn SimulationBackend>,
}

/// Serializes simulation operations and retains their outcomes for idempotent retries.
pub struct Coordinator {
    state: Mutex<State>,
}

impl Coordinator {
    /// Create a coordinator using the fixed, side-effect-free memory backend.
    pub fn new(initial: DesiredProtection) -> Self {
        Self::with_backend(initial, Box::<MemoryBackend>::default())
    }

    /// Create a coordinator with a bounded synchronous simulation backend, e.g. for tests.
    pub fn with_backend(initial: DesiredProtection, backend: Box<dyn SimulationBackend>) -> Self {
        Self {
            state: Mutex::new(State {
                status: SimulationStatus {
                    mode: SimulationMode::Simulation,
                    generation: 0,
                    desired: initial,
                    committed: None,
                    observed: SimulationObservation::NotSubmitted,
                },
                history: HashMap::new(),
                backend,
            }),
        }
    }

    /// Submit once, or return the original outcome for an identical operation retry.
    /// Once the lock is obtained there are no suspension points or detached tasks.
    pub async fn submit(
        &self,
        request: SimulationRequest,
    ) -> Result<SimulationStatus, SimulationError> {
        if request.operation_id == 0 {
            return Err(SimulationError::InvalidOperationId);
        }
        let mut state = self.state.try_lock().map_err(|_| SimulationError::Busy)?;
        if let Some((original, result)) = state.history.get(&request.operation_id) {
            return if *original == request {
                *result
            } else {
                Err(SimulationError::OperationIdReused)
            };
        }
        if request.expected_generation != state.status.generation {
            return Err(SimulationError::Conflict);
        }
        if state.history.len() >= MAX_SIMULATION_OPERATIONS {
            return Err(SimulationError::CapacityExceeded);
        }
        let generation = state
            .status
            .generation
            .checked_add(1)
            .ok_or(SimulationError::CapacityExceeded)?;
        state.status.generation = generation;
        state.status.desired = request.desired;
        state.status.observed = SimulationObservation::Unknown;
        let candidate = SimulatedCommit {
            generation,
            desired: request.desired,
        };
        let result = match state.backend.submit(candidate) {
            BackendSubmission::Rejected => Err(SimulationError::BackendFailed),
            BackendSubmission::Unknown => Err(SimulationError::OutcomeUnknown),
            BackendSubmission::Committed => {
                state.status.committed = Some(candidate);
                if state.backend.observe() == Some(candidate) {
                    state.status.observed = SimulationObservation::Verified { generation };
                    Ok(state.status)
                } else {
                    Err(SimulationError::OutcomeUnknown)
                }
            }
        };
        state
            .history
            .insert(request.operation_id, (request, result));
        result
    }

    /// Read the most recent simulation snapshot.
    pub async fn status(&self) -> SimulationStatus {
        self.state.lock().await.status
    }
}
