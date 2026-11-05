//! Isolated coordinator behavior, without system operations.

use tunlatch_core::config::DesiredProtection;
use tunlatch_core::control::{
    SimulatedCommit, SimulationError, SimulationObservation, SimulationRequest,
};
use tunlatchd::coordinator::{
    BackendSubmission, Coordinator, MAX_SIMULATION_OPERATIONS, SimulationBackend,
};

fn request(id: u64, generation: u64, desired: DesiredProtection) -> SimulationRequest {
    SimulationRequest {
        operation_id: id,
        expected_generation: generation,
        desired,
    }
}

#[tokio::test]
async fn checks_generation_and_preserves_retry_result() {
    let coordinator = Coordinator::new(DesiredProtection::Disabled);
    let first = request(1, 0, DesiredProtection::Enabled);
    let original = coordinator.submit(first).await;
    assert!(
        matches!(original, Ok(status) if status.observed == SimulationObservation::Verified { generation: 1 })
    );
    assert_eq!(coordinator.submit(first).await, original);
    assert_eq!(
        coordinator
            .submit(request(1, 0, DesiredProtection::Disabled))
            .await,
        Err(SimulationError::OperationIdReused)
    );
    assert_eq!(
        coordinator
            .submit(request(2, 0, DesiredProtection::Disabled))
            .await,
        Err(SimulationError::Conflict)
    );
    assert_eq!(
        coordinator
            .submit(request(0, 1, DesiredProtection::Disabled))
            .await,
        Err(SimulationError::InvalidOperationId)
    );
    assert_eq!(coordinator.status().await.generation, 1);
}

struct FaultBackend {
    submission: BackendSubmission,
    observed: Option<SimulatedCommit>,
}

impl SimulationBackend for FaultBackend {
    fn submit(&mut self, _: SimulatedCommit) -> BackendSubmission {
        self.submission
    }

    fn observe(&mut self) -> Option<SimulatedCommit> {
        self.observed
    }
}

#[tokio::test]
async fn failed_or_unverified_backend_never_reports_verified() {
    for (submission, observed, error) in [
        (
            BackendSubmission::Rejected,
            None,
            SimulationError::BackendFailed,
        ),
        (
            BackendSubmission::Unknown,
            None,
            SimulationError::OutcomeUnknown,
        ),
        (
            BackendSubmission::Committed,
            None,
            SimulationError::OutcomeUnknown,
        ),
        (
            BackendSubmission::Committed,
            Some(SimulatedCommit {
                generation: 0,
                desired: DesiredProtection::Enabled,
            }),
            SimulationError::OutcomeUnknown,
        ),
    ] {
        let coordinator = Coordinator::with_backend(
            DesiredProtection::Disabled,
            Box::new(FaultBackend {
                submission,
                observed,
            }),
        );
        let command = request(1, 0, DesiredProtection::Enabled);
        assert_eq!(coordinator.submit(command).await, Err(error));
        assert_eq!(coordinator.submit(command).await, Err(error));
        let status = coordinator.status().await;
        assert_eq!(status.generation, 1);
        assert_eq!(status.observed, SimulationObservation::Unknown);
    }
}

#[tokio::test]
async fn history_exhaustion_refuses_new_ids_without_forgetting_old_ones() {
    let coordinator = Coordinator::new(DesiredProtection::Disabled);
    for generation in 0..MAX_SIMULATION_OPERATIONS as u64 {
        assert!(
            coordinator
                .submit(request(
                    generation + 1,
                    generation,
                    DesiredProtection::Enabled
                ))
                .await
                .is_ok()
        );
    }
    assert_eq!(
        coordinator
            .submit(request(
                MAX_SIMULATION_OPERATIONS as u64 + 1,
                MAX_SIMULATION_OPERATIONS as u64,
                DesiredProtection::Disabled
            ))
            .await,
        Err(SimulationError::CapacityExceeded)
    );
    assert!(
        coordinator
            .submit(request(1, 0, DesiredProtection::Enabled))
            .await
            .is_ok()
    );
}
