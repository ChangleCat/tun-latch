//! End-to-end local simulation protocol, without root or firewall operations.

use std::os::unix::fs::PermissionsExt;

use tokio::sync::oneshot;
use tunlatch_core::config::{Config, DesiredProtection};
use tunlatch_core::control::{SimulationError, SimulationObservation, SimulationRequest};
use tunlatch_core::status::{CommittedPolicy, ObservedProtection};
use tunlatch_ipc::endpoint::ServerSocket;
use tunlatch_ipc::protocol::{ErrorCode, PROTOCOL_VERSION, Request, RequestEnvelope};
use tunlatch_ipc::{
    IpcError, query_network_status, query_simulation, query_status, submit_simulation,
};

#[tokio::test]
async fn observer_rejects_simulation_and_preserves_actual_state() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))?;
    let socket = ServerSocket::bind(dir.path())?;
    let (stop, stopped) = oneshot::channel();
    let task = tokio::spawn(tunlatchd::serve(socket, Config::default(), async {
        stopped.await.map_err(std::io::Error::other)
    }));
    let operation = SimulationRequest {
        operation_id: 1,
        expected_generation: 0,
        desired: DesiredProtection::Enabled,
    };
    for result in [
        query_simulation(dir.path()).await,
        submit_simulation(dir.path(), operation).await,
    ] {
        assert!(matches!(
            result,
            Err(IpcError::Remote(ErrorCode::SimulationUnavailable))
        ));
    }
    let first = query_status(dir.path()).await?;
    assert_eq!(first.committed, CommittedPolicy::Unmanaged);
    assert_eq!(first.desired, DesiredProtection::Disabled);
    assert!(matches!(first.observed, ObservedProtection::Unknown { .. }));
    let (with_network, first_scan) = query_network_status(dir.path()).await?;
    let (_, next_scan) = query_network_status(dir.path()).await?;
    assert_eq!(with_network.observed, first.observed);
    assert!(first_scan.generation < next_scan.generation);
    stop.send(())
        .map_err(|()| anyhow::anyhow!("service already stopped"))?;
    task.await??;
    Ok(())
}

#[tokio::test]
async fn simulation_round_trip_retries_conflicts_and_actual_status_stays_unknown()
-> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))?;
    let socket = ServerSocket::bind(dir.path())?;
    let (stop, stopped) = oneshot::channel();
    let task = tokio::spawn(tunlatchd::serve_simulation(
        socket,
        Config::default(),
        async { stopped.await.map_err(std::io::Error::other) },
    ));
    let initial = query_simulation(dir.path()).await?;
    assert_eq!(initial.generation, 0);
    assert_eq!(initial.observed, SimulationObservation::NotSubmitted);
    let first = SimulationRequest {
        operation_id: 1,
        expected_generation: 0,
        desired: DesiredProtection::Enabled,
    };
    // Lose the first reply, then retry the same operation over a new connection.
    let mut lost_reply =
        tokio::net::UnixStream::connect(dir.path().join(tunlatch_ipc::endpoint::SOCKET_NAME))
            .await?;
    tunlatch_ipc::frame::write(
        &mut lost_reply,
        &RequestEnvelope {
            version: PROTOCOL_VERSION,
            request: Request::Simulate { operation: first },
        },
    )
    .await?;
    drop(lost_reply);
    let committed = submit_simulation(dir.path(), first).await?;
    assert_eq!(committed.generation, 1);
    assert_eq!(
        committed.observed,
        SimulationObservation::Verified { generation: 1 }
    );
    assert_eq!(submit_simulation(dir.path(), first).await?, committed);
    assert!(matches!(
        submit_simulation(
            dir.path(),
            SimulationRequest {
                operation_id: 2,
                ..first
            }
        )
        .await,
        Err(IpcError::Simulation(SimulationError::Conflict))
    ));
    assert!(matches!(
        submit_simulation(
            dir.path(),
            SimulationRequest {
                desired: DesiredProtection::Disabled,
                ..first
            }
        )
        .await,
        Err(IpcError::Simulation(SimulationError::OperationIdReused))
    ));
    let actual = query_status(dir.path()).await?;
    assert_eq!(actual.desired, DesiredProtection::Disabled);
    assert_eq!(actual.committed, CommittedPolicy::Unmanaged);
    assert!(matches!(
        actual.observed,
        ObservedProtection::Unknown { .. }
    ));
    let next = submit_simulation(
        dir.path(),
        SimulationRequest {
            operation_id: 2,
            expected_generation: 1,
            desired: DesiredProtection::Disabled,
        },
    )
    .await?;
    assert_eq!(next.generation, 2);
    assert_eq!(query_simulation(dir.path()).await?, next);
    // Retrying an old operation returns its original result, without rolling state back.
    assert_eq!(submit_simulation(dir.path(), first).await?, committed);
    assert_eq!(query_simulation(dir.path()).await?, next);
    stop.send(())
        .map_err(|()| anyhow::anyhow!("service already stopped"))?;
    task.await??;
    Ok(())
}
