//! Observer and opt-in simulation service with bounded clients and observed task lifetimes.

pub mod coordinator;

use std::future::Future;
use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::net::UnixStream;
use tokio::task::{JoinError, JoinSet};
use tunlatch_core::config::{Config, DesiredProtection};
use tunlatch_core::status::{CommittedPolicy, NetworkCollection, NetworkObservation, Status};
use tunlatch_ipc::endpoint::ServerSocket;
use tunlatch_ipc::protocol::{
    ErrorCode, PROTOCOL_VERSION, Reply, Request, RequestEnvelope, ResponseEnvelope,
};
use tunlatch_ipc::{IpcError, REQUEST_TIMEOUT, frame, verify_peer};
use tunlatch_platform::events::NetworkObserver;
use tunlatch_platform::pf;

use crate::coordinator::Coordinator;

/// Maximum simultaneous exchanges; excess connections are closed without spawning tasks.
pub const MAX_CLIENTS: usize = 16;

#[derive(Clone)]
struct ServiceState {
    desired: DesiredProtection,
    network: Arc<Mutex<NetworkObserver>>,
    simulation: Option<Arc<Coordinator>>,
}

impl ServiceState {
    fn new(config: &Config, simulation: bool) -> Self {
        Self {
            desired: config.desired(),
            network: Arc::new(Mutex::new(NetworkObserver::new(Duration::from_secs(3)))),
            simulation: simulation.then(|| Arc::new(Coordinator::new(config.desired()))),
        }
    }
}

/// Run until shutdown, then stop accepting and drain in-flight status requests.
///
/// Native observations that have started are awaited even after a client's I/O deadline.
/// All task results are observed. No shutdown path enables, disables or flushes PF.
pub async fn serve(
    socket: ServerSocket,
    config: Config,
    shutdown: impl Future<Output = io::Result<()>>,
) -> anyhow::Result<()> {
    serve_inner(socket, ServiceState::new(&config, false), shutdown).await
}

/// Run a separately selected, in-memory simulation alongside the ordinary observer.
///
/// Simulated commits never affect the actual status, configuration file, or PF.
/// Authentication and bounded transport are the same as for the ordinary observer.
pub async fn serve_simulation(
    socket: ServerSocket,
    config: Config,
    shutdown: impl Future<Output = io::Result<()>>,
) -> anyhow::Result<()> {
    serve_inner(socket, ServiceState::new(&config, true), shutdown).await
}

async fn serve_inner(
    socket: ServerSocket,
    state: ServiceState,
    shutdown: impl Future<Output = io::Result<()>>,
) -> anyhow::Result<()> {
    let mut tasks = JoinSet::new();
    tokio::pin!(shutdown);
    let shutdown_result = loop {
        tokio::select! {
            result = &mut shutdown => break result,
            result = tasks.join_next(), if !tasks.is_empty() => observe_task(result)?,
            stream = socket.accept() => {
                let stream = stream?;
                if let Err(error) = verify_peer(&stream) {
                    tracing::warn!(%error, "rejecting unauthorized client");
                    continue;
                }
                if tasks.len() >= MAX_CLIENTS {
                    tracing::warn!("client limit reached; closing incoming connection");
                    continue;
                }
                tasks.spawn(handle(stream, state.clone()));
            }
        }
    };
    while !tasks.is_empty() {
        observe_task(tasks.join_next().await)?;
    }
    shutdown_result?;
    tracing::info!("service stopped; no firewall changes were made");
    Ok(())
}

fn observe_task(result: Option<Result<Result<(), IpcError>, JoinError>>) -> anyhow::Result<()> {
    match result {
        Some(Ok(Ok(()))) | None => Ok(()),
        Some(Ok(Err(error))) => {
            tracing::debug!(%error, "client exchange failed");
            Ok(())
        }
        Some(Err(error)) => Err(error.into()),
    }
}

async fn handle(mut stream: UnixStream, state: ServiceState) -> Result<(), IpcError> {
    let deadline = tokio::time::Instant::now() + REQUEST_TIMEOUT;
    let request: RequestEnvelope = tokio::time::timeout_at(deadline, frame::read(&mut stream))
        .await
        .map_err(|_| IpcError::Timeout)??;
    let reply = if request.version != PROTOCOL_VERSION {
        Reply::Error {
            code: ErrorCode::UnsupportedVersion,
        }
    } else {
        let include_network = matches!(&request.request, Request::NetworkStatus {});
        match request.request {
            Request::Status {} | Request::NetworkStatus {} => {
                // Native enumeration can block; keep it off the async I/O worker. Do not drop
                // its JoinHandle on a deadline: a started native call cannot be cancelled.
                let observer = Arc::clone(&state.network);
                match tokio::task::spawn_blocking(move || {
                    let mut observer = observer
                        .lock()
                        .map_err(|_| io::Error::other("network observer is unavailable"))?;
                    let snapshot = observer.refresh().map_err(io::Error::other)?;
                    Ok::<_, io::Error>((snapshot.interfaces().to_vec(), snapshot.generation()))
                })
                .await
                {
                    Ok(Ok((interfaces, generation))) => {
                        let status = Status {
                            desired: state.desired,
                            committed: CommittedPolicy::Unmanaged,
                            observed: pf::observe(),
                            interfaces,
                        };
                        if include_network {
                            Reply::NetworkStatus {
                                status,
                                network_observation: NetworkObservation {
                                    generation,
                                    collection: NetworkCollection::OnDemandRescan,
                                },
                            }
                        } else {
                            Reply::Status { status }
                        }
                    }
                    result => {
                        tracing::error!(?result, "network observation failed");
                        Reply::Error {
                            code: ErrorCode::ObservationFailed,
                        }
                    }
                }
            }
            Request::Simulate { operation } => match &state.simulation {
                Some(controller) => match controller.submit(operation).await {
                    Ok(status) => Reply::Simulation { status },
                    Err(error) => Reply::SimulationError { error },
                },
                None => Reply::Error {
                    code: ErrorCode::SimulationUnavailable,
                },
            },
            Request::SimulationStatus {} => match &state.simulation {
                Some(controller) => Reply::Simulation {
                    status: controller.status().await,
                },
                None => Reply::Error {
                    code: ErrorCode::SimulationUnavailable,
                },
            },
        }
    };
    tokio::time::timeout_at(
        deadline,
        frame::write(
            &mut stream,
            &ResponseEnvelope {
                version: PROTOCOL_VERSION,
                reply,
            },
        ),
    )
    .await
    .map_err(|_| IpcError::Timeout)?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn partial_request_expires_instead_of_holding_a_worker() -> anyhow::Result<()> {
        use tokio::io::AsyncWriteExt;
        let (mut client, server) = UnixStream::pair()?;
        client.write_all(&[0, 0]).await?;
        assert!(matches!(
            handle(server, ServiceState::new(&Config::default(), false)).await,
            Err(IpcError::Timeout)
        ));
        Ok(())
    }
}
