//! Observer and opt-in simulation service with bounded clients and observed task lifetimes.

pub mod coordinator;
mod observation;

use std::future::Future;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::net::UnixStream;
use tokio::task::{JoinError, JoinSet};
use tunlatch_core::config::{Config, DesiredProtection};
use tunlatch_core::status::{
    CommittedPolicy, NetworkCollection, NetworkInterface, NetworkObservation, Status,
};
use tunlatch_ipc::endpoint::ServerSocket;
use tunlatch_ipc::protocol::{
    ErrorCode, PROTOCOL_VERSION, Reply, Request, RequestEnvelope, ResponseEnvelope,
};
use tunlatch_ipc::{IpcError, REQUEST_TIMEOUT, frame, verify_peer};
use tunlatch_platform::events::{NetworkEventControl, NetworkObserver};
use tunlatch_platform::{network, pf};

use crate::coordinator::Coordinator;

/// Maximum simultaneous exchanges; excess connections are closed without spawning tasks.
pub const MAX_CLIENTS: usize = 16;

#[derive(Clone)]
struct ServiceState {
    desired: DesiredProtection,
    network: Arc<Mutex<NetworkObserver>>,
    simulation: Option<Arc<Coordinator>>,
    notifications: Option<NetworkEventControl>,
}

impl ServiceState {
    fn new(config: &Config, simulation: bool) -> Self {
        Self {
            desired: config.desired(),
            network: Arc::new(Mutex::new(NetworkObserver::new(Duration::from_secs(3)))),
            simulation: simulation.then(|| Arc::new(Coordinator::new(config.desired()))),
            notifications: None,
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
    mut state: ServiceState,
    shutdown: impl Future<Output = io::Result<()>>,
) -> anyhow::Result<()> {
    let mut notifications = observation::Notifications::start()?;
    if let Err(error) = notifications.ready().await {
        notifications.shutdown().await?;
        return Err(error.into());
    }
    state.notifications = Some(notifications.control.clone());
    let mut tasks = JoinSet::new();
    let background_running = Arc::new(AtomicBool::new(false));
    let mut rescan = tokio::time::interval(Duration::from_secs(2));
    rescan.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut event_check = tokio::time::interval(Duration::from_millis(100));
    event_check.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut last_event = notifications.control.status();
    tokio::pin!(shutdown);
    let shutdown_result = loop {
        tokio::select! {
            result = &mut shutdown => break result,
            result = tasks.join_next(), if !tasks.is_empty() => {
                if let Err(error) = observe_task(result) {
                    break Err(io::Error::other(error));
                }
            },
            _ = event_check.tick() => {
                let current = notifications.control.status();
                if current != last_event && schedule_scan(&mut tasks, &state, &background_running) {
                    last_event = current;
                }
            },
            _ = rescan.tick() => {
                schedule_scan(&mut tasks, &state, &background_running);
            },
            stream = socket.accept() => {
                let stream = match stream {
                    Ok(stream) => stream,
                    Err(error) => break Err(error),
                };
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
    let mut drain_error = None;
    while !tasks.is_empty() {
        if let Err(error) = observe_task(tasks.join_next().await) {
            drain_error.get_or_insert(error);
        }
    }
    notifications.shutdown().await?;
    shutdown_result?;
    if let Some(error) = drain_error {
        return Err(error);
    }
    tracing::info!("service stopped; no firewall changes were made");
    Ok(())
}

fn schedule_scan(
    tasks: &mut JoinSet<Result<(), IpcError>>,
    state: &ServiceState,
    running: &Arc<AtomicBool>,
) -> bool {
    if tasks.len() >= MAX_CLIENTS || running.swap(true, Ordering::AcqRel) {
        return false;
    }
    let state = state.clone();
    let guard = BackgroundScan(Arc::clone(running));
    tasks.spawn(async move {
        let _guard = guard;
        scan(&state).await.map(|_| ()).map_err(IpcError::Io)
    });
    true
}

struct BackgroundScan(Arc<AtomicBool>);
impl Drop for BackgroundScan {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

async fn scan(state: &ServiceState) -> io::Result<(Vec<NetworkInterface>, u64)> {
    let observer = Arc::clone(&state.network);
    let notifications = state.notifications.clone();
    tokio::task::spawn_blocking(move || {
        let mut observer = observer
            .lock()
            .map_err(|_| io::Error::other("network observer unavailable"))?;
        let snapshot = match notifications {
            Some(control) => observer.refresh_with_control(&control, network::snapshot),
            None => observer.refresh(),
        }
        .map_err(io::Error::other)?;
        Ok((snapshot.interfaces().to_vec(), snapshot.generation()))
    })
    .await
    .map_err(io::Error::other)?
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
                match scan(&state).await {
                    Ok((interfaces, generation)) => {
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
