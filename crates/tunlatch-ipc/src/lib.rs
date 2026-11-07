//! Versioned local status and isolated simulation protocol. No PF mutation is exposed.

pub mod endpoint;
pub mod frame;
pub mod privileged_endpoint;
pub mod protocol;

use std::time::Duration;
use std::{num::NonZeroU32, path::Path};

use thiserror::Error;
use tokio::net::UnixStream;
use tunlatch_core::control::{SimulationError, SimulationRequest, SimulationStatus};
use tunlatch_core::status::{NetworkObservation, Status};

use crate::protocol::{
    ErrorCode, PROTOCOL_VERSION, Reply, Request, RequestEnvelope, ResponseEnvelope,
};

/// Upper bound for a complete request/response exchange, including connect and partial frames.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(3);

/// Transport and protocol errors never produce a successful status response.
#[derive(Debug, Error)]
pub enum IpcError {
    /// Local socket or stream operation failed.
    #[error("local IPC failed: {0}")]
    Io(#[from] std::io::Error),
    /// Payload was not a valid protocol message.
    #[error("invalid IPC message: {0}")]
    Json(#[from] serde_json::Error),
    /// Message violated the bounded framing contract.
    #[error("invalid IPC frame size {0}")]
    FrameSize(usize),
    /// A request or response used an unsupported protocol version.
    #[error("unsupported IPC version {0}; expected {PROTOCOL_VERSION}")]
    Version(u16),
    /// Remote endpoint reported a typed failure.
    #[error("service rejected request: {0:?}")]
    Remote(ErrorCode),
    /// The kernel-reported peer was not the expected user.
    #[error("IPC peer UID {actual} does not match expected UID {expected}")]
    Peer {
        /// Expected effective UID.
        expected: u32,
        /// Kernel-reported UID.
        actual: u32,
    },
    /// Exchange did not complete before the deadline.
    #[error("service request timed out")]
    Timeout,
    /// A valid response belonged to a different operation.
    #[error("service returned an unexpected reply")]
    UnexpectedReply,
    /// The requested operation is unavailable on the system query channel.
    #[error("system query channel accepts only status queries")]
    QueryOperation,
    /// The isolated simulation rejected the operation or could not verify its result.
    #[error("simulation request failed: {0:?}")]
    Simulation(SimulationError),
}

/// Check kernel peer credentials on both accepted and connected sockets.
pub fn verify_peer(stream: &UnixStream) -> Result<(), IpcError> {
    let expected = nix::unistd::geteuid().as_raw();
    let actual = stream.peer_cred()?.uid();
    if actual != expected {
        return Err(IpcError::Peer { expected, actual });
    }
    Ok(())
}

/// Fetch one fresh status snapshot, verifying directory, socket, credentials and protocol version.
pub async fn query_status(runtime_dir: &Path) -> Result<Status, IpcError> {
    match exchange(runtime_dir, Request::Status {}).await? {
        Reply::Status { status } => Ok(status),
        _ => Err(IpcError::UnexpectedReply),
    }
}

/// Request scan diagnostics explicitly, preserving compatibility of ordinary status queries.
pub async fn query_network_status(
    runtime_dir: &Path,
) -> Result<(Status, NetworkObservation), IpcError> {
    match exchange(runtime_dir, Request::NetworkStatus {}).await? {
        Reply::NetworkStatus {
            status,
            network_observation,
        } => Ok((status, network_observation)),
        _ => Err(IpcError::UnexpectedReply),
    }
}

/// Request status over the fixed system query socket after path and root-peer checks.
/// The current observer daemon does not serve this socket.
pub async fn query_system_status() -> Result<Status, IpcError> {
    match exchange_system(Request::Status {}).await? {
        Reply::Status { status } => Ok(status),
        _ => Err(IpcError::UnexpectedReply),
    }
}

/// Request network observation over the fixed system query socket.
pub async fn query_system_network_status() -> Result<(Status, NetworkObservation), IpcError> {
    match exchange_system(Request::NetworkStatus {}).await? {
        Reply::NetworkStatus {
            status,
            network_observation,
        } => Ok((status, network_observation)),
        _ => Err(IpcError::UnexpectedReply),
    }
}

/// Operations a future system query listener may dispatch after transport verification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SystemQuery {
    /// Read the current status.
    Status,
    /// Read status with network observation diagnostics.
    NetworkStatus,
}

/// Check the accepted peer before reading a single bounded query request.
/// Use the configured owner from the protected service configuration, never a wire field.
pub async fn read_system_query(
    stream: &mut UnixStream,
    owner: NonZeroU32,
) -> Result<SystemQuery, IpcError> {
    privileged_endpoint::verify_query_client(stream, owner)?;
    let envelope: RequestEnvelope = tokio::time::timeout(REQUEST_TIMEOUT, frame::read(stream))
        .await
        .map_err(|_| IpcError::Timeout)??;
    if envelope.version != PROTOCOL_VERSION {
        return Err(IpcError::Version(envelope.version));
    }
    match envelope.request {
        Request::Status {} => Ok(SystemQuery::Status),
        Request::NetworkStatus {} => Ok(SystemQuery::NetworkStatus),
        Request::Simulate { .. } | Request::SimulationStatus {} => Err(IpcError::QueryOperation),
    }
}

/// Query only the explicitly enabled in-memory simulation.
pub async fn query_simulation(runtime_dir: &Path) -> Result<SimulationStatus, IpcError> {
    simulation_reply(exchange(runtime_dir, Request::SimulationStatus {}).await?)
}

/// Submit to the simulation; this never authorizes or executes actual protection changes.
pub async fn submit_simulation(
    runtime_dir: &Path,
    operation: SimulationRequest,
) -> Result<SimulationStatus, IpcError> {
    simulation_reply(exchange(runtime_dir, Request::Simulate { operation }).await?)
}

fn simulation_reply(reply: Reply) -> Result<SimulationStatus, IpcError> {
    match reply {
        Reply::Simulation { status } => Ok(status),
        _ => Err(IpcError::UnexpectedReply),
    }
}

async fn exchange(runtime_dir: &Path, request: Request) -> Result<Reply, IpcError> {
    tokio::time::timeout(REQUEST_TIMEOUT, async {
        endpoint::validate_runtime_dir(runtime_dir)?;
        let path = runtime_dir.join(endpoint::SOCKET_NAME);
        endpoint::validate_socket(&path)?;
        let stream = UnixStream::connect(path).await?;
        verify_peer(&stream)?;
        exchange_connected(stream, request).await
    })
    .await
    .map_err(|_| IpcError::Timeout)?
}

async fn exchange_system(request: Request) -> Result<Reply, IpcError> {
    let deadline = tokio::time::Instant::now() + REQUEST_TIMEOUT;
    tokio::time::timeout_at(deadline, async {
        let stream = privileged_endpoint::connect_query().await?;
        if tokio::time::Instant::now() >= deadline {
            return Err(IpcError::Timeout);
        }
        exchange_connected(stream, request).await
    })
    .await
    .map_err(|_| IpcError::Timeout)?
}

async fn exchange_connected(mut stream: UnixStream, request: Request) -> Result<Reply, IpcError> {
    frame::write(
        &mut stream,
        &RequestEnvelope {
            version: PROTOCOL_VERSION,
            request,
        },
    )
    .await?;
    let response: ResponseEnvelope = frame::read(&mut stream).await?;
    if response.version != PROTOCOL_VERSION {
        return Err(IpcError::Version(response.version));
    }
    match response.reply {
        Reply::Error { code } => Err(IpcError::Remote(code)),
        Reply::SimulationError { error } => Err(IpcError::Simulation(error)),
        reply => Ok(reply),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::endpoint::ServerSocket;
    use std::os::unix::fs::PermissionsExt;

    #[tokio::test]
    async fn system_query_accepts_only_status_after_peer_verification() -> Result<(), IpcError> {
        let owner = NonZeroU32::new(nix::unistd::geteuid().as_raw()).unwrap_or(NonZeroU32::MIN);
        for (version, request) in [
            (PROTOCOL_VERSION, Request::NetworkStatus {}),
            (PROTOCOL_VERSION, Request::SimulationStatus {}),
            (PROTOCOL_VERSION + 1, Request::Status {}),
        ] {
            let network = matches!(request, Request::NetworkStatus {});
            let (mut client, mut server) = UnixStream::pair()?;
            frame::write(&mut client, &RequestEnvelope { version, request }).await?;
            let result = read_system_query(&mut server, owner).await;
            if version != PROTOCOL_VERSION {
                assert!(matches!(result, Err(IpcError::Version(value)) if value == version));
            } else if network {
                assert!(matches!(result, Ok(SystemQuery::NetworkStatus)));
            } else {
                assert!(matches!(result, Err(IpcError::QueryOperation)));
            }
        }
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn system_query_rejects_foreign_peer_before_waiting_for_a_frame() -> Result<(), IpcError>
    {
        let uid = nix::unistd::geteuid().as_raw();
        if uid == 0 {
            return Ok(());
        }
        let owner = if uid == 1 {
            NonZeroU32::new(2).unwrap_or(NonZeroU32::MIN)
        } else {
            NonZeroU32::MIN
        };
        let (_client, mut server) = UnixStream::pair()?;
        assert!(matches!(read_system_query(&mut server, owner).await,
            Err(IpcError::Peer { expected, actual }) if expected == owner.get() && actual == uid));
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn silent_peer_cannot_hold_client_beyond_deadline()
    -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))?;
        let server = ServerSocket::bind(dir.path())?;
        let task = tokio::spawn(async move {
            let stream = server.accept().await?;
            verify_peer(&stream)?;
            std::future::pending::<()>().await;
            Ok::<(), IpcError>(())
        });
        let result = query_status(dir.path()).await;
        task.abort();
        let stopped = task.await;
        assert!(stopped.is_err_and(|error| error.is_cancelled()));
        assert!(matches!(result, Err(IpcError::Timeout)));
        Ok(())
    }
}
