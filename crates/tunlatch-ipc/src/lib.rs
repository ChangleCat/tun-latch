//! Versioned local status and isolated simulation protocol. No PF mutation is exposed.

pub mod endpoint;
pub mod frame;
pub mod protocol;

use std::path::Path;
use std::time::Duration;

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
        let mut stream = UnixStream::connect(path).await?;
        verify_peer(&stream)?;
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
    })
    .await
    .map_err(|_| IpcError::Timeout)?
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::endpoint::ServerSocket;
    use std::os::unix::fs::PermissionsExt;

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
