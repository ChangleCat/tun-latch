//! Single read-only service loop with bounded clients and observed task lifetimes.

use std::future::Future;
use std::io;

use tokio::net::UnixStream;
use tokio::task::{JoinError, JoinSet};
use tunlatch_core::config::Config;
use tunlatch_core::status::{CommittedPolicy, Status};
use tunlatch_ipc::endpoint::ServerSocket;
use tunlatch_ipc::protocol::{
    ErrorCode, PROTOCOL_VERSION, Reply, Request, RequestEnvelope, ResponseEnvelope,
};
use tunlatch_ipc::{IpcError, REQUEST_TIMEOUT, frame, verify_peer};
use tunlatch_platform::{network, pf};

/// Maximum simultaneous exchanges; excess connections are closed without spawning tasks.
pub const MAX_CLIENTS: usize = 16;

/// Run until shutdown, then stop accepting and drain in-flight status requests.
///
/// Native observations that have started are awaited even after a client's I/O deadline.
/// All task results are observed. No shutdown path enables, disables or flushes PF.
pub async fn serve(
    socket: ServerSocket,
    config: Config,
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
                let desired = config.desired();
                tasks.spawn(handle(stream, desired));
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

async fn handle(
    mut stream: UnixStream,
    desired: tunlatch_core::config::DesiredProtection,
) -> Result<(), IpcError> {
    let deadline = tokio::time::Instant::now() + REQUEST_TIMEOUT;
    let request: RequestEnvelope = tokio::time::timeout_at(deadline, frame::read(&mut stream))
        .await
        .map_err(|_| IpcError::Timeout)??;
    let reply = if request.version != PROTOCOL_VERSION {
        Reply::Error {
            code: ErrorCode::UnsupportedVersion,
        }
    } else {
        match request.request {
            Request::Status {} => {
                // Native enumeration can block; keep it off the async I/O worker. Do not drop
                // its JoinHandle on a deadline: a started native call cannot be cancelled.
                match tokio::task::spawn_blocking(network::snapshot).await {
                    Ok(Ok(interfaces)) => Reply::Status {
                        status: Status {
                            desired,
                            committed: CommittedPolicy::Unmanaged,
                            observed: pf::observe(),
                            interfaces,
                        },
                    },
                    result => {
                        tracing::error!(?result, "network observation failed");
                        Reply::Error {
                            code: ErrorCode::ObservationFailed,
                        }
                    }
                }
            }
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
    use tunlatch_core::config::DesiredProtection;

    #[tokio::test(start_paused = true)]
    async fn partial_request_expires_instead_of_holding_a_worker() -> anyhow::Result<()> {
        use tokio::io::AsyncWriteExt;
        let (mut client, server) = UnixStream::pair()?;
        client.write_all(&[0, 0]).await?;
        assert!(matches!(
            handle(server, DesiredProtection::Disabled).await,
            Err(IpcError::Timeout)
        ));
        Ok(())
    }
}
