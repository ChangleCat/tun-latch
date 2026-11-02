//! Real Unix-socket integration, without root or PF modifications.

use std::os::unix::fs::PermissionsExt;

use tokio::net::UnixStream;
use tokio::sync::oneshot;
use tunlatch_core::config::{Config, DesiredProtection};
use tunlatch_core::status::{CommittedPolicy, ObservedProtection, UnknownReason};
use tunlatch_ipc::endpoint::{SOCKET_NAME, ServerSocket};
use tunlatch_ipc::protocol::{
    ErrorCode, PROTOCOL_VERSION, Reply, Request, RequestEnvelope, ResponseEnvelope,
};
use tunlatch_ipc::{frame, query_status};

#[tokio::test]
async fn requested_protection_stays_unknown_across_reconnects_and_shutdown() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))?;
    let socket = ServerSocket::bind(dir.path())?;
    let config = Config::parse("schema_version = 1\ndesired = 'enabled'")?;
    let (shutdown, receiver) = oneshot::channel();
    let service = tokio::spawn(tunlatchd::serve(socket, config, async {
        receiver.await.map_err(std::io::Error::other)
    }));
    for _ in 0..2 {
        let status = query_status(dir.path()).await?;
        assert_eq!(status.desired, DesiredProtection::Enabled);
        assert_eq!(status.committed, CommittedPolicy::Unmanaged);
        assert_eq!(
            status.observed,
            ObservedProtection::Unknown {
                reason: UnknownReason::BackendNotImplemented,
            }
        );
        assert!(status.interfaces.iter().any(|interface| interface.loopback));
    }
    shutdown
        .send(())
        .map_err(|()| anyhow::anyhow!("service stopped prematurely"))?;
    service.await??;
    assert!(!dir.path().join(SOCKET_NAME).exists());
    assert!(query_status(dir.path()).await.is_err());
    Ok(())
}

#[tokio::test]
async fn incompatible_client_is_rejected_and_service_remains_usable() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))?;
    let socket = ServerSocket::bind(dir.path())?;
    let (shutdown, receiver) = oneshot::channel();
    let service = tokio::spawn(tunlatchd::serve(socket, Config::default(), async {
        receiver.await.map_err(std::io::Error::other)
    }));
    let mut stream = UnixStream::connect(dir.path().join(SOCKET_NAME)).await?;
    frame::write(
        &mut stream,
        &RequestEnvelope {
            version: PROTOCOL_VERSION + 1,
            request: Request::Status {},
        },
    )
    .await?;
    let response: ResponseEnvelope = frame::read(&mut stream).await?;
    assert!(matches!(
        response.reply,
        Reply::Error {
            code: ErrorCode::UnsupportedVersion
        }
    ));
    assert!(query_status(dir.path()).await.is_ok());
    shutdown
        .send(())
        .map_err(|()| anyhow::anyhow!("service stopped prematurely"))?;
    service.await??;
    Ok(())
}
