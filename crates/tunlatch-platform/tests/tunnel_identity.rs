//! Snapshot-scoped tunnel hint behavior.

use std::{os::fd::AsRawFd, os::unix::net::UnixStream, time::Duration};

use tunlatch_core::status::NetworkInterface;
use tunlatch_platform::events::{Invalidation, NetworkObserver, ScanError};
use tunlatch_platform::identity::{
    HintStatus, InspectionFailure, InspectionProblem, ProcessInspection, RawInspection,
    inspect_process, inspect_selected_process, inspect_selected_process_privileged, tunnel_hints,
};

#[test]
fn privileged_inspection_rejects_ordinary_user_before_reading() {
    assert!(!nix::unistd::Uid::effective().is_root());
    for pid in [0, std::process::id()] {
        assert!(matches!(
            inspect_selected_process_privileged(pid),
            RawInspection::Error(InspectionFailure {
                problem: InspectionProblem::AdminRequired,
                ..
            })
        ));
    }
}

fn interface() -> NetworkInterface {
    NetworkInterface {
        name: "utun7".into(),
        index: 8,
        up: true,
        loopback: false,
        addresses: vec![],
    }
}

#[test]
fn observes_own_process_without_claiming_ownership() {
    let result = inspect_process(std::process::id());
    if !cfg!(target_arch = "aarch64") {
        assert!(matches!(
            result,
            ProcessInspection::Error(InspectionFailure {
                problem: InspectionProblem::UnsupportedLayout,
                ..
            })
        ));
        return;
    }
    assert!(
        matches!(result, ProcessInspection::Partial(_)),
        "{result:?}"
    );
    if let ProcessInspection::Partial(identity) = result {
        assert_eq!(identity.pid, std::process::id());
        assert_eq!(identity.uid, nix::unistd::Uid::effective().as_raw());
        assert_ne!(identity.birth_seconds, 0);
        assert!(identity.birth_microseconds < 1_000_000);
    }
}

#[test]
fn reads_own_unix_socket_as_fd_without_asserting_tunnel_ownership() -> std::io::Result<()> {
    let (first, second) = UnixStream::pair()?;
    let result = inspect_selected_process(std::process::id());
    if !cfg!(target_arch = "aarch64") {
        assert!(matches!(
            result,
            RawInspection::Error(InspectionFailure {
                problem: InspectionProblem::UnsupportedLayout,
                ..
            })
        ));
        return Ok(());
    }
    assert!(
        matches!(result, RawInspection::CompleteRaw(_)),
        "{result:?}"
    );
    if let RawInspection::CompleteRaw(raw) = result {
        for fd in [first.as_raw_fd(), second.as_raw_fd()] {
            assert!(
                raw.fds
                    .iter()
                    .any(|entry| entry.fd == fd && entry.kind == 2)
            );
            assert!(!raw.controls.iter().any(|control| control.fd == fd));
        }
        assert!(raw.started_at <= raw.finished_at && raw.finished_at < raw.expires_at);
    }
    Ok(())
}

#[test]
fn reuse_and_observer_restart_invalidate_hints() -> Result<(), ScanError> {
    let mut observer = NetworkObserver::new(Duration::from_secs(10));
    let hints = tunnel_hints(observer.refresh_with(|| Ok(vec![interface()]))?);
    let hint = &hints[0];
    assert_eq!(
        hint.check(&mut observer),
        HintStatus::PresentOwnershipUnavailable
    );
    observer.refresh_with(|| Ok(vec![interface()]))?;
    assert_eq!(hint.check(&mut observer), HintStatus::Invalidated);
    let mut restarted = NetworkObserver::new(Duration::from_secs(10));
    let restarted_hints = tunnel_hints(restarted.refresh_with(|| Ok(vec![interface()]))?);
    assert_eq!(*hint, hint.clone());
    assert_ne!(*hint, restarted_hints[0]);
    assert_eq!(hint.check(&mut restarted), HintStatus::Invalidated);
    Ok(())
}

#[test]
fn interruption_or_expiry_invalidates_hints() -> Result<(), ScanError> {
    let mut observer = NetworkObserver::new(Duration::from_secs(10));
    let hints = tunnel_hints(observer.refresh_with(|| Ok(vec![interface()]))?);
    observer.invalidate(Invalidation::Interrupted);
    assert_eq!(hints[0].check(&mut observer), HintStatus::Invalidated);
    let mut stale = NetworkObserver::new(Duration::ZERO);
    let hints = tunnel_hints(stale.refresh_with(|| Ok(vec![interface()]))?);
    assert_eq!(hints[0].check(&mut stale), HintStatus::Invalidated);
    Ok(())
}
