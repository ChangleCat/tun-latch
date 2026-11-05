//! Snapshot-scoped tunnel hint behavior.

use std::time::Duration;

use tunlatch_core::status::NetworkInterface;
use tunlatch_platform::events::{Invalidation, NetworkObserver, ScanError};
use tunlatch_platform::identity::{HintStatus, tunnel_hints};

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
    restarted.refresh_with(|| Ok(vec![interface()]))?;
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
