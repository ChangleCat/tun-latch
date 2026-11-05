//! Polling observation behavior.

use std::time::Duration;

use tunlatch_core::status::NetworkInterface;
use tunlatch_platform::events::{Invalidation, MAX_INTERFACES, NetworkObserver, ScanError};

fn interface(name: &str) -> NetworkInterface {
    NetworkInterface {
        name: name.into(),
        index: 1,
        up: true,
        loopback: false,
        addresses: vec![],
    }
}

#[test]
fn failed_scans_discard_previous_data_and_consume_a_generation() -> Result<(), ScanError> {
    let mut observer = NetworkObserver::new(Duration::from_secs(10));
    assert_eq!(
        observer
            .refresh_with(|| Ok(vec![interface("en0")]))?
            .generation(),
        1
    );
    assert!(
        observer
            .refresh_with(|| Err(nix::errno::Errno::EIO))
            .is_err()
    );
    assert!(observer.current().is_none());
    assert_eq!(observer.invalidation(), Some(Invalidation::ScanFailed));
    assert_eq!(observer.refresh_with(|| Ok(vec![]))?.generation(), 3);
    Ok(())
}

#[test]
fn bounds_expiry_and_shutdown_discard_observations() -> Result<(), ScanError> {
    let mut observer = NetworkObserver::new(Duration::ZERO);
    observer.refresh_with(|| Ok(vec![interface("utun0")]))?;
    assert!(observer.current().is_none());
    assert_eq!(observer.invalidation(), Some(Invalidation::Expired));
    assert!(matches!(
        observer.refresh_with(|| Ok(vec![interface("en0"); MAX_INTERFACES + 1])),
        Err(ScanError::LimitExceeded)
    ));
    assert!(matches!(
        observer.refresh_with(|| Ok(vec![interface(&"x".repeat(256))])),
        Err(ScanError::LimitExceeded)
    ));
    observer.invalidate(Invalidation::Shutdown);
    assert!(matches!(
        observer.refresh_with(|| Ok(vec![])),
        Err(ScanError::Shutdown)
    ));
    Ok(())
}

#[test]
fn ordinary_user_can_take_read_only_native_scan() -> Result<(), ScanError> {
    let mut observer = NetworkObserver::new(Duration::from_secs(10));
    let snapshot = observer.refresh()?;
    assert!(snapshot.interfaces().iter().any(|item| item.loopback));
    Ok(())
}
