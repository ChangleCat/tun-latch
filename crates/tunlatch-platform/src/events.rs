//! Bounded network observations and native invalidation hints, not identity or trust.
//!
//! A scan is not atomic and can miss changes between polls, including sleep/wake and
//! interface reuse. Bounds are checked after native enumeration returns; the underlying
//! enumeration may allocate beyond them, so they are not a hard collection-time memory limit.
//! Every successful scan gets a new generation; callers must not carry
//! identity or authorization across generations.

mod native;

pub use native::{EventStatus, NetworkEventControl, NetworkEventMonitor, SubscriptionState};

use std::sync::Arc;
use std::time::{Duration, Instant};

use thiserror::Error;
use tunlatch_core::status::NetworkInterface;

/// Maximum number of interfaces retained from a scan.
pub const MAX_INTERFACES: usize = 256;
/// Maximum number of addresses retained on each interface.
pub const MAX_ADDRESSES_PER_INTERFACE: usize = 256;
/// Maximum UTF-8 bytes retained in an interface name.
pub const MAX_INTERFACE_NAME_BYTES: usize = 255;

/// Why the most recent observation was discarded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Invalidation {
    /// A scan failed or exceeded the bounds.
    ScanFailed,
    /// The observation exceeded its caller-selected lifetime.
    Expired,
    /// The caller detected a gap, lost notification, wake, or observer interruption.
    Interrupted,
    /// Ordering or continuity could not be established.
    OutOfOrder,
    /// The observer was shut down.
    Shutdown,
}

/// A scan cannot be used as a complete bounded observation.
#[derive(Debug, Error)]
pub enum ScanError {
    /// Native enumeration failed.
    #[error("network enumeration failed: {0}")]
    Native(#[from] nix::Error),
    /// The observation exceeds its resource bounds.
    #[error("network observation exceeds its bounds")]
    LimitExceeded,
    /// No further unique generation can be allocated.
    #[error("network observation generation exhausted")]
    GenerationExhausted,
    /// The observer has been shut down.
    #[error("network observer is shut down")]
    Shutdown,
    /// Notifications arrived during the scan or the subscription was unavailable.
    #[error("network notification continuity unavailable or changed during scan")]
    Interrupted,
}

/// A scan result that carries no authority over interface ownership or lifetime.
#[derive(Debug)]
pub struct NetworkSnapshot {
    generation: u64,
    pub(crate) token: Arc<()>,
    collected_at: Instant,
    interfaces: Vec<NetworkInterface>,
}

impl NetworkSnapshot {
    /// Observer-local generation; it is not an interface instance identifier.
    pub fn generation(&self) -> u64 {
        self.generation
    }
    /// Monotonic time when the scan completed.
    pub fn collected_at(&self) -> Instant {
        self.collected_at
    }
    /// Enumerated interfaces, including IPv6-only interfaces.
    pub fn interfaces(&self) -> &[NetworkInterface] {
        &self.interfaces
    }
}

/// Synchronous polling observer. Its owner decides when to rescan and when to stop.
#[derive(Debug)]
pub struct NetworkObserver {
    max_age: Duration,
    generation: u64,
    current: Option<NetworkSnapshot>,
    invalidation: Option<Invalidation>,
    shutdown: bool,
}

impl NetworkObserver {
    /// Construct an empty observer. Zero lifetime makes every snapshot immediately stale.
    pub fn new(max_age: Duration) -> Self {
        Self {
            max_age,
            generation: 0,
            current: None,
            invalidation: None,
            shutdown: false,
        }
    }

    /// Perform a fresh, ordinary-user, read-only native scan.
    pub fn refresh(&mut self) -> Result<&NetworkSnapshot, ScanError> {
        self.refresh_with(crate::network::snapshot)
    }

    /// Scan while checking the subscription on both sides of enumeration.
    /// A missing notification cannot prove a scan atomic or complete.
    pub fn refresh_with_monitor<F>(
        &mut self,
        monitor: &mut NetworkEventMonitor,
        scan: F,
    ) -> Result<&NetworkSnapshot, ScanError>
    where
        F: FnOnce() -> Result<Vec<NetworkInterface>, nix::Error>,
    {
        self.refresh_with_control(&monitor.control(), scan)
    }

    /// Scan while a separately owned native worker is supervised by its caller.
    pub fn refresh_with_control<F>(
        &mut self,
        control: &NetworkEventControl,
        scan: F,
    ) -> Result<&NetworkSnapshot, ScanError>
    where
        F: FnOnce() -> Result<Vec<NetworkInterface>, nix::Error>,
    {
        if self.shutdown {
            return Err(ScanError::Shutdown);
        }
        let before = control.status();
        if before.0 != SubscriptionState::Running {
            self.invalidate(Invalidation::Interrupted);
            return Err(ScanError::Interrupted);
        }
        self.refresh_with(scan)?;
        let after = control.status();
        if after.0 != SubscriptionState::Running || after.1 != before.1 {
            self.invalidate(Invalidation::Interrupted);
            return Err(ScanError::Interrupted);
        }
        self.current.as_ref().ok_or(ScanError::Interrupted)
    }

    /// Scan with an injected source. Supplied data is untrusted and cannot establish ownership.
    pub fn refresh_with<F>(&mut self, scan: F) -> Result<&NetworkSnapshot, ScanError>
    where
        F: FnOnce() -> Result<Vec<NetworkInterface>, nix::Error>,
    {
        self.current = None;
        if self.shutdown {
            return Err(ScanError::Shutdown);
        }
        let generation = match self.generation.checked_add(1) {
            Some(value) => value,
            None => {
                self.invalidation = Some(Invalidation::ScanFailed);
                return Err(ScanError::GenerationExhausted);
            }
        };
        // Reserve a generation even on failure; a failed scan cannot replay an old locator.
        self.generation = generation;
        let interfaces = match scan() {
            Ok(value) => value,
            Err(error) => {
                self.invalidation = Some(Invalidation::ScanFailed);
                return Err(error.into());
            }
        };
        if interfaces.len() > MAX_INTERFACES
            || interfaces.iter().any(|item| {
                item.addresses.len() > MAX_ADDRESSES_PER_INTERFACE
                    || item.name.is_empty()
                    || item.name.len() > MAX_INTERFACE_NAME_BYTES
            })
        {
            self.invalidation = Some(Invalidation::ScanFailed);
            return Err(ScanError::LimitExceeded);
        }
        self.current = Some(NetworkSnapshot {
            generation,
            token: Arc::new(()),
            collected_at: Instant::now(),
            interfaces,
        });
        self.invalidation = None;
        // The value was just assigned above.
        self.current.as_ref().ok_or(ScanError::GenerationExhausted)
    }

    /// Return the current observation only if its monotonic lifetime has not expired.
    pub fn current(&mut self) -> Option<&NetworkSnapshot> {
        if self
            .current
            .as_ref()
            .is_some_and(|snapshot| snapshot.collected_at.elapsed() >= self.max_age)
        {
            self.invalidate(Invalidation::Expired);
        }
        self.current.as_ref()
    }

    /// Forget cached data on any loss of continuity. Shutdown is permanent.
    pub fn invalidate(&mut self, reason: Invalidation) {
        self.current = None;
        self.invalidation = Some(reason);
        if reason == Invalidation::Shutdown {
            self.shutdown = true;
        }
    }

    /// Most recent reason data was discarded, cleared by a successful scan.
    pub fn invalidation(&self) -> Option<Invalidation> {
        self.invalidation
    }
}
