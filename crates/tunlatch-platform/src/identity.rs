//! Display-only tunnel candidates and conservative invalidation, never ownership evidence.
//!
//! No current collector can verify a process's loaded image or direct utun control FD.
//! Therefore these diagnostics cannot create a correlated or trusted binding.

use std::sync::Arc;

use crate::events::{NetworkObserver, NetworkSnapshot};

/// A snapshot-scoped interface hint. Name and index are diagnostic, not identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TunnelHint {
    generation: u64,
    token: Arc<()>,
    name: String,
    index: u32,
}

/// Result of checking a hint against the current observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HintStatus {
    /// The hint still appears in the exact same observation; ownership remains unavailable.
    PresentOwnershipUnavailable,
    /// The observation is missing, expired, or has changed generation.
    Invalidated,
}

impl TunnelHint {
    /// Name reported by interface enumeration; not proof of ownership.
    pub fn name(&self) -> &str {
        &self.name
    }
    /// Index reported by interface enumeration; not a persistent identifier.
    pub fn index(&self) -> u32 {
        self.index
    }
    /// Generation in which this hint was observed.
    pub fn generation(&self) -> u64 {
        self.generation
    }
    /// Check that this hint still belongs to the very same current observation.
    ///
    /// Repeated names or indices in a later scan do not preserve the hint.
    pub fn check(&self, observer: &mut NetworkObserver) -> HintStatus {
        if observer.current().is_some_and(|snapshot| {
            snapshot.generation() == self.generation
                && Arc::ptr_eq(&snapshot.token, &self.token)
                && snapshot
                    .interfaces()
                    .iter()
                    .any(|interface| interface.name == self.name && interface.index == self.index)
        }) {
            HintStatus::PresentOwnershipUnavailable
        } else {
            HintStatus::Invalidated
        }
    }
}

/// Collect interface-name hints from one scan. This does not inspect process or FD ownership.
pub fn tunnel_hints(snapshot: &NetworkSnapshot) -> Vec<TunnelHint> {
    snapshot
        .interfaces()
        .iter()
        .filter(|interface| interface.is_tun_candidate())
        .map(|interface| TunnelHint {
            generation: snapshot.generation(),
            token: Arc::clone(&snapshot.token),
            name: interface.name.clone(),
            index: interface.index,
        })
        .collect()
}
