//! Display-only tunnel candidates and conservative invalidation, never ownership evidence.
//!
//! Raw control metadata and dynamic CDHash checks do not establish a complete loaded-image
//! identity or direct ownership of a specific interface. These diagnostics cannot create a
//! correlated or trusted binding.

use std::sync::Arc;

use crate::events::{NetworkObserver, NetworkSnapshot};

mod correlation;
mod image;
#[allow(unsafe_code)]
mod native;
mod process;
pub use correlation::{
    TunnelCandidate, TunnelCandidateError, inspect_tunnel_candidate,
    inspect_tunnel_candidate_privileged,
};
pub use image::{ImageInspection, ImageProblem, inspect_expected_cdhash};
pub use process::{
    InspectionFailure, InspectionProblem, InspectionStage, ProcessIdentity, ProcessInspection,
    RawControl, RawFd, RawInspection, RawObservation, inspect_process, inspect_selected_process,
    inspect_selected_process_privileged,
};

/// A snapshot-scoped interface hint. Name and index are diagnostic, not identity.
#[derive(Clone, Debug)]
pub struct TunnelHint {
    generation: u64,
    token: Arc<()>,
    name: String,
    index: u32,
}

impl PartialEq for TunnelHint {
    fn eq(&self, other: &Self) -> bool {
        self.generation == other.generation
            && Arc::ptr_eq(&self.token, &other.token)
            && self.name == other.name
            && self.index == other.index
    }
}

impl Eq for TunnelHint {}

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
