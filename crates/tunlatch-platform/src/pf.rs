//! PF inspection, rule construction and a guarded reference primitive; enforcement is incomplete.

use tunlatch_core::status::{ObservedProtection, UnknownReason};

pub mod anchor;
pub mod hook_readback;
pub mod qualification;
pub mod recovery;
pub mod reference;
pub mod reference_acquire;
pub mod retirement;
pub mod rules;
pub mod session;
pub mod snapshot;

// The native writer is restricted to the protected installed daemon and its guarded session.
#[allow(dead_code)]
mod native_hook;

/// Query the capabilities implemented by this framework, without guessing the global PF state.
pub fn observe() -> ObservedProtection {
    ObservedProtection::Unknown {
        reason: UnknownReason::BackendNotImplemented,
    }
}
