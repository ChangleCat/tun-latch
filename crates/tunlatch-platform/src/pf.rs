//! PF inspection, rule construction and a guarded reference primitive; enforcement is incomplete.

use tunlatch_core::status::{ObservedProtection, UnknownReason};

pub mod hook_readback;
pub mod qualification;
pub mod reference;
pub mod reference_acquire;
pub mod rules;
pub mod snapshot;

// The retained writer remains restricted to the removed lab executable until a protected
// product session and recovery protocol are in place. Only reads are connected here.
#[allow(dead_code)]
mod native_hook;

/// Query the capabilities implemented by this framework, without guessing the global PF state.
pub fn observe() -> ObservedProtection {
    ObservedProtection::Unknown {
        reason: UnknownReason::BackendNotImplemented,
    }
}
