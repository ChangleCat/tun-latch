//! Explicitly unavailable PF adapter. No device is opened and no command is executed.

use tunlatch_core::status::{ObservedProtection, UnknownReason};

/// Query the capabilities implemented by this framework, without guessing the global PF state.
pub fn observe() -> ObservedProtection {
    ObservedProtection::Unknown {
        reason: UnknownReason::BackendNotImplemented,
    }
}
