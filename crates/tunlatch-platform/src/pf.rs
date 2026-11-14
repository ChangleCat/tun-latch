//! PF adapter and offline rule construction. No device is opened and no command is executed.

use tunlatch_core::status::{ObservedProtection, UnknownReason};

pub mod reference;
pub mod rules;
pub mod snapshot;

#[cfg(test)]
mod native_hook;

/// Query the capabilities implemented by this framework, without guessing the global PF state.
pub fn observe() -> ObservedProtection {
    ObservedProtection::Unknown {
        reason: UnknownReason::BackendNotImplemented,
    }
}
