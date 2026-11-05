//! UID egress model: candidate data and checked observations never grant system privileges.
//!
//! The owner must obtain administrator and physical-link facts from trusted platform boundaries,
//! never from client DTOs. This module checks their consistency; it cannot authenticate a
//! collector's identity or an administrator's authority. Its output is a conditional UID requirement, not a
//! packet permit, PF result, or protected status. The current observer does not use this module.
//!
//! System-maintenance drafts are validated and bound to confirmation, but their packet matching
//! is separate work. A UID miss must continue to the independently checked TUN/system boundary.

mod approval;
mod draft;

pub use approval::{
    AdminObservation, ApprovalChannel, ApprovalPreview, BindingSelection, CheckedPolicy,
    EgressError, EgressLocation, EgressModel, EnforcementAuthorization, ObservationWindow,
    ProfileObservation, ProfileSnapshot, SocketOwner, UidDecision, UidRequirement,
};
pub use draft::{
    AddressFamily, Authorizations, EgressPolicyDraft, MAX_AUTHORIZATION_BYTES,
    MAX_AUTHORIZATION_INPUT_BYTES, ProxyUidGrant, SystemProfile, SystemRecipe, Transport,
};
