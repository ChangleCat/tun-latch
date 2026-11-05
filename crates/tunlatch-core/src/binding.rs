//! Snapshot-scoped TUN correlation, kept separate from kernel enforcement authority.
//!
//! This module performs **model checks**, not operating-system authentication. A trusted
//! platform collector must obtain truthful process, loaded-image and direct FD ownership
//! observations. The service must never use a client's self-submitted report as platform
//! evidence. Paths, process names, interface names/indices and user assertions cannot replace
//! those observations. The current observer has no collector that can establish this chain.
//!
//! Even a [`VerifiedCurrentBinding`] only records correlation at the supplied observation
//! window. It does not prove that PF isolates an interface instance after name/index reuse,
//! observer suspension or process failure. [`EnforcementQualifiedBinding`] is deliberately
//! uninhabited until the separate PF and lifecycle contracts are established.

use std::convert::Infallible;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::status::NetworkInterface;

/// Maximum interfaces in one candidate snapshot; this is a model resource limit, not trust.
pub const MAX_TUN_CANDIDATES: usize = 256;

/// An observer-local snapshot locator. These numbers are not kernel instance identities.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotStamp {
    /// Nonzero identifier allocated for this observer lifetime by its trusted owner.
    pub observer_epoch: [u8; 16],
    /// Nonzero, monotonically advanced generation within that observer lifetime.
    pub generation: u64,
}

/// Discovery metadata with a collector-local observation ID; this is still untrusted input.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InterfaceObservation {
    /// Nonzero snapshot-local token; it does not promise kernel lifetime isolation.
    pub observation_id: u64,
    /// Discovered interface metadata, including IPv6-only and scoped addresses.
    pub interface: NetworkInterface,
}

/// Whether a collector can supply a coherent snapshot or needs to rescan first.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotCompleteness {
    /// The collector reports one complete, coherent snapshot.
    Complete,
    /// Events were lost or the scan was interrupted; correlation must not proceed.
    RequiresRescan,
}

/// An immutable, structurally checked discovery snapshot. It grants no interface trust.
#[derive(Debug, Eq, PartialEq)]
pub struct CandidateSnapshot {
    stamp: SnapshotStamp,
    observed_at: u64,
    completeness: SnapshotCompleteness,
    candidates: Vec<InterfaceObservation>,
}

/// Proxy roles supported by this model; matching a role alone never proves identity.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProxyCore {
    /// A sing-box core instance.
    SingBox,
    /// An Xray core instance; it is not assumed to be a particular chain role.
    Xray,
    /// A mihomo core instance.
    Mihomo,
    /// An unrecognized core; it cannot receive a validated selection.
    Unknown,
}

/// User intent to select particular software content, not proof of consent or provenance.
///
/// The caller must separately enforce the operation authorization policy and establish the
/// content's acceptable provenance. No filesystem path or version string is accepted here.
#[derive(Debug, Eq, PartialEq)]
pub struct ProxySelection {
    core: ProxyCore,
    image_sha256: [u8; 32],
}

/// Untrusted process facts reported by the platform collector.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessObservation {
    /// Nonzero process ID; it must be paired with the observed birth identity.
    pub pid: u32,
    /// Process birth time seconds from the platform, not a user-supplied label.
    pub birth_seconds: u64,
    /// Microsecond component, strictly below one million.
    pub birth_microseconds: u32,
    /// Effective user ID observed for this process instance.
    pub uid: u32,
    /// Core role observed for this instance.
    pub core: ProxyCore,
    /// SHA-256 of the running image established by the collector, not merely a path's file.
    pub loaded_image_sha256: [u8; 32],
}

/// How the report claims to associate a process instance with a utun control socket.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OwnershipMethod {
    /// The actual holder queried UTUN_OPT_IFNAME for its own FD.
    HolderFdQuery,
    /// A trusted collector inspected the holder's kernel-control FD and checked its mapping.
    KernelControlInspection,
    /// Interface-name inference; retained as rejectable input, never direct evidence.
    InterfaceNameOnly,
    /// Route inference; retained as rejectable input, never direct evidence.
    RouteInference,
    /// A human asserted ownership without direct evidence; it cannot grant correlation.
    ManualAssertion,
}

/// Untrusted direct-ownership fields for one FD at one sampling point.
///
/// Opaque handles and units may be reused. Equality across a bounded collection window is
/// only a consistency check; the platform must detect races and unknown/hidden handles.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ControlSocketObservation {
    /// FD in the observed process, never an FD that this model opens or operates on.
    pub fd: u32,
    /// Method by which the platform obtained the claimed association.
    pub method: OwnershipMethod,
    /// Kernel-control name; direct utun reports require com.apple.net.utun_control.
    pub controller_name: String,
    /// Nonzero kernel-control identifier observed by the collector.
    pub controller_id: u32,
    /// Nonzero control unit, checked against the reported utun name.
    pub control_unit: u32,
    /// Nonzero opaque socket observation; not a stable cross-close identifier.
    pub opaque_socket: u64,
    /// Nonzero opaque PCB observation; not a stable cross-close identifier.
    pub opaque_pcb: u64,
    /// Interface name obtained by the direct ownership method, not by arbitrary routing.
    pub associated_interface_name: String,
}

/// One untrusted ownership sample. Both sides of collection must describe the same facts.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OwnershipSample {
    /// Observer epoch/generation independently checked at this sampling point.
    pub snapshot: SnapshotStamp,
    /// Observed process birth, role and running-image identity.
    pub process: ProcessObservation,
    /// Observed interface instance within this candidate snapshot.
    pub interface: InterfaceObservation,
    /// Direct FD ownership association for this process/interface pair.
    pub socket: ControlSocketObservation,
}

/// Before/after samples for one possible association; these fields do not attest truth.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OwnershipMatch {
    /// Sample immediately before collecting the association.
    pub before: OwnershipSample,
    /// Sample immediately after collecting the association.
    pub after: OwnershipSample,
}

/// Explicit quality of the raw report. Complete still means untrusted input.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportCompleteness {
    /// No usable ownership facts are available, including permission denial.
    Unavailable,
    /// Some observations are missing or the collector detected an interruption.
    Partial,
    /// The collector reports a complete set; model consistency checks are still mandatory.
    Complete,
}

/// Collector-supplied monotonic times in the observer epoch, in one consistent unit.
///
/// No TTL is invented by this module. The lifecycle owner must set an evidence deadline.
/// A short deadline is never proof of continuous kernel interface isolation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationWindow {
    /// Collection began; the candidate snapshot must fall within this window.
    pub started_at: u64,
    /// Collection completed; validation cannot precede this time.
    pub finished_at: u64,
    /// Exclusive deadline after which this evidence must be reacquired.
    pub valid_until: u64,
}

/// Constructible/deserializable report data. Deserialization never creates a trusted binding.
///
/// A malicious producer can fabricate internally consistent fields. The privileged service
/// must reject client-provided reports as facts and supply its own trusted collector output.
/// The model requires one complete association and matching before/after observations.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UntrustedOwnershipReport {
    /// Nonzero collection counter allocated monotonically throughout the observer epoch.
    ///
    /// The trusted collector advances it for each actual collection, even when a coarse
    /// clock reports the same completion time. Replaying or extending an old report must
    /// not allocate a new counter. This is not a cryptographic attestation of collection.
    pub collection_sequence: u64,
    /// Availability/completeness reported by the collector, with no success boolean shortcut.
    pub completeness: ReportCompleteness,
    /// Collection and validity bounds tied to the supplied observer epoch.
    pub window: ObservationWindow,
    /// All candidate ownership matches; zero or multiple matches cannot grant correlation.
    pub matches: Vec<OwnershipMatch>,
}

/// Reasons model checks cannot establish snapshot-scoped correlation.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum BindingError {
    /// An epoch/generation does not identify a usable observer snapshot.
    #[error("snapshot epoch and generation must be nonzero")]
    InvalidSnapshotStamp,
    /// Candidate metadata is malformed, is loopback or has an invalid scoped address.
    #[error("invalid TUN candidate metadata")]
    InvalidCandidate,
    /// Snapshot-local IDs, interface names or indices are duplicated.
    #[error("candidate identifiers, names and indices must be unique")]
    DuplicateCandidate,
    /// Snapshot exceeds the configured resource limit.
    #[error("candidate snapshot exceeds {MAX_TUN_CANDIDATES} interfaces")]
    TooManyCandidates,
    /// The candidate scan is incomplete and cannot be used for correlation.
    #[error("candidate snapshot requires a complete rescan")]
    SnapshotIncomplete,
    /// Software selection is unknown or lacks a content identity.
    #[error("a known core and nonempty running-image identity are required")]
    InvalidSoftwareSelection,
    /// The collector has no usable direct ownership evidence.
    #[error("direct ownership evidence is unavailable")]
    EvidenceUnavailable,
    /// The collector supplied only part of the required observations.
    #[error("direct ownership evidence is incomplete")]
    PartialEvidence,
    /// The report cannot identify a collection within its observer epoch.
    #[error("ownership collection sequence must be nonzero")]
    InvalidCollectionSequence,
    /// Confirmation/refresh received the same or an older collection again.
    #[error("current direct ownership collection sequence did not advance")]
    CollectionSequenceNotAdvanced,
    /// No association matched.
    #[error("no direct ownership association was observed")]
    NoOwnershipMatch,
    /// More than one association matched and choosing one would guess ownership.
    #[error("direct ownership association is ambiguous")]
    AmbiguousOwnership,
    /// Collection/deadline ordering or snapshot inclusion is invalid.
    #[error("invalid ownership observation window")]
    InvalidObservationWindow,
    /// The caller is trying to use observations from its future.
    #[error("ownership observation has not completed at the supplied time")]
    ObservationNotFinished,
    /// Deadline has been reached; reacquisition is required.
    #[error("ownership observation has expired")]
    EvidenceExpired,
    /// A supposedly current collection predates the evidence it would replace.
    #[error("current ownership collection predates the saved observation")]
    ObservationRegressed,
    /// Observation or confirmation belongs to a different observer epoch/generation.
    #[error("ownership evidence belongs to another snapshot")]
    SnapshotChanged,
    /// Observed interface does not exactly match its snapshot-local instance.
    #[error("interface instance changed during or after collection")]
    InterfaceChanged,
    /// A discovered candidate is not administratively up.
    #[error("candidate interface is not ready")]
    InterfaceNotReady,
    /// Process ID, birth or loaded-image fields are missing/malformed.
    #[error("invalid process-instance observation")]
    InvalidProcessObservation,
    /// Process birth/UID/core/content changed during or after collection.
    #[error("proxy process instance changed")]
    ProcessChanged,
    /// Observed core/content do not match the explicit software selection.
    #[error("observed core or running-image content was not selected")]
    SoftwareNotSelected,
    /// A name, route or manual assertion was supplied instead of direct ownership.
    #[error("ownership requires direct FD evidence")]
    IndirectOwnership,
    /// Control metadata is missing or not a coherent direct utun association.
    #[error("invalid direct utun control-socket association")]
    InvalidControlSocket,
    /// FD/socket/PCB association changed between collection samples.
    #[error("control-socket instance changed during collection")]
    ControlSocketChanged,
    /// Confirmation selected another exact evidence target.
    #[error("confirmation does not select this evidence target")]
    ConfirmationMismatch,
}

#[derive(Debug, Eq, PartialEq)]
struct CheckedEvidence {
    stamp: SnapshotStamp,
    collection_sequence: u64,
    interface: InterfaceObservation,
    process: ProcessObservation,
    socket: ControlSocketObservation,
    window: ObservationWindow,
}

/// Internally consistent platform report, awaiting a separate explicit selection action.
///
/// Its private fields cannot be filled directly. Like all results here, it remains conditional
/// on the caller's trusted platform collection; it does not authenticate report truth itself.
#[derive(Debug, Eq, PartialEq)]
pub struct CorrelatedBinding {
    evidence: CheckedEvidence,
}

/// One selection intent bound to exact already-correlated evidence, not an ownership claim.
///
/// The service must separately authorize the user action that creates this value. This token
/// cannot turn name-only, unavailable or ambiguous evidence into a verified association.
#[derive(Debug, Eq, PartialEq)]
pub struct UserConfirmation {
    stamp: SnapshotStamp,
    collection_sequence: u64,
    interface: InterfaceObservation,
    process: ProcessObservation,
    socket: ControlSocketObservation,
    window: ObservationWindow,
}

/// Selected correlation at a particular snapshot/window; **not** PF enforcement authority.
///
/// Before use, the owner must revalidate against current trusted platform observations or
/// invalidate on lost evidence, observer interruption or core changes. No Clone, Default or
/// Deserialize implementation permits blindly persisting/reusing a successful result.
///
/// Private fields cannot be used to bypass verification:
/// ```compile_fail
/// use tunlatch_core::binding::VerifiedCurrentBinding;
/// fn bypass(binding: VerifiedCurrentBinding) {
///     let _ = binding.evidence;
/// }
/// ```
/// A default cannot manufacture a verified binding:
/// ```compile_fail
/// use tunlatch_core::binding::VerifiedCurrentBinding;
/// let _: VerifiedCurrentBinding = Default::default();
/// ```
/// Client JSON cannot deserialize one:
/// ```compile_fail
/// use tunlatch_core::binding::VerifiedCurrentBinding;
/// fn require_deserialize<T: for<'de> serde::Deserialize<'de>>() {}
/// require_deserialize::<VerifiedCurrentBinding>();
/// ```
#[derive(Debug, Eq, PartialEq)]
pub struct VerifiedCurrentBinding {
    evidence: CheckedEvidence,
}

/// Explicit causes for discarding correlation and requiring new evidence/confirmation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BindingInvalidation {
    /// The observer stopped, restarted, slept or lost notification continuity.
    ObserverInterrupted,
    /// Ownership facts are no longer readable or complete.
    OwnershipEvidenceLost,
    /// Software/core changed and requires a new selection and report.
    CoreOrContentChanged,
    /// A caller explicitly requires a fresh confirmation.
    ReconfirmationRequired,
    /// A current snapshot/process/time check rejected the saved correlation.
    CurrentCheckFailed(BindingError),
}

/// Diagnostic remainder after consuming a binding; it carries no trusted capability.
#[derive(Debug, Eq, PartialEq)]
pub struct InvalidatedBinding {
    previous_stamp: SnapshotStamp,
    observation_id: u64,
    reason: BindingInvalidation,
}

/// Reserved, presently uninhabited kernel-enforcement qualification.
///
/// W12/W15 must establish continuous interface-instance isolation and lifecycle contracts
/// before a future implementation can provide a reviewed constructor.
/// Correlation, a public boolean or manual selection cannot produce this value today.
///
/// ```compile_fail
/// use tunlatch_core::binding::{EnforcementQualifiedBinding, VerifiedCurrentBinding};
/// fn qualify(binding: VerifiedCurrentBinding) -> EnforcementQualifiedBinding {
///     EnforcementQualifiedBinding { binding, _qualification: () }
/// }
/// ```
#[derive(Debug)]
pub struct EnforcementQualifiedBinding {
    binding: VerifiedCurrentBinding,
    _qualification: Infallible,
}

impl CandidateSnapshot {
    /// Check discovery metadata without granting trust. Timestamps use one monotonic epoch.
    pub fn new(
        stamp: SnapshotStamp,
        observed_at: u64,
        completeness: SnapshotCompleteness,
        mut candidates: Vec<InterfaceObservation>,
    ) -> Result<Self, BindingError> {
        if stamp.observer_epoch == [0; 16] || stamp.generation == 0 {
            return Err(BindingError::InvalidSnapshotStamp);
        }
        if candidates.len() > MAX_TUN_CANDIDATES {
            return Err(BindingError::TooManyCandidates);
        }
        for candidate in &mut candidates {
            normalize_candidate(candidate)?;
        }
        for (position, candidate) in candidates.iter().enumerate() {
            if candidates.iter().skip(position + 1).any(|other| {
                candidate.observation_id == other.observation_id
                    || candidate.interface.name == other.interface.name
                    || candidate.interface.index == other.interface.index
            }) {
                return Err(BindingError::DuplicateCandidate);
            }
        }
        Ok(Self {
            stamp,
            observed_at,
            completeness,
            candidates,
        })
    }

    /// Return the observer-local stamp; it is not an OS interface identity.
    pub fn stamp(&self) -> SnapshotStamp {
        self.stamp
    }

    /// Return immutable discovery observations, including unready or IPv6-only candidates.
    pub fn candidates(&self) -> &[InterfaceObservation] {
        &self.candidates
    }
}

impl ProxySelection {
    /// Record a software-content choice. This does not prove provenance or authorization.
    pub fn new(core: ProxyCore, image_sha256: [u8; 32]) -> Result<Self, BindingError> {
        if core == ProxyCore::Unknown || image_sha256 == [0; 32] {
            return Err(BindingError::InvalidSoftwareSelection);
        }
        Ok(Self { core, image_sha256 })
    }
}

impl CorrelatedBinding {
    /// Check one complete report against selected software and a coherent discovery snapshot.
    ///
    /// The caller must provide its trusted collector's report, never self-reported client
    /// data. This pure function can detect inconsistency but cannot detect a complete lie.
    pub fn verify_report(
        snapshot: &CandidateSnapshot,
        selection: &ProxySelection,
        report: UntrustedOwnershipReport,
        now: u64,
    ) -> Result<Self, BindingError> {
        if snapshot.completeness != SnapshotCompleteness::Complete {
            return Err(BindingError::SnapshotIncomplete);
        }
        match report.completeness {
            ReportCompleteness::Unavailable => return Err(BindingError::EvidenceUnavailable),
            ReportCompleteness::Partial => return Err(BindingError::PartialEvidence),
            ReportCompleteness::Complete => {}
        }
        if report.collection_sequence == 0 {
            return Err(BindingError::InvalidCollectionSequence);
        }
        match report.matches.len() {
            0 => return Err(BindingError::NoOwnershipMatch),
            1 => {}
            _ => return Err(BindingError::AmbiguousOwnership),
        }
        check_window(snapshot, report.window, now)?;
        let pair = report
            .matches
            .into_iter()
            .next()
            .ok_or(BindingError::NoOwnershipMatch)?;
        let mut before = pair.before;
        let mut after = pair.after;
        if before.snapshot != snapshot.stamp || after.snapshot != snapshot.stamp {
            return Err(BindingError::SnapshotChanged);
        }
        normalize_candidate(&mut before.interface)?;
        normalize_candidate(&mut after.interface)?;
        if before.interface != after.interface {
            return Err(BindingError::InterfaceChanged);
        }
        let candidate = snapshot
            .candidates
            .iter()
            .find(|candidate| candidate.observation_id == after.interface.observation_id)
            .ok_or(BindingError::InterfaceChanged)?;
        if candidate != &after.interface {
            return Err(BindingError::InterfaceChanged);
        }
        if !candidate.interface.up {
            return Err(BindingError::InterfaceNotReady);
        }
        check_process(&before.process)?;
        check_process(&after.process)?;
        if before.process != after.process {
            return Err(BindingError::ProcessChanged);
        }
        if after.process.core != selection.core
            || after.process.loaded_image_sha256 != selection.image_sha256
        {
            return Err(BindingError::SoftwareNotSelected);
        }
        check_socket(&before.socket, candidate)?;
        check_socket(&after.socket, candidate)?;
        if before.socket != after.socket {
            return Err(BindingError::ControlSocketChanged);
        }
        Ok(Self {
            evidence: CheckedEvidence {
                stamp: snapshot.stamp,
                collection_sequence: report.collection_sequence,
                interface: after.interface,
                process: after.process,
                socket: after.socket,
                window: report.window,
            },
        })
    }

    /// Record an explicit selection of these exact checked facts, not an ownership assertion.
    ///
    /// This must be called only after the service has authorized the user action. Keeping the
    /// token separate prevents a previous selection from confirming new evidence by accident.
    pub fn confirmation_intent(&self) -> UserConfirmation {
        UserConfirmation {
            stamp: self.evidence.stamp,
            collection_sequence: self.evidence.collection_sequence,
            interface: self.evidence.interface.clone(),
            process: self.evidence.process.clone(),
            socket: self.evidence.socket.clone(),
            window: self.evidence.window,
        }
    }

    /// Consume selection and a freshly collected, independently checked direct report.
    ///
    /// `current` must come from the trusted collector's new collection for this action, not
    /// client data or a cached report. Its collector sequence must advance, including when
    /// timestamps are equal. The model detects replayed counters, but cannot authenticate a
    /// fabricated counter: only the trusted collector may allocate them for real collections.
    /// Direct FD/socket/PCB facts must still match; a process-only recheck is insufficient.
    pub fn confirm(
        self,
        confirmation: UserConfirmation,
        current: CorrelatedBinding,
        now: u64,
    ) -> Result<VerifiedCurrentBinding, BindingError> {
        let target = self.confirmation_intent();
        if target != confirmation {
            return Err(BindingError::ConfirmationMismatch);
        }
        check_current(&self.evidence, &current.evidence, now)?;
        Ok(VerifiedCurrentBinding {
            evidence: current.evidence,
        })
    }
}

impl VerifiedCurrentBinding {
    pub(crate) fn request_identity(&self) -> impl Serialize + '_ {
        (
            &self.evidence.stamp,
            &self.evidence.interface,
            &self.evidence.process,
            &self.evidence.socket,
        )
    }

    /// Return the last checked collection counter, scoped to the observer epoch.
    pub fn collection_sequence(&self) -> u64 {
        self.evidence.collection_sequence
    }

    /// Return sampled interface metadata for diagnostics, never as a PF authorization token.
    pub fn interface(&self) -> &InterfaceObservation {
        &self.evidence.interface
    }

    /// Return the sampled process facts; these are not a new live process query.
    pub fn process(&self) -> &ProcessObservation {
        &self.evidence.process
    }

    /// Consume and recheck against a newly collected complete direct ownership correlation.
    ///
    /// Callers must invalidate instead if ownership evidence is lost or observer continuity
    /// is interrupted. `current` must come from the trusted collector's new collection for
    /// this action. This model compares the direct FD/socket/PCB facts as well as the process
    /// and interface; it cannot authenticate a producer or make kernel lifetime guarantees.
    /// An expired old binding requires new confirmation, even if the new report is valid.
    pub fn revalidate(
        self,
        current: CorrelatedBinding,
        now: u64,
    ) -> Result<Self, InvalidatedBinding> {
        match check_current(&self.evidence, &current.evidence, now) {
            Ok(()) => Ok(Self {
                evidence: current.evidence,
            }),
            Err(error) => Err(self.invalidate(BindingInvalidation::CurrentCheckFailed(error))),
        }
    }

    /// Consume correlation when continuity/evidence is lost; the remainder has no capability.
    pub fn invalidate(self, reason: BindingInvalidation) -> InvalidatedBinding {
        InvalidatedBinding {
            previous_stamp: self.evidence.stamp,
            observation_id: self.evidence.interface.observation_id,
            reason,
        }
    }
}

impl InvalidatedBinding {
    /// Return the reason fresh collection and confirmation are required.
    pub fn reason(&self) -> &BindingInvalidation {
        &self.reason
    }

    /// Return the old snapshot locator strictly for diagnostics.
    pub fn previous_stamp(&self) -> SnapshotStamp {
        self.previous_stamp
    }

    /// Return the old observation ID strictly for diagnostics.
    pub fn observation_id(&self) -> u64 {
        self.observation_id
    }
}

impl EnforcementQualifiedBinding {
    /// Borrow the correlation under this reserved qualification. No value exists yet.
    pub fn correlation(&self) -> &VerifiedCurrentBinding {
        &self.binding
    }
}

fn normalize_candidate(candidate: &mut InterfaceObservation) -> Result<(), BindingError> {
    let interface = &mut candidate.interface;
    if candidate.observation_id == 0
        || interface.index == 0
        || interface.loopback
        || interface.name.len() >= 16
        || !interface.is_tun_candidate()
    {
        return Err(BindingError::InvalidCandidate);
    }
    for address in &interface.addresses {
        match address.address {
            std::net::IpAddr::V4(_) if address.scope_id != 0 => {
                return Err(BindingError::InvalidCandidate);
            }
            std::net::IpAddr::V6(ip)
                if ip.is_unicast_link_local() && address.scope_id != interface.index =>
            {
                return Err(BindingError::InvalidCandidate);
            }
            _ => {}
        }
    }
    interface
        .addresses
        .sort_by_key(|address| (address.address, address.scope_id));
    interface.addresses.dedup();
    Ok(())
}

fn check_window(
    snapshot: &CandidateSnapshot,
    window: ObservationWindow,
    now: u64,
) -> Result<(), BindingError> {
    if window.started_at > window.finished_at
        || window.finished_at >= window.valid_until
        || snapshot.observed_at < window.started_at
        || snapshot.observed_at > window.finished_at
    {
        return Err(BindingError::InvalidObservationWindow);
    }
    if now < window.finished_at {
        return Err(BindingError::ObservationNotFinished);
    }
    if now >= window.valid_until {
        return Err(BindingError::EvidenceExpired);
    }
    Ok(())
}

fn check_process(process: &ProcessObservation) -> Result<(), BindingError> {
    if process.pid == 0
        || process.birth_seconds == 0
        || process.birth_microseconds >= 1_000_000
        || process.core == ProxyCore::Unknown
        || process.loaded_image_sha256 == [0; 32]
    {
        return Err(BindingError::InvalidProcessObservation);
    }
    Ok(())
}

fn check_socket(
    socket: &ControlSocketObservation,
    candidate: &InterfaceObservation,
) -> Result<(), BindingError> {
    match socket.method {
        OwnershipMethod::HolderFdQuery | OwnershipMethod::KernelControlInspection => {}
        OwnershipMethod::InterfaceNameOnly
        | OwnershipMethod::RouteInference
        | OwnershipMethod::ManualAssertion => return Err(BindingError::IndirectOwnership),
    }
    let named_unit = candidate
        .interface
        .name
        .strip_prefix("utun")
        .and_then(|number| number.parse::<u32>().ok())
        .and_then(|number| number.checked_add(1));
    if socket.controller_name != "com.apple.net.utun_control"
        || socket.controller_id == 0
        || socket.control_unit == 0
        || socket.opaque_socket == 0
        || socket.opaque_pcb == 0
        || socket.associated_interface_name != candidate.interface.name
        || named_unit != Some(socket.control_unit)
    {
        return Err(BindingError::InvalidControlSocket);
    }
    Ok(())
}

fn check_current(
    evidence: &CheckedEvidence,
    current: &CheckedEvidence,
    now: u64,
) -> Result<(), BindingError> {
    if current.stamp != evidence.stamp {
        return Err(BindingError::SnapshotChanged);
    }
    if current.collection_sequence <= evidence.collection_sequence {
        return Err(BindingError::CollectionSequenceNotAdvanced);
    }
    for window in [evidence.window, current.window] {
        if now < window.finished_at {
            return Err(BindingError::ObservationNotFinished);
        }
        if now >= window.valid_until {
            return Err(BindingError::EvidenceExpired);
        }
    }
    if current.window.started_at < evidence.window.started_at
        || current.window.finished_at < evidence.window.finished_at
    {
        return Err(BindingError::ObservationRegressed);
    }
    if current.interface != evidence.interface {
        return Err(BindingError::InterfaceChanged);
    }
    if current.process != evidence.process {
        return Err(BindingError::ProcessChanged);
    }
    if current.socket != evidence.socket {
        return Err(BindingError::ControlSocketChanged);
    }
    Ok(())
}
