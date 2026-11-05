use std::collections::{BTreeMap, BTreeSet};
use std::convert::Infallible;

use serde::Serialize;
use thiserror::Error;

use super::draft::{AddressFamily, EgressPolicyDraft, ProxyUidGrant, Transport, bytes};
use crate::binding::VerifiedCurrentBinding;
use crate::policy::{
    self, Destination, OrdinaryDecision, PacketDescriptor, PacketProtocol, PolicyDigest,
    PolicyError, PolicyId,
};

pub use crate::binding::ObservationWindow;

const MAX_PROFILE_LIFETIME_MS: u64 = 5_000;
const CONFIRMATION_LIFETIME_MS: u64 = 60_000;
const MAX_SESSION_OPERATIONS: usize = 64;

/// Model failure. It never means that a real administrator or PF transaction was authenticated.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum EgressError {
    /// A candidate failed strict structural or policy validation.
    #[error(transparent)]
    Input(#[from] PolicyError),
    /// Zero/duplicate/out-of-range profile or service metadata.
    #[error("invalid model observation")]
    InvalidObservation,
    /// Missing, expired, regressed or inconsistently replayed collection.
    #[error("fresh consistent platform observations are required")]
    StaleObservation,
    /// A required physical scope is missing or does not cover candidate families.
    #[error("required physical scope is unavailable")]
    ProfileUnavailable,
    /// Confirmation observed a different physical instance or binding selection.
    #[error("the proposed scope or binding has changed")]
    ScopeChanged,
    /// The model has no checked policy yet.
    #[error("no checked policy")]
    NoCheckedPolicy,
    /// One confirmation is already pending.
    #[error("another model confirmation is pending")]
    PendingConfirmation,
    /// No matching one-shot request exists, or its nonce/operation has already been used.
    #[error("missing or replayed model confirmation")]
    Replay,
    /// Caller reported a query channel instead of an administrator channel.
    #[error("administrator observation required")]
    AdministratorRequired,
    /// Deadline/service identity/action or exact request content did not match.
    #[error("confirmation is expired or does not match its request")]
    ConfirmationMismatch,
    /// Policy generation differs or cannot safely advance.
    #[error("policy generation conflict")]
    GenerationConflict,
    /// Bounded replay storage is full; entries are never silently evicted.
    #[error("model session capacity exhausted")]
    SessionCapacity,
}

/// Collector-supplied, untrusted physical-scope metadata. No name/index establishes identity.
#[derive(Clone, Debug)]
pub struct ProfileObservation {
    /// Reference selected by the policy, not an interface name.
    pub profile_id: String,
    /// Content identity of the separately protected scope description.
    pub scope_digest: [u8; 32],
    /// Nonzero approved-scope generation.
    pub scope_generation: u64,
    /// Nonzero attachment identity allocated by a trusted collector.
    pub attachment_epoch: u64,
    /// Actual families covered by this observation.
    pub families: Vec<AddressFamily>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct ProfileIdentity {
    attachment_epoch: u64,
    families: Vec<AddressFamily>,
    profile_id: PolicyId,
    scope_digest: [u8; 32],
    scope_generation: u64,
}

/// Internally consistent bounded observations; this does not authenticate their producer.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ProfileSnapshot {
    observer_epoch: [u8; 16],
    profiles: BTreeMap<PolicyId, ProfileIdentity>,
    sequence: u64,
    window: ObservationWindow,
}

impl ProfileSnapshot {
    /// Validate at most four scopes and an exclusive freshness deadline, in monotonic milliseconds.
    /// The real collector must establish physical identity and use genuinely advancing sequences.
    pub fn new(
        observer_epoch: [u8; 16],
        sequence: u64,
        window: ObservationWindow,
        observations: Vec<ProfileObservation>,
        now_ms: u64,
    ) -> Result<Self, EgressError> {
        if observer_epoch == [0; 16] || sequence == 0 || observations.len() > 4 {
            return Err(EgressError::InvalidObservation);
        }
        check_window(&window, now_ms)?;
        let mut profiles = BTreeMap::new();
        for mut observation in observations {
            if observation.scope_generation == 0
                || observation.attachment_epoch == 0
                || observation.scope_digest == [0; 32]
                || observation.families.is_empty()
                || observation.families.len() > 2
            {
                return Err(EgressError::InvalidObservation);
            }
            observation.families.sort();
            if observation.families.windows(2).any(|a| a[0] == a[1]) {
                return Err(EgressError::InvalidObservation);
            }
            let id = PolicyId::from_value(
                &serde_json::Value::String(observation.profile_id),
                "profile.id",
            )?;
            let value = ProfileIdentity {
                attachment_epoch: observation.attachment_epoch,
                families: observation.families,
                profile_id: id.clone(),
                scope_digest: observation.scope_digest,
                scope_generation: observation.scope_generation,
            };
            if profiles.insert(id, value).is_some() {
                return Err(EgressError::InvalidObservation);
            }
        }
        Ok(Self {
            observer_epoch,
            profiles,
            sequence,
            window,
        })
    }
    /// Collector sequence, scoped to its observer epoch, not a privilege or kernel identifier.
    pub fn sequence(&self) -> u64 {
        self.sequence
    }
    fn fingerprint(&self) -> Result<PolicyDigest, EgressError> {
        Ok(policy::digest(
            b"tunlatch-profile-observation\0",
            &bytes(self)?,
        ))
    }
    fn profile(&self, id: &str) -> Option<&ProfileIdentity> {
        self.profiles.values().find(|p| p.profile_id.as_str() == id)
    }
}

fn check_window(window: &ObservationWindow, now: u64) -> Result<(), EgressError> {
    if window.started_at > window.finished_at
        || window.finished_at > now
        || now >= window.valid_until
        || window.valid_until.saturating_sub(window.started_at) > MAX_PROFILE_LIFETIME_MS
    {
        return Err(EgressError::StaleObservation);
    }
    Ok(())
}

/// Binding-selection content, not live TUN qualification. Collection timestamps are not identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BindingSelection(Option<PolicyDigest>);

impl BindingSelection {
    /// No selected TUN; an independently valid UID scope may still be eligible.
    pub fn unavailable() -> Self {
        Self(None)
    }
    /// Bind checked process/interface/direct-FD identity, never a client-provided fingerprint.
    /// Even this checked correlation cannot authorize TUN traffic or authenticate a collector.
    pub fn from_checked(binding: &VerifiedCurrentBinding) -> Result<Self, EgressError> {
        let value = serde_json::to_value(binding.request_identity())
            .map_err(|_| EgressError::InvalidObservation)?;
        Ok(Self(Some(policy::digest(
            b"tunlatch-binding-selection\0",
            &bytes(&value)?,
        ))))
    }
}

/// Reported channel, not proof of OS peer credentials. Never deserialize this from a client.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApprovalChannel {
    /// Ordinary query observations cannot confirm a model mutation.
    Query,
    /// The trusted owner reports its administrator path. Real authentication is outside core.
    Administrator,
}

/// Untrusted administrator-path observations checked against one private pending request.
/// These fields are data, not an approval token; a completely fabricated truthful-looking
/// observation cannot be authenticated by a pure core model.
#[derive(Clone, Debug)]
pub struct AdminObservation {
    /// Reported privileged channel; no proxy/socket UID can substitute for it.
    pub channel: ApprovalChannel,
    /// Claimed service session.
    pub service_epoch: [u8; 16],
    /// Claimed operation identifier.
    pub operation_id: [u8; 16],
    /// Claimed one-shot nonce from the preview.
    pub nonce: [u8; 32],
    /// Exact preview content identity.
    pub request_digest: [u8; 32],
    /// Current model generation expected by the request.
    pub expected_generation: u64,
    /// Exact requested action; only replace_policy is accepted by this checker.
    pub action: String,
    /// Exact exclusive preview deadline, not a client-extensible lifetime.
    pub expires_at_ms: u64,
}

/// Read-only proposed action. It does not contain OS administrator or PF authority.
#[derive(Clone, Debug)]
pub struct ApprovalPreview {
    service_epoch: [u8; 16],
    operation_id: [u8; 16],
    nonce: [u8; 32],
    request_digest: PolicyDigest,
    expected_generation: u64,
    expires_at_ms: u64,
}
impl ApprovalPreview {
    /// Owning model session.
    pub fn service_epoch(&self) -> [u8; 16] {
        self.service_epoch
    }
    /// Exact operation ID.
    pub fn operation_id(&self) -> [u8; 16] {
        self.operation_id
    }
    /// One-shot nonce, generated by the trusted caller, not by this pure library.
    pub fn nonce(&self) -> [u8; 32] {
        self.nonce
    }
    /// Exact policy/scope/selection identity to confirm.
    pub fn request_digest(&self) -> PolicyDigest {
        self.request_digest
    }
    /// Expected generation prior to replacing model data.
    pub fn expected_generation(&self) -> u64 {
        self.expected_generation
    }
    /// Exclusive monotonic deadline in milliseconds.
    pub fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
    }
}

/// Checked model state. Private fields, Default and Deserialize cannot manufacture one.
/// It is still not an administrator credential or a PF enforcement policy.
///
/// ```compile_fail
/// use tunlatch_core::egress::CheckedPolicy;
/// let _: CheckedPolicy = Default::default();
/// ```
/// ```compile_fail
/// use tunlatch_core::egress::CheckedPolicy;
/// fn deserialize<T: for<'a> serde::Deserialize<'a>>() {}
/// deserialize::<CheckedPolicy>();
/// ```
/// ```compile_fail
/// use tunlatch_core::egress::CheckedPolicy;
/// fn overwrite(policy: &mut CheckedPolicy) { policy.generation = 0; }
/// ```
#[derive(Debug)]
pub struct CheckedPolicy {
    draft: EgressPolicyDraft,
    profiles: BTreeMap<PolicyId, ProfileIdentity>,
    binding: BindingSelection,
    generation: u64,
}
impl CheckedPolicy {
    /// Borrow candidate policy data; no mutable grant or live capability is exposed.
    pub fn draft(&self) -> &EgressPolicyDraft {
        &self.draft
    }
    /// Model generation, not proof of a committed kernel rule set.
    pub fn generation(&self) -> u64 {
        self.generation
    }
    /// Selected correlation reference, never PF qualification.
    pub fn binding(&self) -> BindingSelection {
        self.binding
    }
}

/// Reserved real execution capability; no value can be constructed until the platform boundary
/// has been implemented and reviewed. A model match or checked record cannot become this type.
///
/// ```compile_fail
/// use tunlatch_core::egress::{CheckedPolicy, EnforcementAuthorization};
/// fn promote(policy: CheckedPolicy) -> EnforcementAuthorization { policy.into() }
/// ```
/// ```compile_fail
/// use tunlatch_core::egress::EnforcementAuthorization;
/// let _ = EnforcementAuthorization { _platform: () };
/// ```
#[derive(Debug)]
pub struct EnforcementAuthorization {
    _platform: Infallible,
}

struct Pending {
    preview: ApprovalPreview,
    draft: EgressPolicyDraft,
    profiles: BTreeMap<PolicyId, ProfileIdentity>,
    binding: BindingSelection,
    observer_epoch: [u8; 16],
    sequence: u64,
}
struct Cursor {
    observer_epoch: [u8; 16],
    sequence: u64,
    window: ObservationWindow,
    digest: PolicyDigest,
}

/// One bounded model owner. It is deliberately neither Clone, Default nor Deserialize.
/// It checks reported administrative facts only; real peer authentication, nonce randomness,
/// crash persistence and PF qualification remain the trusted service's separate responsibilities.
pub struct EgressModel {
    service_epoch: [u8; 16],
    generation: u64,
    last_tick: Option<u64>,
    cursor: Option<Cursor>,
    pending: Option<Pending>,
    operations: BTreeSet<[u8; 16]>,
    nonces: BTreeSet<[u8; 32]>,
    current: Option<CheckedPolicy>,
}

impl EgressModel {
    /// Create an empty model; session identity must come from its trusted owner, not IPC.
    pub fn new(service_epoch: [u8; 16], generation: u64) -> Result<Self, EgressError> {
        if service_epoch == [0; 16] || generation == 0 {
            return Err(EgressError::InvalidObservation);
        }
        Ok(Self {
            service_epoch,
            generation,
            last_tick: None,
            cursor: None,
            pending: None,
            operations: BTreeSet::new(),
            nonces: BTreeSet::new(),
            current: None,
        })
    }
    /// Inspect checked data without exposing a mutable record or execution token.
    pub fn checked_policy(&self) -> Option<&CheckedPolicy> {
        self.current.as_ref()
    }
    /// Current model generation; rejected confirmations do not advance it.
    pub fn generation(&self) -> u64 {
        self.generation
    }
    /// Cancel only the pending preview. This never removes the last checked policy or protection.
    /// Its nonce/operation stay retired for this model session.
    pub fn cancel_preview(&mut self) {
        self.pending = None;
    }

    /// Prepare one exact confirmation using fresh observations. No privileged action occurs.
    /// Nonce/operation must be nonzero, fresh and generated outside this pure model by its owner.
    pub fn prepare(
        &mut self,
        draft: EgressPolicyDraft,
        profiles: &ProfileSnapshot,
        binding: BindingSelection,
        operation_id: [u8; 16],
        nonce: [u8; 32],
        now_ms: u64,
    ) -> Result<ApprovalPreview, EgressError> {
        if self.pending.is_some() {
            return Err(EgressError::PendingConfirmation);
        }
        if operation_id == [0; 16] || nonce == [0; 32] {
            return Err(EgressError::InvalidObservation);
        }
        if self.operations.contains(&operation_id) || self.nonces.contains(&nonce) {
            return Err(EgressError::Replay);
        }
        if self.operations.len() == MAX_SESSION_OPERATIONS {
            return Err(EgressError::SessionCapacity);
        }
        self.observe(profiles, now_ms)?;
        let selected = select_profiles(&draft, profiles)?;
        let request_digest = request_digest(&draft, &selected, binding, self.generation)?;
        let expires_at_ms = now_ms
            .checked_add(CONFIRMATION_LIFETIME_MS)
            .ok_or(EgressError::InvalidObservation)?;
        let preview = ApprovalPreview {
            service_epoch: self.service_epoch,
            operation_id,
            nonce,
            request_digest,
            expected_generation: self.generation,
            expires_at_ms,
        };
        self.operations.insert(operation_id);
        self.nonces.insert(nonce);
        self.pending = Some(Pending {
            preview: preview.clone(),
            draft,
            profiles: selected,
            binding,
            observer_epoch: profiles.observer_epoch,
            sequence: profiles.sequence,
        });
        Ok(preview)
    }

    /// Consume one model confirmation. Caller-reported admin data is not OS authentication.
    /// Any rejected attempt discards that preview and preserves the previous checked policy.
    pub fn confirm_model(
        &mut self,
        observation: AdminObservation,
        profiles: &ProfileSnapshot,
        binding: BindingSelection,
        now_ms: u64,
    ) -> Result<(), EgressError> {
        let pending = self.pending.take().ok_or(EgressError::Replay)?;
        let p = &pending.preview;
        if observation.channel != ApprovalChannel::Administrator {
            return Err(EgressError::AdministratorRequired);
        }
        if observation.expected_generation != self.generation
            || p.expected_generation != self.generation
        {
            return Err(EgressError::GenerationConflict);
        }
        if observation.service_epoch != p.service_epoch
            || observation.operation_id != p.operation_id
            || observation.nonce != p.nonce
            || observation.request_digest != *p.request_digest.as_bytes()
            || observation.action != "replace_policy"
            || observation.action.len() > 32
            || observation.expires_at_ms != p.expires_at_ms
            || now_ms >= p.expires_at_ms
        {
            return Err(EgressError::ConfirmationMismatch);
        }
        self.observe(profiles, now_ms)?;
        if profiles.observer_epoch != pending.observer_epoch
            || profiles.sequence <= pending.sequence
        {
            return Err(EgressError::StaleObservation);
        }
        let selected = select_profiles(&pending.draft, profiles)?;
        if selected != pending.profiles || binding != pending.binding {
            return Err(EgressError::ScopeChanged);
        }
        if request_digest(&pending.draft, &selected, binding, self.generation)? != p.request_digest
        {
            return Err(EgressError::ConfirmationMismatch);
        }
        let generation = self
            .generation
            .checked_add(1)
            .ok_or(EgressError::GenerationConflict)?;
        self.current = Some(CheckedPolicy {
            draft: pending.draft,
            profiles: selected,
            binding,
            generation,
        });
        self.generation = generation;
        Ok(())
    }

    /// Evaluate the ordinary-rule and UID branch for a non-loopback outbound packet.
    /// The outer boundary must separately handle direction/real loopback and any qualified
    /// TUN/system/target exception. `NeedsOtherAuthorization` is not a packet allow or block.
    /// Fresh observations may be reused within their deadline, never with regressed/replayed data.
    pub fn evaluate_uid<'a>(
        &'a mut self,
        packet: Option<&PacketDescriptor>,
        location: EgressLocation<'_>,
        owner: SocketOwner,
        profiles: &ProfileSnapshot,
        now_ms: u64,
    ) -> Result<UidDecision<'a>, EgressError> {
        let current = self.current.as_ref().ok_or(EgressError::NoCheckedPolicy)?;
        match current.draft.config().ordinary_decision(packet) {
            OrdinaryDecision::Unmanaged => return Ok(UidDecision::Unmanaged),
            OrdinaryDecision::Block { .. } => {
                // Borrow again after the potential observation mutation below is avoided.
                return Ok(UidDecision::BlockedByOrdinaryRule);
            }
            OrdinaryDecision::NeedsEgressAuthorization { .. } => {}
        }
        let (
            Some(packet),
            EgressLocation::Physical {
                profile_id,
                attachment_epoch,
            },
        ) = (packet, location)
        else {
            return Ok(UidDecision::NeedsOtherAuthorization);
        };
        if packet.destination().is_loopback() {
            return Ok(UidDecision::BlockedByOrdinaryRule);
        }
        let transport = match packet.protocol() {
            PacketProtocol::Tcp { .. } => Transport::Tcp,
            PacketProtocol::Udp { .. } => Transport::Udp,
            _ => return Ok(UidDecision::NeedsOtherAuthorization),
        };
        let SocketOwner::Known(uid) = owner else {
            return Ok(UidDecision::NeedsOtherAuthorization);
        };
        self.observe(profiles, now_ms)?;
        let current = self.current.as_ref().ok_or(EgressError::NoCheckedPolicy)?;
        let Some(expected) = current
            .profiles
            .values()
            .find(|p| p.profile_id.as_str() == profile_id)
        else {
            return Ok(UidDecision::NeedsOtherAuthorization);
        };
        let Some(actual) = profiles.profile(profile_id) else {
            return Err(EgressError::ProfileUnavailable);
        };
        if actual != expected || actual.attachment_epoch != attachment_epoch {
            return Err(EgressError::ScopeChanged);
        }
        let family = if packet.destination().is_ipv4() {
            AddressFamily::Ipv4
        } else {
            AddressFamily::Ipv6
        };
        for grant in current.draft.authorizations().proxy_uid_grants() {
            if grant.egress_profile().as_str() == profile_id
                && grant.uid() == uid
                && grant.protocols().contains(&transport)
                && grant.families().contains(&family)
            {
                return Ok(UidDecision::Eligible(UidRequirement {
                    grant,
                    generation: current.generation,
                    attachment_epoch,
                    valid_until_ms: profiles.window.valid_until,
                }));
            }
        }
        Ok(UidDecision::NeedsOtherAuthorization)
    }

    fn observe(&mut self, profiles: &ProfileSnapshot, now: u64) -> Result<(), EgressError> {
        check_window(&profiles.window, now)?;
        if self.last_tick.is_some_and(|last| now < last) {
            return Err(EgressError::StaleObservation);
        }
        let digest = profiles.fingerprint()?;
        if let Some(cursor) = &self.cursor
            && (profiles.observer_epoch != cursor.observer_epoch
                || profiles.sequence < cursor.sequence
                || profiles.window.started_at < cursor.window.started_at
                || profiles.window.finished_at < cursor.window.finished_at
                || profiles.sequence == cursor.sequence && digest != cursor.digest)
        {
            return Err(EgressError::StaleObservation);
        }
        self.cursor = Some(Cursor {
            observer_epoch: profiles.observer_epoch,
            sequence: profiles.sequence,
            window: profiles.window,
            digest,
        });
        self.last_tick = Some(now);
        Ok(())
    }
}

fn select_profiles(
    draft: &EgressPolicyDraft,
    snapshot: &ProfileSnapshot,
) -> Result<BTreeMap<PolicyId, ProfileIdentity>, EgressError> {
    let mut selected = BTreeMap::new();
    for id in draft.profile_ids() {
        let p = snapshot
            .profile(id)
            .ok_or(EgressError::ProfileUnavailable)?;
        selected.insert(p.profile_id.clone(), p.clone());
    }
    for item in draft.authorizations().proxy_uid_grants() {
        let p = snapshot
            .profile(item.egress_profile().as_str())
            .ok_or(EgressError::ProfileUnavailable)?;
        if item.families().iter().any(|f| !p.families.contains(f)) {
            return Err(EgressError::ProfileUnavailable);
        }
    }
    for item in draft.authorizations().system_profiles() {
        let p = snapshot
            .profile(item.egress_profile().as_str())
            .ok_or(EgressError::ProfileUnavailable)?;
        if item.families().iter().any(|f| !p.families.contains(f)) {
            return Err(EgressError::ProfileUnavailable);
        }
    }
    for item in draft.config().direct_exceptions() {
        let family = match item.destination() {
            Destination::Network(network) if network.addr().is_ipv4() => AddressFamily::Ipv4,
            Destination::Network(_) => AddressFamily::Ipv6,
            Destination::Any => return Err(EgressError::ProfileUnavailable),
        };
        let p = snapshot
            .profile(item.egress_profile().as_str())
            .ok_or(EgressError::ProfileUnavailable)?;
        if !p.families.contains(&family) {
            return Err(EgressError::ProfileUnavailable);
        }
    }
    Ok(selected)
}

fn request_digest(
    draft: &EgressPolicyDraft,
    profiles: &BTreeMap<PolicyId, ProfileIdentity>,
    binding: BindingSelection,
    generation: u64,
) -> Result<PolicyDigest, EgressError> {
    // BTreeMap and Value order recursive keys; no client-controlled paths, fields or PF text.
    let profile_values = profiles.values().collect::<Vec<_>>();
    let value = serde_json::json!({
        "authorization_digest": draft.authorizations().digest().to_string(),
        "binding_selection": binding.0.map(|v| v.to_string()),
        "config_digest": draft.config().digest().to_string(),
        "expected_generation": generation,
        "profiles": profile_values,
    });
    Ok(policy::digest(
        b"tunlatch-policy-request\0",
        &bytes(&value)?,
    ))
}

/// A reported local socket owner; Unknown is never converted to zero.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SocketOwner {
    /// Numeric kernel socket-creation UID, not the current process UID.
    Known(u32),
    /// No local owner, failed lookup or a forwarded connection.
    Unknown,
}

/// Claimed location for the UID branch only. The collector must establish truthful identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EgressLocation<'a> {
    /// A specific physical-scope reference and current attachment identity.
    Physical {
        /// Protected-scope ID, not a name/route-derived trust assertion.
        profile_id: &'a str,
        /// Collector instance identity; zero/mismatch cannot match a current scope.
        attachment_epoch: u64,
    },
    /// TUN, loopback, another interface, or unresolved egress: no UID physical permission.
    Other,
}

/// Conditional result. There is no unconditional Allow or actual protected-state variant.
#[derive(Debug)]
pub enum UidDecision<'a> {
    /// Configuration intent is disabled, not a PF disable action.
    Unmanaged,
    /// An ordinary rule or incomplete/off-loopback-loopback packet forbids the UID branch.
    BlockedByOrdinaryRule,
    /// No UID match; independently verify the TUN/system/target boundary before any use.
    NeedsOtherAuthorization,
    /// Required UID conditions match this checked model, still awaiting real enforcement proof.
    Eligible(UidRequirement<'a>),
}

/// Borrowed model requirement, not a transferable grant or packet permit.
/// Borrowing prevents replacing this model's policy while the requirement is in use.
#[derive(Debug)]
pub struct UidRequirement<'a> {
    grant: &'a ProxyUidGrant,
    generation: u64,
    attachment_epoch: u64,
    valid_until_ms: u64,
}
impl UidRequirement<'_> {
    /// The exact candidate whose conditions matched.
    pub fn grant(&self) -> &ProxyUidGrant {
        self.grant
    }
    /// Checked model generation, not a kernel generation.
    pub fn generation(&self) -> u64 {
        self.generation
    }
    /// Exact physical attachment required by this model result.
    pub fn attachment_epoch(&self) -> u64 {
        self.attachment_epoch
    }
    /// Exclusive profile-observation deadline; this object cannot stop time from expiring.
    pub fn valid_until_ms(&self) -> u64 {
        self.valid_until_ms
    }
}
