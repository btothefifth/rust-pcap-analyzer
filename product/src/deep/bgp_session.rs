//! Offline observations of a caller-scoped BGP exchange. This is not a speaker FSM.
//! Absence of a message, elapsed time, and peer labels never establish a transition.
use super::bgp_import::ImportContext;
use super::model::{bad, Limits};
use pcap_evidence::{sha256, Error, Result};
use std::collections::BTreeSet;

pub const SCHEMA: &str = "pcap-evidence.bgp.session-observer.v1";

/// The partition is an immutable capture identity or import batch/checkpoint
/// identity supplied by the caller. A name or timestamp alone is insufficient.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct SourcePartition {
    pub kind: PartitionKind,
    pub source_id: String,
    pub partition_id: String,
}
impl SourcePartition {
    /// Exact existing import batch/checkpoint namespace. The context is
    /// validated, but its labels are still caller-supplied evidence.
    pub fn from_import_context(context: &ImportContext, limits: &Limits) -> Result<Self> {
        context.validate(limits)?;
        let partition = context
            .partition()
            .json()
            .encode_bounded(limits.input_bytes)?;
        Ok(Self {
            kind: PartitionKind::Imported,
            source_id: context.source_id.clone(),
            partition_id: format!(
                "import-context-v1:{}",
                sha256::hex(&sha256::digest(partition.as_bytes()))
            ),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum PartitionKind {
    Captured,
    Imported,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct SessionKey {
    pub source: SourcePartition,
    pub session: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Family {
    pub afi: u16,
    pub safi: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StaleKind {
    Graceful,
    LongLivedGraceful,
}

/// A reset proved by a decoded BGP message rather than asserted from transport
/// metadata. The journal retains the original message record as the boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtocolResetKind {
    Notification,
    UpdateError,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Capability {
    pub code: u8,
    /// Identity of exact advertised value bytes, not a trust or negotiation proof.
    pub value_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenAdvertisement {
    pub capabilities: Vec<Capability>,
    /// Set by a syntax/semantic producer when duplicate or malformed occurrences
    /// prevent a unique capability interpretation.
    pub ambiguous: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EventKind {
    Open(OpenAdvertisement),
    Keepalive,
    Update,
    Notification,
    /// A decoded message that both terminates the current observed generation
    /// and establishes its exact successor in the captured decoder state.
    ProtocolReset {
        next_generation: u64,
        kind: ProtocolResetKind,
    },
    RouteRefresh {
        family: Family,
        subtype: Option<u8>,
    },
    EndOfRib(Family),
    Stale {
        family: Family,
        kind: StaleKind,
    },
    Gap {
        reason: String,
    },
    Reset {
        previous_generation: u64,
        reason: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Event {
    pub session: SessionKey,
    pub generation: u64,
    pub direction: Option<u8>,
    pub record_id: String,
    pub kind: EventKind,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenAlternative {
    pub advertisement: OpenAdvertisement,
    pub witnesses: Vec<String>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DirectionView {
    pub opens: Vec<OpenAlternative>,
    pub keepalives: Vec<String>,
    pub updates: Vec<String>,
    pub notifications: Vec<String>,
    pub refreshes: Vec<(Family, Option<u8>, String)>,
    pub eors: Vec<(Family, String)>,
    pub stale: Vec<(Family, StaleKind, String)>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CapabilityContext {
    Unresolved(&'static str),
    /// Intersection of unambiguous bilateral advertisements. This remains an
    /// observed candidate context, never endpoint negotiation or active state.
    BilateralCandidate {
        common_codes: Vec<u8>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionView {
    pub generation: u64,
    pub directions: [DirectionView; 2],
    pub context: CapabilityContext,
    pub gaps: Vec<String>,
    /// Record IDs with no trusted direction. Their details stay in `events`.
    pub unscoped: Vec<String>,
    pub unscoped_open: bool,
    pub resets: Vec<String>,
    pub closed_by_notification: bool,
    pub identity_conflict: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApplyStatus {
    Applied,
    IdenticalReplay,
    Historical,
    Closed,
    IdentityConflict,
}

#[derive(Clone, Debug)]
pub struct SessionObserver {
    key: SessionKey,
    limits: Limits,
    events: Vec<Event>,
    view: Option<SessionView>,
}

impl SessionObserver {
    pub fn new(key: SessionKey, limits: Limits) -> Result<Self> {
        limits.validate()?;
        check_text(&key.source.source_id, &limits)?;
        check_text(&key.source.partition_id, &limits)?;
        check_text(&key.session, &limits)?;
        Ok(Self {
            key,
            limits,
            events: Vec::new(),
            view: None,
        })
    }
    pub fn key(&self) -> &SessionKey {
        &self.key
    }
    pub fn events(&self) -> &[Event] {
        &self.events
    }
    pub fn view(&self) -> Option<&SessionView> {
        self.view.as_ref()
    }
    /// Logical retention measure, including the complete journal and projection.
    pub fn retained_bytes(&self) -> usize {
        self.accounted_size()
    }
    pub fn accounted_work(&self) -> usize {
        self.accounted_size().saturating_mul(2)
    }
    fn accounted_size(&self) -> usize {
        format!("{:?}{:?}", self.events, self.view).len()
    }
    pub fn apply(&mut self, event: Event) -> Result<ApplyStatus> {
        if event.session != self.key {
            return Err(bad("bgp_session_scope", 0, "session identity changed"));
        }
        check_text(&event.record_id, &self.limits)?;
        if event.direction.is_some_and(|d| d > 1) {
            return Err(bad(
                "bgp_session_direction",
                0,
                "direction must be zero or one",
            ));
        }
        if let EventKind::Open(open) = &event.kind {
            if open.capabilities.len() > self.limits.elements {
                return Err(Error::limit("bgp_session_capabilities"));
            }
            for cap in &open.capabilities {
                check_sha256(&cap.value_sha256)?;
            }
        }
        match &event.kind {
            EventKind::Gap { reason } | EventKind::Reset { reason, .. } => {
                check_text(reason, &self.limits)?
            }
            _ => {}
        }
        if let EventKind::ProtocolReset {
            next_generation, ..
        } = &event.kind
        {
            if event.generation.checked_add(1) != Some(*next_generation) {
                return Err(bad(
                    "bgp_session_protocol_reset",
                    0,
                    "protocol reset must name the exact next generation",
                ));
            }
        }
        match &event.kind {
            EventKind::RouteRefresh { family, .. }
            | EventKind::EndOfRib(family)
            | EventKind::Stale { family, .. } => check_family(family)?,
            _ => {}
        }
        if self.events.iter().any(|old| old == &event) {
            return Ok(ApplyStatus::IdenticalReplay);
        }
        let mut next = self.clone();
        let conflict = next
            .events
            .iter()
            .any(|old| old.record_id == event.record_id);
        let status = next.apply_inner(&event, conflict)?;
        next.events.push(event);
        if next.events.len() > next.limits.elements {
            return Err(Error::limit("bgp_session_events"));
        }
        let size = next.accounted_size();
        if size > next.limits.retained_bytes
            || size > next.limits.output_bytes
            || next.accounted_work() > next.limits.work
        {
            return Err(Error::limit("bgp_session_budget"));
        }
        *self = next;
        Ok(status)
    }
    fn apply_inner(&mut self, event: &Event, conflict: bool) -> Result<ApplyStatus> {
        if self.view.is_none() {
            if matches!(event.kind, EventKind::Reset { .. }) {
                return Err(bad(
                    "bgp_session_reset",
                    0,
                    "reset needs observed predecessor",
                ));
            }
            self.view = Some(empty_view(event.generation));
        }
        let view = self.view.as_mut().expect("initialized");
        if conflict {
            view.identity_conflict = true;
            view.context = CapabilityContext::Unresolved("record_identity_conflict");
            return Ok(ApplyStatus::IdentityConflict);
        }
        if view.identity_conflict {
            return Ok(ApplyStatus::IdentityConflict);
        }
        if let EventKind::Reset {
            previous_generation,
            ..
        } = &event.kind
        {
            if event.direction.is_some()
                || *previous_generation != view.generation
                || event.generation <= view.generation
                || self.key.source.kind == PartitionKind::Imported
                    && view.generation.checked_add(1) != Some(event.generation)
            {
                return Err(bad(
                    "bgp_session_reset",
                    0,
                    "explicit advancing reset required",
                ));
            }
            let mut replacement = empty_view(event.generation);
            replacement.resets = view.resets.clone();
            replacement.resets.push(event.record_id.clone());
            *view = replacement;
            return Ok(ApplyStatus::Applied);
        }
        if let EventKind::ProtocolReset {
            next_generation,
            kind,
        } = &event.kind
        {
            if event.generation != view.generation {
                return if event.generation < view.generation {
                    Ok(ApplyStatus::Historical)
                } else {
                    Err(bad(
                        "bgp_session_generation",
                        0,
                        "protocol reset skipped an observed generation",
                    ))
                };
            }
            if *kind == ProtocolResetKind::Notification {
                if let Some(direction) = event.direction {
                    view.directions[usize::from(direction)]
                        .notifications
                        .push(event.record_id.clone());
                } else {
                    view.unscoped.push(event.record_id.clone());
                }
            }
            let mut replacement = empty_view(*next_generation);
            replacement.resets = view.resets.clone();
            replacement.resets.push(event.record_id.clone());
            *view = replacement;
            return Ok(ApplyStatus::Applied);
        }
        if event.generation < view.generation {
            return Ok(ApplyStatus::Historical);
        }
        if event.generation > view.generation {
            return Err(bad(
                "bgp_session_generation",
                0,
                "new generation needs reset",
            ));
        }
        if view.closed_by_notification {
            return Ok(ApplyStatus::Closed);
        }
        if let EventKind::Gap { .. } = &event.kind {
            view.gaps.push(event.record_id.clone());
            view.context = CapabilityContext::Unresolved("explicit_gap");
            return Ok(ApplyStatus::Applied);
        }
        let Some(direction) = event.direction else {
            view.unscoped.push(event.record_id.clone());
            if matches!(event.kind, EventKind::Open(_)) {
                view.unscoped_open = true;
                view.context = CapabilityContext::Unresolved("unscoped_open_alternative");
            }
            if matches!(event.kind, EventKind::Notification) {
                view.closed_by_notification = true;
                view.context = CapabilityContext::Unresolved("notification_observed");
            }
            return Ok(ApplyStatus::Applied);
        };
        let side = &mut view.directions[usize::from(direction)];
        match &event.kind {
            EventKind::Open(open) => {
                if let Some(existing) = side.opens.iter_mut().find(|o| o.advertisement == *open) {
                    existing.witnesses.push(event.record_id.clone());
                } else {
                    side.opens.push(OpenAlternative {
                        advertisement: open.clone(),
                        witnesses: vec![event.record_id.clone()],
                    });
                }
            }
            EventKind::Keepalive => side.keepalives.push(event.record_id.clone()),
            EventKind::Update => side.updates.push(event.record_id.clone()),
            EventKind::Notification => {
                side.notifications.push(event.record_id.clone());
                view.closed_by_notification = true;
            }
            EventKind::ProtocolReset { .. } => unreachable!(),
            EventKind::RouteRefresh { family, subtype } => {
                side.refreshes
                    .push((*family, *subtype, event.record_id.clone()))
            }
            EventKind::EndOfRib(family) => {
                side.eors.push((*family, event.record_id.clone()));
                side.stale.retain(|(f, _, _)| f != family);
            }
            EventKind::Stale { family, kind } => {
                side.stale.push((*family, *kind, event.record_id.clone()))
            }
            EventKind::Gap { .. } | EventKind::Reset { .. } => unreachable!(),
        }
        view.context = context(view);
        Ok(ApplyStatus::Applied)
    }
}

fn check_text(value: &str, limits: &Limits) -> Result<()> {
    if value.trim().is_empty()
        || value.len() > limits.input_bytes.min(1024)
        || value.chars().any(char::is_control)
    {
        return Err(bad(
            "bgp_session_identity",
            0,
            "nonempty bounded identity required",
        ));
    }
    Ok(())
}
fn check_sha256(value: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(bad(
            "bgp_session_capability_hash",
            0,
            "expected 64 lowercase SHA-256 hexadecimal digits",
        ));
    }
    Ok(())
}
fn check_family(family: &Family) -> Result<()> {
    if family.afi == 0 || family.safi == 0 {
        return Err(bad(
            "bgp_session_family",
            0,
            "nonzero AFI and SAFI required",
        ));
    }
    Ok(())
}
fn empty_view(generation: u64) -> SessionView {
    SessionView {
        generation,
        directions: [DirectionView::default(), DirectionView::default()],
        context: CapabilityContext::Unresolved("bilateral_open_missing"),
        gaps: Vec::new(),
        unscoped: Vec::new(),
        unscoped_open: false,
        resets: Vec::new(),
        closed_by_notification: false,
        identity_conflict: false,
    }
}
fn context(view: &SessionView) -> CapabilityContext {
    if view.identity_conflict {
        return CapabilityContext::Unresolved("record_identity_conflict");
    }
    if !view.gaps.is_empty() {
        return CapabilityContext::Unresolved("explicit_gap");
    }
    if view.unscoped_open {
        return CapabilityContext::Unresolved("unscoped_open_alternative");
    }
    if view.closed_by_notification {
        return CapabilityContext::Unresolved("notification_observed");
    }
    let [left, right] = &view.directions;
    if left.opens.len() != 1
        || right.opens.len() != 1
        || left.opens[0].witnesses.len() != 1
        || right.opens[0].witnesses.len() != 1
    {
        return CapabilityContext::Unresolved("bilateral_unique_open_missing");
    }
    let a = &left.opens[0].advertisement;
    let b = &right.opens[0].advertisement;
    if a.ambiguous || b.ambiguous {
        return CapabilityContext::Unresolved("open_capability_ambiguous");
    }
    let aa: BTreeSet<_> = a.capabilities.iter().map(|c| c.code).collect();
    let bb: BTreeSet<_> = b.capabilities.iter().map(|c| c.code).collect();
    CapabilityContext::BilateralCandidate {
        common_codes: aa.intersection(&bb).copied().collect(),
    }
}
