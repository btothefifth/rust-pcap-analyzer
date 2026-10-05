//! Offline observations of a caller-scoped BGP exchange. This is not a speaker FSM.
//! Absence of a message, elapsed time, and peer labels never establish a transition.
use super::bgp_import::ImportContext;
use super::model::{bad, Limits};
use pcap_evidence::{sha256, Error, Result};
use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;

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
    /// Complete accepted captured OPEN identity. Only the immutable message
    /// bytes contribute; record labels and packet proof are not OPEN content.
    CapturedOpen {
        advertisement: OpenAdvertisement,
        message_sha256: [u8; 32],
    },
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
    /// Captured content identity certifies repeated witnesses describe one
    /// complete OPEN. Legacy capability-only advertisements remain unproven.
    pub captured_message_sha256: Option<[u8; 32]>,
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

/// A new OPEN content alternative invalidates the bilateral observed layout
/// for exactly this session generation. This is neither reset nor withdrawal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OpenContinuityVerdict {
    Preserved,
    Contradiction {
        session: SessionKey,
        generation: u64,
    },
}

/// Supplemental logical traversal counters for admitted operations only.
/// Failed preparation publishes neither semantic state nor diagnostics. These
/// count visited/copied retained items, not wall time, RSS, or allocator calls.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SessionReductionWork {
    pub event_comparisons: usize,
    pub copied_history_items: usize,
    pub measured_history_items: usize,
    pub inventory_items: usize,
}
impl SessionReductionWork {
    fn accumulate(&mut self, other: Self) {
        self.inventory_items = self.inventory_items.saturating_add(other.inventory_items);
        self.event_comparisons = self
            .event_comparisons
            .saturating_add(other.event_comparisons);
        self.copied_history_items = self
            .copied_history_items
            .saturating_add(other.copied_history_items);
        self.measured_history_items = self
            .measured_history_items
            .saturating_add(other.measured_history_items);
    }
}

pub(crate) struct PreparedSessionEvent {
    instance: Arc<()>,
    revision: usize,
    status: ApplyStatus,
    plan: SessionPlan,
    work: SessionReductionWork,
    admitted_work: usize,
}
// Keep the admitted Event inline: boxing this variant would add a per-message
// heap allocation to the prepublication append path. Its bounded 264-byte
// payload is intentional; logical charge and diagnostics do not depend on it.
#[allow(clippy::large_enum_variant)]
enum SessionPlan {
    Inert,
    Append {
        event: Event,
        projection_record: String,
        index_record: String,
        indices: Vec<usize>,
        bytes: usize,
    },
    Staged(Box<SessionObserver>),
}
impl PreparedSessionEvent {
    pub(crate) fn status(&self) -> ApplyStatus {
        self.status
    }
}

#[derive(Debug)]
pub struct SessionObserver {
    instance: Arc<()>,
    key: SessionKey,
    limits: Limits,
    events: Vec<Event>,
    record_index: HashMap<String, Vec<usize>>,
    bytes: usize,
    work_units: usize,
    reduction_work: SessionReductionWork,
    view: Option<SessionView>,
}

impl Clone for SessionObserver {
    fn clone(&self) -> Self {
        let (copied_history_items, inventory_items) = self.retained_item_count();
        let mut reduction_work = self.reduction_work;
        reduction_work.accumulate(SessionReductionWork {
            copied_history_items,
            inventory_items,
            ..SessionReductionWork::default()
        });
        Self {
            instance: Arc::new(()),
            key: self.key.clone(),
            limits: self.limits.clone(),
            events: self.events.clone(),
            record_index: self.record_index.clone(),
            bytes: self.bytes,
            work_units: self.work_units,
            reduction_work,
            view: self.view.clone(),
        }
    }
}

impl SessionObserver {
    pub fn new(key: SessionKey, limits: Limits) -> Result<Self> {
        limits.validate()?;
        check_text(&key.source.source_id, &limits)?;
        check_text(&key.source.partition_id, &limits)?;
        check_text(&key.session, &limits)?;
        let bytes = std::mem::size_of::<Self>()
            + key.source.source_id.len()
            + key.source.partition_id.len()
            + key.session.len();
        Ok(Self {
            instance: Arc::new(()),
            key,
            limits,
            events: Vec::new(),
            record_index: HashMap::new(),
            bytes,
            work_units: 0,
            reduction_work: SessionReductionWork::default(),
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
    /// Classify an incoming captured OPEN against the retained current scope.
    /// Consume this verdict only if `apply` subsequently admits the event as
    /// newly Applied; historical, conflicting, closed, and replay events cannot
    /// establish a new contradiction. The ordinary OPEN observer API lacks
    /// complete-message identity and therefore cannot fabricate this verdict.
    pub fn open_continuity(&self, event: &Event) -> OpenContinuityVerdict {
        let EventKind::CapturedOpen { message_sha256, .. } = &event.kind else {
            return OpenContinuityVerdict::Preserved;
        };
        let Some(view) = &self.view else {
            return OpenContinuityVerdict::Preserved;
        };
        if self.key.source.kind != PartitionKind::Captured
            || event.session != self.key
            || event.generation != view.generation
            || event.direction.is_none()
            || view.identity_conflict
            || view.closed_by_notification
        {
            return OpenContinuityVerdict::Preserved;
        }
        let mut previous_open = false;
        for old in self
            .events
            .iter()
            .filter(|old| old.generation == event.generation && old.direction == event.direction)
        {
            if let EventKind::CapturedOpen {
                message_sha256: previous,
                ..
            } = &old.kind
            {
                if previous == message_sha256 {
                    return OpenContinuityVerdict::Preserved;
                }
                previous_open = true;
            }
        }
        if previous_open {
            OpenContinuityVerdict::Contradiction {
                session: self.key.clone(),
                generation: event.generation,
            }
        } else {
            OpenContinuityVerdict::Preserved
        }
    }
    pub fn reduction_work(&self) -> SessionReductionWork {
        self.reduction_work
    }
    /// Logical retention measure, including the complete journal and projection.
    pub fn retained_bytes(&self) -> usize {
        self.accounted_size()
    }
    /// Cumulative admitted logical work. Ordinary appends charge only new
    /// retention units; rare controls precharge the retained copy and projected
    /// measurement. Exact replay and rejected preparation leave it unchanged.
    pub fn accounted_work(&self) -> usize {
        self.work_units
    }
    fn accounted_size(&self) -> usize {
        self.bytes
    }
    pub fn apply(&mut self, event: Event) -> Result<ApplyStatus> {
        let prepared = self.prepare(event)?;
        let status = prepared.status();
        self.admit_prepared(&prepared)?;
        self.commit(prepared);
        Ok(status)
    }
    pub(crate) fn prepared_current(&self, prepared: &PreparedSessionEvent) -> bool {
        Arc::ptr_eq(&self.instance, &prepared.instance) && self.events.len() == prepared.revision
    }
    /// A unique ordinary observation stages only the new journal/projection
    /// witness. Rare controls retain the existing bounded clone transaction.
    pub(crate) fn prepare(&self, event: Event) -> Result<PreparedSessionEvent> {
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
        if let EventKind::Open(open)
        | EventKind::CapturedOpen {
            advertisement: open,
            ..
        } = &event.kind
        {
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
        let revision = self.events.len();
        let existing = self.record_index.get(&event.record_id);
        let mut work = SessionReductionWork::default();
        if let Some(indices) = existing {
            for index in indices {
                work.event_comparisons = work.event_comparisons.saturating_add(1);
                if self.events[*index] == event {
                    return Ok(PreparedSessionEvent {
                        instance: Arc::clone(&self.instance),
                        revision,
                        status: ApplyStatus::IdenticalReplay,
                        plan: SessionPlan::Inert,
                        work,
                        admitted_work: self.work_units,
                    });
                }
            }
        }
        if self.events.len() >= self.limits.elements {
            return Err(Error::limit("bgp_session_events"));
        }
        let conflict = existing.is_some();
        let ordinary = !conflict
            && event.direction.is_some()
            && matches!(event.kind, EventKind::Update | EventKind::Keepalive)
            && self.view.as_ref().is_some_and(|view| {
                view.generation == event.generation
                    && !view.identity_conflict
                    && !view.closed_by_notification
            });
        if ordinary {
            let mut bytes = add_size(self.bytes, event_size(&event)?)?;
            bytes = add_size(bytes, new_record_index_size(&event.record_id))?;
            bytes = add_size(bytes, text_storage(&event.record_id))?;
            let append_units = bytes
                .checked_sub(self.bytes)
                .and_then(|units| units.checked_mul(2))
                .ok_or_else(|| Error::limit("bgp_session_budget"))?;
            let admitted_work = add_size(self.work_units, append_units)?;
            self.check_budget(bytes, admitted_work)?;
            return Ok(PreparedSessionEvent {
                instance: Arc::clone(&self.instance),
                revision,
                status: ApplyStatus::Applied,
                plan: SessionPlan::Append {
                    projection_record: event.record_id.clone(),
                    index_record: event.record_id.clone(),
                    indices: vec![revision],
                    event,
                    bytes,
                },
                work,
                admitted_work,
            });
        }
        // Charge the retained copy before making it. The projected measurement
        // is admitted before publication; rare controls remain bounded.
        let copy_work = add_size(self.work_units, self.bytes)?;
        self.check_budget(self.bytes, copy_work)?;
        let mut next = self.clone();
        let status = next.apply_inner(&event, conflict)?;
        next.record_index
            .entry(event.record_id.clone())
            .or_default()
            .push(next.events.len());
        next.events.push(event);
        let (measured_bytes, measured_items) = next.measure_size()?;
        work.measured_history_items = measured_items;
        next.bytes = measured_bytes;
        let admitted_work = add_size(copy_work, next.bytes)?;
        next.check_budget(next.bytes, admitted_work)?;
        Ok(PreparedSessionEvent {
            instance: Arc::clone(&self.instance),
            revision,
            status,
            plan: SessionPlan::Staged(Box::new(next)),
            work,
            admitted_work,
        })
    }
    /// Reserve append vectors before publishing any owned projection. Capacity
    /// changes are not canonical journal/projection state. The private replay
    /// index is never serialized or used to determine journal order.
    pub(crate) fn admit_prepared(&mut self, prepared: &PreparedSessionEvent) -> Result<()> {
        if !self.prepared_current(prepared) {
            return Err(bad(
                "bgp_session_revision",
                0,
                "prepared session revision changed",
            ));
        }
        if let SessionPlan::Append { event, .. } = &prepared.plan {
            self.record_index
                .try_reserve(1)
                .map_err(|_| Error::limit("bgp_session_capacity"))?;
            self.events
                .try_reserve(1)
                .map_err(|_| Error::limit("bgp_session_capacity"))?;
            let view = self.view.as_mut().expect("prepared current view");
            let side =
                &mut view.directions[usize::from(event.direction.expect("prepared direction"))];
            let witnesses = if matches!(event.kind, EventKind::Update) {
                &mut side.updates
            } else {
                &mut side.keepalives
            };
            witnesses
                .try_reserve(1)
                .map_err(|_| Error::limit("bgp_session_capacity"))?;
        }
        Ok(())
    }
    /// Caller checks the prepared revision before committing any sibling
    /// projection. No validation or fallible operation follows publication.
    pub(crate) fn commit(&mut self, prepared: PreparedSessionEvent) {
        let admitted_work = prepared.admitted_work;
        match prepared.plan {
            SessionPlan::Inert => self.reduction_work.accumulate(prepared.work),
            SessionPlan::Staged(mut next) => {
                next.instance = Arc::clone(&self.instance);
                next.reduction_work.accumulate(prepared.work);
                *self = *next;
            }
            SessionPlan::Append {
                event,
                projection_record,
                index_record,
                indices,
                bytes,
            } => {
                let view = self.view.as_mut().expect("prepared current view");
                let side =
                    &mut view.directions[usize::from(event.direction.expect("prepared direction"))];
                if matches!(event.kind, EventKind::Update) {
                    side.updates.push(projection_record);
                } else {
                    side.keepalives.push(projection_record);
                }
                self.record_index.insert(index_record, indices);
                self.events.push(event);
                self.bytes = bytes;
                self.reduction_work.accumulate(prepared.work);
            }
        }
        self.work_units = admitted_work;
    }
    fn check_budget(&self, bytes: usize, work: usize) -> Result<()> {
        if bytes > self.limits.retained_bytes
            || bytes > self.limits.output_bytes
            || work > self.limits.work
        {
            Err(Error::limit("bgp_session_budget"))
        } else {
            Ok(())
        }
    }
    fn retained_item_count(&self) -> (usize, usize) {
        let mut inventory_items = 0usize;
        let mut items = self.events.len().saturating_add(self.record_index.len());
        for indices in self.record_index.values() {
            inventory_items = inventory_items.saturating_add(1);
            items = items.saturating_add(indices.len());
        }
        if let Some(view) = &self.view {
            items = items
                .saturating_add(view.gaps.len())
                .saturating_add(view.unscoped.len())
                .saturating_add(view.resets.len());
            for side in &view.directions {
                items = items
                    .saturating_add(side.keepalives.len())
                    .saturating_add(side.updates.len())
                    .saturating_add(side.notifications.len())
                    .saturating_add(side.refreshes.len())
                    .saturating_add(side.eors.len())
                    .saturating_add(side.stale.len());
                for open in &side.opens {
                    inventory_items = inventory_items.saturating_add(1);
                    items = items
                        .saturating_add(1)
                        .saturating_add(open.advertisement.capabilities.len())
                        .saturating_add(open.witnesses.len());
                }
            }
            if let CapabilityContext::BilateralCandidate { common_codes } = &view.context {
                items = items.saturating_add(common_codes.len());
            }
        }
        // Each retained event is copied together with any capability array.
        for event in &self.events {
            inventory_items = inventory_items.saturating_add(1);
            if let EventKind::Open(open)
            | EventKind::CapturedOpen {
                advertisement: open,
                ..
            } = &event.kind
            {
                items = items.saturating_add(open.capabilities.len());
            }
        }
        (items, inventory_items)
    }
    fn measure_size(&self) -> Result<(usize, usize)> {
        let mut visited = 0usize;
        let mut bytes = add_size(std::mem::size_of::<Self>(), self.key.source.source_id.len())?;
        bytes = add_size(bytes, self.key.source.partition_id.len())?;
        bytes = add_size(bytes, self.key.session.len())?;
        for event in &self.events {
            visited = visited.saturating_add(1);
            if let EventKind::Open(open)
            | EventKind::CapturedOpen {
                advertisement: open,
                ..
            } = &event.kind
            {
                visited = visited.saturating_add(open.capabilities.len());
            }
            bytes = add_size(bytes, event_size(event)?)?;
        }
        for (record, indices) in &self.record_index {
            visited = visited.saturating_add(1);
            bytes = add_size(bytes, new_record_index_size(record))?;
            bytes = add_size(
                bytes,
                indices
                    .len()
                    .saturating_sub(1)
                    .checked_mul(std::mem::size_of::<usize>())
                    .ok_or_else(|| Error::limit("bgp_session_budget"))?,
            )?;
        }
        if let Some(view) = &self.view {
            let (dynamic_bytes, dynamic_visited) = view_dynamic_size(view)?;
            bytes = add_size(bytes, dynamic_bytes)?;
            visited = visited.saturating_add(dynamic_visited);
        }
        Ok((bytes, visited))
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
            if matches!(
                event.kind,
                EventKind::Open(_) | EventKind::CapturedOpen { .. }
            ) {
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
            EventKind::Open(open)
            | EventKind::CapturedOpen {
                advertisement: open,
                ..
            } => {
                let captured_message_sha256 = match &event.kind {
                    EventKind::CapturedOpen { message_sha256, .. } => Some(*message_sha256),
                    _ => None,
                };
                if let Some(existing) = side.opens.iter_mut().find(|o| {
                    o.advertisement == *open && o.captured_message_sha256 == captured_message_sha256
                }) {
                    existing.witnesses.push(event.record_id.clone());
                } else {
                    side.opens.push(OpenAlternative {
                        advertisement: open.clone(),
                        captured_message_sha256,
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

// Typed logical retention units. These bound the journal, indexes and current
// projection; they are neither allocator/RSS accounting nor a CPU sandbox.
fn add_size(left: usize, right: usize) -> Result<usize> {
    left.checked_add(right)
        .ok_or_else(|| Error::limit("bgp_session_budget"))
}
fn text_storage(text: &str) -> usize {
    std::mem::size_of::<String>() + text.len()
}
fn new_record_index_size(record: &str) -> usize {
    text_storage(record) + std::mem::size_of::<Vec<usize>>() + std::mem::size_of::<usize>()
}
fn advertisement_dynamic_size(open: &OpenAdvertisement) -> Result<usize> {
    open.capabilities.iter().try_fold(0usize, |bytes, cap| {
        add_size(
            bytes,
            std::mem::size_of::<Capability>() + cap.value_sha256.len(),
        )
    })
}
fn event_size(event: &Event) -> Result<usize> {
    let mut bytes = std::mem::size_of::<Event>();
    for text in [
        &event.session.source.source_id,
        &event.session.source.partition_id,
        &event.session.session,
        &event.record_id,
    ] {
        bytes = add_size(bytes, text.len())?;
    }
    match &event.kind {
        EventKind::Open(open)
        | EventKind::CapturedOpen {
            advertisement: open,
            ..
        } => bytes = add_size(bytes, advertisement_dynamic_size(open)?)?,
        EventKind::Gap { reason } | EventKind::Reset { reason, .. } => {
            bytes = add_size(bytes, reason.len())?
        }
        _ => {}
    }
    Ok(bytes)
}
fn view_dynamic_size(view: &SessionView) -> Result<(usize, usize)> {
    let mut bytes = 0usize;
    let mut visited = 0usize;
    for text in view.gaps.iter().chain(&view.unscoped).chain(&view.resets) {
        visited = visited.saturating_add(1);
        bytes = add_size(bytes, text_storage(text))?;
    }
    if let CapabilityContext::BilateralCandidate { common_codes } = &view.context {
        bytes = add_size(bytes, common_codes.len())?;
    }
    for side in &view.directions {
        for open in &side.opens {
            visited = visited.saturating_add(1 + open.advertisement.capabilities.len());
            bytes = add_size(bytes, std::mem::size_of::<OpenAlternative>())?;
            bytes = add_size(bytes, advertisement_dynamic_size(&open.advertisement)?)?;
            for witness in &open.witnesses {
                visited = visited.saturating_add(1);
                bytes = add_size(bytes, text_storage(witness))?;
            }
        }
        for witness in side
            .keepalives
            .iter()
            .chain(&side.updates)
            .chain(&side.notifications)
        {
            visited = visited.saturating_add(1);
            bytes = add_size(bytes, text_storage(witness))?;
        }
        for (_, _, witness) in &side.refreshes {
            visited = visited.saturating_add(1);
            bytes = add_size(
                bytes,
                std::mem::size_of::<(Family, Option<u8>, String)>() + witness.len(),
            )?;
        }
        for (_, witness) in &side.eors {
            visited = visited.saturating_add(1);
            bytes = add_size(
                bytes,
                std::mem::size_of::<(Family, String)>() + witness.len(),
            )?;
        }
        for (_, _, witness) in &side.stale {
            visited = visited.saturating_add(1);
            bytes = add_size(
                bytes,
                std::mem::size_of::<(Family, StaleKind, String)>() + witness.len(),
            )?;
        }
    }
    Ok((bytes, visited))
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
        || left.opens[0].witnesses.len() != 1 && left.opens[0].captured_message_sha256.is_none()
        || right.opens[0].witnesses.len() != 1 && right.opens[0].captured_message_sha256.is_none()
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

#[cfg(test)]
mod prepared_tests {
    use super::*;
    fn observer() -> SessionObserver {
        SessionObserver::new(
            SessionKey {
                source: SourcePartition {
                    kind: PartitionKind::Captured,
                    source_id: "s".into(),
                    partition_id: "p".into(),
                },
                session: "session".into(),
            },
            Limits::default(),
        )
        .unwrap()
    }
    fn keepalive(observer: &SessionObserver, record: &str) -> Event {
        Event {
            session: observer.key().clone(),
            generation: 0,
            direction: Some(0),
            record_id: record.into(),
            kind: EventKind::Keepalive,
        }
    }
    #[test]
    fn ordinary_append_charge_exact_and_one_below_preserves_state_and_replay() {
        let mut reference = observer();
        let first = keepalive(&reference, "first");
        let second = keepalive(&reference, "second");
        reference.apply(first.clone()).unwrap();
        let before_history_work = reference.reduction_work();
        reference.apply(second.clone()).unwrap();
        assert_eq!(reference.reduction_work(), before_history_work);
        let size = reference.retained_bytes();
        let work = reference.accounted_work();
        let key = reference.key().clone();
        let mut exact = SessionObserver::new(
            key.clone(),
            Limits {
                retained_bytes: size,
                output_bytes: size,
                work,
                ..Limits::default()
            },
        )
        .unwrap();
        exact.apply(first.clone()).unwrap();
        assert_eq!(exact.apply(second.clone()).unwrap(), ApplyStatus::Applied);
        assert_eq!(exact.events(), reference.events());
        assert_eq!(exact.view(), reference.view());
        for limits in [
            Limits {
                retained_bytes: size - 1,
                ..Limits::default()
            },
            Limits {
                output_bytes: size - 1,
                ..Limits::default()
            },
            Limits {
                work: work - 1,
                ..Limits::default()
            },
        ] {
            let mut limited = SessionObserver::new(key.clone(), limits).unwrap();
            assert_eq!(limited.apply(first.clone()).unwrap(), ApplyStatus::Applied);
            let events = limited.events().to_vec();
            let view = limited.view().cloned();
            let retained = limited.retained_bytes();
            let admitted_work = limited.accounted_work();
            let diagnostics = limited.reduction_work();
            let error = limited.apply(second.clone()).unwrap_err();
            assert_eq!(error.field, "bgp_session_budget");
            assert_eq!(limited.events(), events);
            assert_eq!(limited.view(), view.as_ref());
            assert_eq!(limited.retained_bytes(), retained);
            assert_eq!(limited.accounted_work(), admitted_work);
            assert_eq!(limited.reduction_work(), diagnostics);
            assert_eq!(
                limited.apply(first.clone()).unwrap(),
                ApplyStatus::IdenticalReplay
            );
            assert_eq!(limited.events(), events);
            assert_eq!(limited.view(), view.as_ref());
            assert_eq!(limited.retained_bytes(), retained);
            assert_eq!(limited.accounted_work(), admitted_work);
        }
    }
    #[test]
    fn prepared_session_token_rejects_same_count_clone_sibling_and_stale_revision() {
        let mut owner = observer();
        owner.apply(keepalive(&owner, "first")).unwrap();
        let mut sibling = owner.clone();
        let plan = owner.prepare(keepalive(&owner, "next")).unwrap();
        let before_events = sibling.events().to_vec();
        let before_view = sibling.view().cloned();
        let before_work = sibling.reduction_work();
        assert!(!sibling.prepared_current(&plan));
        assert!(sibling.admit_prepared(&plan).is_err());
        assert_eq!(sibling.events(), before_events);
        assert_eq!(sibling.view(), before_view.as_ref());
        assert_eq!(sibling.reduction_work(), before_work);
        owner.apply(keepalive(&owner, "other")).unwrap();
        assert!(!owner.prepared_current(&plan));
        let before_events = owner.events().to_vec();
        let before_view = owner.view().cloned();
        let before_work = owner.reduction_work();
        assert!(owner.admit_prepared(&plan).is_err());
        assert_eq!(owner.events(), before_events);
        assert_eq!(owner.view(), before_view.as_ref());
        assert_eq!(owner.reduction_work(), before_work);
    }
}
