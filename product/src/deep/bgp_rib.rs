//! Versioned, source-partitioned Adj-RIB-In *candidates*. No endpoint RIB is read.
//! Input order is an explicit replay assertion; clocks and labels never order it.
use super::bgp_session::{Family, PartitionKind, SessionKey, SourcePartition, StaleKind};
use super::bgp_state::{tree_budget, CandidateState, PrefixIdentity, RoutePathId};
use super::model::{bad, Limits};
use pcap_evidence::{json::Json, sha256, Error, Result};
use std::collections::{BTreeMap, BTreeSet};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

pub const SCHEMA: &str = "pcap-evidence.bgp.adj-rib-in-candidate.v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum PathId {
    Absent,
    Present(u32),
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct RibScope {
    pub source: SourcePartition,
    pub session: String,
    pub generation: u64,
    pub direction: Option<u8>,
    pub peer: Option<String>,
}
impl RibScope {
    fn session_key(&self) -> SessionKey {
        SessionKey {
            source: self.source.clone(),
            session: self.session.clone(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct RouteKey {
    pub scope: RibScope,
    pub family: Family,
    pub path_id: PathId,
    pub prefix: PrefixIdentity,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RibAction {
    Announce {
        prefix: PrefixIdentity,
        path_id: PathId,
        attributes: Json,
        attribute_identity: String,
    },
    Withdraw {
        prefix: PrefixIdentity,
        path_id: PathId,
    },
    /// Explicit upstream error disposition. It does not withdraw an older
    /// candidate unless a separate withdrawal observation is supplied.
    Reject {
        prefix: PrefixIdentity,
        path_id: PathId,
        reason: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RibEventKind {
    /// All route actions decoded from one immutable source record. Keeping the
    /// complete ordered record together prevents a multi-NLRI UPDATE from
    /// conflicting with itself and makes publication atomic.
    Update(Vec<RibAction>),
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
pub struct RibEvent {
    pub scope: RibScope,
    pub record_id: String,
    pub kind: RibEventKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouteStatus {
    Active,
    Stale(StaleKind),
    StaleAtEor,
    Withdrawn,
    Superseded,
    Unresolved,
    Rejected,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VersionDisposition {
    Current,
    Replaced,
    Withdrawn,
    Superseded,
    Conflicting,
}

/// Exact source occurrence attached at the native version mutation point.
/// Ordinals are zero-based; the digest names a verified normalized observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct NativeVersionOccurrence {
    pub event_index: usize,
    pub observation_sha256: [u8; 32],
    pub route_index: usize,
}
impl NativeVersionOccurrence {
    /// Explicit evidence projection. Existing default native JSON omits this.
    pub fn json(&self) -> Json {
        Json::object([
            ("event_index", self.event_index.into()),
            (
                "observation_sha256",
                sha256::hex(&self.observation_sha256).into(),
            ),
            ("route_index", self.route_index.into()),
        ])
    }
}
/// Checked native ordinals passed together for one action; never retained.
#[derive(Clone, Copy)]
struct NativeActionPosition {
    event_index: usize,
    route_index: usize,
}

#[derive(Clone, Debug)]
struct VersionBinding {
    key: RouteKey,
    version_index: usize,
    route_index: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteVersion {
    pub attributes: Json,
    pub attribute_identity: String,
    pub witnesses: Vec<String>,
    pub occurrences: Vec<NativeVersionOccurrence>,
    pub disposition: VersionDisposition,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteEntry {
    pub key: RouteKey,
    pub versions: Vec<RouteVersion>,
    pub status: RouteStatus,
    pub last_witness: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FamilyMarker {
    pub scope: RibScope,
    pub family: Family,
    pub record_id: String,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RejectedRecord {
    pub key: RouteKey,
    pub record_id: String,
    pub reason: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApplyStatus {
    Applied,
    IdenticalReplay,
    Historical,
    MissingScope,
    IdentityConflict,
}

#[derive(Clone)]
pub struct LegacyAdapter {
    snapshot: CandidateState,
}
impl LegacyAdapter {
    /// Exact original journal, outcomes, partitions and alternatives are retained
    /// so projection cannot silently erase ambiguity or old witnesses.
    pub fn snapshot(&self) -> &CandidateState {
        &self.snapshot
    }
}

pub struct AdjRibIn {
    owner: Arc<()>,
    diagnostics: RibTransactionDiagnostics,
    limits: Limits,
    events: Vec<RibEvent>,
    entries: BTreeMap<RouteKey, RouteEntry>,
    generations: BTreeMap<SessionKey, u64>,
    gaps: Vec<(RibScope, String)>,
    eors: Vec<FamilyMarker>,
    rejections: Vec<RejectedRecord>,
    tainted_sessions: BTreeSet<SessionKey>,
    legacy: Option<LegacyAdapter>,
    record_index: BTreeMap<(SessionKey, String), Vec<usize>>,
    gap_index: BTreeSet<(SessionKey, u64)>,
    peer_index: BTreeMap<RibScope, BTreeSet<Option<String>>>,
    entry_charges: BTreeMap<RouteKey, usize>,
    version_bindings: BTreeMap<usize, Vec<VersionBinding>>,
    origin_index: BTreeSet<(usize, [u8; 32])>,
    origin_elements: usize,
    retained: usize,
    work: usize,
    actions: usize,
    versions: usize,
}

/// Continuity mutation actually staged by the native owner, without Update
/// actions or an owned source copy. Consumers admit their own retained carrier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NativeContinuityKind {
    Gap,
    Reset {
        previous_generation: u64,
        next_generation: u64,
    },
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NativeContinuityEffect {
    SessionGeneration,
    SessionAllGenerations,
    BaseDirectionalGeneration,
}
#[derive(Clone, Copy)]
pub(crate) struct NativeContinuityRef<'a> {
    pub(crate) record_id: &'a str,
    pub(crate) scope: &'a RibScope,
    pub(crate) status: ApplyStatus,
    pub(crate) kind: NativeContinuityKind,
    pub(crate) effect: NativeContinuityEffect,
    pub(crate) reason: &'a str,
}
/// Canonical matcher for an admitted owned continuity carrier as well as the
/// prepared borrowed view. No status is invented when protocol evidence owns
/// a Reset separately from native state mutation.
pub(crate) fn continuity_affects_scope(
    kind: NativeContinuityKind,
    effect: NativeContinuityEffect,
    boundary: &RibScope,
    candidate: &RibScope,
) -> bool {
    match effect {
        NativeContinuityEffect::SessionAllGenerations => {
            same_session_identity(candidate, &boundary.source, &boundary.session)
        }
        NativeContinuityEffect::SessionGeneration => {
            let generation = match kind {
                NativeContinuityKind::Gap => boundary.generation,
                NativeContinuityKind::Reset {
                    previous_generation,
                    ..
                } => previous_generation,
            };
            same_session_identity(candidate, &boundary.source, &boundary.session)
                && candidate.generation == generation
        }
        NativeContinuityEffect::BaseDirectionalGeneration => same_base_scope(boundary, candidate),
    }
}

/// Prepared against one append-only reducer revision. The caller must verify
/// `prepared_current` before publishing any member of an enclosing transaction.
/// No Result-returning operation remains in commit. Standard map operations may
/// still abort on allocator exhaustion; logical admission is not an RSS quota.
pub(crate) struct PreparedRibEvent {
    owner: Arc<()>,
    diagnostics: RibTransactionDiagnostics,
    revision: usize,
    status: ApplyStatus,
    event: Option<RibEvent>,
    stage: AdjRibIn,
    charges: BTreeMap<RouteKey, usize>,
    retained: usize,
    work: usize,
    actions: usize,
    versions: usize,
    origin_elements: usize,
    event_growth: Option<Vec<RibEvent>>,
    gap_growth: Option<Vec<(RibScope, String)>>,
    eor_growth: Option<Vec<FamilyMarker>>,
    rejection_growth: Option<Vec<RejectedRecord>>,
}
impl PreparedRibEvent {
    pub(crate) fn prospective_retained_bytes(&self) -> usize {
        self.retained
    }
    pub(crate) fn prospective_work(&self) -> usize {
        self.work
    }
    pub(crate) fn status(&self) -> ApplyStatus {
        self.status
    }
    pub(crate) fn continuity_effect(&self) -> Option<NativeContinuityRef<'_>> {
        let event = self.event.as_ref()?;
        // The staged gap inventory is actual mutation evidence: a tainted
        // no-op or directionless missing scope has no newly staged gap.
        let (kind, effect, reason) = match self.status {
            ApplyStatus::IdentityConflict if !self.stage.gaps.is_empty() => (
                NativeContinuityKind::Gap,
                NativeContinuityEffect::SessionAllGenerations,
                "record_identity_conflict",
            ),
            ApplyStatus::MissingScope if !self.stage.gaps.is_empty() => (
                NativeContinuityKind::Gap,
                NativeContinuityEffect::BaseDirectionalGeneration,
                "peer_binding_mismatch",
            ),
            ApplyStatus::Applied => match &event.kind {
                RibEventKind::Gap { reason } if !self.stage.gaps.is_empty() => (
                    NativeContinuityKind::Gap,
                    NativeContinuityEffect::SessionGeneration,
                    reason.as_str(),
                ),
                RibEventKind::Reset {
                    previous_generation,
                    reason,
                } => (
                    NativeContinuityKind::Reset {
                        previous_generation: *previous_generation,
                        next_generation: event.scope.generation,
                    },
                    NativeContinuityEffect::SessionGeneration,
                    reason.as_str(),
                ),
                _ => return None,
            },
            _ => return None,
        };
        Some(NativeContinuityRef {
            record_id: &event.record_id,
            scope: &event.scope,
            status: self.status,
            kind,
            effect,
            reason,
        })
    }
}
impl AdjRibIn {
    /// Internal owner boundary for an embedding whose encoder measures actual
    /// public output bytes. Retained logical units keep the native default
    /// ceiling and any stricter caller retention limit; other caps are unchanged.
    pub(crate) fn for_embedded_projection(mut limits: Limits) -> Result<Self> {
        // Validate the caller's original configuration before replacing a field.
        limits.validate()?;
        limits.output_bytes = limits.retained_bytes.min(Limits::default().output_bytes);
        Self::new(limits)
    }
    pub fn new(limits: Limits) -> Result<Self> {
        limits.validate()?;
        Ok(Self {
            owner: Arc::new(()),
            diagnostics: RibTransactionDiagnostics::default(),
            limits,
            events: Vec::new(),
            entries: BTreeMap::new(),
            generations: BTreeMap::new(),
            gaps: Vec::new(),
            eors: Vec::new(),
            rejections: Vec::new(),
            tainted_sessions: BTreeSet::new(),
            legacy: None,
            record_index: BTreeMap::new(),
            gap_index: BTreeSet::new(),
            peer_index: BTreeMap::new(),
            entry_charges: BTreeMap::new(),
            version_bindings: BTreeMap::new(),
            origin_index: BTreeSet::new(),
            origin_elements: 0,
            retained: 0,
            work: 0,
            actions: 0,
            versions: 0,
        })
    }
    pub fn events(&self) -> &[RibEvent] {
        &self.events
    }
    pub fn entries(&self) -> &BTreeMap<RouteKey, RouteEntry> {
        &self.entries
    }
    pub fn eors(&self) -> &[FamilyMarker] {
        &self.eors
    }
    pub fn rejections(&self) -> &[RejectedRecord] {
        &self.rejections
    }
    pub fn gaps(&self) -> &[(RibScope, String)] {
        &self.gaps
    }
    pub fn legacy(&self) -> Option<&LegacyAdapter> {
        self.legacy.as_ref()
    }
    /// Conservative typed logical-content charge, including all private indexes.
    /// This is deterministic across allocator/platform changes, not measured RSS.
    pub fn retained_bytes(&self) -> usize {
        self.retained
    }
    pub fn transaction_diagnostics(&self) -> RibTransactionDiagnostics {
        self.diagnostics
    }
    /// Cumulative admitted work. Consumers charge the checked after-before delta.
    /// Inert replays and rejected preparations do not change this counter.
    /// A replay with a new origin proof charges its admitted metadata delta.
    pub fn accounted_work(&self) -> usize {
        self.work
    }

    pub fn apply(&mut self, event: RibEvent) -> Result<ApplyStatus> {
        let plan = self.prepare(event)?;
        let status = plan.status();
        debug_assert!(self.prepared_current(&plan));
        self.commit(plan);
        Ok(status)
    }
    /// Source adapters must verify the observation digest and preserve Update
    /// action order as the normalized route order before invoking this API.
    pub fn apply_with_origin(
        &mut self,
        event: RibEvent,
        observation_sha256: [u8; 32],
    ) -> Result<ApplyStatus> {
        let plan = self.prepare_with_origin(event, observation_sha256)?;
        let status = plan.status();
        self.commit(plan);
        Ok(status)
    }
    pub(crate) fn prepared_current(&self, plan: &PreparedRibEvent) -> bool {
        Arc::ptr_eq(&self.owner, &plan.owner)
            && self.events.len() == plan.revision
            && self.work == plan.stage.work
    }
    pub(crate) fn prepare(&self, event: RibEvent) -> Result<PreparedRibEvent> {
        self.prepare_inner(event, None)
    }
    pub(crate) fn prepare_with_origin(
        &self,
        event: RibEvent,
        observation_sha256: [u8; 32],
    ) -> Result<PreparedRibEvent> {
        self.prepare_inner(event, Some(observation_sha256))
    }
    fn prepare_inner(&self, event: RibEvent, origin: Option<[u8; 32]>) -> Result<PreparedRibEvent> {
        if self.legacy.is_some() {
            return Err(bad("bgp_rib_legacy", 0, "legacy projection is read only"));
        }
        validate_event(&event, &self.limits)?;
        let event_size = charge_event(&event);
        let session = event.scope.session_key();
        let label = (session.clone(), event.record_id.clone());
        let mut admission = event_size.saturating_mul(3);
        let mut conflict = false;
        let mut diagnostics = self.diagnostics;
        if let Some(records) = self.record_index.get(&label) {
            conflict = true;
            for index in records {
                diagnostics.indexed_event_comparisons =
                    diagnostics.indexed_event_comparisons.saturating_add(1);
                admission = admission
                    .saturating_add(event_size)
                    .saturating_add(charge_event(&self.events[*index]));
                if admission == usize::MAX || admission > self.limits.work {
                    return Err(Error::limit("bgp_rib_budget"));
                }
                // The index is only a selector. Complete content equality owns replay.
                if self.events[*index] == event {
                    return self.prepare_origin_replay(*index, origin, admission, diagnostics);
                }
            }
        }
        self.check_work(admission)?;
        let tainted = self.tainted_sessions.contains(&session);
        let current = self.generations.get(&session).copied();
        if !tainted && !conflict {
            validate_generation(&event, current)?;
        }
        let historical = current.is_some_and(|g| event.scope.generation < g);
        let peer_mismatch = self.peer_binding_mismatch(&event.scope);
        let gap = self
            .gap_index
            .contains(&(session.clone(), event.scope.generation));
        let mut selected = BTreeSet::new();
        // Charge the incoming mutation and every prospective index copy before
        // copying entries. Wide controls may inspect entries, never event history.
        let index_size = self.event_index_growth(&event);
        admission = admission
            .saturating_add(mutation_bound(&event, origin.is_some()).saturating_mul(2))
            .saturating_add(index_size.saturating_mul(2));
        self.check_work(admission)?;
        if !tainted {
            let wide = conflict
                || matches!(event.kind, RibEventKind::Reset { .. })
                || !historical
                    && (peer_mismatch && is_route_scoped(&event.kind)
                        || matches!(
                            event.kind,
                            RibEventKind::Gap { .. }
                                | RibEventKind::EndOfRib(_)
                                | RibEventKind::Stale { .. }
                        ));
            if wide {
                for (key, entry) in &self.entries {
                    diagnostics.wide_entry_visits = diagnostics.wide_entry_visits.saturating_add(1);
                    admission = admission.saturating_add(charge_key(key));
                    self.check_work(admission)?;
                    let affected = if conflict {
                        same_session(&key.scope, &session)
                    } else if let RibEventKind::Reset {
                        previous_generation,
                        ..
                    } = &event.kind
                    {
                        same_session(&key.scope, &session)
                            && key.scope.generation == *previous_generation
                    } else if peer_mismatch && is_route_scoped(&event.kind) {
                        same_base_scope(&key.scope, &event.scope)
                    } else {
                        match &event.kind {
                            RibEventKind::Gap { .. } => {
                                same_session(&key.scope, &session)
                                    && key.scope.generation == event.scope.generation
                            }
                            RibEventKind::EndOfRib(family) => {
                                same_family_scope(key, &event.scope, *family)
                                    && matches!(entry.status, RouteStatus::Stale(_))
                            }
                            RibEventKind::Stale { family, .. } => {
                                same_family_scope(key, &event.scope, *family)
                                    && entry.status == RouteStatus::Active
                            }
                            _ => false,
                        }
                    };
                    if affected {
                        admission =
                            admission.saturating_add(self.entry_charges[key].saturating_mul(2));
                        self.check_work(admission)?;
                        selected.insert(key.clone());
                    }
                }
            }
            if let RibEventKind::Update(actions) = &event.kind {
                if conflict || !historical && event.scope.direction.is_some() && !peer_mismatch {
                    for action in actions {
                        let (prefix, path_id) = match action {
                            RibAction::Announce {
                                prefix, path_id, ..
                            } => (prefix, path_id),
                            RibAction::Withdraw { prefix, path_id } if !conflict => {
                                (prefix, path_id)
                            }
                            _ => continue,
                        };
                        let key = route_key(&event.scope, prefix, *path_id);
                        if !selected.contains(&key) {
                            admission = admission.saturating_add(
                                self.entry_charges
                                    .get(&key)
                                    .copied()
                                    .unwrap_or(0)
                                    .saturating_mul(2),
                            );
                            self.check_work(admission)?;
                            selected.insert(key);
                        }
                    }
                }
            }
        }
        // Necessary retained growth is known without a staging copy. Exact final
        // growth is checked below; replaced affected entry content may shrink.
        let removed: usize = selected
            .iter()
            .map(|key| self.entry_charges.get(key).copied().unwrap_or(0))
            .fold(0, usize::saturating_add);
        let minimum = self
            .retained
            .saturating_sub(removed)
            .saturating_add(event_size)
            .saturating_add(index_size);
        // Exact newly retained binding metadata is knowable before entry copies.
        let binding_growth = if !tainted
            && (conflict && event.scope.direction.is_some()
                || !conflict && !historical && event.scope.direction.is_some() && !peer_mismatch)
        {
            if let RibEventKind::Update(actions) = &event.kind {
                let mut count = 0usize;
                let mut growth = 0usize;
                for action in actions {
                    if let RibAction::Announce { prefix, .. } = action {
                        count = count.saturating_add(1);
                        growth = growth
                            .saturating_add(NODE + 16 + SLOT)
                            .saturating_add(charge_action_key(&event.scope, prefix));
                    }
                }
                if count > 0 {
                    growth = growth.saturating_add(NODE + 8 + CONTAINER);
                    if origin.is_some() {
                        growth = growth
                            .saturating_add(ORIGIN_INDEX_CHARGE)
                            .saturating_add(count.saturating_mul(OCCURRENCE_CHARGE));
                    }
                }
                growth
            } else {
                0
            }
        } else {
            0
        };
        self.check_sizes(minimum.saturating_add(binding_growth))?;
        let mut stage = Self::new(self.limits.clone())?;
        stage.work = self.work;
        if let Some(generation) = current {
            stage.generations.insert(session.clone(), generation);
        }
        if tainted {
            stage.tainted_sessions.insert(session.clone());
        }
        for key in selected {
            if let Some(entry) = self.entries.get(&key) {
                diagnostics.staged_entries = diagnostics.staged_entries.saturating_add(1);
                diagnostics.copied_versions = diagnostics
                    .copied_versions
                    .saturating_add(entry.versions.len());
                diagnostics.copied_occurrences = diagnostics.copied_occurrences.saturating_add(
                    entry
                        .versions
                        .iter()
                        .map(|v| v.occurrences.len())
                        .sum::<usize>(),
                );
                diagnostics.copied_witnesses = diagnostics.copied_witnesses.saturating_add(
                    entry
                        .versions
                        .iter()
                        .map(|v| v.witnesses.len())
                        .sum::<usize>(),
                );
                stage.entries.insert(key, entry.clone());
            }
        }
        let old_versions: usize = stage
            .entries
            .values()
            .map(|entry| entry.versions.len())
            .sum();
        let status = stage.apply_inner(
            &event,
            conflict,
            gap,
            peer_mismatch,
            self.events.len(),
            origin,
        )?;
        let mut charges = BTreeMap::new();
        let mut added = 0usize;
        for (key, entry) in &stage.entries {
            diagnostics.measured_versions = diagnostics
                .measured_versions
                .saturating_add(entry.versions.len());
            diagnostics.measured_occurrences = diagnostics.measured_occurrences.saturating_add(
                entry
                    .versions
                    .iter()
                    .map(|v| v.occurrences.len())
                    .sum::<usize>(),
            );
            diagnostics.measured_witnesses = diagnostics.measured_witnesses.saturating_add(
                entry
                    .versions
                    .iter()
                    .map(|v| v.witnesses.len())
                    .sum::<usize>(),
            );
            let charge = charge_stored_entry(key, entry);
            added = added.saturating_add(charge);
            charges.insert(key.clone(), charge);
        }
        diagnostics.binding_visits = diagnostics
            .binding_visits
            .saturating_add(stage.version_bindings.values().map(Vec::len).sum::<usize>());
        let metadata = charge_metadata_delta(self, &stage, &session)
            .saturating_add(charge_bindings(&stage.version_bindings))
            .saturating_add(stage.origin_index.len().saturating_mul(ORIGIN_INDEX_CHARGE));
        let origin_elements = self.origin_elements.saturating_add(stage.origin_elements);
        let retained = minimum.saturating_add(added).saturating_add(metadata);
        self.check_sizes(retained)?;
        let actions = self.actions.saturating_add(event_actions(&event));
        let versions = self.versions.saturating_sub(old_versions).saturating_add(
            stage
                .entries
                .values()
                .map(|entry| entry.versions.len())
                .sum::<usize>(),
        );
        if actions
            .saturating_add(versions)
            .saturating_add(origin_elements)
            > self.limits.elements
            || self.entries.len().saturating_add(
                stage
                    .entries
                    .keys()
                    .filter(|key| !self.entries.contains_key(*key))
                    .count(),
            ) > self.limits.active
        {
            return Err(Error::limit("bgp_rib_elements"));
        }
        self.check_work(admission)?;
        let work = self
            .work
            .checked_add(admission)
            .ok_or_else(|| Error::limit("bgp_rib_budget"))?;
        let event_growth = reserve_append(&self.events, 1)?;
        diagnostics.committed_entries = diagnostics
            .committed_entries
            .saturating_add(stage.entries.len());
        if event_growth.is_some() {
            diagnostics.moved_events = diagnostics.moved_events.saturating_add(self.events.len());
        }
        let gap_growth = reserve_append(&self.gaps, stage.gaps.len())?;
        let eor_growth = reserve_append(&self.eors, stage.eors.len())?;
        let rejection_growth = reserve_append(&self.rejections, stage.rejections.len())?;
        Ok(PreparedRibEvent {
            owner: Arc::clone(&self.owner),
            diagnostics,
            revision: self.events.len(),
            status,
            event: Some(event),
            stage,
            charges,
            retained,
            work,
            actions,
            versions,
            origin_elements,
            event_growth,
            gap_growth,
            eor_growth,
            rejection_growth,
        })
    }
    pub(crate) fn commit(&mut self, mut plan: PreparedRibEvent) -> ApplyStatus {
        // Exclusive caller checks revision before its first publication; no
        // fallible validation or reservation is deferred until this point.
        assert!(
            self.prepared_current(&plan),
            "prepared RIB transaction owner/revision mismatch"
        );
        if let Some(event) = plan.event.take() {
            let session = event.scope.session_key();
            let label = (session, event.record_id.clone());
            self.record_index
                .entry(label)
                .or_default()
                .push(self.events.len());
            if is_route_scoped(&event.kind) {
                self.peer_index
                    .entry(base_scope(&event.scope))
                    .or_default()
                    .insert(event.scope.peer.clone());
            }
            if let Some(mut events) = plan.event_growth.take() {
                events.append(&mut self.events);
                self.events = events;
            }
            self.events.push(event);
        }
        for (event_index, bindings) in plan.stage.version_bindings {
            self.version_bindings.insert(event_index, bindings);
        }
        for origin in plan.stage.origin_index {
            self.origin_index.insert(origin);
        }
        for (scope, _) in &plan.stage.gaps {
            self.gap_index
                .insert((scope.session_key(), scope.generation));
        }
        // BTreeMap::append rebuilds unrelated contents on Rust 1.85. Insert only
        // staged members; no whole-map traversal is hidden at commit.
        for (key, entry) in plan.stage.entries {
            self.entries.insert(key, entry);
        }
        for (key, charge) in plan.charges {
            self.entry_charges.insert(key, charge);
        }
        for (session, generation) in plan.stage.generations {
            self.generations.insert(session, generation);
        }
        for session in plan.stage.tainted_sessions {
            self.tainted_sessions.insert(session);
        }
        append_reserved(&mut self.gaps, &mut plan.stage.gaps, plan.gap_growth);
        append_reserved(&mut self.eors, &mut plan.stage.eors, plan.eor_growth);
        append_reserved(
            &mut self.rejections,
            &mut plan.stage.rejections,
            plan.rejection_growth,
        );
        self.retained = plan.retained;
        self.work = plan.work;
        self.diagnostics = plan.diagnostics;
        self.actions = plan.actions;
        self.versions = plan.versions;
        self.origin_elements = plan.origin_elements;
        plan.status
    }
    fn prepare_origin_replay(
        &self,
        event_index: usize,
        origin: Option<[u8; 32]>,
        mut admission: usize,
        mut diagnostics: RibTransactionDiagnostics,
    ) -> Result<PreparedRibEvent> {
        let mut stage = Self::new(self.limits.clone())?;
        stage.work = self.work;
        let mut retained = self.retained;
        let mut work = self.work;
        let mut origin_elements = self.origin_elements;
        let mut charges = BTreeMap::new();
        if let Some(digest) =
            origin.filter(|digest| !self.origin_index.contains(&(event_index, *digest)))
        {
            if let Some(bindings) = self.version_bindings.get(&event_index) {
                // Bindings are produced only at the actual Announce mutation and
                // survive reset, quarantine and attribute coalescing. No label or
                // attribute heuristic recovers their target versions.
                admission = admission
                    .saturating_add(ORIGIN_INDEX_CHARGE.saturating_mul(2))
                    .saturating_add(
                        bindings
                            .len()
                            .saturating_mul(OCCURRENCE_CHARGE)
                            .saturating_mul(2),
                    );
                self.check_work(admission)?;
                let mut selected = BTreeSet::new();
                for binding in bindings {
                    diagnostics.binding_visits = diagnostics.binding_visits.saturating_add(1);
                    admission = admission
                        .saturating_add(NODE + 16 + SLOT)
                        .saturating_add(charge_key(&binding.key));
                    if !selected.contains(&binding.key) {
                        admission = admission
                            .saturating_add(self.entry_charges[&binding.key].saturating_mul(2));
                    }
                    self.check_work(admission)?;
                    selected.insert(binding.key.clone());
                }
                let removed = selected
                    .iter()
                    .fold(0usize, |n, key| n.saturating_add(self.entry_charges[key]));
                let minimum = self
                    .retained
                    .saturating_sub(removed)
                    .saturating_add(ORIGIN_INDEX_CHARGE)
                    .saturating_add(bindings.len().saturating_mul(OCCURRENCE_CHARGE));
                self.check_sizes(minimum)?;
                origin_elements = self
                    .origin_elements
                    .saturating_add(bindings.len())
                    .saturating_add(1);
                if self
                    .actions
                    .saturating_add(self.versions)
                    .saturating_add(origin_elements)
                    > self.limits.elements
                {
                    return Err(Error::limit("bgp_rib_elements"));
                }
                for key in selected {
                    let entry = &self.entries[&key];
                    diagnostics.staged_entries = diagnostics.staged_entries.saturating_add(1);
                    diagnostics.copied_versions = diagnostics
                        .copied_versions
                        .saturating_add(entry.versions.len());
                    diagnostics.copied_witnesses = diagnostics.copied_witnesses.saturating_add(
                        entry
                            .versions
                            .iter()
                            .map(|v| v.witnesses.len())
                            .sum::<usize>(),
                    );
                    diagnostics.copied_occurrences = diagnostics.copied_occurrences.saturating_add(
                        entry
                            .versions
                            .iter()
                            .map(|v| v.occurrences.len())
                            .sum::<usize>(),
                    );
                    stage.entries.insert(key, entry.clone());
                }
                for binding in bindings {
                    stage
                        .entries
                        .get_mut(&binding.key)
                        .expect("binding entry retained")
                        .versions[binding.version_index]
                        .occurrences
                        .push(NativeVersionOccurrence {
                            event_index,
                            observation_sha256: digest,
                            route_index: binding.route_index,
                        });
                }
                let mut added = 0usize;
                for (key, entry) in &stage.entries {
                    diagnostics.measured_versions = diagnostics
                        .measured_versions
                        .saturating_add(entry.versions.len());
                    diagnostics.measured_witnesses = diagnostics.measured_witnesses.saturating_add(
                        entry
                            .versions
                            .iter()
                            .map(|v| v.witnesses.len())
                            .sum::<usize>(),
                    );
                    diagnostics.measured_occurrences =
                        diagnostics.measured_occurrences.saturating_add(
                            entry
                                .versions
                                .iter()
                                .map(|v| v.occurrences.len())
                                .sum::<usize>(),
                        );
                    let charge = charge_stored_entry(key, entry);
                    added = added.saturating_add(charge);
                    charges.insert(key.clone(), charge);
                }
                retained = self
                    .retained
                    .saturating_sub(removed)
                    .saturating_add(added)
                    .saturating_add(ORIGIN_INDEX_CHARGE);
                self.check_sizes(retained)?;
                self.check_work(admission)?;
                work = self
                    .work
                    .checked_add(admission)
                    .ok_or_else(|| Error::limit("bgp_rib_budget"))?;
                diagnostics.committed_entries = diagnostics
                    .committed_entries
                    .saturating_add(stage.entries.len());
                stage.origin_index.insert((event_index, digest));
            }
        }
        if work == self.work {
            diagnostics = self.diagnostics;
        }
        Ok(PreparedRibEvent {
            owner: Arc::clone(&self.owner),
            diagnostics,
            revision: self.events.len(),
            status: ApplyStatus::IdenticalReplay,
            event: None,
            stage,
            charges,
            retained,
            work,
            actions: self.actions,
            versions: self.versions,
            origin_elements,
            event_growth: None,
            gap_growth: None,
            eor_growth: None,
            rejection_growth: None,
        })
    }

    fn check_sizes(&self, size: usize) -> Result<()> {
        if size == usize::MAX
            || size > self.limits.retained_bytes
            || size > self.limits.output_bytes
        {
            return Err(Error::limit("bgp_rib_budget"));
        }
        Ok(())
    }
    fn check_work(&self, extra: usize) -> Result<()> {
        if extra == usize::MAX
            || self
                .work
                .checked_add(extra)
                .is_none_or(|work| work > self.limits.work)
        {
            return Err(Error::limit("bgp_rib_budget"));
        }
        Ok(())
    }
    fn event_index_growth(&self, event: &RibEvent) -> usize {
        let session = event.scope.session_key();
        let mut charge = SLOT;
        if !self
            .record_index
            .contains_key(&(session.clone(), event.record_id.clone()))
        {
            charge = charge
                .saturating_add(NODE)
                .saturating_add(charge_session(&session))
                .saturating_add(charge_text(&event.record_id))
                .saturating_add(CONTAINER);
        }
        if is_route_scoped(&event.kind) {
            let base = base_scope(&event.scope);
            match self.peer_index.get(&base) {
                None => {
                    charge = charge
                        .saturating_add(NODE)
                        .saturating_add(charge_scope(&base))
                        .saturating_add(CONTAINER)
                        .saturating_add(NODE)
                        .saturating_add(charge_peer(&event.scope.peer))
                }
                Some(peers) if !peers.contains(&event.scope.peer) => {
                    charge = charge
                        .saturating_add(NODE)
                        .saturating_add(charge_peer(&event.scope.peer))
                }
                _ => (),
            }
        }
        charge
    }
    fn apply_inner(
        &mut self,
        event: &RibEvent,
        conflict: bool,
        gap: bool,
        peer_mismatch: bool,
        event_index: usize,
        origin: Option<[u8; 32]>,
    ) -> Result<ApplyStatus> {
        let session = event.scope.session_key();
        if self.tainted_sessions.contains(&session) {
            return Ok(ApplyStatus::IdentityConflict);
        }
        if conflict {
            self.quarantine_session(&session);
            self.tainted_sessions.insert(session);
            if let RibEventKind::Update(actions) = &event.kind {
                for (route_index, action) in actions.iter().enumerate() {
                    if let RibAction::Announce {
                        prefix,
                        path_id,
                        attributes,
                        attribute_identity,
                    } = action
                    {
                        if event.scope.direction.is_some() {
                            let key = route_key(&event.scope, prefix, *path_id);
                            let entry =
                                self.entries
                                    .entry(key.clone())
                                    .or_insert_with(|| RouteEntry {
                                        key,
                                        versions: Vec::new(),
                                        status: RouteStatus::Unresolved,
                                        last_witness: event.record_id.clone(),
                                    });
                            entry.versions.push(RouteVersion {
                                attributes: attributes.clone(),
                                attribute_identity: attribute_identity.clone(),
                                witnesses: vec![event.record_id.clone()],
                                occurrences: occurrence(event_index, origin, route_index),
                                disposition: VersionDisposition::Conflicting,
                            });
                            let binding = VersionBinding {
                                key: entry.key.clone(),
                                version_index: entry.versions.len() - 1,
                                route_index,
                            };
                            self.version_bindings
                                .entry(event_index)
                                .or_default()
                                .push(binding);
                            self.origin_elements = self
                                .origin_elements
                                .saturating_add(1 + usize::from(origin.is_some()));
                            entry.status = RouteStatus::Unresolved;
                        }
                    }
                }
            }
            self.finish_origin(event_index, origin);
            self.gaps
                .push((event.scope.clone(), event.record_id.clone()));
            return Ok(ApplyStatus::IdentityConflict);
        }
        let current = self.generations.get(&session).copied();
        if let RibEventKind::Reset {
            previous_generation,
            ..
        } = &event.kind
        {
            if event.scope.direction.is_some()
                || current != Some(*previous_generation)
                || event.scope.generation <= *previous_generation
                || event.scope.source.kind == PartitionKind::Imported
                    && previous_generation.checked_add(1) != Some(event.scope.generation)
            {
                return Err(bad(
                    "bgp_rib_reset",
                    0,
                    "explicit advancing predecessor required",
                ));
            }
            for entry in self.entries.values_mut().filter(|e| {
                same_session(&e.key.scope, &session)
                    && e.key.scope.generation == *previous_generation
            }) {
                entry.status = RouteStatus::Superseded;
                for version in &mut entry.versions {
                    if version.disposition == VersionDisposition::Current {
                        version.disposition = VersionDisposition::Superseded;
                    }
                }
            }
            self.generations.insert(session, event.scope.generation);
            return Ok(ApplyStatus::Applied);
        }
        if current.is_some_and(|g| event.scope.generation < g) {
            return Ok(ApplyStatus::Historical);
        }
        if current.is_some_and(|g| event.scope.generation > g) {
            return Err(bad(
                "bgp_rib_generation",
                0,
                "generation change needs reset",
            ));
        }
        if current.is_none() {
            self.generations
                .insert(session.clone(), event.scope.generation);
        }
        if event.scope.direction.is_none() && !matches!(event.kind, RibEventKind::Gap { .. }) {
            return Ok(ApplyStatus::MissingScope);
        }
        if matches!(
            event.kind,
            RibEventKind::Update(_) | RibEventKind::EndOfRib(_) | RibEventKind::Stale { .. }
        ) && peer_mismatch
        {
            self.quarantine_scope(&event.scope);
            self.gaps
                .push((event.scope.clone(), event.record_id.clone()));
            return Ok(ApplyStatus::MissingScope);
        }
        match &event.kind {
            RibEventKind::Gap { .. } => {
                self.gaps
                    .push((event.scope.clone(), event.record_id.clone()));
                for entry in self.entries.values_mut().filter(|e| {
                    same_session(&e.key.scope, &session)
                        && e.key.scope.generation == event.scope.generation
                }) {
                    entry.status = RouteStatus::Unresolved;
                }
            }
            RibEventKind::EndOfRib(family) => {
                self.eors.push(FamilyMarker {
                    scope: event.scope.clone(),
                    family: *family,
                    record_id: event.record_id.clone(),
                });
                for entry in self
                    .entries
                    .values_mut()
                    .filter(|e| same_family_scope(&e.key, &event.scope, *family))
                {
                    if matches!(entry.status, RouteStatus::Stale(_)) {
                        entry.status = RouteStatus::StaleAtEor;
                    }
                }
            }
            RibEventKind::Stale { family, kind } => {
                for entry in self
                    .entries
                    .values_mut()
                    .filter(|e| same_family_scope(&e.key, &event.scope, *family))
                {
                    if entry.status == RouteStatus::Active {
                        entry.status = RouteStatus::Stale(*kind);
                    }
                }
            }
            RibEventKind::Update(actions) => {
                for (route_index, action) in actions.iter().enumerate() {
                    self.apply_action(
                        &event.scope,
                        &event.record_id,
                        action,
                        gap,
                        NativeActionPosition {
                            event_index,
                            route_index,
                        },
                        origin,
                    );
                }
                self.finish_origin(event_index, origin);
            }
            RibEventKind::Reset { .. } => unreachable!(),
        }
        Ok(ApplyStatus::Applied)
    }
    fn finish_origin(&mut self, event_index: usize, origin: Option<[u8; 32]>) {
        if self.version_bindings.contains_key(&event_index) {
            if let Some(digest) = origin {
                self.origin_index.insert((event_index, digest));
                self.origin_elements = self.origin_elements.saturating_add(1);
            }
        }
    }
    fn apply_action(
        &mut self,
        scope: &RibScope,
        record_id: &str,
        action: &RibAction,
        gap: bool,
        position: NativeActionPosition,
        origin: Option<[u8; 32]>,
    ) {
        let NativeActionPosition {
            event_index,
            route_index,
        } = position;
        match action {
            RibAction::Announce {
                prefix,
                path_id,
                attributes,
                attribute_identity,
            } => {
                let key = route_key(scope, prefix, *path_id);
                let entry = self
                    .entries
                    .entry(key.clone())
                    .or_insert_with(|| RouteEntry {
                        key,
                        versions: Vec::new(),
                        status: RouteStatus::Unresolved,
                        last_witness: record_id.to_owned(),
                    });
                if entry.status == RouteStatus::Active
                    && entry.versions.last().is_some_and(|version| {
                        version.attributes == *attributes
                            && version.attribute_identity == *attribute_identity
                    })
                {
                    entry
                        .versions
                        .last_mut()
                        .expect("last exists")
                        .witnesses
                        .push(record_id.to_owned());
                    entry
                        .versions
                        .last_mut()
                        .expect("last exists")
                        .occurrences
                        .extend(occurrence(event_index, origin, route_index));
                } else {
                    for version in &mut entry.versions {
                        if version.disposition == VersionDisposition::Current {
                            version.disposition = VersionDisposition::Replaced;
                        }
                    }
                    entry.versions.push(RouteVersion {
                        attributes: attributes.clone(),
                        attribute_identity: attribute_identity.clone(),
                        witnesses: vec![record_id.to_owned()],
                        occurrences: occurrence(event_index, origin, route_index),
                        disposition: VersionDisposition::Current,
                    });
                }
                let binding = VersionBinding {
                    key: entry.key.clone(),
                    version_index: entry.versions.len() - 1,
                    route_index,
                };
                self.version_bindings
                    .entry(event_index)
                    .or_default()
                    .push(binding);
                self.origin_elements = self
                    .origin_elements
                    .saturating_add(1 + usize::from(origin.is_some()));
                entry.status = if gap || *path_id == PathId::Unknown || !supported(prefix) {
                    RouteStatus::Unresolved
                } else {
                    RouteStatus::Active
                };
                entry.last_witness = record_id.to_owned();
            }
            RibAction::Withdraw { prefix, path_id } => {
                let key = route_key(scope, prefix, *path_id);
                let entry = self
                    .entries
                    .entry(key.clone())
                    .or_insert_with(|| RouteEntry {
                        key,
                        versions: Vec::new(),
                        status: RouteStatus::Withdrawn,
                        last_witness: record_id.to_owned(),
                    });
                for version in &mut entry.versions {
                    if version.disposition == VersionDisposition::Current {
                        version.disposition = VersionDisposition::Withdrawn;
                    }
                }
                entry.status = if gap {
                    RouteStatus::Unresolved
                } else {
                    RouteStatus::Withdrawn
                };
                entry.last_witness = record_id.to_owned();
            }
            RibAction::Reject {
                prefix,
                path_id,
                reason,
            } => self.rejections.push(RejectedRecord {
                key: route_key(scope, prefix, *path_id),
                record_id: record_id.to_owned(),
                reason: reason.clone(),
            }),
        }
    }
    fn quarantine_session(&mut self, session: &SessionKey) {
        for entry in self
            .entries
            .values_mut()
            .filter(|entry| same_session(&entry.key.scope, session))
        {
            entry.status = RouteStatus::Unresolved;
            for version in &mut entry.versions {
                version.disposition = VersionDisposition::Conflicting;
            }
        }
    }
    fn quarantine_scope(&mut self, scope: &RibScope) {
        for entry in self
            .entries
            .values_mut()
            .filter(|entry| same_base_scope(&entry.key.scope, scope))
        {
            entry.status = RouteStatus::Unresolved;
        }
    }
    fn peer_binding_mismatch(&self, scope: &RibScope) -> bool {
        self.peer_index
            .get(&base_scope(scope))
            .is_some_and(|peers| peers.len() > 1 || !peers.contains(&scope.peer))
    }
    fn check_budget(&self) -> Result<()> {
        if self
            .actions
            .saturating_add(self.versions)
            .saturating_add(self.origin_elements)
            > self.limits.elements
            || self.entries.len() > self.limits.active
        {
            return Err(Error::limit("bgp_rib_elements"));
        }
        self.check_sizes(self.retained)?;
        self.check_work(0)
    }
    /// Explicit compatibility bridge. The exact legacy snapshot is retained and
    /// cannot accept new v1 events; migration requires replaying source records.
    pub fn from_candidate_state(state: &CandidateState, limits: Limits) -> Result<Self> {
        let mut rib = Self::new(limits)?;
        let legacy_partition = format!(
            "legacy_snapshot:{}",
            sha256::hex(&sha256::digest(state.encode().as_bytes()))
        );
        for old in state.routes() {
            let source = SourcePartition {
                kind: match old.source_kind {
                    super::bgp::SourceKind::Captured => super::bgp_session::PartitionKind::Captured,
                    super::bgp::SourceKind::Imported => super::bgp_session::PartitionKind::Imported,
                },
                source_id: old.source_id.clone(),
                partition_id: old
                    .import_partition
                    .as_ref()
                    .map(|p| {
                        p.json()
                            .encode_bounded(rib.limits.input_bytes)
                            .map(|bytes| {
                                format!(
                                    "import-context-v1:{}",
                                    sha256::hex(&sha256::digest(bytes.as_bytes()))
                                )
                            })
                    })
                    .transpose()?
                    .unwrap_or_else(|| legacy_partition.clone()),
            };
            let peer = old
                .alternatives
                .iter()
                .flat_map(|a| &a.witnesses)
                .find_map(|w| {
                    state
                        .observations()
                        .get(w.observation)
                        .and_then(|o| o.source().peer.clone())
                });
            let scope = RibScope {
                source,
                session: old.session.clone(),
                generation: old.generation,
                direction: Some(old.direction),
                peer,
            };
            let key = RouteKey {
                scope,
                family: Family {
                    afi: old.prefix.afi,
                    safi: old.prefix.safi,
                },
                path_id: match old.path_id {
                    RoutePathId::Absent => PathId::Absent,
                    RoutePathId::Present(value) => PathId::Present(value),
                },
                prefix: old.prefix.clone(),
            };
            let mut versions = Vec::new();
            for a in &old.alternatives {
                let mut witnesses = Vec::new();
                for w in &a.witnesses {
                    let observation = state
                        .observations()
                        .get(w.observation)
                        .ok_or_else(|| bad("bgp_rib_legacy", 0, "dangling legacy witness"))?;
                    witnesses.push(format!("{}:{}", observation.source().record_id, w.route));
                }
                versions.push(RouteVersion {
                    attributes: a.attributes.clone(),
                    attribute_identity: a
                        .attribute_identity
                        .encode_bounded(rib.limits.input_bytes)?,
                    witnesses,
                    occurrences: Vec::new(),
                    disposition: VersionDisposition::Current,
                });
            }
            rib.entries.insert(
                key.clone(),
                RouteEntry {
                    key,
                    versions,
                    status: RouteStatus::Unresolved,
                    last_witness: "legacy_projection".into(),
                },
            );
        }
        rib.legacy = Some(LegacyAdapter {
            snapshot: state.clone(),
        });
        for (key, entry) in &rib.entries {
            let charge = charge_stored_entry(key, entry);
            rib.retained = rib.retained.saturating_add(charge);
            rib.versions = rib.versions.saturating_add(entry.versions.len());
            rib.entry_charges.insert(key.clone(), charge);
        }
        rib.retained = rib.retained.saturating_add(state.retained_bytes());
        rib.work = rib.retained.saturating_mul(3);
        rib.check_budget()?;
        Ok(rib)
    }
    pub fn legacy_snapshot_sha256(&self) -> Option<[u8; 32]> {
        self.legacy
            .as_ref()
            .map(|l| sha256::digest(l.snapshot.encode().as_bytes()))
    }
}

fn same_family_scope(key: &RouteKey, scope: &RibScope, family: Family) -> bool {
    key.scope == *scope && key.family == family
}
fn same_base_scope(left: &RibScope, right: &RibScope) -> bool {
    same_session_identity(left, &right.source, &right.session)
        && left.generation == right.generation
        && left.direction == right.direction
}
fn is_route_scoped(kind: &RibEventKind) -> bool {
    matches!(
        kind,
        RibEventKind::Update(_) | RibEventKind::EndOfRib(_) | RibEventKind::Stale { .. }
    )
}
fn route_key(scope: &RibScope, prefix: &PrefixIdentity, path_id: PathId) -> RouteKey {
    RouteKey {
        scope: scope.clone(),
        family: Family {
            afi: prefix.afi,
            safi: prefix.safi,
        },
        path_id,
        prefix: prefix.clone(),
    }
}
fn validate_text(value: &str, limits: &Limits) -> Result<()> {
    if value.trim().is_empty()
        || value.len() > limits.input_bytes.min(1024)
        || value.chars().any(char::is_control)
    {
        return Err(bad(
            "bgp_rib_identity",
            0,
            "nonempty bounded identity required",
        ));
    }
    Ok(())
}
fn validate_event(event: &RibEvent, limits: &Limits) -> Result<()> {
    validate_text(&event.scope.source.source_id, limits)?;
    validate_text(&event.scope.source.partition_id, limits)?;
    validate_text(&event.scope.session, limits)?;
    validate_text(&event.record_id, limits)?;
    if event.scope.direction.is_some_and(|d| d > 1) {
        return Err(bad("bgp_rib_direction", 0, "direction must be zero or one"));
    }
    if let Some(peer) = &event.scope.peer {
        validate_text(peer, limits)?;
    }
    match &event.kind {
        RibEventKind::Update(actions) => {
            if actions.is_empty() || actions.len() > limits.elements {
                return Err(bad(
                    "bgp_rib_update",
                    0,
                    "nonempty bounded action set required",
                ));
            }
            for action in actions {
                match action {
                    RibAction::Announce {
                        prefix,
                        attributes,
                        attribute_identity,
                        ..
                    } => {
                        validate_text(attribute_identity, limits)?;
                        tree_budget(attributes, limits)?;
                        attributes.encoded_len_bounded(limits.input_bytes)?;
                        validate_prefix(prefix, limits)?;
                    }
                    RibAction::Withdraw { prefix, .. } => validate_prefix(prefix, limits)?,
                    RibAction::Reject { prefix, reason, .. } => {
                        validate_prefix(prefix, limits)?;
                        validate_text(reason, limits)?;
                    }
                }
            }
        }
        RibEventKind::EndOfRib(family) | RibEventKind::Stale { family, .. } => {
            validate_family(*family)?;
        }
        RibEventKind::Gap { reason } | RibEventKind::Reset { reason, .. } => {
            validate_text(reason, limits)?
        }
    }
    Ok(())
}
fn validate_family(family: Family) -> Result<()> {
    if family.afi == 0 || family.safi == 0 {
        return Err(bad("bgp_rib_family", 0, "nonzero AFI and SAFI required"));
    }
    Ok(())
}
pub(crate) fn validate_route_key(key: &RouteKey, limits: &Limits, active: bool) -> Result<()> {
    validate_text(&key.scope.source.source_id, limits)?;
    validate_text(&key.scope.source.partition_id, limits)?;
    validate_text(&key.scope.session, limits)?;
    if key.scope.direction.is_some_and(|direction| direction > 1) {
        return Err(bad("bgp_rib_direction", 0, "direction must be zero or one"));
    }
    if let Some(peer) = &key.scope.peer {
        validate_text(peer, limits)?;
    }
    validate_family(key.family)?;
    validate_prefix(&key.prefix, limits)?;
    if key.family.afi != key.prefix.afi || key.family.safi != key.prefix.safi {
        return Err(bad("bgp_rib_family", 0, "route family and prefix disagree"));
    }
    if active
        && (key.scope.direction.is_none()
            || key.path_id == PathId::Unknown
            || !supported(&key.prefix))
    {
        return Err(bad(
            "bgp_rib_active",
            0,
            "active candidate lacks proven route scope",
        ));
    }
    Ok(())
}
fn validate_prefix(prefix: &PrefixIdentity, limits: &Limits) -> Result<()> {
    validate_text(&prefix.address, limits)?;
    let max = match prefix.afi {
        1 => 32,
        2 => 128,
        _ => 255,
    };
    if prefix.length > max || prefix.safi == 0 {
        return Err(bad("bgp_rib_prefix", 0, "invalid family or prefix length"));
    }
    match prefix.afi {
        1 => {
            let address: Ipv4Addr = prefix
                .address
                .parse()
                .map_err(|_| bad("bgp_rib_prefix", 0, "invalid IPv4 address"))?;
            if address.to_string() != prefix.address {
                return Err(bad("bgp_rib_prefix", 0, "noncanonical IPv4 text"));
            }
            let bits = u32::from(address);
            let mask = if prefix.length == 0 {
                0
            } else {
                u32::MAX << (32 - prefix.length)
            };
            if bits & !mask != 0 {
                return Err(bad("bgp_rib_prefix", 0, "noncanonical IPv4 network"));
            }
        }
        2 => {
            let address: Ipv6Addr = prefix
                .address
                .parse()
                .map_err(|_| bad("bgp_rib_prefix", 0, "invalid IPv6 address"))?;
            if address.to_string() != prefix.address {
                return Err(bad("bgp_rib_prefix", 0, "noncanonical IPv6 text"));
            }
            let bits = u128::from(address);
            let mask = if prefix.length == 0 {
                0
            } else {
                u128::MAX << (128 - prefix.length)
            };
            if bits & !mask != 0 {
                return Err(bad("bgp_rib_prefix", 0, "noncanonical IPv6 network"));
            }
        }
        _ => {} // Opaque unsupported family remains an unresolved candidate.
    }
    Ok(())
}
fn supported(prefix: &PrefixIdentity) -> bool {
    matches!(prefix.afi, 1 | 2) && matches!(prefix.safi, 1 | 2)
}

// Fixed-width logical accounting v1. Every owned string reserves six bytes per
// UTF-8 byte plus its 32-byte descriptor. Structural objects/map nodes reserve
// 256, sequence containers 64, slots 32, scalar identities 8. This conservative
// content model includes private-index copies; allocator capacity/RSS is separate.
const NODE: usize = 256;
const CONTAINER: usize = 64;
const SLOT: usize = 32;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RibTransactionDiagnostics {
    pub staged_entries: usize,
    pub indexed_event_comparisons: usize,
    pub wide_entry_visits: usize,
    pub copied_versions: usize,
    pub copied_witnesses: usize,
    pub measured_versions: usize,
    pub measured_witnesses: usize,
    pub copied_events: usize,
    pub moved_events: usize,
    pub committed_entries: usize,
    pub copied_occurrences: usize,
    pub measured_occurrences: usize,
    pub binding_visits: usize,
    pub copied_bindings: usize,
}
impl Clone for AdjRibIn {
    fn clone(&self) -> Self {
        let mut diagnostics = self.diagnostics;
        diagnostics.copied_bindings = diagnostics
            .copied_bindings
            .saturating_add(self.version_bindings.values().map(Vec::len).sum::<usize>());
        diagnostics.copied_events = diagnostics.copied_events.saturating_add(self.events.len());
        for entry in self.entries.values() {
            diagnostics.staged_entries = diagnostics.staged_entries.saturating_add(1);
            diagnostics.copied_versions = diagnostics
                .copied_versions
                .saturating_add(entry.versions.len());
            diagnostics.copied_occurrences = diagnostics.copied_occurrences.saturating_add(
                entry
                    .versions
                    .iter()
                    .map(|v| v.occurrences.len())
                    .sum::<usize>(),
            );
            diagnostics.copied_witnesses = diagnostics.copied_witnesses.saturating_add(
                entry
                    .versions
                    .iter()
                    .map(|v| v.witnesses.len())
                    .sum::<usize>(),
            );
        }
        Self {
            owner: Arc::new(()),
            diagnostics,
            limits: self.limits.clone(),
            events: self.events.clone(),
            entries: self.entries.clone(),
            generations: self.generations.clone(),
            gaps: self.gaps.clone(),
            eors: self.eors.clone(),
            rejections: self.rejections.clone(),
            tainted_sessions: self.tainted_sessions.clone(),
            legacy: self.legacy.clone(),
            record_index: self.record_index.clone(),
            gap_index: self.gap_index.clone(),
            peer_index: self.peer_index.clone(),
            entry_charges: self.entry_charges.clone(),
            version_bindings: self.version_bindings.clone(),
            origin_index: self.origin_index.clone(),
            origin_elements: self.origin_elements,
            retained: self.retained,
            work: self.work,
            actions: self.actions,
            versions: self.versions,
        }
    }
}
fn charge_text(value: &str) -> usize {
    SLOT.saturating_add(value.len().saturating_mul(6))
}
fn charge_peer(peer: &Option<String>) -> usize {
    8usize.saturating_add(peer.as_ref().map_or(0, |p| charge_text(p)))
}
fn charge_source(source: &SourcePartition) -> usize {
    NODE.saturating_add(charge_text(&source.source_id))
        .saturating_add(charge_text(&source.partition_id))
        .saturating_add(8)
}
fn charge_session(session: &SessionKey) -> usize {
    NODE.saturating_add(charge_source(&session.source))
        .saturating_add(charge_text(&session.session))
}
fn charge_scope(scope: &RibScope) -> usize {
    NODE.saturating_add(charge_source(&scope.source))
        .saturating_add(charge_text(&scope.session))
        .saturating_add(16)
        .saturating_add(charge_peer(&scope.peer))
}
fn charge_prefix(prefix: &PrefixIdentity) -> usize {
    NODE.saturating_add(8)
        .saturating_add(charge_text(&prefix.address))
}
fn charge_action_key(scope: &RibScope, prefix: &PrefixIdentity) -> usize {
    NODE.saturating_add(charge_scope(scope))
        .saturating_add(16)
        .saturating_add(charge_prefix(prefix))
}
fn charge_key(key: &RouteKey) -> usize {
    charge_action_key(&key.scope, &key.prefix)
}
fn charge_json(value: &Json) -> usize {
    match value {
        Json::String(s) => NODE.saturating_add(charge_text(s)),
        Json::Array(items) => items.iter().fold(NODE.saturating_add(CONTAINER), |n, v| {
            n.saturating_add(SLOT).saturating_add(charge_json(v))
        }),
        Json::Object(items) => items
            .iter()
            .fold(NODE.saturating_add(CONTAINER), |n, (k, v)| {
                n.saturating_add(SLOT)
                    .saturating_add(charge_text(k))
                    .saturating_add(charge_json(v))
            }),
        Json::Null | Json::Bool(_) | Json::Number(_) => NODE,
    }
}
fn charge_action(action: &RibAction) -> usize {
    match action {
        RibAction::Announce {
            prefix,
            attributes,
            attribute_identity,
            ..
        } => NODE
            .saturating_add(charge_prefix(prefix))
            .saturating_add(8)
            .saturating_add(charge_json(attributes))
            .saturating_add(charge_text(attribute_identity)),
        RibAction::Withdraw { prefix, .. } => {
            NODE.saturating_add(charge_prefix(prefix)).saturating_add(8)
        }
        RibAction::Reject { prefix, reason, .. } => NODE
            .saturating_add(charge_prefix(prefix))
            .saturating_add(8)
            .saturating_add(charge_text(reason)),
    }
}
fn charge_event(event: &RibEvent) -> usize {
    let kind = match &event.kind {
        RibEventKind::Update(actions) => {
            actions.iter().fold(NODE.saturating_add(CONTAINER), |n, a| {
                n.saturating_add(SLOT).saturating_add(charge_action(a))
            })
        }
        RibEventKind::EndOfRib(_) | RibEventKind::Stale { .. } => NODE.saturating_add(16),
        RibEventKind::Gap { reason } | RibEventKind::Reset { reason, .. } => {
            NODE.saturating_add(8).saturating_add(charge_text(reason))
        }
    };
    NODE.saturating_add(charge_scope(&event.scope))
        .saturating_add(charge_text(&event.record_id))
        .saturating_add(kind)
}
const OCCURRENCE_CHARGE: usize = NODE + 48 + SLOT;
const ORIGIN_INDEX_CHARGE: usize = NODE + 40;
fn occurrence(
    event_index: usize,
    origin: Option<[u8; 32]>,
    route_index: usize,
) -> Vec<NativeVersionOccurrence> {
    origin
        .map(|observation_sha256| {
            vec![NativeVersionOccurrence {
                event_index,
                observation_sha256,
                route_index,
            }]
        })
        .unwrap_or_default()
}
fn charge_bindings(bindings: &BTreeMap<usize, Vec<VersionBinding>>) -> usize {
    bindings.values().fold(0usize, |n, values| {
        values
            .iter()
            .fold(n.saturating_add(NODE + 8 + CONTAINER), |n, value| {
                n.saturating_add(NODE + 16 + SLOT)
                    .saturating_add(charge_key(&value.key))
            })
    })
}
fn charge_version(version: &RouteVersion) -> usize {
    version
        .witnesses
        .iter()
        .fold(
            NODE.saturating_add(charge_json(&version.attributes))
                .saturating_add(charge_text(&version.attribute_identity))
                .saturating_add(CONTAINER)
                .saturating_add(8),
            |n, witness| n.saturating_add(SLOT).saturating_add(charge_text(witness)),
        )
        .saturating_add(CONTAINER)
        .saturating_add(version.occurrences.len().saturating_mul(OCCURRENCE_CHARGE))
}
fn charge_stored_entry(key: &RouteKey, entry: &RouteEntry) -> usize {
    entry.versions.iter().fold(
        NODE.saturating_mul(3)
            .saturating_add(charge_key(key).saturating_mul(3))
            .saturating_add(CONTAINER)
            .saturating_add(16)
            .saturating_add(charge_text(&entry.last_witness)),
        |n, v| n.saturating_add(SLOT).saturating_add(charge_version(v)),
    )
}
fn mutation_bound(event: &RibEvent, origin: bool) -> usize {
    // Includes possible generation and taint nodes even if already present.
    let session = event.scope.session_key();
    let mut charge = NODE
        .saturating_mul(2)
        .saturating_add(charge_session(&session).saturating_mul(2))
        .saturating_add(8);
    match &event.kind {
        RibEventKind::Update(actions) => {
            if actions
                .iter()
                .any(|a| matches!(a, RibAction::Announce { .. }))
            {
                charge = charge.saturating_add(NODE + 8 + CONTAINER);
                if origin {
                    charge = charge.saturating_add(ORIGIN_INDEX_CHARGE);
                }
            }
            for action in actions {
                if let RibAction::Announce { prefix, .. } = action {
                    charge = charge
                        .saturating_add(CONTAINER + NODE + 16 + SLOT)
                        .saturating_add(charge_action_key(&event.scope, prefix));
                    if origin {
                        charge = charge.saturating_add(OCCURRENCE_CHARGE);
                    }
                }
                charge = charge.saturating_add(match action {
                    RibAction::Announce {
                        prefix,
                        attributes,
                        attribute_identity,
                        ..
                    } => NODE
                        .saturating_mul(4)
                        .saturating_add(charge_action_key(&event.scope, prefix).saturating_mul(3))
                        .saturating_add(CONTAINER.saturating_mul(2))
                        .saturating_add(SLOT.saturating_mul(2))
                        .saturating_add(24)
                        .saturating_add(charge_text(&event.record_id).saturating_mul(2))
                        .saturating_add(charge_json(attributes))
                        .saturating_add(charge_text(attribute_identity)),
                    RibAction::Withdraw { prefix, .. } => NODE
                        .saturating_mul(3)
                        .saturating_add(charge_action_key(&event.scope, prefix).saturating_mul(3))
                        .saturating_add(CONTAINER)
                        .saturating_add(16)
                        .saturating_add(charge_text(&event.record_id)),
                    RibAction::Reject { prefix, reason, .. } => NODE
                        .saturating_add(charge_action_key(&event.scope, prefix))
                        .saturating_add(charge_text(&event.record_id))
                        .saturating_add(charge_text(reason)),
                });
            }
        }
        RibEventKind::EndOfRib(_) => {
            charge = charge
                .saturating_add(NODE)
                .saturating_add(charge_scope(&event.scope))
                .saturating_add(8)
                .saturating_add(charge_text(&event.record_id))
        }
        _ => (),
    }
    // Any record collision or peer mismatch may additionally retain a gap.
    charge
        .saturating_add(NODE.saturating_mul(2))
        .saturating_add(charge_scope(&event.scope))
        .saturating_add(charge_text(&event.record_id))
        .saturating_add(charge_session(&session))
        .saturating_add(8)
}
fn charge_metadata_delta(old: &AdjRibIn, stage: &AdjRibIn, session: &SessionKey) -> usize {
    let mut charge = 0usize;
    if !old.generations.contains_key(session) && stage.generations.contains_key(session) {
        charge = charge
            .saturating_add(NODE)
            .saturating_add(charge_session(session))
            .saturating_add(8);
    }
    if !old.tainted_sessions.contains(session) && stage.tainted_sessions.contains(session) {
        charge = charge
            .saturating_add(NODE)
            .saturating_add(charge_session(session));
    }
    for (scope, record) in &stage.gaps {
        charge = charge
            .saturating_add(NODE)
            .saturating_add(charge_scope(scope))
            .saturating_add(charge_text(record));
        let key = (scope.session_key(), scope.generation);
        if !old.gap_index.contains(&key) {
            charge = charge
                .saturating_add(NODE)
                .saturating_add(charge_session(&key.0))
                .saturating_add(8);
        }
    }
    for marker in &stage.eors {
        charge = charge
            .saturating_add(NODE)
            .saturating_add(charge_scope(&marker.scope))
            .saturating_add(8)
            .saturating_add(charge_text(&marker.record_id));
    }
    for rejection in &stage.rejections {
        charge = charge
            .saturating_add(NODE)
            .saturating_add(charge_key(&rejection.key))
            .saturating_add(charge_text(&rejection.record_id))
            .saturating_add(charge_text(&rejection.reason));
    }
    charge
}
fn event_actions(event: &RibEvent) -> usize {
    match &event.kind {
        RibEventKind::Update(actions) => actions.len(),
        _ => 1,
    }
}
fn base_scope(scope: &RibScope) -> RibScope {
    let mut base = scope.clone();
    base.peer = None;
    base
}
fn same_session_identity(scope: &RibScope, source: &SourcePartition, session: &str) -> bool {
    scope.source == *source && scope.session == session
}
fn same_session(scope: &RibScope, session: &SessionKey) -> bool {
    same_session_identity(scope, &session.source, &session.session)
}
fn validate_generation(event: &RibEvent, current: Option<u64>) -> Result<()> {
    if let RibEventKind::Reset {
        previous_generation,
        ..
    } = event.kind
    {
        if event.scope.direction.is_some()
            || current != Some(previous_generation)
            || event.scope.generation <= previous_generation
            || event.scope.source.kind == PartitionKind::Imported
                && previous_generation.checked_add(1) != Some(event.scope.generation)
        {
            return Err(bad(
                "bgp_rib_reset",
                0,
                "explicit advancing predecessor required",
            ));
        }
    } else if current.is_some_and(|g| event.scope.generation > g) {
        return Err(bad(
            "bgp_rib_generation",
            0,
            "generation change needs reset",
        ));
    }
    Ok(())
}
fn reserve_append<T>(old: &Vec<T>, count: usize) -> Result<Option<Vec<T>>> {
    let needed = old
        .len()
        .checked_add(count)
        .ok_or_else(|| Error::limit("bgp_rib_budget"))?;
    if needed <= old.capacity() {
        return Ok(None);
    }
    let capacity = needed.max(old.len().saturating_mul(2));
    let mut replacement = Vec::new();
    replacement
        .try_reserve_exact(capacity)
        .map_err(|_| Error::limit("bgp_rib_allocation"))?;
    Ok(Some(replacement))
}
fn append_reserved<T>(old: &mut Vec<T>, additions: &mut Vec<T>, replacement: Option<Vec<T>>) {
    if let Some(mut replacement) = replacement {
        replacement.append(old);
        *old = replacement;
    }
    old.append(additions);
}

#[cfg(test)]
mod prepared_transaction_tests {
    use super::*;
    fn gap(id: &str) -> RibEvent {
        RibEvent {
            scope: RibScope {
                source: SourcePartition {
                    kind: PartitionKind::Captured,
                    source_id: "a".into(),
                    partition_id: "p".into(),
                },
                session: "s".into(),
                generation: 0,
                direction: None,
                peer: None,
            },
            record_id: id.into(),
            kind: RibEventKind::Gap { reason: "x".into() },
        }
    }
    #[test]
    fn prepared_rib_owner_revision_and_no_publication() {
        let mut rib = AdjRibIn::new(Limits::default()).unwrap();
        let plan = rib.prepare(gap("a")).unwrap();
        assert_eq!(plan.status(), ApplyStatus::Applied);
        assert!(rib.events().is_empty() && rib.gaps().is_empty());
        assert_eq!((rib.retained_bytes(), rib.accounted_work()), (0, 0));
        assert!(rib.prepared_current(&plan));
        assert!(!rib.clone().prepared_current(&plan));
        rib.apply(gap("b")).unwrap();
        assert!(!rib.prepared_current(&plan));
        let before = (
            rib.events().to_vec(),
            rib.retained_bytes(),
            rib.accounted_work(),
        );
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| rib.commit(plan))).is_err()
        );
        assert_eq!(
            (
                rib.events().to_vec(),
                rib.retained_bytes(),
                rib.accounted_work()
            ),
            before
        );
        let current = rib.prepare(gap("c")).unwrap();
        assert!(rib.prepared_current(&current));
        assert_eq!(rib.commit(current), ApplyStatus::Applied);
        assert_eq!(rib.events().len(), 2);
    }
    #[test]
    fn prepared_origin_replay_stages_only_evidence_and_invalidates_pending_plan() {
        let mut event = gap("r");
        event.scope.direction = Some(0);
        event.kind = RibEventKind::Update(vec![RibAction::Announce {
            prefix: PrefixIdentity {
                afi: 1,
                safi: 1,
                length: 0,
                address: "0.0.0.0".into(),
            },
            path_id: PathId::Absent,
            attributes: Json::Null,
            attribute_identity: "i".into(),
        }]);
        let mut rib = AdjRibIn::new(Limits::default()).unwrap();
        rib.apply_with_origin(event.clone(), [1; 32]).unwrap();
        let plan = rib.prepare_with_origin(event.clone(), [2; 32]).unwrap();
        let stale = rib.prepare_with_origin(event.clone(), [3; 32]).unwrap();
        assert_eq!(plan.status(), ApplyStatus::IdenticalReplay);
        assert_eq!(
            rib.entries().values().next().unwrap().versions[0]
                .occurrences
                .len(),
            1
        );
        assert!(rib.prepared_current(&plan));
        assert!(!rib.clone().prepared_current(&plan));
        rib.commit(plan);
        assert_eq!(rib.events().len(), 1);
        assert!(!rib.prepared_current(&stale));
        assert_eq!(
            rib.entries().values().next().unwrap().versions[0]
                .occurrences
                .len(),
            2
        );
        let inert = rib.prepare_with_origin(event, [2; 32]).unwrap();
        let before = (
            rib.retained_bytes(),
            rib.accounted_work(),
            rib.transaction_diagnostics(),
        );
        rib.commit(inert);
        assert_eq!(
            (
                rib.retained_bytes(),
                rib.accounted_work(),
                rib.transaction_diagnostics()
            ),
            before
        );
    }
    #[test]
    fn embedded_projection_preserves_native_caps_and_separate_output_units() {
        // Public output cap1 is valid configuration and belongs to the outer
        // encoder. Native Gap charges remain the independent5026/13086 oracle.
        let limits = Limits {
            output_bytes: 1,
            retained_bytes: 5026,
            work: 13086,
            ..Limits::default()
        };
        assert!(AdjRibIn::new(limits.clone())
            .unwrap()
            .apply(gap("g"))
            .is_err());
        let mut rib = AdjRibIn::for_embedded_projection(limits).unwrap();
        assert_eq!(rib.apply(gap("g")).unwrap(), ApplyStatus::Applied);
        assert_eq!((rib.retained_bytes(), rib.accounted_work()), (5026, 13086));
        for limits in [
            Limits {
                output_bytes: 1,
                retained_bytes: 5025,
                ..Limits::default()
            },
            Limits {
                output_bytes: 1,
                work: 13085,
                ..Limits::default()
            },
            Limits {
                output_bytes: 1,
                elements: 1,
                ..Limits::default()
            },
        ] {
            let mut rib = AdjRibIn::for_embedded_projection(limits).unwrap();
            // Element refusal needs two actions; the other caps use the Gap.
            let event = if rib.limits.elements == 1 {
                let mut event = gap("r");
                event.scope.direction = Some(0);
                let action = RibAction::Withdraw {
                    prefix: PrefixIdentity {
                        afi: 1,
                        safi: 1,
                        length: 0,
                        address: "0.0.0.0".into(),
                    },
                    path_id: PathId::Absent,
                };
                event.kind = RibEventKind::Update(vec![action.clone(), action]);
                event
            } else {
                gap("g")
            };
            assert!(rib.apply(event).is_err());
            assert!(rib.events().is_empty() && rib.entries().is_empty() && rib.gaps().is_empty());
            assert_eq!((rib.retained_bytes(), rib.accounted_work()), (0, 0));
            assert_eq!(
                rib.transaction_diagnostics(),
                RibTransactionDiagnostics::default()
            );
        }
        assert!(AdjRibIn::for_embedded_projection(Limits {
            output_bytes: 0,
            ..Limits::default()
        })
        .is_err());
        let defaults = Limits::default();
        let embedded = AdjRibIn::for_embedded_projection(defaults.clone()).unwrap();
        assert_eq!(embedded.limits.output_bytes, defaults.output_bytes);
        assert_eq!(embedded.limits.retained_bytes, defaults.retained_bytes);
        assert_eq!(embedded.limits.work, defaults.work);
        assert_eq!(embedded.limits.elements, defaults.elements);
        let high = AdjRibIn::for_embedded_projection(Limits {
            output_bytes: usize::MAX,
            retained_bytes: usize::MAX,
            ..defaults.clone()
        })
        .unwrap();
        assert_eq!(high.limits.output_bytes, defaults.output_bytes);
        let lower = AdjRibIn::for_embedded_projection(Limits {
            output_bytes: 1,
            retained_bytes: 4096,
            ..defaults
        })
        .unwrap();
        assert_eq!(lower.limits.output_bytes, 4096);
    }
    fn update(id: &str) -> RibEvent {
        let mut event = gap(id);
        event.scope.direction = Some(0);
        event.scope.peer = Some("peer-a".into());
        event.kind = RibEventKind::Update(vec![RibAction::Announce {
            prefix: PrefixIdentity {
                afi: 1,
                safi: 1,
                length: 0,
                address: "0.0.0.0".into(),
            },
            path_id: PathId::Absent,
            attributes: Json::Null,
            attribute_identity: "i".into(),
        }]);
        event
    }
    #[test]
    fn native_continuity_gap_and_reset_match_actual_generation_effect() {
        let mut rib = AdjRibIn::new(Limits::default()).unwrap();
        let mut boundary = gap("gap");
        boundary.scope.direction = Some(0);
        boundary.scope.peer = Some("reported-peer".into());
        let plan = rib.prepare(boundary.clone()).unwrap();
        let effect = plan.continuity_effect().unwrap();
        assert_eq!(effect.status, ApplyStatus::Applied);
        assert_eq!(effect.kind, NativeContinuityKind::Gap);
        assert_eq!(effect.effect, NativeContinuityEffect::SessionGeneration);
        assert_eq!(effect.reason, "x");
        for direction in [None, Some(0), Some(1)] {
            let mut candidate = boundary.scope.clone();
            candidate.direction = direction;
            candidate.peer = Some("other-peer".into());
            assert!(continuity_affects_scope(
                effect.kind,
                effect.effect,
                effect.scope,
                &candidate
            ));
        }
        for neighbor in 0..3 {
            let mut candidate = boundary.scope.clone();
            match neighbor {
                0 => candidate.generation = 1,
                1 => candidate.session = "other".into(),
                _ => candidate.source.partition_id = "other".into(),
            }
            assert!(!continuity_affects_scope(
                effect.kind,
                effect.effect,
                effect.scope,
                &candidate
            ));
        }
        assert!(rib.events().is_empty() && rib.gaps().is_empty());
        rib.commit(plan);
        assert!(rib
            .prepare(boundary.clone())
            .unwrap()
            .continuity_effect()
            .is_none());
        let mut reset = gap("reset");
        reset.scope.generation = 2;
        reset.kind = RibEventKind::Reset {
            previous_generation: 0,
            reason: "explicit-reset".into(),
        };
        let plan = rib.prepare(reset.clone()).unwrap();
        let effect = plan.continuity_effect().unwrap();
        assert_eq!(
            effect.kind,
            NativeContinuityKind::Reset {
                previous_generation: 0,
                next_generation: 2
            }
        );
        assert_eq!(effect.reason, "explicit-reset");
        assert!(continuity_affects_scope(
            effect.kind,
            effect.effect,
            effect.scope,
            &boundary.scope
        ));
        let mut skipped = boundary.scope.clone();
        skipped.generation = 1;
        assert!(!continuity_affects_scope(
            effect.kind,
            effect.effect,
            effect.scope,
            &skipped
        ));
        assert!(!continuity_affects_scope(
            effect.kind,
            effect.effect,
            effect.scope,
            &reset.scope
        ));
        rib.commit(plan);
        assert!(rib.prepare(reset).unwrap().continuity_effect().is_none());
        boundary.record_id = "historical-gap".into();
        let historical = rib.prepare(boundary).unwrap();
        assert_eq!(historical.status(), ApplyStatus::Historical);
        assert!(historical.continuity_effect().is_none());
    }
    #[test]
    fn native_continuity_collision_all_generations_and_tainted_noop() {
        let mut rib = AdjRibIn::new(Limits::default()).unwrap();
        let first = update("collision");
        rib.apply(first.clone()).unwrap();
        let mut reset = gap("reset");
        reset.scope.generation = 1;
        reset.kind = RibEventKind::Reset {
            previous_generation: 0,
            reason: "explicit".into(),
        };
        rib.apply(reset).unwrap();
        let mut conflict = first.clone();
        if let RibEventKind::Update(actions) = &mut conflict.kind {
            if let RibAction::Announce {
                attribute_identity, ..
            } = &mut actions[0]
            {
                *attribute_identity = "different".into();
            }
        }
        let plan = rib.prepare(conflict).unwrap();
        let effect = plan.continuity_effect().unwrap();
        assert_eq!(effect.status, ApplyStatus::IdentityConflict);
        assert_eq!(effect.effect, NativeContinuityEffect::SessionAllGenerations);
        assert_eq!(effect.reason, "record_identity_conflict");
        for generation in [0, 1, 2] {
            let mut candidate = first.scope.clone();
            candidate.generation = generation;
            candidate.direction = Some(1);
            candidate.peer = None;
            assert!(continuity_affects_scope(
                effect.kind,
                effect.effect,
                effect.scope,
                &candidate
            ));
        }
        let mut other = first.scope.clone();
        other.session = "other".into();
        assert!(!continuity_affects_scope(
            effect.kind,
            effect.effect,
            effect.scope,
            &other
        ));
        rib.commit(plan);
        let mut tainted = update("new-tainted");
        tainted.scope.generation = 1;
        let plan = rib.prepare(tainted).unwrap();
        assert_eq!(plan.status(), ApplyStatus::IdentityConflict);
        assert!(plan.continuity_effect().is_none());
        let replay = rib.prepare(first).unwrap();
        assert_eq!(replay.status(), ApplyStatus::IdenticalReplay);
        assert!(replay.continuity_effect().is_none());
    }
    #[test]
    fn native_continuity_peer_mismatch_is_directional_and_noop_branches_inert() {
        let mut rib = AdjRibIn::new(Limits::default()).unwrap();
        let first = update("first");
        rib.apply_with_origin(first.clone(), [1; 32]).unwrap();
        let ordinary = rib.prepare(update("ordinary")).unwrap();
        assert!(ordinary.continuity_effect().is_none());
        for kind in [
            RibEventKind::EndOfRib(Family { afi: 1, safi: 1 }),
            RibEventKind::Stale {
                family: Family { afi: 1, safi: 1 },
                kind: StaleKind::Graceful,
            },
        ] {
            let mut event = update("ordinary-control");
            event.kind = kind;
            let plan = rib.prepare(event).unwrap();
            assert_eq!(plan.status(), ApplyStatus::Applied);
            assert!(plan.continuity_effect().is_none());
        }
        let mut directionless = update("directionless");
        directionless.scope.direction = None;
        let missing = rib.prepare(directionless).unwrap();
        assert_eq!(missing.status(), ApplyStatus::MissingScope);
        assert!(missing.continuity_effect().is_none());
        let origin_only = rib.prepare_with_origin(first.clone(), [2; 32]).unwrap();
        assert_eq!(origin_only.status(), ApplyStatus::IdenticalReplay);
        assert!(origin_only.continuity_effect().is_none());
        let mut drift = update("drift");
        drift.scope.peer = Some("peer-b".into());
        let plan = rib.prepare(drift.clone()).unwrap();
        let effect = plan.continuity_effect().unwrap();
        assert_eq!(effect.status, ApplyStatus::MissingScope);
        assert_eq!(
            effect.effect,
            NativeContinuityEffect::BaseDirectionalGeneration
        );
        assert_eq!(effect.reason, "peer_binding_mismatch");
        assert!(continuity_affects_scope(
            effect.kind,
            effect.effect,
            effect.scope,
            &first.scope
        ));
        let mut candidate = drift.scope.clone();
        candidate.peer = None;
        assert!(continuity_affects_scope(
            effect.kind,
            effect.effect,
            effect.scope,
            &candidate
        ));
        for direction in [None, Some(1)] {
            candidate.direction = direction;
            assert!(!continuity_affects_scope(
                effect.kind,
                effect.effect,
                effect.scope,
                &candidate
            ));
        }
        candidate = first.scope.clone();
        candidate.generation = 1;
        assert!(!continuity_affects_scope(
            effect.kind,
            effect.effect,
            effect.scope,
            &candidate
        ));
        candidate = first.scope.clone();
        candidate.source.source_id = "other".into();
        assert!(!continuity_affects_scope(
            effect.kind,
            effect.effect,
            effect.scope,
            &candidate
        ));
        rib.commit(plan);
        assert!(rib.prepare(drift).unwrap().continuity_effect().is_none());
    }
}
