//! Versioned, source-partitioned Adj-RIB-In *candidates*. No endpoint RIB is read.
//! Input order is an explicit replay assertion; clocks and labels never order it.
use super::bgp_session::{Family, PartitionKind, SessionKey, SourcePartition, StaleKind};
use super::bgp_state::{tree_budget, CandidateState, PrefixIdentity, RoutePathId};
use super::model::{bad, Limits};
use pcap_evidence::{json::Json, sha256, Error, Result};
use std::collections::{BTreeMap, BTreeSet};
use std::net::{Ipv4Addr, Ipv6Addr};

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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteVersion {
    pub attributes: Json,
    pub attribute_identity: String,
    pub witnesses: Vec<String>,
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

#[derive(Clone)]
pub struct AdjRibIn {
    limits: Limits,
    events: Vec<RibEvent>,
    entries: BTreeMap<RouteKey, RouteEntry>,
    generations: BTreeMap<SessionKey, u64>,
    gaps: Vec<(RibScope, String)>,
    eors: Vec<FamilyMarker>,
    rejections: Vec<RejectedRecord>,
    tainted_sessions: BTreeSet<SessionKey>,
    legacy: Option<LegacyAdapter>,
}
impl AdjRibIn {
    pub fn new(limits: Limits) -> Result<Self> {
        limits.validate()?;
        Ok(Self {
            limits,
            events: Vec::new(),
            entries: BTreeMap::new(),
            generations: BTreeMap::new(),
            gaps: Vec::new(),
            eors: Vec::new(),
            rejections: Vec::new(),
            tainted_sessions: BTreeSet::new(),
            legacy: None,
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
    pub fn retained_bytes(&self) -> usize {
        self.accounted_size()
    }
    pub fn accounted_work(&self) -> usize {
        self.accounted_size().saturating_mul(3)
    }
    fn accounted_size(&self) -> usize {
        format!(
            "{:?}{:?}{:?}{:?}{:?}{:?}",
            self.events,
            self.entries,
            self.generations,
            self.gaps,
            self.eors,
            self.tainted_sessions
        )
        .len()
        .saturating_add(format!("{:?}", self.rejections).len())
        .saturating_add(
            self.legacy
                .as_ref()
                .map_or(0, |l| l.snapshot.retained_bytes()),
        )
    }
    pub fn apply(&mut self, event: RibEvent) -> Result<ApplyStatus> {
        if self.legacy.is_some() {
            return Err(bad("bgp_rib_legacy", 0, "legacy projection is read only"));
        }
        validate_event(&event, &self.limits)?;
        if self.events.iter().any(|old| old == &event) {
            return Ok(ApplyStatus::IdenticalReplay);
        }
        let mut next = self.clone();
        let conflict = next.events.iter().any(|old| {
            old.scope.session_key() == event.scope.session_key() && old.record_id == event.record_id
        });
        let status = next.apply_inner(&event, conflict)?;
        next.events.push(event);
        next.check_budget()?;
        *self = next;
        Ok(status)
    }
    fn apply_inner(&mut self, event: &RibEvent, conflict: bool) -> Result<ApplyStatus> {
        let session = event.scope.session_key();
        if self.tainted_sessions.contains(&session) {
            return Ok(ApplyStatus::IdentityConflict);
        }
        if conflict {
            self.quarantine_session(&session);
            self.tainted_sessions.insert(session);
            if let RibEventKind::Update(actions) = &event.kind {
                for action in actions {
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
                                disposition: VersionDisposition::Conflicting,
                            });
                            entry.status = RouteStatus::Unresolved;
                        }
                    }
                }
            }
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
                e.key.scope.session_key() == session
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
        ) && self.peer_binding_mismatch(&event.scope)
        {
            self.quarantine_scope(&event.scope);
            self.gaps
                .push((event.scope.clone(), event.record_id.clone()));
            return Ok(ApplyStatus::MissingScope);
        }
        let gap = self.gaps.iter().any(|(scope, _)| {
            scope.session_key() == session && scope.generation == event.scope.generation
        });
        match &event.kind {
            RibEventKind::Gap { .. } => {
                self.gaps
                    .push((event.scope.clone(), event.record_id.clone()));
                for entry in self.entries.values_mut().filter(|e| {
                    e.key.scope.session_key() == session
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
                for action in actions {
                    self.apply_action(&event.scope, &event.record_id, action, gap);
                }
            }
            RibEventKind::Reset { .. } => unreachable!(),
        }
        Ok(ApplyStatus::Applied)
    }
    fn apply_action(&mut self, scope: &RibScope, record_id: &str, action: &RibAction, gap: bool) {
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
                        disposition: VersionDisposition::Current,
                    });
                }
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
            .filter(|entry| entry.key.scope.session_key() == *session)
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
        self.events.iter().any(|old| {
            is_route_scoped(&old.kind)
                && same_base_scope(&old.scope, scope)
                && old.scope.peer != scope.peer
        })
    }
    fn check_budget(&self) -> Result<()> {
        let versions: usize = self.entries.values().map(|e| e.versions.len()).sum();
        let actions: usize = self
            .events
            .iter()
            .map(|event| match &event.kind {
                RibEventKind::Update(actions) => actions.len(),
                _ => 1,
            })
            .sum();
        if actions.saturating_add(versions) > self.limits.elements
            || self.entries.len() > self.limits.active
        {
            return Err(Error::limit("bgp_rib_elements"));
        }
        let size = self.accounted_size();
        if size > self.limits.retained_bytes
            || size > self.limits.output_bytes
            || self.accounted_work() > self.limits.work
        {
            return Err(Error::limit("bgp_rib_budget"));
        }
        Ok(())
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
    left.source == right.source
        && left.session == right.session
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
                        attributes.encode_bounded(limits.input_bytes)?;
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
