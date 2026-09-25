//! A bounded reduction of normalized observations, NOT a BGP RIB or best path.
//!
//! This opt-in API does not change the existing BGP decoder or event contracts.
//! Apply order is caller order. Provenance is retained and checked structurally,
//! not authenticated or re-derived from packet bytes by this consumer.
use super::bgp::{RouteAction, SourceKind, SCHEMA as ROUTE_SCHEMA};
use super::bgp_import::{GenerationBoundary, ImportContext, ImportPartition};
use super::model::{bad, Limits};
use pcap_evidence::{json::Json, sha256, Error, Result};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::{Ipv4Addr, Ipv6Addr};

pub const SCHEMA: &str = "pcap-evidence.bgp.candidate-state.v1";
const BOUNDARY_SCHEMA: &str = "pcap-evidence.bgp.candidate-boundary.v1";

/// Imported scope is an explicit caller assertion, never inferred from a peer,
/// timestamp, port, source preference, or the normalizer's placeholder zero.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ImportScope {
    pub generation: u64,
    pub direction: u8,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Source {
    pub kind: SourceKind,
    pub source_id: String,
    pub record_id: String,
    pub session: Option<String>,
    pub generation: Option<u64>,
    pub direction: Option<u8>,
    pub observed_at_ns: Option<i64>,
    pub peer: Option<String>,
    pub local: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObservationKind {
    Routes,
    Open,
    Notification,
    Keepalive,
    RouteRefresh,
    Reset,
}
impl ObservationKind {
    fn name(self) -> &'static str {
        match self {
            Self::Routes => "routes",
            Self::Open => "open",
            Self::Notification => "notification",
            Self::Keepalive => "keepalive",
            Self::RouteRefresh => "route_refresh",
            Self::Reset => "caller_reset",
        }
    }
}

/// The exact normalized prefix key. Noncanonical IP addresses are rejected, not
/// silently masked. Other AFI/SAFI values survive as unsupported observations.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct PrefixIdentity {
    pub afi: u16,
    pub safi: u8,
    pub length: u8,
    pub address: String,
}

/// The path identifier is part of an ADD-PATH route key. `Absent` is the
/// ordinary non-ADD-PATH layout; an unresolved layout never reaches this type.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum RoutePathId {
    Absent,
    Present(u32),
}
impl PrefixIdentity {
    fn supported(&self) -> bool {
        matches!(self.afi, 1 | 2) && matches!(self.safi, 1 | 2)
    }
    fn json(&self) -> Json {
        Json::object([
            ("afi", self.afi.into()),
            ("safi", self.safi.into()),
            ("length", self.length.into()),
            ("address", self.address.clone().into()),
        ])
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteObservation {
    prefix: PrefixIdentity,
    path_id: RoutePathId,
    action: RouteAction,
    attributes: Json,
    attribute_identity: Json,
    semantic_identity: Json,
    field_start: usize,
    field_end: usize,
    ambiguous_attributes: bool,
}
impl RouteObservation {
    pub fn prefix(&self) -> &PrefixIdentity {
        &self.prefix
    }
    pub fn path_id(&self) -> RoutePathId {
        self.path_id
    }
    pub fn action(&self) -> RouteAction {
        self.action
    }
    /// All supplied fields, including unknown fields, are retained, not interpreted.
    pub fn attributes(&self) -> &Json {
        &self.attributes
    }
    /// Canonical identity of every path-attribute occurrence after removing
    /// source offsets. This is evidence identity, not policy equivalence.
    pub fn attribute_identity(&self) -> &Json {
        &self.attribute_identity
    }
    /// Versioned source-neutral comparison identity, when supplied by a
    /// producer. It is informational and never merges source partitions.
    pub fn semantic_identity(&self) -> &Json {
        &self.semantic_identity
    }
    pub fn field_range(&self) -> std::ops::Range<usize> {
        self.field_start..self.field_end
    }
    pub fn ambiguous_attributes(&self) -> bool {
        self.ambiguous_attributes
    }
}

/// Immutable, validated observation. Retain the original normalized envelope:
/// route references in state output resolve through this ordered journal.
#[derive(Clone, Debug)]
pub struct Observation {
    source: Source,
    kind: ObservationKind,
    routes: Vec<RouteObservation>,
    normalized: Json,
    encoded: String,
    identity: Identity,
    nodes: usize,
    spans: usize,
    import_context: Option<ImportContext>,
    import_boundary: Option<GenerationBoundary>,
}

// Sources of different kinds are never merged, even if all other labels agree.
type SessionKey = (u8, String, String, Option<ImportPartition>);
// Captured locators distinguish repeated wire messages from replay of one record.
// The locator contains packets/spans, NOT a possibly mislabeled payload digest.
type Identity = (u8, String, Option<String>, String, String);
type RouteKey = (SessionKey, u8, PrefixIdentity, RoutePathId);

impl Observation {
    pub fn from_normalized(
        value: &Json,
        imported_scope: Option<ImportScope>,
        limits: &Limits,
    ) -> Result<Self> {
        limits.validate()?;
        let stats = tree_budget(value, limits)?;
        value.encode_bounded(limits.input_bytes)?;
        if text(member(value, "schema")?)? != ROUTE_SCHEMA {
            return Err(bad(
                "bgp_state_schema",
                0,
                "expected normalized route evidence",
            ));
        }
        for name in ["endpoint_state_established", "causality_established"] {
            if member(value, name)? != &Json::Bool(false) {
                return Err(bad(
                    "bgp_state_authority",
                    0,
                    "authority claims are not accepted",
                ));
            }
        }
        for name in [
            "rib_established",
            "best_path_selected",
            "reachability_established",
            "source_authority_established",
            "normative_conformance_certified",
        ] {
            if optional_member(value, name)?.is_some_and(|claim| claim != &Json::Bool(false)) {
                return Err(bad(
                    "bgp_state_authority",
                    0,
                    "optional authority claims must be absent or false",
                ));
            }
        }
        let kind = match text(member(value, "source_kind")?)? {
            "captured" => SourceKind::Captured,
            "imported" => SourceKind::Imported,
            _ => return Err(bad("bgp_state_source", 0, "unknown source kind")),
        };
        let mut source = Source {
            kind,
            source_id: identity_text(member(value, "source_id")?)?,
            record_id: identity_text(member(value, "record_id")?)?,
            session: optional_identity(member(value, "session")?)?,
            generation: if member(value, "generation")? == &Json::Null {
                None
            } else {
                Some(number(member(value, "generation")?)?)
            },
            direction: optional_direction(member(value, "direction")?)?,
            observed_at_ns: optional_time(member(value, "observed_at_ns")?)?,
            peer: optional_text(member(value, "peer")?)?,
            local: optional_text(member(value, "local")?)?,
        };
        let message = number(member(value, "message_type")?)?;
        let mut observation_kind = match (kind, message) {
            (SourceKind::Imported, 0) | (SourceKind::Captured, 2) => ObservationKind::Routes,
            (SourceKind::Captured, 1) => ObservationKind::Open,
            (SourceKind::Captured, 3) => ObservationKind::Notification,
            (SourceKind::Captured, 4) => ObservationKind::Keepalive,
            (SourceKind::Captured, 5) => ObservationKind::RouteRefresh,
            _ => return Err(bad("bgp_state_message", 0, "source/message type mismatch")),
        };
        for issue in array(member(value, "issues")?)? {
            text(issue)?;
        }
        let import_context = match optional_member(value, "import_context")? {
            None | Some(Json::Null) => None,
            Some(context) => Some(ImportContext::from_json(context, limits)?),
        };
        let import_boundary = match optional_member(value, "import_boundary")? {
            None | Some(Json::Null) => None,
            Some(boundary) => {
                let context = import_context
                    .as_ref()
                    .ok_or_else(|| bad("bgp_import_boundary", 0, "boundary context missing"))?;
                Some(GenerationBoundary::from_json(boundary, context, limits)?)
            }
        };
        let evidence = member(value, "evidence")?;
        let (extent, span_count, locator) = match kind {
            SourceKind::Captured => {
                if imported_scope.is_some() || import_context.is_some() || import_boundary.is_some()
                {
                    return Err(bad(
                        "bgp_state_scope",
                        0,
                        "cannot override captured scope or assert import context",
                    ));
                }
                if source.generation.is_none() {
                    return Err(bad("bgp_state_scope", 0, "captured generation is required"));
                }
                captured_evidence(evidence, limits)?
            }
            SourceKind::Imported => {
                if evidence != &Json::Null {
                    return Err(bad(
                        "bgp_state_import",
                        0,
                        "imported observations cannot assert wire evidence",
                    ));
                }
                if let Some(context) = &import_context {
                    if imported_scope.is_some()
                        || source.source_id != context.source_id
                        || source.session.as_deref() != Some(context.session.as_str())
                        || source.generation != Some(context.generation)
                        || source.direction != context.direction
                        || source.peer != context.peer
                        || source.local != context.local
                    {
                        return Err(bad(
                            "bgp_import_context",
                            0,
                            "envelope and context identities disagree or scope was overridden",
                        ));
                    }
                    if import_boundary.is_some() {
                        observation_kind = ObservationKind::Reset;
                    }
                    // Record identity is immutable inside its batch/checkpoint.
                    // Changing generation/direction on the SAME record is not a
                    // fresh observation; canonical content then exposes conflict.
                    let locator = context
                        .partition()
                        .json()
                        .encode_bounded(limits.input_bytes)?;
                    (0, context.provenance.len(), locator)
                } else {
                    // v1 compatibility: old zero was a placeholder, never evidence.
                    if source.direction.is_some() || !matches!(source.generation, None | Some(0)) {
                        return Err(bad(
                            "bgp_state_import",
                            0,
                            "unscoped legacy import cannot assert generation or direction",
                        ));
                    }
                    source.generation = imported_scope.map(|s| s.generation);
                    source.direction = imported_scope.map(|s| s.direction);
                    if source.direction.is_some_and(|d| d > 1) {
                        return Err(bad(
                            "bgp_state_direction",
                            0,
                            "direction must be zero or one",
                        ));
                    }
                    (0, 0, String::new())
                }
            }
        };
        let raw_routes = array(member(value, "routes")?)?;
        if raw_routes.len() > limits.elements {
            return Err(Error::limit("bgp_state_routes"));
        }
        if observation_kind != ObservationKind::Routes && !raw_routes.is_empty() {
            return Err(bad(
                "bgp_state_message",
                0,
                "control message contains routes",
            ));
        }
        let mut routes = Vec::new();
        for raw in raw_routes {
            routes.push(parse_route(raw, kind, extent, limits)?);
        }
        let mut observation = Self::finish(
            source,
            observation_kind,
            routes,
            value,
            locator,
            stats.nodes,
            span_count,
            limits,
        )?;
        observation.import_context = import_context;
        observation.import_boundary = import_boundary;
        Ok(observation)
    }

    /// Establish a new caller-assigned generation, with an explicit reason and
    /// source record. This is not a synthetic wire NOTIFICATION. The generation
    /// must advance to affect existing state; counters never wrap or saturate.
    pub fn reset(source: Source, reason: &str, evidence: Json, limits: &Limits) -> Result<Self> {
        limits.validate()?;
        tree_budget(&evidence, limits)?;
        evidence.encode_bounded(limits.input_bytes)?;
        // Optional packet/span lists in caller boundary context consume the same
        // retention budget. Counting them does not certify their provenance.
        let mut context_references = 0;
        if let Json::Object(items) = &evidence {
            for (name, value) in items {
                if matches!(*name, "spans" | "packets") {
                    context_references =
                        add(context_references, array(value)?.len(), "bgp_state_spans")?;
                }
            }
        }
        if context_references > limits.spans {
            return Err(Error::limit("bgp_state_spans"));
        }
        for text in [&source.source_id, &source.record_id]
            .into_iter()
            .chain(source.session.iter())
            .chain(source.peer.iter())
            .chain(source.local.iter())
        {
            if text.len() > limits.input_bytes {
                return Err(Error::limit("bgp_state_input"));
            }
        }
        if reason.len() > limits.input_bytes {
            return Err(Error::limit("bgp_state_input"));
        }
        if source.session.is_none() || source.generation.is_none() || source.direction.is_some() {
            return Err(bad(
                "bgp_state_reset",
                0,
                "reset requires session/generation and no direction",
            ));
        }
        let raw = Json::object([
            ("schema", BOUNDARY_SCHEMA.into()),
            ("source", source_json(&source)),
            ("reason", reason.into()),
            ("evidence", evidence),
            (
                "basis",
                "caller_asserted_boundary_not_wire_notification".into(),
            ),
        ]);
        limits.validate()?;
        let stats = tree_budget(&raw, limits)?;
        raw.encode_bounded(limits.input_bytes)?;
        identity_text(&Json::String(source.source_id.clone()))?;
        identity_text(&Json::String(source.record_id.clone()))?;
        if let Some(s) = &source.session {
            identity_text(&Json::String(s.clone()))?;
        }
        if reason.is_empty() {
            return Err(bad("bgp_state_reset", 0, "reason required"));
        }
        Self::finish(
            source,
            ObservationKind::Reset,
            Vec::new(),
            &raw,
            String::new(),
            stats.nodes,
            context_references,
            limits,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn finish(
        source: Source,
        kind: ObservationKind,
        routes: Vec<RouteObservation>,
        value: &Json,
        locator: String,
        nodes: usize,
        spans: usize,
        limits: &Limits,
    ) -> Result<Self> {
        let normalized = canonical(value);
        let identity = (
            source_code(source.kind),
            source.source_id.clone(),
            source.session.clone(),
            source.record_id.clone(),
            locator,
        );
        let encoded = Json::object([
            ("source", source_json(&source)),
            ("kind", kind.name().into()),
            ("normalized", normalized.clone()),
        ])
        .encode_bounded(limits.retained_bytes)?;
        Ok(Self {
            source,
            kind,
            routes,
            normalized,
            encoded,
            identity,
            nodes,
            spans,
            import_context: None,
            import_boundary: None,
        })
    }
    pub fn import_context(&self) -> Option<&ImportContext> {
        self.import_context.as_ref()
    }
    pub fn import_boundary(&self) -> Option<&GenerationBoundary> {
        self.import_boundary.as_ref()
    }
    pub fn source(&self) -> &Source {
        &self.source
    }
    pub fn kind(&self) -> ObservationKind {
        self.kind
    }
    pub fn routes(&self) -> &[RouteObservation] {
        &self.routes
    }
    pub fn normalized(&self) -> &Json {
        &self.normalized
    }
    pub fn sha256(&self) -> [u8; 32] {
        sha256::digest(self.encoded.as_bytes())
    }
    pub(super) fn batch_work(&self) -> Result<usize> {
        observation_work(self, self.nodes)
    }
    fn session_key(&self) -> Option<SessionKey> {
        self.source.session.as_ref().map(|s| {
            (
                source_code(self.source.kind),
                self.source.source_id.clone(),
                s.clone(),
                self.import_context.as_ref().map(ImportContext::partition),
            )
        })
    }
    fn json(&self) -> Json {
        Json::object([
            ("source", source_json(&self.source)),
            ("kind", self.kind.name().into()),
            ("observation_sha256", sha256::hex(&self.sha256()).into()),
            ("normalized", self.normalized.clone()),
        ])
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApplyStatus {
    Applied,
    IdenticalReplay,
    MissingScope,
    LateGeneration,
    ClosedGeneration,
    IdentityConflict,
    Reset,
    NonAdvancingReset,
    Notification,
    MetadataOnly,
}
impl ApplyStatus {
    fn name(self) -> &'static str {
        match self {
            Self::Applied => "applied",
            Self::IdenticalReplay => "identical_replay",
            Self::MissingScope => "missing_scope",
            Self::LateGeneration => "late_generation",
            Self::ClosedGeneration => "closed_generation",
            Self::IdentityConflict => "record_identity_conflict",
            Self::Reset => "caller_generation_reset",
            Self::NonAdvancingReset => "nonadvancing_reset",
            Self::Notification => "notification_closes_generation",
            Self::MetadataOnly => "metadata_only",
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EffectKind {
    Announced,
    RepeatedAnnouncement,
    ConflictingAnnouncement,
    Withdrawn,
    AbsentWithdrawal,
    MixedActions,
    UnsupportedPrefix,
}
impl EffectKind {
    fn name(self) -> &'static str {
        match self {
            Self::Announced => "announced_candidate",
            Self::RepeatedAnnouncement => "repeated_announcement",
            Self::ConflictingAnnouncement => "conflicting_attributes",
            Self::Withdrawn => "withdrawn_candidate",
            Self::AbsentWithdrawal => "withdrawal_of_absent_candidate",
            Self::MixedActions => "ambiguous_actions_in_record",
            Self::UnsupportedPrefix => "unsupported_prefix_semantics",
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteEffect {
    pub prefix: PrefixIdentity,
    pub path_id: RoutePathId,
    pub kind: EffectKind,
    /// Indices into this observation, including duplicate routes in one record.
    pub routes: Vec<usize>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApplyOutcome {
    pub observation: usize,
    pub status: ApplyStatus,
    pub effects: Vec<RouteEffect>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RouteRef {
    pub observation: usize,
    pub route: usize,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Alternative {
    pub action: RouteAction,
    pub attributes: Json,
    /// Ordered type/flags/opaque tokens; byte offsets are NOT path identity.
    pub attribute_identity: Json,
    pub ambiguous_attributes: bool,
    pub witnesses: Vec<RouteRef>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidateRoute {
    pub source_kind: SourceKind,
    pub source_id: String,
    pub session: String,
    pub generation: u64,
    pub direction: u8,
    pub prefix: PrefixIdentity,
    pub path_id: RoutePathId,
    pub alternatives: Vec<Alternative>,
    pub import_partition: Option<ImportPartition>,
}
impl CandidateRoute {
    pub fn conflicting(&self) -> bool {
        self.alternatives.len() != 1
            || self
                .alternatives
                .iter()
                .any(|a| a.ambiguous_attributes || a.action == RouteAction::Withdraw)
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionView {
    pub source_kind: SourceKind,
    pub source_id: String,
    pub session: String,
    pub generation: u64,
    pub closed: bool,
    pub identity_conflict: bool,
    /// Journal entry that established the currently displayed generation.
    pub generation_witness: usize,
    pub import_partition: Option<ImportPartition>,
}

/// Bounded journal and derived view. All successful observations remain in the
/// journal, even after withdrawals/resets. Exhaustion returns Err without mutation:
/// callers must stop/cut explicitly, never silently evict history and continue.
/// Rebuilding derived views is transactional and simplifies fail-closed
/// reclassification of earlier rows after a record-identity conflict. Bulk
/// callers should use `apply_batch` so a source snapshot is reduced only once.
#[derive(Clone)]
pub struct CandidateState {
    limits: Limits,
    observations: Vec<Observation>,
    routes: Vec<CandidateRoute>,
    sessions: Vec<SessionView>,
    outcomes: Vec<ApplyOutcome>,
    encoded: String,
    retained: usize,
    last_work: usize,
}
impl CandidateState {
    pub fn new(limits: Limits) -> Result<Self> {
        limits.validate()?;
        let encoded = snapshot_json(&[], &[], &[], &[]).encode_bounded(limits.output_bytes)?;
        if encoded.len() > limits.retained_bytes {
            return Err(Error::limit("bgp_state_retained_bytes"));
        }
        let retained = encoded.len();
        Ok(Self {
            limits,
            observations: Vec::new(),
            routes: Vec::new(),
            sessions: Vec::new(),
            outcomes: Vec::new(),
            encoded,
            retained,
            last_work: 0,
        })
    }
    pub fn observations(&self) -> &[Observation] {
        &self.observations
    }
    pub fn routes(&self) -> &[CandidateRoute] {
        &self.routes
    }
    pub fn sessions(&self) -> &[SessionView] {
        &self.sessions
    }
    pub fn outcomes(&self) -> &[ApplyOutcome] {
        &self.outcomes
    }
    /// This already-bounded serialized snapshot has no fallible deferred work.
    pub fn encode(&self) -> &str {
        &self.encoded
    }
    /// Rebuild the already-validated snapshot as a structured value for a
    /// bounded parent output. This is the same representation as `encode`;
    /// callers must still apply their own enclosing output budget.
    pub fn json(&self) -> Json {
        snapshot_json(
            &self.observations,
            &self.routes,
            &self.sessions,
            &self.outcomes,
        )
    }
    /// Logical accounting, not process RSS or allocator overhead.
    pub fn retained_bytes(&self) -> usize {
        self.retained
    }
    /// Logical budget units consumed by the most recent successful application
    /// call. This is deterministic accounting, not CPU time or process memory.
    pub fn last_work(&self) -> usize {
        self.last_work
    }

    /// Apply several observations as one atomic journal update. The ordinary
    /// context-free and contextual paths validate and reduce the complete batch
    /// once, avoiding repeated full-history rebuilds for large imported snapshots.
    /// Contextual generations and explicit boundaries are checked in caller order;
    /// mixed legacy/context batches use the sequential validator on a staged copy.
    /// Accepted receipts use the final batch classification so an identity
    /// conflict can reclassify earlier observations in the same batch.
    pub fn apply_batch<I>(&mut self, observations: I) -> Result<Vec<ApplyOutcome>>
    where
        I: IntoIterator<Item = Observation>,
    {
        let mut batch = Vec::new();
        let mut staged_work = 0usize;
        for observation in observations {
            if batch.len() >= self.limits.elements {
                return Err(Error::limit("bgp_state_batch"));
            }
            staged_work = add(staged_work, observation.batch_work()?, "bgp_state_work")?;
            if staged_work > self.limits.work {
                return Err(Error::limit("bgp_state_work"));
            }
            batch
                .try_reserve(1)
                .map_err(|_| Error::limit("bgp_state_batch"))?;
            batch.push(observation);
        }
        if batch.is_empty() {
            self.last_work = 0;
            return Ok(Vec::new());
        }
        let context_free = batch.iter().all(|observation| {
            observation.import_context.is_none() && observation.import_boundary.is_none()
        });
        let contextual = batch
            .iter()
            .all(|observation| observation.import_context.is_some());
        if !context_free && !contextual {
            let mut staged = self.clone();
            let mut outcomes = Vec::new();
            outcomes
                .try_reserve(batch.len())
                .map_err(|_| Error::limit("bgp_state_batch"))?;
            let mut total_work = 0usize;
            for observation in batch {
                outcomes.push(staged.apply_one(observation)?);
                total_work = add(total_work, staged.last_work, "bgp_state_work")?;
                if total_work > staged.limits.work {
                    return Err(Error::limit("bgp_state_work"));
                }
            }
            // Match the indexed path: accepted receipts describe the FINAL
            // committed classification, including conflicts introduced later
            // in this mixed batch. Identical replay stays a replay receipt.
            for outcome in &mut outcomes {
                if outcome.status != ApplyStatus::IdenticalReplay {
                    *outcome = staged
                        .outcomes
                        .get(outcome.observation)
                        .cloned()
                        .ok_or_else(|| bad("bgp_state", 0, "missing final batch receipt"))?;
                }
            }
            staged.last_work = total_work;
            *self = staged;
            return Ok(outcomes);
        }
        self.apply_indexed_batch(batch, contextual)
    }

    pub fn apply(&mut self, observation: Observation) -> Result<ApplyOutcome> {
        self.apply_batch(std::iter::once(observation))?
            .into_iter()
            .next()
            .ok_or_else(|| bad("bgp_state", 0, "missing application receipt"))
    }

    fn apply_indexed_batch(
        &mut self,
        batch: Vec<Observation>,
        contextual: bool,
    ) -> Result<Vec<ApplyOutcome>> {
        let limits = self.limits.clone();
        let l = &limits;
        let existing_len = self.observations.len();
        let input_len = batch.len();
        let mut work = Work::new(l.work);
        let mut storage = 0usize;
        let mut route_count = 0usize;
        let mut spans = 0usize;
        let mut seen: HashMap<&Identity, HashMap<&str, usize>> = HashMap::new();
        let mut generations: BTreeMap<SessionKey, (u64, bool)> = BTreeMap::new();

        for (index, observation) in self.observations.iter().enumerate() {
            storage = add(
                storage,
                observation.encoded.len(),
                "bgp_state_retained_bytes",
            )?;
            route_count = add(route_count, observation.routes.len(), "bgp_state_routes")?;
            spans = add(spans, observation.spans, "bgp_state_spans")?;
            work.charge(observation_work(observation, observation.nodes)?)?;
            seen.try_reserve(1)
                .map_err(|_| Error::limit("bgp_state_identity_index"))?;
            let encoded = seen.entry(&observation.identity).or_default();
            encoded
                .try_reserve(1)
                .map_err(|_| Error::limit("bgp_state_identity_index"))?;
            encoded.entry(observation.encoded.as_str()).or_insert(index);
        }
        if contextual {
            for session in &self.sessions {
                generations.insert(
                    (
                        source_code(session.source_kind),
                        session.source_id.clone(),
                        session.session.clone(),
                        session.import_partition.clone(),
                    ),
                    (session.generation, session.identity_conflict),
                );
            }
        }

        let mut input_outcomes = Vec::new();
        input_outcomes
            .try_reserve(input_len)
            .map_err(|_| Error::limit("bgp_state_batch"))?;
        input_outcomes.resize_with(input_len, || None);
        let mut accepted_slots = Vec::new();
        accepted_slots
            .try_reserve(input_len)
            .map_err(|_| Error::limit("bgp_state_batch"))?;

        for (input_index, observation) in batch.iter().enumerate() {
            let stats = tree_budget(&observation.normalized, l)?;
            observation.normalized.encode_bounded(l.input_bytes)?;
            if observation.routes.len() > l.elements || observation.spans > l.spans {
                return Err(Error::limit("bgp_state_observation"));
            }
            if contextual {
                observation
                    .import_context
                    .as_ref()
                    .ok_or_else(|| bad("bgp_import_context", 0, "context is missing"))?
                    .validate(l)?;
            }
            work.charge(observation_work(observation, stats.nodes)?)?;

            if let Some(index) = seen
                .get(&observation.identity)
                .and_then(|encoded| encoded.get(observation.encoded.as_str()))
                .copied()
            {
                input_outcomes[input_index] = Some(ApplyOutcome {
                    observation: index,
                    status: ApplyStatus::IdenticalReplay,
                    effects: Vec::new(),
                });
                continue;
            }

            let mut contextual_key = None;
            if contextual {
                let context = observation
                    .import_context
                    .as_ref()
                    .ok_or_else(|| bad("bgp_import_context", 0, "context is missing"))?;
                let key = observation
                    .session_key()
                    .ok_or_else(|| bad("bgp_import_context", 0, "session is missing"))?;
                if let Some(boundary) = &observation.import_boundary {
                    match generations.get(&key) {
                        Some((previous, false)) if *previous == boundary.previous_generation => {
                            generations.insert(key.clone(), (context.generation, false));
                        }
                        _ => {
                            return Err(bad(
                                "bgp_import_transition",
                                0,
                                "boundary predecessor does not match the current unambiguous partition",
                            ));
                        }
                    }
                } else {
                    match generations.get(&key) {
                        Some((previous, _)) if *previous != context.generation => {
                            return Err(bad(
                                "bgp_import_transition",
                                0,
                                "generation change requires an explicit successor boundary",
                            ));
                        }
                        Some(_) => {}
                        None => {
                            generations.insert(key.clone(), (context.generation, false));
                        }
                    }
                }
                contextual_key = Some(key);
            }

            let identity_conflict = seen
                .get(&observation.identity)
                .is_some_and(|encodings| !encodings.is_empty());

            let index = existing_len
                .checked_add(accepted_slots.len())
                .ok_or_else(|| Error::limit("bgp_state_observations"))?;
            if index >= l.elements {
                return Err(Error::limit("bgp_state_observations"));
            }
            storage = add(
                storage,
                observation.encoded.len(),
                "bgp_state_retained_bytes",
            )?;
            route_count = add(route_count, observation.routes.len(), "bgp_state_routes")?;
            spans = add(spans, observation.spans, "bgp_state_spans")?;
            if storage > l.retained_bytes || route_count > l.elements || spans > l.spans {
                return Err(Error::limit("bgp_state_retention"));
            }
            seen.try_reserve(1)
                .map_err(|_| Error::limit("bgp_state_identity_index"))?;
            let encoded = seen.entry(&observation.identity).or_default();
            encoded
                .try_reserve(1)
                .map_err(|_| Error::limit("bgp_state_identity_index"))?;
            encoded.insert(observation.encoded.as_str(), index);
            if identity_conflict {
                if let Some(key) = contextual_key {
                    let Some((_, conflict)) = generations.get_mut(&key) else {
                        return Err(bad(
                            "bgp_import_context",
                            0,
                            "context session was not staged",
                        ));
                    };
                    *conflict = true;
                }
            }
            accepted_slots.push(input_index);
        }
        drop(seen);

        if accepted_slots.is_empty() {
            self.last_work = work.used;
            return input_outcomes
                .into_iter()
                .map(|outcome| outcome.ok_or_else(|| bad("bgp_state", 0, "missing replay receipt")))
                .collect();
        }
        if storage > l.retained_bytes || route_count > l.elements || spans > l.spans {
            return Err(Error::limit("bgp_state_retention"));
        }

        let next_len = existing_len
            .checked_add(accepted_slots.len())
            .ok_or_else(|| Error::limit("bgp_state_observations"))?;
        let mut next = Vec::new();
        next.try_reserve_exact(next_len)
            .map_err(|_| Error::limit("bgp_state_observations"))?;
        next.extend(self.observations.iter().cloned());
        let mut accepted_cursor = 0usize;
        for (input_index, observation) in batch.into_iter().enumerate() {
            if accepted_slots.get(accepted_cursor) == Some(&input_index) {
                next.push(observation);
                accepted_cursor += 1;
            }
        }

        let (routes, sessions, reduced_outcomes) = reduce(&next, l, &mut work)?;
        // Bound the transient tree before its construction as well as the exact
        // serialized output. All witness references are bounded by route_count.
        work.charge(
            storage
                .saturating_mul(3)
                .saturating_add(route_count.saturating_mul(32)),
        )?;
        let json = snapshot_json(&next, &routes, &sessions, &reduced_outcomes);
        let encoded =
            json.encode_bounded(l.output_bytes.min(l.retained_bytes.saturating_sub(storage)))?;
        let retained = add(storage, encoded.len(), "bgp_state_retained_bytes")?;
        for (offset, input_index) in accepted_slots.iter().copied().enumerate() {
            let state_index = existing_len
                .checked_add(offset)
                .ok_or_else(|| Error::limit("bgp_state_observations"))?;
            input_outcomes[input_index] = Some(
                reduced_outcomes
                    .get(state_index)
                    .cloned()
                    .ok_or_else(|| bad("bgp_state", state_index, "missing application receipt"))?,
            );
        }
        let input_outcomes = input_outcomes
            .into_iter()
            .map(|outcome| outcome.ok_or_else(|| bad("bgp_state", 0, "missing batch receipt")))
            .collect::<Result<Vec<_>>>()?;

        self.observations = next;
        self.routes = routes;
        self.sessions = sessions;
        self.outcomes = reduced_outcomes;
        self.encoded = encoded;
        self.retained = retained;
        self.last_work = work.used;
        Ok(input_outcomes)
    }

    fn apply_one(&mut self, observation: Observation) -> Result<ApplyOutcome> {
        let l = &self.limits;
        // Recheck limits: the observation may have been constructed with larger ones.
        tree_budget(&observation.normalized, l)?;
        observation.normalized.encode_bounded(l.input_bytes)?;
        if observation.routes.len() > l.elements || observation.spans > l.spans {
            return Err(Error::limit("bgp_state_observation"));
        }
        if let Some(context) = &observation.import_context {
            context.validate(l)?;
        }
        let mut work = Work::new(l.work);
        work.charge(observation.encoded.len())?;
        for (index, old) in self.observations.iter().enumerate() {
            work.charge(
                old.encoded
                    .len()
                    .saturating_add(observation.identity.4.len()),
            )?;
            if old.identity == observation.identity && old.encoded == observation.encoded {
                // Receipt only; no journal, derived-state, or serialized mutation,
                // even after a reset. The separate work diagnostic is refreshed.
                self.last_work = work.used;
                return Ok(ApplyOutcome {
                    observation: index,
                    status: ApplyStatus::IdenticalReplay,
                    effects: Vec::new(),
                });
            }
        }
        // Replays were handled above: replaying an old accepted record does not
        // replay its effects. New contextual records may not guess a generation.
        if let Some(context) = &observation.import_context {
            let partition = context.partition();
            let previous = self.sessions.iter().find(|s| {
                s.source_kind == observation.source.kind
                    && s.source_id == observation.source.source_id
                    && s.session == context.session
                    && s.import_partition.as_ref() == Some(&partition)
            });
            if let Some(boundary) = &observation.import_boundary {
                if previous.is_none_or(|s| {
                    s.identity_conflict || s.generation != boundary.previous_generation
                }) {
                    return Err(bad(
                        "bgp_import_transition",
                        0,
                        "boundary predecessor does not match the current unambiguous partition",
                    ));
                }
            } else if previous.is_some_and(|s| s.generation != context.generation) {
                return Err(bad(
                    "bgp_import_transition",
                    0,
                    "generation change requires an explicit successor boundary",
                ));
            }
        }
        if self.observations.len() >= l.elements {
            return Err(Error::limit("bgp_state_observations"));
        }
        let mut storage = 0usize;
        let mut route_count = 0usize;
        let mut spans = 0usize;
        for item in self
            .observations
            .iter()
            .chain(std::iter::once(&observation))
        {
            storage = add(storage, item.encoded.len(), "bgp_state_retained_bytes")?;
            route_count = add(route_count, item.routes.len(), "bgp_state_routes")?;
            spans = add(spans, item.spans, "bgp_state_spans")?;
            // Charge before cloning/rebuilding; covers input trees and lookup keys.
            work.charge(
                item.encoded
                    .len()
                    .saturating_mul(4)
                    .saturating_add(item.nodes),
            )?;
        }
        if storage > l.retained_bytes || route_count > l.elements || spans > l.spans {
            return Err(Error::limit("bgp_state_retention"));
        }
        let mut next = self.observations.clone();
        next.push(observation);
        let (routes, sessions, outcomes) = reduce(&next, l, &mut work)?;
        // Bound the transient tree before its construction as well as the exact
        // serialized output. All witness references are bounded by route_count.
        work.charge(
            storage
                .saturating_mul(3)
                .saturating_add(route_count.saturating_mul(32)),
        )?;
        let json = snapshot_json(&next, &routes, &sessions, &outcomes);
        let encoded =
            json.encode_bounded(l.output_bytes.min(l.retained_bytes.saturating_sub(storage)))?;
        let retained = add(storage, encoded.len(), "bgp_state_retained_bytes")?;
        let result = outcomes
            .last()
            .cloned()
            .ok_or_else(|| bad("bgp_state", 0, "missing application receipt"))?;
        self.observations = next;
        self.routes = routes;
        self.sessions = sessions;
        self.outcomes = outcomes;
        self.encoded = encoded;
        self.retained = retained;
        self.last_work = work.used;
        Ok(result)
    }
}

type Reduced = (Vec<CandidateRoute>, Vec<SessionView>, Vec<ApplyOutcome>);
fn reduce(observations: &[Observation], limits: &Limits, work: &mut Work) -> Result<Reduced> {
    let mut identities: BTreeMap<&Identity, usize> = BTreeMap::new();
    let mut tainted = BTreeSet::new();
    let mut conflicting_rows = BTreeSet::new();
    for (index, o) in observations.iter().enumerate() {
        work.charge(o.encoded.len())?;
        if let Some(previous) = identities.insert(&o.identity, index) {
            conflicting_rows.insert(previous);
            conflicting_rows.insert(index);
            if let Some(key) = o.session_key() {
                tainted.insert(key);
            }
        }
    }
    let mut sessions: BTreeMap<SessionKey, SessionView> = BTreeMap::new();
    let mut routes: BTreeMap<RouteKey, CandidateRoute> = BTreeMap::new();
    let mut outcomes = Vec::new();
    for (index, o) in observations.iter().enumerate() {
        work.charge(1)?;
        let mut outcome = ApplyOutcome {
            observation: index,
            status: ApplyStatus::MissingScope,
            effects: Vec::new(),
        };
        let Some(key) = o.session_key() else {
            if conflicting_rows.contains(&index) {
                outcome.status = ApplyStatus::IdentityConflict;
            }
            outcomes.push(outcome);
            continue;
        };
        let Some(generation) = o.source.generation else {
            if conflicting_rows.contains(&index) {
                outcome.status = ApplyStatus::IdentityConflict;
            }
            outcomes.push(outcome);
            continue;
        };
        if !sessions.contains_key(&key) && sessions.len() >= limits.active {
            return Err(Error::limit("bgp_state_sessions"));
        }
        if tainted.contains(&key) {
            // Quarantine ALL generations of the ambiguous source/session. No old
            // winner survives and no suspect withdrawal/reset becomes authority.
            let session = sessions
                .entry(key.clone())
                .or_insert_with(|| session_view(o, generation, index));
            session.identity_conflict = true;
            outcome.status = ApplyStatus::IdentityConflict;
            outcomes.push(outcome);
            continue;
        }
        // Unscoped route observations cannot advance or close an existing scope.
        if o.kind == ObservationKind::Routes && o.source.direction.is_none() {
            outcomes.push(outcome);
            continue;
        }
        let previous = sessions.get(&key).map(|s| (s.generation, s.closed));
        if previous.is_some_and(|(old, _)| generation < old) {
            outcome.status = ApplyStatus::LateGeneration;
            outcomes.push(outcome);
            continue;
        }
        if o.kind == ObservationKind::Reset && previous.is_some_and(|(old, _)| generation <= old) {
            outcome.status = ApplyStatus::NonAdvancingReset;
            outcomes.push(outcome);
            continue;
        }
        if previous.is_none_or(|(old, _)| generation > old) {
            work.charge(routes.len())?;
            routes.retain(|(k, _, _, _), _| k != &key);
            sessions.insert(key.clone(), session_view(o, generation, index));
        }
        let session = sessions
            .get_mut(&key)
            .ok_or_else(|| bad("bgp_state", 0, "missing session"))?;
        if session.closed {
            outcome.status = ApplyStatus::ClosedGeneration;
        } else if o.kind == ObservationKind::Notification {
            session.closed = true;
            work.charge(routes.len())?;
            routes.retain(|(k, _, _, _), _| k != &key);
            outcome.status = ApplyStatus::Notification;
        } else if o.kind == ObservationKind::Reset {
            outcome.status = ApplyStatus::Reset;
        } else if o.kind != ObservationKind::Routes {
            outcome.status = ApplyStatus::MetadataOnly;
        } else {
            outcome.status = ApplyStatus::Applied;
            let direction = o
                .source
                .direction
                .ok_or_else(|| bad("bgp_state", 0, "missing direction"))?;
            let mut groups: BTreeMap<(&PrefixIdentity, RoutePathId), Vec<usize>> = BTreeMap::new();
            for (i, r) in o.routes.iter().enumerate() {
                groups.entry((&r.prefix, r.path_id)).or_default().push(i);
            }
            for ((prefix, path_id), indices) in groups {
                work.charge(indices.len())?;
                let route_key = (key.clone(), direction, prefix.clone(), path_id);
                let announce = indices
                    .iter()
                    .any(|&i| o.routes[i].action == RouteAction::Announce);
                let withdraw = indices
                    .iter()
                    .any(|&i| o.routes[i].action == RouteAction::Withdraw);
                let effect = if !prefix.supported() {
                    EffectKind::UnsupportedPrefix
                } else if !announce {
                    if routes.remove(&route_key).is_some() {
                        EffectKind::Withdrawn
                    } else {
                        EffectKind::AbsentWithdrawal
                    }
                } else {
                    let entry = routes.entry(route_key).or_insert_with(|| CandidateRoute {
                        source_kind: o.source.kind,
                        source_id: o.source.source_id.clone(),
                        session: key.2.clone(),
                        generation,
                        direction,
                        prefix: prefix.clone(),
                        path_id,
                        alternatives: Vec::new(),
                        import_partition: key.3.clone(),
                    });
                    let existed = !entry.alternatives.is_empty();
                    for &i in &indices {
                        let r = &o.routes[i];
                        let mut found = None;
                        for (ai, a) in entry.alternatives.iter().enumerate() {
                            // Charge comparisons before walking potentially nested attributes.
                            work.charge(o.encoded.len())?;
                            if a.action == r.action
                                && a.attributes == r.attributes
                                && a.attribute_identity == r.attribute_identity
                            {
                                found = Some(ai);
                                break;
                            }
                        }
                        let witness = RouteRef {
                            observation: index,
                            route: i,
                        };
                        if let Some(ai) = found {
                            entry.alternatives[ai].witnesses.push(witness);
                        } else {
                            entry.alternatives.push(Alternative {
                                action: r.action,
                                attributes: r.attributes.clone(),
                                attribute_identity: r.attribute_identity.clone(),
                                ambiguous_attributes: r.ambiguous_attributes,
                                witnesses: vec![witness],
                            });
                        }
                    }
                    if withdraw {
                        EffectKind::MixedActions
                    } else if entry.conflicting() {
                        EffectKind::ConflictingAnnouncement
                    } else if existed || indices.len() > 1 {
                        EffectKind::RepeatedAnnouncement
                    } else {
                        EffectKind::Announced
                    }
                };
                outcome.effects.push(RouteEffect {
                    prefix: prefix.clone(),
                    path_id,
                    kind: effect,
                    routes: indices,
                });
            }
        }
        outcomes.push(outcome);
    }
    Ok((
        routes.into_values().collect(),
        sessions.into_values().collect(),
        outcomes,
    ))
}

fn session_view(o: &Observation, generation: u64, index: usize) -> SessionView {
    SessionView {
        source_kind: o.source.kind,
        source_id: o.source.source_id.clone(),
        session: o.source.session.clone().unwrap_or_default(),
        generation,
        closed: false,
        identity_conflict: false,
        generation_witness: index,
        import_partition: o.import_context.as_ref().map(ImportContext::partition),
    }
}
fn snapshot_json(
    observations: &[Observation],
    routes: &[CandidateRoute],
    sessions: &[SessionView],
    outcomes: &[ApplyOutcome],
) -> Json {
    Json::object([
        ("schema", SCHEMA.into()),
        ("endpoint_state_established", false.into()),
        ("rib_established", false.into()),
        ("best_path_selected", false.into()),
        ("causality_established", false.into()),
        ("source_authority_established", false.into()),
        ("reachability_established", false.into()),
        ("normative_conformance_certified", false.into()),
        (
            "issues",
            Json::array(
                [
                    "candidate_state_is_not_endpoint_rib",
                    "caller_order_is_not_causality",
                    "input_provenance_inherited_not_independently_verified",
                    "attribute_identity_tokens_are_opaque_not_verified_digests",
                    "upstream_unknown_or_lossy_semantics_not_repaired",
                    "import_context_is_caller_asserted_not_wire_evidence",
                    "legacy_import_context_is_unknown_when_present",
                ]
                .into_iter()
                .map(Json::from),
            ),
        ),
        (
            "observations",
            Json::array(observations.iter().map(Observation::json)),
        ),
        (
            "outcomes",
            Json::array(outcomes.iter().map(|o| {
                Json::object([
                    ("observation", o.observation.to_string().into()),
                    ("status", o.status.name().into()),
                    ("effects", Json::array(o.effects.iter().map(effect_json))),
                ])
            })),
        ),
        (
            "sessions",
            Json::array(sessions.iter().map(|s| {
                Json::object([
                    ("source_kind", source_name(s.source_kind).into()),
                    ("source_id", s.source_id.clone().into()),
                    ("session", s.session.clone().into()),
                    ("generation", s.generation.to_string().into()),
                    ("closed", s.closed.into()),
                    ("identity_conflict", s.identity_conflict.into()),
                    (
                        "generation_witness",
                        s.generation_witness.to_string().into(),
                    ),
                    (
                        "import_partition",
                        s.import_partition
                            .as_ref()
                            .map_or(Json::Null, ImportPartition::json),
                    ),
                ])
            })),
        ),
        ("routes", Json::array(routes.iter().map(candidate_json))),
    ])
}
fn effect_json(effect: &RouteEffect) -> Json {
    let mut fields = vec![
        ("prefix", effect.prefix.json()),
        ("status", effect.kind.name().into()),
        (
            "routes",
            Json::array(effect.routes.iter().map(|route| route.to_string().into())),
        ),
    ];
    if let RoutePathId::Present(path_id) = effect.path_id {
        fields.push(("path_id", path_id.into()));
    }
    Json::Object(fields)
}
fn candidate_json(route: &CandidateRoute) -> Json {
    let mut fields = vec![
        ("source_kind", source_name(route.source_kind).into()),
        ("source_id", route.source_id.clone().into()),
        ("session", route.session.clone().into()),
        ("generation", route.generation.to_string().into()),
        ("direction", route.direction.into()),
        ("prefix", route.prefix.json()),
        (
            "import_partition",
            route
                .import_partition
                .as_ref()
                .map_or(Json::Null, ImportPartition::json),
        ),
        (
            "status",
            if route.conflicting() {
                "conflict"
            } else {
                "candidate"
            }
            .into(),
        ),
        (
            "alternatives",
            Json::array(route.alternatives.iter().map(|alternative| {
                Json::object([
                    ("action", action_name(alternative.action).into()),
                    ("attributes", alternative.attributes.clone()),
                    ("attribute_identity", alternative.attribute_identity.clone()),
                    (
                        "ambiguous_attributes",
                        alternative.ambiguous_attributes.into(),
                    ),
                    (
                        "witnesses",
                        Json::array(alternative.witnesses.iter().map(|witness| {
                            Json::object([
                                ("observation", witness.observation.to_string().into()),
                                ("route", witness.route.to_string().into()),
                            ])
                        })),
                    ),
                ])
            })),
        ),
    ];
    if let RoutePathId::Present(path_id) = route.path_id {
        fields.push(("path_id", path_id.into()));
    }
    Json::Object(fields)
}
fn source_json(s: &Source) -> Json {
    Json::object([
        ("source_kind", source_name(s.kind).into()),
        ("source_id", s.source_id.clone().into()),
        ("record_id", s.record_id.clone().into()),
        ("session", optional_string(&s.session)),
        (
            "generation",
            s.generation.map_or(Json::Null, |n| n.to_string().into()),
        ),
        ("direction", s.direction.map_or(Json::Null, Json::from)),
        (
            "observed_at_ns",
            s.observed_at_ns
                .map_or(Json::Null, |n| n.to_string().into()),
        ),
        ("peer", optional_string(&s.peer)),
        ("local", optional_string(&s.local)),
    ])
}
fn optional_string(s: &Option<String>) -> Json {
    s.clone().map_or(Json::Null, Json::String)
}
fn source_code(k: SourceKind) -> u8 {
    match k {
        SourceKind::Captured => 0,
        SourceKind::Imported => 1,
    }
}
fn source_name(k: SourceKind) -> &'static str {
    match k {
        SourceKind::Captured => "captured",
        SourceKind::Imported => "imported",
    }
}
fn action_name(k: RouteAction) -> &'static str {
    match k {
        RouteAction::Announce => "announce",
        RouteAction::Withdraw => "withdraw",
    }
}

fn parse_route(
    raw: &Json,
    kind: SourceKind,
    extent: usize,
    limits: &Limits,
) -> Result<RouteObservation> {
    let action = match text(member(raw, "action")?)? {
        "announce" => RouteAction::Announce,
        "withdraw" => RouteAction::Withdraw,
        _ => return Err(bad("bgp_state_action", 0, "unknown route action")),
    };
    let p = member(raw, "prefix")?;
    let path_id = match optional_member(raw, "path_id")? {
        Some(value) => RoutePathId::Present(
            u32::try_from(number(value)?)
                .map_err(|_| bad("bgp_state_path_id", 0, "path identifier out of range"))?,
        ),
        None => RoutePathId::Absent,
    };
    let prefix = PrefixIdentity {
        afi: u16::try_from(number(member(p, "afi")?)?)
            .map_err(|_| bad("bgp_state_prefix", 0, "AFI out of range"))?,
        safi: byte(member(p, "safi")?)?,
        length: byte(member(p, "length")?)?,
        address: text(member(p, "address")?)?.to_owned(),
    };
    let address: Vec<u8> = match prefix.afi {
        1 => prefix
            .address
            .parse::<Ipv4Addr>()
            .map_err(|_| bad("bgp_state_prefix", 0, "invalid IPv4 address"))?
            .octets()
            .to_vec(),
        2 => prefix
            .address
            .parse::<Ipv6Addr>()
            .map_err(|_| bad("bgp_state_prefix", 0, "invalid IPv6 address"))?
            .octets()
            .to_vec(),
        _ => Vec::new(),
    };
    if !address.is_empty()
        && (usize::from(prefix.length) > address.len() * 8
            || (usize::from(prefix.length)..address.len() * 8)
                .any(|bit| address[bit / 8] & (0x80 >> (bit % 8)) != 0))
    {
        return Err(bad(
            "bgp_state_prefix",
            0,
            "noncanonical prefix or excessive prefix length",
        ));
    }
    // Use one spelling for semantically identical IP prefix keys; retain original
    // spelling unchanged in normalized provenance. No host bits are modified.
    let mut prefix = prefix;
    if prefix.afi == 1 {
        prefix.address = Ipv4Addr::new(address[0], address[1], address[2], address[3]).to_string();
    }
    if prefix.afi == 2 {
        let mut a = [0; 16];
        a.copy_from_slice(&address);
        prefix.address = Ipv6Addr::from(a).to_string();
    }
    let route_key = Json::object([(
        "prefix",
        Json::object([
            ("afi", prefix.afi.into()),
            ("safi", prefix.safi.into()),
            ("length", prefix.length.into()),
            ("address", prefix.address.clone().into()),
        ]),
    )]);
    let field_start = position(member(raw, "field_start")?)?;
    let field_end = position(member(raw, "field_end")?)?;
    if (kind == SourceKind::Captured && (field_start >= field_end || field_end > extent))
        || (kind == SourceKind::Imported && (field_start != 0 || field_end != 0))
    {
        return Err(bad(
            "bgp_state_range",
            field_start,
            "route range outside source evidence",
        ));
    }
    let attributes = member(raw, "attributes")?;
    object(attributes)?;
    let ranges = array(member(raw, "attribute_ranges")?)?;
    if kind == SourceKind::Imported && !ranges.is_empty() {
        return Err(bad(
            "bgp_state_import",
            0,
            "imported attributes cannot assert wire ranges",
        ));
    }
    let semantic_identity = match optional_member(raw, "semantic_identity")? {
        None => Json::Null,
        Some(identity) => {
            validate_semantic_identity(identity, &route_key, attributes, ranges, kind, limits)?
        }
    };
    let mut types = BTreeSet::new();
    let identity_incomplete = match &semantic_identity {
        // Older v1 route envelopes do not carry the additive identity sidecar.
        // Their historical replay/cursor commitments and candidate semantics
        // remain valid; only a supplied incomplete identity blocks trust.
        Json::Null => false,
        identity => match optional_member(identity, "completeness")? {
            None => false,
            Some(Json::String(state)) => state != "complete",
            Some(_) => true,
        },
    };
    let mut ambiguous_attributes = action == RouteAction::Announce && identity_incomplete;
    let mut identities = Vec::new();
    for range in ranges {
        let code = byte(member(range, "type")?)?;
        byte(member(range, "flags")?)?;
        let start = position(member(range, "start")?)?;
        let end = position(member(range, "end")?)?;
        if start >= end || end > extent {
            return Err(bad(
                "bgp_state_range",
                start,
                "attribute range outside evidence",
            ));
        }
        text(member(range, "sha256")?)?;
        let value_start = optional_member(range, "value_start")?;
        let value_end = optional_member(range, "value_end")?;
        if let (Some(a), Some(b)) = (value_start, value_end) {
            let expected = add(
                start,
                if number(member(range, "flags")?)? & 0x10 != 0 {
                    4
                } else {
                    3
                },
                "bgp_state_range",
            )?;
            if position(a)? != expected || position(b)? != end || expected > end {
                return Err(bad(
                    "bgp_state_range",
                    start,
                    "attribute value range disagrees with envelope",
                ));
            }
        } else if value_start.is_some() || value_end.is_some() {
            return Err(bad(
                "bgp_state_range",
                start,
                "partial attribute value range",
            ));
        }
        let duplicate = !types.insert(code);
        let duplicate_discarded = duplicate
            && text(member(range, "disposition")?)? == "discard_later_occurrence"
            && !matches!(code, 14 | 15);
        ambiguous_attributes |= duplicate && !duplicate_discarded;
        ambiguous_attributes |= object(range)?.iter().any(|(key, value)|
            *key == "interpretation" && matches!(value, Json::String(s) if matches!(s.as_str(), "unresolved_asn_width" | "unresolved_next_hop_context" | "unresolved_capability_context")));
        identities.push(canonical(&Json::Object(
            object(range)?
                .iter()
                .filter(|(key, _)| !matches!(*key, "start" | "end" | "value_start" | "value_end"))
                .cloned()
                .collect(),
        )));
    }
    Ok(RouteObservation {
        prefix,
        path_id,
        action,
        attributes: canonical(attributes),
        attribute_identity: Json::Array(identities),
        semantic_identity,
        field_start,
        field_end,
        ambiguous_attributes,
    })
}

fn validate_semantic_identity(
    identity: &Json,
    route_key: &Json,
    route_attributes: &Json,
    ranges: &[Json],
    source_kind: SourceKind,
    limits: &Limits,
) -> Result<Json> {
    let completeness = text(member(identity, "completeness")?)?;
    if text(member(identity, "schema")?)? != super::bgp::SEMANTIC_IDENTITY_SCHEMA {
        return Err(bad(
            "bgp_state_semantic_identity",
            0,
            "unsupported semantic identity schema",
        ));
    }
    let fingerprint = member(identity, "fingerprint_sha256")?;
    let payload = member(identity, "canonical_payload")?;
    let reasons = array(member(identity, "incompleteness_reasons")?)?;
    let opaque = array(member(identity, "opaque_occurrence_fingerprints")?)?;
    for reason in reasons {
        text(reason)?;
    }
    for occurrence in opaque {
        let _ = byte(member(occurrence, "type")?)?;
        byte(member(occurrence, "flags")?)?;
        validate_hash(text(member(occurrence, "value_sha256")?)?)?;
    }

    match completeness {
        "complete" => {
            if !reasons.is_empty() || !opaque.is_empty() || object(payload).is_err() {
                return Err(bad(
                    "bgp_state_semantic_identity",
                    0,
                    "complete identity requires a payload and no unresolved or opaque evidence",
                ));
            }
            if canonical(member(payload, "route_key")?) != canonical(route_key) {
                return Err(bad(
                    "bgp_state_semantic_identity",
                    0,
                    "identity payload disagrees with route envelope",
                ));
            }
            validate_identity_attributes(
                member(payload, "attributes")?,
                route_attributes,
                ranges,
                source_kind,
                limits,
            )?;
            let encoded = payload.encode_bounded(limits.input_bytes)?;
            let payload_len = u64::try_from(encoded.len())
                .map_err(|_| Error::limit("bgp_state_semantic_identity"))?;
            let domain = b"pcap-evidence.bgp.semantic-route-identity.v1\0";
            let total = domain
                .len()
                .checked_add(8)
                .and_then(|size| size.checked_add(encoded.len()))
                .ok_or_else(|| Error::limit("bgp_state_semantic_identity"))?;
            let mut preimage = Vec::new();
            preimage
                .try_reserve_exact(total)
                .map_err(|_| Error::limit("bgp_state_semantic_identity"))?;
            preimage.extend_from_slice(domain);
            preimage.extend_from_slice(&payload_len.to_be_bytes());
            preimage.extend_from_slice(encoded.as_bytes());
            let actual = sha256::hex(&sha256::digest(&preimage));
            if text(fingerprint)? != actual {
                return Err(bad(
                    "bgp_state_semantic_identity",
                    0,
                    "fingerprint does not match canonical payload",
                ));
            }
        }
        "incomplete" | "unresolved" => {
            if !matches!(fingerprint, Json::Null)
                || !matches!(payload, Json::Null)
                || reasons.is_empty()
            {
                return Err(bad(
                    "bgp_state_semantic_identity",
                    0,
                    "incomplete identity must omit its fingerprint and payload",
                ));
            }
        }
        _ => {
            return Err(bad(
                "bgp_state_semantic_identity",
                0,
                "unknown completeness state",
            ));
        }
    }
    Ok(canonical(identity))
}

fn validate_identity_attributes(
    identity_attributes: &Json,
    route_attributes: &Json,
    ranges: &[Json],
    source_kind: SourceKind,
    limits: &Limits,
) -> Result<()> {
    const IDENTITY_FIELDS: [&str; 10] = [
        "origin",
        "as_path",
        "next_hop",
        "med",
        "local_preference",
        "aggregator",
        "communities",
        "large_communities",
        "originator_id",
        "cluster_list",
    ];
    let identity_fields = object(identity_attributes)?;
    if identity_fields.len() != IDENTITY_FIELDS.len()
        || identity_fields
            .iter()
            .any(|(name, _)| !IDENTITY_FIELDS.contains(name))
    {
        return Err(identity_attribute_mismatch("identity attribute shape"));
    }
    for name in [
        "origin",
        "next_hop",
        "med",
        "local_preference",
        "aggregator",
        "originator_id",
        "cluster_list",
    ] {
        if canonical(member(identity_attributes, name)?)
            != canonical(member(route_attributes, name)?)
        {
            return Err(identity_attribute_mismatch("normalized route attributes"));
        }
    }

    if canonical_as_path(member(identity_attributes, "as_path")?, limits)?
        != canonical_as_path(member(route_attributes, "as_path")?, limits)?
        || canonical_communities(member(identity_attributes, "communities")?, limits)?
            != canonical_communities(member(route_attributes, "communities")?, limits)?
    {
        return Err(identity_attribute_mismatch("AS_PATH or Communities"));
    }

    // Captured envelopes retain the source occurrence that supplies Large
    // Communities. MRT-normalized route attributes currently omit that field,
    // so imported identities cannot be cross-checked for it at this seam.
    let identity_large_communities =
        canonical_large_communities(member(identity_attributes, "large_communities")?, limits)?;
    if source_kind == SourceKind::Captured {
        validate_captured_attribute_projection(route_attributes, ranges, limits)?;
        let empty = Json::Array(Vec::new());
        let source_value = first_effective_attribute(ranges, 32)?.unwrap_or(&empty);
        if identity_large_communities != canonical_large_communities(source_value, limits)? {
            return Err(identity_attribute_mismatch("Large Communities"));
        }
    } else if identity_large_communities
        != canonical_large_communities(member(route_attributes, "large_communities")?, limits)?
    {
        return Err(identity_attribute_mismatch(
            "imported Large Communities projection",
        ));
    }
    Ok(())
}

fn first_effective_attribute(ranges: &[Json], code: u8) -> Result<Option<&Json>> {
    first_effective_occurrence(ranges, code)?
        .map(|range| member(range, "decoded"))
        .transpose()
}

fn first_effective_occurrence(ranges: &[Json], code: u8) -> Result<Option<&Json>> {
    for range in ranges {
        if byte(member(range, "type")?)? == code {
            return if text(member(range, "disposition")?)? == "accept_evidence_only" {
                Ok(Some(range))
            } else {
                Ok(None)
            };
        }
    }
    Ok(None)
}

fn validate_captured_attribute_projection(
    route_attributes: &Json,
    ranges: &[Json],
    limits: &Limits,
) -> Result<()> {
    let empty = Json::Array(Vec::new());
    let null = Json::Null;
    let source_path = canonical_source_as_path_from_ranges(ranges, limits)?;
    if source_path != canonical_as_path(member(route_attributes, "as_path")?, limits)? {
        return Err(identity_attribute_mismatch("source AS_PATH projection"));
    }

    for (field, code) in [
        ("origin", 1),
        ("med", 4),
        ("local_preference", 5),
        ("originator_id", 9),
    ] {
        let expected = first_effective_attribute(ranges, code)?.unwrap_or(&null);
        if canonical(expected) != canonical(member(route_attributes, field)?) {
            return Err(identity_attribute_mismatch(
                "first-effective scalar attribute",
            ));
        }
    }

    let source_aggregator = first_effective_attribute(ranges, 7)?
        .cloned()
        .unwrap_or(Json::Null);
    if canonical(&source_aggregator) != canonical(member(route_attributes, "aggregator")?) {
        return Err(identity_attribute_mismatch("AGGREGATOR source projection"));
    }

    let communities = first_effective_attribute(ranges, 8)?.unwrap_or(&empty);
    if canonical_communities(communities, limits)?
        != canonical_communities(member(route_attributes, "communities")?, limits)?
    {
        return Err(identity_attribute_mismatch("Communities source projection"));
    }
    let clusters = first_effective_attribute(ranges, 10)?.unwrap_or(&empty);
    if canonical(clusters) != canonical(member(route_attributes, "cluster_list")?) {
        return Err(identity_attribute_mismatch(
            "Cluster List source projection",
        ));
    }

    let mut has_ipv4_next_hop = false;
    let mut has_mp_reach = false;
    for range in ranges {
        match byte(member(range, "type")?)? {
            3 => has_ipv4_next_hop = true,
            14 => has_mp_reach = true,
            _ => {}
        }
    }
    let expected_next_hop = if has_ipv4_next_hop && has_mp_reach {
        &null
    } else if let Some(decoded) =
        first_effective_attribute(ranges, if has_mp_reach { 14 } else { 3 })?
    {
        if has_mp_reach {
            member(decoded, "next_hop")?
        } else {
            decoded
        }
    } else {
        &null
    };
    if canonical(expected_next_hop) != canonical(member(route_attributes, "next_hop")?) {
        return Err(identity_attribute_mismatch("NEXT_HOP source projection"));
    }

    let mp_reach = first_effective_attribute(ranges, 14)?
        .map(|decoded| member(decoded, "prefixes"))
        .transpose()?
        .unwrap_or(&empty);
    let mp_unreach = first_effective_attribute(ranges, 15)?.unwrap_or(&empty);
    if canonical(mp_reach) != canonical(member(route_attributes, "mp_reach")?)
        || canonical(mp_unreach) != canonical(member(route_attributes, "mp_unreach")?)
    {
        return Err(identity_attribute_mismatch(
            "multiprotocol prefix source projection",
        ));
    }
    Ok(())
}

fn canonical_source_as_path_from_ranges(ranges: &[Json], limits: &Limits) -> Result<Json> {
    let empty = Json::Array(Vec::new());
    let source = first_effective_occurrence(ranges, 2)?;
    Ok(source
        .map(|range| canonical_source_as_path(range, limits))
        .transpose()?
        .flatten()
        .unwrap_or_else(|| canonical(&empty)))
}

fn canonical_source_as_path(range: &Json, limits: &Limits) -> Result<Option<Json>> {
    // This specific label means the producer intentionally withheld the
    // normalized AS_PATH. A wire-shape-only interpretation without negotiated
    // width can still be retained as a candidate, so it remains cross-checkable.
    if text(member(range, "interpretation")?)? == "unresolved_capability_context" {
        return Ok(None);
    }
    let value = member(range, "decoded")?;
    if matches!(value, Json::Array(_)) {
        return canonical_as_path(value, limits).map(Some);
    }
    let interpretations = array(member(value, "interpretations")?)?;
    let mut normalized = None;
    let mut ambiguous = false;
    for interpretation in interpretations {
        let path = canonical_as_path(member(interpretation, "as_path")?, limits)?;
        if normalized.as_ref().is_some_and(|current| current != &path) {
            ambiguous = true;
        }
        normalized = Some(path);
    }
    if ambiguous {
        Ok(None)
    } else {
        normalized
            .map(Some)
            .ok_or_else(|| identity_attribute_mismatch("AS_PATH occurrence interpretations"))
    }
}

fn identity_attribute_mismatch(detail: &'static str) -> crate::Error {
    bad("bgp_state_semantic_identity", 0, detail)
}

fn canonical_as_path(value: &Json, limits: &Limits) -> Result<Json> {
    let segments = array(value)?;
    if segments.len() > limits.elements {
        return Err(Error::limit("bgp_state_semantic_identity"));
    }
    let mut normalized = Vec::new();
    normalized
        .try_reserve_exact(segments.len())
        .map_err(|_| Error::limit("bgp_state_semantic_identity"))?;
    for segment in segments {
        let kind = number(member(segment, "kind")?)?;
        if !(1..=4).contains(&kind) {
            return Err(bad(
                "bgp_state_semantic_identity",
                0,
                "unknown AS path segment kind",
            ));
        }
        let values = array(member(segment, "values")?)?;
        if values.len() > limits.elements {
            return Err(Error::limit("bgp_state_semantic_identity"));
        }
        let mut normalized_values = Vec::new();
        normalized_values
            .try_reserve_exact(values.len())
            .map_err(|_| Error::limit("bgp_state_semantic_identity"))?;
        for value in values {
            normalized_values.push(
                u32::try_from(number(value)?)
                    .map_err(|_| bad("bgp_state_semantic_identity", 0, "ASN out of range"))?,
            );
        }
        let mut values = normalized_values;
        if matches!(kind, 1 | 4) {
            values.sort_unstable();
        }
        normalized.push(Json::object([
            ("kind", Json::from(kind)),
            ("values", Json::array(values.into_iter().map(Json::from))),
        ]));
    }
    Ok(Json::Array(normalized))
}

fn canonical_communities(value: &Json, limits: &Limits) -> Result<Json> {
    let values = array(value)?;
    if values.len() > limits.elements {
        return Err(Error::limit("bgp_state_semantic_identity"));
    }
    let mut normalized = Vec::new();
    normalized
        .try_reserve_exact(values.len())
        .map_err(|_| Error::limit("bgp_state_semantic_identity"))?;
    for value in values {
        normalized.push(
            u32::try_from(number(value)?)
                .map_err(|_| bad("bgp_state_semantic_identity", 0, "community out of range"))?,
        );
    }
    let mut values = normalized;
    values.sort_unstable();
    values.dedup();
    Ok(Json::array(values.into_iter().map(Json::from)))
}

fn canonical_large_communities(value: &Json, limits: &Limits) -> Result<Json> {
    let values = array(value)?;
    if values.len() > limits.elements {
        return Err(Error::limit("bgp_state_semantic_identity"));
    }
    let mut normalized = Vec::new();
    normalized
        .try_reserve_exact(values.len())
        .map_err(|_| Error::limit("bgp_state_semantic_identity"))?;
    for value in values {
        let tuple = array(value)?;
        if tuple.len() != 3 {
            return Err(bad(
                "bgp_state_semantic_identity",
                0,
                "large community must contain three values",
            ));
        }
        let mut fields = [0u32; 3];
        for (index, field) in tuple.iter().enumerate() {
            fields[index] = u32::try_from(number(field)?).map_err(|_| {
                bad(
                    "bgp_state_semantic_identity",
                    0,
                    "large community value out of range",
                )
            })?;
        }
        normalized.push(fields);
    }
    normalized.sort_unstable();
    normalized.dedup();
    Ok(Json::array(normalized.into_iter().map(|tuple| {
        Json::array(tuple.into_iter().map(Json::from))
    })))
}

fn validate_hash(value: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(bad(
            "bgp_state_semantic_identity",
            0,
            "invalid SHA-256 shape",
        ));
    }
    Ok(())
}

fn captured_evidence(e: &Json, l: &Limits) -> Result<(usize, usize, String)> {
    let extent = position(member(e, "byte_length")?)?;
    if extent < 19 || extent > l.input_bytes {
        return Err(Error::limit("bgp_state_evidence_bytes"));
    }
    let hash = text(member(e, "reconstructed_sha256")?)?;
    if hash.len() != 64
        || !hash
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(bad("bgp_state_hash", 0, "invalid message digest shape"));
    }
    let spans = array(member(e, "spans")?)?;
    let packets = array(member(e, "packets")?)?;
    let count = add(spans.len(), packets.len(), "bgp_state_spans")?;
    if count > l.spans {
        return Err(Error::limit("bgp_state_spans"));
    }
    let mut witnesses = BTreeSet::new();
    for p in packets {
        let frame = number(member(p, "frame")?)?;
        if frame == 0 {
            return Err(bad("bgp_state_packet", 0, "packet ordinals are one based"));
        }
        witnesses.insert((frame, number(member(p, "record_offset")?)?));
    }
    let mut cursor = 0;
    for span in spans {
        let start = position(member(span, "start")?)?;
        let end = position(member(span, "end")?)?;
        let packet_start = position(member(span, "packet_start")?)?;
        if start != cursor || end <= start || end > extent {
            return Err(bad(
                "bgp_state_provenance",
                start,
                "noncontiguous span coverage",
            ));
        }
        add(packet_start, end - start, "bgp_state_packet_offset")?;
        if !witnesses.contains(&(
            number(member(span, "frame")?)?,
            number(member(span, "record_offset")?)?,
        )) {
            return Err(bad(
                "bgp_state_provenance",
                start,
                "span packet witness absent",
            ));
        }
        cursor = end;
    }
    if cursor != extent {
        return Err(bad(
            "bgp_state_provenance",
            cursor,
            "incomplete span coverage",
        ));
    }
    let locator = canonical(&Json::object([
        ("packets", member(e, "packets")?.clone()),
        ("spans", member(e, "spans")?.clone()),
    ]))
    .encode_bounded(l.input_bytes)?;
    Ok((extent, count, locator))
}

struct Work {
    used: usize,
    limit: usize,
}
fn observation_work(observation: &Observation, nodes: usize) -> Result<usize> {
    let mut bytes = 1usize;
    for value in [
        observation.identity.1.len(),
        observation.identity.2.as_ref().map_or(0, String::len),
        observation.identity.3.len(),
        observation.identity.4.len(),
        observation.encoded.len(),
        nodes,
    ] {
        bytes = add(bytes, value, "bgp_state_work")?;
    }
    Ok(bytes)
}
impl Work {
    fn new(limit: usize) -> Self {
        Self { used: 0, limit }
    }
    fn charge(&mut self, n: usize) -> Result<()> {
        self.used = add(self.used, n, "bgp_state_work")?;
        if self.used > self.limit {
            return Err(Error::limit("bgp_state_work"));
        }
        Ok(())
    }
}
pub(crate) struct Stats {
    nodes: usize,
}
pub(crate) fn tree_budget(value: &Json, limits: &Limits) -> Result<Stats> {
    fn visit(v: &Json, depth: usize, l: &Limits, nodes: &mut usize, work: &mut Work) -> Result<()> {
        if depth > l.depth {
            return Err(Error::limit("bgp_state_depth"));
        }
        *nodes = add(*nodes, 1, "bgp_state_fields")?;
        if *nodes > l.fields {
            return Err(Error::limit("bgp_state_fields"));
        }
        work.charge(1)?;
        match v {
            Json::String(s) => {
                work.charge(s.len())?;
                if s.len() > l.input_bytes {
                    return Err(Error::limit("bgp_state_input"));
                }
            }
            Json::Array(items) => {
                if items.len() > l.fields {
                    return Err(Error::limit("bgp_state_fields"));
                }
                for item in items {
                    visit(item, depth + 1, l, nodes, work)?;
                }
            }
            Json::Object(items) => {
                if items.len() > l.fields {
                    return Err(Error::limit("bgp_state_fields"));
                }
                let mut keys = BTreeSet::new();
                for (key, item) in items {
                    work.charge(key.len())?;
                    if !keys.insert(*key) {
                        return Err(bad("bgp_state_duplicate_field", 0, "duplicate JSON key"));
                    }
                    visit(item, depth + 1, l, nodes, work)?;
                }
            }
            _ => {}
        }
        Ok(())
    }
    let mut nodes = 0;
    visit(value, 1, limits, &mut nodes, &mut Work::new(limits.work))?;
    Ok(Stats { nodes })
}
fn canonical(value: &Json) -> Json {
    match value {
        Json::Object(items) => {
            let mut items: Vec<_> = items.iter().map(|(k, v)| (*k, canonical(v))).collect();
            items.sort_by_key(|(k, _)| *k);
            Json::Object(items)
        }
        Json::Array(items) => Json::array(items.iter().map(canonical)),
        _ => value.clone(),
    }
}
fn object(v: &Json) -> Result<&[(&'static str, Json)]> {
    match v {
        Json::Object(items) => Ok(items),
        _ => Err(bad("bgp_state_shape", 0, "expected object")),
    }
}
pub(crate) fn member<'a>(v: &'a Json, name: &str) -> Result<&'a Json> {
    object(v)?
        .iter()
        .find(|(key, _)| *key == name)
        .map(|(_, value)| value)
        .ok_or_else(|| bad("bgp_state_shape", 0, "required field absent"))
}
pub(crate) fn text(v: &Json) -> Result<&str> {
    match v {
        Json::String(s) => Ok(s),
        _ => Err(bad("bgp_state_shape", 0, "expected string")),
    }
}
pub(crate) fn array(v: &Json) -> Result<&[Json]> {
    match v {
        Json::Array(a) => Ok(a),
        _ => Err(bad("bgp_state_shape", 0, "expected array")),
    }
}
pub(crate) fn number(v: &Json) -> Result<u64> {
    match v {
        Json::Number(n) => Ok(*n),
        Json::String(s) => s
            .parse::<u64>()
            .ok()
            .filter(|n| n.to_string() == *s)
            .ok_or_else(|| bad("bgp_state_number", 0, "expected exact unsigned decimal")),
        _ => Err(bad("bgp_state_number", 0, "expected unsigned integer")),
    }
}
fn position(v: &Json) -> Result<usize> {
    usize::try_from(number(v)?).map_err(|_| Error::limit("bgp_state_offset"))
}
fn byte(v: &Json) -> Result<u8> {
    u8::try_from(number(v)?).map_err(|_| bad("bgp_state_byte", 0, "octet out of range"))
}
pub(crate) fn optional_direction(v: &Json) -> Result<Option<u8>> {
    if v == &Json::Null {
        return Ok(None);
    }
    let d = byte(v)?;
    if d > 1 {
        return Err(bad(
            "bgp_state_direction",
            0,
            "direction must be zero or one",
        ));
    }
    Ok(Some(d))
}
pub(crate) fn optional_text(v: &Json) -> Result<Option<String>> {
    if v == &Json::Null {
        Ok(None)
    } else {
        Ok(Some(text(v)?.into()))
    }
}
fn identity_text(v: &Json) -> Result<String> {
    let s = text(v)?;
    if s.is_empty() || s.len() > 1024 || s.chars().any(char::is_control) {
        return Err(bad(
            "bgp_state_identity",
            0,
            "empty, control-containing or oversized identity",
        ));
    }
    Ok(s.into())
}
fn optional_identity(v: &Json) -> Result<Option<String>> {
    if v == &Json::Null {
        Ok(None)
    } else {
        Ok(Some(identity_text(v)?))
    }
}
fn optional_time(v: &Json) -> Result<Option<i64>> {
    if v == &Json::Null {
        return Ok(None);
    }
    let s = text(v)?;
    let n = s
        .parse::<i64>()
        .map_err(|_| bad("bgp_state_time", 0, "expected signed decimal timestamp"))?;
    if n.to_string() != s {
        return Err(bad("bgp_state_time", 0, "noncanonical timestamp"));
    }
    Ok(Some(n))
}
fn add(a: usize, b: usize, field: &'static str) -> Result<usize> {
    a.checked_add(b).ok_or_else(|| Error::limit(field))
}

fn optional_member<'a>(v: &'a Json, name: &str) -> Result<Option<&'a Json>> {
    Ok(object(v)?
        .iter()
        .find(|(key, _)| *key == name)
        .map(|(_, value)| value))
}
