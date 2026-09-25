//! Read-only, bounded candidate associations, not traffic causality or a RIB.
//!
//! Both adapters and every association policy are explicit caller inputs. This
//! module does no I/O, source authentication, route selection or state mutation.
use super::bgp::{RouteAction, SourceKind};
use super::bgp_import::{ClockPolicy, ObservationClock, SourceBatch, SourceRange};
use super::bgp_state::{
    self, ApplyStatus, CandidateState, Observation, PrefixIdentity, RoutePathId,
};
use super::model::{bad, Limits};
use pcap_evidence::{json::Json, sha256, Error, Result};
use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const SCHEMA: &str = "pcap-evidence.bgp.association.v1";
pub const INPUT_SCHEMA: &str = "pcap-evidence.association-input.v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InternalKind {
    Flow,
    Security,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Coverage {
    DeclaredComplete,
    Incomplete,
    Unknown,
}

/// Producer identity, not an endpoint identity. Optional values are not wildcards.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceIdentity {
    pub source_id: String,
    pub record_id: String,
    pub schema: String,
    pub version: Option<String>,
    pub batch: Option<SourceBatch>,
    pub checkpoint_id: Option<String>,
}

/// Namespace is an explicitly caller-established common comparison namespace.
/// Session/generation/flow labels may be compared only by the explicit policy.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Scope {
    pub namespace: Option<String>,
    pub session: Option<String>,
    pub generation: Option<u64>,
    pub flow_id: Option<String>,
    pub direction: Option<u8>,
}

/// IP-address identity only. Ports, MACs, NAT, tunnels and inferred next hops are
/// not supported spatial dimensions. Other AFIs are retained as unsupported.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EndpointIdentity {
    pub afi: u16,
    pub address: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Dimensions {
    pub scope: Scope,
    pub prefix: Option<PrefixIdentity>,
    pub endpoint: Option<EndpointIdentity>,
    pub unsupported: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TimeLabel {
    pub observed_at_ns: Option<i64>,
    pub clock: ObservationClock,
}

/// Source-relative ranges are NOT synthesized packet spans. Details are bounded,
/// opaque producer metadata. A digest is not verification of the source bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Provenance {
    pub record_sha256: Option<String>,
    pub ranges: Vec<SourceRange>,
    pub details: Json,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InternalInput {
    pub kind: InternalKind,
    pub source: SourceIdentity,
    pub dimensions: Dimensions,
    pub time: TimeLabel,
    pub coverage: Coverage,
    pub provenance: Provenance,
}

/// No implicit namespace mapping or clock calibration is performed. Contextual
/// imports already own clock metadata: supplying another clock is rejected.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteContext {
    pub namespace: Option<String>,
    pub flow_id: Option<String>,
    pub captured_or_legacy_clock: Option<ObservationClock>,
    pub coverage: Coverage,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DimensionRule {
    Ignore,
    RequireEqual,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirectionRule {
    Ignore,
    Equal,
    Opposite,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SpatialRule {
    EqualPrefix,
    RoutePrefixContainsEndpoint,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ClockRelation {
    SamePolicyAndId,
    /// An explicit comparability assertion, not a clock correction or guarantee.
    CallerComparable {
        basis: String,
    },
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MissingClockHandling {
    Unresolved,
    Error,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WindowSemantics {
    /// Compare supplied labels only; reported uncertainty is retained, not zeroed.
    LabelDistance,
    /// Require reported uncertainty on both sides. A straddling interval is
    /// unresolved, not silently rounded into or out of the inclusive window.
    AllReportedBounds,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TimePolicy {
    Ignore {
        reason: String,
    },
    Window {
        max_distance_ns: u64,
        clocks: ClockRelation,
        missing: MissingClockHandling,
        semantics: WindowSemantics,
    },
}

/// There is deliberately no Default policy. Namespace equality is always required.
/// A policy that ignores a dimension records that choice in the result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Policy {
    pub policy_id: String,
    pub session: DimensionRule,
    pub generation: DimensionRule,
    pub flow: DimensionRule,
    pub direction: DirectionRule,
    pub spatial: SpatialRule,
    pub time: TimePolicy,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum Reason {
    MissingNamespace,
    IncompatibleNamespace,
    MissingSession,
    IncompatibleSession,
    MissingGeneration,
    IncompatibleGeneration,
    MissingFlow,
    IncompatibleFlow,
    MissingDirection,
    IncompatibleDirection,
    MissingPrefix,
    IncompatiblePrefix,
    MissingEndpoint,
    IncompatibleEndpoint,
    UnsupportedDimension,
    MissingTime,
    UnknownClock,
    IncompatibleClock,
    UnknownUncertainty,
    UncertainWindow,
    OutsideWindow,
    InsufficientCoverage,
    InsufficientProvenance,
    MissingImportContext,
    DuplicateIdentity,
    ChangedContentConflict,
    ConflictingAttributes,
    MultipleCandidates,
    NotAnnouncement,
    NotCurrentCandidate,
    NoRouteEvidence,
    NoInternalEvidence,
    MetadataOnly,
}
impl Reason {
    pub fn name(self) -> &'static str {
        match self {
            Self::MissingNamespace => "missing_namespace",
            Self::IncompatibleNamespace => "incompatible_namespace",
            Self::MissingSession => "missing_session",
            Self::IncompatibleSession => "incompatible_session",
            Self::MissingGeneration => "missing_generation",
            Self::IncompatibleGeneration => "incompatible_generation",
            Self::MissingFlow => "missing_flow",
            Self::IncompatibleFlow => "incompatible_flow",
            Self::MissingDirection => "missing_direction",
            Self::IncompatibleDirection => "incompatible_direction",
            Self::MissingPrefix => "missing_prefix",
            Self::IncompatiblePrefix => "incompatible_prefix",
            Self::MissingEndpoint => "missing_endpoint",
            Self::IncompatibleEndpoint => "incompatible_endpoint",
            Self::UnsupportedDimension => "unsupported_dimension",
            Self::MissingTime => "missing_time",
            Self::UnknownClock => "unknown_clock",
            Self::IncompatibleClock => "incompatible_clock",
            Self::UnknownUncertainty => "unknown_uncertainty",
            Self::UncertainWindow => "uncertain_window",
            Self::OutsideWindow => "outside_window",
            Self::InsufficientCoverage => "insufficient_coverage",
            Self::InsufficientProvenance => "insufficient_provenance",
            Self::MissingImportContext => "missing_import_context",
            Self::DuplicateIdentity => "duplicate_identity",
            Self::ChangedContentConflict => "changed_content_conflict",
            Self::ConflictingAttributes => "conflicting_attributes",
            Self::MultipleCandidates => "multiple_candidates",
            Self::NotAnnouncement => "not_announcement",
            Self::NotCurrentCandidate => "not_current_candidate",
            Self::NoRouteEvidence => "no_route_evidence",
            Self::NoInternalEvidence => "no_internal_evidence",
            Self::MetadataOnly => "metadata_only",
        }
    }
    fn incompatible(self) -> bool {
        matches!(
            self,
            Self::IncompatibleNamespace
                | Self::IncompatibleSession
                | Self::IncompatibleGeneration
                | Self::IncompatibleFlow
                | Self::IncompatibleDirection
                | Self::IncompatiblePrefix
                | Self::IncompatibleEndpoint
                | Self::IncompatibleClock
                | Self::OutsideWindow
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AssociationStatus {
    CompatibleCandidate,
    Unresolved,
    Incompatible,
}
impl AssociationStatus {
    pub fn name(self) -> &'static str {
        match self {
            Self::CompatibleCandidate => "compatible_candidate",
            Self::Unresolved => "unresolved",
            Self::Incompatible => "incompatible",
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TimeComparison {
    pub label_distance_ns: Option<u128>,
    pub minimum_distance_ns: Option<u128>,
    pub maximum_distance_ns: Option<u128>,
    pub uncertainty_used: bool,
}
impl TimeComparison {
    fn unused() -> Self {
        Self {
            label_distance_ns: None,
            minimum_distance_ns: None,
            maximum_distance_ns: None,
            uncertainty_used: false,
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Association {
    /// Stable indices in this report's canonically sorted evidence arrays.
    pub route: Option<usize>,
    pub internal: Option<usize>,
    pub status: AssociationStatus,
    pub reasons: Vec<Reason>,
    pub time: TimeComparison,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvidenceEntry {
    data: Json,
    input_sha256: String,
    occurrences: usize,
    reasons: Vec<Reason>,
}
impl EvidenceEntry {
    pub fn data(&self) -> &Json {
        &self.data
    }
    pub fn occurrences(&self) -> usize {
        self.occurrences
    }
    pub fn input_sha256(&self) -> &str {
        &self.input_sha256
    }
    pub fn reasons(&self) -> &[Reason] {
        &self.reasons
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SelectionNote {
    reason: Reason,
    witness: Json,
}
impl SelectionNote {
    pub fn reason(&self) -> Reason {
        self.reason
    }
    pub fn witness(&self) -> &Json {
        &self.witness
    }
}

#[derive(Clone, Debug)]
struct Frozen {
    data: Json,
    encoded: String,
    record_identity: String,
    record_content: String,
    spans: usize,
}

/// Validated, immutable route-side input. The normalized producer envelope is
/// retained intact (except canonical object-key order) with its original ranges.
#[derive(Clone, Debug)]
pub struct RouteEvidence {
    frozen: Frozen,
    scope: Scope,
    prefix: PrefixIdentity,
    path_id: RoutePathId,
    time: TimeLabel,
    reasons: Vec<Reason>,
    native_key: String,
    path_identity: String,
    action: RouteAction,
}
impl RouteEvidence {
    pub fn from_normalized(
        value: &Json,
        route: usize,
        context: &RouteContext,
        l: &Limits,
    ) -> Result<Self> {
        // The existing normalizer/state validator remains the producer contract.
        let observation = Observation::from_normalized(value, None, l)?;
        Self::from_observation(&observation, route, context, l)
    }
    pub fn from_observation(
        o: &Observation,
        route: usize,
        context: &RouteContext,
        l: &Limits,
    ) -> Result<Self> {
        l.validate()?;
        if o.routes().len() > l.elements {
            return Err(Error::limit("bgp_association_routes"));
        }
        inspect(o.normalized(), l)?;
        o.normalized().encode_bounded(l.input_bytes)?;
        let spans = reference_count(o.normalized(), l)?;
        validate_route_context(context, l)?;
        let r = o.routes().get(route).ok_or_else(|| {
            bad(
                "bgp_association_route",
                0,
                "route index outside observation",
            )
        })?;
        validate_prefix(r.prefix(), l)?;
        let source = o.source();
        for s in [&source.source_id, &source.record_id] {
            identity(s, l)?;
        }
        for s in [&source.session, &source.peer, &source.local] {
            optional_identity(s, l)?;
        }
        if source.direction.is_some_and(|d| d > 1) {
            return Err(bad(
                "bgp_association_direction",
                0,
                "direction must be zero or one",
            ));
        }
        let mut reasons = Vec::new();
        let clock = if let Some(import) = o.import_context() {
            import.validate(l)?;
            if context.captured_or_legacy_clock.is_some() {
                return Err(bad(
                    "bgp_association_clock_override",
                    0,
                    "contextual import owns its clock metadata",
                ));
            }
            import.clock.clone()
        } else {
            if source.kind == SourceKind::Imported {
                reasons.push(Reason::MissingImportContext);
            }
            context.captured_or_legacy_clock.clone().unwrap_or_default()
        };
        let time = TimeLabel {
            observed_at_ns: source.observed_at_ns,
            clock,
        };
        validate_time(&time, l)?;
        let scope = Scope {
            namespace: context.namespace.clone(),
            session: source.session.clone(),
            generation: source.generation,
            direction: source.direction,
            flow_id: context.flow_id.clone(),
        };
        validate_scope(&scope, l)?;
        if context.coverage != Coverage::DeclaredComplete {
            reasons.push(Reason::InsufficientCoverage);
        }
        if r.action() != RouteAction::Announce {
            reasons.push(Reason::NotAnnouncement);
        }
        if r.ambiguous_attributes() {
            reasons.push(Reason::ConflictingAttributes);
        }
        // Unresolved producer semantics stay visible; the seam cannot decide
        // that a route is fully covered merely from a syntactically complete PDU.
        for issue in bgp_state::array(bgp_state::member(o.normalized(), "issues")?)? {
            let issue = bgp_state::text(issue)?;
            if !matches!(
                issue,
                "route_candidates_are_not_endpoint_state"
                    | "cross_source_correlation_requires_explicit_join"
                    | "imported_observation_not_wire_verified"
                    | "asn_width_derived_from_two_octet_default_or_open"
            ) {
                reasons.push(Reason::InsufficientCoverage);
            }
        }
        let partition = o
            .import_context()
            .map(|c| c.partition().json())
            .unwrap_or(Json::Null);
        let evidence = bgp_state::member(o.normalized(), "evidence")?;
        let locator = if source.kind == SourceKind::Captured {
            Json::object([
                ("packets", bgp_state::member(evidence, "packets")?.clone()),
                ("spans", bgp_state::member(evidence, "spans")?.clone()),
            ])
        } else {
            Json::Null
        };
        let record_identity = canonical(&Json::object([
            ("kind", source_name(source.kind).into()),
            ("source_id", source.source_id.clone().into()),
            ("session", optional(&source.session)),
            ("record_id", source.record_id.clone().into()),
            ("partition", partition.clone()),
            ("packet_locator", locator),
        ]))
        .encode_bounded(l.input_bytes)?;
        let record = Json::object([
            ("normalized", o.normalized().clone()),
            ("scope", scope_json(&scope)),
            ("time", time_json(&time)),
            ("coverage", coverage_name(context.coverage).into()),
            (
                "scope_basis",
                "caller_namespace_and_flow_producer_session_generation_direction".into(),
            ),
        ]);
        let record_content = canonical(&record).encode_bounded(l.input_bytes)?;
        let mut native_key_fields = vec![
            ("source_kind", source_name(source.kind).into()),
            ("source_id", source.source_id.clone().into()),
            ("session", optional(&source.session)),
            ("generation", unsigned(source.generation)),
            ("direction", source.direction.map_or(Json::Null, Json::from)),
            ("partition", partition),
            ("prefix", prefix_json(r.prefix())),
        ];
        if let RoutePathId::Present(path_id) = r.path_id() {
            native_key_fields.push(("path_id", path_id.into()));
        }
        let native_key =
            canonical(&Json::Object(native_key_fields)).encode_bounded(l.input_bytes)?;
        let raw_routes = bgp_state::array(bgp_state::member(o.normalized(), "routes")?)?;
        let raw_route = raw_routes
            .get(route)
            .ok_or_else(|| bad("bgp_association_route", 0, "missing normalized route"))?;
        let mut tokens = Vec::new();
        for range in bgp_state::array(bgp_state::member(raw_route, "attribute_ranges")?)? {
            let Json::Object(fields) = range else {
                return Err(bad(
                    "bgp_association_attributes",
                    0,
                    "attribute range is not an object",
                ));
            };
            tokens.push(Json::Object(
                fields
                    .iter()
                    .filter(|(k, _)| !matches!(*k, "start" | "end" | "value_start" | "value_end"))
                    .cloned()
                    .collect(),
            ));
        }
        let path_identity = canonical(&Json::object([
            ("attributes", r.attributes().clone()),
            ("attribute_tokens", Json::Array(tokens)),
        ]))
        .encode_bounded(l.input_bytes)?;
        normalize_reasons(&mut reasons);
        let data = Json::object([
            ("schema", INPUT_SCHEMA.into()),
            ("side", "bgp_route".into()),
            ("record", record),
            ("route_index", route.to_string().into()),
            (
                "selection",
                "normalized_observation_not_active_route_assertion".into(),
            ),
            ("selection_snapshot_sha256", Json::Null),
        ]);
        let frozen = freeze(data, record_identity, record_content, spans, l)?;
        if frozen
            .encoded
            .len()
            .saturating_add(frozen.record_identity.len())
            .saturating_add(frozen.record_content.len())
            .saturating_add(native_key.len())
            .saturating_add(path_identity.len())
            > l.retained_bytes
        {
            return Err(Error::limit("bgp_association_retained"));
        }
        Ok(Self {
            frozen,
            scope,
            prefix: r.prefix().clone(),
            path_id: r.path_id(),
            time,
            reasons,
            native_key,
            path_identity,
            action: r.action(),
        })
    }
    pub fn data(&self) -> &Json {
        &self.frozen.data
    }
    pub fn scope(&self) -> &Scope {
        &self.scope
    }
    pub fn prefix(&self) -> &PrefixIdentity {
        &self.prefix
    }
    pub fn path_id(&self) -> RoutePathId {
        self.path_id
    }
    pub fn time(&self) -> &TimeLabel {
        &self.time
    }
}

#[derive(Clone, Debug)]
pub struct InternalEvidence {
    frozen: Frozen,
    input: InternalInput,
}
impl InternalEvidence {
    pub fn new(input: InternalInput, l: &Limits) -> Result<Self> {
        l.validate()?;
        validate_source(&input.source, l)?;
        validate_dimensions(&input.dimensions, l)?;
        validate_time(&input.time, l)?;
        if input.provenance.ranges.len() > l.spans.min(l.elements) {
            return Err(Error::limit("bgp_association_spans"));
        }
        if let Some(h) = &input.provenance.record_sha256 {
            hash(h)?;
        }
        for s in &input.provenance.ranges {
            validate_range(s, input.source.batch.as_ref().and_then(|b| b.byte_length))?;
        }
        inspect(&input.provenance.details, l)?;
        input.provenance.details.encode_bounded(l.input_bytes)?;
        let record_identity = canonical(&Json::object([
            ("kind", internal_name(input.kind).into()),
            ("source", source_identity_json(&input.source)),
        ]))
        .encode_bounded(l.input_bytes)?;
        let data = Json::object([
            ("schema", INPUT_SCHEMA.into()),
            ("side", internal_name(input.kind).into()),
            ("source", source_identity_json(&input.source)),
            ("dimensions", dimensions_json(&input.dimensions)),
            ("time", time_json(&input.time)),
            ("coverage", coverage_name(input.coverage).into()),
            (
                "provenance",
                Json::object([
                    ("record_sha256", optional(&input.provenance.record_sha256)),
                    ("ranges", ranges_json(&input.provenance.ranges)),
                    ("details", input.provenance.details.clone()),
                ]),
            ),
            (
                "basis",
                "independently_produced_caller_adapted_not_verified_here".into(),
            ),
        ]);
        let content = canonical(&data).encode_bounded(l.input_bytes)?;
        let spans = checked_add(
            input.provenance.ranges.len(),
            reference_count(&input.provenance.details, l)?,
        )?;
        if spans > l.spans {
            return Err(Error::limit("bgp_association_spans"));
        }
        let frozen = freeze(data, record_identity, content, spans, l)?;
        Ok(Self { frozen, input })
    }
    pub fn data(&self) -> &Json {
        &self.frozen.data
    }
    pub fn input(&self) -> &InternalInput {
        &self.input
    }
}

/// A bounded selection. Candidate-state extraction also retains inactive rows
/// and boundary witnesses, so quarantine/reset/missing-scope is not hidden by an
/// empty active-route view. No state or captured/imported source is mutated.
#[derive(Clone, Debug)]
pub struct RouteBatch {
    routes: Vec<RouteEvidence>,
    notes: Vec<SelectionNote>,
    snapshot: Option<String>,
}
impl RouteBatch {
    pub fn new(routes: Vec<RouteEvidence>, l: &Limits) -> Result<Self> {
        let value = Self {
            routes,
            notes: Vec::new(),
            snapshot: None,
        };
        value.validate(l)?;
        Ok(value)
    }
    pub fn from_candidate_state(
        state: &CandidateState,
        context: &RouteContext,
        l: &Limits,
    ) -> Result<Self> {
        l.validate()?;
        validate_route_context(context, l)?;
        if state.encode().len() > l.input_bytes.min(l.retained_bytes)
            || state.encode().len() > l.work
        {
            return Err(Error::limit("bgp_association_state_input"));
        }
        if state.observations().len() > l.elements
            || state.routes().len() > l.elements
            || state.sessions().len() > l.active
        {
            return Err(Error::limit("bgp_association_state_count"));
        }
        let mut active: BTreeMap<(usize, usize), bool> = BTreeMap::new();
        let mut count = 0usize;
        for route in state.routes() {
            for a in &route.alternatives {
                for w in &a.witnesses {
                    count = checked_add(count, 1)?;
                    if count > l.elements {
                        return Err(Error::limit("bgp_association_state_witnesses"));
                    }
                    active
                        .entry((w.observation, w.route))
                        .and_modify(|v| *v |= route.conflicting())
                        .or_insert(route.conflicting());
                }
            }
        }
        let digest = sha256::hex(&sha256::digest(state.encode().as_bytes()));
        let mut routes = Vec::new();
        let mut notes = Vec::new();
        let mut budget = Budget::new(l);
        budget.charge(state.encode().len())?;
        for (oi, o) in state.observations().iter().enumerate() {
            budget.tree(o.normalized(), 1)?;
            let outcome = state
                .outcomes()
                .get(oi)
                .ok_or_else(|| bad("bgp_association_state", 0, "missing state outcome"))?;
            if o.routes().is_empty() {
                if notes.len() >= l.elements {
                    return Err(Error::limit("bgp_association_selection"));
                }
                budget.bytes(o.normalized().encode_bounded(l.input_bytes)?.len())?;
                budget.spans(reference_count(o.normalized(), l)?)?;
                notes.push(SelectionNote {
                    reason: if outcome.status == ApplyStatus::IdentityConflict {
                        Reason::ChangedContentConflict
                    } else {
                        Reason::MetadataOnly
                    },
                    witness: o.normalized().clone(),
                });
            }
            for ri in 0..o.routes().len() {
                if routes.len() >= l.elements {
                    return Err(Error::limit("bgp_association_routes"));
                }
                let mut row = RouteEvidence::from_observation(o, ri, context, l)?;
                budget.input(&row.frozen)?;
                if !active.contains_key(&(oi, ri)) {
                    row.reasons.push(Reason::NotCurrentCandidate);
                }
                if active.get(&(oi, ri)) == Some(&true) {
                    row.reasons.push(Reason::ConflictingAttributes);
                }
                if outcome.status == ApplyStatus::IdentityConflict {
                    row.reasons.push(Reason::ChangedContentConflict);
                }
                if outcome.status == ApplyStatus::MissingScope {
                    row.reasons.push(Reason::InsufficientCoverage);
                }
                let mut data = row.frozen.data.clone();
                replace(
                    &mut data,
                    "selection",
                    if active.contains_key(&(oi, ri)) {
                        "current_candidate_witness"
                    } else {
                        "inactive_or_unresolved_state_observation"
                    }
                    .into(),
                );
                replace(
                    &mut data,
                    "selection_snapshot_sha256",
                    digest.clone().into(),
                );
                normalize_reasons(&mut row.reasons);
                row.frozen = freeze(
                    data,
                    row.frozen.record_identity,
                    row.frozen.record_content,
                    row.frozen.spans,
                    l,
                )?;
                routes.push(row);
            }
        }
        let result = Self {
            routes,
            notes,
            snapshot: Some(digest),
        };
        result.validate(l)?;
        Ok(result)
    }
    pub fn routes(&self) -> &[RouteEvidence] {
        &self.routes
    }
    pub fn notes(&self) -> &[SelectionNote] {
        &self.notes
    }
    pub fn snapshot_sha256(&self) -> Option<&str> {
        self.snapshot.as_deref()
    }
    fn validate(&self, l: &Limits) -> Result<()> {
        l.validate()?;
        if self.routes.len().saturating_add(self.notes.len()) > l.elements {
            return Err(Error::limit("bgp_association_selection"));
        }
        let mut b = Budget::new(l);
        for r in &self.routes {
            b.input(&r.frozen)?;
            b.retain(r.native_key.len().saturating_add(r.path_identity.len()))?;
        }
        for n in &self.notes {
            b.tree(&n.witness, 1)?;
            b.bytes(n.witness.encode_bounded(l.input_bytes)?.len())?;
            b.spans(reference_count(&n.witness, l)?)?;
        }
        Ok(())
    }
}

/// Only returned after every input, pair, output and resource check succeeds.
/// No callback, streaming partial result, mutable consumer or hidden cache exists.
#[derive(Clone, Debug)]
pub struct AssociationReport {
    routes: Vec<EvidenceEntry>,
    internal: Vec<EvidenceEntry>,
    associations: Vec<Association>,
    notes: Vec<SelectionNote>,
    encoded: String,
}
impl AssociationReport {
    pub fn routes(&self) -> &[EvidenceEntry] {
        &self.routes
    }
    pub fn internal(&self) -> &[EvidenceEntry] {
        &self.internal
    }
    pub fn associations(&self) -> &[Association] {
        &self.associations
    }
    pub fn notes(&self) -> &[SelectionNote] {
        &self.notes
    }
    pub fn encode(&self) -> &str {
        &self.encoded
    }
}

pub fn associate(
    routes: &RouteBatch,
    internal: &[InternalEvidence],
    policy: &Policy,
    l: &Limits,
) -> Result<AssociationReport> {
    l.validate()?;
    validate_policy(policy, l)?;
    if routes
        .routes
        .len()
        .saturating_add(internal.len())
        .saturating_add(routes.notes.len())
        > l.elements
    {
        return Err(Error::limit("bgp_association_inputs"));
    }
    // Worst-case Cartesian output is bounded before comparison or publication.
    let pairs = if routes.routes.is_empty() || internal.is_empty() {
        routes.routes.len().saturating_add(internal.len()).max(1)
    } else {
        routes
            .routes
            .len()
            .checked_mul(internal.len())
            .ok_or_else(|| Error::limit("bgp_association_pairs"))?
    };
    if pairs
        .saturating_add(routes.routes.len())
        .saturating_add(internal.len())
        .saturating_add(routes.notes.len())
        > l.elements
    {
        return Err(Error::limit("bgp_association_pairs"));
    }
    let mut budget = Budget::new(l);
    let policy_json = policy_json(policy);
    budget.tree(&policy_json, 1)?;
    budget.bytes(policy_json.encode_bounded(l.input_bytes)?.len())?;
    for r in &routes.routes {
        budget.input(&r.frozen)?;
        budget.retain(r.native_key.len().saturating_add(r.path_identity.len()))?;
    }
    for i in internal {
        budget.input(&i.frozen)?;
    }
    for n in &routes.notes {
        budget.tree(&n.witness, 1)?;
        budget.bytes(n.witness.encode_bounded(l.input_bytes)?.len())?;
        budget.spans(reference_count(&n.witness, l)?)?;
    }
    // Charge sorting, identity/path comparison and each pair conservatively.
    let count = routes
        .routes
        .len()
        .saturating_add(internal.len())
        .saturating_add(routes.notes.len())
        .max(1);
    let logarithm = (usize::BITS - count.leading_zeros()) as usize + 1;
    budget.charge(
        budget
            .input_bytes
            .saturating_mul(logarithm.saturating_mul(8)),
    )?;
    budget.charge(pairs.saturating_mul(budget.input_bytes.saturating_add(256)))?;
    let mut scopes = BTreeSet::new();
    for r in &routes.routes {
        scopes.insert(r.native_key.as_str());
    }
    // active bounds retained route source/prefix keys and independent record identities;
    // it is a logical key budget, not a number of real endpoints or connections.
    for i in internal {
        scopes.insert(i.frozen.record_identity.as_str());
    }
    if scopes.len() > l.active {
        return Err(Error::limit("bgp_association_active_keys"));
    }

    let rr = sorted_unique(routes.routes.iter().map(|r| &r.frozen));
    let ii = sorted_unique(internal.iter().map(|r| &r.frozen));
    let route_lookup: BTreeMap<_, _> = routes
        .routes
        .iter()
        .map(|r| (r.frozen.encoded.as_str(), r))
        .collect();
    let internal_lookup: BTreeMap<_, _> = internal
        .iter()
        .map(|r| (r.frozen.encoded.as_str(), r))
        .collect();
    let mut route_entries = entries(&rr);
    let mut internal_entries = entries(&ii);
    let mut paths: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for r in &routes.routes {
        if r.action == RouteAction::Announce && !r.reasons.contains(&Reason::NotCurrentCandidate) {
            paths
                .entry(&r.native_key)
                .or_default()
                .insert(&r.path_identity);
        }
    }
    for (index, (f, _)) in rr.iter().enumerate() {
        let r = route_lookup[f.encoded.as_str()];
        route_entries[index]
            .reasons
            .extend(r.reasons.iter().copied());
        if paths
            .get(r.native_key.as_str())
            .is_some_and(|p| p.len() > 1)
        {
            route_entries[index]
                .reasons
                .push(Reason::ConflictingAttributes);
        }
        normalize_reasons(&mut route_entries[index].reasons);
    }
    for (index, (f, _)) in ii.iter().enumerate() {
        let i = &internal_lookup[f.encoded.as_str()].input;
        if i.coverage != Coverage::DeclaredComplete {
            internal_entries[index]
                .reasons
                .push(Reason::InsufficientCoverage);
        }
        if i.provenance.record_sha256.is_none()
            && i.provenance.ranges.is_empty()
            && i.provenance.details == Json::Null
        {
            internal_entries[index]
                .reasons
                .push(Reason::InsufficientProvenance);
        }
        normalize_reasons(&mut internal_entries[index].reasons);
    }
    let mut associations = Vec::new();
    for (ri, (r, _)) in rr.iter().enumerate() {
        for (ni, (i, _)) in ii.iter().enumerate() {
            let r = route_lookup[r.encoded.as_str()];
            let i = &internal_lookup[i.encoded.as_str()].input;
            let mut reasons = route_entries[ri].reasons.clone();
            reasons.extend(internal_entries[ni].reasons.iter().copied());
            compare_scope(&r.scope, &i.dimensions.scope, policy, &mut reasons);
            compare_spatial(&r.prefix, &i.dimensions, policy.spatial, &mut reasons)?;
            let time = compare_time(&r.time, &i.time, &policy.time, &mut reasons)?;
            normalize_reasons(&mut reasons);
            associations.push(Association {
                route: Some(ri),
                internal: Some(ni),
                status: status(&reasons),
                reasons,
                time,
            });
        }
    }
    // No compatible alternative is removed. Multiple plausible candidates are
    // explicitly unresolved even when one would rank higher in a real router.
    let mut multiplicity = vec![0usize; ii.len()];
    let mut route_multiplicity = vec![0usize; rr.len()];
    for a in &associations {
        if potential(a) {
            multiplicity[a.internal.unwrap_or(0)] += 1;
            route_multiplicity[a.route.unwrap_or(0)] += 1;
        }
    }
    for a in &mut associations {
        if potential(a)
            && (multiplicity[a.internal.unwrap_or(0)] > 1
                || route_multiplicity[a.route.unwrap_or(0)] > 1)
        {
            a.reasons.push(Reason::MultipleCandidates);
            normalize_reasons(&mut a.reasons);
            a.status = status(&a.reasons);
        }
    }
    if ii.is_empty() {
        for (ri, entry) in route_entries.iter().enumerate() {
            let mut reasons = entry.reasons.clone();
            reasons.push(Reason::NoInternalEvidence);
            normalize_reasons(&mut reasons);
            associations.push(Association {
                route: Some(ri),
                internal: None,
                status: AssociationStatus::Unresolved,
                reasons,
                time: TimeComparison::unused(),
            });
        }
    }
    if rr.is_empty() {
        for (ni, entry) in internal_entries.iter().enumerate() {
            let mut reasons = entry.reasons.clone();
            reasons.push(Reason::NoRouteEvidence);
            normalize_reasons(&mut reasons);
            associations.push(Association {
                route: None,
                internal: Some(ni),
                status: AssociationStatus::Unresolved,
                reasons,
                time: TimeComparison::unused(),
            });
        }
    }
    if rr.is_empty() && ii.is_empty() {
        associations.push(Association {
            route: None,
            internal: None,
            status: AssociationStatus::Unresolved,
            reasons: vec![Reason::NoRouteEvidence, Reason::NoInternalEvidence],
            time: TimeComparison::unused(),
        });
    }
    let mut notes = routes.notes.clone();
    notes.sort_by_key(|n| canonical(&n.witness).encode());
    // A conservative shape bound precedes construction of the output tree.
    let output_nodes = budget
        .nodes
        .saturating_add((rr.len().saturating_add(ii.len())).saturating_mul(20))
        .saturating_add(associations.len().saturating_mul(56))
        .saturating_add(notes.len().saturating_mul(4))
        .saturating_add(64);
    if output_nodes > l.fields {
        return Err(Error::limit("bgp_association_output_nodes"));
    }
    let data = Json::object([
        ("schema", SCHEMA.into()),
        ("policy", policy_json),
        ("candidate_snapshot_sha256", optional(&routes.snapshot)),
        ("endpoint_state_established", false.into()),
        ("rib_established", false.into()),
        ("best_path_selected", false.into()),
        ("reachability_established", false.into()),
        ("attack_established", false.into()),
        ("causality_established", false.into()),
        ("source_authority_established", false.into()),
        ("normative_conformance_certified", false.into()),
        (
            "issues",
            Json::array(
                [
                    "candidate_evidence_association_only",
                    "source_verification_and_ingestion_are_caller_responsibilities",
                    "clock_labels_are_not_order_or_causality",
                    "no_preferred_source_or_attribute_vote",
                    "all_cartesian_comparisons_retained_within_explicit_limits",
                    "input_provenance_is_not_authenticated_here",
                ]
                .into_iter()
                .map(Json::from),
            ),
        ),
        (
            "route_evidence",
            Json::array(route_entries.iter().map(entry_json)),
        ),
        (
            "internal_evidence",
            Json::array(internal_entries.iter().map(entry_json)),
        ),
        (
            "selection_notes",
            Json::array(notes.iter().map(|n| {
                Json::object([
                    ("reason", n.reason.name().into()),
                    ("witness", n.witness.clone()),
                ])
            })),
        ),
        (
            "associations",
            Json::array(associations.iter().map(association_json)),
        ),
    ]);
    let output_work = inspect(&data, l)?;
    budget.charge(output_work)?;
    budget.charge(budget.input_bytes.saturating_mul(4))?;
    let encoded = canonical(&data).encode_bounded(
        l.output_bytes
            .min(l.retained_bytes.saturating_sub(budget.retained)),
    )?;
    Ok(AssociationReport {
        routes: route_entries,
        internal: internal_entries,
        associations,
        notes,
        encoded,
    })
}

fn sorted_unique<'a>(values: impl Iterator<Item = &'a Frozen>) -> Vec<(&'a Frozen, usize)> {
    let mut sorted: Vec<_> = values.collect();
    sorted.sort_by(|a, b| a.encoded.cmp(&b.encoded));
    let mut result: Vec<(&Frozen, usize)> = Vec::new();
    for value in sorted {
        if let Some((old, count)) = result.last_mut() {
            if old.encoded == value.encoded {
                *count += 1;
                continue;
            }
        }
        result.push((value, 1));
    }
    result
}
fn entries(values: &[(&Frozen, usize)]) -> Vec<EvidenceEntry> {
    let mut identities: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for (v, _) in values {
        identities
            .entry(&v.record_identity)
            .or_default()
            .insert(&v.record_content);
    }
    values
        .iter()
        .map(|(v, count)| {
            let mut reasons = Vec::new();
            if *count > 1 {
                reasons.push(Reason::DuplicateIdentity);
            }
            if identities
                .get(v.record_identity.as_str())
                .is_some_and(|items| items.len() > 1)
            {
                reasons.push(Reason::ChangedContentConflict);
            }
            EvidenceEntry {
                data: v.data.clone(),
                input_sha256: sha256::hex(&sha256::digest(v.encoded.as_bytes())),
                occurrences: *count,
                reasons,
            }
        })
        .collect()
}
fn potential(a: &Association) -> bool {
    a.status != AssociationStatus::Incompatible
        && !a
            .reasons
            .iter()
            .any(|r| matches!(r, Reason::NotAnnouncement | Reason::NotCurrentCandidate))
}
fn compare_scope(a: &Scope, b: &Scope, p: &Policy, reasons: &mut Vec<Reason>) {
    equal(
        &a.namespace,
        &b.namespace,
        Reason::MissingNamespace,
        Reason::IncompatibleNamespace,
        reasons,
    );
    if p.session == DimensionRule::RequireEqual {
        equal(
            &a.session,
            &b.session,
            Reason::MissingSession,
            Reason::IncompatibleSession,
            reasons,
        );
    }
    if p.generation == DimensionRule::RequireEqual {
        equal(
            &a.generation,
            &b.generation,
            Reason::MissingGeneration,
            Reason::IncompatibleGeneration,
            reasons,
        );
    }
    if p.flow == DimensionRule::RequireEqual {
        equal(
            &a.flow_id,
            &b.flow_id,
            Reason::MissingFlow,
            Reason::IncompatibleFlow,
            reasons,
        );
    }
    if p.direction != DirectionRule::Ignore {
        match (a.direction, b.direction) {
            (Some(x), Some(y)) if (x == y) == (p.direction == DirectionRule::Equal) => {}
            (Some(_), Some(_)) => reasons.push(Reason::IncompatibleDirection),
            _ => reasons.push(Reason::MissingDirection),
        }
    }
}
fn equal<T: PartialEq>(
    a: &Option<T>,
    b: &Option<T>,
    missing: Reason,
    mismatch: Reason,
    r: &mut Vec<Reason>,
) {
    match (a, b) {
        (Some(x), Some(y)) if x == y => {}
        (Some(_), Some(_)) => r.push(mismatch),
        _ => r.push(missing),
    }
}
fn compare_spatial(
    route: &PrefixIdentity,
    other: &Dimensions,
    rule: SpatialRule,
    r: &mut Vec<Reason>,
) -> Result<()> {
    if !other.unsupported.is_empty()
        || other.prefix.as_ref().is_some_and(|p| !supported_prefix(p))
        || other
            .endpoint
            .as_ref()
            .is_some_and(|e| !matches!(e.afi, 1 | 2))
    {
        r.push(Reason::UnsupportedDimension);
    }
    if !supported_prefix(route) {
        r.push(Reason::UnsupportedDimension);
        return Ok(());
    }
    match rule {
        SpatialRule::EqualPrefix => match &other.prefix {
            None => r.push(Reason::MissingPrefix),
            Some(p) if !supported_prefix(p) => r.push(Reason::UnsupportedDimension),
            Some(p) => {
                if route.afi != p.afi
                    || route.safi != p.safi
                    || route.length != p.length
                    || ip(route.afi, &route.address)? != ip(p.afi, &p.address)?
                {
                    r.push(Reason::IncompatiblePrefix);
                }
            }
        },
        SpatialRule::RoutePrefixContainsEndpoint => match &other.endpoint {
            None => r.push(Reason::MissingEndpoint),
            Some(e) if !matches!(e.afi, 1 | 2) => r.push(Reason::UnsupportedDimension),
            Some(e) if e.afi != route.afi => r.push(Reason::IncompatibleEndpoint),
            Some(e) => {
                let a = octets(ip(route.afi, &route.address)?);
                let b = octets(ip(e.afi, &e.address)?);
                if (0..usize::from(route.length))
                    .any(|bit| a[bit / 8] & (0x80 >> (bit % 8)) != b[bit / 8] & (0x80 >> (bit % 8)))
                {
                    r.push(Reason::IncompatibleEndpoint);
                }
            }
        },
    }
    Ok(())
}
fn compare_time(
    a: &TimeLabel,
    b: &TimeLabel,
    policy: &TimePolicy,
    reasons: &mut Vec<Reason>,
) -> Result<TimeComparison> {
    let TimePolicy::Window {
        max_distance_ns,
        clocks,
        missing,
        semantics,
    } = policy
    else {
        return Ok(TimeComparison::unused());
    };
    let unresolved = |reason: Reason, reasons: &mut Vec<Reason>| -> Result<()> {
        if *missing == MissingClockHandling::Error {
            return Err(bad("bgp_association_clock", 0, reason.name()));
        }
        reasons.push(reason);
        Ok(())
    };
    let (Some(x), Some(y)) = (a.observed_at_ns, b.observed_at_ns) else {
        unresolved(Reason::MissingTime, reasons)?;
        return Ok(TimeComparison::unused());
    };
    if a.clock.policy == ClockPolicy::Unknown
        || b.clock.policy == ClockPolicy::Unknown
        || a.clock.clock_id.is_none()
        || b.clock.clock_id.is_none()
    {
        unresolved(Reason::UnknownClock, reasons)?;
        return Ok(TimeComparison::unused());
    }
    if *clocks == ClockRelation::SamePolicyAndId
        && (a.clock.policy != b.clock.policy || a.clock.clock_id != b.clock.clock_id)
    {
        reasons.push(Reason::IncompatibleClock);
        return Ok(TimeComparison::unused());
    }
    let distance = (i128::from(x) - i128::from(y)).unsigned_abs();
    let mut result = TimeComparison {
        label_distance_ns: Some(distance),
        minimum_distance_ns: None,
        maximum_distance_ns: None,
        uncertainty_used: false,
    };
    if *semantics == WindowSemantics::LabelDistance {
        if distance > u128::from(*max_distance_ns) {
            reasons.push(Reason::OutsideWindow);
        }
        return Ok(result);
    }
    let (Some(u), Some(v)) = (
        a.clock.reported_uncertainty_ns,
        b.clock.reported_uncertainty_ns,
    ) else {
        unresolved(Reason::UnknownUncertainty, reasons)?;
        return Ok(result);
    };
    let radius = u128::from(u) + u128::from(v);
    let minimum = distance.saturating_sub(radius);
    let maximum = distance + radius;
    result.minimum_distance_ns = Some(minimum);
    result.maximum_distance_ns = Some(maximum);
    result.uncertainty_used = true;
    if minimum > u128::from(*max_distance_ns) {
        reasons.push(Reason::OutsideWindow);
    } else if maximum > u128::from(*max_distance_ns) {
        reasons.push(Reason::UncertainWindow);
    }
    Ok(result)
}
fn normalize_reasons(r: &mut Vec<Reason>) {
    r.sort();
    r.dedup();
}
fn status(r: &[Reason]) -> AssociationStatus {
    if r.iter().any(|r| r.incompatible()) {
        AssociationStatus::Incompatible
    } else if r.is_empty() {
        AssociationStatus::CompatibleCandidate
    } else {
        AssociationStatus::Unresolved
    }
}

fn validate_policy(p: &Policy, l: &Limits) -> Result<()> {
    identity(&p.policy_id, l)?;
    match &p.time {
        TimePolicy::Ignore { reason } => identity(reason, l)?,
        TimePolicy::Window {
            clocks: ClockRelation::CallerComparable { basis },
            ..
        } => identity(basis, l)?,
        _ => {}
    }
    inspect(&policy_json(p), l)?;
    Ok(())
}
fn validate_route_context(c: &RouteContext, l: &Limits) -> Result<()> {
    optional_identity(&c.namespace, l)?;
    optional_identity(&c.flow_id, l)?;
    if let Some(clock) = &c.captured_or_legacy_clock {
        validate_clock(clock, l)?;
    }
    Ok(())
}
fn validate_scope(s: &Scope, l: &Limits) -> Result<()> {
    for v in [&s.namespace, &s.session, &s.flow_id] {
        optional_identity(v, l)?;
    }
    if s.direction.is_some_and(|d| d > 1) {
        return Err(bad(
            "bgp_association_direction",
            0,
            "direction must be zero or one",
        ));
    }
    Ok(())
}
fn validate_dimensions(d: &Dimensions, l: &Limits) -> Result<()> {
    validate_scope(&d.scope, l)?;
    if let Some(p) = &d.prefix {
        validate_prefix(p, l)?;
    }
    if let Some(e) = &d.endpoint {
        identity(&e.address, l)?;
        if matches!(e.afi, 1 | 2) {
            ip(e.afi, &e.address)?;
        }
    }
    if d.unsupported.len() > l.elements {
        return Err(Error::limit("bgp_association_dimensions"));
    }
    for s in &d.unsupported {
        identity(s, l)?;
    }
    Ok(())
}
fn validate_prefix(p: &PrefixIdentity, l: &Limits) -> Result<()> {
    identity(&p.address, l)?;
    if matches!(p.afi, 1 | 2) {
        let a = octets(ip(p.afi, &p.address)?);
        if usize::from(p.length) > a.len() * 8
            || (usize::from(p.length)..a.len() * 8).any(|bit| a[bit / 8] & (0x80 >> (bit % 8)) != 0)
        {
            return Err(bad(
                "bgp_association_prefix",
                0,
                "noncanonical or oversized prefix",
            ));
        }
    }
    Ok(())
}
fn supported_prefix(p: &PrefixIdentity) -> bool {
    matches!(p.afi, 1 | 2) && p.safi == 1
}
fn ip(afi: u16, s: &str) -> Result<IpAddr> {
    match afi {
        1 => s
            .parse::<Ipv4Addr>()
            .map(IpAddr::V4)
            .map_err(|_| bad("bgp_association_endpoint", 0, "invalid IPv4 address")),
        2 => s
            .parse::<Ipv6Addr>()
            .map(IpAddr::V6)
            .map_err(|_| bad("bgp_association_endpoint", 0, "invalid IPv6 address")),
        _ => Err(bad(
            "bgp_association_endpoint",
            0,
            "unsupported address family",
        )),
    }
}
fn octets(a: IpAddr) -> Vec<u8> {
    match a {
        IpAddr::V4(a) => a.octets().to_vec(),
        IpAddr::V6(a) => a.octets().to_vec(),
    }
}
fn validate_time(t: &TimeLabel, l: &Limits) -> Result<()> {
    validate_clock(&t.clock, l)
}
fn validate_clock(c: &ObservationClock, l: &Limits) -> Result<()> {
    optional_identity(&c.clock_id, l)?;
    if c.policy == ClockPolicy::Unknown
        && (c.clock_id.is_some() || c.reported_uncertainty_ns.is_some())
    {
        return Err(bad(
            "bgp_association_clock",
            0,
            "unknown clock cannot assert identity or uncertainty",
        ));
    }
    Ok(())
}
fn validate_source(s: &SourceIdentity, l: &Limits) -> Result<()> {
    for s in [&s.source_id, &s.record_id, &s.schema] {
        identity(s, l)?;
    }
    optional_identity(&s.version, l)?;
    optional_identity(&s.checkpoint_id, l)?;
    if let Some(b) = &s.batch {
        optional_identity(&b.batch_id, l)?;
        if let Some(h) = &b.sha256 {
            hash(h)?;
        }
        if b.batch_id.is_none() && b.sha256.is_none() {
            return Err(bad(
                "bgp_association_batch",
                0,
                "batch needs an identity or hash",
            ));
        }
    }
    Ok(())
}
fn validate_range(s: &SourceRange, extent: Option<u64>) -> Result<()> {
    if s.start >= s.end || extent.is_some_and(|n| s.end > n) {
        return Err(bad("bgp_association_range", 0, "invalid source range"));
    }
    if let Some(h) = &s.sha256 {
        hash(h)?;
    }
    Ok(())
}
fn identity(s: &str, l: &Limits) -> Result<()> {
    if s.len() > l.input_bytes.min(1024) {
        return Err(Error::limit("bgp_association_metadata"));
    }
    if s.trim().is_empty() || s.chars().any(char::is_control) {
        return Err(bad(
            "bgp_association_identity",
            0,
            "nonempty control-free identity required",
        ));
    }
    Ok(())
}
fn optional_identity(s: &Option<String>, l: &Limits) -> Result<()> {
    if let Some(s) = s {
        identity(s, l)?;
    }
    Ok(())
}
fn hash(s: &str) -> Result<()> {
    if s.len() != 64
        || !s
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(bad(
            "bgp_association_hash",
            0,
            "expected lowercase SHA-256 text",
        ));
    }
    Ok(())
}
fn checked_add(a: usize, b: usize) -> Result<usize> {
    a.checked_add(b)
        .ok_or_else(|| Error::limit("bgp_association_size"))
}
fn freeze(
    data: Json,
    record_identity: String,
    record_content: String,
    spans: usize,
    l: &Limits,
) -> Result<Frozen> {
    inspect(&data, l)?;
    if spans > l.spans {
        return Err(Error::limit("bgp_association_spans"));
    }
    let data = canonical(&data);
    let encoded = data.encode_bounded(l.input_bytes.min(l.retained_bytes))?;
    if encoded
        .len()
        .saturating_add(record_identity.len())
        .saturating_add(record_content.len())
        > l.retained_bytes
    {
        return Err(Error::limit("bgp_association_retained"));
    }
    Ok(Frozen {
        data,
        encoded,
        record_identity,
        record_content,
        spans,
    })
}

struct Budget<'a> {
    l: &'a Limits,
    nodes: usize,
    used: usize,
    input_bytes: usize,
    retained: usize,
    spans: usize,
}
impl<'a> Budget<'a> {
    fn new(l: &'a Limits) -> Self {
        Self {
            l,
            nodes: 0,
            used: 0,
            input_bytes: 0,
            retained: 0,
            spans: 0,
        }
    }
    fn charge(&mut self, n: usize) -> Result<()> {
        self.used = checked_add(self.used, n)?;
        if self.used > self.l.work {
            return Err(Error::limit("bgp_association_work"));
        }
        Ok(())
    }
    fn bytes(&mut self, n: usize) -> Result<()> {
        self.input_bytes = checked_add(self.input_bytes, n)?;
        self.retain(n)?;
        if self.input_bytes > self.l.input_bytes.min(self.l.retained_bytes) {
            return Err(Error::limit("bgp_association_input_bytes"));
        }
        Ok(())
    }
    fn retain(&mut self, n: usize) -> Result<()> {
        self.retained = checked_add(self.retained, n)?;
        if self.retained > self.l.retained_bytes {
            return Err(Error::limit("bgp_association_retained"));
        }
        Ok(())
    }
    fn spans(&mut self, n: usize) -> Result<()> {
        self.spans = checked_add(self.spans, n)?;
        if self.spans > self.l.spans {
            return Err(Error::limit("bgp_association_spans"));
        }
        Ok(())
    }
    fn input(&mut self, f: &Frozen) -> Result<()> {
        self.tree(&f.data, 1)?;
        self.bytes(f.encoded.len())?;
        self.spans(f.spans)?;
        self.retain(
            f.record_identity
                .len()
                .saturating_add(f.record_content.len()),
        )?;
        self.charge(
            f.record_identity
                .len()
                .saturating_add(f.record_content.len())
                .saturating_add(f.encoded.len()),
        )
    }
    fn tree(&mut self, v: &Json, depth: usize) -> Result<()> {
        if depth > self.l.depth {
            return Err(Error::limit("bgp_association_depth"));
        }
        self.nodes = checked_add(self.nodes, 1)?;
        if self.nodes > self.l.fields {
            return Err(Error::limit("bgp_association_fields"));
        }
        self.charge(1)?;
        match v {
            Json::String(s) => {
                if s.len() > self.l.input_bytes {
                    return Err(Error::limit("bgp_association_string"));
                }
                self.charge(s.len())?;
            }
            Json::Array(v) => {
                if v.len() > self.l.fields {
                    return Err(Error::limit("bgp_association_nodes"));
                }
                for item in v {
                    self.tree(item, depth + 1)?;
                }
            }
            Json::Object(v) => {
                if v.len() > self.l.fields {
                    return Err(Error::limit("bgp_association_nodes"));
                }
                let mut keys = BTreeSet::new();
                for (key, value) in v {
                    self.charge(key.len())?;
                    if !keys.insert(*key) {
                        return Err(bad(
                            "bgp_association_duplicate_key",
                            0,
                            "duplicate JSON key",
                        ));
                    }
                    if matches!(
                        *key,
                        "endpoint_state_established"
                            | "rib_established"
                            | "best_path_selected"
                            | "reachability_established"
                            | "attack_established"
                            | "causality_established"
                            | "source_authority_established"
                            | "normative_conformance_certified"
                    ) && value != &Json::Bool(false)
                    {
                        return Err(bad(
                            "bgp_association_authority",
                            0,
                            "authority claims must be absent or false",
                        ));
                    }
                    self.tree(value, depth + 1)?;
                }
            }
            _ => {}
        }
        Ok(())
    }
}
fn inspect(v: &Json, l: &Limits) -> Result<usize> {
    let mut b = Budget::new(l);
    b.tree(v, 1)?;
    Ok(b.used)
}
fn reference_count(v: &Json, l: &Limits) -> Result<usize> {
    // A prior tree check bounds recursion, nodes and key/string sizes.
    inspect(v, l)?;
    fn count(v: &Json) -> Result<usize> {
        let mut n = 0usize;
        match v {
            Json::Object(items) => {
                for (key, v) in items {
                    if matches!(*key, "spans" | "packets" | "provenance" | "ranges") {
                        if let Json::Array(a) = v {
                            n = checked_add(n, a.len())?;
                        }
                    }
                    n = checked_add(n, count(v)?)?;
                }
            }
            Json::Array(items) => {
                for v in items {
                    n = checked_add(n, count(v)?)?;
                }
            }
            _ => {}
        }
        Ok(n)
    }
    let n = count(v)?;
    if n > l.spans {
        return Err(Error::limit("bgp_association_spans"));
    }
    Ok(n)
}
fn canonical(v: &Json) -> Json {
    match v {
        Json::Object(items) => {
            let mut items: Vec<_> = items.iter().map(|(k, v)| (*k, canonical(v))).collect();
            items.sort_by_key(|(k, _)| *k);
            Json::Object(items)
        }
        Json::Array(items) => Json::Array(items.iter().map(canonical).collect()),
        _ => v.clone(),
    }
}
fn replace(v: &mut Json, key: &'static str, value: Json) {
    if let Json::Object(fields) = v {
        if let Some((_, old)) = fields.iter_mut().find(|(k, _)| *k == key) {
            *old = value;
        }
    }
}
fn optional(v: &Option<String>) -> Json {
    v.clone().map_or(Json::Null, Json::String)
}
fn unsigned(v: Option<u64>) -> Json {
    v.map_or(Json::Null, |v| v.to_string().into())
}
fn wide(v: Option<u128>) -> Json {
    v.map_or(Json::Null, |v| v.to_string().into())
}
fn source_name(v: SourceKind) -> &'static str {
    match v {
        SourceKind::Captured => "captured",
        SourceKind::Imported => "imported",
    }
}
fn internal_name(v: InternalKind) -> &'static str {
    match v {
        InternalKind::Flow => "internal_flow",
        InternalKind::Security => "internal_security",
    }
}
fn coverage_name(v: Coverage) -> &'static str {
    match v {
        Coverage::DeclaredComplete => "caller_declared_complete",
        Coverage::Incomplete => "incomplete",
        Coverage::Unknown => "unknown",
    }
}
fn clock_name(v: ClockPolicy) -> &'static str {
    match v {
        ClockPolicy::Unknown => "unknown",
        ClockPolicy::SourceLabel => "source_label",
        ClockPolicy::IngestionLabel => "ingestion_label",
    }
}
fn prefix_json(p: &PrefixIdentity) -> Json {
    Json::object([
        ("afi", p.afi.into()),
        ("safi", p.safi.into()),
        ("length", p.length.into()),
        ("address", p.address.clone().into()),
    ])
}
fn endpoint_json(e: &EndpointIdentity) -> Json {
    Json::object([("afi", e.afi.into()), ("address", e.address.clone().into())])
}
fn scope_json(s: &Scope) -> Json {
    Json::object([
        ("namespace", optional(&s.namespace)),
        ("session", optional(&s.session)),
        ("generation", unsigned(s.generation)),
        ("flow_id", optional(&s.flow_id)),
        ("direction", s.direction.map_or(Json::Null, Json::from)),
    ])
}
fn dimensions_json(d: &Dimensions) -> Json {
    Json::object([
        ("scope", scope_json(&d.scope)),
        ("prefix", d.prefix.as_ref().map_or(Json::Null, prefix_json)),
        (
            "endpoint",
            d.endpoint.as_ref().map_or(Json::Null, endpoint_json),
        ),
        (
            "unsupported",
            Json::array(d.unsupported.iter().cloned().map(Json::from)),
        ),
    ])
}
fn time_json(t: &TimeLabel) -> Json {
    Json::object([
        (
            "observed_at_ns",
            t.observed_at_ns
                .map_or(Json::Null, |n| n.to_string().into()),
        ),
        (
            "clock",
            Json::object([
                ("policy", clock_name(t.clock.policy).into()),
                ("clock_id", optional(&t.clock.clock_id)),
                (
                    "reported_uncertainty_ns",
                    unsigned(t.clock.reported_uncertainty_ns),
                ),
                ("accuracy_verified", false.into()),
            ]),
        ),
    ])
}
fn batch_json(b: &SourceBatch) -> Json {
    Json::object([
        ("batch_id", optional(&b.batch_id)),
        ("sha256", optional(&b.sha256)),
        ("byte_length", unsigned(b.byte_length)),
    ])
}
fn source_identity_json(s: &SourceIdentity) -> Json {
    Json::object([
        ("source_id", s.source_id.clone().into()),
        ("record_id", s.record_id.clone().into()),
        ("source_schema", s.schema.clone().into()),
        ("source_version", optional(&s.version)),
        ("batch", s.batch.as_ref().map_or(Json::Null, batch_json)),
        ("checkpoint_id", optional(&s.checkpoint_id)),
    ])
}
fn ranges_json(ranges: &[SourceRange]) -> Json {
    Json::array(ranges.iter().map(|r| {
        Json::object([
            ("start", r.start.to_string().into()),
            ("end", r.end.to_string().into()),
            ("sha256", optional(&r.sha256)),
        ])
    }))
}
fn policy_json(p: &Policy) -> Json {
    let rule = |r: DimensionRule| {
        if r == DimensionRule::Ignore {
            "ignore"
        } else {
            "require_equal"
        }
    };
    let time = match &p.time {
        TimePolicy::Ignore { reason } => Json::object([
            ("mode", "ignore_labels".into()),
            ("reason", reason.clone().into()),
        ]),
        TimePolicy::Window {
            max_distance_ns,
            clocks,
            missing,
            semantics,
        } => Json::object([
            ("mode", "inclusive_absolute_distance".into()),
            ("max_distance_ns", max_distance_ns.to_string().into()),
            (
                "clocks",
                match clocks {
                    ClockRelation::SamePolicyAndId => {
                        Json::object([("mode", "same_policy_and_id".into())])
                    }
                    ClockRelation::CallerComparable { basis } => Json::object([
                        ("mode", "caller_comparable".into()),
                        ("basis", basis.clone().into()),
                    ]),
                },
            ),
            (
                "missing",
                if *missing == MissingClockHandling::Error {
                    "error"
                } else {
                    "unresolved"
                }
                .into(),
            ),
            (
                "semantics",
                if *semantics == WindowSemantics::LabelDistance {
                    "label_distance_only"
                } else {
                    "all_reported_bounds"
                }
                .into(),
            ),
        ]),
    };
    Json::object([
        ("policy_id", p.policy_id.clone().into()),
        ("namespace", "require_equal".into()),
        ("session", rule(p.session).into()),
        ("generation", rule(p.generation).into()),
        ("flow", rule(p.flow).into()),
        (
            "direction",
            match p.direction {
                DirectionRule::Ignore => "ignore",
                DirectionRule::Equal => "equal",
                DirectionRule::Opposite => "opposite",
            }
            .into(),
        ),
        (
            "spatial",
            match p.spatial {
                SpatialRule::EqualPrefix => "equal_prefix",
                SpatialRule::RoutePrefixContainsEndpoint => "route_prefix_contains_endpoint",
            }
            .into(),
        ),
        ("time", time),
    ])
}
fn entry_json(e: &EvidenceEntry) -> Json {
    Json::object([
        ("evidence", e.data.clone()),
        ("input_sha256", e.input_sha256.clone().into()),
        ("occurrences", e.occurrences.to_string().into()),
        (
            "reasons",
            Json::array(e.reasons.iter().map(|r| r.name().into())),
        ),
    ])
}
fn association_json(a: &Association) -> Json {
    Json::object([
        (
            "route",
            a.route.map_or(Json::Null, |n| n.to_string().into()),
        ),
        (
            "internal",
            a.internal.map_or(Json::Null, |n| n.to_string().into()),
        ),
        ("status", a.status.name().into()),
        (
            "reasons",
            Json::array(a.reasons.iter().map(|r| r.name().into())),
        ),
        (
            "time",
            Json::object([
                ("label_distance_ns", wide(a.time.label_distance_ns)),
                ("minimum_distance_ns", wide(a.time.minimum_distance_ns)),
                ("maximum_distance_ns", wide(a.time.maximum_distance_ns)),
                ("uncertainty_used", a.time.uncertainty_used.into()),
            ]),
        ),
    ])
}
