//! Generic, caller-asserted imported evidence context. No I/O or wire authority.
//! Immutable identities partition observations; clocks never order them.
use super::bgp::{self, ImportedRouteObservation, PathAttributes, Prefix};
use super::bgp_state::{
    self, array, member, number, optional_direction, optional_text, text, tree_budget,
};
use super::model::{bad, Limits};
use pcap_evidence::{json::Json, Error, Result};

pub const CONTEXT_SCHEMA: &str = "pcap-evidence.bgp.import-context.v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClockPolicy {
    Unknown,
    SourceLabel,
    IngestionLabel,
}
impl ClockPolicy {
    fn name(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::SourceLabel => "source_label",
            Self::IngestionLabel => "ingestion_label",
        }
    }
}

/// Accuracy is a caller label, not a measured guarantee. None is never zero.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservationClock {
    pub policy: ClockPolicy,
    pub clock_id: Option<String>,
    pub reported_uncertainty_ns: Option<u64>,
}
impl Default for ObservationClock {
    fn default() -> Self {
        Self {
            policy: ClockPolicy::Unknown,
            clock_id: None,
            reported_uncertainty_ns: None,
        }
    }
}

/// At least one of batch_id or sha256 is required. Neither authenticates a source.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct SourceBatch {
    pub batch_id: Option<String>,
    pub sha256: Option<String>,
    pub byte_length: Option<u64>,
}

/// A source-relative half-open interval, NOT a packet span. Order and repeats stay.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceRange {
    pub start: u64,
    pub end: u64,
    pub sha256: Option<String>,
}

/// Everything here is supplied, not inferred from timestamps, peers or paths.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImportContext {
    pub source_id: String,
    pub source_schema: String,
    pub source_version: Option<String>,
    pub clock: ObservationClock,
    pub batch: SourceBatch,
    pub checkpoint_id: String,
    pub session: String,
    pub generation: u64,
    pub direction: Option<u8>,
    pub peer: Option<String>,
    pub local: Option<String>,
    pub provenance: Vec<SourceRange>,
}

/// A source-local continuity cut with its original immutable witness.
/// Its exact scope may become known after a partial header is enriched, without
/// changing the decoder session or permitting same-generation route currency.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImportContinuityCut {
    pub context: ImportContext,
    pub record_id: String,
    pub reason: String,
}

/// Producer-owned source semantics. Opaque references are evidence, not input
/// to this classification or a substitute for checked observation bindings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ImportedSourceEventKind {
    Open,
    Keepalive,
    Update,
    Notification,
    RouteRefresh,
    SessionMetadata,
    ContinuityGap,
    /// A source occurrence that caused a decoder generation boundary. Its
    /// context preserves the occurrence's original reported generation; this
    /// classification is not a standalone native reset command.
    GenerationBoundary,
    Opaque,
}

/// A continuity mutation admitted by the native reducer for this exact source
/// occurrence. Reporting context is retained separately; it cannot redefine the
/// native affected generation or turn immutable replay into another mutation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImportedNativeContinuity {
    pub scope: super::bgp_rib::RibScope,
    pub record_id: String,
    pub reason: String,
    pub native_status: super::bgp_rib::ApplyStatus,
    pub(crate) kind: super::bgp_rib::NativeContinuityKind,
    pub(crate) effect: super::bgp_rib::NativeContinuityEffect,
}
impl ImportedNativeContinuity {
    pub fn is_reset(&self) -> bool {
        matches!(
            self.kind,
            super::bgp_rib::NativeContinuityKind::Reset { .. }
        )
    }
    pub fn generations(&self) -> (u64, u64) {
        match self.kind {
            super::bgp_rib::NativeContinuityKind::Gap => {
                (self.scope.generation, self.scope.generation)
            }
            super::bgp_rib::NativeContinuityKind::Reset {
                previous_generation,
                next_generation,
            } => (previous_generation, next_generation),
        }
    }
    pub fn affects_scope(&self, candidate: &super::bgp_rib::RibScope) -> bool {
        super::bgp_rib::continuity_affects_scope(self.kind, self.effect, &self.scope, candidate)
    }
    pub fn json(&self) -> Json {
        let (previous, next) = self.generations();
        let effect = match self.effect {
            super::bgp_rib::NativeContinuityEffect::SessionGeneration => "session_generation",
            super::bgp_rib::NativeContinuityEffect::SessionAllGenerations => {
                "session_all_generations"
            }
            super::bgp_rib::NativeContinuityEffect::BaseDirectionalGeneration => {
                "base_directional_generation"
            }
        };
        Json::object([
            ("kind", if self.is_reset() { "reset" } else { "gap" }.into()),
            ("affected_scope", effect.into()),
            ("source_id", self.scope.source.source_id.clone().into()),
            (
                "partition_id",
                self.scope.source.partition_id.clone().into(),
            ),
            ("session", self.scope.session.clone().into()),
            ("reporting_generation", self.scope.generation.into()),
            (
                "direction",
                self.scope.direction.map_or(Json::Null, Json::from),
            ),
            (
                "peer",
                self.scope.peer.clone().map_or(Json::Null, Json::from),
            ),
            ("previous_generation", previous.into()),
            ("next_generation", next.into()),
            ("native_status", format!("{:?}", self.native_status).into()),
            ("record_id", self.record_id.clone().into()),
            ("reason", self.reason.clone().into()),
        ])
    }
    pub fn retained_charge(&self) -> usize {
        std::mem::size_of::<Self>()
            .saturating_add(self.scope.source.source_id.len())
            .saturating_add(self.scope.source.partition_id.len())
            .saturating_add(self.scope.session.len())
            .saturating_add(self.scope.peer.as_ref().map_or(0, String::len))
            .saturating_add(self.record_id.len())
            .saturating_add(self.reason.len())
    }
}
/// The native owner supplies the effect before commit. Admit the retained
/// carrier against the complete prospective replay footprint before copying it.
/// Admission is (external retained, total work including all committed native
/// work, collector retained factor, collector copy-work factor). The collector
/// is not yet charged in the caller totals; prepared native growth is added once.
pub(crate) fn apply_native_event(
    rib: &mut super::bgp_rib::AdjRibIn,
    event: super::bgp_rib::RibEvent,
    origin: Option<[u8; 32]>,
    effects: &mut Vec<ImportedNativeContinuity>,
    admission: (usize, usize, usize, usize),
    limits: &Limits,
) -> Result<super::bgp_rib::ApplyStatus> {
    let plan = if let Some(origin) = origin {
        rib.prepare_with_origin(event, origin)?
    } else {
        rib.prepare(event)?
    };
    let status = plan.status();
    let added = plan.continuity_effect().map_or(0, |effect| {
        std::mem::size_of::<ImportedNativeContinuity>()
            .saturating_add(effect.scope.source.source_id.len())
            .saturating_add(effect.scope.source.partition_id.len())
            .saturating_add(effect.scope.session.len())
            .saturating_add(effect.scope.peer.as_ref().map_or(0, String::len))
            .saturating_add(effect.record_id.len())
            .saturating_add(effect.reason.len())
    });
    let charge = effects
        .iter()
        .try_fold(added, |n, e| n.checked_add(e.retained_charge()))
        .ok_or_else(|| Error::limit("bgp_import_native_continuity"))?;
    if (added != 0 && effects.len() >= limits.elements)
        || charge
            .checked_mul(admission.2)
            .and_then(|n| n.checked_add(admission.0))
            .and_then(|n| n.checked_add(plan.prospective_retained_bytes()))
            .is_none_or(|n| n > limits.retained_bytes)
        || plan
            .prospective_work()
            .checked_sub(rib.accounted_work())
            .and_then(|n| n.checked_add(admission.1))
            .and_then(|n| {
                charge
                    .checked_mul(admission.3)
                    .and_then(|copy| n.checked_add(copy))
            })
            .is_none_or(|n| n > limits.work)
    {
        return Err(Error::limit("bgp_import_native_continuity"));
    }
    if let Some(effect) = plan.continuity_effect() {
        effects
            .try_reserve(1)
            .map_err(|_| Error::limit("bgp_import_native_continuity"))?;
        effects.push(ImportedNativeContinuity {
            scope: effect.scope.clone(),
            record_id: effect.record_id.into(),
            reason: effect.reason.into(),
            native_status: effect.status,
            kind: effect.kind,
            effect: effect.effect,
        });
    }
    debug_assert!(rib.prepared_current(&plan));
    rib.commit(plan);
    Ok(status)
}

/// An exact imported source occurrence, including route-free and rejected
/// records. The enclosing verified archive binds the source-store receipt.
#[derive(Clone, Debug)]
pub struct ImportedSourceEvent {
    /// Source identity from the enclosing verified raw-source producer.
    pub source_id: String,
    pub checkpoint_id: String,
    /// Actual newly admitted native mutations; an empty inventory is inert.
    pub native_continuity: Vec<ImportedNativeContinuity>,
    pub source_record_index: usize,
    pub observation_index: Option<usize>,
    pub kind: ImportedSourceEventKind,
    pub context: Option<ImportContext>,
    pub continuity_cuts: Vec<ImportContinuityCut>,
    pub reference: Json,
}

/// Separate checkpoint/batch namespaces never act as continuation of each other.
/// Clock and record spans are record metadata, not partition selection inputs.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct ImportPartition {
    pub source_schema: String,
    pub source_version: Option<String>,
    pub batch: SourceBatch,
    pub checkpoint_id: String,
    pub peer: Option<String>,
    pub local: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GenerationBoundary {
    pub previous_generation: u64,
    pub reason: String,
}

fn optional(s: &Option<String>) -> Json {
    s.clone().map_or(Json::Null, Json::String)
}
fn optional_number(n: Option<u64>) -> Json {
    n.map_or(Json::Null, |v| v.to_string().into())
}
fn optional_u64(v: &Json) -> Result<Option<u64>> {
    if v == &Json::Null {
        Ok(None)
    } else {
        Ok(Some(number(v)?))
    }
}
fn identity(s: &str, l: &Limits) -> Result<()> {
    if s.len() > l.input_bytes.min(1024) {
        return Err(Error::limit("bgp_import_metadata"));
    }
    if s.trim().is_empty() || s.chars().any(char::is_control) {
        return Err(bad(
            "bgp_import_identity",
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
            "bgp_import_hash",
            0,
            "expected 64 lowercase SHA-256 hexadecimal digits",
        ));
    }
    Ok(())
}
fn exact_keys(value: &Json, keys: &[&str]) -> Result<()> {
    let Json::Object(items) = value else {
        return Err(bad("bgp_import_shape", 0, "expected object"));
    };
    if items.len() != keys.len() || items.iter().any(|(k, _)| !keys.contains(k)) {
        return Err(bad(
            "bgp_import_shape",
            0,
            "missing or unknown context field",
        ));
    }
    // Duplicate keys are rejected by tree_budget before this helper is used.
    Ok(())
}
impl SourceBatch {
    fn validate(&self, l: &Limits) -> Result<()> {
        optional_identity(&self.batch_id, l)?;
        if let Some(h) = &self.sha256 {
            hash(h)?;
        }
        if self.batch_id.is_none() && self.sha256.is_none() {
            return Err(bad(
                "bgp_import_batch",
                0,
                "immutable batch identity or source hash required",
            ));
        }
        Ok(())
    }
    fn json(&self) -> Json {
        Json::object([
            ("batch_id", optional(&self.batch_id)),
            ("sha256", optional(&self.sha256)),
            ("byte_length", optional_number(self.byte_length)),
        ])
    }
    fn from_json(v: &Json) -> Result<Self> {
        exact_keys(v, &["batch_id", "sha256", "byte_length"])?;
        Ok(Self {
            batch_id: optional_text(member(v, "batch_id")?)?,
            sha256: optional_text(member(v, "sha256")?)?,
            byte_length: optional_u64(member(v, "byte_length")?)?,
        })
    }
}
impl ImportPartition {
    pub(crate) fn json(&self) -> Json {
        Json::object([
            ("source_schema", self.source_schema.clone().into()),
            ("source_version", optional(&self.source_version)),
            ("batch", self.batch.json()),
            ("checkpoint_id", self.checkpoint_id.clone().into()),
            ("peer", optional(&self.peer)),
            ("local", optional(&self.local)),
        ])
    }
}
impl ImportContext {
    /// Conservative logical retention charge without allocating JSON or
    /// cloning metadata. Callers may multiply by six to admit escaped output.
    pub fn retained_charge(&self) -> Result<usize> {
        let mut bytes = 1024usize;
        for value in [
            Some(self.source_id.as_str()),
            Some(self.source_schema.as_str()),
            self.source_version.as_deref(),
            self.clock.clock_id.as_deref(),
            self.batch.batch_id.as_deref(),
            self.batch.sha256.as_deref(),
            Some(self.checkpoint_id.as_str()),
            Some(self.session.as_str()),
            self.peer.as_deref(),
            self.local.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            bytes = bytes
                .checked_add(value.len())
                .ok_or_else(|| Error::limit("bgp_import_retained"))?;
        }
        for range in &self.provenance {
            bytes = bytes
                .checked_add(128)
                .and_then(|n| n.checked_add(range.sha256.as_ref().map_or(0, String::len)))
                .ok_or_else(|| Error::limit("bgp_import_retained"))?;
        }
        Ok(bytes)
    }

    pub(crate) fn partition(&self) -> ImportPartition {
        ImportPartition {
            source_schema: self.source_schema.clone(),
            source_version: self.source_version.clone(),
            batch: self.batch.clone(),
            checkpoint_id: self.checkpoint_id.clone(),
            peer: self.peer.clone(),
            local: self.local.clone(),
        }
    }
    pub fn validate(&self, l: &Limits) -> Result<()> {
        l.validate()?;
        for s in [
            &self.source_id,
            &self.source_schema,
            &self.checkpoint_id,
            &self.session,
        ] {
            identity(s, l)?;
        }
        for s in [
            &self.source_version,
            &self.peer,
            &self.local,
            &self.clock.clock_id,
        ] {
            optional_identity(s, l)?;
        }
        self.batch.validate(l)?;
        let mut metadata_bytes = 0usize;
        for s in [
            &self.source_id,
            &self.source_schema,
            &self.checkpoint_id,
            &self.session,
        ]
        .into_iter()
        .chain(self.source_version.iter())
        .chain(self.peer.iter())
        .chain(self.local.iter())
        .chain(self.clock.clock_id.iter())
        .chain(self.batch.batch_id.iter())
        .chain(self.batch.sha256.iter())
        {
            metadata_bytes = metadata_bytes
                .checked_add(s.len())
                .filter(|n| *n <= l.input_bytes)
                .ok_or_else(|| Error::limit("bgp_import_context_bytes"))?;
        }
        if metadata_bytes.saturating_add(self.provenance.len().saturating_mul(96)) > l.work {
            return Err(Error::limit("bgp_import_context_work"));
        }
        if self.direction.is_some_and(|d| d > 1) {
            return Err(bad(
                "bgp_import_direction",
                0,
                "direction must be zero or one",
            ));
        }
        if self.clock.policy == ClockPolicy::Unknown
            && (self.clock.clock_id.is_some() || self.clock.reported_uncertainty_ns.is_some())
        {
            return Err(bad(
                "bgp_import_clock",
                0,
                "unknown clock policy cannot assert a clock or accuracy",
            ));
        }
        if self.provenance.len() > l.spans.min(l.elements) {
            return Err(Error::limit("bgp_import_spans"));
        }
        // Guard traversal/allocation before constructing the JSON tree.
        if self.provenance.len().saturating_mul(5).saturating_add(32) > l.fields
            || self.provenance.len().saturating_mul(96).saturating_add(32) > l.work
        {
            return Err(Error::limit("bgp_import_context_work"));
        }
        for span in &self.provenance {
            if span.start >= span.end || self.batch.byte_length.is_some_and(|n| span.end > n) {
                return Err(bad(
                    "bgp_import_range",
                    0,
                    "source range is empty, inverted or outside declared batch",
                ));
            }
            if let Some(h) = &span.sha256 {
                hash(h)?;
            }
        }
        let raw = self.json();
        tree_budget(&raw, l)?;
        raw.encode_bounded(l.input_bytes.min(l.output_bytes))?;
        Ok(())
    }
    pub(crate) fn json(&self) -> Json {
        Json::object([
            ("schema", CONTEXT_SCHEMA.into()),
            ("source_id", self.source_id.clone().into()),
            ("source_schema", self.source_schema.clone().into()),
            ("source_version", optional(&self.source_version)),
            (
                "clock",
                Json::object([
                    ("policy", self.clock.policy.name().into()),
                    ("clock_id", optional(&self.clock.clock_id)),
                    (
                        "reported_uncertainty_ns",
                        optional_number(self.clock.reported_uncertainty_ns),
                    ),
                    ("ordering_established", false.into()),
                ]),
            ),
            ("batch", self.batch.json()),
            ("checkpoint_id", self.checkpoint_id.clone().into()),
            ("session", self.session.clone().into()),
            ("generation", self.generation.to_string().into()),
            ("direction", self.direction.map_or(Json::Null, Json::from)),
            ("peer", optional(&self.peer)),
            ("local", optional(&self.local)),
            (
                "provenance",
                Json::array(self.provenance.iter().map(|s| {
                    Json::object([
                        ("start", s.start.to_string().into()),
                        ("end", s.end.to_string().into()),
                        ("sha256", optional(&s.sha256)),
                    ])
                })),
            ),
            ("wire_verified", false.into()),
            ("source_authenticated", false.into()),
        ])
    }
    pub fn to_json(&self, l: &Limits) -> Result<Json> {
        self.validate(l)?;
        Ok(self.json())
    }
    pub fn from_json(v: &Json, l: &Limits) -> Result<Self> {
        l.validate()?;
        tree_budget(v, l)?;
        v.encode_bounded(l.input_bytes.min(l.output_bytes))?;
        exact_keys(
            v,
            &[
                "schema",
                "source_id",
                "source_schema",
                "source_version",
                "clock",
                "batch",
                "checkpoint_id",
                "session",
                "generation",
                "direction",
                "peer",
                "local",
                "provenance",
                "wire_verified",
                "source_authenticated",
            ],
        )?;
        if text(member(v, "schema")?)? != CONTEXT_SCHEMA
            || member(v, "wire_verified")? != &Json::Bool(false)
            || member(v, "source_authenticated")? != &Json::Bool(false)
        {
            return Err(bad(
                "bgp_import_schema",
                0,
                "invalid schema or authority claim",
            ));
        }
        let clock = member(v, "clock")?;
        exact_keys(
            clock,
            &[
                "policy",
                "clock_id",
                "reported_uncertainty_ns",
                "ordering_established",
            ],
        )?;
        if member(clock, "ordering_established")? != &Json::Bool(false) {
            return Err(bad(
                "bgp_import_clock",
                0,
                "clock does not establish ordering",
            ));
        }
        let policy = match text(member(clock, "policy")?)? {
            "unknown" => ClockPolicy::Unknown,
            "source_label" => ClockPolicy::SourceLabel,
            "ingestion_label" => ClockPolicy::IngestionLabel,
            _ => return Err(bad("bgp_import_clock", 0, "unknown clock policy code")),
        };
        let spans = array(member(v, "provenance")?)?;
        if spans.len() > l.spans.min(l.elements) {
            return Err(Error::limit("bgp_import_spans"));
        }
        let mut provenance = Vec::new();
        for s in spans {
            exact_keys(s, &["start", "end", "sha256"])?;
            provenance.push(SourceRange {
                start: number(member(s, "start")?)?,
                end: number(member(s, "end")?)?,
                sha256: optional_text(member(s, "sha256")?)?,
            });
        }
        let context = Self {
            source_id: text(member(v, "source_id")?)?.into(),
            source_schema: text(member(v, "source_schema")?)?.into(),
            source_version: optional_text(member(v, "source_version")?)?,
            clock: ObservationClock {
                policy,
                clock_id: optional_text(member(clock, "clock_id")?)?,
                reported_uncertainty_ns: optional_u64(member(clock, "reported_uncertainty_ns")?)?,
            },
            batch: SourceBatch::from_json(member(v, "batch")?)?,
            checkpoint_id: text(member(v, "checkpoint_id")?)?.into(),
            session: text(member(v, "session")?)?.into(),
            generation: number(member(v, "generation")?)?,
            direction: optional_direction(member(v, "direction")?)?,
            peer: optional_text(member(v, "peer")?)?,
            local: optional_text(member(v, "local")?)?,
            provenance,
        };
        context.validate(l)?;
        Ok(context)
    }
}
impl GenerationBoundary {
    fn validate(&self, context: &ImportContext, l: &Limits) -> Result<()> {
        identity(&self.reason, l)?;
        if self.previous_generation.checked_add(1) != Some(context.generation)
            || context.direction.is_some()
        {
            return Err(bad(
                "bgp_import_boundary",
                0,
                "reset requires the exact successor generation and no direction",
            ));
        }
        Ok(())
    }
    pub(crate) fn from_json(v: &Json, context: &ImportContext, l: &Limits) -> Result<Self> {
        exact_keys(v, &["previous_generation", "reason"])?;
        let b = Self {
            previous_generation: number(member(v, "previous_generation")?)?,
            reason: text(member(v, "reason")?)?.into(),
        };
        b.validate(context, l)?;
        Ok(b)
    }
    fn json(&self) -> Json {
        Json::object([
            (
                "previous_generation",
                self.previous_generation.to_string().into(),
            ),
            ("reason", self.reason.clone().into()),
        ])
    }
}

// Count variable metadata before the old normalizer allocates/clones its JSON.
// Unknown attribute semantics are not validated as endpoint behavior.
fn validate_input(input: &ImportedRouteObservation, l: &Limits) -> Result<()> {
    l.validate()?;
    for s in [&input.source_id, &input.record_id] {
        identity(s, l)?;
    }
    for s in [&input.session, &input.peer, &input.local] {
        optional_identity(s, l)?;
    }
    fn prefix(p: &Prefix, l: &Limits) -> Result<()> {
        if p.address.len() > l.input_bytes {
            return Err(Error::limit("bgp_import_prefix"));
        }
        let width = match p.afi {
            1 => Some(4),
            2 => Some(16),
            _ => None,
        };
        if let Some(width) = width {
            if p.address.len() != width
                || usize::from(p.length) > width * 8
                || (usize::from(p.length)..width * 8)
                    .any(|bit| p.address[bit / 8] & (0x80 >> (bit % 8)) != 0)
            {
                return Err(bad(
                    "bgp_import_prefix",
                    0,
                    "invalid or noncanonical prefix",
                ));
            }
        }
        Ok(())
    }
    prefix(&input.prefix, l)?;
    let a: &PathAttributes = &input.attributes;
    let mut count = 1usize;
    for n in [
        a.as_path.len(),
        a.communities.len(),
        a.cluster_list.len(),
        a.mp_reach.len(),
        a.mp_unreach.len(),
    ] {
        count = count
            .checked_add(n)
            .filter(|n| *n <= l.elements)
            .ok_or_else(|| Error::limit("bgp_import_elements"))?;
    }
    for s in &a.as_path {
        count = count
            .checked_add(s.values.len())
            .filter(|n| *n <= l.elements)
            .ok_or_else(|| Error::limit("bgp_import_elements"))?;
    }
    let mut string_bytes = input
        .source_id
        .len()
        .saturating_add(input.record_id.len())
        .saturating_add(input.prefix.address.len());
    for s in input
        .session
        .iter()
        .chain(input.peer.iter())
        .chain(input.local.iter())
        .chain(a.next_hop.iter())
        .chain(a.aggregator.iter())
        .chain(a.originator_id.iter())
        .chain(a.cluster_list.iter())
    {
        identity(s, l)?;
        string_bytes = string_bytes
            .checked_add(s.len())
            .filter(|n| *n <= l.input_bytes)
            .ok_or_else(|| Error::limit("bgp_import_input"))?;
    }
    for p in a.mp_reach.iter().chain(a.mp_unreach.iter()) {
        prefix(p, l)?;
        string_bytes = string_bytes
            .checked_add(p.address.len())
            .filter(|n| *n <= l.input_bytes)
            .ok_or_else(|| Error::limit("bgp_import_input"))?;
    }
    if string_bytes > l.input_bytes
        || count.saturating_add(32) > l.fields
        || count.saturating_mul(16).saturating_add(string_bytes) > l.work
    {
        return Err(Error::limit("bgp_import_work"));
    }
    Ok(())
}
fn replace(v: &mut Json, key: &'static str, value: Json) {
    // Every caller here holds an object produced locally, never arbitrary input.
    if let Json::Object(fields) = v {
        if let Some((_, old)) = fields.iter_mut().find(|(k, _)| *k == key) {
            *old = value;
        } else {
            fields.push((key, value));
        }
    }
}
fn finish(v: Json, l: &Limits) -> Result<Json> {
    if array(member(&v, "issues")?)?.len() > l.elements {
        return Err(Error::limit("bgp_import_issues"));
    }
    tree_budget(&v, l)?;
    v.encode_bounded(l.input_bytes.min(l.output_bytes))?;
    // Shares exact normalized route/provenance validation with the reducer.
    bgp_state::Observation::from_normalized(&v, None, l)?;
    Ok(v)
}

/// Compatibility implementation behind bgp::normalize_imported. No placeholder
/// generation is asserted by new output; old generation-zero envelopes remain readable.
pub(crate) fn normalize_legacy(input: ImportedRouteObservation, l: &Limits) -> Result<Json> {
    validate_input(&input, l)?;
    let mut v = bgp::normalize_imported_raw(input, l)?;
    replace(&mut v, "generation", Json::Null);
    replace(&mut v, "import_context", Json::Null);
    replace(&mut v, "import_boundary", Json::Null);
    finish(v, l)
}

/// Normalize one immutable imported record. No route selection or state mutation.
pub fn normalize_with_context(
    input: ImportedRouteObservation,
    context: ImportContext,
    l: &Limits,
) -> Result<Json> {
    validate_input(&input, l)?;
    context.validate(l)?;
    if input.source_id != context.source_id
        || input.session.as_deref() != Some(context.session.as_str())
        || input.peer != context.peer
        || input.local != context.local
    {
        return Err(bad(
            "bgp_import_context",
            0,
            "record and context identities disagree",
        ));
    }
    let mut v = bgp::normalize_imported_raw(input, l)?;
    replace(&mut v, "generation", context.generation.to_string().into());
    replace(
        &mut v,
        "direction",
        context.direction.map_or(Json::Null, Json::from),
    );
    replace(&mut v, "import_context", context.json());
    replace(&mut v, "import_boundary", Json::Null);
    finish(v, l)
}

/// A replayable caller boundary, not a wire message or an attribute transaction.
/// The reducer also checks the previous generation against its current partition.
pub fn normalize_boundary(
    context: ImportContext,
    boundary: GenerationBoundary,
    record_id: String,
    observed_at_ns: Option<i64>,
    l: &Limits,
) -> Result<Json> {
    context.validate(l)?;
    boundary.validate(&context, l)?;
    identity(&record_id, l)?;
    finish(
        Json::object([
            ("schema", bgp::SCHEMA.into()),
            ("source_kind", "imported".into()),
            ("source_id", context.source_id.clone().into()),
            ("record_id", record_id.into()),
            (
                "observed_at_ns",
                observed_at_ns.map_or(Json::Null, |n| n.to_string().into()),
            ),
            ("session", context.session.clone().into()),
            ("direction", Json::Null),
            ("peer", optional(&context.peer)),
            ("local", optional(&context.local)),
            ("generation", context.generation.to_string().into()),
            ("message_type", 0u8.into()),
            ("routes", Json::Array(Vec::new())),
            ("message_detail", Json::Null),
            (
                "issues",
                Json::array(
                    [
                        "imported_observation_not_wire_verified",
                        "caller_import_generation_boundary",
                        "route_candidates_are_not_endpoint_state",
                        "cross_source_correlation_requires_explicit_join",
                    ]
                    .into_iter()
                    .map(Json::from),
                ),
            ),
            ("evidence", Json::Null),
            ("endpoint_state_established", false.into()),
            ("causality_established", false.into()),
            ("import_context", context.json()),
            ("import_boundary", boundary.json()),
        ]),
        l,
    )
}

#[cfg(test)]
mod native_continuity_tests {
    use super::*;
    use crate::deep::bgp_rib::{AdjRibIn, RibEvent, RibEventKind, RibScope};
    fn scope() -> RibScope {
        RibScope {
            source: crate::deep::bgp_session::SourcePartition {
                source_id: "source-a".into(),
                partition_id: "partition-a".into(),
                kind: crate::deep::bgp_session::PartitionKind::Imported,
            },
            session: "session-a".into(),
            generation: 0,
            direction: Some(0),
            peer: Some("peer-a".into()),
        }
    }
    fn gap() -> RibEvent {
        RibEvent {
            scope: scope(),
            record_id: "gap-a".into(),
            kind: RibEventKind::Gap {
                reason: "source-continuity-unknown".into(),
            },
        }
    }
    #[test]
    fn native_effect_is_newly_applied_generation_scope_and_replay_is_inert() {
        let limits = Limits::default();
        let mut rib = AdjRibIn::for_embedded_projection(limits.clone()).unwrap();
        let mut effects = Vec::new();
        let work_before = rib.accounted_work();
        apply_native_event(
            &mut rib,
            gap(),
            None,
            &mut effects,
            (0, work_before, 1, 8),
            &limits,
        )
        .unwrap();
        assert_eq!(effects.len(), 1);
        let first = effects.remove(0);
        assert!(!first.is_reset());
        let mut opposite = scope();
        opposite.direction = Some(1);
        opposite.peer = None;
        assert!(first.affects_scope(&opposite));
        opposite.generation = 1;
        assert!(!first.affects_scope(&opposite));
        opposite = scope();
        opposite.source.partition_id = "partition-b".into();
        assert!(!first.affects_scope(&opposite));
        let work_before = rib.accounted_work();
        apply_native_event(
            &mut rib,
            gap(),
            None,
            &mut effects,
            (0, work_before, 1, 8),
            &limits,
        )
        .unwrap();
        assert!(effects.is_empty());
        let mut next = scope();
        next.generation = 1;
        next.direction = None;
        let work_before = rib.accounted_work();
        apply_native_event(
            &mut rib,
            RibEvent {
                scope: next.clone(),
                record_id: "reset-a".into(),
                kind: RibEventKind::Reset {
                    previous_generation: 0,
                    reason: "source-generation-boundary".into(),
                },
            },
            None,
            &mut effects,
            (0, work_before, 1, 8),
            &limits,
        )
        .unwrap();
        assert_eq!(effects.len(), 1);
        assert!(effects[0].is_reset());
        assert_eq!(effects[0].generations(), (0, 1));
        assert!(effects[0].affects_scope(&scope()));
        assert!(!effects[0].affects_scope(&next));
    }
    #[test]
    fn native_carrier_precopy_admits_nonzero_native_and_multiple_effects_exactly() {
        let high = Limits::default();
        let mut next = scope();
        next.generation = 1;
        next.direction = None;
        let reset = RibEvent {
            scope: next,
            record_id: "reset-a".into(),
            kind: RibEventKind::Reset {
                previous_generation: 0,
                reason: "source-generation-boundary".into(),
            },
        };
        // The native owner's direct apply is an independent prospective-state
        // oracle. Carrier strings are counted individually, without its helper.
        let mut native = AdjRibIn::for_embedded_projection(high.clone()).unwrap();
        native.apply(gap()).unwrap();
        let before_native_work = native.accounted_work();
        assert!(native.retained_bytes() > 0);
        native.apply(reset.clone()).unwrap();
        let base = std::mem::size_of::<ImportedNativeContinuity>()
            + "source-a".len()
            + "partition-a".len()
            + "session-a".len()
            + "peer-a".len();
        let carrier_bytes = 2 * base
            + "gap-a".len()
            + "source-continuity-unknown".len()
            + "reset-a".len()
            + "source-generation-boundary".len();
        for (retained_factor, work_factor) in [(6, 6), (1, 8)] {
            let exact_retained = 17 + native.retained_bytes() + retained_factor * carrier_bytes;
            let exact_work = 19 + native.accounted_work() + work_factor * carrier_bytes;
            for below in [false, true] {
                for work_cap in [false, true] {
                    let limits = if work_cap {
                        Limits {
                            work: exact_work - usize::from(below),
                            ..high.clone()
                        }
                    } else {
                        Limits {
                            retained_bytes: exact_retained - usize::from(below),
                            ..high.clone()
                        }
                    };
                    let mut rib = AdjRibIn::for_embedded_projection(high.clone()).unwrap();
                    let mut effects = Vec::new();
                    apply_native_event(
                        &mut rib,
                        gap(),
                        None,
                        &mut effects,
                        (17, 19, retained_factor, work_factor),
                        &high,
                    )
                    .unwrap();
                    let before = (
                        rib.events().len(),
                        rib.retained_bytes(),
                        rib.accounted_work(),
                        effects.clone(),
                    );
                    let result = apply_native_event(
                        &mut rib,
                        reset.clone(),
                        None,
                        &mut effects,
                        (17, 19 + before_native_work, retained_factor, work_factor),
                        &limits,
                    );
                    assert_eq!(result.is_ok(), !below);
                    if below {
                        assert_eq!(
                            (
                                rib.events().len(),
                                rib.retained_bytes(),
                                rib.accounted_work()
                            ),
                            (before.0, before.1, before.2)
                        );
                        assert_eq!(effects, before.3);
                    } else {
                        assert_eq!(effects.len(), 2);
                        assert_eq!(rib.retained_bytes(), native.retained_bytes());
                        assert_eq!(rib.accounted_work(), native.accounted_work());
                        assert_eq!(
                            effects.iter().map(|e| e.retained_charge()).sum::<usize>(),
                            carrier_bytes
                        );
                    }
                }
            }
        }
    }
}
