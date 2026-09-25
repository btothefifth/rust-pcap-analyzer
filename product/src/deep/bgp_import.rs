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
