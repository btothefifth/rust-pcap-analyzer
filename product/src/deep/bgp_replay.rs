//! I/O-free, bounded replay of a caller-adapted immutable imported sequence.
//!
//! Reuses import context, normalized observations, candidate reduction and
//! association coverage. Feed order is supplied evidence order, not clock order.
//! A cursor is an integrity reference, never authorization to omit a predecessor.
use super::bgp::SourceKind;
use super::bgp_association::{Coverage, RouteBatch, RouteContext};
use super::bgp_import::ImportContext;
use super::bgp_state::{CandidateState, Observation, ObservationKind};
use super::model::{bad, Limits};
use pcap_evidence::{json::Json, sha256, Error, Result};
use std::collections::BTreeSet;

pub const FEED_SCHEMA: &str = "pcap-evidence.bgp.replay-feed.v1";
pub const RECEIPT_SCHEMA: &str = "pcap-evidence.bgp.replay-receipt.v1";
pub const ASSOCIATION_RECEIPT_SCHEMA: &str = "pcap-evidence.bgp.replay-association.v1";
const PREFIX_DOMAIN: &[u8] = b"pcap-evidence/bgp/replay-prefix/v1\0";

/// Partial/final describes the declared sequence, never completeness of a RIB.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Completion {
    Partial,
    Final,
}

/// Each coordinate must match a prefix retained by this replay instance.
/// A fresh instance accepts only its own zero-record cursor, even if a caller
/// presents a syntactically valid digest for a later checkpoint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Cursor {
    pub feed_sha256: String,
    pub next_ordinal: u64,
    pub prefix_sha256: String,
}
impl Cursor {
    fn validate(&self) -> Result<()> {
        hash(&self.feed_sha256)?;
        hash(&self.prefix_sha256)
    }
    fn json(&self) -> Json {
        Json::object([
            ("feed_sha256", self.feed_sha256.clone().into()),
            ("next_ordinal", self.next_ordinal.to_string().into()),
            ("prefix_sha256", self.prefix_sha256.clone().into()),
        ])
    }
}

/// The ordinal belongs to the immutable record identity: replays retain it.
/// Existing normalized fields and unknown extensions are retained, not parsed
/// into a second set of path, clock, prefix or provenance types.
#[derive(Clone, Debug)]
pub struct FeedRecord {
    ordinal: u64,
    observation: Observation,
    coverage: Coverage,
    value: Json,
    encoded: String,
}
impl FeedRecord {
    pub fn from_normalized(
        ordinal: u64,
        value: &Json,
        coverage: Coverage,
        limits: &Limits,
    ) -> Result<Self> {
        limits.validate()?;
        let mut guard = Guard::new(limits);
        guard.measure(value, limits.input_bytes)?;
        let observation = Observation::from_normalized(value, None, limits)?;
        let record_id = &observation.source().record_id;
        if record_id.trim().is_empty()
            || record_id.len() > limits.input_bytes.min(1024)
            || record_id.chars().any(char::is_control)
        {
            return Err(bad(
                "bgp_replay_record_identity",
                0,
                "nonempty bounded record identity required",
            ));
        }
        if observation.source().kind != SourceKind::Imported
            || observation.import_context().is_none()
            || !matches!(
                observation.kind(),
                ObservationKind::Routes | ObservationKind::Reset
            )
        {
            return Err(bad(
                "bgp_replay_context",
                0,
                "contextual imported observation required",
            ));
        }
        let value = Json::object([
            ("ordinal", ordinal.to_string().into()),
            ("coverage", coverage_name(coverage).into()),
            ("observation", observation.normalized().clone()),
        ]);
        let (_, encoded) = guard.encode(&value, limits.input_bytes.min(limits.output_bytes))?;
        Ok(Self {
            ordinal,
            observation,
            coverage,
            value,
            encoded,
        })
    }
    pub fn ordinal(&self) -> u64 {
        self.ordinal
    }
    pub fn observation(&self) -> &Observation {
        &self.observation
    }
    pub fn coverage(&self) -> Coverage {
        self.coverage
    }
    pub fn encode(&self) -> &str {
        &self.encoded
    }

    fn validate(&self, context: &ImportContext, guard: &mut Guard<'_>) -> Result<()> {
        let limits = guard.limits;
        guard.measure(&self.value, limits.input_bytes.min(limits.output_bytes))?;
        let c = self
            .observation
            .import_context()
            .ok_or_else(|| bad("bgp_replay_context", 0, "import context absent"))?;
        c.validate(limits)?;
        if c.source_id != context.source_id
            || c.session != context.session
            || c.partition() != context.partition()
            || c.clock != context.clock
        {
            return Err(bad(
                "bgp_replay_partition",
                0,
                "record and feed partition or clock declaration differ",
            ));
        }
        // Recheck immutable observations constructed under larger limits.
        Observation::from_normalized(self.observation.normalized(), None, limits)?;
        Ok(())
    }
}

/// One contiguous page, possibly overlapping an earlier accepted prefix. The
/// existing ImportContext is the feed declaration (no direction): source/schema/
/// version, batch, checkpoint, session, initial generation, clock and provenance.
/// Each record keeps its own exact direction, generation and source ranges.
#[derive(Clone, Debug)]
pub struct FeedEnvelope {
    context: ImportContext,
    previous: Cursor,
    records: Vec<FeedRecord>,
    completion: Completion,
    value: Json,
    encoded: String,
}
impl FeedEnvelope {
    pub fn new(
        context: ImportContext,
        previous: Cursor,
        records: Vec<FeedRecord>,
        completion: Completion,
        limits: &Limits,
    ) -> Result<Self> {
        validate_declaration(&context, limits)?;
        previous.validate()?;
        if records.len() > limits.elements {
            return Err(Error::limit("bgp_replay_records"));
        }
        let mut guard = Guard::new(limits);
        let mut size = 0usize;
        for (i, record) in records.iter().enumerate() {
            guard.tree(&record.value, 1)?;
            size = add(size, record.encoded.len())?;
            if size > limits.input_bytes {
                return Err(Error::limit("bgp_replay_input"));
            }
            record.validate(&context, &mut guard)?;
            let expected = previous
                .next_ordinal
                .checked_add(as_u64(i)?)
                .ok_or_else(|| Error::limit("bgp_replay_ordinal"))?;
            if record.ordinal != expected {
                return Err(bad(
                    "bgp_replay_record_order",
                    0,
                    "record ordinals must be contiguous in supplied order",
                ));
            }
        }
        previous
            .next_ordinal
            .checked_add(as_u64(records.len())?)
            .ok_or_else(|| Error::limit("bgp_replay_ordinal"))?;
        let value = Json::object([
            ("schema", FEED_SCHEMA.into()),
            ("context", context.to_json(limits)?),
            ("previous", previous.json()),
            ("completion", completion_name(completion).into()),
            (
                "records",
                Json::array(records.iter().map(|r| r.value.clone())),
            ),
        ]);
        let (_, encoded) = guard.encode(&value, limits.input_bytes.min(limits.output_bytes))?;
        Ok(Self {
            context,
            previous,
            records,
            completion,
            value,
            encoded,
        })
    }
    pub fn context(&self) -> &ImportContext {
        &self.context
    }
    pub fn previous(&self) -> &Cursor {
        &self.previous
    }
    pub fn records(&self) -> &[FeedRecord] {
        &self.records
    }
    pub fn completion(&self) -> Completion {
        self.completion
    }
    pub fn encode(&self) -> &str {
        &self.encoded
    }
}

/// Every alternative is a full source-bound record; none is a selected winner.
/// The first observation defines the prefix commitment only. On any conflict
/// that commitment cannot authorize extension or candidate/association access.
#[derive(Clone, Debug)]
pub struct RecordWitness {
    original: FeedRecord,
    alternatives: Vec<FeedRecord>,
    state_observation: usize,
}
impl RecordWitness {
    pub fn original(&self) -> &FeedRecord {
        &self.original
    }
    pub fn alternatives(&self) -> &[FeedRecord] {
        &self.alternatives
    }
    /// Historical journal index; not permission to use quarantined state.
    pub fn state_observation(&self) -> usize {
        self.state_observation
    }
    fn contains(&self, record: &FeedRecord) -> bool {
        self.original.encoded == record.encoded
            || self
                .alternatives
                .iter()
                .any(|a| a.encoded == record.encoded)
    }
    fn json(&self) -> Json {
        Json::object([
            ("record", self.original.value.clone()),
            (
                "state_observation",
                self.state_observation.to_string().into(),
            ),
            ("conflict", (!self.alternatives.is_empty()).into()),
            (
                "alternatives",
                Json::array(self.alternatives.iter().map(|r| r.value.clone())),
            ),
        ])
    }
}

#[derive(Clone, Debug)]
pub struct ReplayReceipt {
    value: Json,
    encoded: String,
}
impl ReplayReceipt {
    pub fn json(&self) -> &Json {
        &self.value
    }
    pub fn encode(&self) -> &str {
        &self.encoded
    }
    pub fn sha256(&self) -> [u8; 32] {
        sha256::digest(self.encoded.as_bytes())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplayStatus {
    Applied,
    IdenticalReplay,
    Finalized,
    Quarantined,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplayOutcome {
    pub status: ReplayStatus,
    pub next: Cursor,
    pub receipt_sha256: [u8; 32],
}

/// One bounded immutable source partition per instance. Create an independent
/// instance for another checkpoint/batch, never seed it with an unverified cursor.
/// All commits are staged including final output. No callback or partial success.
#[derive(Clone)]
pub struct FeedReplay {
    limits: Limits,
    context: ImportContext,
    state: CandidateState,
    records: Vec<RecordWitness>,
    cursors: Vec<Cursor>,
    generation: u64,
    completion: Completion,
    quarantined: bool,
    receipt: ReplayReceipt,
}
impl FeedReplay {
    pub fn new(context: ImportContext, limits: Limits) -> Result<Self> {
        validate_declaration(&context, &limits)?;
        let declaration = Json::object([
            ("schema", FEED_SCHEMA.into()),
            ("context", context.to_json(&limits)?),
        ]);
        let mut guard = Guard::new(&limits);
        let (_, encoded) = guard.encode(&declaration, limits.input_bytes)?;
        let reserved_work = guard.work;
        let feed_sha256 = digest(encoded.as_bytes());
        let mut prefix = sha256::Sha256::new();
        prefix.update(PREFIX_DOMAIN);
        prefix.update(feed_sha256.as_bytes());
        let cursor = Cursor {
            feed_sha256,
            next_ordinal: 0,
            prefix_sha256: sha256::hex(&prefix.finalize()),
        };
        let state = CandidateState::new(limits.clone())?;
        let generation = context.generation;
        let mut replay = Self {
            limits,
            context,
            state,
            records: Vec::new(),
            cursors: vec![cursor],
            generation,
            completion: Completion::Partial,
            quarantined: false,
            receipt: ReplayReceipt {
                value: Json::Null,
                encoded: String::new(),
            },
        };
        // Use an independent limits borrow while the staged instance refreshes.
        let refresh_limits = replay.limits.clone();
        let mut refresh_guard = Guard::new(&refresh_limits);
        refresh_guard.charge(reserved_work)?;
        replay.refresh(&mut refresh_guard)?;
        Ok(replay)
    }
    pub fn context(&self) -> &ImportContext {
        &self.context
    }
    pub fn cursor(&self) -> &Cursor {
        &self.cursors[self.cursors.len() - 1]
    }
    pub fn records(&self) -> &[RecordWitness] {
        &self.records
    }
    pub fn receipt(&self) -> &ReplayReceipt {
        &self.receipt
    }
    pub fn completion(&self) -> Completion {
        self.completion
    }
    pub fn is_quarantined(&self) -> bool {
        self.quarantined
    }
    /// The guarded view is unavailable after any ordered-record/content conflict.
    /// The complete evidence and alternatives remain in records()/receipt().
    pub fn candidate_state(&self) -> Result<&CandidateState> {
        if self.quarantined {
            return Err(bad(
                "bgp_replay_quarantined",
                0,
                "conflicting feed has no publishable candidate view",
            ));
        }
        Ok(&self.state)
    }
    pub fn effective_coverage(&self) -> Coverage {
        if self.quarantined || self.completion == Completion::Partial {
            return Coverage::Incomplete;
        }
        self.records
            .iter()
            .fold(Coverage::DeclaredComplete, |coverage, r| {
                meet(coverage, r.original.coverage)
            })
    }

    pub fn apply(&mut self, feed: &FeedEnvelope) -> Result<ReplayOutcome> {
        let l = &self.limits;
        validate_declaration(&feed.context, l)?;
        let mut guard = Guard::new(l);
        guard.measure(&feed.value, l.input_bytes.min(l.output_bytes))?;
        feed.previous.validate()?;
        if feed.context != self.context {
            return Err(bad(
                "bgp_replay_partition",
                0,
                "feed declaration changed; use an independent replay instance",
            ));
        }
        let start = usize::try_from(feed.previous.next_ordinal)
            .map_err(|_| Error::limit("bgp_replay_ordinal"))?;
        if self.cursors.get(start) != Some(&feed.previous) {
            return Err(bad(
                "bgp_replay_predecessor",
                0,
                "missing, changed or cross-partition prefix commitment",
            ));
        }
        let end = start
            .checked_add(feed.records.len())
            .ok_or_else(|| Error::limit("bgp_replay_ordinal"))?;
        let grows = end > self.records.len();
        if feed.records.len() > l.elements || end > l.elements {
            return Err(Error::limit("bgp_replay_records"));
        }
        if grows && (self.quarantined || self.completion == Completion::Final) {
            return Err(bad(
                "bgp_replay_closed",
                0,
                "final or quarantined feeds cannot extend",
            ));
        }
        if feed.completion == Completion::Final && end < self.records.len() {
            return Err(bad(
                "bgp_replay_final",
                0,
                "final marker omits an already retained tail",
            ));
        }
        let mut conflict = false;
        // Charge before identity indexing, comparisons and staging; all old/new
        // evidence is bounded. The index must not precede its reservation.
        guard.charge(
            self.receipt
                .encoded
                .len()
                .saturating_mul(feed.records.len().saturating_add(4)),
        )?;
        guard.charge(self.state.retained_bytes().saturating_mul(4))?;
        let mut identities: BTreeSet<&str> = self
            .records
            .iter()
            .map(|r| r.original.observation.source().record_id.as_str())
            .collect();
        for (i, r) in feed.records.iter().enumerate() {
            r.validate(&self.context, &mut guard)?;
            let ordinal = start + i;
            if r.ordinal != as_u64(ordinal)? {
                return Err(bad(
                    "bgp_replay_record_order",
                    0,
                    "record ordinal disagrees with supplied order",
                ));
            }
            guard.charge(
                r.encoded
                    .len()
                    .saturating_mul(self.records.len().saturating_add(4)),
            )?;
            if let Some(old) = self.records.get(ordinal) {
                conflict |= !old.contains(r);
            } else if !identities.insert(r.observation.source().record_id.as_str()) {
                return Err(bad(
                    "bgp_replay_reordered_identity",
                    0,
                    "record identity moved to a new ordinal",
                ));
            }
        }
        if conflict && grows {
            return Err(bad(
                "bgp_replay_ambiguous_extension",
                0,
                "cannot append records using a conflicting prefix",
            ));
        }
        let finalizes = !conflict
            && !self.quarantined
            && self.completion == Completion::Partial
            && feed.completion == Completion::Final;
        if !grows && !conflict && !finalizes {
            return Ok(self.outcome(ReplayStatus::IdenticalReplay));
        }
        // Preflight retained old and novel record envelopes before cloning.
        // Final exact state/output sizes are checked again on the staged copy.
        let mut storage_guard = Guard::new(l);
        storage_guard.work = guard.work;
        storage_guard.tree(&self.context.json(), 1)?;
        let mut retained_records = 0usize;
        let mut retained_routes = 0usize;
        let mut retained_bytes = self.state.retained_bytes();
        for record in self
            .records
            .iter()
            .flat_map(|w| std::iter::once(&w.original).chain(w.alternatives.iter()))
            .chain(feed.records.iter().enumerate().filter_map(|(i, r)| {
                match self.records.get(start + i) {
                    Some(old) if old.contains(r) => None,
                    _ => Some(r),
                }
            }))
        {
            retained_records = add(retained_records, 1)?;
            retained_routes = add(retained_routes, record.observation.routes().len())?;
            retained_bytes = add(retained_bytes, record.encoded.len())?;
            if retained_records > l.elements
                || retained_routes > l.elements
                || retained_bytes > l.retained_bytes
            {
                return Err(Error::limit("bgp_replay_retention"));
            }
            storage_guard.tree(&record.value, 1)?;
        }
        guard.work = storage_guard.work;
        // Cloning is deliberately after admission/work checks. The accepted
        // reducer and all existing state/association contracts remain unchanged.
        let mut next = self.clone();
        for (i, record) in feed.records.iter().enumerate() {
            let ordinal = start + i;
            if let Some(old) = next.records.get_mut(ordinal) {
                if !old.contains(record) {
                    old.alternatives.push(record.clone());
                    next.quarantined = true;
                }
                continue;
            }
            let c = record
                .observation
                .import_context()
                .ok_or_else(|| bad("bgp_replay_context", 0, "record context missing"))?;
            if let Some(boundary) = record.observation.import_boundary() {
                if boundary.previous_generation != next.generation
                    || boundary.previous_generation.checked_add(1) != Some(c.generation)
                {
                    return Err(bad(
                        "bgp_replay_generation",
                        0,
                        "boundary is not the exact current successor",
                    ));
                }
            } else if c.generation != next.generation {
                return Err(bad(
                    "bgp_replay_generation",
                    0,
                    "missing generation boundary or reversed generation",
                ));
            }
            let estimate = next
                .state
                .retained_bytes()
                .saturating_add(record.encoded.len())
                .saturating_mul(next.state.observations().len().saturating_add(16));
            guard.charge(estimate)?;
            let applied = next.state.apply(record.observation.clone())?;
            next.generation = c.generation;
            let old_cursor = next.cursor();
            let mut hash = sha256::Sha256::new();
            hash.update(PREFIX_DOMAIN);
            hash.update(old_cursor.prefix_sha256.as_bytes());
            hash.update(record.encoded.as_bytes());
            let cursor = Cursor {
                feed_sha256: old_cursor.feed_sha256.clone(),
                next_ordinal: record
                    .ordinal
                    .checked_add(1)
                    .ok_or_else(|| Error::limit("bgp_replay_ordinal"))?,
                prefix_sha256: sha256::hex(&hash.finalize()),
            };
            next.records.push(RecordWitness {
                original: record.clone(),
                alternatives: Vec::new(),
                state_observation: applied.observation,
            });
            next.cursors.push(cursor);
        }
        if finalizes {
            next.completion = Completion::Final;
        }
        next.refresh(&mut guard)?;
        let status = if conflict {
            ReplayStatus::Quarantined
        } else if finalizes {
            ReplayStatus::Finalized
        } else {
            ReplayStatus::Applied
        };
        let outcome = next.outcome(status);
        *self = next;
        Ok(outcome)
    }

    fn outcome(&self, status: ReplayStatus) -> ReplayOutcome {
        ReplayOutcome {
            status,
            next: self.cursor().clone(),
            receipt_sha256: self.receipt.sha256(),
        }
    }
    fn refresh(&mut self, work: &mut Guard<'_>) -> Result<()> {
        let l = &self.limits;
        let mut guard = Guard::new(l);
        guard.work = work.work;
        guard.tree(&self.context.json(), 1)?;
        let mut records = 0usize;
        let mut routes = 0usize;
        let mut retained = guard.measure(&self.context.to_json(l)?, l.input_bytes)?;
        for row in &self.records {
            for r in std::iter::once(&row.original).chain(row.alternatives.iter()) {
                records = add(records, 1)?;
                routes = add(routes, r.observation.routes().len())?;
                if records > l.elements || routes > l.elements {
                    return Err(Error::limit("bgp_replay_retention"));
                }
                guard.tree(&r.value, 1)?;
                retained = add(retained, r.encoded.len())?;
                if retained > l.retained_bytes {
                    return Err(Error::limit("bgp_replay_retention"));
                }
            }
        }
        retained = add(retained, self.cursors.len().saturating_mul(192))?;
        retained = add(retained, self.state.retained_bytes())?;
        if retained > l.retained_bytes {
            return Err(Error::limit("bgp_replay_retention"));
        }
        guard.charge(retained)?;
        let value = Json::object([
            ("schema", RECEIPT_SCHEMA.into()),
            ("feed_schema", FEED_SCHEMA.into()),
            ("context", self.context.to_json(l)?),
            ("next", self.cursor().json()),
            ("completion", completion_name(self.completion).into()),
            ("quarantined", self.quarantined.into()),
            (
                "current_generation",
                if self.quarantined {
                    Json::Null
                } else {
                    self.generation.to_string().into()
                },
            ),
            (
                "effective_coverage",
                coverage_name(self.effective_coverage()).into(),
            ),
            (
                "records",
                Json::array(self.records.iter().map(RecordWitness::json)),
            ),
            (
                "candidate_state_sha256",
                if self.quarantined {
                    Json::Null
                } else {
                    digest(self.state.encode().as_bytes()).into()
                },
            ),
            ("candidate_state_available", (!self.quarantined).into()),
            (
                "issues",
                Json::array(
                    [
                        "replay_is_candidate_evidence_not_endpoint_state",
                        "input_order_is_evidence_order_not_clock_or_causal_order",
                        "source_adapter_and_source_verification_are_caller_responsibilities",
                        "final_means_declared_sequence_end_not_complete_route_coverage",
                        "prefix_commitment_is_integrity_not_authority_or_conflict_resolution",
                    ]
                    .into_iter()
                    .map(Json::from),
                ),
            ),
            ("endpoint_state_established", false.into()),
            ("rib_established", false.into()),
            ("best_path_selected", false.into()),
            ("reachability_established", false.into()),
            ("attack_established", false.into()),
            ("causality_established", false.into()),
            ("source_authority_established", false.into()),
            ("source_verified", false.into()),
            ("normative_conformance_certified", false.into()),
        ]);
        let (value, encoded) = guard.encode(
            &value,
            l.output_bytes
                .min(l.retained_bytes.saturating_sub(retained)),
        )?;
        work.work = guard.work;
        self.receipt = ReplayReceipt { value, encoded };
        Ok(())
    }

    /// Binds the existing read-only association snapshot adapter to this receipt.
    /// Partial/unknown record coverage can only downgrade caller coverage. An
    /// explicit namespace/policy must still be supplied; no mapping is inferred.
    /// Quarantined feeds return a typed error with their full receipt still
    /// available from receipt(); no old candidate view is allowed to escape.
    pub fn association_receipt(
        &self,
        context: &RouteContext,
        limits: &Limits,
    ) -> Result<AssociationReceipt> {
        limits.validate()?;
        let state = self.candidate_state()?;
        if context.captured_or_legacy_clock.is_some() {
            return Err(bad(
                "bgp_replay_clock_override",
                0,
                "imported evidence already owns clock metadata",
            ));
        }
        let mut guard = Guard::new(limits);
        guard.tree(self.receipt.json(), 1)?;
        if self.receipt.encoded.len() > limits.input_bytes {
            return Err(Error::limit("bgp_replay_association_input"));
        }
        guard.charge(self.receipt.encoded.len().saturating_mul(4))?;
        let coverage = meet(self.effective_coverage(), context.coverage);
        let mut adjusted = context.clone();
        adjusted.coverage = coverage;
        let routes = RouteBatch::from_candidate_state(state, &adjusted, limits)?;
        let mut retained = self.receipt.encoded.len();
        for route in routes.routes() {
            let size = guard.tree(route.data(), 1)?;
            if size > limits.input_bytes {
                return Err(Error::limit("report_bytes"));
            }
            retained = add(retained, size)?;
        }
        for note in routes.notes() {
            let size = guard.tree(note.witness(), 1)?;
            if size > limits.input_bytes {
                return Err(Error::limit("report_bytes"));
            }
            retained = add(retained, size)?;
        }
        guard.charge(retained.saturating_mul(4))?;
        let value = Json::object([
            ("schema", ASSOCIATION_RECEIPT_SCHEMA.into()),
            ("replay_receipt", self.receipt.value.clone()),
            (
                "replay_receipt_sha256",
                digest(self.receipt.encoded.as_bytes()).into(),
            ),
            (
                "candidate_state_sha256",
                routes.snapshot_sha256().map_or(Json::Null, Json::from),
            ),
            ("effective_coverage", coverage_name(coverage).into()),
            (
                "namespace",
                context.namespace.clone().map_or(Json::Null, Json::from),
            ),
            (
                "flow_id",
                context.flow_id.clone().map_or(Json::Null, Json::from),
            ),
            ("namespace_equivalence_established", false.into()),
            ("causality_established", false.into()),
            ("source_authority_established", false.into()),
        ]);
        if retained > limits.retained_bytes {
            return Err(Error::limit("bgp_replay_association_retention"));
        }
        let (_, encoded) = guard.encode(
            &value,
            limits
                .output_bytes
                .min(limits.retained_bytes.saturating_sub(retained)),
        )?;
        Ok(AssociationReceipt {
            routes,
            coverage,
            encoded,
        })
    }
}

/// Pass routes() to bgp_association::associate and keep encode() beside its
/// result. This receipt preserves ordered source witnesses and completion,
/// which the association module intentionally does not infer or reconstruct.
#[derive(Clone, Debug)]
pub struct AssociationReceipt {
    routes: RouteBatch,
    coverage: Coverage,
    encoded: String,
}
impl AssociationReceipt {
    pub fn routes(&self) -> &RouteBatch {
        &self.routes
    }
    pub fn coverage(&self) -> Coverage {
        self.coverage
    }
    pub fn encode(&self) -> &str {
        &self.encoded
    }
}

fn validate_declaration(context: &ImportContext, l: &Limits) -> Result<()> {
    context.validate(l)?;
    if context.direction.is_some() {
        return Err(bad(
            "bgp_replay_declaration",
            0,
            "feed declaration is bidirectional; direction belongs to each record",
        ));
    }
    Ok(())
}
fn completion_name(c: Completion) -> &'static str {
    match c {
        Completion::Partial => "partial",
        Completion::Final => "final",
    }
}
fn coverage_name(c: Coverage) -> &'static str {
    match c {
        Coverage::DeclaredComplete => "caller_declared_complete",
        Coverage::Incomplete => "incomplete",
        Coverage::Unknown => "unknown",
    }
}
fn meet(a: Coverage, b: Coverage) -> Coverage {
    if a == Coverage::Incomplete || b == Coverage::Incomplete {
        Coverage::Incomplete
    } else if a == Coverage::Unknown || b == Coverage::Unknown {
        Coverage::Unknown
    } else {
        Coverage::DeclaredComplete
    }
}
fn digest(b: &[u8]) -> String {
    sha256::hex(&sha256::digest(b))
}
fn hash(s: &str) -> Result<()> {
    if s.len() != 64
        || !s
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(bad(
            "bgp_replay_hash",
            0,
            "64 lowercase SHA-256 hexadecimal digits required",
        ));
    }
    Ok(())
}
fn as_u64(n: usize) -> Result<u64> {
    u64::try_from(n).map_err(|_| Error::limit("bgp_replay_ordinal"))
}
fn add(a: usize, b: usize) -> Result<usize> {
    a.checked_add(b)
        .ok_or_else(|| Error::limit("bgp_replay_budget"))
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
/// A logical work/node/reference budget, not an allocator/RSS or CPU-time claim.
/// Recursion, array/key width and strings are checked before canonical cloning.
struct Guard<'a> {
    limits: &'a Limits,
    work: usize,
    nodes: usize,
    spans: usize,
}
impl<'a> Guard<'a> {
    fn new(limits: &'a Limits) -> Self {
        Self {
            limits,
            work: 0,
            nodes: 0,
            spans: 0,
        }
    }
    fn charge(&mut self, amount: usize) -> Result<()> {
        self.work = add(self.work, amount)?;
        if self.work > self.limits.work {
            return Err(Error::limit("bgp_replay_work"));
        }
        Ok(())
    }
    /// Validate and measure without constructing a serialized document. Structural
    /// counters describe this tree; work carries across all phases of this guard.
    fn measure(&mut self, value: &Json, max: usize) -> Result<usize> {
        let mut phase = Self::new(self.limits);
        phase.work = self.work;
        let size = phase.tree(value, 1)?;
        self.work = phase.work;
        if size > max {
            return Err(Error::limit("report_bytes"));
        }
        Ok(size)
    }
    /// Reserve clone/length/render/hash work BEFORE cloning or serialization.
    /// Four units per exact output byte retain the existing logical serialization
    /// model. Structural traversal, depth, keys and references keep their limits;
    /// these units are not a count of CPU instructions or allocator operations.
    fn prepare_encoding(&mut self, value: &Json, max: usize) -> Result<usize> {
        let size = self.measure(value, max.min(self.limits.output_bytes))?;
        self.charge(
            size.checked_mul(4)
                .ok_or_else(|| Error::limit("bgp_replay_work"))?,
        )?;
        Ok(size)
    }
    fn encode(&mut self, value: &Json, max: usize) -> Result<(Json, String)> {
        let size = self.prepare_encoding(value, max)?;
        let value = canonical(value);
        // The shared encoder independently checks its exact length, then renders
        // ONCE. No serialization is used to discover or charge work afterwards.
        let encoded = value.encode_bounded(size)?;
        Ok((value, encoded))
    }
    /// Exact compact JSON length matching the shared encoder, without allocation
    /// for numbers/escaped strings. No object-key or source-array order is changed.
    fn tree(&mut self, value: &Json, depth: usize) -> Result<usize> {
        if depth > self.limits.depth {
            return Err(Error::limit("bgp_replay_depth"));
        }
        self.nodes = add(self.nodes, 1)?;
        if self.nodes > self.limits.fields {
            return Err(Error::limit("bgp_replay_fields"));
        }
        self.charge(1)?;
        match value {
            Json::Null => Ok(4),
            Json::Bool(true) => Ok(4),
            Json::Bool(false) => Ok(5),
            Json::Number(n) => {
                // A u64 has at most 20 decimal digits, including zero's one digit.
                self.charge(20)?;
                let mut n = *n;
                let mut digits = 1;
                while n >= 10 {
                    n /= 10;
                    digits += 1;
                }
                Ok(digits)
            }
            Json::String(s) => self.quoted_len(s),
            Json::Array(items) => {
                if items.len() > self.limits.fields {
                    return Err(Error::limit("bgp_replay_fields"));
                }
                let mut size = add(2, items.len().saturating_sub(1))?;
                for v in items {
                    size = add(size, self.tree(v, depth + 1)?)?;
                }
                Ok(size)
            }
            Json::Object(items) => {
                if items.len() > self.limits.fields {
                    return Err(Error::limit("bgp_replay_fields"));
                }
                let width = items.len();
                let mut size = add(2, width.saturating_sub(1))?;
                let mut keys = BTreeSet::new();
                for (key, v) in items {
                    size = add(size, add(self.quoted_len(key)?, 1)?)?;
                    if !keys.insert(*key) {
                        return Err(bad("bgp_replay_duplicate_key", 0, "duplicate JSON field"));
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
                            | "wire_verified"
                            | "source_authenticated"
                            | "source_verified"
                            | "ordering_established"
                            | "namespace_equivalence_established"
                    ) && v != &Json::Bool(false)
                    {
                        return Err(bad(
                            "bgp_replay_authority",
                            0,
                            "authority claims must be absent or false",
                        ));
                    }
                    if matches!(*key, "spans" | "packets" | "ranges" | "provenance") {
                        if let Json::Array(items) = v {
                            self.spans = add(self.spans, items.len())?;
                            if self.spans > self.limits.spans {
                                return Err(Error::limit("bgp_replay_spans"));
                            }
                        }
                    }
                    size = add(size, self.tree(v, depth + 1)?)?;
                }
                Ok(size)
            }
        }
    }
    fn quoted_len(&mut self, value: &str) -> Result<usize> {
        if value.len() > self.limits.input_bytes {
            return Err(Error::limit("bgp_replay_string"));
        }
        self.charge(value.len())?;
        value.chars().try_fold(2usize, |size, c| {
            let bytes = match c {
                '"' | '\\' | '\n' | '\r' | '\t' | '\x08' | '\x0c' => 2,
                c if (c as u32) < 32 => 6,
                c => c.len_utf8(),
            };
            add(size, bytes)
        })
    }
}

#[cfg(test)]
mod accounting_tests;
