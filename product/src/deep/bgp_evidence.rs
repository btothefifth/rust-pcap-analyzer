//! Source-ordered, bounded historical evidence exports. A final manifest is
//! emitted only after every independent source completes verified replay.
//! Earlier rows remain provisional on any error; the caller owns publication.
//! No decoder state, RIB history, or resume cursor crosses a checkpoint.
use super::{
    bgp::{self, PeerRelationship, RouteAction},
    bgp_mrt_store::MrtReplayOptions,
    bgp_mrt_stream::{visit_verified, StreamEvent},
    bgp_mrt_stream_store::{verify_stream, MrtStreamLimits, StreamReceipt},
    bgp_state::{Observation, ObservationKind, RoutePathId},
    model::{bad, Limits},
};
use pcap_evidence::{json::Json, sha256, Error, Result};
use std::{fs::File, io::Write, path::PathBuf};

pub const SEQUENCE_SCHEMA: &str = "pcap-evidence.bgp.source-sequence.v1";
pub const ROW_SCHEMA: &str = "pcap-evidence.bgp.evidence-row.v1";
pub const MANIFEST_SCHEMA: &str = "pcap-evidence.bgp.evidence-manifest.v1";
pub const ROW_SCHEMA_V2: &str = "pcap-evidence.bgp.evidence-row.v2";
pub const MANIFEST_SCHEMA_V2: &str = "pcap-evidence.bgp.evidence-manifest.v2";
pub const FIELD_AVAILABILITY_SCHEMA: &str = "pcap-evidence.bgp.route-field-availability.v1";

/// Explicit compatibility boundary: legacy export bytes remain unchanged.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ComparisonFields {
    #[default]
    Legacy,
    PerFieldV2,
}
pub const ALL_SOURCE_CLOCKS: &str = "all-source-clocks";
const SEQUENCE_DOMAIN: &str = "pcap-evidence/bgp-source-sequence/v1";

#[derive(Clone, Debug)]
pub struct EvidenceLimits {
    pub comparison_fields: ComparisonFields,
    pub checkpoints: usize,
    pub source_bytes: u64,
    pub store_bytes: u64,
    pub work: u64,
    pub rows: u64,
    pub output_bytes: usize,
    pub row_bytes: usize,
    pub retained_bytes: usize,
    pub witnesses: usize,
}
impl Default for EvidenceLimits {
    fn default() -> Self {
        Self {
            comparison_fields: ComparisonFields::Legacy,
            checkpoints: 128,
            source_bytes: 1024 * 1024 * 1024,
            store_bytes: 2 * 1024 * 1024 * 1024,
            work: 8 * 1024 * 1024 * 1024,
            rows: 1_000_000,
            output_bytes: 64 * 1024 * 1024,
            row_bytes: 4 * 1024 * 1024,
            retained_bytes: 16 * 1024 * 1024,
            witnesses: 64,
        }
    }
}
impl EvidenceLimits {
    pub fn validate(&self) -> Result<()> {
        if self.checkpoints == 0
            || self.checkpoints > 4096
            || self.source_bytes == 0
            || self.store_bytes == 0
            || self.work == 0
            || self.rows == 0
            || self.output_bytes == 0
            || self.row_bytes == 0
            || self.retained_bytes == 0
            || self.witnesses > 4096
            || self.row_bytes > self.retained_bytes
        {
            return Err(Error::limit("bgp_evidence_configuration"));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TimeBasis {
    MrtRecordTime,
    RibOriginatedTime,
    ObservationTime,
}
impl TimeBasis {
    pub fn name(self) -> &'static str {
        match self {
            Self::MrtRecordTime => "mrt_record_time",
            Self::RibOriginatedTime => "rib_originated_time",
            Self::ObservationTime => "observation_time",
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AsnRole {
    Origin,
    PathMember,
}
impl AsnRole {
    pub fn name(self) -> &'static str {
        match self {
            Self::Origin => "origin",
            Self::PathMember => "path_member",
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AsnSelector {
    pub asn: u32,
    pub role: AsnRole,
}
/// Source labels are data; selecting every independent clock is explicit control.
/// String conversions always select one literal source, including `all-source-clocks`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ClockScope {
    Source(String),
    AllSourceClocks,
}
impl ClockScope {
    fn includes(&self, source_id: &str) -> bool {
        match self {
            Self::Source(source) => source == source_id,
            Self::AllSourceClocks => true,
        }
    }
    fn label(&self) -> &str {
        match self {
            Self::Source(source) => source,
            Self::AllSourceClocks => ALL_SOURCE_CLOCKS,
        }
    }
    fn kind(&self) -> &'static str {
        match self {
            Self::Source(_) => "source",
            Self::AllSourceClocks => "all_source_clocks",
        }
    }
}
impl From<String> for ClockScope {
    fn from(source: String) -> Self {
        Self::Source(source)
    }
}
impl From<&str> for ClockScope {
    fn from(source: &str) -> Self {
        Self::Source(source.into())
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowQuery {
    pub asn: Option<AsnSelector>,
    pub time_basis: TimeBasis,
    /// Checkpoints remain independent clock labels in either variant.
    pub clock_scope: ClockScope,
    pub start_ns: i128,
    pub end_ns: i128,
}
impl WindowQuery {
    pub fn validate(&self) -> Result<()> {
        if self.clock_scope.label().is_empty()
            || self.clock_scope.label().len() > 1024
            || self.start_ns >= self.end_ns
            || matches!(self.asn, Some(AsnSelector { asn: 0, .. }))
        {
            return Err(bad("bgp_evidence_window", 0, "invalid explicit window"));
        }
        Ok(())
    }
    pub fn json(&self) -> Json {
        Json::object([
            ("time_basis", self.time_basis.name().into()),
            ("clock_scope", self.clock_scope.label().into()),
            ("clock_scope_kind", self.clock_scope.kind().into()),
            (
                "clock_scope_semantics",
                "independent_source_checkpoint_labels".into(),
            ),
            ("start_ns", self.start_ns.to_string().into()),
            ("end_ns", self.end_ns.to_string().into()),
            ("interval", "half_open".into()),
            ("certain_occurrence_time_claimed", false.into()),
            (
                "asn",
                self.asn.map_or(Json::Null, |selector| {
                    Json::object([
                        ("number", selector.asn.into()),
                        ("role", selector.role.name().into()),
                    ])
                }),
            ),
        ])
    }
}

/// Navigation paths are supplied separately and never determine identity.
/// Public values are untrusted until `validate` and fresh source verification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SequenceEntry {
    pub ordinal: u64,
    pub source_id: String,
    pub checkpoint_id: String,
    pub source_sha256: String,
    pub source_bytes: u64,
    pub record_count: u64,
    pub final_chain: String,
    pub store_seal: String,
    pub predecessor_digest: String,
    pub entry_digest: String,
}
impl SequenceEntry {
    fn payload(&self) -> Json {
        Json::object([
            ("ordinal", self.ordinal.to_string().into()),
            ("source_id", self.source_id.clone().into()),
            ("checkpoint_id", self.checkpoint_id.clone().into()),
            ("source_sha256", self.source_sha256.clone().into()),
            ("source_bytes", self.source_bytes.to_string().into()),
            ("record_count", self.record_count.to_string().into()),
            ("final_chain", self.final_chain.clone().into()),
            ("store_seal", self.store_seal.clone().into()),
            ("predecessor_digest", self.predecessor_digest.clone().into()),
        ])
    }
    pub fn json(&self) -> Json {
        let Json::Object(mut fields) = self.payload() else {
            unreachable!()
        };
        fields.push(("entry_digest", self.entry_digest.clone().into()));
        Json::Object(fields)
    }
    fn matches(&self, receipt: &StreamReceipt) -> bool {
        self.source_id == receipt.source.source_id
            && self.checkpoint_id == receipt.source.checkpoint_id
            && self.source_sha256 == receipt.sha256
            && self.source_bytes == receipt.byte_length
            && self.record_count == receipt.record_count
            && self.final_chain == receipt.final_chain
            && self.store_seal == receipt.seal
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceSequence {
    pub entries: Vec<SequenceEntry>,
    pub sequence_digest: String,
}
impl SourceSequence {
    pub fn json(&self) -> Json {
        Json::object([
            ("schema", SEQUENCE_SCHEMA.into()),
            ("ordering", "caller_file_order".into()),
            ("independent_checkpoints", true.into()),
            (
                "entries",
                Json::array(self.entries.iter().map(SequenceEntry::json)),
            ),
            ("sequence_digest", self.sequence_digest.clone().into()),
        ])
    }
    pub fn validate(&self, limits: &EvidenceLimits) -> Result<()> {
        limits.validate()?;
        if self.entries.is_empty() || self.entries.len() > limits.checkpoints {
            return Err(Error::limit("bgp_evidence_checkpoints"));
        }
        // Admit every field before any cloning or semantic serialization.
        let mut bytes = 0u64;
        let mut records = 0u64;
        let mut predecessor = genesis();
        for (ordinal, entry) in self.entries.iter().enumerate() {
            if entry.ordinal != ordinal as u64
                || entry.source_id.trim().is_empty()
                || entry.checkpoint_id.trim().is_empty()
                || entry.source_id.chars().any(char::is_control)
                || entry.checkpoint_id.chars().any(char::is_control)
                || entry.source_id.len() > 1024
                || entry.checkpoint_id.len() > 1024
                || entry.source_bytes == 0
                || entry.record_count == 0
                || entry.record_count > entry.source_bytes / 12
                || ![
                    &entry.source_sha256,
                    &entry.final_chain,
                    &entry.store_seal,
                    &entry.predecessor_digest,
                    &entry.entry_digest,
                ]
                .iter()
                .all(|value| digest_text(value))
                || entry.predecessor_digest != predecessor
            {
                return Err(bad(
                    "bgp_evidence_sequence",
                    ordinal,
                    "invalid sequence reference",
                ));
            }
            bytes = add(
                bytes,
                entry.source_bytes,
                limits.source_bytes,
                "bgp_evidence_source_bytes",
            )?;
            records = add(
                records,
                entry.record_count,
                limits.rows,
                "bgp_evidence_rows",
            )?;
            let encoded = entry.payload().encode_bounded(limits.retained_bytes)?;
            let expected = domain_digest(SEQUENCE_DOMAIN, encoded.as_bytes());
            if entry.entry_digest != expected {
                return Err(bad(
                    "bgp_evidence_sequence",
                    ordinal,
                    "entry digest mismatch",
                ));
            }
            predecessor = expected;
        }
        if self.sequence_digest != predecessor {
            return Err(bad("bgp_evidence_sequence", 0, "sequence digest mismatch"));
        }
        self.json().encoded_len_bounded(limits.retained_bytes)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Default)]
pub struct Coverage {
    pub records: u64,
    pub rows: u64,
    pub observations: u64,
    pub route_free: u64,
    pub opaque: u64,
    pub rejected: u64,
    pub quarantined: u64,
    pub unsupported: u64,
    pub unknown_time: u64,
    pub unknown_mrt_record_time: u64,
    pub unknown_asn: u64,
    pub selected: u64,
    pub timestamp_regressions: u64,
    pub witnesses: Vec<Json>,
    pub witnesses_truncated: u64,
}
impl Coverage {
    pub fn json(&self) -> Json {
        Json::object([
            ("records", self.records.to_string().into()),
            ("rows", self.rows.to_string().into()),
            ("observations", self.observations.to_string().into()),
            ("route_free", self.route_free.to_string().into()),
            ("opaque", self.opaque.to_string().into()),
            ("rejected", self.rejected.to_string().into()),
            ("quarantined", self.quarantined.to_string().into()),
            ("unsupported", self.unsupported.to_string().into()),
            ("unknown_time", self.unknown_time.to_string().into()),
            (
                "unknown_mrt_record_time",
                self.unknown_mrt_record_time.to_string().into(),
            ),
            ("unknown_asn", self.unknown_asn.to_string().into()),
            ("selected", self.selected.to_string().into()),
            (
                "timestamp_regressions",
                self.timestamp_regressions.to_string().into(),
            ),
            ("witnesses", Json::array(self.witnesses.iter().cloned())),
            (
                "witnesses_truncated",
                self.witnesses_truncated.to_string().into(),
            ),
            (
                "count_unit",
                "rows_except_records_unknown_mrt_record_time_and_timestamp_regressions".into(),
            ),
        ])
    }
}
#[derive(Clone, Debug)]
pub struct EvidenceManifest {
    pub comparison_fields: ComparisonFields,
    pub sequence: SourceSequence,
    pub rows: u64,
    pub rows_bytes: u64,
    pub rows_sha256: String,
    pub coverage: Coverage,
    pub replay_relationship: String,
    pub window: Option<WindowQuery>,
    pub semantic_identity: String,
}
impl EvidenceManifest {
    fn payload(&self) -> Json {
        let mut payload = Json::object([
            (
                "schema",
                if self.comparison_fields == ComparisonFields::Legacy {
                    MANIFEST_SCHEMA
                } else {
                    MANIFEST_SCHEMA_V2
                }
                .into(),
            ),
            ("complete", true.into()),
            ("rows", self.rows.to_string().into()),
            ("rows_bytes", self.rows_bytes.to_string().into()),
            ("rows_sha256", self.rows_sha256.clone().into()),
            (
                "rows_digest_scope",
                "exact_ndjson_rows_including_newlines_excluding_manifest".into(),
            ),
            ("sequence", self.sequence.json()),
            ("semantic_profile", bgp::SEMANTIC_IDENTITY_SCHEMA.into()),
            (
                "replay_relationship",
                self.replay_relationship.clone().into(),
            ),
            (
                "window",
                self.window.as_ref().map_or(Json::Null, WindowQuery::json),
            ),
            ("coverage", self.coverage.json()),
            ("source_authenticated", false.into()),
            ("endpoint_state_claimed", false.into()),
            ("resume_cursor_supported", false.into()),
        ]);
        if self.comparison_fields == ComparisonFields::PerFieldV2 {
            let Json::Object(fields) = &mut payload else {
                unreachable!()
            };
            fields.push(("comparison_fields", "per-field-v2".into()));
            fields.push((
                "field_availability_schema",
                FIELD_AVAILABILITY_SCHEMA.into(),
            ));
        }
        payload
    }
    pub fn json(&self) -> Json {
        let Json::Object(mut fields) = self.payload() else {
            unreachable!()
        };
        fields.push(("semantic_identity", self.semantic_identity.clone().into()));
        Json::Object(fields)
    }
}

/// Verify a bounded list in caller order. Serialized sequence entries never
/// restore a decoder; the export API reopens and independently verifies each.
pub fn create_sequence(
    paths: &[PathBuf],
    stream: &MrtStreamLimits,
    limits: &EvidenceLimits,
) -> Result<SourceSequence> {
    let mut budget = Budget::new(limits)?;
    create_sequence_inner(paths, stream, limits, &mut budget)
}
fn create_sequence_inner(
    paths: &[PathBuf],
    stream: &MrtStreamLimits,
    limits: &EvidenceLimits,
    budget: &mut Budget,
) -> Result<SourceSequence> {
    if paths.is_empty() || paths.len() > limits.checkpoints {
        return Err(Error::limit("bgp_evidence_checkpoints"));
    }
    let mut entries = Vec::new();
    entries
        .try_reserve_exact(paths.len())
        .map_err(|_| Error::limit("bgp_evidence_sequence_allocation"))?;
    let mut predecessor = genesis();
    let mut store_bytes = 0;
    let mut record_count = 0;
    for (ordinal, path) in paths.iter().enumerate() {
        let mut file = File::open(path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() {
            return Err(Error::limit("bgp_evidence_regular_file"));
        }
        store_bytes = add(
            store_bytes,
            metadata.len(),
            limits.store_bytes,
            "bgp_evidence_store_bytes",
        )?;
        let mut local = stream.clone();
        local.work = local.work.min(limits.work.saturating_sub(budget.work));
        local.source_bytes = local
            .source_bytes
            .min(limits.source_bytes.saturating_sub(budget.source_bytes));
        local.store_bytes = local.store_bytes.min(metadata.len());
        local.records = local.records.min(limits.rows.saturating_sub(record_count));
        let receipt = verify_stream(&mut file, &local)?;
        budget.charge(receipt.work_used, limits)?;
        record_count = add(
            record_count,
            receipt.record_count,
            limits.rows,
            "bgp_evidence_rows",
        )?;
        budget.source_bytes = add(
            budget.source_bytes,
            receipt.byte_length,
            limits.source_bytes,
            "bgp_evidence_source_bytes",
        )?;
        let mut entry = SequenceEntry {
            ordinal: ordinal as u64,
            source_id: receipt.source.source_id,
            checkpoint_id: receipt.source.checkpoint_id,
            source_sha256: receipt.sha256,
            source_bytes: receipt.byte_length,
            record_count: receipt.record_count,
            final_chain: receipt.final_chain,
            store_seal: receipt.seal,
            predecessor_digest: predecessor,
            entry_digest: String::new(),
        };
        let encoded = entry.payload().encode_bounded(limits.retained_bytes)?;
        budget.charge((encoded.len() as u64).saturating_mul(3), limits)?;
        entry.entry_digest = domain_digest(SEQUENCE_DOMAIN, encoded.as_bytes());
        predecessor = entry.entry_digest.clone();
        entries.push(entry);
    }
    let sequence = SourceSequence {
        entries,
        sequence_digest: predecessor,
    };
    sequence.validate(limits)?;
    Ok(sequence)
}

/// Every row is written in source order, even when a window does not select it.
/// Known nonmembers, unknowns and route-free chronology remain inspectable.
pub fn export_sequence<W: Write>(
    paths: &[PathBuf],
    stream: &MrtStreamLimits,
    deep: &Limits,
    limits: &EvidenceLimits,
    options: &MrtReplayOptions,
    window: Option<&WindowQuery>,
    writer: &mut W,
) -> Result<EvidenceManifest> {
    let mut budget = Budget::new(limits)?;
    let sequence = create_sequence_inner(paths, stream, limits, &mut budget)?;
    export_inner(
        &sequence, paths, stream, deep, limits, options, window, writer, budget,
    )
}
#[allow(clippy::too_many_arguments)]
pub fn export_verified_sequence<W: Write>(
    sequence: &SourceSequence,
    paths: &[PathBuf],
    stream: &MrtStreamLimits,
    deep: &Limits,
    limits: &EvidenceLimits,
    options: &MrtReplayOptions,
    window: Option<&WindowQuery>,
    writer: &mut W,
) -> Result<EvidenceManifest> {
    export_inner(
        sequence,
        paths,
        stream,
        deep,
        limits,
        options,
        window,
        writer,
        Budget::new(limits)?,
    )
}

#[allow(clippy::too_many_arguments)]
fn export_inner<W: Write>(
    sequence: &SourceSequence,
    paths: &[PathBuf],
    stream: &MrtStreamLimits,
    deep: &Limits,
    limits: &EvidenceLimits,
    options: &MrtReplayOptions,
    window: Option<&WindowQuery>,
    writer: &mut W,
    mut budget: Budget,
) -> Result<EvidenceManifest> {
    sequence.validate(limits)?;
    deep.validate()?;
    if paths.len() != sequence.entries.len() {
        return Err(bad(
            "bgp_evidence_sequence",
            0,
            "path/reference cardinality mismatch",
        ));
    }
    if let Some(query) = window {
        query.validate()?;
        if !sequence
            .entries
            .iter()
            .any(|entry| query.clock_scope.includes(&entry.source_id))
        {
            return Err(bad(
                "bgp_evidence_clock_scope",
                0,
                "clock scope has no source reference",
            ));
        }
    }
    let sequence_size = sequence.json().encoded_len_bounded(limits.retained_bytes)?;
    budget.charge((sequence_size as u64).saturating_mul(3), limits)?;
    let mut coverage = Coverage::default();
    let mut hash = sha256::Sha256::new();
    let mut rows_bytes = 0u64;
    let mut retained = sequence_size;
    let mut store_bytes = 0;
    for (entry, path) in sequence.entries.iter().zip(paths) {
        let mut file = File::open(path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() {
            return Err(Error::limit("bgp_evidence_regular_file"));
        }
        store_bytes = add(
            store_bytes,
            metadata.len(),
            limits.store_bytes,
            "bgp_evidence_store_bytes",
        )?;
        let mut local = stream.clone();
        local.work = local.work.min(limits.work.saturating_sub(budget.work) / 2);
        local.source_bytes = local.source_bytes.min(entry.source_bytes);
        local.store_bytes = local.store_bytes.min(metadata.len());
        local.records = local.records.min(entry.record_count);
        // Reserve the stream grant before callbacks spend the remaining work.
        // Actual unused stream work is released only at terminal success.
        let reserved_work = local.work;
        budget.charge(reserved_work, limits)?;
        let mut last_record = None;
        let mut last_time = None;
        let receipt = visit_verified(&mut file, &local, deep, options, |event| {
            if !entry.matches(event.receipt) {
                return Err(bad(
                    "bgp_evidence_source_reference",
                    0,
                    "fresh source does not match sequence",
                ));
            }
            if last_record != Some(event.record_ordinal) {
                coverage.records = increment(coverage.records)?;
                last_record = Some(event.record_ordinal);
                let time = mrt_ns(&event);
                if matches!((last_time, time), (Some(prior), Some(time)) if time < prior) {
                    coverage.timestamp_regressions = increment(coverage.timestamp_regressions)?;
                }
                if time.is_none() {
                    coverage.unknown_mrt_record_time = increment(coverage.unknown_mrt_record_time)?;
                }
                // Unknown labels interrupt the adjacent-record comparison.
                last_time = time;
            }
            coverage.rows = add(coverage.rows, 1, limits.rows, "bgp_evidence_rows")?;
            let observation_time = event
                .observation
                .and_then(|value| value_at(value, "observed_at_ns"))
                .and_then(integer);
            let originated = event
                .originated_seconds
                .map(|value| i128::from(value) * 1_000_000_000);
            let (time_disposition, asn_disposition, selected) =
                classify(&event, window, observation_time, originated, deep)?;
            if event.observation.is_some() {
                coverage.observations = increment(coverage.observations)?;
            }
            let routes = event
                .observation
                .and_then(|value| value_at(value, "routes"));
            if !matches!(routes, Some(Json::Array(routes)) if !routes.is_empty()) {
                coverage.route_free = increment(coverage.route_free)?;
            }
            let status = text_at(event.event, "parse_status")
                .or_else(|| text_at(event.event, "status"))
                .or_else(|| text_at(event.event, "kind"))
                .unwrap_or("unknown");
            let status_coverage = StatusCoverage::new(status);
            if status_coverage.opaque {
                coverage.opaque = increment(coverage.opaque)?;
            }
            if status_coverage.rejected {
                coverage.rejected = increment(coverage.rejected)?;
            }
            if status_coverage.quarantined {
                coverage.quarantined = increment(coverage.quarantined)?;
            }
            if status_coverage.unsupported {
                coverage.unsupported = increment(coverage.unsupported)?;
            }
            if time_disposition == Some("unknown_time") {
                coverage.unknown_time = increment(coverage.unknown_time)?;
            }
            if asn_disposition == Some("unknown_asn") {
                coverage.unknown_asn = increment(coverage.unknown_asn)?;
            }
            if selected {
                coverage.selected = increment(coverage.selected)?;
            }
            for reason in [
                time_disposition.filter(|value| *value == "unknown_time"),
                mrt_ns(&event)
                    .is_none()
                    .then_some(mrt_time_validity(&event)),
                asn_disposition.filter(|value| *value == "unknown_asn"),
                status_coverage.needs_witness().then_some(status),
            ]
            .into_iter()
            .flatten()
            {
                if coverage.witnesses.len() < limits.witnesses {
                    let witness = Json::object([
                        ("sequence_ordinal", entry.ordinal.to_string().into()),
                        ("source_sha256", entry.source_sha256.clone().into()),
                        ("record_ordinal", event.record_ordinal.to_string().into()),
                        ("record_offset", event.record_offset.to_string().into()),
                        ("record_sha256", event.record_sha256.into()),
                        (
                            "entry_index",
                            event
                                .entry_index
                                .map_or(Json::Null, |value| value.to_string().into()),
                        ),
                        ("reason", reason.into()),
                    ]);
                    retained = retained
                        .checked_add(witness.encoded_len_bounded(limits.retained_bytes)?)
                        .filter(|size| *size <= limits.retained_bytes)
                        .ok_or_else(|| Error::limit("bgp_evidence_retained_bytes"))?;
                    coverage.witnesses.push(witness);
                } else {
                    coverage.witnesses_truncated = increment(coverage.witnesses_truncated)?;
                }
            }
            // Bound before cloning the normalizer's current row, with room for
            // the encoding and the bounded witness inventory to coexist.
            let observation_size = event
                .observation
                .map_or(Ok(0), |value| value.encoded_len_bounded(limits.row_bytes))?;
            let event_size = event.event.encoded_len_bounded(limits.row_bytes)?;
            if retained
                .checked_add((observation_size + event_size).saturating_mul(3))
                .is_none_or(|size| size > limits.retained_bytes)
            {
                return Err(Error::limit("bgp_evidence_retained_bytes"));
            }
            let row = row_json(
                entry,
                &event,
                observation_time,
                originated,
                time_disposition,
                asn_disposition,
                selected,
                limits.comparison_fields,
                deep,
            )?;
            // Declaration and original evidence coexist before encoding.
            let row_size = row.encoded_len_bounded(limits.row_bytes)?;
            if limits.comparison_fields == ComparisonFields::PerFieldV2
                && retained
                    .checked_add(row_size.saturating_mul(3))
                    .is_none_or(|size| size > limits.retained_bytes)
            {
                return Err(Error::limit("bgp_evidence_retained_bytes"));
            }
            let remaining = limits.output_bytes.saturating_sub(budget.output);
            let line = row.encode_bounded_line(limits.row_bytes.min(remaining))?;
            budget.charge((line.len() as u64).saturating_mul(4), limits)?;
            budget.output = budget
                .output
                .checked_add(line.len())
                .filter(|size| *size <= limits.output_bytes)
                .ok_or_else(|| Error::limit("bgp_evidence_output_bytes"))?;
            writer.write_all(line.as_bytes())?;
            hash.update(line.as_bytes());
            rows_bytes = add(
                rows_bytes,
                line.len() as u64,
                u64::MAX,
                "bgp_evidence_output_bytes",
            )?;
            Ok(())
        })?;
        if !entry.matches(&receipt) {
            return Err(bad(
                "bgp_evidence_source_reference",
                0,
                "terminal source does not match sequence",
            ));
        }
        budget.work -= reserved_work;
        budget.charge(receipt.work_used, limits)?;
    }
    let mut manifest = EvidenceManifest {
        comparison_fields: limits.comparison_fields,
        sequence: sequence.clone(),
        rows: coverage.rows,
        rows_bytes,
        rows_sha256: sha256::hex(&hash.finalize()),
        coverage,
        replay_relationship: relationship(options).into(),
        window: window.cloned(),
        semantic_identity: String::new(),
    };
    let payload = manifest.payload().encode_bounded(limits.retained_bytes)?;
    budget.charge((payload.len() as u64).saturating_mul(3), limits)?;
    manifest.semantic_identity = domain_digest(
        if limits.comparison_fields == ComparisonFields::Legacy {
            "pcap-evidence/bgp-evidence-manifest/v1"
        } else {
            "pcap-evidence/bgp-evidence-manifest/v2"
        },
        payload.as_bytes(),
    );
    let line = manifest
        .json()
        .encode_bounded_line(limits.output_bytes.saturating_sub(budget.output))?;
    budget.charge((line.len() as u64).saturating_mul(3), limits)?;
    writer.write_all(line.as_bytes())?;
    Ok(manifest)
}

#[allow(clippy::too_many_arguments)]
fn row_json(
    entry: &SequenceEntry,
    event: &StreamEvent<'_>,
    observation_time: Option<i128>,
    originated: Option<i128>,
    time_disposition: Option<&str>,
    asn_disposition: Option<&str>,
    selected: bool,
    mode: ComparisonFields,
    limits: &Limits,
) -> Result<Json> {
    let mut row = Json::object([
        (
            "schema",
            if mode == ComparisonFields::Legacy {
                ROW_SCHEMA
            } else {
                ROW_SCHEMA_V2
            }
            .into(),
        ),
        ("provisional", true.into()),
        ("sequence_ordinal", entry.ordinal.to_string().into()),
        ("source_id", entry.source_id.clone().into()),
        ("checkpoint_id", entry.checkpoint_id.clone().into()),
        ("source_sha256", entry.source_sha256.clone().into()),
        ("full_source_bytes", entry.source_bytes.to_string().into()),
        ("store_seal", entry.store_seal.clone().into()),
        ("record_ordinal", event.record_ordinal.to_string().into()),
        ("record_offset", event.record_offset.to_string().into()),
        ("record_bytes", event.record_bytes.to_string().into()),
        ("record_type", event.record_type.into()),
        ("subtype", event.subtype.into()),
        ("record_sha256", event.record_sha256.into()),
        (
            "entry_index",
            event
                .entry_index
                .map_or(Json::Null, |value| value.to_string().into()),
        ),
        (
            "mrt_record_time",
            Json::object([
                ("seconds", event.time.seconds.to_string().into()),
                (
                    "microseconds",
                    event
                        .time
                        .microseconds
                        .map_or(Json::Null, |value| value.to_string().into()),
                ),
                ("validity", mrt_time_validity(event).into()),
                (
                    "precision",
                    match mrt_time_validity(event) {
                        "seconds" => "seconds",
                        "microseconds" => "microseconds",
                        _ => "unknown",
                    }
                    .into(),
                ),
                ("time_ns", optional_integer(mrt_ns(event))),
            ]),
        ),
        ("rib_originated_time_ns", optional_integer(originated)),
        ("observation_time_ns", optional_integer(observation_time)),
        ("event", event.event.clone()),
        (
            "observation",
            event.observation.cloned().unwrap_or(Json::Null),
        ),
        (
            "window_disposition",
            time_disposition.map_or(Json::Null, Json::from),
        ),
        (
            "asn_disposition",
            asn_disposition.map_or(Json::Null, Json::from),
        ),
        ("selected", selected.into()),
        ("certain_occurrence_time_claimed", false.into()),
    ]);
    if mode == ComparisonFields::PerFieldV2 {
        let declaration = route_field_availability(entry, event, limits)?;
        let Json::Object(fields) = &mut row else {
            unreachable!()
        };
        fields.push(("field_availability", declaration));
    }
    Ok(row)
}

/// Derive availability from the validated producer DTO, never semantic completeness.
/// Export commitments establish integrity only, not source authentication.
fn route_field_availability(
    entry: &SequenceEntry,
    event: &StreamEvent<'_>,
    limits: &Limits,
) -> Result<Json> {
    let mut status = "unavailable";
    let mut projection_complete = false;
    let mut routes = Vec::new();
    if let Some(normalized) = event.observation {
        let observation = Observation::from_normalized(normalized, None, limits)?;
        let context = observation.import_context().ok_or_else(|| {
            bad(
                "bgp_field_availability",
                0,
                "imported source context missing",
            )
        })?;
        let end = event
            .record_offset
            .checked_add(event.record_bytes)
            .ok_or_else(|| Error::limit("bgp_field_availability"))?;
        if observation.source().source_id != entry.source_id
            || context.batch.sha256.as_deref() != Some(entry.source_sha256.as_str())
            || context.batch.byte_length != Some(entry.source_bytes)
            || !context.provenance.iter().any(|range| {
                range.start >= event.record_offset
                    && range.start < range.end
                    && range.end <= end
                    && range.sha256.is_some()
            })
        {
            return Err(bad(
                "bgp_field_availability",
                0,
                "observation/source row reference mismatch",
            ));
        }
        if observation.kind() == ObservationKind::Routes {
            // BGP4MP UPDATEs carry an explicit producer flag. Imported RIB
            // observations have no opaque NLRI and no message detail.
            projection_complete = match value_at(observation.normalized(), "message_detail") {
                Some(Json::Null) | None => event.entry_index.is_some(),
                Some(detail) => {
                    value_at(detail, "route_projection_incomplete") == Some(&Json::Bool(false))
                }
            };
            status = if projection_complete {
                "complete"
            } else {
                "incomplete"
            };
            for (index, route) in observation.routes().iter().enumerate() {
                let prefix = route.prefix();
                if !matches!((prefix.afi, prefix.safi), (1 | 2, 1 | 2)) {
                    status = "incomplete";
                }
                let path_id = match route.path_id() {
                    RoutePathId::Absent => Json::Null,
                    RoutePathId::Present(value) => value.into(),
                };
                routes.push(Json::object([
                    ("route_index", index.to_string().into()),
                    (
                        "action",
                        match route.action() {
                            RouteAction::Announce => "announce",
                            RouteAction::Withdraw => "withdraw",
                        }
                        .into(),
                    ),
                    (
                        "prefix",
                        Json::object([
                            ("afi", prefix.afi.into()),
                            ("safi", prefix.safi.into()),
                            ("length", prefix.length.into()),
                            ("address", prefix.address.clone().into()),
                        ]),
                    ),
                    ("path_id", path_id),
                ]));
            }
        }
    }
    Ok(Json::object([
        ("schema", FIELD_AVAILABILITY_SCHEMA.into()),
        (
            "source_reference",
            Json::object([
                ("sequence_ordinal", entry.ordinal.to_string().into()),
                ("source_sha256", entry.source_sha256.clone().into()),
                ("store_seal", entry.store_seal.clone().into()),
                ("record_ordinal", event.record_ordinal.to_string().into()),
                ("record_offset", event.record_offset.to_string().into()),
                ("record_sha256", event.record_sha256.into()),
                (
                    "entry_index",
                    event
                        .entry_index
                        .map_or(Json::Null, |value| value.to_string().into()),
                ),
            ]),
        ),
        ("route_projection_complete", projection_complete.into()),
        ("status", status.into()),
        ("routes", Json::Array(routes)),
    ]))
}

fn classify(
    event: &StreamEvent<'_>,
    query: Option<&WindowQuery>,
    observation_time: Option<i128>,
    originated: Option<i128>,
    limits: &Limits,
) -> Result<(Option<&'static str>, Option<&'static str>, bool)> {
    let Some(query) = query else {
        return Ok((None, None, true));
    };
    let time = match query.time_basis {
        TimeBasis::MrtRecordTime => mrt_ns(event),
        TimeBasis::RibOriginatedTime => originated,
        TimeBasis::ObservationTime => observation_time,
    };
    let time_disposition = if !query.clock_scope.includes(&event.receipt.source.source_id) {
        "outside_clock_scope"
    } else {
        match time {
            None => "unknown_time",
            Some(time) if time >= query.start_ns && time < query.end_ns => "inside_label_window",
            Some(_) => "outside_label_window",
        }
    };
    let asn_disposition = query
        .asn
        .map(|selector| {
            let Some(normalized) = event.observation else {
                return Ok::<_, Error>("unknown_asn");
            };
            let observation = Observation::from_normalized(normalized, None, limits)?;
            Ok(asn_match(&observation, selector))
        })
        .transpose()?;
    Ok((
        Some(time_disposition),
        asn_disposition,
        time_disposition == "inside_label_window"
            && asn_disposition.is_none_or(|value| value == "matched"),
    ))
}
fn asn_match(observation: &Observation, selector: AsnSelector) -> &'static str {
    let mut unknown = observation.routes().is_empty();
    for route in observation.routes() {
        match asn_route_match(route, selector) {
            "matched" => return "matched",
            "unknown_asn" => unknown = true,
            _ => {}
        }
    }
    if unknown {
        "unknown_asn"
    } else {
        "not_matched"
    }
}
/// The common ASN selector rule consumes one already validated native route.
pub(crate) fn asn_route_match(
    route: &super::bgp_state::RouteObservation,
    selector: AsnSelector,
) -> &'static str {
    let mut unknown = false;
    if route.action() != RouteAction::Announce
        || route.ambiguous_attributes()
        || text_at(route.semantic_identity(), "completeness") != Some("complete")
    {
        return "unknown_asn";
    }
    let Some(Json::Array(path)) = value_at(route.attributes(), "as_path") else {
        return "unknown_asn";
    };
    if path.is_empty() {
        return "unknown_asn";
    }
    if selector.role == AsnRole::PathMember {
        let mut unresolved = false;
        for segment in path {
            let kind = value_at(segment, "kind").and_then(number);
            let Some(Json::Array(values)) = value_at(segment, "values") else {
                unresolved = true;
                continue;
            };
            if !matches!(kind, Some(1 | 2)) {
                unresolved = true;
                continue;
            }
            for value in values {
                if number(value) == Some(u64::from(selector.asn)) && selector.asn != 23456 {
                    return "matched";
                }
                if number(value) == Some(23456) {
                    unresolved = true;
                }
            }
        }
        unknown |= unresolved;
    } else {
        let terminal = path.last().expect("nonempty path");
        let Some(Json::Array(values)) = value_at(terminal, "values") else {
            return "unknown_asn";
        };
        if value_at(terminal, "kind").and_then(number) != Some(2) {
            return "unknown_asn";
        }
        match values.last().and_then(number) {
            Some(23456) | None => unknown = true,
            Some(value) if value == u64::from(selector.asn) => return "matched",
            Some(_) => {}
        }
    }
    if unknown {
        "unknown_asn"
    } else {
        "not_matched"
    }
}

/// Overlapping diagnostic row classes, independent of reducer admission.
/// Keep the converter's mirrored classifier and canonical coverage order in
/// sync. Unrecognized statuses retain their original event and unknown
/// interpretation; this summary never promotes them to accepted or rejected.
struct StatusCoverage {
    opaque: bool,
    rejected: bool,
    quarantined: bool,
    unsupported: bool,
}
impl StatusCoverage {
    fn new(status: &str) -> Self {
        Self {
            opaque: status.contains("opaque"),
            rejected: status.contains("reject"),
            quarantined: status.contains("quarantin"),
            unsupported: status.contains("unsupported"),
        }
    }
    fn needs_witness(&self) -> bool {
        self.opaque || self.rejected || self.quarantined || self.unsupported
    }
}
struct Budget {
    work: u64,
    output: usize,
    source_bytes: u64,
}
impl Budget {
    fn new(limits: &EvidenceLimits) -> Result<Self> {
        limits.validate()?;
        Ok(Self {
            work: 0,
            output: 0,
            source_bytes: 0,
        })
    }
    fn charge(&mut self, amount: u64, limits: &EvidenceLimits) -> Result<()> {
        self.work = add(self.work, amount, limits.work, "bgp_evidence_work")?;
        Ok(())
    }
}
fn add(value: u64, amount: u64, cap: u64, context: &'static str) -> Result<u64> {
    value
        .checked_add(amount)
        .filter(|value| *value <= cap)
        .ok_or_else(|| Error::limit(context))
}
fn increment(value: u64) -> Result<u64> {
    add(value, 1, u64::MAX, "bgp_evidence_count")
}
fn mrt_time_validity(event: &StreamEvent<'_>) -> &'static str {
    if event.record_type != 17 {
        "seconds"
    } else {
        match event.time.microseconds {
            None => "missing_microseconds",
            Some(value) if value >= 1_000_000 => "invalid_microseconds",
            Some(_) => "microseconds",
        }
    }
}
fn mrt_ns(event: &StreamEvent<'_>) -> Option<i128> {
    let seconds = i128::from(event.time.seconds) * 1_000_000_000;
    if event.record_type != 17 {
        Some(seconds)
    } else {
        event
            .time
            .microseconds
            .filter(|value| *value < 1_000_000)
            .map(|value| seconds + i128::from(value) * 1000)
    }
}
fn optional_integer(value: Option<i128>) -> Json {
    value.map_or(Json::Null, |value| value.to_string().into())
}
fn integer(value: &Json) -> Option<i128> {
    match value {
        Json::String(value) => value.parse().ok(),
        Json::Number(value) => Some(i128::from(*value)),
        _ => None,
    }
}
fn number(value: &Json) -> Option<u64> {
    match value {
        Json::Number(value) => Some(*value),
        _ => None,
    }
}
fn value_at<'a>(value: &'a Json, key: &str) -> Option<&'a Json> {
    match value {
        Json::Object(fields) => fields
            .iter()
            .find(|(name, _)| *name == key)
            .map(|(_, value)| value),
        _ => None,
    }
}
fn text_at<'a>(value: &'a Json, key: &str) -> Option<&'a str> {
    value_at(value, key).and_then(|value| match value {
        Json::String(value) => Some(value.as_str()),
        _ => None,
    })
}
fn digest_text(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
fn genesis() -> String {
    domain_digest(SEQUENCE_DOMAIN, b"genesis")
}
fn domain_digest(domain: &str, bytes: &[u8]) -> String {
    let mut hash = sha256::Sha256::new();
    hash.update(domain.as_bytes());
    hash.update(&[0]);
    hash.update(bytes);
    sha256::hex(&hash.finalize())
}
fn relationship(options: &MrtReplayOptions) -> &'static str {
    match options.peer_relationship {
        Some(PeerRelationship::Internal) => "internal",
        Some(PeerRelationship::External) => "external",
        Some(PeerRelationship::Unknown) | None => "unknown",
    }
}
