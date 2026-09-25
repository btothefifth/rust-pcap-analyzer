//! Restartable storage for external MRT evidence.
//!
//! The container stores the exact MRT bytes and caller-provided source labels,
//! not a trusted serialized projection. Fresh replay verifies the terminal
//! digest, reparses the MRT grammar, renormalizes every safe TABLE_DUMP_V2 RIB
//! entry, and runs those observations through the shared candidate-state model.
//! A collector RIB has no captured packet direction, so its entries remain
//! explicit collector candidates and `missing_scope` in Adj-RIB-In state.
#[path = "bgp_mrt_store_io.rs"]
mod io_support;
#[path = "bgp_mrt_store_output.rs"]
mod output;
pub use io_support::read_source;

use super::{
    bgp::{self, RouteAction, SourceKind},
    bgp_import::{self, GenerationBoundary, ImportContext, ImportPartition, SourceRange},
    bgp_mrt::{Bgp4mpPayload, MrtBatch, MrtBody, MrtLimits, MrtRecord, MrtSource, Rib},
    bgp_state::{CandidateState, Observation, PrefixIdentity, RoutePathId},
    model::{bad, Limits},
};
use pcap_evidence::{json::Json, sha256, Error, ErrorCode, Result};
use std::{
    collections::{BTreeMap, HashSet},
    fmt::Write as _,
    fs::{File, OpenOptions},
    io::{Read, Write},
    net::{Ipv4Addr, Ipv6Addr},
    path::Path,
};

pub const SCHEMA: &str = "pcap-evidence.bgp.mrt-source-store.v1";
pub const REPLAY_SCHEMA: &str = "pcap-evidence.bgp.mrt-replay.v3";
pub const MAGIC: &[u8; 8] = b"PCBMRT01";
const VERSION: u16 = 1;
const SEAL_DOMAIN: &[u8] = b"pcap-evidence/bgp-mrt-source-store/v1\0";
const FIXED_HEADER: usize = 8 + 2;
const DIGEST_BYTES: usize = 32;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MrtStoreReceipt {
    pub source_id: String,
    pub checkpoint_id: String,
    pub source_sha256: [u8; 32],
    pub source_bytes: u64,
    pub terminal_sha256: [u8; 32],
    pub records: u64,
}

/// Optional RFC 7606 relationship context for imported BGP4MP replay.
///
/// A configured relationship applies uniformly to every BGP4MP peer session
/// in the replay. Use `None` for mixed or unverified source relationships;
/// the replay never infers one from addresses or ASNs. Supply the same options
/// again when replaying a source store because its sealed bytes remain the
/// original evidence and do not embed analysis policy.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MrtReplayOptions {
    pub peer_relationship: Option<bgp::PeerRelationship>,
}

fn peer_relationship_name(value: bgp::PeerRelationship) -> &'static str {
    match value {
        bgp::PeerRelationship::Unknown => "unknown",
        bgp::PeerRelationship::Internal => "internal",
        bgp::PeerRelationship::External => "external",
    }
}

impl MrtStoreReceipt {
    pub fn json(&self) -> Json {
        Json::object([
            ("schema", SCHEMA.into()),
            ("source_id", self.source_id.clone().into()),
            ("checkpoint_id", self.checkpoint_id.clone().into()),
            ("source_sha256", sha256::hex(&self.source_sha256).into()),
            ("source_bytes", self.source_bytes.to_string().into()),
            ("records", self.records.to_string().into()),
            ("terminal_sha256", sha256::hex(&self.terminal_sha256).into()),
            ("sealed", true.into()),
            ("source_authenticated", false.into()),
            ("endpoint_state_claimed", false.into()),
        ])
    }
}

#[derive(Clone, Debug)]
pub struct CollectorCandidate {
    pub record_index: usize,
    pub entry_index: usize,
    pub observation_sha256: [u8; 32],
    pub source_id: String,
    pub checkpoint_id: String,
    pub record_id: String,
    pub session: String,
    pub peer: Option<String>,
    pub observed_at_ns: Option<i64>,
    pub prefix: PrefixIdentity,
    pub path_id: RoutePathId,
    pub action: RouteAction,
    pub ambiguous_attributes: bool,
    /// Index into `MrtReplayArchive::state.observations()`.
    pub observation_index: usize,
    /// Index into the referenced observation's `routes` array.
    pub route_index: usize,
}

impl CollectorCandidate {
    pub fn json(&self) -> Json {
        let mut fields = vec![
            ("schema", "pcap-evidence.bgp.collector-candidate.v2".into()),
            ("status", "collector_candidate".into()),
            ("source_kind", "imported".into()),
            ("source_id", self.source_id.clone().into()),
            ("checkpoint_id", self.checkpoint_id.clone().into()),
            ("record_id", self.record_id.clone().into()),
            ("session", self.session.clone().into()),
            ("peer", self.peer.clone().map_or(Json::Null, Json::String)),
            (
                "observed_at_ns",
                self.observed_at_ns
                    .map_or(Json::Null, |value| value.to_string().into()),
            ),
            ("record_index", self.record_index.to_string().into()),
            ("entry_index", self.entry_index.to_string().into()),
            (
                "observation_sha256",
                sha256::hex(&self.observation_sha256).into(),
            ),
            ("prefix", prefix_json(&self.prefix)),
            ("action", action_name(self.action).into()),
            ("ambiguous_attributes", self.ambiguous_attributes.into()),
            (
                "observation_index",
                self.observation_index.to_string().into(),
            ),
            ("route_index", self.route_index.to_string().into()),
            ("direction", Json::Null),
            ("adj_rib_in_established", false.into()),
            ("endpoint_state_claimed", false.into()),
        ];
        if let RoutePathId::Present(path_id) = self.path_id {
            fields.push(("path_id", path_id.into()));
        }
        Json::Object(fields)
    }
}

#[derive(Clone, Debug)]
pub struct Bgp4mpCandidate {
    pub record_index: usize,
    pub observation_sha256: [u8; 32],
    pub source_id: String,
    pub checkpoint_id: String,
    pub record_id: String,
    pub session: String,
    pub peer: Option<String>,
    pub observed_at_ns: Option<i64>,
    pub direction: u8,
    pub source_range_start: u64,
    pub source_range_end: u64,
    pub message_sha256: String,
    pub prefix: PrefixIdentity,
    pub path_id: RoutePathId,
    pub action: RouteAction,
    pub observation_index: usize,
    pub route_index: usize,
}

impl Bgp4mpCandidate {
    pub fn json(&self) -> Json {
        let mut fields = vec![
            ("schema", "pcap-evidence.bgp.bgp4mp-candidate.v1".into()),
            ("status", "imported_wire_route_candidate".into()),
            ("source_kind", "imported".into()),
            ("source_id", self.source_id.clone().into()),
            ("checkpoint_id", self.checkpoint_id.clone().into()),
            ("record_id", self.record_id.clone().into()),
            ("session", self.session.clone().into()),
            ("peer", self.peer.clone().map_or(Json::Null, Json::String)),
            (
                "observed_at_ns",
                self.observed_at_ns
                    .map_or(Json::Null, |value| value.to_string().into()),
            ),
            ("record_index", self.record_index.to_string().into()),
            ("direction", self.direction.into()),
            ("message_range_start", self.source_range_start.into()),
            ("message_range_end", self.source_range_end.into()),
            ("message_sha256", self.message_sha256.clone().into()),
            (
                "observation_sha256",
                sha256::hex(&self.observation_sha256).into(),
            ),
            ("prefix", prefix_json(&self.prefix)),
            ("action", action_name(self.action).into()),
            (
                "observation_index",
                self.observation_index.to_string().into(),
            ),
            ("route_index", self.route_index.to_string().into()),
            ("adj_rib_in_established", false.into()),
            ("endpoint_state_claimed", false.into()),
        ];
        if let RoutePathId::Present(path_id) = self.path_id {
            fields.push(("path_id", path_id.into()));
        }
        Json::Object(fields)
    }
}

pub struct MrtReplayArchive {
    pub receipt: MrtStoreReceipt,
    batch: MrtBatch,
    pub state: CandidateState,
    /// Explicit context for all BGP4MP peer sessions in this replay.
    pub peer_relationship: Option<bgp::PeerRelationship>,
    pub candidates: Vec<CollectorCandidate>,
    pub bgp4mp_candidates: Vec<Bgp4mpCandidate>,
    pub bgp4mp_events: Vec<Json>,
    pub opaque_records: u64,
    pub unsupported_rib_entries: u64,
    unsupported_rib_entry_evidence: Vec<Json>,
    pub bgp4mp_messages: u64,
    pub bgp4mp_state_changes: u64,
}

impl MrtReplayArchive {
    /// Parsed source material is immutable after replay construction so cached
    /// source-bound evidence cannot become stale through caller mutation.
    pub fn batch(&self) -> &MrtBatch {
        &self.batch
    }

    pub fn json(&self) -> Json {
        Json::object([
            ("schema", REPLAY_SCHEMA.into()),
            ("receipt", self.receipt.json()),
            ("adapter_schema", self.batch.schema.into()),
            ("fresh_process_reduction", true.into()),
            ("source_authenticated", false.into()),
            ("endpoint_state_claimed", false.into()),
            (
                "bgp4mp_peer_relationship",
                self.peer_relationship
                    .map_or("unknown", peer_relationship_name)
                    .into(),
            ),
            (
                "bgp4mp_peer_relationship_basis",
                if self.peer_relationship.is_some() {
                    "explicit_configuration"
                } else {
                    "default_unknown"
                }
                .into(),
            ),
            (
                "bgp4mp_peer_relationship_scope",
                "all_sessions_in_this_replay".into(),
            ),
            (
                "collector_candidates",
                Json::array(self.candidates.iter().map(CollectorCandidate::json)),
            ),
            (
                "bgp4mp_candidates",
                Json::array(self.bgp4mp_candidates.iter().map(Bgp4mpCandidate::json)),
            ),
            (
                "bgp4mp_events",
                Json::array(self.bgp4mp_events.iter().cloned()),
            ),
            ("candidate_state", self.state.json()),
            (
                "record_summaries",
                Json::array(self.batch.records.iter().map(record_json)),
            ),
            ("opaque_records", self.opaque_records.to_string().into()),
            (
                "unsupported_rib_entries",
                self.unsupported_rib_entries.to_string().into(),
            ),
            (
                "unsupported_rib_entry_evidence",
                Json::array(self.unsupported_rib_entry_evidence.iter().cloned()),
            ),
            ("bgp4mp_messages", self.bgp4mp_messages.to_string().into()),
            (
                "bgp4mp_state_changes",
                self.bgp4mp_state_changes.to_string().into(),
            ),
        ])
    }

    pub fn session_candidates(&self, session: &str) -> Vec<&CollectorCandidate> {
        self.candidates
            .iter()
            .filter(|candidate| candidate.session == session)
            .collect()
    }

    pub fn session_bgp4mp_candidates(&self, session: &str) -> Vec<&Bgp4mpCandidate> {
        self.bgp4mp_candidates
            .iter()
            .filter(|candidate| candidate.session == session)
            .collect()
    }

    /// Resolve a compact reference only after its identity, route, and original
    /// MRT record/entry bindings agree. These public values are not authenticated
    /// by an in-range numeric index, nor by a hash supplied by a different archive.
    pub fn candidate_observation(&self, candidate: &CollectorCandidate) -> Result<&Observation> {
        let observation = self
            .state
            .observations()
            .get(candidate.observation_index)
            .ok_or_else(|| {
                bad(
                    "bgp_mrt_observation_ref",
                    candidate.observation_index,
                    "candidate observation reference is outside the journal",
                )
            })?;
        let route = observation
            .routes()
            .get(candidate.route_index)
            .ok_or_else(|| {
                bad(
                    "bgp_mrt_route_ref",
                    candidate.route_index,
                    "candidate route reference is outside the observation",
                )
            })?;
        let record = self
            .batch
            .records
            .get(candidate.record_index)
            .ok_or_else(|| {
                bad(
                    "bgp_mrt_record_ref",
                    candidate.record_index,
                    "candidate record reference is outside the source",
                )
            })?;
        let MrtBody::Rib(rib) = &record.body else {
            return Err(bad(
                "bgp_mrt_record_ref",
                candidate.record_index,
                "candidate record is not RIB",
            ));
        };
        if candidate.entry_index >= rib.entries.len() {
            return Err(bad(
                "bgp_mrt_entry_ref",
                candidate.entry_index,
                "candidate entry is absent",
            ));
        }
        let source = observation.source();
        let context = observation
            .import_context()
            .ok_or_else(|| bad("bgp_mrt_observation_ref", 0, "collector context is absent"))?;
        let end = record
            .offset
            .checked_add(12)
            .and_then(|offset| offset.checked_add(u64::from(record.length)))
            .filter(|offset| *offset <= self.batch.byte_length)
            .ok_or_else(|| Error::limit("bgp_mrt_record_ref"))?;
        let expected_record = format!(
            "mrt:{}:{}:{}",
            record.offset, rib.sequence, candidate.entry_index
        );
        if source.kind != SourceKind::Imported
            || candidate.observation_sha256 != observation.sha256()
            || candidate.source_id != source.source_id
            || candidate.source_id != self.batch.source.source_id
            || candidate.source_id != self.receipt.source_id
            || candidate.checkpoint_id != self.batch.source.checkpoint_id
            || candidate.checkpoint_id != self.receipt.checkpoint_id
            || candidate.record_id != source.record_id
            || candidate.record_id != expected_record
            || source.session.as_deref() != Some(candidate.session.as_str())
            || candidate.peer != source.peer
            || candidate.observed_at_ns != source.observed_at_ns
            || source.direction.is_some()
            || source.generation != Some(0)
            || observation.import_boundary().is_some()
            || &candidate.prefix != route.prefix()
            || candidate.path_id != route.path_id()
            || candidate.action != route.action()
            || candidate.ambiguous_attributes != route.ambiguous_attributes()
            || context.batch.sha256.as_deref() != Some(self.batch.sha256.as_str())
            || context.batch.byte_length != Some(self.batch.byte_length)
            || self.receipt.source_bytes != self.batch.byte_length
            || sha256::hex(&self.receipt.source_sha256) != self.batch.sha256
            || context.provenance.len() != 1
            || context.provenance[0].start != record.offset
            || context.provenance[0].end != end
            || context.provenance[0].sha256.as_deref() != Some(record.sha256.as_str())
        {
            return Err(bad(
                "bgp_mrt_candidate_binding",
                candidate.observation_index,
                "compact candidate identity, route, or source binding disagrees",
            ));
        }
        Ok(observation)
    }

    /// Resolve an imported wire-route reference only after checking its
    /// observation, route, session direction, and exact embedded source range.
    pub fn bgp4mp_candidate_observation(
        &self,
        candidate: &Bgp4mpCandidate,
    ) -> Result<&Observation> {
        let observation = self
            .state
            .observations()
            .get(candidate.observation_index)
            .ok_or_else(|| {
                bad(
                    "bgp_mrt_observation_ref",
                    candidate.observation_index,
                    "BGP4MP observation reference is outside the journal",
                )
            })?;
        let route = observation
            .routes()
            .get(candidate.route_index)
            .ok_or_else(|| {
                bad(
                    "bgp_mrt_route_ref",
                    candidate.route_index,
                    "BGP4MP route reference is outside the observation",
                )
            })?;
        let record = self
            .batch
            .records
            .get(candidate.record_index)
            .ok_or_else(|| {
                bad(
                    "bgp_mrt_record_ref",
                    candidate.record_index,
                    "BGP4MP candidate record is outside the source",
                )
            })?;
        let MrtBody::Bgp4mp(message) = &record.body else {
            return Err(bad(
                "bgp_mrt_record_ref",
                candidate.record_index,
                "candidate record is not BGP4MP",
            ));
        };
        if !matches!(&message.payload, Bgp4mpPayload::Message(_)) {
            return Err(bad(
                "bgp_mrt_record_ref",
                candidate.record_index,
                "candidate record has no BGP message",
            ));
        }
        let range = self
            .batch
            .bgp4mp_message_source_range(candidate.record_index)?
            .ok_or_else(|| {
                bad(
                    "bgp_mrt_record_ref",
                    candidate.record_index,
                    "message range absent",
                )
            })?;
        let expected_record_id = format!(
            "mrt-bgp4mp:{}:{}:{}:{}",
            record.offset,
            record.subtype,
            candidate.record_index,
            range.sha256.as_deref().unwrap_or(&record.sha256),
        );
        let source = observation.source();
        let context = observation.import_context().ok_or_else(|| {
            bad(
                "bgp_mrt_observation_ref",
                0,
                "BGP4MP import context is absent",
            )
        })?;
        let message_hash = range.sha256.as_deref().unwrap_or_default();
        if source.kind != SourceKind::Imported
            || candidate.observation_sha256 != observation.sha256()
            || candidate.source_id != source.source_id
            || candidate.source_id != self.batch.source.source_id
            || candidate.source_id != self.receipt.source_id
            || candidate.checkpoint_id != self.batch.source.checkpoint_id
            || candidate.checkpoint_id != self.receipt.checkpoint_id
            || candidate.record_id != source.record_id
            || candidate.record_id != expected_record_id
            || source.session.as_deref() != Some(candidate.session.as_str())
            || context.session != candidate.session
            || candidate.peer != source.peer
            || candidate.observed_at_ns != source.observed_at_ns
            || candidate.direction != u8::from(message.locally_generated)
            || source.direction != Some(candidate.direction)
            || context.direction != Some(candidate.direction)
            || context.generation != source.generation.unwrap_or(u64::MAX)
            || candidate.source_range_start != range.start
            || candidate.source_range_end != range.end
            || candidate.message_sha256 != message_hash
            || &candidate.prefix != route.prefix()
            || candidate.path_id != route.path_id()
            || candidate.action != route.action()
            || observation.import_boundary().is_some()
            || context.batch.sha256.as_deref() != Some(self.batch.sha256.as_str())
            || context.batch.byte_length != Some(self.batch.byte_length)
            || self.receipt.source_bytes != self.batch.byte_length
            || sha256::hex(&self.receipt.source_sha256) != self.batch.sha256
            || context.provenance.len() != 1
            || context.provenance[0].start != range.start
            || context.provenance[0].end != range.end
            || context.provenance[0].sha256.as_deref() != Some(message_hash)
        {
            return Err(bad(
                "bgp_mrt_candidate_binding",
                candidate.observation_index,
                "BGP4MP candidate identity, route, or source-range binding disagrees",
            ));
        }
        Ok(observation)
    }

    /// Return each distinct normalized envelope referenced by a candidate query
    /// once, preserving first-candidate order for deterministic output.
    pub fn observations_for_candidates(&self, candidates: &[&CollectorCandidate]) -> Result<Json> {
        let mut seen = HashSet::new();
        seen.try_reserve(candidates.len())
            .map_err(|_| Error::limit("bgp_mrt_observations"))?;
        let mut observations = Vec::new();
        observations
            .try_reserve(candidates.len())
            .map_err(|_| Error::limit("bgp_mrt_observations"))?;
        for candidate in candidates {
            // Validate even a duplicate index: deduplication must not hide a
            // conflicting digest/source/route supplied by a later candidate.
            let observation = self.candidate_observation(candidate)?;
            if seen.insert(candidate.observation_index) {
                observations.push(Json::object([
                    (
                        "observation_index",
                        candidate.observation_index.to_string().into(),
                    ),
                    ("normalized_observation", observation.normalized().clone()),
                ]));
            }
        }
        Ok(Json::array(observations))
    }

    pub fn record_summaries(&self) -> impl Iterator<Item = Json> + '_ {
        self.batch.records.iter().map(record_json)
    }
}

/// Write one immutable, sealed MRT source store. The MRT is fully parsed and
/// normalized before the destination is created, so semantic rejection leaves
/// no artifact. I/O failure may leave the caller-owned partial path in place.
pub fn create(
    path: &Path,
    input: &[u8],
    source: MrtSource,
    maximum: u64,
    mrt_limits: MrtLimits,
    limits: Limits,
) -> Result<MrtReplayArchive> {
    create_with_options(
        path,
        input,
        source,
        maximum,
        mrt_limits,
        limits,
        MrtReplayOptions::default(),
    )
}

/// Import and replay with an explicit optional peer relationship context.
pub fn create_with_options(
    path: &Path,
    input: &[u8],
    source: MrtSource,
    maximum: u64,
    mrt_limits: MrtLimits,
    limits: Limits,
    options: MrtReplayOptions,
) -> Result<MrtReplayArchive> {
    limits.validate()?;
    mrt_limits.validate()?;
    check_text(&source.source_id, &limits, "bgp_mrt_source")?;
    check_text(&source.checkpoint_id, &limits, "bgp_mrt_checkpoint")?;
    let total_size = io_support::encoded_size(
        input.len(),
        source.source_id.len(),
        source.checkpoint_id.len(),
    )?;
    if as_u64(total_size, "bgp_mrt_store_bytes")? > maximum {
        return Err(Error::limit("bgp_mrt_store_disk"));
    }
    let batch = MrtBatch::parse(input, source.clone(), &mrt_limits)?;
    let source_sha256 = sha256::digest(input);
    // Retain only the small header here. The caller already owns the source;
    // hashing and writing its borrowed bytes preserves the exact v1 seal.
    let header_size = total_size
        .checked_sub(input.len())
        .and_then(|size| size.checked_sub(DIGEST_BYTES))
        .ok_or_else(|| Error::limit("bgp_mrt_store_bytes"))?;
    let mut header = Vec::new();
    header
        .try_reserve_exact(header_size)
        .map_err(|_| Error::limit("bgp_mrt_store_bytes"))?;
    header.extend_from_slice(MAGIC);
    header.extend_from_slice(&VERSION.to_le_bytes());
    put_text(&mut header, &source.source_id)?;
    put_text(&mut header, &source.checkpoint_id)?;
    header.extend_from_slice(&as_u64(input.len(), "bgp_mrt_source_bytes")?.to_le_bytes());
    header.extend_from_slice(&source_sha256);
    let mut digest = sha256::Sha256::new();
    digest.update(SEAL_DOMAIN);
    digest.update(&header);
    digest.update(input);
    let terminal = digest.finalize();
    let archive = build_archive(batch, terminal, input, limits, options)?;
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(&header)?;
    file.write_all(input)?;
    file.write_all(&terminal)?;
    file.sync_all()?;
    Ok(archive)
}

/// Verify and replay a sealed MRT source store without trusting saved state.
pub fn replay(
    path: &Path,
    maximum: u64,
    mrt_limits: MrtLimits,
    limits: Limits,
) -> Result<MrtReplayArchive> {
    replay_with_options(
        path,
        maximum,
        mrt_limits,
        limits,
        MrtReplayOptions::default(),
    )
}

/// Verify and replay a sealed source store with an explicit optional peer
/// relationship context. The analysis option is not written into the evidence
/// container and must be supplied again to reproduce the same BGP4MP result.
pub fn replay_with_options(
    path: &Path,
    maximum: u64,
    mrt_limits: MrtLimits,
    limits: Limits,
    options: MrtReplayOptions,
) -> Result<MrtReplayArchive> {
    limits.validate()?;
    mrt_limits.validate()?;
    let mut file = File::open(path)?;
    let metadata = file.metadata()?;
    // The source cap is much tighter than a caller's generic journal/disk cap.
    // Reject an impossible envelope BEFORE reserving or reading its large body.
    let maximum_envelope = io_support::encoded_size(
        mrt_limits.input_bytes,
        limits.input_bytes.min(4096),
        limits.input_bytes.min(4096),
    )?;
    if !metadata.is_file()
        || metadata.len() > maximum
        || metadata.len() > as_u64(maximum_envelope, "bgp_mrt_store_disk")?
    {
        return Err(Error::limit("bgp_mrt_store_disk"));
    }
    let minimum = FIXED_HEADER + 4 + 1 + 4 + 1 + 8 + DIGEST_BYTES + 1 + DIGEST_BYTES;
    if metadata.len() < as_u64(minimum, "bgp_mrt_store_bytes")? {
        return Err(Error::new(
            ErrorCode::Truncated,
            0,
            "bgp_mrt_store",
            "MRT source store is truncated",
        ));
    }
    let size = usize::try_from(metadata.len()).map_err(|_| Error::limit("bgp_mrt_store_disk"))?;
    let bytes = io_support::read_snapshot(&mut file, size)?;
    let seal_offset = bytes
        .len()
        .checked_sub(DIGEST_BYTES)
        .ok_or_else(|| Error::limit("bgp_mrt_store"))?;
    let mut terminal = [0u8; 32];
    terminal.copy_from_slice(&bytes[seal_offset..]);
    if seal(&bytes[..seal_offset]) != terminal {
        return Err(Error::new(
            ErrorCode::SourceMismatch,
            seal_offset as u64,
            "bgp_mrt_store_seal",
            "terminal digest does not match source store",
        ));
    }
    let (source_id, checkpoint_id, source_bytes, expected) = {
        let mut decoder = Decoder::new(&bytes[..seal_offset], &limits);
        if decoder.take(8, "bgp_mrt_store_magic")? != MAGIC {
            return Err(Error::new(
                ErrorCode::BadMagic,
                0,
                "bgp_mrt_store_magic",
                "not a BGP MRT source store",
            ));
        }
        if decoder.u16()? != VERSION {
            return Err(Error::new(
                ErrorCode::UnsupportedVersion,
                8,
                "bgp_mrt_store_version",
                "unsupported BGP MRT source-store version",
            ));
        }
        let source_id = decoder.text("bgp_mrt_source")?;
        let checkpoint_id = decoder.text("bgp_mrt_checkpoint")?;
        let source_len =
            usize::try_from(decoder.u64()?).map_err(|_| Error::limit("bgp_mrt_source_bytes"))?;
        if source_len == 0 || source_len > mrt_limits.input_bytes {
            return Err(Error::limit("bgp_mrt_source_bytes"));
        }
        let mut expected = [0u8; 32];
        expected.copy_from_slice(decoder.take(DIGEST_BYTES, "bgp_mrt_source_sha256")?);
        let source_bytes = decoder.take(source_len, "bgp_mrt_source_bytes")?;
        decoder.finish()?;
        (source_id, checkpoint_id, source_bytes, expected)
    };
    let actual = sha256::digest(source_bytes);
    if expected != actual {
        return Err(Error::new(
            ErrorCode::SourceMismatch,
            0,
            "bgp_mrt_source_sha256",
            "stored MRT source hash does not match bytes",
        ));
    }
    let batch = MrtBatch::parse(
        source_bytes,
        MrtSource {
            source_id,
            checkpoint_id,
        },
        &mrt_limits,
    )?;
    build_archive(batch, terminal, source_bytes, limits, options)
}

fn build_archive(
    batch: MrtBatch,
    terminal: [u8; 32],
    source_bytes: &[u8],
    limits: Limits,
    options: MrtReplayOptions,
) -> Result<MrtReplayArchive> {
    if u64::try_from(source_bytes.len()).ok() != Some(batch.byte_length) {
        return Err(Error::limit("bgp_mrt_source_bytes"));
    }
    let mut state = CandidateState::new(limits.clone())?;
    let mut candidates = Vec::new();
    let mut bgp4mp_candidates = Vec::new();
    let mut bgp4mp_events = Vec::new();
    let mut bgp4mp_event_bytes = 0usize;
    let mut imported_sessions =
        bgp::mrt::ReplayState::with_peer_relationship(options.peer_relationship);
    let mut observations = Vec::new();
    let mut observations_work = 0usize;
    let mut bgp4mp_contexts: BTreeMap<(String, ImportPartition), ImportContext> = BTreeMap::new();
    let mut opaque_records = 0u64;
    let mut unsupported_rib_entries = 0u64;
    let mut bgp4mp_messages = 0u64;
    let mut bgp4mp_state_changes = 0u64;
    for (record_index, record) in batch.records.iter().enumerate() {
        match &record.body {
            MrtBody::Rib(rib) => {
                for entry_index in 0..rib.entries.len() {
                    let Some(normalized) =
                        batch.normalize_rib_entry(record_index, entry_index, &limits)?
                    else {
                        unsupported_rib_entries =
                            increment(unsupported_rib_entries, "bgp_mrt_unsupported_rib_entries")?;
                        if unsupported_rib_entries > limits.elements as u64 {
                            return Err(Error::limit("bgp_mrt_unsupported_rib_entries"));
                        }
                        continue;
                    };
                    let candidate_count_before = candidates.len();
                    let observation = Observation::from_normalized(&normalized, None, &limits)?;
                    observations_work = observations_work
                        .checked_add(observation.batch_work()?)
                        .ok_or_else(|| Error::limit("bgp_state_work"))?;
                    if observations_work > limits.work {
                        return Err(Error::limit("bgp_state_work"));
                    }
                    if observations.len() >= limits.elements {
                        return Err(Error::limit("bgp_mrt_observations"));
                    }
                    observations
                        .try_reserve(1)
                        .map_err(|_| Error::limit("bgp_mrt_observations"))?;
                    let observation_index = observations.len();
                    for (route_index, route) in observation.routes().iter().enumerate() {
                        if candidates.len() >= limits.elements {
                            return Err(Error::limit("bgp_mrt_collector_candidates"));
                        }
                        candidates
                            .try_reserve(1)
                            .map_err(|_| Error::limit("bgp_mrt_collector_candidates"))?;
                        let source = observation.source();
                        if source.kind != SourceKind::Imported {
                            return Err(bad(
                                "bgp_mrt_source_kind",
                                0,
                                "MRT normalization produced non-imported evidence",
                            ));
                        }
                        candidates.push(CollectorCandidate {
                            record_index,
                            entry_index,
                            observation_sha256: observation.sha256(),
                            source_id: source.source_id.clone(),
                            checkpoint_id: batch.source.checkpoint_id.clone(),
                            record_id: source.record_id.clone(),
                            session: source.session.clone().ok_or_else(|| {
                                bad("bgp_mrt_session", 0, "normalized MRT session is absent")
                            })?,
                            peer: source.peer.clone(),
                            observed_at_ns: source.observed_at_ns,
                            prefix: route.prefix().clone(),
                            path_id: route.path_id(),
                            action: route.action(),
                            ambiguous_attributes: route.ambiguous_attributes(),
                            observation_index,
                            route_index,
                        });
                    }
                    if candidates.len() == candidate_count_before {
                        return Err(bad(
                            "bgp_mrt_collector_candidate",
                            entry_index,
                            "normalized RIB entry produced no route candidate",
                        ));
                    }
                    observations.push(observation);
                }
            }
            MrtBody::Bgp4mp(message) => match &message.payload {
                Bgp4mpPayload::Message(embedded) => {
                    bgp4mp_messages = increment(bgp4mp_messages, "bgp_mrt_bgp4mp_messages")?;
                    let range = batch
                        .bgp4mp_message_source_range(record_index)?
                        .ok_or_else(|| {
                            bad("bgp_mrt_message_range", record_index, "range absent")
                        })?;
                    let start = usize::try_from(range.start)
                        .map_err(|_| Error::limit("bgp_mrt_message_range"))?;
                    let end = usize::try_from(range.end)
                        .map_err(|_| Error::limit("bgp_mrt_message_range"))?;
                    let original = source_bytes.get(start..end).ok_or_else(|| {
                        bad(
                            "bgp_mrt_message_source",
                            start,
                            "message range outside source",
                        )
                    })?;
                    let source_message_sha256 = sha256::hex(&sha256::digest(original));
                    if original != embedded.as_slice()
                        || range.sha256.as_deref() != Some(source_message_sha256.as_str())
                    {
                        return Err(bad(
                            "bgp_mrt_message_source",
                            start,
                            "embedded message differs from original source range",
                        ));
                    }
                    let replay = bgp::mrt::replay_message_record(
                        &batch,
                        record_index,
                        record,
                        super::bgp_import::SourceRange {
                            start: range.start,
                            end: range.end,
                            sha256: range.sha256.clone(),
                        },
                        &limits,
                        &mut imported_sessions,
                    )?;
                    append_bgp4mp_generation_boundaries(Bgp4mpGenerationBoundaryInput {
                        observations: &mut observations,
                        observations_work: &mut observations_work,
                        contexts: &mut bgp4mp_contexts,
                        batch: &batch,
                        record_index,
                        record,
                        event: &replay.event,
                        limits: &limits,
                    })?;
                    retain_bgp4mp_event(
                        &mut bgp4mp_events,
                        &mut bgp4mp_event_bytes,
                        replay.event,
                        &limits,
                    )?;
                    if let Some(normalized) = replay.observation {
                        let observation = Observation::from_normalized(&normalized, None, &limits)?;
                        if !observation.routes().is_empty() {
                            observations_work = observations_work
                                .checked_add(observation.batch_work()?)
                                .ok_or_else(|| Error::limit("bgp_state_work"))?;
                            if observations_work > limits.work {
                                return Err(Error::limit("bgp_state_work"));
                            }
                            if observations.len() >= limits.elements {
                                return Err(Error::limit("bgp_mrt_observations"));
                            }
                            observations
                                .try_reserve(1)
                                .map_err(|_| Error::limit("bgp_mrt_observations"))?;
                            let observation_index = observations.len();
                            let source = observation.source();
                            for (route_index, route) in observation.routes().iter().enumerate() {
                                if bgp4mp_candidates.len() >= limits.elements {
                                    return Err(Error::limit("bgp_mrt_bgp4mp_candidates"));
                                }
                                bgp4mp_candidates
                                    .try_reserve(1)
                                    .map_err(|_| Error::limit("bgp_mrt_bgp4mp_candidates"))?;
                                bgp4mp_candidates.push(Bgp4mpCandidate {
                                    record_index,
                                    observation_sha256: observation.sha256(),
                                    source_id: source.source_id.clone(),
                                    checkpoint_id: batch.source.checkpoint_id.clone(),
                                    record_id: source.record_id.clone(),
                                    session: source.session.clone().ok_or_else(|| {
                                        bad("bgp_mrt_session", record_index, "session absent")
                                    })?,
                                    peer: source.peer.clone(),
                                    observed_at_ns: source.observed_at_ns,
                                    direction: source.direction.ok_or_else(|| {
                                        bad("bgp_mrt_direction", record_index, "direction absent")
                                    })?,
                                    source_range_start: range.start,
                                    source_range_end: range.end,
                                    message_sha256: range.sha256.clone().ok_or_else(|| {
                                        bad(
                                            "bgp_mrt_message_hash",
                                            record_index,
                                            "message digest absent",
                                        )
                                    })?,
                                    prefix: route.prefix().clone(),
                                    path_id: route.path_id(),
                                    action: route.action(),
                                    observation_index,
                                    route_index,
                                });
                            }
                            let context =
                                observation.import_context().cloned().ok_or_else(|| {
                                    bad(
                                        "bgp_mrt_import_context",
                                        record_index,
                                        "BGP4MP route observation has no import context",
                                    )
                                })?;
                            let context_key = (context.session.clone(), context.partition());
                            if !bgp4mp_contexts.contains_key(&context_key)
                                && bgp4mp_contexts.len() >= limits.elements
                            {
                                return Err(Error::limit("bgp_mrt_generation_contexts"));
                            }
                            bgp4mp_contexts.insert(context_key, context);
                            observations.push(observation);
                        }
                    }
                }
                Bgp4mpPayload::State { .. } => {
                    bgp4mp_state_changes =
                        increment(bgp4mp_state_changes, "bgp_mrt_bgp4mp_states")?;
                    let event = bgp::mrt::replay_state_record(
                        &batch,
                        record_index,
                        record,
                        &limits,
                        &mut imported_sessions,
                    )?;
                    append_bgp4mp_generation_boundaries(Bgp4mpGenerationBoundaryInput {
                        observations: &mut observations,
                        observations_work: &mut observations_work,
                        contexts: &mut bgp4mp_contexts,
                        batch: &batch,
                        record_index,
                        record,
                        event: &event,
                        limits: &limits,
                    })?;
                    retain_bgp4mp_event(
                        &mut bgp4mp_events,
                        &mut bgp4mp_event_bytes,
                        event,
                        &limits,
                    )?;
                }
            },
            MrtBody::Opaque { .. } => {
                opaque_records = increment(opaque_records, "bgp_mrt_opaque_records")?;
            }
            MrtBody::PeerIndex(_) => {}
        }
    }
    let outcomes = state.apply_batch(observations)?;
    for candidate in &mut candidates {
        let outcome = outcomes.get(candidate.observation_index).ok_or_else(|| {
            bad(
                "bgp_mrt_observation_ref",
                candidate.observation_index,
                "missing batch receipt",
            )
        })?;
        candidate.observation_index = outcome.observation;
        let routes = state
            .observations()
            .get(candidate.observation_index)
            .ok_or_else(|| {
                bad(
                    "bgp_mrt_observation_ref",
                    candidate.observation_index,
                    "missing retained observation",
                )
            })?
            .routes();
        if candidate.route_index >= routes.len() {
            return Err(bad(
                "bgp_mrt_route_ref",
                candidate.route_index,
                "candidate route reference is outside the observation",
            ));
        }
    }
    for candidate in &mut bgp4mp_candidates {
        let outcome = outcomes.get(candidate.observation_index).ok_or_else(|| {
            bad(
                "bgp_mrt_observation_ref",
                candidate.observation_index,
                "missing BGP4MP batch receipt",
            )
        })?;
        candidate.observation_index = outcome.observation;
        let observation = state
            .observations()
            .get(candidate.observation_index)
            .ok_or_else(|| {
                bad(
                    "bgp_mrt_observation_ref",
                    candidate.observation_index,
                    "missing retained BGP4MP observation",
                )
            })?;
        let route = observation
            .routes()
            .get(candidate.route_index)
            .ok_or_else(|| {
                bad(
                    "bgp_mrt_route_ref",
                    candidate.route_index,
                    "BGP4MP candidate route is outside observation",
                )
            })?;
        if route.prefix() != &candidate.prefix
            || route.path_id() != candidate.path_id
            || route.action() != candidate.action
        {
            return Err(bad(
                "bgp_mrt_candidate_route",
                candidate.route_index,
                "BGP4MP route changed during state reduction",
            ));
        }
    }
    let records = as_u64(batch.records.len(), "bgp_mrt_records")?;
    let mut source_sha256 = [0u8; 32];
    let decoded = decode_hex_32(&batch.sha256)?;
    source_sha256.copy_from_slice(&decoded);
    let receipt = MrtStoreReceipt {
        source_id: batch.source.source_id.clone(),
        checkpoint_id: batch.source.checkpoint_id.clone(),
        source_sha256,
        source_bytes: batch.byte_length,
        terminal_sha256: terminal,
        records,
    };
    let mut archive = MrtReplayArchive {
        receipt,
        batch,
        state,
        peer_relationship: options.peer_relationship,
        candidates,
        bgp4mp_candidates,
        bgp4mp_events,
        opaque_records,
        unsupported_rib_entries,
        unsupported_rib_entry_evidence: Vec::new(),
        bgp4mp_messages,
        bgp4mp_state_changes,
    };
    // Logical retained-byte accounting, not allocator capacity or process RSS.
    // Keep the parsed batch, shared state, and compact projection inside one cap.
    let mut retained = archive
        .state
        .retained_bytes()
        .checked_add(archive.batch.retained_bytes)
        .ok_or_else(|| Error::limit("bgp_mrt_retained"))?;
    for candidate in &archive.candidates {
        retained = retained
            .checked_add(
                candidate
                    .json()
                    .encoded_len_bounded(limits.retained_bytes)?,
            )
            .ok_or_else(|| Error::limit("bgp_mrt_retained"))?;
        if retained > limits.retained_bytes {
            return Err(Error::limit("bgp_mrt_retained"));
        }
    }
    for candidate in &archive.bgp4mp_candidates {
        retained = retained
            .checked_add(
                candidate
                    .json()
                    .encoded_len_bounded(limits.retained_bytes)?,
            )
            .ok_or_else(|| Error::limit("bgp_mrt_retained"))?;
        if retained > limits.retained_bytes {
            return Err(Error::limit("bgp_mrt_retained"));
        }
    }
    retained = retained
        .checked_add(bgp4mp_event_bytes)
        .ok_or_else(|| Error::limit("bgp_mrt_retained"))?;
    if retained > limits.retained_bytes {
        return Err(Error::limit("bgp_mrt_retained"));
    }
    let base_output_bytes = archive.encoded_len_bounded(limits.output_bytes)?;
    let unsupported_count = usize::try_from(unsupported_rib_entries)
        .map_err(|_| Error::limit("bgp_mrt_unsupported_rib_entries"))?;
    let plan = preflight_unsupported_rib_evidence(
        &archive.batch,
        &archive.candidates,
        unsupported_count,
        limits.output_bytes - base_output_bytes,
        limits.retained_bytes - retained,
        limits
            .work
            .checked_sub(observations_work)
            .ok_or_else(|| Error::limit("bgp_state_work"))?,
    )?;
    if observations_work
        .checked_add(plan.work_units)
        .filter(|work| *work <= limits.work)
        .is_none()
    {
        return Err(Error::limit("bgp_state_work"));
    }
    let planned_output_bytes = base_output_bytes
        .checked_add(plan.output_growth)
        .ok_or_else(|| Error::limit("bgp_mrt_output"))?;
    if planned_output_bytes > limits.output_bytes {
        return Err(Error::limit("report_bytes"));
    }
    archive.unsupported_rib_entry_evidence = materialize_unsupported_rib_evidence(
        &archive.batch,
        &archive.candidates,
        plan.count,
        plan.rib_entry_count,
    )?;
    retained = retained
        .checked_add(plan.retained_bytes)
        .ok_or_else(|| Error::limit("bgp_mrt_retained"))?;
    if retained > limits.retained_bytes {
        return Err(Error::limit("bgp_mrt_retained"));
    }
    Ok(archive)
}

#[derive(Debug)]
struct UnsupportedRibEvidencePlan {
    count: usize,
    rib_entry_count: usize,
    output_growth: usize,
    retained_bytes: usize,
    work_units: usize,
}

fn unsupported_rib_evidence_json(
    record_index: usize,
    entry_index: usize,
    record: &MrtRecord,
    rib: &Rib,
    attribute_bytes: usize,
    attribute_sha256: &str,
) -> Json {
    let address = match (rib.prefix.afi, rib.prefix.address.as_slice()) {
        (1, [a, b, c, d]) => Ipv4Addr::new(*a, *b, *c, *d).to_string(),
        (2, octets) if octets.len() == 16 => {
            let mut bytes = [0; 16];
            bytes.copy_from_slice(octets);
            Ipv6Addr::from(bytes).to_string()
        }
        _ => {
            let mut address = String::new();
            for byte in &rib.prefix.address {
                let _ = write!(&mut address, "{byte:02x}");
            }
            address
        }
    };
    Json::object([
        (
            "semantic_identity_status",
            Json::object([
                ("schema", bgp::SEMANTIC_IDENTITY_SCHEMA.into()),
                ("completeness", "opaque_only".into()),
                ("fingerprint_sha256", Json::Null),
                ("reason", "path_attribute_semantics_not_normalized".into()),
                ("candidate_admitted", false.into()),
            ]),
        ),
        (
            "route_key",
            Json::object([
                ("afi", rib.afi.into()),
                ("safi", rib.safi.into()),
                ("length", rib.prefix.length.into()),
                ("address", address.into()),
            ]),
        ),
        (
            "source_record",
            Json::object([
                ("record_index", record_index.into()),
                ("record_offset", record.offset.to_string().into()),
                ("record_sha256", record.sha256.clone().into()),
                ("entry_index", entry_index.into()),
            ]),
        ),
        (
            "attribute_block",
            Json::object([
                ("byte_length", attribute_bytes.into()),
                ("block_sha256", attribute_sha256.into()),
            ]),
        ),
    ])
}

fn preflight_unsupported_rib_evidence(
    batch: &MrtBatch,
    candidates: &[CollectorCandidate],
    expected_count: usize,
    output_remaining: usize,
    retained_remaining: usize,
    work_remaining: usize,
) -> Result<UnsupportedRibEvidencePlan> {
    const ZERO_SHA256: &str = "0000000000000000000000000000000000000000000000000000000000000000";
    let mut count = 0usize;
    let mut output_growth = 0usize;
    let mut row_work = 0usize;
    let rib_entry_count = visit_unsupported_rib_entries(
        batch,
        candidates,
        |record_index, entry_index, record, rib, entry| {
            count = count
                .checked_add(1)
                .ok_or_else(|| Error::limit("bgp_mrt_unsupported_rib_entries"))?;
            if count > expected_count {
                return Err(bad(
                    "bgp_mrt_unsupported_rib_entry",
                    entry_index,
                    "unsupported RIB count changed after replay construction",
                ));
            }
            let projection = unsupported_rib_evidence_json(
                record_index,
                entry_index,
                record,
                rib,
                entry.attributes.len(),
                ZERO_SHA256,
            );
            let available = output_remaining
                .checked_sub(output_growth)
                .ok_or_else(|| Error::limit("report_bytes"))?;
            let encoded_bytes = projection.encoded_len_bounded(available)?;
            output_growth = output_growth
                .checked_add(encoded_bytes)
                .and_then(|size| size.checked_add(usize::from(count > 1)))
                .ok_or_else(|| Error::limit("bgp_mrt_output"))?;
            let retained_bytes = output_growth
                .checked_add(2)
                .ok_or_else(|| Error::limit("bgp_mrt_retained"))?;
            let row_units = encoded_bytes
                .checked_mul(2)
                .and_then(|size| size.checked_add(entry.attributes.len()))
                .ok_or_else(|| Error::limit("bgp_state_work"))?;
            row_work = row_work
                .checked_add(row_units)
                .ok_or_else(|| Error::limit("bgp_state_work"))?;
            if output_growth > output_remaining {
                return Err(Error::limit("report_bytes"));
            }
            if retained_bytes > retained_remaining {
                return Err(Error::limit("bgp_mrt_retained"));
            }
            Ok(())
        },
    )?;
    if count != expected_count {
        return Err(bad(
            "bgp_mrt_unsupported_rib_entry",
            count,
            "unsupported RIB count changed after replay construction",
        ));
    }
    let retained_bytes = if count == 0 {
        0
    } else {
        output_growth
            .checked_add(2)
            .ok_or_else(|| Error::limit("bgp_mrt_retained"))?
    };
    let work_units = rib_entry_count
        .checked_mul(2)
        .and_then(|size| size.checked_add(row_work))
        .ok_or_else(|| Error::limit("bgp_state_work"))?;
    if work_units > work_remaining {
        return Err(Error::limit("bgp_state_work"));
    }
    if retained_bytes > retained_remaining {
        return Err(Error::limit("bgp_mrt_retained"));
    }
    Ok(UnsupportedRibEvidencePlan {
        count,
        rib_entry_count,
        output_growth,
        retained_bytes,
        work_units,
    })
}

fn materialize_unsupported_rib_evidence(
    batch: &MrtBatch,
    candidates: &[CollectorCandidate],
    expected_count: usize,
    expected_rib_entry_count: usize,
) -> Result<Vec<Json>> {
    let mut evidence = Vec::new();
    evidence
        .try_reserve_exact(expected_count)
        .map_err(|_| Error::limit("bgp_mrt_unsupported_rib_entries"))?;
    let rib_entry_count = visit_unsupported_rib_entries(
        batch,
        candidates,
        |record_index, entry_index, record, rib, entry| {
            if evidence.len() >= expected_count {
                return Err(bad(
                    "bgp_mrt_unsupported_rib_entry",
                    entry_index,
                    "unsupported RIB count grew after successful preflight",
                ));
            }
            let digest = sha256::hex(&sha256::digest(&entry.attributes));
            let evidence_row = unsupported_rib_evidence_json(
                record_index,
                entry_index,
                record,
                rib,
                entry.attributes.len(),
                &digest,
            );
            evidence.push(evidence_row);
            Ok(())
        },
    )?;
    if evidence.len() != expected_count || rib_entry_count != expected_rib_entry_count {
        return Err(bad(
            "bgp_mrt_unsupported_rib_entry",
            evidence.len(),
            "source traversal changed after successful preflight",
        ));
    }
    Ok(evidence)
}

/// Visit unsupported RIB entries without retaining an input-sized coordinate
/// list. Normalized candidates are emitted in source order; this zipper also
/// rejects candidate/source inconsistencies instead of silently misclassifying.
fn visit_unsupported_rib_entries<F>(
    batch: &MrtBatch,
    candidates: &[CollectorCandidate],
    mut visit: F,
) -> Result<usize>
where
    F: FnMut(usize, usize, &MrtRecord, &Rib, &super::bgp_mrt::RibEntry) -> Result<()>,
{
    let mut candidate_index = 0usize;
    let mut rib_entry_count = 0usize;
    for (record_index, record) in batch.records.iter().enumerate() {
        let MrtBody::Rib(rib) = &record.body else {
            continue;
        };
        for (entry_index, entry) in rib.entries.iter().enumerate() {
            rib_entry_count = rib_entry_count
                .checked_add(1)
                .ok_or_else(|| Error::limit("bgp_mrt_rib_entries"))?;
            let coordinate = (record_index, entry_index);
            let mut supported = false;
            while let Some(candidate) = candidates.get(candidate_index) {
                let candidate_coordinate = (candidate.record_index, candidate.entry_index);
                if candidate_coordinate < coordinate {
                    return Err(bad(
                        "bgp_mrt_collector_candidate",
                        candidate_index,
                        "candidate source order is inconsistent with MRT RIB entries",
                    ));
                }
                if candidate_coordinate != coordinate {
                    break;
                }
                supported = true;
                candidate_index = candidate_index
                    .checked_add(1)
                    .ok_or_else(|| Error::limit("bgp_mrt_collector_candidate"))?;
            }
            if !supported {
                visit(record_index, entry_index, record, rib, entry)?;
            }
        }
    }
    if candidate_index != candidates.len() {
        return Err(bad(
            "bgp_mrt_collector_candidate",
            candidate_index,
            "candidate points outside the parsed RIB entries",
        ));
    }
    Ok(rib_entry_count)
}

/// Turn producer-reported BGP4MP decoder-generation advances into explicit
/// imported-session boundaries before any successor UPDATE observation is
/// reduced. Boundaries are emitted only for partitions already represented by
/// route candidates; they never synthesize route withdrawals.
struct Bgp4mpGenerationBoundaryInput<'a> {
    observations: &'a mut Vec<Observation>,
    observations_work: &'a mut usize,
    contexts: &'a mut BTreeMap<(String, ImportPartition), ImportContext>,
    batch: &'a MrtBatch,
    record_index: usize,
    record: &'a super::bgp_mrt::MrtRecord,
    event: &'a Json,
    limits: &'a Limits,
}

fn append_bgp4mp_generation_boundaries(input: Bgp4mpGenerationBoundaryInput<'_>) -> Result<()> {
    let Bgp4mpGenerationBoundaryInput {
        observations,
        observations_work,
        contexts,
        batch,
        record_index,
        record,
        event,
        limits,
    } = input;
    let Some((generation, reason)) = bgp4mp_reset_generation(event, record_index)? else {
        return Ok(());
    };
    let session = event_text(event, "session").ok_or_else(|| {
        bad(
            "bgp_mrt_generation_boundary",
            record_index,
            "reset event has no session identity",
        )
    })?;
    if event_text(event, "source_id") != Some(batch.source.source_id.as_str())
        || event_text(event, "checkpoint_id") != Some(batch.source.checkpoint_id.as_str())
    {
        return Err(bad(
            "bgp_mrt_generation_boundary",
            record_index,
            "reset event does not belong to this exact source checkpoint",
        ));
    }
    let mut keys = Vec::new();
    keys.try_reserve(contexts.len())
        .map_err(|_| Error::limit("bgp_mrt_generation_contexts"))?;
    keys.extend(
        contexts
            .keys()
            .filter(|(known_session, partition)| {
                known_session == session && partition.checkpoint_id == batch.source.checkpoint_id
            })
            .cloned(),
    );

    for key in keys {
        let previous = contexts.get(&key).cloned().ok_or_else(|| {
            bad(
                "bgp_mrt_generation_boundary",
                record_index,
                "tracked import partition disappeared",
            )
        })?;
        if generation == previous.generation {
            continue;
        }
        if previous.generation.checked_add(1) != Some(generation) {
            return Err(bad(
                "bgp_mrt_generation_boundary",
                record_index,
                "source reset does not advance the tracked generation exactly once",
            ));
        }

        let end = record
            .offset
            .checked_add(12)
            .and_then(|offset| offset.checked_add(u64::from(record.length)))
            .filter(|end| *end <= batch.byte_length)
            .ok_or_else(|| Error::limit("bgp_mrt_generation_boundary_range"))?;
        let mut context = previous;
        let previous_generation = context.generation;
        context.generation = generation;
        context.direction = None;
        context.provenance = vec![SourceRange {
            start: record.offset,
            end,
            sha256: Some(record.sha256.clone()),
        }];
        let boundary = GenerationBoundary {
            previous_generation,
            reason: reason.to_owned(),
        };
        let record_id = format!(
            "mrt-bgp4mp-reset:{}:{}:{}:{}",
            record.offset, record.subtype, record_index, record.sha256
        );
        let normalized = bgp_import::normalize_boundary(
            context.clone(),
            boundary,
            record_id,
            record_time_ns(record),
            limits,
        )?;
        let observation = Observation::from_normalized(&normalized, None, limits)?;
        *observations_work = observations_work
            .checked_add(observation.batch_work()?)
            .ok_or_else(|| Error::limit("bgp_state_work"))?;
        if *observations_work > limits.work {
            return Err(Error::limit("bgp_state_work"));
        }
        if observations.len() >= limits.elements {
            return Err(Error::limit("bgp_mrt_observations"));
        }
        observations
            .try_reserve(1)
            .map_err(|_| Error::limit("bgp_mrt_observations"))?;
        observations.push(observation);
        contexts.insert(key, context);
    }
    Ok(())
}

fn bgp4mp_reset_generation(
    event: &Json,
    record_index: usize,
) -> Result<Option<(u64, &'static str)>> {
    let event_kind = event_text(event, "event_kind").ok_or_else(|| {
        bad(
            "bgp_mrt_generation_boundary",
            record_index,
            "event kind is absent",
        )
    })?;
    let parse_status = event_text(event, "parse_status").ok_or_else(|| {
        bad(
            "bgp_mrt_generation_boundary",
            record_index,
            "event status is absent",
        )
    })?;
    match (event_kind, parse_status) {
        ("state_change", _) => event_number(event, "generation")
            .map(|generation| Some((generation, "mrt_bgp4mp_state_generation_advance")))
            .ok_or_else(|| {
                bad(
                    "bgp_mrt_generation_boundary",
                    record_index,
                    "state event generation is absent",
                )
            }),
        ("message", "decoded_notification_reset") => {
            let detail = event_value(event, "detail").ok_or_else(|| {
                bad(
                    "bgp_mrt_generation_boundary",
                    record_index,
                    "NOTIFICATION reset detail is absent",
                )
            })?;
            event_number(detail, "next_generation")
                .map(|generation| Some((generation, "mrt_bgp4mp_notification_generation_advance")))
                .ok_or_else(|| {
                    bad(
                        "bgp_mrt_generation_boundary",
                        record_index,
                        "NOTIFICATION next generation is absent",
                    )
                })
        }
        ("message", "quarantined_session_reset") => event_number(event, "generation")
            .and_then(|generation| generation.checked_add(1))
            .map(|generation| Some((generation, "mrt_bgp4mp_malformed_update_generation_advance")))
            .ok_or_else(|| {
                bad(
                    "bgp_mrt_generation_boundary",
                    record_index,
                    "malformed UPDATE reset generation overflows or is absent",
                )
            }),
        _ => Ok(None),
    }
}

fn event_value<'a>(event: &'a Json, name: &str) -> Option<&'a Json> {
    match event {
        Json::Object(fields) => fields
            .iter()
            .find(|(key, _)| *key == name)
            .map(|(_, value)| value),
        _ => None,
    }
}

fn event_text<'a>(event: &'a Json, name: &str) -> Option<&'a str> {
    match event_value(event, name)? {
        Json::String(value) => Some(value),
        _ => None,
    }
}

fn event_number(event: &Json, name: &str) -> Option<u64> {
    match event_value(event, name)? {
        Json::Number(value) => Some(*value),
        _ => None,
    }
}

fn record_time_ns(record: &super::bgp_mrt::MrtRecord) -> Option<i64> {
    let seconds = i64::from(record.time.seconds).checked_mul(1_000_000_000)?;
    let microseconds = i64::from(record.time.microseconds.unwrap_or(0)).checked_mul(1_000)?;
    seconds.checked_add(microseconds)
}

fn record_json(record: &super::bgp_mrt::MrtRecord) -> Json {
    let body = match &record.body {
        MrtBody::PeerIndex(table) => Json::object([
            ("kind", "peer_index".into()),
            ("peers", table.peers.len().to_string().into()),
        ]),
        MrtBody::Rib(rib) => Json::object([
            ("kind", "rib".into()),
            ("sequence", rib.sequence.into()),
            ("prefix", mrt_prefix_json(&rib.prefix)),
            ("entries", rib.entries.len().to_string().into()),
            (
                "peer_table_offset",
                rib.peer_table_offset.to_string().into(),
            ),
        ]),
        MrtBody::Bgp4mp(message) => {
            let (payload, old, new) = match message.payload {
                Bgp4mpPayload::Message(_) => ("message", Json::Null, Json::Null),
                Bgp4mpPayload::State { old, new } => ("state_change", old.into(), new.into()),
            };
            Json::object([
                ("kind", "bgp4mp".into()),
                ("peer_asn", message.peer_asn.into()),
                ("local_asn", message.local_asn.into()),
                ("peer_address", message.peer_address.to_string().into()),
                ("local_address", message.local_address.to_string().into()),
                ("locally_generated", message.locally_generated.into()),
                ("add_path", message.add_path.into()),
                ("payload", payload.into()),
                ("old_state", old),
                ("new_state", new),
            ])
        }
        MrtBody::Opaque { reason, bytes } => Json::object([
            ("kind", "opaque".into()),
            ("reason", (*reason).into()),
            ("retained_bytes", bytes.len().to_string().into()),
        ]),
    };
    Json::object([
        ("schema", "pcap-evidence.bgp.mrt-record-summary.v1".into()),
        ("offset", record.offset.to_string().into()),
        ("length", record.length.into()),
        ("record_type", record.record_type.into()),
        ("subtype", record.subtype.into()),
        ("seconds", record.time.seconds.into()),
        (
            "microseconds",
            record.time.microseconds.map_or(Json::Null, Json::from),
        ),
        ("sha256", record.sha256.clone().into()),
        ("body", body),
    ])
}

fn mrt_prefix_json(prefix: &super::bgp::Prefix) -> Json {
    let address = match (prefix.afi, prefix.address.len()) {
        (1, 4) => Ipv4Addr::new(
            prefix.address[0],
            prefix.address[1],
            prefix.address[2],
            prefix.address[3],
        )
        .to_string(),
        (2, 16) => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&prefix.address);
            Ipv6Addr::from(octets).to_string()
        }
        _ => sha256::hex(&prefix.address),
    };
    Json::object([
        ("afi", prefix.afi.into()),
        ("safi", prefix.safi.into()),
        ("length", prefix.length.into()),
        ("address", address.into()),
    ])
}

fn prefix_json(prefix: &PrefixIdentity) -> Json {
    Json::object([
        ("afi", prefix.afi.into()),
        ("safi", prefix.safi.into()),
        ("length", prefix.length.into()),
        ("address", prefix.address.clone().into()),
    ])
}

fn action_name(action: RouteAction) -> &'static str {
    match action {
        RouteAction::Announce => "announce",
        RouteAction::Withdraw => "withdraw",
    }
}

fn seal(bytes: &[u8]) -> [u8; 32] {
    let mut digest = sha256::Sha256::new();
    digest.update(SEAL_DOMAIN);
    digest.update(bytes);
    digest.finalize()
}

fn put_text(output: &mut Vec<u8>, value: &str) -> Result<()> {
    let length = u32::try_from(value.len()).map_err(|_| Error::limit("bgp_mrt_text"))?;
    output.extend_from_slice(&length.to_le_bytes());
    output.extend_from_slice(value.as_bytes());
    Ok(())
}

fn check_text(value: &str, limits: &Limits, field: &'static str) -> Result<()> {
    if value.is_empty()
        || value.len() > limits.input_bytes.min(4096)
        || value.chars().any(char::is_control)
        || value.trim().is_empty()
    {
        return Err(bad(field, 0, "nonempty bounded source label required"));
    }
    Ok(())
}

fn increment(value: u64, field: &'static str) -> Result<u64> {
    value.checked_add(1).ok_or_else(|| Error::limit(field))
}

fn retain_bgp4mp_event(
    events: &mut Vec<Json>,
    total_bytes: &mut usize,
    event: Json,
    limits: &Limits,
) -> Result<()> {
    if events.len() >= limits.elements {
        return Err(Error::limit("bgp_mrt_events"));
    }
    let remaining = limits
        .retained_bytes
        .checked_sub(*total_bytes)
        .ok_or_else(|| Error::limit("bgp_mrt_retained"))?;
    let size = event.encoded_len_bounded(remaining.min(limits.output_bytes))?;
    *total_bytes = total_bytes
        .checked_add(size)
        .filter(|bytes| *bytes <= limits.retained_bytes)
        .ok_or_else(|| Error::limit("bgp_mrt_retained"))?;
    events
        .try_reserve(1)
        .map_err(|_| Error::limit("bgp_mrt_events"))?;
    events.push(event);
    Ok(())
}

fn as_u64(value: usize, field: &'static str) -> Result<u64> {
    u64::try_from(value).map_err(|_| Error::limit(field))
}

fn decode_hex_32(value: &str) -> Result<[u8; 32]> {
    if value.len() != 64 {
        return Err(bad("bgp_mrt_source_sha256", 0, "invalid digest length"));
    }
    let mut output = [0u8; 32];
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| bad("bgp_mrt_source_sha256", index * 2, "invalid digest"))?;
    }
    Ok(output)
}

struct Decoder<'bytes, 'limits> {
    bytes: &'bytes [u8],
    at: usize,
    limits: &'limits Limits,
}

impl<'bytes, 'limits> Decoder<'bytes, 'limits> {
    fn new(bytes: &'bytes [u8], limits: &'limits Limits) -> Self {
        Self {
            bytes,
            at: 0,
            limits,
        }
    }

    fn take(&mut self, length: usize, field: &'static str) -> Result<&'bytes [u8]> {
        let end = self
            .at
            .checked_add(length)
            .filter(|end| *end <= self.bytes.len())
            .ok_or_else(|| bad(field, self.at, "MRT source store is truncated"))?;
        let output = &self.bytes[self.at..end];
        self.at = end;
        Ok(output)
    }

    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(
            self.take(2, "bgp_mrt_integer")?
                .try_into()
                .expect("fixed slice"),
        ))
    }

    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(
            self.take(4, "bgp_mrt_integer")?
                .try_into()
                .expect("fixed slice"),
        ))
    }

    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(
            self.take(8, "bgp_mrt_integer")?
                .try_into()
                .expect("fixed slice"),
        ))
    }

    fn text(&mut self, field: &'static str) -> Result<String> {
        let length = usize::try_from(self.u32()?).expect("u32 fits usize");
        if length == 0 || length > self.limits.input_bytes.min(4096) {
            return Err(Error::limit(field));
        }
        let value = std::str::from_utf8(self.take(length, field)?)
            .map_err(|_| bad(field, self.at, "MRT source label is not UTF-8"))?
            .to_owned();
        check_text(&value, self.limits, field)?;
        Ok(value)
    }

    fn finish(&self) -> Result<()> {
        if self.at != self.bytes.len() {
            return Err(bad(
                "bgp_mrt_store",
                self.at,
                "trailing bytes before terminal digest",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn path(label: &str) -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "pcap-bgp-mrt-store-{label}-{}-{nonce}",
            std::process::id()
        ))
    }

    fn record(seconds: u32, kind: u16, subtype: u16, body: &[u8]) -> Vec<u8> {
        let mut value = Vec::new();
        value.extend_from_slice(&seconds.to_be_bytes());
        value.extend_from_slice(&kind.to_be_bytes());
        value.extend_from_slice(&subtype.to_be_bytes());
        value.extend_from_slice(&(body.len() as u32).to_be_bytes());
        value.extend_from_slice(body);
        value
    }

    fn source() -> MrtSource {
        MrtSource {
            source_id: "collector-a".into(),
            checkpoint_id: "dump-7".into(),
        }
    }

    #[test]
    fn unsupported_rib_evidence_preflight_enforces_exact_growth_and_work_caps() {
        let mut batch = MrtBatch::parse(&mrt(), source(), &MrtLimits::default()).unwrap();
        let (expected_count, attribute_len) = {
            let MrtBody::Rib(rib) = &mut batch.records[1].body else {
                panic!("fixture record 1 is a RIB")
            };
            let entry = rib.entries[0].clone();
            rib.entries.extend(std::iter::repeat_n(entry, 63));
            (rib.entries.len(), rib.entries[0].attributes.len())
        };
        let measured = preflight_unsupported_rib_evidence(
            &batch,
            &[],
            expected_count,
            usize::MAX,
            usize::MAX,
            usize::MAX,
        )
        .unwrap();
        assert_eq!(measured.count, expected_count);
        assert_eq!(measured.rib_entry_count, expected_count);
        assert!(
            measured.work_units > measured.output_growth + expected_count * attribute_len,
            "work accounting includes repeated sizing/materialization and source traversal"
        );
        assert!(
            preflight_unsupported_rib_evidence(
                &batch,
                &[],
                expected_count,
                measured.output_growth,
                measured.retained_bytes,
                measured.work_units,
            )
            .is_ok(),
            "each independently measured budget must accept an exact fit"
        );
        assert!(preflight_unsupported_rib_evidence(
            &batch,
            &[],
            expected_count,
            measured.output_growth - 1,
            measured.retained_bytes,
            measured.work_units,
        )
        .is_err());
        assert!(preflight_unsupported_rib_evidence(
            &batch,
            &[],
            expected_count,
            measured.output_growth,
            measured.retained_bytes - 1,
            measured.work_units,
        )
        .is_err());
        assert!(preflight_unsupported_rib_evidence(
            &batch,
            &[],
            expected_count,
            measured.output_growth,
            measured.retained_bytes,
            measured.work_units - 1,
        )
        .is_err());
    }

    fn mrt() -> Vec<u8> {
        let mut table = vec![
            192, 0, 2, 1, 0, 1, b'v', 0, 1, 2, 192, 0, 2, 2, 203, 0, 113, 9,
        ];
        table.extend_from_slice(&65551u32.to_be_bytes());
        let table = record(11, 13, 1, &table);
        let mut attributes = vec![0x40, 1, 1, 0, 0x40, 2, 6, 2, 1];
        attributes.extend_from_slice(&65551u32.to_be_bytes());
        attributes.extend_from_slice(&[0x40, 3, 4, 192, 0, 2, 9]);
        let mut rib = vec![0, 0, 0, 7, 24, 203, 0, 113, 0, 1, 0, 0];
        rib.extend_from_slice(&10u32.to_be_bytes());
        rib.extend_from_slice(&(attributes.len() as u16).to_be_bytes());
        rib.extend_from_slice(&attributes);
        let mut bgp4mp = Vec::new();
        bgp4mp.extend_from_slice(&65551u32.to_be_bytes());
        bgp4mp.extend_from_slice(&65552u32.to_be_bytes());
        bgp4mp.extend_from_slice(&2u16.to_be_bytes());
        bgp4mp.extend_from_slice(&1u16.to_be_bytes());
        bgp4mp.extend_from_slice(&[203, 0, 113, 9, 192, 0, 2, 1]);
        bgp4mp.extend_from_slice(&[0xff; 16]);
        bgp4mp.extend_from_slice(&19u16.to_be_bytes());
        bgp4mp.push(4);
        [table, record(12, 13, 2, &rib), record(21, 16, 4, &bgp4mp)].concat()
    }

    /// Independently assemble one peer-index table followed by many ordinary
    /// TABLE_DUMP_V2 IPv4-unicast RIB records. Every record has a distinct /32
    /// and source occurrence, so the scale test exercises admission rather than
    /// collapsing repeated observations.
    fn many_ribs(entries: usize) -> Vec<u8> {
        let mut table = vec![
            192, 0, 2, 1, 0, 1, b'v', 0, 1, 2, 192, 0, 2, 2, 203, 0, 113, 9,
        ];
        table.extend_from_slice(&65551u32.to_be_bytes());
        let mut bytes = record(11, 13, 1, &table);
        let mut attributes = vec![0x40, 1, 1, 0, 0x40, 2, 6, 2, 1];
        attributes.extend_from_slice(&65551u32.to_be_bytes());
        attributes.extend_from_slice(&[0x40, 3, 4, 192, 0, 2, 9]);
        for index in 0..entries {
            let sequence = u32::try_from(index).expect("test sequence fits MRT field");
            let address = 0x0a00_0000u32
                .checked_add(sequence)
                .expect("test prefix fits IPv4");
            let mut rib = Vec::new();
            rib.extend_from_slice(&sequence.to_be_bytes());
            rib.push(32);
            rib.extend_from_slice(&address.to_be_bytes());
            rib.extend_from_slice(&1u16.to_be_bytes());
            rib.extend_from_slice(&0u16.to_be_bytes());
            rib.extend_from_slice(&10u32.to_be_bytes());
            rib.extend_from_slice(
                &u16::try_from(attributes.len())
                    .expect("test attributes fit MRT field")
                    .to_be_bytes(),
            );
            rib.extend_from_slice(&attributes);
            bytes.extend_from_slice(&record(12, 13, 2, &rib));
        }
        bytes
    }

    /// Independently assemble many peer-index/RIB series so normalization must
    /// resolve peer tables throughout a large source-ordered record vector.
    fn many_peer_tables(entries: usize) -> Vec<u8> {
        let mut bytes = Vec::new();
        let mut attributes = vec![0x40, 1, 1, 0, 0x40, 2, 6, 2, 1];
        attributes.extend_from_slice(&65551u32.to_be_bytes());
        attributes.extend_from_slice(&[0x40, 3, 4, 192, 0, 2, 9]);
        for index in 0..entries {
            let sequence = u32::try_from(index).expect("test sequence fits MRT field");
            let mut table = vec![192, 0, 2, 1, 0, 1, b'v', 0, 1, 2, 192, 0, 2, 2];
            let peer_address = 0xcb00_7109u32
                .checked_add(sequence)
                .expect("test peer address fits IPv4");
            table.extend_from_slice(&peer_address.to_be_bytes());
            table.extend_from_slice(
                &65551u32
                    .checked_add(sequence)
                    .expect("test ASN fits MRT field")
                    .to_be_bytes(),
            );
            bytes.extend_from_slice(&record(sequence + 11, 13, 1, &table));

            let mut rib = Vec::new();
            rib.extend_from_slice(&sequence.to_be_bytes());
            rib.push(32);
            rib.extend_from_slice(
                &0x0a00_0000u32
                    .checked_add(sequence)
                    .expect("test prefix fits IPv4")
                    .to_be_bytes(),
            );
            rib.extend_from_slice(&1u16.to_be_bytes());
            rib.extend_from_slice(&0u16.to_be_bytes());
            rib.extend_from_slice(&10u32.to_be_bytes());
            rib.extend_from_slice(
                &u16::try_from(attributes.len())
                    .expect("test attributes fit MRT field")
                    .to_be_bytes(),
            );
            rib.extend_from_slice(&attributes);
            bytes.extend_from_slice(&record(sequence + 12, 13, 2, &rib));
        }
        bytes
    }

    #[test]
    fn sealed_source_replays_through_shared_state_without_inventing_direction() {
        let path = path("replay");
        let bytes = mrt();
        let archive = create(
            &path,
            &bytes,
            source(),
            1024 * 1024,
            MrtLimits::default(),
            Limits::default(),
        )
        .unwrap();
        assert_eq!(archive.candidates.len(), 1);
        assert_eq!(archive.bgp4mp_messages, 1);
        assert_eq!(archive.candidates[0].prefix.address, "203.0.113.0");
        assert_eq!(archive.candidates[0].checkpoint_id, "dump-7");
        assert_eq!(archive.candidates[0].observation_index, 0);
        assert_eq!(archive.candidates[0].route_index, 0);
        assert_eq!(
            archive
                .candidate_observation(&archive.candidates[0])
                .unwrap()
                .routes()[0]
                .prefix()
                .address,
            "203.0.113.0"
        );
        assert!(archive.state.routes().is_empty());
        assert_eq!(archive.state.observations().len(), 1);
        let replayed = replay(&path, 1024 * 1024, MrtLimits::default(), Limits::default()).unwrap();
        assert_eq!(replayed.receipt.source_sha256, sha256::digest(&bytes));
        assert_eq!(replayed.candidates[0].session, "mrt:0:0");
        assert!(replayed
            .state
            .encode()
            .contains("\"status\":\"missing_scope\""));
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn multi_record_rib_reduction_and_retained_output_growth_are_bounded() {
        let small_path = path("scale-small");
        let large_path = path("scale-large");
        let limits = Limits {
            fields: 65_536,
            elements: 1024,
            depth: 64,
            active: 128,
            retained_bytes: 16 * 1024 * 1024,
            work: 32 * 1024 * 1024,
            output_bytes: 16 * 1024 * 1024,
            ..Limits::default()
        };
        let small = create(
            &small_path,
            &many_ribs(128),
            source(),
            4 * 1024 * 1024,
            MrtLimits::default(),
            limits.clone(),
        )
        .unwrap();
        let large = create(
            &large_path,
            &many_ribs(256),
            source(),
            4 * 1024 * 1024,
            MrtLimits::default(),
            limits.clone(),
        )
        .unwrap();

        assert_eq!(small.candidates.len(), 128);
        assert_eq!(large.candidates.len(), 256);
        assert_eq!(small.state.observations().len(), 128);
        assert_eq!(large.state.observations().len(), 256);
        assert!(large.state.last_work() <= limits.work);
        assert!(large.state.retained_bytes() <= small.state.retained_bytes() * 3);
        let small_output = small.json().encode_bounded(limits.output_bytes).unwrap();
        let large_output = large.json().encode_bounded(limits.output_bytes).unwrap();
        assert!(large_output.len() <= small_output.len() * 3);
        let candidate_line = large.candidates[0]
            .json()
            .encode_bounded(limits.output_bytes)
            .unwrap();
        assert!(candidate_line.contains("\"observation_index\""));
        assert!(!candidate_line.contains("\"normalized_observation\""));
        for candidate in &large.candidates {
            let observation = large.candidate_observation(candidate).unwrap();
            assert!(candidate.route_index < observation.routes().len());
        }

        std::fs::remove_file(small_path).unwrap();
        std::fs::remove_file(large_path).unwrap();
    }

    #[test]
    fn peer_table_resolution_stays_logarithmic_across_many_rib_series() {
        let source_path = path("peer-table-index");
        let limits = Limits {
            fields: 65_536,
            elements: 1024,
            depth: 64,
            active: 128,
            retained_bytes: 16 * 1024 * 1024,
            work: 32 * 1024 * 1024,
            output_bytes: 16 * 1024 * 1024,
            ..Limits::default()
        };
        let archive = create(
            &source_path,
            &many_peer_tables(256),
            source(),
            4 * 1024 * 1024,
            MrtLimits::default(),
            limits,
        )
        .unwrap();
        let records = &archive.batch.records;
        assert_eq!(records.len(), 512);
        let maximum_probes = (usize::BITS - records.len().leading_zeros()) as usize + 1;
        let mut rib_count = 0usize;
        for record in records {
            let MrtBody::Rib(rib) = &record.body else {
                continue;
            };
            let (table_index, probes) = archive
                .batch
                .record_index_by_offset(rib.peer_table_offset)
                .unwrap();
            assert!(probes <= maximum_probes);
            let table_record = &records[table_index];
            assert_eq!(table_record.sha256.as_str(), rib.peer_table_sha256.as_str());
            assert!(matches!(&table_record.body, MrtBody::PeerIndex(_)));
            rib_count += 1;
        }
        assert_eq!(rib_count, 256);
        assert_eq!(archive.candidates.len(), 256);

        std::fs::remove_file(source_path).unwrap();
    }

    #[test]
    fn semantic_or_output_rejection_precedes_destination_creation() {
        let path = path("atomic");
        let limits = Limits {
            output_bytes: 1,
            ..Limits::default()
        };
        assert!(create(
            &path,
            &mrt(),
            source(),
            1024 * 1024,
            MrtLimits::default(),
            limits,
        )
        .is_err());
        assert!(!path.exists());
    }

    #[test]
    fn every_truncation_tamper_and_trailing_byte_is_rejected() {
        let complete = path("complete");
        let probe = path("probe");
        create(
            &complete,
            &mrt(),
            source(),
            1024 * 1024,
            MrtLimits::default(),
            Limits::default(),
        )
        .unwrap();
        let bytes = std::fs::read(&complete).unwrap();
        for cut in 0..bytes.len() {
            std::fs::write(&probe, &bytes[..cut]).unwrap();
            assert!(
                replay(&probe, 1024 * 1024, MrtLimits::default(), Limits::default()).is_err(),
                "truncation at {cut} was accepted"
            );
        }
        let mut tampered = bytes.clone();
        tampered[20] ^= 1;
        std::fs::write(&probe, tampered).unwrap();
        assert!(replay(&probe, 1024 * 1024, MrtLimits::default(), Limits::default()).is_err());
        let mut trailing = bytes.clone();
        trailing.push(0);
        std::fs::write(&probe, trailing).unwrap();
        assert!(replay(&probe, 1024 * 1024, MrtLimits::default(), Limits::default()).is_err());
        std::fs::remove_file(complete).unwrap();
        std::fs::remove_file(probe).unwrap();
    }
}
