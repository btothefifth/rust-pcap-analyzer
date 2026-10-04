//! Sealed raw BMP file evidence. Fresh replay always verifies and reparses bytes.
use super::bgp::{self, PeerRelationship};
use super::bgp_bmp::{self, BmpBatch, BmpLimits, BmpSource};
use super::bgp_import::ImportContext;
use super::bgp_rib::{AdjRibIn, RibEvent, RibEventKind, RibScope};
use super::bgp_session::SourcePartition;
use super::bgp_state::{CandidateState, Observation};
use super::model::{bad, Limits};
use pcap_evidence::{json::Json, sha256, Error, ErrorCode, Result};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;
#[path = "bgp_bmp_store_output.rs"]
mod output;

pub const SCHEMA: &str = "pcap-evidence.bgp.bmp-source-store.v1";
pub const REPLAY_SCHEMA: &str = "pcap-evidence.bgp.bmp-replay.v1";
pub const MAGIC: &[u8; 8] = b"PCBBMP01";
const VERSION: u16 = 1;
const SEAL_DOMAIN: &[u8] = b"pcap-evidence.bgp.bmp-source-store.v1\0";
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BmpReplayOptions {
    pub peer_relationship: Option<PeerRelationship>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BmpStoreReceipt {
    pub source_id: String,
    pub checkpoint_id: String,
    pub source_sha256: [u8; 32],
    pub source_bytes: u64,
    pub terminal_sha256: [u8; 32],
    pub records: u64,
}
impl BmpStoreReceipt {
    pub fn json(&self) -> Json {
        Json::object([
            ("schema", SCHEMA.into()),
            ("source_id", self.source_id.clone().into()),
            ("checkpoint_id", self.checkpoint_id.clone().into()),
            ("source_sha256", sha256::hex(&self.source_sha256).into()),
            ("source_bytes", self.source_bytes.into()),
            ("terminal_sha256", sha256::hex(&self.terminal_sha256).into()),
            ("records", self.records.into()),
            ("source_authenticated", false.into()),
        ])
    }
}
pub struct BmpReplayArchive {
    pub receipt: BmpStoreReceipt,
    pub state: CandidateState,
    pub bmp_rib: AdjRibIn,
    pub bmp_events: Vec<Json>,
    pub peer_relationship: Option<PeerRelationship>,
    batch: BmpBatch,
}
impl BmpReplayArchive {
    pub fn batch(&self) -> &BmpBatch {
        &self.batch
    }
    /// Deterministic logical charge for the complete final archive, not allocator RSS.
    pub fn retained_charge(&self) -> Result<usize> {
        let event_bytes = self.bmp_events.iter().try_fold(0usize, |used, event| {
            used.checked_add(event.encoded_len_bounded(usize::MAX)?)
                .ok_or_else(|| Error::limit("bmp_replay_retained"))
        })?;
        self.state
            .retained_bytes()
            .checked_add(self.bmp_rib.retained_bytes())
            .and_then(|n| n.checked_add(self.batch.retained_charge))
            .and_then(|n| n.checked_add(event_bytes))
            .and_then(|n| n.checked_add(self.receipt.json().encoded_len_bounded(usize::MAX).ok()?))
            .ok_or_else(|| Error::limit("bmp_replay_retained"))
    }
    /// Convenience tree construction, outside the bounded output method contract.
    pub fn bmp_rib_json(&self, session: Option<&str>) -> Json {
        super::bgp_mrt_store::rib_support::rib_json(&self.bmp_rib, session)
    }
    /// Convenience tree construction; use borrowed bounded writers for publication.
    pub fn json(&self) -> Json {
        Json::object([
            ("schema", REPLAY_SCHEMA.into()),
            ("receipt", self.receipt.json()),
            ("adapter_schema", bgp_bmp::SCHEMA.into()),
            ("fresh_process_reduction", true.into()),
            ("source_authenticated", false.into()),
            ("endpoint_state_claimed", false.into()),
            (
                "bmp_peer_relationship",
                self.peer_relationship
                    .map_or("unknown", PeerRelationship::as_str)
                    .into(),
            ),
            (
                "bmp_peer_relationship_basis",
                if self.peer_relationship.is_some() {
                    "explicit_configuration"
                } else {
                    "default_unknown"
                }
                .into(),
            ),
            (
                "bmp_peer_relationship_scope",
                "all_sessions_in_this_replay".into(),
            ),
            ("candidate_state", self.state.json()),
            ("bmp_rib", self.bmp_rib_json(None)),
            ("bmp_events", Json::array(self.bmp_events.iter().cloned())),
        ])
    }
    /// Convenience tree construction; normal queries use the bounded writer.
    pub fn session_query_json(&self, session: &str) -> Result<Json> {
        let observations = self
            .state
            .observations()
            .iter()
            .enumerate()
            .filter(|(_, o)| o.source().session.as_deref() == Some(session))
            .map(|(index, o)| {
                Json::object([
                    ("observation_index", index.into()),
                    ("observation_sha256", sha256::hex(&o.sha256()).into()),
                    ("normalized_observation", o.normalized().clone()),
                ])
            });
        Ok(Json::object([
            ("schema", "pcap-evidence.bgp.bmp-candidate-query.v1".into()),
            ("receipt", self.receipt.json()),
            ("session", session.into()),
            ("bmp_rib", self.bmp_rib_json(Some(session))),
            (
                "bmp_events",
                Json::array(
                    self.bmp_events
                        .iter()
                        .filter(|event| event_matches(event, session))
                        .cloned(),
                ),
            ),
            ("observations", Json::array(observations)),
            ("source_authenticated", false.into()),
            ("endpoint_state_claimed", false.into()),
        ]))
    }
}
fn event_value<'a>(event: &'a Json, key: &str) -> Option<&'a Json> {
    if let Json::Object(fields) = event {
        fields
            .iter()
            .find(|(name, _)| *name == key)
            .map(|(_, value)| value)
    } else {
        None
    }
}
fn event_matches(event: &Json, session: &str) -> bool {
    if let Some(Json::Array(scopes)) =
        event_value(event, "detail").and_then(|detail| event_value(detail, "affected_scopes"))
    {
        // An explicit inventory owns membership, including an empty inventory.
        // A base label must not admit a policy stream first seen after this cut.
        return scopes.iter().any(|scope| {
            if let Some(Json::String(label)) = event_value(scope, "session") {
                label == session
                    || label
                        .strip_prefix(session)
                        .is_some_and(|suffix| matches!(suffix, ":pre" | ":post"))
            } else {
                false
            }
        });
    }
    if let Some(Json::String(label)) = event_value(event, "session") {
        label == session
            || session
                .strip_prefix(label.as_str())
                .is_some_and(|suffix| matches!(suffix, ":pre" | ":post"))
    } else {
        false
    }
}

pub fn create(
    path: &Path,
    input: &[u8],
    source: BmpSource,
    maximum: u64,
    bmp_limits: BmpLimits,
    limits: Limits,
) -> Result<BmpReplayArchive> {
    create_with_options(
        path,
        input,
        source,
        maximum,
        bmp_limits,
        limits,
        BmpReplayOptions::default(),
    )
}
pub fn create_with_options(
    path: &Path,
    input: &[u8],
    source: BmpSource,
    maximum: u64,
    bmp_limits: BmpLimits,
    limits: Limits,
    options: BmpReplayOptions,
) -> Result<BmpReplayArchive> {
    limits.validate()?;
    bmp_limits.validate()?;
    let size = encoded_size(
        input.len(),
        source.source_id.len(),
        source.checkpoint_id.len(),
    )?;
    if size as u64 > maximum {
        return Err(Error::limit("bmp_store_disk"));
    }
    let batch = BmpBatch::parse(input, source.clone(), &bmp_limits)?;
    let mut header = Vec::new();
    let header_size = size - input.len() - 32;
    header
        .try_reserve_exact(header_size)
        .map_err(|_| Error::limit("bmp_store_header"))?;
    header.extend_from_slice(MAGIC);
    header.extend_from_slice(&VERSION.to_le_bytes());
    put_text(&mut header, &source.source_id)?;
    put_text(&mut header, &source.checkpoint_id)?;
    header.extend_from_slice(&(input.len() as u64).to_le_bytes());
    header.extend_from_slice(&sha256::digest(input));
    let mut digest = sha256::Sha256::new();
    digest.update(SEAL_DOMAIN);
    digest.update(&header);
    digest.update(input);
    let terminal = digest.finalize();
    let archive = build_archive(batch, terminal, &bmp_limits, limits, options)?;
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(&header)?;
    file.write_all(input)?;
    file.write_all(&terminal)?;
    file.sync_all()?;
    Ok(archive)
}
pub fn replay(
    path: &Path,
    maximum: u64,
    bmp_limits: BmpLimits,
    limits: Limits,
) -> Result<BmpReplayArchive> {
    replay_with_options(
        path,
        maximum,
        bmp_limits,
        limits,
        BmpReplayOptions::default(),
    )
}
pub fn replay_with_options(
    path: &Path,
    maximum: u64,
    bmp_limits: BmpLimits,
    limits: Limits,
    options: BmpReplayOptions,
) -> Result<BmpReplayArchive> {
    limits.validate()?;
    bmp_limits.validate()?;
    let mut file = File::open(path)?;
    let metadata = file.metadata()?;
    let max_envelope = encoded_size(bmp_limits.input_bytes, 1024, 1024)?;
    if !metadata.is_file() || metadata.len() > maximum || metadata.len() > max_envelope as u64 {
        return Err(Error::limit("bmp_store_disk"));
    }
    let size = usize::try_from(metadata.len()).map_err(|_| Error::limit("bmp_store_disk"))?;
    let bytes = read_snapshot(&mut file, size)?;
    if bytes.len() < 90 + 2 + 1 {
        return Err(Error::new(
            ErrorCode::Truncated,
            0,
            "bmp_store",
            "truncated source store",
        ));
    }
    let seal_offset = bytes.len() - 32;
    let mut terminal = [0; 32];
    terminal.copy_from_slice(&bytes[seal_offset..]);
    let mut digest = sha256::Sha256::new();
    digest.update(SEAL_DOMAIN);
    digest.update(&bytes[..seal_offset]);
    if digest.finalize() != terminal {
        return Err(Error::new(
            ErrorCode::SourceMismatch,
            seal_offset as u64,
            "bmp_store_seal",
            "terminal digest mismatch",
        ));
    }
    let mut cursor = Cursor {
        bytes: &bytes[..seal_offset],
        position: 0,
    };
    if cursor.take(8)? != MAGIC {
        return Err(Error::new(
            ErrorCode::BadMagic,
            0,
            "bmp_store_magic",
            "not a BMP source store",
        ));
    }
    if u16::from_le_bytes(cursor.take(2)?.try_into().unwrap()) != VERSION {
        return Err(Error::new(
            ErrorCode::UnsupportedVersion,
            8,
            "bmp_store_version",
            "unsupported store version",
        ));
    }
    let source_id = cursor.text()?;
    let checkpoint_id = cursor.text()?;
    let source_len = usize::try_from(u64::from_le_bytes(cursor.take(8)?.try_into().unwrap()))
        .map_err(|_| Error::limit("bmp_source"))?;
    if source_len == 0 || source_len > bmp_limits.input_bytes {
        return Err(Error::limit("bmp_source"));
    }
    let expected = cursor.take(32)?;
    let source_bytes = cursor.take(source_len)?;
    if cursor.position != seal_offset {
        return Err(bad(
            "bmp_store_trailing",
            cursor.position,
            "unexpected store data",
        ));
    }
    if expected != sha256::digest(source_bytes) {
        return Err(Error::new(
            ErrorCode::SourceMismatch,
            0,
            "bmp_source_hash",
            "source digest mismatch",
        ));
    }
    let batch = BmpBatch::parse(
        source_bytes,
        BmpSource {
            source_id,
            checkpoint_id,
        },
        &bmp_limits,
    )?;
    build_archive(batch, terminal, &bmp_limits, limits, options)
}
fn build_archive(
    batch: BmpBatch,
    terminal: [u8; 32],
    bmp_limits: &BmpLimits,
    limits: Limits,
    options: BmpReplayOptions,
) -> Result<BmpReplayArchive> {
    let mut state = CandidateState::new(limits.clone())?;
    let mut rib = AdjRibIn::new(limits.clone())?;
    let mut decoder = bgp::bmp::ReplayState::new(options.peer_relationship);
    let mut events = Vec::new();
    let mut observations = Vec::new();
    let mut work = batch.work_charge;
    let mut retained = batch.retained_charge;
    for index in 0..batch.records.len() {
        let replay =
            bgp::bmp::replay_record(&batch, index, &limits, bmp_limits.peers, &mut decoder)?;
        let event_bytes = replay.event.encoded_len_bounded(limits.output_bytes)?;
        retained = retained
            .checked_add(event_bytes)
            .filter(|n| *n <= limits.retained_bytes)
            .ok_or_else(|| Error::limit("bmp_replay_retained"))?;
        work = work
            .checked_add(event_bytes)
            .filter(|n| *n <= limits.work)
            .ok_or_else(|| Error::limit("bmp_replay_work"))?;
        if events.len() >= limits.elements {
            return Err(Error::limit("bmp_replay_events"));
        }
        events
            .try_reserve(1)
            .map_err(|_| Error::limit("bmp_replay_events"))?;
        events.push(replay.event);
        for normalized in replay.observations {
            let observation = Observation::from_normalized(&normalized, None, &limits)?;
            let bytes = normalized.encoded_len_bounded(limits.input_bytes)?;
            retained = retained
                .checked_add(bytes)
                .filter(|n| *n <= limits.retained_bytes)
                .ok_or_else(|| Error::limit("bmp_replay_retained"))?;
            work = work
                .checked_add(observation.batch_work()?)
                .filter(|n| *n <= limits.work)
                .ok_or_else(|| Error::limit("bmp_replay_work"))?;
            if let Some(event) =
                super::bgp_mrt_store::rib_support::observation_event(&observation, &limits)?
            {
                // Journal publication includes route-free, unsupported-family
                // observations. Their boundaries must remain in CandidateState,
                // but cannot reset a native scope that has never been admitted.
                // Once admitted (including EOR or Gap), forward the exact reset
                // so the canonical reducer still validates its predecessor.
                if !matches!(event.kind, RibEventKind::Reset { .. })
                    || native_scope_initialized(&rib, &event, &mut work, &limits)?
                {
                    rib.apply(event)?;
                }
            }
            if observations.len() >= limits.elements {
                return Err(Error::limit("bmp_replay_observations"));
            }
            observations
                .try_reserve(1)
                .map_err(|_| Error::limit("bmp_replay_observations"))?;
            observations.push(observation);
        }
        for (ordinal, context) in replay.gaps.into_iter().enumerate() {
            rib.apply(RibEvent {
                scope: scope(&context, &limits)?,
                record_id: format!("bmp-gap:{index}:{ordinal}:{}", batch.records[index].sha256),
                kind: RibEventKind::Gap {
                    reason: "quarantined_bmp_context_continuity".into(),
                },
            })?;
        }
        // The canonical reducer owns and enforces its own retained representation.
        if rib
            .retained_bytes()
            .checked_add(retained)
            .is_none_or(|n| n > limits.retained_bytes)
        {
            return Err(Error::limit("bmp_replay_retained"));
        }
        work = work
            .checked_add(rib.accounted_work())
            .filter(|n| *n <= limits.work)
            .ok_or_else(|| Error::limit("bmp_replay_work"))?;
    }
    state.apply_batch(observations)?;
    if state
        .retained_bytes()
        .checked_add(rib.retained_bytes())
        .and_then(|n| n.checked_add(batch.retained_charge))
        .is_none_or(|n| n > limits.retained_bytes)
    {
        return Err(Error::limit("bmp_replay_retained"));
    }
    let receipt = BmpStoreReceipt {
        source_id: batch.source.source_id.clone(),
        checkpoint_id: batch.source.checkpoint_id.clone(),
        source_sha256: sha256::digest(batch.bytes()),
        source_bytes: batch.byte_length,
        terminal_sha256: terminal,
        records: batch.records.len() as u64,
    };
    let archive = BmpReplayArchive {
        receipt,
        state,
        bmp_rib: rib,
        bmp_events: events,
        peer_relationship: options.peer_relationship,
        batch,
    };
    let output_size = archive.encoded_len_bounded(limits.output_bytes)?;
    work.checked_add(output_size)
        .filter(|n| *n <= limits.work)
        .ok_or_else(|| Error::limit("bmp_replay_work"))?;
    if archive.retained_charge()? > limits.retained_bytes {
        return Err(Error::limit("bmp_replay_retained"));
    }
    Ok(archive)
}
fn native_scope_initialized(
    rib: &AdjRibIn,
    event: &RibEvent,
    work: &mut usize,
    limits: &Limits,
) -> Result<bool> {
    // Reuse canonical admitted evidence instead of allocating a second scope
    // inventory. Native SessionKey consists only of source partition/session;
    // direction and generation cannot turn a missing predecessor into a reset.
    for prior in rib.events() {
        let comparison_bytes = [
            event.scope.source.source_id.len(),
            event.scope.source.partition_id.len(),
            event.scope.session.len(),
            prior.scope.source.source_id.len(),
            prior.scope.source.partition_id.len(),
            prior.scope.session.len(),
        ]
        .into_iter()
        .try_fold(1usize, usize::checked_add)
        .ok_or_else(|| Error::limit("bmp_replay_work"))?;
        *work = work
            .checked_add(comparison_bytes)
            .filter(|n| *n <= limits.work)
            .ok_or_else(|| Error::limit("bmp_replay_work"))?;
        if prior.scope.source == event.scope.source && prior.scope.session == event.scope.session {
            return Ok(true);
        }
    }
    Ok(false)
}
fn scope(context: &ImportContext, limits: &Limits) -> Result<RibScope> {
    Ok(RibScope {
        source: SourcePartition::from_import_context(context, limits)?,
        session: context.session.clone(),
        generation: context.generation,
        direction: context.direction,
        peer: context.peer.clone(),
    })
}
fn encoded_size(input: usize, source: usize, checkpoint: usize) -> Result<usize> {
    90usize
        .checked_add(input)
        .and_then(|n| n.checked_add(source))
        .and_then(|n| n.checked_add(checkpoint))
        .ok_or_else(|| Error::limit("bmp_store_bytes"))
}
fn put_text(bytes: &mut Vec<u8>, value: &str) -> Result<()> {
    let len = u32::try_from(value.len()).map_err(|_| Error::limit("bmp_label"))?;
    bytes.extend_from_slice(&len.to_le_bytes());
    bytes.extend_from_slice(value.as_bytes());
    Ok(())
}
struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
}
impl<'a> Cursor<'a> {
    fn take(&mut self, length: usize) -> Result<&'a [u8]> {
        let end = self
            .position
            .checked_add(length)
            .ok_or_else(|| Error::limit("bmp_store_length"))?;
        let value = self.bytes.get(self.position..end).ok_or_else(|| {
            Error::new(
                ErrorCode::Truncated,
                self.position as u64,
                "bmp_store",
                "truncated field",
            )
        })?;
        self.position = end;
        Ok(value)
    }
    fn text(&mut self) -> Result<String> {
        let length = u32::from_le_bytes(self.take(4)?.try_into().unwrap()) as usize;
        if length == 0 || length > 1024 {
            return Err(Error::limit("bmp_label"));
        }
        std::str::from_utf8(self.take(length)?)
            .map(str::to_owned)
            .map_err(|_| bad("bmp_label", self.position, "invalid UTF-8 label"))
    }
}
fn read_snapshot(reader: &mut impl Read, size: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(size)
        .map_err(|_| Error::limit("bmp_source_allocation"))?;
    bytes.resize(size, 0);
    reader.read_exact(&mut bytes)?;
    let mut probe = [0; 1];
    loop {
        match reader.read(&mut probe) {
            Ok(0) => return Ok(bytes),
            Ok(_) => {
                return Err(bad(
                    "bmp_source_growth",
                    size,
                    "source grew beyond admitted size",
                ))
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.into()),
        }
    }
}
pub fn read_source(path: &Path, maximum: u64) -> Result<Vec<u8>> {
    if maximum == 0 || maximum > 64 * 1024 * 1024 {
        return Err(Error::limit("bmp_input"));
    }
    let mut file = File::open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > maximum {
        return Err(Error::limit("bmp_input"));
    }
    read_snapshot(
        &mut file,
        usize::try_from(metadata.len()).map_err(|_| Error::limit("bmp_input"))?,
    )
}
