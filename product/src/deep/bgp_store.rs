//! Restartable, source-record BGP persistence.
//!
//! The journal stores exact reconstructed message bytes and packet provenance,
//! not a trusted serialized projection. A fresh process verifies the hash chain
//! and replays every source record through the wire/session/RIB pipeline.
use super::bgp::PcapMetadata;
use super::bgp_manager::{CapturedSessionManager, SessionSnapshot};
use super::model::{bad, Limits};
use pcap_evidence::{
    json::Json,
    provenance::{EvidenceBytes, PacketId, SourceSpan},
    sha256, Error, ErrorCode, Result,
};
use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::Path,
};

pub const SCHEMA: &str = "pcap-evidence.bgp.source-journal.v1";
pub const REPLAY_SCHEMA: &str = "pcap-evidence.bgp.journal-replay.v1";
pub const MAGIC: &[u8; 8] = b"PCBGP001";
const VERSION: u16 = 1;
const HEADER_DOMAIN: &[u8] = b"pcap-evidence/bgp-journal-header/v1\0";
const RECORD_DOMAIN: &[u8] = b"pcap-evidence/bgp-journal-record/v1\0";
const MESSAGE: u8 = 1;
const GAP: u8 = 2;
const RESET: u8 = 3;
const END: u8 = 4;
const CLEAR: u8 = 5;
const SEAL: u8 = 255;
const RECORD_OVERHEAD: u64 = 1 + 8 + 32 + 32;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JournalReceipt {
    pub source_id: String,
    pub capture_namespace: [u8; 32],
    pub records: u64,
    pub terminal_sha256: [u8; 32],
}

impl JournalReceipt {
    pub fn json(&self) -> Json {
        Json::object([
            ("schema", SCHEMA.into()),
            ("source_id", self.source_id.clone().into()),
            (
                "capture_namespace_sha256",
                sha256::hex(&self.capture_namespace).into(),
            ),
            ("records", self.records.to_string().into()),
            ("terminal_sha256", sha256::hex(&self.terminal_sha256).into()),
            ("sealed", true.into()),
            ("endpoint_state_claimed", false.into()),
        ])
    }
}

pub struct JournalWriter {
    file: File,
    limits: Limits,
    source_id: String,
    capture_namespace: [u8; 32],
    chain: [u8; 32],
    records: u64,
    written: u64,
    maximum: u64,
    sealed: bool,
}

impl JournalWriter {
    pub fn create(
        path: &Path,
        source_id: String,
        capture_namespace: [u8; 32],
        maximum: u64,
        limits: Limits,
    ) -> Result<Self> {
        limits.validate()?;
        check_text(&source_id, &limits, "bgp_journal_source")?;
        let mut header = Encoder::default();
        header.bytes(MAGIC);
        header.u16(VERSION);
        header.bytes(&capture_namespace);
        header.text(&source_id)?;
        let header = header.finish();
        let written = as_u64(header.len(), "bgp_journal_bytes")?;
        if written > maximum {
            return Err(Error::limit("bgp_journal_disk"));
        }
        let file = OpenOptions::new().write(true).create_new(true).open(path)?;
        let mut chain = sha256::Sha256::new();
        chain.update(HEADER_DOMAIN);
        chain.update(&header);
        let mut this = Self {
            file,
            limits,
            source_id,
            capture_namespace,
            chain: chain.finalize(),
            records: 0,
            written: 0,
            maximum,
            sealed: false,
        };
        this.write_all(&header)?;
        Ok(this)
    }

    pub fn message(
        &mut self,
        session: u64,
        bytes: &EvidenceBytes,
        metadata: &PcapMetadata,
    ) -> Result<()> {
        if metadata.source_id != self.source_id || metadata.session != Some(session) {
            return Err(bad(
                "bgp_journal_scope",
                0,
                "message metadata differs from journal scope",
            ));
        }
        if !bytes.validate()
            || bytes.is_empty()
            || bytes.len() > self.limits.input_bytes
            || bytes.spans().len() > self.limits.spans
            || bytes
                .spans()
                .iter()
                .any(|span| span.packet.capture != self.capture_namespace)
        {
            return Err(bad(
                "bgp_journal_provenance",
                0,
                "message bytes or provenance differ from journal scope",
            ));
        }
        check_text(&metadata.record_id, &self.limits, "bgp_journal_record_id")?;
        check_optional_text(&metadata.peer, &self.limits)?;
        check_optional_text(&metadata.local, &self.limits)?;
        let mut body = Encoder::default();
        body.u64(session);
        body.option_u8(metadata.direction);
        body.text(&metadata.record_id)?;
        body.option_i64(metadata.observed_at_ns);
        body.option_text(metadata.peer.as_deref())?;
        body.option_text(metadata.local.as_deref())?;
        body.blob(bytes.data())?;
        body.u32(as_u32(bytes.spans().len(), "bgp_journal_spans")?);
        for span in bytes.spans() {
            body.u64(as_u64(span.start, "bgp_journal_span")?);
            body.u64(as_u64(span.end, "bgp_journal_span")?);
            body.bytes(&span.packet.capture);
            body.u64(span.packet.frame);
            body.u64(span.packet.record_offset);
            body.u64(as_u64(span.packet_start, "bgp_journal_span")?);
        }
        self.append(MESSAGE, &body.finish())
    }

    pub fn gap(&mut self, session: u64, record_id: &str, reason: &str) -> Result<()> {
        self.boundary(GAP, session, record_id, reason)
    }

    pub fn reset(&mut self, session: u64, record_id: &str, reason: &str) -> Result<()> {
        self.boundary(RESET, session, record_id, reason)
    }

    fn boundary(&mut self, kind: u8, session: u64, record_id: &str, reason: &str) -> Result<()> {
        check_text(record_id, &self.limits, "bgp_journal_record_id")?;
        check_text(reason, &self.limits, "bgp_journal_reason")?;
        let mut body = Encoder::default();
        body.u64(session);
        body.text(record_id)?;
        body.text(reason)?;
        self.append(kind, &body.finish())
    }

    pub fn end_session(&mut self, session: u64) -> Result<()> {
        let mut body = Encoder::default();
        body.u64(session);
        self.append(END, &body.finish())
    }

    pub fn clear(&mut self) -> Result<()> {
        self.append(CLEAR, &[])
    }

    pub fn seal(mut self) -> Result<JournalReceipt> {
        let count = self.records;
        let mut body = Encoder::default();
        body.u64(count);
        self.append(SEAL, &body.finish())?;
        self.file.flush()?;
        self.file.sync_all()?;
        self.sealed = true;
        Ok(JournalReceipt {
            source_id: self.source_id.clone(),
            capture_namespace: self.capture_namespace,
            records: count,
            terminal_sha256: self.chain,
        })
    }

    fn append(&mut self, kind: u8, body: &[u8]) -> Result<()> {
        if self.sealed || kind == 0 {
            return Err(bad(
                "bgp_journal_state",
                usize::try_from(self.written).unwrap_or(usize::MAX),
                "cannot append to sealed journal",
            ));
        }
        if body.len() > self.maximum.min(self.limits.retained_bytes as u64) as usize {
            return Err(Error::limit("bgp_journal_record"));
        }
        let length = as_u64(body.len(), "bgp_journal_record")?;
        let digest = record_digest(kind, length, &self.chain, body);
        let needed = RECORD_OVERHEAD
            .checked_add(length)
            .ok_or_else(|| Error::limit("bgp_journal_disk"))?;
        if self
            .written
            .checked_add(needed)
            .is_none_or(|n| n > self.maximum)
        {
            return Err(Error::limit("bgp_journal_disk"));
        }
        let mut encoded = Vec::with_capacity(needed as usize);
        encoded.push(kind);
        encoded.extend_from_slice(&length.to_le_bytes());
        encoded.extend_from_slice(&self.chain);
        encoded.extend_from_slice(&digest);
        encoded.extend_from_slice(body);
        self.write_all(&encoded)?;
        self.chain = digest;
        if kind != SEAL {
            self.records = self
                .records
                .checked_add(1)
                .ok_or_else(|| Error::limit("bgp_journal_records"))?;
        } else {
            self.sealed = true;
        }
        Ok(())
    }

    fn write_all(&mut self, bytes: &[u8]) -> Result<()> {
        self.file.write_all(bytes)?;
        self.written = self
            .written
            .checked_add(as_u64(bytes.len(), "bgp_journal_bytes")?)
            .ok_or_else(|| Error::limit("bgp_journal_disk"))?;
        Ok(())
    }
}

/// Source-replay lifecycle and exact normalized occurrence witnesses. These
/// supplement canonical reducer entries without changing their historical status.
#[derive(Clone, Debug)]
pub struct CapturedEntryEvidence {
    pub lifecycle: u64,
    pub current: bool,
    pub observation_sha256: Vec<[u8; 32]>,
}
#[derive(Clone, Debug)]
pub struct CapturedObservationEvidence {
    pub lifecycle: u64,
    pub journal_record_sha256: [u8; 32],
    pub source_record_index: u64,
    pub source_start: u64,
    pub source_end: u64,
}

/// Verified journal-only events unavailable as normalized route observations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapturedSourceEventKind {
    Gap,
    Reset,
    EndSession,
    Clear,
    RejectedContainer,
    DecodedGap,
    DecodedReset,
}
impl CapturedSourceEventKind {
    pub fn name(self) -> &'static str {
        match self {
            Self::Gap => "gap",
            Self::Reset => "reset",
            Self::EndSession => "end_session",
            Self::Clear => "clear",
            Self::RejectedContainer => "rejected_container",
            Self::DecodedGap => "decoded_gap",
            Self::DecodedReset => "decoded_reset",
        }
    }
}
#[derive(Clone, Debug)]
pub struct CapturedSourceEvent {
    pub kind: CapturedSourceEventKind,
    pub source_record_index: u64,
    pub journal_record_sha256: [u8; 32],
    pub source_start: u64,
    pub source_end: u64,
    /// A CLEAR has one scope per actually retained session; empty remains empty.
    pub scopes: Vec<CapturedSourceScope>,
    pub record_id: Option<String>,
    pub cause: Option<String>,
    pub packet_spans: Vec<SourceSpan>,
    pub metadata: Option<PcapMetadata>,
    pub continuity: Option<CapturedDecodedContinuity>,
}
/// Exact normalized occurrence binding for a pipeline-owned continuity decision.
#[derive(Clone, Debug)]
pub struct CapturedDecodedContinuity {
    pub observation_index: usize,
    pub observation_sha256: [u8; 32],
    pub decision: super::bgp_pipeline::DecodedContinuity,
}
#[derive(Clone, Debug)]
pub struct CapturedSourceScope {
    pub session: u64,
    pub lifecycle: u64,
    pub generation: Option<u64>,
}
impl CapturedSourceEvent {
    /// Conservative typed-storage charge, available without cloning evidence subtrees.
    pub fn retained_charge(&self) -> usize {
        1024usize
            .saturating_add(
                self.continuity
                    .as_ref()
                    .map_or(0, |c| c.decision.retained_charge().saturating_add(256)),
            )
            .saturating_add(self.scopes.len().saturating_mul(192))
            .saturating_add(self.record_id.as_ref().map_or(0, String::len))
            .saturating_add(self.cause.as_ref().map_or(0, String::len))
            .saturating_add(self.packet_spans.len().saturating_mul(512))
            .saturating_add(self.metadata.as_ref().map_or(0, |m| {
                m.source_id
                    .len()
                    .saturating_add(m.record_id.len())
                    .saturating_add(m.peer.as_ref().map_or(0, String::len))
                    .saturating_add(m.local.as_ref().map_or(0, String::len))
                    .saturating_add(256)
            }))
    }
    pub fn projection_nodes(&self) -> usize {
        14usize
            .saturating_add(self.scopes.len().saturating_mul(4))
            .saturating_add(usize::from(self.metadata.is_some()).saturating_mul(6))
            .saturating_add(self.packet_spans.len().saturating_mul(8))
            .saturating_add(usize::from(self.continuity.is_some()).saturating_mul(18))
    }
    pub fn projection_depth(&self) -> usize {
        2usize
            .max(if self.scopes.is_empty() { 2 } else { 4 })
            .max(if self.metadata.is_some() { 3 } else { 2 })
            .max(if self.continuity.is_some() { 4 } else { 2 })
            .max(if self.packet_spans.is_empty() { 2 } else { 5 })
    }
    pub fn json(&self) -> Json {
        let mut value = Json::object([
            (
                "schema",
                if self.continuity.is_some() {
                    "pcap-evidence.bgp.captured-source-event.v2"
                } else {
                    "pcap-evidence.bgp.captured-source-event.v1"
                }
                .into(),
            ),
            ("event_kind", self.kind.name().into()),
            ("source_record_index", self.source_record_index.into()),
            (
                "journal_record_sha256",
                sha256::hex(&self.journal_record_sha256).into(),
            ),
            ("source_start", self.source_start.into()),
            ("source_end", self.source_end.into()),
            (
                "scopes",
                Json::array(self.scopes.iter().map(|scope| {
                    Json::object([
                        ("session", scope.session.to_string().into()),
                        ("captured_lifecycle", scope.lifecycle.into()),
                        (
                            "generation",
                            scope.generation.map_or(Json::Null, Json::from),
                        ),
                    ])
                })),
            ),
            (
                "record_id",
                self.record_id.clone().map_or(Json::Null, Json::from),
            ),
            ("cause", self.cause.clone().map_or(Json::Null, Json::from)),
            (
                "metadata",
                self.metadata.as_ref().map_or(Json::Null, |m| {
                    Json::object([
                        ("source_id", m.source_id.clone().into()),
                        ("record_id", m.record_id.clone().into()),
                        ("direction", m.direction.map_or(Json::Null, Json::from)),
                        ("peer", m.peer.clone().map_or(Json::Null, Json::from)),
                        ("local", m.local.clone().map_or(Json::Null, Json::from)),
                        (
                            "observed_at_ns",
                            m.observed_at_ns
                                .map_or(Json::Null, |v| v.to_string().into()),
                        ),
                    ])
                }),
            ),
            (
                "spans",
                Json::array(self.packet_spans.iter().map(|span| {
                    Json::object([
                        ("start", span.start.into()),
                        ("end", span.end.into()),
                        ("packet_start", span.packet_start.into()),
                        (
                            "packet",
                            Json::object([
                                ("capture", sha256::hex(&span.packet.capture).into()),
                                ("frame", span.packet.frame.into()),
                                ("record_offset", span.packet.record_offset.into()),
                            ]),
                        ),
                    ])
                })),
            ),
            ("source_authenticated", false.into()),
            ("route_action_created", false.into()),
        ]);
        if let (Json::Object(fields), Some(c)) = (&mut value, &self.continuity) {
            fields.push((
                "decoded_continuity",
                Json::object([
                    ("observation_index", c.observation_index.into()),
                    (
                        "observation_sha256",
                        sha256::hex(&c.observation_sha256).into(),
                    ),
                    ("decision", c.decision.json()),
                ]),
            ));
        }
        value
    }
}
/// A native rejected action bound when the reducer first emits it. The index
/// selects the exact normalized observation and its journal/lifecycle witness;
/// record labels alone cannot identify reused occurrences.
#[derive(Clone, Debug)]
pub struct CapturedRejection {
    pub rejection: super::bgp_rib::RejectedRecord,
    pub observation_index: usize,
}

#[derive(Clone, Debug)]
pub struct ReplayArchive {
    pub receipt: JournalReceipt,
    pub sessions: Vec<SessionSnapshot>,
    pub messages: u64,
    pub boundaries: u64,
    pub rejected_records: u64,
    /// Typed terminal entries sampled from the canonical reducer before each
    /// session leaves the manager. Reused session labels remain occurrences.
    pub route_entries: Vec<super::bgp_rib::RouteEntry>,
    pub route_rejections: Vec<CapturedRejection>,
    /// Successful normalized observations rebuilt from verified source bytes.
    pub observations: Vec<super::bgp_state::Observation>,
    pub route_entry_evidence: Vec<CapturedEntryEvidence>,
    pub observation_evidence: Vec<CapturedObservationEvidence>,
    pub source_events: Vec<CapturedSourceEvent>,
}

impl ReplayArchive {
    pub fn json(&self) -> Json {
        Json::object([
            ("schema", REPLAY_SCHEMA.into()),
            ("journal", self.receipt.json()),
            ("messages", self.messages.to_string().into()),
            ("boundaries", self.boundaries.to_string().into()),
            ("rejected_records", self.rejected_records.to_string().into()),
            (
                "sessions",
                Json::array(self.sessions.iter().map(SessionSnapshot::json)),
            ),
            ("fresh_process_reduction", true.into()),
            ("endpoint_state_claimed", false.into()),
        ])
    }

    pub fn session_history(&self, id: u64) -> Vec<&SessionSnapshot> {
        self.sessions
            .iter()
            .filter(|snapshot| snapshot.session == id)
            .collect()
    }
}

pub fn replay(path: &Path, maximum: u64, limits: Limits) -> Result<ReplayArchive> {
    limits.validate()?;
    let mut file = File::open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > maximum {
        return Err(Error::limit("bgp_journal_disk"));
    }
    let mut consumed = 0u64;
    let mut fixed = [0u8; 42];
    read_exact_at(&mut file, &mut fixed, &mut consumed, "bgp_journal_header")?;
    if &fixed[..8] != MAGIC {
        return Err(Error::new(
            ErrorCode::BadMagic,
            0,
            "bgp_journal_magic",
            "not a BGP source journal",
        ));
    }
    if u16::from_le_bytes([fixed[8], fixed[9]]) != VERSION {
        return Err(Error::new(
            ErrorCode::UnsupportedVersion,
            8,
            "bgp_journal_version",
            "unsupported BGP journal version",
        ));
    }
    let mut capture_namespace = [0u8; 32];
    capture_namespace.copy_from_slice(&fixed[10..42]);
    let source_id = read_text(&mut file, &mut consumed, &limits, "bgp_journal_source")?;
    let mut header = Vec::new();
    header.extend_from_slice(&fixed);
    let source_bytes = source_id.as_bytes();
    header.extend_from_slice(&as_u32(source_bytes.len(), "bgp_journal_source")?.to_le_bytes());
    header.extend_from_slice(source_bytes);
    let mut initial = sha256::Sha256::new();
    initial.update(HEADER_DOMAIN);
    initial.update(&header);
    let mut chain = initial.finalize();
    let mut manager =
        CapturedSessionManager::new(capture_namespace, source_id.clone(), limits.clone())?;
    let mut sessions = Vec::new();
    let mut route_entries = Vec::new();
    let mut route_rejections = Vec::new();
    let mut observations = Vec::new();
    let mut route_entry_evidence = Vec::new();
    let mut observation_evidence = Vec::new();
    let mut source_events = Vec::new();
    let mut source_event_spans = 0usize;
    let mut lifecycles = BTreeMap::<u64, u64>::new();
    let mut latest_observations = BTreeMap::<(u64, String), [u8; 32]>::new();
    let mut adapter_bytes = 0usize;
    let mut records = 0u64;
    let mut messages = 0u64;
    let mut boundaries = 0u64;
    let mut rejected_records = 0u64;
    let terminal;
    loop {
        let offset = consumed;
        let mut prefix = [0u8; RECORD_OVERHEAD as usize];
        read_exact_at(&mut file, &mut prefix, &mut consumed, "bgp_journal_record")?;
        let kind = prefix[0];
        let length = u64::from_le_bytes(prefix[1..9].try_into().expect("fixed slice"));
        if length > maximum
            || length > limits.retained_bytes as u64
            || consumed
                .checked_add(length)
                .is_none_or(|n| n > metadata.len())
        {
            return Err(Error::new(
                ErrorCode::InvalidLength,
                offset,
                "bgp_journal_record",
                "record length exceeds configured or file boundary",
            ));
        }
        if prefix[9..41] != chain {
            return Err(Error::new(
                ErrorCode::SourceMismatch,
                offset,
                "bgp_journal_chain",
                "previous-record digest does not match",
            ));
        }
        let mut expected = [0u8; 32];
        expected.copy_from_slice(&prefix[41..73]);
        let mut body =
            vec![0u8; usize::try_from(length).map_err(|_| Error::limit("bgp_journal_record"))?];
        read_exact_at(&mut file, &mut body, &mut consumed, "bgp_journal_body")?;
        let actual = record_digest(kind, length, &chain, &body);
        if expected != actual {
            return Err(Error::new(
                ErrorCode::SourceMismatch,
                offset,
                "bgp_journal_digest",
                "record digest does not match body",
            ));
        }
        chain = actual;
        let mut decoder = Decoder::new(&body, &limits);
        match kind {
            MESSAGE => {
                let (session, bytes, metadata) = decoder.message(&source_id, capture_namespace)?;
                decoder.finish()?;
                messages = checked_increment(messages, "bgp_journal_messages")?;
                let rejection_start = manager.rib(session).map_or(0, |rib| rib.rejections().len());
                let event_scope = CapturedSourceScope {
                    session,
                    lifecycle: *lifecycles.get(&session).unwrap_or(&0),
                    generation: manager.wire_state(session).map(|v| v.generation()),
                };
                let event_metadata = metadata.clone();
                match manager.apply_message(session, &bytes, metadata) {
                    Ok(receipt) => {
                        let observation = super::bgp_state::Observation::from_normalized(
                            &receipt.normalized,
                            None,
                            &limits,
                        )?;
                        adapter_bytes = adapter_bytes
                            .checked_add(
                                receipt
                                    .normalized
                                    .encoded_len_bounded(limits.retained_bytes)?
                                    .checked_mul(3)
                                    .ok_or_else(|| Error::limit("bgp_journal_adapter"))?,
                            )
                            .ok_or_else(|| Error::limit("bgp_journal_adapter"))?;
                        if observations.len() >= limits.elements
                            || adapter_bytes > limits.retained_bytes
                            || adapter_bytes > limits.work
                        {
                            return Err(Error::limit("bgp_journal_adapter"));
                        }
                        let key = (session, observation.source().record_id.clone());
                        let extra =
                            96usize.saturating_add(if latest_observations.contains_key(&key) {
                                0
                            } else {
                                key.1.len().saturating_add(96)
                            });
                        adapter_bytes = adapter_bytes
                            .checked_add(extra)
                            .ok_or_else(|| Error::limit("bgp_journal_adapter"))?;
                        if adapter_bytes > limits.retained_bytes
                            || adapter_bytes > limits.work
                            || latest_observations.len() >= limits.elements
                        {
                            return Err(Error::limit("bgp_journal_adapter"));
                        }
                        retain_rejections(
                            &manager,
                            session,
                            rejection_start,
                            observations.len(),
                            &mut route_rejections,
                            &mut adapter_bytes,
                            &limits,
                        )?;
                        if let Some(decision) = receipt.continuity {
                            // Admit the complete borrowed carrier and packet mappings before
                            // copying any scope, metadata or decision into the source archive.
                            let charge = 1024usize
                                .saturating_add(192)
                                .saturating_add(event_metadata.record_id.len())
                                .saturating_add(decision.reason.len())
                                .saturating_add(event_metadata.source_id.len())
                                .saturating_add(event_metadata.record_id.len())
                                .saturating_add(event_metadata.peer.as_ref().map_or(0, String::len))
                                .saturating_add(
                                    event_metadata.local.as_ref().map_or(0, String::len),
                                )
                                .saturating_add(256)
                                .saturating_add(decision.retained_charge())
                                .saturating_add(256)
                                .saturating_add(bytes.spans().len().saturating_mul(512));
                            source_event_admission(
                                charge,
                                source_events.len(),
                                1,
                                source_event_spans,
                                bytes.spans().len(),
                                adapter_bytes,
                                &limits,
                            )?;
                            let event = CapturedSourceEvent {
                                kind: if decision.is_reset() {
                                    CapturedSourceEventKind::DecodedReset
                                } else {
                                    CapturedSourceEventKind::DecodedGap
                                },
                                source_record_index: records,
                                journal_record_sha256: actual,
                                source_start: offset,
                                source_end: consumed,
                                scopes: vec![event_scope],
                                record_id: Some(event_metadata.record_id.clone()),
                                cause: Some(decision.reason.clone()),
                                packet_spans: Vec::new(),
                                metadata: Some(event_metadata),
                                continuity: Some(CapturedDecodedContinuity {
                                    observation_index: observations.len(),
                                    observation_sha256: observation.sha256(),
                                    decision,
                                }),
                            };
                            retain_source_event(
                                event,
                                Some(bytes.spans()),
                                &mut source_events,
                                &mut source_event_spans,
                                &mut adapter_bytes,
                                &limits,
                            )?;
                        }
                        latest_observations.insert(key, observation.sha256());
                        observation_evidence.push(CapturedObservationEvidence {
                            lifecycle: *lifecycles.get(&session).unwrap_or(&0),
                            journal_record_sha256: actual,
                            source_record_index: records,
                            source_start: offset,
                            source_end: consumed,
                        });
                        observations.push(observation);
                    }
                    Err(error) if error.code == ErrorCode::LimitExceeded => return Err(error),
                    Err(error) => {
                        let event = CapturedSourceEvent {
                            kind: CapturedSourceEventKind::RejectedContainer,
                            source_record_index: records,
                            journal_record_sha256: actual,
                            source_start: offset,
                            source_end: consumed,
                            scopes: vec![event_scope],
                            record_id: Some(event_metadata.record_id.clone()),
                            cause: Some(format!("{:?}", error.code)),
                            packet_spans: Vec::new(),
                            metadata: Some(event_metadata),
                            continuity: None,
                        };
                        // Charge borrowed packet mappings before copying them into the retained event.
                        retain_source_event(
                            event,
                            Some(bytes.spans()),
                            &mut source_events,
                            &mut source_event_spans,
                            &mut adapter_bytes,
                            &limits,
                        )?;
                        rejected_records =
                            checked_increment(rejected_records, "bgp_journal_rejected_records")?;
                        // A rejected source record cannot prove continuous
                        // candidate state. Retain its sealed bytes and mark only
                        // the known session as gapped; never invent withdrawal.
                        manager.observe_gap(
                            session,
                            format!("journal-rejected-message:{}", sha256::hex(&actual)),
                            "sealed_source_message_rejected".into(),
                        )?;
                    }
                }
            }
            GAP | RESET => {
                let session = decoder.u64()?;
                let record_id = decoder.text("bgp_journal_record_id")?;
                let reason = decoder.text("bgp_journal_reason")?;
                decoder.finish()?;
                boundaries = checked_increment(boundaries, "bgp_journal_boundaries")?;
                let event = CapturedSourceEvent {
                    kind: if kind == GAP {
                        CapturedSourceEventKind::Gap
                    } else {
                        CapturedSourceEventKind::Reset
                    },
                    source_record_index: records,
                    journal_record_sha256: actual,
                    source_start: offset,
                    source_end: consumed,
                    scopes: vec![CapturedSourceScope {
                        session,
                        lifecycle: *lifecycles.get(&session).unwrap_or(&0),
                        generation: manager.wire_state(session).map(|v| v.generation()),
                    }],
                    record_id: Some(record_id.clone()),
                    cause: Some(reason.clone()),
                    packet_spans: Vec::new(),
                    metadata: None,
                    continuity: None,
                };
                retain_source_event(
                    event,
                    None,
                    &mut source_events,
                    &mut source_event_spans,
                    &mut adapter_bytes,
                    &limits,
                )?;
                let result = if kind == GAP {
                    manager.observe_gap(session, record_id, reason)
                } else {
                    manager.reset_generation(session, record_id, reason)
                };
                if let Err(error) = result {
                    if error.code == ErrorCode::LimitExceeded {
                        return Err(error);
                    }
                    rejected_records =
                        checked_increment(rejected_records, "bgp_journal_rejected_records")?;
                }
            }
            END => {
                let session = decoder.u64()?;
                decoder.finish()?;
                retain_source_event(
                    CapturedSourceEvent {
                        kind: CapturedSourceEventKind::EndSession,
                        source_record_index: records,
                        journal_record_sha256: actual,
                        source_start: offset,
                        source_end: consumed,
                        scopes: vec![CapturedSourceScope {
                            session,
                            lifecycle: *lifecycles.get(&session).unwrap_or(&0),
                            generation: manager.wire_state(session).map(|v| v.generation()),
                        }],
                        record_id: None,
                        cause: None,
                        packet_spans: Vec::new(),
                        metadata: None,
                        continuity: None,
                    },
                    None,
                    &mut source_events,
                    &mut source_event_spans,
                    &mut adapter_bytes,
                    &limits,
                )?;
                retain_entries(
                    &manager,
                    session,
                    &mut route_entries,
                    &mut route_entry_evidence,
                    CapturedSelection {
                        lifecycle: *lifecycles.get(&session).unwrap_or(&0),
                        current: false,
                    },
                    &mut adapter_bytes,
                    &limits,
                )?;
                if let Some(snapshot) = manager.end_session_snapshot(session) {
                    retain_snapshot(&mut sessions, snapshot, &mut adapter_bytes, &limits)?;
                }
                advance_lifecycle(
                    session,
                    &mut lifecycles,
                    &mut latest_observations,
                    &mut adapter_bytes,
                    &limits,
                )?;
            }
            CLEAR => {
                decoder.finish()?;
                let scope_count = manager.active_sessions();
                admit_clear_scopes(scope_count, source_events.len(), adapter_bytes, &limits)?;
                let cleared_sessions = manager.session_ids();
                let scopes = cleared_sessions
                    .iter()
                    .copied()
                    .map(|session| CapturedSourceScope {
                        session,
                        lifecycle: *lifecycles.get(&session).unwrap_or(&0),
                        generation: manager.wire_state(session).map(|v| v.generation()),
                    })
                    .collect();
                retain_source_event(
                    CapturedSourceEvent {
                        kind: CapturedSourceEventKind::Clear,
                        source_record_index: records,
                        journal_record_sha256: actual,
                        source_start: offset,
                        source_end: consumed,
                        scopes,
                        record_id: None,
                        cause: None,
                        packet_spans: Vec::new(),
                        metadata: None,
                        continuity: None,
                    },
                    None,
                    &mut source_events,
                    &mut source_event_spans,
                    &mut adapter_bytes,
                    &limits,
                )?;
                for session in cleared_sessions {
                    retain_entries(
                        &manager,
                        session,
                        &mut route_entries,
                        &mut route_entry_evidence,
                        CapturedSelection {
                            lifecycle: *lifecycles.get(&session).unwrap_or(&0),
                            current: false,
                        },
                        &mut adapter_bytes,
                        &limits,
                    )?;
                    advance_lifecycle(
                        session,
                        &mut lifecycles,
                        &mut latest_observations,
                        &mut adapter_bytes,
                        &limits,
                    )?;
                }
                for snapshot in manager.clear_snapshots() {
                    retain_snapshot(&mut sessions, snapshot, &mut adapter_bytes, &limits)?;
                }
            }
            SEAL => {
                let declared = decoder.u64()?;
                decoder.finish()?;
                if declared != records || consumed != metadata.len() {
                    return Err(Error::new(
                        ErrorCode::LengthMismatch,
                        offset,
                        "bgp_journal_seal",
                        "seal count differs or trailing bytes remain",
                    ));
                }
                terminal = chain;
                break;
            }
            _ => {
                return Err(Error::new(
                    ErrorCode::UnsupportedVersion,
                    offset,
                    "bgp_journal_record_kind",
                    "unknown record kind",
                ));
            }
        }
        records = checked_increment(records, "bgp_journal_records")?;
    }
    for session in manager.session_ids() {
        retain_entries(
            &manager,
            session,
            &mut route_entries,
            &mut route_entry_evidence,
            CapturedSelection {
                lifecycle: *lifecycles.get(&session).unwrap_or(&0),
                current: true,
            },
            &mut adapter_bytes,
            &limits,
        )?;
    }
    for snapshot in manager.clear_snapshots() {
        retain_snapshot(&mut sessions, snapshot, &mut adapter_bytes, &limits)?;
    }
    Ok(ReplayArchive {
        receipt: JournalReceipt {
            source_id,
            capture_namespace,
            records,
            terminal_sha256: terminal,
        },
        sessions,
        messages,
        boundaries,
        rejected_records,
        route_entries,
        route_rejections,
        observations,
        route_entry_evidence,
        observation_evidence,
        source_events,
    })
}

fn admit_clear_scopes(
    scope_count: usize,
    event_count: usize,
    retained: usize,
    limits: &Limits,
) -> Result<()> {
    let prospective = scope_count
        .checked_mul(192)
        .and_then(|v| v.checked_add(1024))
        .and_then(|v| v.checked_mul(6))
        .and_then(|v| retained.checked_add(v))
        .ok_or_else(|| Error::limit("bgp_journal_source_events"))?;
    if scope_count > limits.elements
        || event_count >= limits.elements
        || prospective > limits.retained_bytes
        || prospective > limits.work
    {
        return Err(Error::limit("bgp_journal_source_events"));
    }
    Ok(())
}

fn source_event_admission(
    size: usize,
    event_count: usize,
    scope_count: usize,
    span_count: usize,
    additional_spans: usize,
    retained: usize,
    limits: &Limits,
) -> Result<(usize, usize)> {
    let next_spans = span_count
        .checked_add(additional_spans)
        .ok_or_else(|| Error::limit("bgp_journal_source_events"))?;
    let next_retained = size
        .checked_mul(6)
        .and_then(|v| v.checked_add(retained))
        .ok_or_else(|| Error::limit("bgp_journal_source_events"))?;
    if event_count >= limits.elements
        || scope_count > limits.elements
        || next_spans > limits.spans
        || next_retained > limits.retained_bytes
        || next_retained > limits.work
    {
        return Err(Error::limit("bgp_journal_source_events"));
    }
    Ok((next_retained, next_spans))
}

fn retain_source_event(
    mut event: CapturedSourceEvent,
    spans: Option<&[SourceSpan]>,
    events: &mut Vec<CapturedSourceEvent>,
    span_count: &mut usize,
    retained: &mut usize,
    limits: &Limits,
) -> Result<()> {
    let borrowed_spans = spans.unwrap_or(&[]);
    let size = event.retained_charge();
    let charge = size
        .checked_add(borrowed_spans.len().saturating_mul(512))
        .ok_or_else(|| Error::limit("bgp_journal_source_events"))?;
    let (next_retained, next_spans) = source_event_admission(
        charge,
        events.len(),
        event.scopes.len(),
        *span_count,
        borrowed_spans.len(),
        *retained,
        limits,
    )?;
    *retained = next_retained;
    *span_count = next_spans;
    event.packet_spans = borrowed_spans.to_vec();
    events.push(event);
    Ok(())
}

fn advance_lifecycle(
    session: u64,
    lifecycles: &mut BTreeMap<u64, u64>,
    latest: &mut BTreeMap<(u64, String), [u8; 32]>,
    retained: &mut usize,
    limits: &Limits,
) -> Result<()> {
    if !lifecycles.contains_key(&session) {
        if lifecycles.len() >= limits.elements {
            return Err(Error::limit("bgp_journal_lifecycles"));
        }
        *retained = retained
            .checked_add(64)
            .ok_or_else(|| Error::limit("bgp_journal_adapter"))?;
        if *retained > limits.retained_bytes || *retained > limits.work {
            return Err(Error::limit("bgp_journal_adapter"));
        }
    }
    let next = lifecycles
        .get(&session)
        .copied()
        .unwrap_or(0)
        .checked_add(1)
        .ok_or_else(|| Error::limit("bgp_journal_lifecycles"))?;
    lifecycles.insert(session, next);
    latest.retain(|(id, _), _| *id != session);
    Ok(())
}

struct CapturedSelection {
    lifecycle: u64,
    current: bool,
}

fn retain_entries(
    manager: &CapturedSessionManager,
    session: u64,
    entries: &mut Vec<super::bgp_rib::RouteEntry>,
    evidence: &mut Vec<CapturedEntryEvidence>,
    selection: CapturedSelection,
    bytes: &mut usize,
    limits: &Limits,
) -> Result<()> {
    if let Some(rib) = manager.rib(session) {
        // Every retained native origin and current-origin receipt consumes an
        // aggregate element before snapshot copies, including prior lifecycles.
        let mut origin_elements = entries.iter().try_fold(entries.len(), |n, entry| {
            entry.versions.iter().try_fold(n, |n, version| {
                n.checked_add(version.occurrences.len())
                    .ok_or_else(|| Error::limit("bgp_journal_adapter"))
            })
        })?;
        origin_elements = evidence.iter().try_fold(origin_elements, |n, e| {
            n.checked_add(e.observation_sha256.len())
                .ok_or_else(|| Error::limit("bgp_journal_adapter"))
        })?;
        for entry in rib.entries().values() {
            let mut size = entry
                .key
                .scope
                .source
                .source_id
                .len()
                .saturating_add(entry.key.scope.source.partition_id.len())
                .saturating_add(entry.key.scope.session.len())
                .saturating_add(entry.key.scope.peer.as_ref().map_or(0, String::len))
                .saturating_add(entry.key.prefix.address.len())
                .saturating_add(entry.last_witness.len())
                .saturating_add(512);
            for version in &entry.versions {
                size = size
                    .checked_add(
                        version
                            .attributes
                            .encoded_len_bounded(limits.retained_bytes)?
                            .saturating_mul(3),
                    )
                    .and_then(|n| n.checked_add(version.attribute_identity.len()))
                    .and_then(|n| {
                        version
                            .occurrences
                            .len()
                            .checked_mul(128)
                            .and_then(|charge| n.checked_add(charge))
                    })
                    .and_then(|n| {
                        n.checked_add(
                            version
                                .witnesses
                                .iter()
                                .map(|v| v.len().saturating_add(32))
                                .sum::<usize>(),
                        )
                    })
                    .ok_or_else(|| Error::limit("bgp_journal_adapter"))?;
            }
            let witness_count: usize = entry
                .versions
                .iter()
                .filter(|v| v.disposition == super::bgp_rib::VersionDisposition::Current)
                .try_fold(0usize, |n, v| {
                    n.checked_add(v.occurrences.len())
                        .ok_or_else(|| Error::limit("bgp_journal_adapter"))
                })?;
            size = size
                .saturating_add(96)
                .saturating_add(witness_count.saturating_mul(32));
            origin_elements = entry
                .versions
                .iter()
                .try_fold(origin_elements, |n, version| {
                    n.checked_add(version.occurrences.len())
                        .ok_or_else(|| Error::limit("bgp_journal_adapter"))
                })?
                .checked_add(1)
                .and_then(|n| n.checked_add(witness_count))
                .ok_or_else(|| Error::limit("bgp_journal_adapter"))?;
            if origin_elements > limits.elements {
                return Err(Error::limit("bgp_journal_adapter"));
            }
            *bytes = bytes
                .checked_add(size)
                .ok_or_else(|| Error::limit("bgp_journal_adapter"))?;
            if entries.len() >= limits.elements
                || *bytes > limits.retained_bytes
                || *bytes > limits.work
            {
                return Err(Error::limit("bgp_journal_adapter"));
            }
            let observation_sha256 = entry
                .versions
                .iter()
                .filter(|v| v.disposition == super::bgp_rib::VersionDisposition::Current)
                .flat_map(|v| v.occurrences.iter())
                .map(|origin| origin.observation_sha256)
                .collect();
            entries.push(entry.clone());
            evidence.push(CapturedEntryEvidence {
                lifecycle: selection.lifecycle,
                current: selection.current,
                observation_sha256,
            });
        }
    }
    Ok(())
}

fn retain_rejections(
    manager: &CapturedSessionManager,
    session: u64,
    start: usize,
    observation_index: usize,
    rejections: &mut Vec<CapturedRejection>,
    retained: &mut usize,
    limits: &Limits,
) -> Result<()> {
    if let Some(rib) = manager.rib(session) {
        let added = rib.rejections().get(start..).ok_or_else(|| {
            bad(
                "bgp_journal_rejection",
                0,
                "native rejection history shortened",
            )
        })?;
        for rejection in added {
            let size = rejection
                .key
                .scope
                .source
                .source_id
                .len()
                .saturating_add(rejection.key.scope.source.partition_id.len())
                .saturating_add(rejection.key.scope.session.len())
                .saturating_add(rejection.key.scope.peer.as_ref().map_or(0, String::len))
                .saturating_add(rejection.key.prefix.address.len())
                .saturating_add(rejection.record_id.len())
                .saturating_add(rejection.reason.len())
                .saturating_add(2048)
                .saturating_mul(3);
            *retained = retained
                .checked_add(size)
                .ok_or_else(|| Error::limit("bgp_journal_adapter"))?;
            if rejections.len() >= limits.elements
                || *retained > limits.retained_bytes
                || *retained > limits.work
            {
                return Err(Error::limit("bgp_journal_adapter"));
            }
            // Retain before END/CLEAR can drop the owning session. Rejections
            // are always historical and cannot change an accepted entry.
            rejections.push(CapturedRejection {
                rejection: rejection.clone(),
                observation_index,
            });
        }
    }
    Ok(())
}

fn retain_snapshot(
    sessions: &mut Vec<SessionSnapshot>,
    snapshot: SessionSnapshot,
    retained: &mut usize,
    limits: &Limits,
) -> Result<()> {
    if sessions.len() >= limits.elements {
        return Err(Error::limit("bgp_journal_sessions"));
    }
    *retained = retained
        .checked_add(
            snapshot
                .state
                .encoded_len_bounded(limits.retained_bytes)?
                .saturating_mul(3),
        )
        .ok_or_else(|| Error::limit("bgp_journal_adapter"))?;
    if *retained > limits.retained_bytes || *retained > limits.work {
        return Err(Error::limit("bgp_journal_adapter"));
    }
    sessions.push(snapshot);
    Ok(())
}

fn record_digest(kind: u8, length: u64, previous: &[u8; 32], body: &[u8]) -> [u8; 32] {
    let mut digest = sha256::Sha256::new();
    digest.update(RECORD_DOMAIN);
    digest.update(&[kind]);
    digest.update(&length.to_le_bytes());
    digest.update(previous);
    digest.update(body);
    digest.finalize()
}

fn read_exact_at(
    file: &mut File,
    bytes: &mut [u8],
    consumed: &mut u64,
    field: &'static str,
) -> Result<()> {
    file.read_exact(bytes).map_err(|error| {
        if error.kind() == std::io::ErrorKind::UnexpectedEof {
            Error::new(
                ErrorCode::Truncated,
                *consumed,
                field,
                "unexpected end of journal",
            )
        } else {
            Error::io(error)
        }
    })?;
    *consumed = consumed
        .checked_add(as_u64(bytes.len(), "bgp_journal_bytes")?)
        .ok_or_else(|| Error::limit("bgp_journal_bytes"))?;
    Ok(())
}

fn read_text(
    file: &mut File,
    consumed: &mut u64,
    limits: &Limits,
    field: &'static str,
) -> Result<String> {
    let mut length = [0u8; 4];
    read_exact_at(file, &mut length, consumed, field)?;
    let length = usize::try_from(u32::from_le_bytes(length)).expect("u32 fits usize");
    if length == 0 || length > limits.input_bytes.min(4096) {
        return Err(Error::limit(field));
    }
    let mut value = vec![0u8; length];
    read_exact_at(file, &mut value, consumed, field)?;
    let value = String::from_utf8(value).map_err(|_| {
        bad(
            field,
            usize::try_from(*consumed).unwrap_or(usize::MAX),
            "journal text is not UTF-8",
        )
    })?;
    check_text(&value, limits, field)?;
    Ok(value)
}

fn check_text(value: &str, limits: &Limits, field: &'static str) -> Result<()> {
    if value.is_empty()
        || value.len() > limits.input_bytes.min(4096)
        || value.chars().any(char::is_control)
    {
        return Err(bad(field, 0, "nonempty bounded text required"));
    }
    Ok(())
}

fn check_optional_text(value: &Option<String>, limits: &Limits) -> Result<()> {
    if let Some(value) = value {
        check_text(value, limits, "bgp_journal_optional_text")?;
    }
    Ok(())
}

fn as_u32(value: usize, field: &'static str) -> Result<u32> {
    u32::try_from(value).map_err(|_| Error::limit(field))
}

fn as_u64(value: usize, field: &'static str) -> Result<u64> {
    u64::try_from(value).map_err(|_| Error::limit(field))
}

fn checked_increment(value: u64, field: &'static str) -> Result<u64> {
    value.checked_add(1).ok_or_else(|| Error::limit(field))
}

#[derive(Default)]
struct Encoder(Vec<u8>);

impl Encoder {
    fn u8(&mut self, value: u8) {
        self.0.push(value);
    }
    fn u16(&mut self, value: u16) {
        self.0.extend_from_slice(&value.to_le_bytes());
    }
    fn u32(&mut self, value: u32) {
        self.0.extend_from_slice(&value.to_le_bytes());
    }
    fn u64(&mut self, value: u64) {
        self.0.extend_from_slice(&value.to_le_bytes());
    }
    fn i64(&mut self, value: i64) {
        self.0.extend_from_slice(&value.to_le_bytes());
    }
    fn bytes(&mut self, value: &[u8]) {
        self.0.extend_from_slice(value);
    }
    fn blob(&mut self, value: &[u8]) -> Result<()> {
        self.u32(as_u32(value.len(), "bgp_journal_blob")?);
        self.bytes(value);
        Ok(())
    }
    fn text(&mut self, value: &str) -> Result<()> {
        self.blob(value.as_bytes())
    }
    fn option_u8(&mut self, value: Option<u8>) {
        self.u8(value.unwrap_or(u8::MAX));
    }
    fn option_i64(&mut self, value: Option<i64>) {
        match value {
            Some(value) => {
                self.u8(1);
                self.i64(value);
            }
            None => self.u8(0),
        }
    }
    fn option_text(&mut self, value: Option<&str>) -> Result<()> {
        match value {
            Some(value) => {
                self.u8(1);
                self.text(value)?;
            }
            None => self.u8(0),
        }
        Ok(())
    }
    fn finish(self) -> Vec<u8> {
        self.0
    }
}

struct Decoder<'a> {
    bytes: &'a [u8],
    at: usize,
    limits: &'a Limits,
}

impl<'a> Decoder<'a> {
    fn new(bytes: &'a [u8], limits: &'a Limits) -> Self {
        Self {
            bytes,
            at: 0,
            limits,
        }
    }
    fn take(&mut self, count: usize, field: &'static str) -> Result<&'a [u8]> {
        let end = self
            .at
            .checked_add(count)
            .filter(|end| *end <= self.bytes.len())
            .ok_or_else(|| bad(field, self.at, "record body is truncated"))?;
        let out = &self.bytes[self.at..end];
        self.at = end;
        Ok(out)
    }
    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1, "bgp_journal_integer")?[0])
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(
            self.take(4, "bgp_journal_integer")?
                .try_into()
                .expect("fixed slice"),
        ))
    }
    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(
            self.take(8, "bgp_journal_integer")?
                .try_into()
                .expect("fixed slice"),
        ))
    }
    fn i64(&mut self) -> Result<i64> {
        Ok(i64::from_le_bytes(
            self.take(8, "bgp_journal_integer")?
                .try_into()
                .expect("fixed slice"),
        ))
    }
    fn blob(&mut self, field: &'static str) -> Result<&'a [u8]> {
        let length = usize::try_from(self.u32()?).expect("u32 fits usize");
        if length > self.limits.input_bytes {
            return Err(Error::limit(field));
        }
        self.take(length, field)
    }
    fn text(&mut self, field: &'static str) -> Result<String> {
        let value = std::str::from_utf8(self.blob(field)?)
            .map_err(|_| bad(field, self.at, "journal text is not UTF-8"))?
            .to_owned();
        check_text(&value, self.limits, field)?;
        Ok(value)
    }
    fn option_u8(&mut self) -> Result<Option<u8>> {
        match self.u8()? {
            u8::MAX => Ok(None),
            value => Ok(Some(value)),
        }
    }
    fn option_i64(&mut self) -> Result<Option<i64>> {
        match self.u8()? {
            0 => Ok(None),
            1 => Ok(Some(self.i64()?)),
            _ => Err(bad(
                "bgp_journal_option",
                self.at,
                "invalid optional integer marker",
            )),
        }
    }
    fn option_text(&mut self) -> Result<Option<String>> {
        match self.u8()? {
            0 => Ok(None),
            1 => Ok(Some(self.text("bgp_journal_optional_text")?)),
            _ => Err(bad(
                "bgp_journal_option",
                self.at,
                "invalid optional text marker",
            )),
        }
    }
    fn message(
        &mut self,
        source_id: &str,
        capture_namespace: [u8; 32],
    ) -> Result<(u64, EvidenceBytes, PcapMetadata)> {
        let session = self.u64()?;
        let direction = self.option_u8()?;
        if direction.is_some_and(|value| value > 1) {
            return Err(bad(
                "bgp_journal_direction",
                self.at,
                "direction must be zero, one, or absent",
            ));
        }
        let record_id = self.text("bgp_journal_record_id")?;
        let observed_at_ns = self.option_i64()?;
        let peer = self.option_text()?;
        let local = self.option_text()?;
        let data = self.blob("bgp_journal_message")?.to_vec();
        if data.is_empty() {
            return Err(bad(
                "bgp_journal_message",
                self.at,
                "empty BGP message evidence",
            ));
        }
        let span_count = usize::try_from(self.u32()?).expect("u32 fits usize");
        if span_count == 0 || span_count > self.limits.spans {
            return Err(Error::limit("bgp_journal_spans"));
        }
        let mut spans = Vec::with_capacity(span_count);
        for _ in 0..span_count {
            let start =
                usize::try_from(self.u64()?).map_err(|_| Error::limit("bgp_journal_span"))?;
            let end = usize::try_from(self.u64()?).map_err(|_| Error::limit("bgp_journal_span"))?;
            let mut capture = [0u8; 32];
            capture.copy_from_slice(self.take(32, "bgp_journal_capture")?);
            let frame = self.u64()?;
            let record_offset = self.u64()?;
            let packet_start =
                usize::try_from(self.u64()?).map_err(|_| Error::limit("bgp_journal_span"))?;
            spans.push(SourceSpan {
                start,
                end,
                packet: PacketId {
                    capture,
                    frame,
                    record_offset,
                },
                packet_start,
            });
        }
        let evidence = rebuild_evidence(&data, &spans, capture_namespace, self.limits)?;
        Ok((
            session,
            evidence,
            PcapMetadata {
                source_id: source_id.to_owned(),
                record_id,
                observed_at_ns,
                session: Some(session),
                direction,
                peer,
                local,
            },
        ))
    }
    fn finish(&self) -> Result<()> {
        if self.at != self.bytes.len() {
            return Err(bad("bgp_journal_record", self.at, "trailing record bytes"));
        }
        Ok(())
    }
}

fn rebuild_evidence(
    data: &[u8],
    spans: &[SourceSpan],
    capture_namespace: [u8; 32],
    limits: &Limits,
) -> Result<EvidenceBytes> {
    let mut evidence = EvidenceBytes::default();
    let mut cursor = 0usize;
    for span in spans {
        if span.start != cursor
            || span.end <= span.start
            || span.end > data.len()
            || span.packet.capture != capture_namespace
        {
            return Err(bad(
                "bgp_journal_provenance",
                0,
                "invalid or foreign packet-span layout",
            ));
        }
        let piece =
            EvidenceBytes::from_packet(&data[span.start..span.end], span.packet, span.packet_start);
        evidence.append(&piece, limits.input_bytes)?;
        cursor = span.end;
    }
    if cursor != data.len() || !evidence.validate() {
        return Err(bad(
            "bgp_journal_provenance",
            0,
            "packet spans do not cover message bytes",
        ));
    }
    Ok(evidence)
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
            "pcap-bgp-journal-{label}-{}-{nonce}",
            std::process::id()
        ))
    }

    fn keepalive(namespace: [u8; 32]) -> EvidenceBytes {
        let mut bytes = vec![0xff; 16];
        bytes.extend_from_slice(&[0, 19, 4]);
        EvidenceBytes::from_packet(
            &bytes,
            PacketId {
                capture: namespace,
                frame: 7,
                record_offset: 91,
            },
            40,
        )
    }

    #[test]
    fn sealed_journal_replays_in_fresh_state() {
        let path = path("roundtrip");
        let namespace = [3; 32];
        let mut writer = JournalWriter::create(
            &path,
            "capture-a".into(),
            namespace,
            1024 * 1024,
            Limits::default(),
        )
        .unwrap();
        writer
            .message(
                9,
                &keepalive(namespace),
                &PcapMetadata {
                    source_id: "capture-a".into(),
                    record_id: "record-1".into(),
                    observed_at_ns: Some(17),
                    session: Some(9),
                    direction: Some(0),
                    peer: None,
                    local: None,
                },
            )
            .unwrap();
        writer.gap(9, "gap-1", "missing bytes").unwrap();
        writer.end_session(9).unwrap();
        let receipt = writer.seal().unwrap();
        let archive = replay(&path, 1024 * 1024, Limits::default()).unwrap();
        assert_eq!(archive.receipt, receipt);
        assert_eq!(archive.messages, 1);
        assert_eq!(archive.boundaries, 1);
        assert_eq!(archive.sessions.len(), 1);
        assert_eq!(archive.sessions[0].session, 9);
        assert_eq!(archive.sessions[0].summary.gaps, 1);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn changed_body_and_unsealed_journal_are_rejected() {
        let path = path("corrupt");
        let namespace = [4; 32];
        let mut writer = JournalWriter::create(
            &path,
            "capture-b".into(),
            namespace,
            1024 * 1024,
            Limits::default(),
        )
        .unwrap();
        writer.clear().unwrap();
        drop(writer);
        assert!(replay(&path, 1024 * 1024, Limits::default()).is_err());
        let mut bytes = std::fs::read(&path).unwrap();
        *bytes.last_mut().unwrap() ^= 1;
        std::fs::write(&path, bytes).unwrap();
        assert!(replay(&path, 1024 * 1024, Limits::default()).is_err());
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn every_truncation_and_trailing_bytes_are_rejected() {
        let complete = path("complete");
        let probe = path("probe");
        let mut writer = JournalWriter::create(
            &complete,
            "capture-c".into(),
            [5; 32],
            1024 * 1024,
            Limits::default(),
        )
        .unwrap();
        writer.clear().unwrap();
        writer.seal().unwrap();
        let bytes = std::fs::read(&complete).unwrap();
        for cut in 0..bytes.len() {
            std::fs::write(&probe, &bytes[..cut]).unwrap();
            assert!(
                replay(&probe, 1024 * 1024, Limits::default()).is_err(),
                "truncation at {cut} was accepted"
            );
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        std::fs::write(&probe, trailing).unwrap();
        assert!(replay(&probe, 1024 * 1024, Limits::default()).is_err());
        std::fs::remove_file(complete).unwrap();
        std::fs::remove_file(probe).unwrap();
    }
}

#[cfg(test)]
mod source_event_admission_tests {
    use super::*;
    #[test]
    fn clear_scopes_admit_exact_charge_and_reject_each_one_below_before_collection() {
        let charge = (1024 + 4 * 192) * 6;
        let mut l = Limits {
            elements: 4,
            retained_bytes: charge,
            work: charge,
            ..Limits::default()
        };
        admit_clear_scopes(4, 0, 0, &l).unwrap();
        l.retained_bytes = charge - 1;
        assert!(admit_clear_scopes(4, 0, 0, &l).is_err());
        l.retained_bytes = charge;
        l.work = charge - 1;
        assert!(admit_clear_scopes(4, 0, 0, &l).is_err());
        l.work = charge;
        l.elements = 3;
        assert!(admit_clear_scopes(4, 0, 0, &l).is_err());
        l.elements = 4;
        assert!(admit_clear_scopes(4, 4, 0, &l).is_err());
    }
}

#[cfg(test)]
mod decoded_continuity_budget_tests {
    use super::*;
    #[test]
    fn decoded_source_projection_matches_actual_nodes_and_depth() {
        let source = super::super::bgp_session::SourcePartition {
            kind: super::super::bgp_session::PartitionKind::Captured,
            source_id: "capture".into(),
            partition_id: "capture-namespace-sha256:test".into(),
        };
        let event = CapturedSourceEvent {
            kind: CapturedSourceEventKind::DecodedGap,
            source_record_index: 1,
            journal_record_sha256: [1; 32],
            source_start: 4,
            source_end: 9,
            scopes: vec![CapturedSourceScope {
                session: 1,
                lifecycle: 0,
                generation: Some(0),
            }],
            record_id: Some("gap".into()),
            cause: Some("opaque".into()),
            packet_spans: vec![SourceSpan {
                start: 0,
                end: 1,
                packet_start: 0,
                packet: PacketId {
                    capture: [1; 32],
                    frame: 2,
                    record_offset: 0,
                },
            }],
            metadata: Some(PcapMetadata {
                source_id: "capture".into(),
                record_id: "gap".into(),
                session: Some(1),
                direction: Some(0),
                peer: None,
                local: None,
                observed_at_ns: None,
            }),
            continuity: Some(CapturedDecodedContinuity {
                observation_index: 0,
                observation_sha256: [2; 32],
                decision: super::super::bgp_pipeline::DecodedContinuity {
                    scope: super::super::bgp_rib::RibScope {
                        source,
                        session: "1".into(),
                        generation: 0,
                        direction: Some(0),
                        peer: None,
                    },
                    reason: "opaque".into(),
                    native_status: Some(super::super::bgp_rib::ApplyStatus::Applied),
                    session_status: super::super::bgp_session::ApplyStatus::Applied,
                    newly_applied: true,
                    kind: super::super::bgp_rib::NativeContinuityKind::Gap,
                    effect: super::super::bgp_rib::NativeContinuityEffect::SessionGeneration,
                },
            }),
        };
        fn measure(value: &Json, depth: usize) -> (usize, usize) {
            let children = match value {
                Json::Object(v) => v.iter().map(|(_, v)| v).collect::<Vec<_>>(),
                Json::Array(v) => v.iter().collect(),
                _ => Vec::new(),
            };
            children
                .into_iter()
                .fold((1, depth), |(nodes, max_depth), child| {
                    let (n, d) = measure(child, depth + 1);
                    (nodes + n, max_depth.max(d))
                })
        }
        let (nodes, depth) = measure(&event.json(), 1);
        assert_eq!(event.projection_nodes(), nodes);
        assert_eq!(event.projection_depth(), depth);
        let limits = Limits {
            fields: nodes,
            depth,
            ..Limits::default()
        };
        super::super::bgp_state::tree_budget(&event.json(), &limits).unwrap();
        for l in [
            Limits {
                fields: nodes - 1,
                ..limits.clone()
            },
            Limits {
                depth: depth - 1,
                ..limits.clone()
            },
        ] {
            assert_eq!(
                super::super::bgp_state::tree_budget(&event.json(), &l)
                    .err()
                    .expect("one-below projection must reject")
                    .code,
                ErrorCode::LimitExceeded
            );
        }
    }
    #[test]
    fn legacy_source_projection_scopes_and_empty_envelope_have_exact_depth() {
        fn actual_depth(value: &Json) -> usize {
            match value {
                Json::Object(fields) => {
                    1 + fields
                        .iter()
                        .map(|(_, v)| actual_depth(v))
                        .max()
                        .unwrap_or(0)
                }
                Json::Array(items) => 1 + items.iter().map(actual_depth).max().unwrap_or(0),
                _ => 1,
            }
        }
        for kind in [
            CapturedSourceEventKind::Gap,
            CapturedSourceEventKind::Reset,
            CapturedSourceEventKind::EndSession,
            CapturedSourceEventKind::Clear,
        ] {
            let mut event = CapturedSourceEvent {
                kind,
                source_record_index: 1,
                journal_record_sha256: [1; 32],
                source_start: 0,
                source_end: 1,
                scopes: vec![CapturedSourceScope {
                    session: 1,
                    lifecycle: 0,
                    generation: Some(0),
                }],
                record_id: None,
                cause: None,
                packet_spans: Vec::new(),
                metadata: None,
                continuity: None,
            };
            for scoped in [true, false] {
                if !scoped {
                    event.scopes.clear();
                }
                // Prospective depth is obtained before materializing the reference.
                let expected = if scoped { 4 } else { 2 };
                assert_eq!(event.projection_depth(), expected);
                let limits = Limits {
                    depth: expected,
                    fields: event.projection_nodes(),
                    ..Limits::default()
                };
                assert!(event.projection_depth() <= limits.depth);
                assert!(event.projection_depth() > limits.depth - 1);
                let reference = event.json();
                assert_eq!(actual_depth(&reference), expected);
                assert!(super::super::bgp_state::tree_budget(&reference, &limits).is_ok());
                assert_eq!(
                    super::super::bgp_state::tree_budget(
                        &reference,
                        &Limits {
                            depth: expected - 1,
                            ..limits
                        }
                    )
                    .err()
                    .expect("one-below legacy projection must reject")
                    .code,
                    ErrorCode::LimitExceeded
                );
                let Json::Object(fields) = &reference else {
                    panic!("source event object")
                };
                assert_eq!(
                    fields.iter().find(|(k, _)| *k == "schema").unwrap().1,
                    Json::from("pcap-evidence.bgp.captured-source-event.v1")
                );
            }
        }
    }
    #[test]
    fn decoded_source_event_charge_exact_and_one_below() {
        let size = 2048;
        let retained = 19;
        let exact = retained + size * 6;
        let limits = Limits {
            retained_bytes: exact,
            work: exact,
            spans: 3,
            elements: 2,
            ..Limits::default()
        };
        assert_eq!(
            source_event_admission(size, 1, 1, 1, 2, retained, &limits).unwrap(),
            (exact, 3)
        );
        for l in [
            Limits {
                retained_bytes: exact - 1,
                ..limits.clone()
            },
            Limits {
                work: exact - 1,
                ..limits.clone()
            },
            Limits {
                spans: 2,
                ..limits.clone()
            },
            Limits {
                elements: 1,
                ..limits.clone()
            },
        ] {
            assert_eq!(
                source_event_admission(size, 1, 1, 1, 2, retained, &l)
                    .unwrap_err()
                    .code,
                ErrorCode::LimitExceeded
            );
        }
    }
}
