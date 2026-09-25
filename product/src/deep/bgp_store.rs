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

#[derive(Clone, Debug)]
pub struct ReplayArchive {
    pub receipt: JournalReceipt,
    pub sessions: Vec<SessionSnapshot>,
    pub messages: u64,
    pub boundaries: u64,
    pub rejected_records: u64,
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
                if manager.apply_message(session, &bytes, metadata).is_err() {
                    rejected_records =
                        checked_increment(rejected_records, "bgp_journal_rejected_records")?;
                }
            }
            GAP | RESET => {
                let session = decoder.u64()?;
                let record_id = decoder.text("bgp_journal_record_id")?;
                let reason = decoder.text("bgp_journal_reason")?;
                decoder.finish()?;
                boundaries = checked_increment(boundaries, "bgp_journal_boundaries")?;
                let result = if kind == GAP {
                    manager.observe_gap(session, record_id, reason)
                } else {
                    manager.reset_generation(session, record_id, reason)
                };
                if result.is_err() {
                    rejected_records =
                        checked_increment(rejected_records, "bgp_journal_rejected_records")?;
                }
            }
            END => {
                let session = decoder.u64()?;
                decoder.finish()?;
                if let Some(snapshot) = manager.end_session_snapshot(session) {
                    retain_snapshot(&mut sessions, snapshot, &limits)?;
                }
            }
            CLEAR => {
                decoder.finish()?;
                for snapshot in manager.clear_snapshots() {
                    retain_snapshot(&mut sessions, snapshot, &limits)?;
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
    for snapshot in manager.clear_snapshots() {
        retain_snapshot(&mut sessions, snapshot, &limits)?;
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
    })
}

fn retain_snapshot(
    sessions: &mut Vec<SessionSnapshot>,
    snapshot: SessionSnapshot,
    limits: &Limits,
) -> Result<()> {
    if sessions.len() >= limits.elements {
        return Err(Error::limit("bgp_journal_sessions"));
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
