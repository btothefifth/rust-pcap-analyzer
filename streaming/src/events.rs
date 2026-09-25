//! Versioned events. All 64/128-bit identities, positions and times are decimal
//! strings so JavaScript/JSON consumers cannot silently round them.
use crate::{Error, ErrorCode, Result};
use pcap_evidence::{
    json::Json,
    provenance::{EvidenceBytes, PacketId, SourceSpan},
    sha256,
};
use std::io::Write;

pub const SCHEMA: &str = "pcap-evidence.event.v1";
pub const HASH_DOMAIN: &[u8] = b"pcap-evidence/event/v1\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvidenceStatus {
    Observed,
    Candidate,
    Ambiguous,
    Incomplete,
    Unsupported,
    Rejected,
}
impl EvidenceStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Observed => "observed",
            Self::Candidate => "candidate",
            Self::Ambiguous => "ambiguous",
            Self::Incomplete => "incomplete",
            Self::Unsupported => "unsupported",
            Self::Rejected => "rejected",
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventKind {
    CaptureStart,
    CaptureComplete,
    CaptureAborted,
    Metadata,
    Packet,
    Network,
    Reassembled,
    FlowStart,
    FlowEnd,
    StreamChunk,
    StreamGap,
    StreamConflict,
    Detection,
    Message,
    ProtocolIssue,
    Transaction,
    Dnp3Confirmation,
    Diagnostic,
    Boundary,
}
impl EventKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CaptureStart => "capture.start",
            Self::CaptureComplete => "capture.complete",
            Self::CaptureAborted => "capture.aborted",
            Self::Metadata => "capture.metadata",
            Self::Packet => "packet.observed",
            Self::Network => "network.observed",
            Self::Reassembled => "network.reassembled",
            Self::FlowStart => "flow.start",
            Self::FlowEnd => "flow.end",
            Self::StreamChunk => "stream.chunk",
            Self::StreamGap => "stream.gap",
            Self::StreamConflict => "stream.conflict",
            Self::Detection => "protocol.detection",
            Self::Message => "protocol.message",
            Self::ProtocolIssue => "protocol.issue",
            Self::Transaction => "transaction.candidate",
            Self::Dnp3Confirmation => "dnp3.confirmation_candidate",
            Self::Diagnostic => "diagnostic",
            Self::Boundary => "coverage.boundary",
        }
    }
}
#[derive(Clone, Debug, Default)]
pub struct Evidence {
    /// Exact selected source-byte mapping; not alternative retransmission truth.
    pub spans: Vec<SourceSpan>,
    /// Includes contributors with no selected payload (e.g. an ACK or duplicate).
    pub packets: Vec<PacketId>,
    pub reconstructed_sha256: Option<[u8; 32]>,
    pub byte_length: usize,
}
impl Evidence {
    pub fn bytes(bytes: &EvidenceBytes) -> Self {
        Self {
            spans: bytes.spans().to_vec(),
            packets: bytes.packets(),
            reconstructed_sha256: Some(sha256::digest(bytes.data())),
            byte_length: bytes.len(),
        }
    }
    pub fn packets(mut packets: Vec<PacketId>) -> Self {
        packets.sort();
        packets.dedup();
        Self {
            packets,
            ..Self::default()
        }
    }
    pub fn json(&self) -> Json {
        Json::object([
            ("byte_length", self.byte_length.to_string().into()),
            (
                "reconstructed_sha256",
                self.reconstructed_sha256
                    .map_or(Json::Null, |h| sha256::hex(&h).into()),
            ),
            ("packets", Json::array(self.packets.iter().map(packet_ref))),
            (
                "spans",
                Json::array(self.spans.iter().map(|s| {
                    Json::object([
                        ("frame", s.packet.frame.to_string().into()),
                        ("record_offset", s.packet.record_offset.to_string().into()),
                        ("packet_start", s.packet_start.to_string().into()),
                        ("start", s.start.to_string().into()),
                        ("end", s.end.to_string().into()),
                    ])
                })),
            ),
        ])
    }
}
pub fn packet_ref(p: &PacketId) -> Json {
    // PacketId.capture is a provisional namespace internally, never a source hash.
    Json::object([
        ("frame", p.frame.to_string().into()),
        ("record_offset", p.record_offset.to_string().into()),
    ])
}
#[derive(Clone, Debug)]
pub struct Event {
    pub kind: EventKind,
    pub status: EvidenceStatus,
    /// Analysis session/window ID; NOT a claim that this is a unique TCP connection.
    pub session: Option<u64>,
    pub direction: Option<u8>,
    pub protocol: Option<String>,
    pub stream_range: Option<(i64, i64)>,
    pub related_events: Vec<u64>,
    pub evidence: Evidence,
    pub data: Json,
}
impl Event {
    pub fn new(kind: EventKind, status: EvidenceStatus, data: Json) -> Self {
        Self {
            kind,
            status,
            session: None,
            direction: None,
            protocol: None,
            stream_range: None,
            related_events: Vec::new(),
            evidence: Evidence::default(),
            data,
        }
    }
    pub fn json(&self, run_id: &str, sequence: u64) -> Json {
        Json::object([
            ("schema", SCHEMA.into()),
            ("run_id", run_id.into()),
            ("sequence", sequence.to_string().into()),
            ("kind", self.kind.as_str().into()),
            ("status", self.status.as_str().into()),
            ("source_binding", "requires_capture_complete".into()),
            (
                "session",
                self.session.map_or(Json::Null, |n| n.to_string().into()),
            ),
            ("direction", self.direction.map_or(Json::Null, Json::from)),
            (
                "protocol",
                self.protocol.clone().map_or(Json::Null, Json::from),
            ),
            (
                "stream_range",
                self.stream_range.map_or(Json::Null, |(a, b)| {
                    Json::object([
                        ("start", a.to_string().into()),
                        ("end", b.to_string().into()),
                    ])
                }),
            ),
            (
                "related_events",
                Json::array(self.related_events.iter().map(|n| n.to_string().into())),
            ),
            ("evidence", self.evidence.json()),
            ("data", self.data.clone()),
        ])
    }
}
/// A synchronous callback is intentional: a slow consumer applies backpressure.
/// Errors stop the producer. Implementations must not silently drop evidence.
pub trait EventSink {
    fn run_id(&self) -> &str;
    fn emit(&mut self, event: &Event) -> Result<u64>;
}
/// Exact-byte hash chaining detects corruption, not authorship or authenticity.
/// A source-bound replay is required to trust an index derived from this log.
pub struct NdjsonSink<W: Write> {
    writer: W,
    run_id: String,
    sequence: u64,
    previous: [u8; 32],
    limit: usize,
    failed: bool,
}
impl<W: Write> NdjsonSink<W> {
    pub fn new(writer: W, run_id: impl Into<String>, limit: usize) -> Result<Self> {
        let run_id = run_id.into();
        if run_id.is_empty()
            || run_id.len() > 128
            || run_id.chars().any(char::is_control)
            || limit < 1024
        {
            return Err(Error::new(
                ErrorCode::Usage,
                0,
                "event_sink",
                "invalid run ID or event budget",
            ));
        }
        Ok(Self {
            writer,
            run_id,
            sequence: 0,
            previous: [0; 32],
            limit,
            failed: false,
        })
    }
    pub fn finish(mut self) -> Result<W> {
        if self.failed {
            return Err(Error::new(
                ErrorCode::Io,
                0,
                "event_sink",
                "sink failed; discard partial output",
            ));
        }
        self.writer.flush()?;
        Ok(self.writer)
    }
}
impl<W: Write> EventSink for NdjsonSink<W> {
    fn run_id(&self) -> &str {
        &self.run_id
    }
    fn emit(&mut self, event: &Event) -> Result<u64> {
        if self.failed {
            return Err(Error::new(
                ErrorCode::Io,
                0,
                "event_sink",
                "sink is poisoned after an earlier failure",
            ));
        }
        let seq = self
            .sequence
            .checked_add(1)
            .ok_or_else(|| Error::limit("event_sequence"))?;
        let body = event.json(&self.run_id, seq);
        let encoded = body.encode_bounded(self.limit)?;
        let mut hash = sha256::Sha256::new();
        hash.update(HASH_DOMAIN);
        hash.update(&self.previous);
        hash.update(encoded.as_bytes());
        let digest = hash.finalize();
        let line = Json::object([
            ("event", body),
            ("previous_sha256", sha256::hex(&self.previous).into()),
            ("event_sha256", sha256::hex(&digest).into()),
        ])
        .encode_bounded_line(self.limit)?;
        let written = self.writer.write_all(line.as_bytes()).and_then(|_| {
            if matches!(
                event.kind,
                EventKind::CaptureComplete | EventKind::CaptureAborted
            ) {
                self.writer.flush()
            } else {
                Ok(())
            }
        });
        if let Err(e) = written {
            self.failed = true;
            return Err(e.into());
        }
        self.previous = digest;
        self.sequence = seq;
        Ok(seq)
    }
}
