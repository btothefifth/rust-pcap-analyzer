use pcap_evidence::{json::Json, sha256};
use pcap_evidence_stream::{
    analyze_reader, Event, EventKind, EventSink, EvidenceStatus, Registry, Result, StreamConfig,
};
#[derive(Default)]
struct Collect {
    events: Vec<Event>,
}
impl EventSink for Collect {
    fn run_id(&self) -> &str {
        "semantic-pipeline-test"
    }
    fn emit(&mut self, e: &Event) -> Result<u64> {
        self.events.push(e.clone());
        Ok(self.events.len() as u64)
    }
}
fn capture(name: &str) -> Vec<u8> {
    std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../fixtures/semantics")
            .join(name),
    )
    .unwrap()
}
fn run(b: &[u8], c: StreamConfig) -> Collect {
    let registry = Registry::builtins(&c).unwrap();
    let mut out = Collect::default();
    let summary = analyze_reader(b, c, &registry, &mut out).unwrap();
    assert_eq!(summary.source_sha256, sha256::digest(b));
    out
}
#[test]
fn streaming_semantics_and_terminal_source_binding() {
    let b = capture("modbus_bits_valid.pcap");
    let out = run(&b, StreamConfig::default());
    assert_eq!(out.events.last().unwrap().kind, EventKind::CaptureComplete);
    assert!(out
        .events
        .iter()
        .any(|e| e.kind == EventKind::Message && e.data.encode().contains("semantic_subset")));
    assert!(out
        .events
        .iter()
        .any(|e| e.kind == EventKind::Transaction && e.status == EvidenceStatus::Candidate));
}
#[test]
fn streaming_and_snapshot_padding_decisions_agree() {
    let out = run(
        &capture("modbus_bits_bad_padding.pcap"),
        StreamConfig::default(),
    );
    assert!(out.events.iter().any(|e| e.kind == EventKind::Transaction
        && e.status == EvidenceStatus::Rejected
        && e.data.encode().contains("inconsistent_response")));
    assert!(!out
        .events
        .iter()
        .any(|e| e.kind == EventKind::Transaction && e.status == EvidenceStatus::Candidate));
}
#[test]
fn streaming_dnp_fragment_semantics_survive_tcp_segmentation() {
    let out = run(&capture("dnp3_split_valid.pcap"), StreamConfig::default());
    assert!(out.events.iter().any(|e| e.kind == EventKind::Message
        && e.protocol.as_deref() == Some("dnp3")
        && e.data.encode().contains("lsb_zero_bit_position")));
}
#[test]
fn streaming_dnp_conflicts_are_not_cleaned_up_by_semantics() {
    let out = run(
        &capture("dnp3_split_conflict.pcap"),
        StreamConfig::default(),
    );
    assert!(out
        .events
        .iter()
        .any(|e| e.kind == EventKind::StreamConflict));
    assert!(
        !out.events
            .iter()
            .any(|e| e.kind == EventKind::Message
                && e.data.encode().contains("lsb_zero_bit_position"))
    );
}
#[test]
fn streaming_default_provenance_still_reconstructs_original_message_bytes() {
    let b = capture("modbus_bits_valid.pcap");
    let out = run(&b, StreamConfig::default());
    let mut packets = std::collections::BTreeMap::new();
    for rec in pcap_evidence::capture::CaptureIter::new(
        &b,
        pcap_evidence::Limits::default(),
        pcap_evidence::capture::ParseMode::Strict,
    )
    .unwrap()
    {
        let rec = rec.unwrap();
        if let Some((m, bytes)) = rec.packet() {
            packets.insert(m.frame, bytes.to_vec());
        }
    }
    for e in out.events.iter().filter(|e| e.kind == EventKind::Message) {
        let mut raw = Vec::new();
        for s in &e.evidence.spans {
            raw.extend_from_slice(
                &packets[&s.packet.frame][s.packet_start..s.packet_start + s.end - s.start],
            );
        }
        assert_eq!(e.evidence.reconstructed_sha256, Some(sha256::digest(&raw)));
        assert!(!matches!(e.data, Json::Null));
    }
}
#[test]
fn streaming_window_cut_remains_explicit_no_cross_cut_semantic_values() {
    let c = StreamConfig {
        window_packets: 1,
        ..StreamConfig::default()
    };
    let out = run(&capture("dnp3_split_valid.pcap"), c);
    assert!(out
        .events
        .iter()
        .any(|e| e.kind == EventKind::Boundary && e.status == EvidenceStatus::Incomplete));
    assert!(
        !out.events
            .iter()
            .any(|e| e.kind == EventKind::Message
                && e.data.encode().contains("lsb_zero_bit_position"))
    );
}
