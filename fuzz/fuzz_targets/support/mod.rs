#![allow(dead_code)]
use pcap_evidence::provenance::{EvidenceBytes, PacketId};
use pcap_evidence::tcp::{StreamChunk, StreamResult};
use pcap_evidence::Limits;
pub fn limits() -> Limits {
    Limits {
        max_input_bytes: 65536,
        max_block_bytes: 65536,
        max_packet_bytes: 65536,
        max_records: 512,
        max_interfaces: 32,
        max_options: 64,
        max_flows: 32,
        max_segments_per_flow: 128,
        max_stream_span: 65536,
        max_retained_payload: 65536,
        max_fragment_sets: 32,
        max_fragments_per_set: 64,
        max_protocol_messages: 128,
        max_application_bytes: 4096,
        max_labels: 16,
        max_correlation_checks: 4096,
        ..Limits::default()
    }
}
pub fn id(frame: u64) -> PacketId {
    PacketId {
        capture: [0; 32],
        frame,
        record_offset: 0,
    }
}
pub fn evidence(data: &[u8]) -> EvidenceBytes {
    EvidenceBytes::from_packet(data, id(1), 0)
}
pub fn stream(data: &[u8]) -> StreamResult {
    StreamResult {
        base_sequence: Some(0),
        anchored_by_syn: true,
        chunks: vec![StreamChunk {
            offset: 0,
            bytes: evidence(data),
        }],
        gaps: Vec::new(),
        conflicts: Vec::new(),
        duplicate_observed_bytes: 0,
    }
}
pub fn assert_source(source: &[u8], bytes: &EvidenceBytes) {
    assert!(bytes.validate());
    for span in bytes.spans() {
        let count = span.end - span.start;
        let end = span.packet_start.checked_add(count).unwrap();
        assert_eq!(span.packet, id(1));
        assert_eq!(
            &bytes.data()[span.start..span.end],
            source.get(span.packet_start..end).unwrap()
        );
    }
}
pub fn assert_dnp(source: &[u8], parsed: &pcap_evidence::dnp3::Dnp3Result) {
    for frame in &parsed.frames {
        assert_source(source, &frame.raw);
        assert_source(source, &frame.user_data);
    }
    for fragment in &parsed.fragments {
        assert_source(source, &fragment.raw);
        assert_source(source, &fragment.objects);
    }
    for message in &parsed.messages {
        assert_source(source, &message.objects);
    }
}
