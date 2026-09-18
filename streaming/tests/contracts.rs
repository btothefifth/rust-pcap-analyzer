//! Native regression tests. Included in the handoff but NOT executed on its authoring host.
use pcap_evidence::{
    json::Json,
    protocol::{ProbeInput, ProbeResult, ProbeStrength},
    provenance::{EvidenceBytes, PacketId},
    sha256,
    wire::{internet_checksum, Scope},
};
use pcap_evidence_stream::plugin::{
    AnalyzerLimits, AnalyzerPlugin, DatagramAnalyzer, DatagramInput, Output, ProtocolDetector,
    StreamAnalyzer,
};
use pcap_evidence_stream::{
    analyze_reader, Event, EventKind, EventSink, EvidenceStatus, NdjsonSink, Registry, Result,
    StreamConfig,
};
use pcap_evidence_stream::{network, protocols};
use std::io::{self, Read, Write};

#[derive(Default)]
struct Collect {
    events: Vec<Event>,
}
impl EventSink for Collect {
    fn run_id(&self) -> &str {
        "contract-test"
    }
    fn emit(&mut self, e: &Event) -> Result<u64> {
        self.events.push(e.clone());
        Ok(self.events.len() as u64)
    }
}
fn evidence(b: &[u8]) -> EvidenceBytes {
    EvidenceBytes::from_packet(
        b,
        PacketId {
            capture: [1; 32],
            frame: 1,
            record_offset: 24,
        },
        0,
    )
}
fn scope() -> Scope {
    Scope {
        section: 0,
        interface: 0,
        vlans: vec![],
    }
}
fn dns() -> Vec<u8> {
    let mut b = vec![0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    b.extend_from_slice(b"\x07example\x04test\0\0\x01\0\x01");
    b
}
fn ipv4(protocol: u8, payload: &[u8]) -> Vec<u8> {
    let mut b = vec![0u8; 20];
    b[0] = 0x45;
    b[2..4].copy_from_slice(&((20 + payload.len()) as u16).to_be_bytes());
    b[8] = 64;
    b[9] = protocol;
    b[12..16].copy_from_slice(&[10, 0, 0, 1]);
    b[16..20].copy_from_slice(&[10, 0, 0, 2]);
    let check = internet_checksum(&b);
    b[10..12].copy_from_slice(&check.to_be_bytes());
    b.extend_from_slice(payload);
    b
}
fn ethernet(ip: &[u8]) -> Vec<u8> {
    let mut b = vec![0; 12];
    b.extend_from_slice(&[8, 0]);
    b.extend_from_slice(ip);
    b
}
fn udp(payload: &[u8], src: u16, dst: u16) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&src.to_be_bytes());
    b.extend_from_slice(&dst.to_be_bytes());
    b.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    b.extend_from_slice(&[0, 0]);
    b.extend_from_slice(payload);
    ethernet(&ipv4(17, &b))
}
fn capture(packets: &[Vec<u8>]) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes());
    b.extend_from_slice(&2u16.to_le_bytes());
    b.extend_from_slice(&4u16.to_le_bytes());
    for n in [0u32, 0, 65535, 1] {
        b.extend_from_slice(&n.to_le_bytes());
    }
    for (i, p) in packets.iter().enumerate() {
        for n in [1u32, i as u32, p.len() as u32, p.len() as u32] {
            b.extend_from_slice(&n.to_le_bytes());
        }
        b.extend_from_slice(p);
    }
    b
}
fn analyze(b: &[u8], c: StreamConfig) -> (pcap_evidence_stream::Summary, Collect) {
    let registry = Registry::builtins(&c).unwrap();
    let mut out = Collect::default();
    let result = analyze_reader(b, c, &registry, &mut out).unwrap();
    (result, out)
}

#[test]
fn nonstandard_udp_dns_is_detected_without_port_hints() {
    let data = capture(&[udp(&dns(), 51000, 52000)]);
    let (_, out) = analyze(&data, StreamConfig::default());
    assert!(out
        .events
        .iter()
        .any(|e| e.kind == EventKind::Message && e.protocol.as_deref() == Some("dns")));
}
#[test]
fn complete_hash_is_exact_source_bytes() {
    let b = capture(&[udp(&dns(), 40000, 40001)]);
    let (summary, _) = analyze(&b, StreamConfig::default());
    assert_eq!(summary.source_sha256, sha256::digest(&b));
    assert_eq!(summary.source_bytes, b.len() as u64);
}
#[test]
fn packet_ordinals_are_conserved() {
    let b = capture(&vec![udp(&dns(), 45000, 46000); 12]);
    let (s, out) = analyze(&b, StreamConfig::default());
    assert_eq!(s.packets, 12);
    assert_eq!(
        out.events
            .iter()
            .filter(|e| e.kind == EventKind::Packet)
            .count(),
        12
    );
}
#[test]
fn truncated_source_has_abort_and_no_complete() {
    let mut b = capture(&[udp(&dns(), 40000, 40001)]);
    b.pop();
    let c = StreamConfig::default();
    let registry = Registry::builtins(&c).unwrap();
    let mut out = Collect::default();
    assert!(analyze_reader(b.as_slice(), c, &registry, &mut out).is_err());
    assert!(out
        .events
        .iter()
        .any(|e| e.kind == EventKind::CaptureAborted));
    assert!(!out
        .events
        .iter()
        .any(|e| e.kind == EventKind::CaptureComplete));
}
#[test]
fn tiny_reads_have_the_same_hash_and_packet_count() {
    struct Tiny<'a>(&'a [u8]);
    impl Read for Tiny<'_> {
        fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
            let n = out.len().min(3).min(self.0.len());
            out[..n].copy_from_slice(&self.0[..n]);
            self.0 = &self.0[n..];
            Ok(n)
        }
    }
    let b = capture(&[udp(&dns(), 40000, 40001)]);
    let c = StreamConfig::default();
    let registry = Registry::builtins(&c).unwrap();
    let mut out = Collect::default();
    let s = analyze_reader(Tiny(&b), c, &registry, &mut out).unwrap();
    assert_eq!(s.source_sha256, sha256::digest(&b));
    assert_eq!(s.packets, 1);
}
#[test]
fn active_key_eviction_is_explicit_and_bounded() {
    let packets: Vec<_> = (0..20).map(|i| udp(&dns(), 40000 + i, 53000)).collect();
    let b = capture(&packets);
    let c = StreamConfig {
        max_active_keys: 2,
        ..StreamConfig::default()
    };
    let (s, out) = analyze(&b, c);
    assert!(s.peak_active_keys <= 2);
    assert!(out
        .events
        .iter()
        .any(|e| e.kind == EventKind::Boundary && e.status == EvidenceStatus::Incomplete));
    assert_eq!(s.packets, 20);
}
#[test]
fn packet_window_rollover_is_not_silent() {
    let b = capture(&vec![udp(&dns(), 40000, 53000); 9]);
    let c = StreamConfig {
        window_packets: 2,
        ..StreamConfig::default()
    };
    let (s, out) = analyze(&b, c);
    assert!(s.windows >= 5);
    assert!(out.events.iter().any(|e| e.kind == EventKind::Boundary
        && e.data.encode().contains("reconstruction_window_budget")));
}
#[test]
fn sink_backpressure_errors_stop_analysis() {
    struct Fails;
    impl EventSink for Fails {
        fn run_id(&self) -> &str {
            "fail"
        }
        fn emit(&mut self, _: &Event) -> Result<u64> {
            Err(io::Error::new(io::ErrorKind::BrokenPipe, "consumer stopped").into())
        }
    }
    let c = StreamConfig::default();
    let registry = Registry::builtins(&c).unwrap();
    assert!(analyze_reader(capture(&[]).as_slice(), c, &registry, &mut Fails).is_err());
}
#[test]
fn plugin_sink_error_is_not_swallowed_as_a_parse_error() {
    struct FailsMessage;
    impl EventSink for FailsMessage {
        fn run_id(&self) -> &str {
            "fail-message"
        }
        fn emit(&mut self, e: &Event) -> Result<u64> {
            if e.kind == EventKind::Message {
                Err(io::Error::new(io::ErrorKind::BrokenPipe, "consumer stopped").into())
            } else {
                Ok(1)
            }
        }
    }
    let c = StreamConfig::default();
    let registry = Registry::builtins(&c).unwrap();
    assert!(analyze_reader(
        capture(&[udp(&dns(), 40000, 53000)]).as_slice(),
        c,
        &registry,
        &mut FailsMessage
    )
    .is_err());
}
#[test]
fn no_payload_is_exported_by_default() {
    let b = capture(&[udp(&dns(), 40000, 53000)]);
    let (_, out) = analyze(&b, StreamConfig::default());
    assert!(out
        .events
        .iter()
        .all(|e| !e.data.encode().contains("6578616d706c65")));
}
#[test]
fn every_message_span_stays_in_its_source_packet() {
    let packet = udp(&dns(), 40000, 53000);
    let b = capture(std::slice::from_ref(&packet));
    let (_, out) = analyze(&b, StreamConfig::default());
    for e in out.events.iter().filter(|e| e.kind == EventKind::Message) {
        let mut selected = Vec::new();
        for span in &e.evidence.spans {
            selected.extend_from_slice(
                &packet[span.packet_start..span.packet_start + span.end - span.start],
            );
        }
        assert_eq!(
            Some(sha256::digest(&selected)),
            e.evidence.reconstructed_sha256
        );
    }
}
#[test]
fn vxlan_inner_dns_keeps_outer_packet_spans() {
    let inner = udp(&dns(), 40000, 53000);
    let mut payload = vec![8, 0, 0, 0, 0, 0, 42, 0];
    payload.extend_from_slice(&inner);
    let outer = udp(&payload, 40000, 4789);
    let b = capture(std::slice::from_ref(&outer));
    let (_, out) = analyze(&b, StreamConfig::default());
    let message = out
        .events
        .iter()
        .find(|e| e.kind == EventKind::Message && e.protocol.as_deref() == Some("dns"))
        .unwrap();
    let mut selected = Vec::new();
    for span in &message.evidence.spans {
        assert_eq!(span.packet.frame, 1);
        selected.extend_from_slice(
            &outer[span.packet_start..span.packet_start + span.end - span.start],
        );
    }
    assert_eq!(selected, dns());
}
#[test]
fn invalid_vxlan_reserved_bits_do_not_decode_inner_dns() {
    let inner = udp(&dns(), 40000, 53000);
    let mut payload = vec![9, 0, 0, 0, 0, 0, 42, 0];
    payload.extend_from_slice(&inner);
    let (_, out) = analyze(
        &capture(&[udp(&payload, 40000, 4789)]),
        StreamConfig::default(),
    );
    assert!(!out
        .events
        .iter()
        .any(|e| e.kind == EventKind::Message && e.protocol.as_deref() == Some("dns")));
}
#[test]
fn ndjson_is_incremental_and_has_a_completion_binding() {
    let b = capture(&[udp(&dns(), 40000, 53000)]);
    let c = StreamConfig::default();
    let registry = Registry::builtins(&c).unwrap();
    let mut sink = NdjsonSink::new(Vec::new(), "stable", c.max_event_bytes).unwrap();
    let summary = analyze_reader(b.as_slice(), c, &registry, &mut sink).unwrap();
    let text = String::from_utf8(sink.finish().unwrap()).unwrap();
    assert_eq!(text.lines().count(), summary.events as usize);
    assert!(text.lines().last().unwrap().contains("capture.complete"));
}
#[test]
fn json_counter_above_2_pow_53_is_a_string() {
    let e = Event::new(EventKind::Diagnostic, EvidenceStatus::Observed, Json::Null);
    assert!(e
        .json("x", (1u64 << 53) + 1)
        .encode()
        .contains("\"sequence\":\"9007199254740993\""));
}
#[test]
fn ndjson_partial_write_poisoning() {
    struct Broken;
    impl Write for Broken {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::BrokenPipe, "fail"))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut sink = NdjsonSink::new(Broken, "x", 4096).unwrap();
    let e = Event::new(EventKind::Diagnostic, EvidenceStatus::Observed, Json::Null);
    assert!(sink.emit(&e).is_err());
    assert!(sink.emit(&e).is_err());
    assert!(sink.finish().is_err());
}
#[test]
fn config_rejects_inconsistent_budgets() {
    let c = StreamConfig {
        max_active_payload: 1,
        ..StreamConfig::default()
    };
    assert!(c.validate().is_err());
}
#[test]
fn source_size_limit_is_separate_from_active_memory() {
    let c = StreamConfig::default();
    assert!(c.reader_limits().max_input_bytes > 500_000_000_000usize);
    assert_eq!(c.tracker_limits().max_retained_payload, c.window_payload);
}

struct Marker(&'static str);
impl ProtocolDetector for Marker {
    fn protocol(&self) -> &'static str {
        self.0
    }
    fn detect(&self, input: &ProbeInput<'_>) -> ProbeResult {
        if input.prefix.is_empty() {
            ProbeResult::NoMatch
        } else {
            ProbeResult::Match {
                protocol: self.0,
                strength: ProbeStrength::HeaderStructure,
                examined_bytes: 1,
                reason: "test detector",
            }
        }
    }
}
impl AnalyzerPlugin for Marker {
    fn stream(&self, _: AnalyzerLimits) -> Option<Box<dyn StreamAnalyzer>> {
        None
    }
    fn datagram(&self, _: AnalyzerLimits) -> Option<Box<dyn DatagramAnalyzer>> {
        Some(Box::new(Marker(self.0)))
    }
}
impl DatagramAnalyzer for Marker {
    fn analyze(&mut self, input: &DatagramInput<'_>, out: &mut Output<'_>) -> Result<()> {
        out.message(
            self.0,
            input.bytes,
            None,
            Json::object([("test", true.into())]),
            None,
            true,
        )?;
        Ok(())
    }
    fn retained_bytes(&self) -> usize {
        0
    }
}
#[test]
fn simultaneous_detectors_are_all_emitted_as_ambiguous() {
    let c = StreamConfig::default();
    let mut registry = Registry::new(2).unwrap();
    registry.register(Box::new(Marker("alpha"))).unwrap();
    registry.register(Box::new(Marker("beta"))).unwrap();
    let mut out = Collect::default();
    analyze_reader(
        capture(&[udp(b"x", 40000, 53000)]).as_slice(),
        c,
        &registry,
        &mut out,
    )
    .unwrap();
    let messages: Vec<_> = out
        .events
        .iter()
        .filter(|e| e.kind == EventKind::Message)
        .collect();
    assert_eq!(messages.len(), 2);
    assert!(messages
        .iter()
        .all(|e| e.status == EvidenceStatus::Ambiguous));
}
#[test]
fn duplicate_plugin_names_are_rejected() {
    let mut registry = Registry::new(2).unwrap();
    registry.register(Box::new(Marker("same"))).unwrap();
    assert!(registry.register(Box::new(Marker("same"))).is_err());
}
#[test]
fn registry_enforces_capacity() {
    let mut registry = Registry::new(1).unwrap();
    registry.register(Box::new(Marker("one"))).unwrap();
    assert!(registry.register(Box::new(Marker("two"))).is_err());
}

#[test]
fn dns_query_decodes_exact_name() {
    let m = protocols::dns(&dns()).unwrap();
    assert_eq!(m.questions[0].name, "example.test");
    assert!(!m.response);
}
#[test]
fn dns_pointer_cycle_is_rejected() {
    assert!(protocols::dns_name(&[0xc0, 0], 0).is_err());
}
#[test]
fn dns_pointer_out_of_range_is_rejected() {
    assert!(protocols::dns_name(&[0xc0, 0xff], 0).is_err());
}
#[test]
fn dns_name_extreme_start_is_rejected_without_panic() {
    assert!(protocols::dns_name(&[0], usize::MAX).is_err());
}
#[test]
fn dns_trailing_bytes_do_not_become_a_clean_message() {
    let mut b = dns();
    b.push(0);
    assert!(protocols::dns(&b).is_err());
}
#[test]
fn http_authorization_is_not_exported() {
    let (m, _) = protocols::http_header(
        b"GET / HTTP/1.1\r\nHost: example.test\r\nAuthorization: Bearer secret-token\r\n\r\n",
    )
    .unwrap();
    assert!(!m.encode().contains("secret-token"));
}
#[test]
fn http_incomplete_header_is_not_success() {
    assert!(protocols::http_header(b"GET / HTTP/1.1\r\nHost: x\r\n").is_err());
}
#[test]
fn quic_short_header_is_not_claimed_decrypted() {
    assert!(protocols::quic(&[0x40, 1, 2, 3, 4, 5, 6, 7]).is_err());
}
#[test]
fn tls_client_hello_minimal_structure() {
    let mut b = vec![3, 3];
    b.extend_from_slice(&[0; 32]);
    b.extend_from_slice(&[0, 0, 2, 0x13, 1, 1, 0, 0, 0]);
    assert!(protocols::tls_client_hello(&b).is_ok());
}
#[test]
fn tls_truncated_client_hello_rejected() {
    assert!(protocols::tls_client_hello(&[3, 3, 0, 0]).is_err());
}
#[test]
fn dhcp_cookie_required() {
    assert!(protocols::dhcp(&vec![0; 240]).is_err());
}
#[test]
fn dhcpv6_relay_is_explicitly_unsupported() {
    assert!(protocols::dhcpv6(&[12, 0, 0, 0, 0, 0, 0, 0]).is_err());
}
#[test]
fn smb_short_header_is_not_a_full_message() {
    assert!(protocols::smb2(b"\xfeSMB").is_err());
}
#[test]
fn arp_metadata_decodes_without_tcp() {
    let mut b = vec![0; 12];
    b.extend_from_slice(&[8, 6, 0, 1, 8, 0, 6, 4, 0, 1]);
    b.extend_from_slice(&[0; 20]);
    assert!(matches!(
        network::decode(1, &evidence(&b), scope()).unwrap(),
        network::Decoded::Metadata {
            protocol: "arp",
            ..
        }
    ));
}
#[test]
fn truncated_ethernet_is_rejected() {
    assert!(network::decode(1, &evidence(&[0; 13]), scope()).is_err());
}
#[test]
fn radiotap_bad_version_is_rejected() {
    assert!(network::decode(127, &evidence(&[1, 0, 8, 0, 0, 0, 0, 0]), scope()).is_err());
}
#[test]
fn unsupported_link_is_not_silently_dropped() {
    assert!(network::decode(99999, &evidence(&[0; 64]), scope()).is_err());
}

#[test]
fn a_tunnel_port_alone_does_not_hide_dns() {
    let (_, out) = analyze(
        &capture(&[udp(&dns(), 40000, 4789)]),
        StreamConfig::default(),
    );
    assert!(out
        .events
        .iter()
        .any(|e| e.kind == EventKind::Message && e.protocol.as_deref() == Some("dns")));
}
#[test]
fn tls_oversized_session_id_is_rejected() {
    let mut b = vec![3, 3];
    b.extend_from_slice(&[0; 32]);
    b.push(33);
    b.extend_from_slice(&[0; 33]);
    b.extend_from_slice(&[0, 2, 0x13, 1, 1, 0, 0, 0]);
    assert!(protocols::tls_client_hello(&b).is_err());
}
