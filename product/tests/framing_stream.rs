#![cfg(feature = "extensions")]
use pcap_evidence::{
    protocol::{ProbeInput, ProbeResult, ProbeTransport},
    provenance::{EvidenceBytes, PacketId},
    tcp::{StreamChunk, StreamResult},
    wire::Endpoint,
    Result,
};
use pcap_evidence_product::{
    protocols::Protocol,
    registry::{self, FramingPlugin},
};
use pcap_evidence_stream::{
    plugin::{
        AnalyzerLimits, AnalyzerPlugin, Context, Output, ProtocolDetector, RegistryOutput,
        StreamAnalyzer, StreamInput,
    },
    Event, EventKind, EventSink, Registry, StreamConfig,
};
#[derive(Default)]
struct Events(Vec<Event>);
impl EventSink for Events {
    fn run_id(&self) -> &str {
        "framing-regression"
    }
    fn emit(&mut self, event: &Event) -> Result<u64> {
        self.0.push(event.clone());
        Ok(self.0.len() as u64)
    }
}
struct SplitPlugin {
    protocol: Protocol,
    width: usize,
}
impl ProtocolDetector for SplitPlugin {
    fn protocol(&self) -> &'static str {
        self.protocol.name()
    }
    fn detect(&self, input: &ProbeInput<'_>) -> ProbeResult {
        FramingPlugin(self.protocol).detect(input)
    }
}
impl AnalyzerPlugin for SplitPlugin {
    fn datagram(
        &self,
        _: AnalyzerLimits,
    ) -> Option<Box<dyn pcap_evidence_stream::plugin::DatagramAnalyzer>> {
        None
    }

    fn stream(&self, limits: AnalyzerLimits) -> Option<Box<dyn StreamAnalyzer>> {
        Some(Box::new(SplitAnalyzer {
            inner: FramingPlugin(self.protocol).stream(limits)?,
            width: self.width,
        }))
    }
}
struct SplitAnalyzer {
    inner: Box<dyn StreamAnalyzer>,
    width: usize,
}
impl StreamAnalyzer for SplitAnalyzer {
    fn push(&mut self, input: &StreamInput<'_>, output: &mut Output<'_>) -> Result<()> {
        for start in (0..input.bytes.len()).step_by(self.width) {
            let bytes = input
                .bytes
                .slice(start..(start + self.width).min(input.bytes.len()))?;
            self.inner.push(
                &StreamInput {
                    offset: input.offset + start as i64,
                    bytes: &bytes,
                    boundary_verified: input.boundary_verified,
                },
                output,
            )?;
        }
        Ok(())
    }
    fn gap(&mut self, reason: &str, output: &mut Output<'_>) -> Result<()> {
        self.inner.gap(reason, output)
    }
    fn finish(&mut self, output: &mut Output<'_>) -> Result<()> {
        self.inner.finish(output)
    }
    fn retained_bytes(&self) -> usize {
        self.inner.retained_bytes()
    }
}
fn run(raw: &[u8], piece: usize, profile: bool, buffer: usize, p: Protocol) -> Vec<Event> {
    let config = StreamConfig {
        max_plugin_bytes: buffer,
        max_detectors: 64,
        ..StreamConfig::default()
    };
    let mut bytes = EvidenceBytes::default();
    for (i, part) in raw.chunks(piece).enumerate() {
        bytes
            .append(
                &EvidenceBytes::from_packet(
                    part,
                    PacketId {
                        capture: [9; 32],
                        frame: i as u64 + 1,
                        record_offset: i as u64 * 100,
                    },
                    54,
                ),
                raw.len(),
            )
            .unwrap();
    }
    let stream = StreamResult {
        base_sequence: Some(1),
        anchored_by_syn: true,
        chunks: vec![StreamChunk { offset: 100, bytes }],
        gaps: vec![],
        conflicts: vec![],
        duplicate_observed_bytes: 0,
    };
    let context = Context {
        session: 7,
        window: 0,
        generation: Some(0),
        direction: 0,
        source: Endpoint {
            address: "192.0.2.1".parse().unwrap(),
            port: 40000,
        },
        destination: Endpoint {
            address: "192.0.2.2".parse().unwrap(),
            port: 179,
        },
        transport: ProbeTransport::Tcp,
        ambiguous: false,
        boundary_verified: true,
        modbus_ports: vec![],
    };
    let registry = if profile {
        registry::registry(&config, "it-full").unwrap()
    } else {
        let mut r = Registry::new(1).unwrap();
        r.register(Box::new(SplitPlugin {
            protocol: p,
            width: piece,
        }))
        .unwrap();
        r
    };
    let mut events = Events::default();
    registry
        .stream(
            &context,
            &stream,
            &config,
            &mut RegistryOutput {
                sink: &mut events,
                records: &mut vec![],
                dnp3_confirmations: &mut vec![],
                remaining: &mut 10000,
            },
        )
        .unwrap();
    events.0
}
#[test]
fn coalesced_bgp_frames_preserve_offsets_and_packet_witnesses() {
    let raw = [vec![255; 16], vec![0, 19, 4]].concat().repeat(2000);
    for (piece, profile) in [(raw.len(), false), (7, false), (raw.len(), true)] {
        let events = run(&raw, piece, profile, 1024 * 1024, Protocol::Bgp);
        let messages: Vec<_> = events
            .iter()
            .filter(|e| e.kind == EventKind::Message && e.protocol.as_deref() == Some("bgp"))
            .collect();
        assert_eq!(messages.len(), 2000);
        for (i, e) in messages.iter().enumerate() {
            assert_eq!(
                e.stream_range,
                Some((100 + i as i64 * 19, 119 + i as i64 * 19))
            );
            let mut count = 0;
            for span in &e.evidence.spans {
                let start = (span.packet.frame as usize - 1) * piece + span.packet_start - 54;
                assert_eq!(start, i * 19 + span.start);
                count += span.end - span.start;
            }
            assert_eq!(count, 19);
        }
        assert!(!events
            .iter()
            .any(|e| e.data.encode().contains("plugin_work")));
    }
    let limited = run(&raw, raw.len(), false, 1024, Protocol::Bgp);
    assert!(limited
        .iter()
        .any(|e| e.data.encode().contains("plugin_work")));
}
#[test]
fn coalesced_imap_numeric_reply_keeps_tagged_completion() {
    let events = run(
        b"* OK ready\r\n* 23 EXISTS\r\na047 OK done\r\n",
        4096,
        false,
        65536,
        Protocol::Imap,
    );
    let messages: Vec<_> = events
        .iter()
        .filter(|e| e.kind == EventKind::Message)
        .collect();
    assert_eq!(messages.len(), 3);
    assert_eq!(messages[1].stream_range, Some((112, 125)));
    assert_eq!(messages[2].stream_range, Some((125, 139)));
}
#[test]
fn initial_telnet_detection_requires_command_evidence() {
    let probe = |bytes| ProbeInput {
        transport: ProbeTransport::Tcp,
        source_port: 23,
        destination_port: 179,
        prefix: bytes,
    };
    let bgp = [vec![255; 16], vec![0, 19, 4]].concat();
    assert!(!matches!(
        FramingPlugin(Protocol::Telnet).detect(&probe(&bgp)),
        ProbeResult::Match { .. }
    ));
    assert!(matches!(
        FramingPlugin(Protocol::Telnet).detect(&probe(&[255, 251, 1])),
        ProbeResult::Match { .. }
    ));
    assert!(Protocol::Telnet.decode(&[255, 255]).is_ok());
}

#[test]
fn coalesced_frame_keeps_partial_and_malformed_tail_diagnostics() {
    let valid = [vec![255; 16], vec![0, 19, 4]].concat();
    for tail in [vec![255; 18], vec![0; 19]] {
        let raw = [valid.clone(), tail.clone()].concat();
        let events = run(&raw, raw.len(), false, 65536, Protocol::Bgp);
        assert_eq!(
            events
                .iter()
                .filter(|e| e.kind == EventKind::Message)
                .count(),
            1
        );
        let issues: Vec<_> = events
            .iter()
            .filter(|e| e.kind == EventKind::ProtocolIssue)
            .collect();
        assert_eq!(issues.len(), 1);
        let spans = &issues[0].evidence.spans;
        assert_eq!(
            spans.iter().map(|s| s.end - s.start).sum::<usize>(),
            tail.len()
        );
        assert_eq!(spans[0].packet_start, 54 + 19);
    }
}
