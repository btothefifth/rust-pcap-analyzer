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
fn confirmation_capture() -> Vec<u8> {
    let text = include_str!("../../tests/fixtures/dnp3_confirmations_capture.hex");
    let hex = text.lines().find(|line| !line.starts_with('#')).unwrap();
    (0..hex.len())
        .step_by(2)
        .map(|p| u8::from_str_radix(&hex[p..p + 2], 16).unwrap())
        .collect()
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
    assert!(!out.events.iter().any(|e| {
        e.kind == EventKind::Dnp3Confirmation && e.status == EvidenceStatus::Candidate
    }));
}

#[test]
fn streaming_dnp3_confirmation_projection_is_source_bound_and_additive() {
    let out = run(&confirmation_capture(), StreamConfig::default());
    let candidate = out
        .events
        .iter()
        .find(|e| e.kind == EventKind::Dnp3Confirmation)
        .expect("streaming DNP3 confirmation projection");
    assert_eq!(candidate.status, EvidenceStatus::Candidate);
    assert!(candidate
        .data
        .encode()
        .contains("generic_transaction_untouched"));
    assert!(candidate.related_events.len() >= 2);
    assert!(
        out.events
            .iter()
            .any(|e| e.kind == EventKind::CaptureComplete
                && e.data.encode().contains("source_sha256"))
    );
    assert!(!out.events.iter().any(|e| {
        e.kind == EventKind::Transaction && e.data.encode().contains("dnp3_confirmation_candidate")
    }));
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

#[test]
fn modbus_read_mapping_retains_conditional_boundary_and_both_witnesses() {
    let full = capture("modbus_bits_valid.pcap");
    // Omit the three handshake records and restore capture order by sequence
    // for the two response fragments, so midstream alignment is observable.
    let mut mid = [&full[..24], &full[234..316], &full[392..], &full[316..392]].concat();
    // Keep the original monotonic record timestamps after the permutation.
    mid[106..114].copy_from_slice(&full[316..324]);
    mid[181..189].copy_from_slice(&full[392..400]);
    for (bytes, status) in [
        (&full, "candidate_pair"),
        (&mid, "candidate_unverified_boundary"),
    ] {
        let out = run(bytes, StreamConfig::default());
        let tx = out
            .events
            .iter()
            .find(|e| e.kind == EventKind::Transaction && e.status == EvidenceStatus::Candidate)
            .unwrap();
        assert_eq!(tx.related_events.len(), 2);
        let json = tx.data.encode();
        assert!(json.contains(&format!("\"read_mapping\":{{\"status\":\"{status}\"")));
        assert!(json.contains("\"quantity\":9"));
        assert!(json.contains("\"padding_checked\":true"));
    }
}

#[test]
fn competing_modbus_observations_withhold_only_the_affected_group() {
    for (fixture, paired) in [
        ("modbus_partial_same.pcap", false),
        ("modbus_partial_sibling.pcap", true),
        ("modbus_mei_exception_reuse.pcap", false),
    ] {
        let bytes = capture(fixture);
        let root = pcap_evidence::engine::analyze(&bytes, Default::default()).unwrap();
        assert!(
            root.transactions.iter().any(|tx| if paired {
                tx.status == "candidate_pair"
            } else {
                tx.reason == "competing_modbus_observation"
            }),
            "{fixture}"
        );
        let stream = run(&bytes, StreamConfig::default());
        let tx = stream
            .events
            .iter()
            .find(|e| e.kind == EventKind::Transaction)
            .unwrap();
        assert_eq!(
            tx.status,
            if paired {
                EvidenceStatus::Candidate
            } else {
                EvidenceStatus::Ambiguous
            },
            "{fixture}"
        );
        assert_eq!(tx.data.encode().contains("read_mapping"), paired);
        assert_eq!(
            pcap_evidence::report::analysis(&root, false)
                .encode()
                .contains("read_mapping"),
            paired
        );
    }
}

fn field<'a>(value: &'a Json, name: &str) -> &'a Json {
    let Json::Object(fields) = value else {
        panic!("expected object with {name}")
    };
    &fields.iter().find(|(key, _)| *key == name).unwrap().1
}

#[test]
fn modbus_mapping_references_resolve_to_both_wire_values() {
    use pcap_evidence::{
        capture::{CaptureIter, ParseMode},
        engine::{self, ApplicationData},
        provenance::SourceSpan,
    };
    let bytes = capture("modbus_bits_valid.pcap");
    let mut packets = std::collections::BTreeMap::new();
    for record in CaptureIter::new(&bytes, Default::default(), ParseMode::Strict).unwrap() {
        let record = record.unwrap();
        if let Some((m, data)) = record.packet() {
            packets.insert(m.frame, data.to_vec());
        }
    }
    let snapshot = engine::analyze(&bytes, Default::default()).unwrap();
    let report = pcap_evidence::report::analysis(&snapshot, false);
    let Json::Array(transactions) = field(&report, "transaction_candidates") else {
        panic!("missing transactions")
    };
    let streaming = run(&bytes, Default::default());
    let tx = &streaming
        .events
        .iter()
        .find(|e| e.kind == EventKind::Transaction)
        .unwrap()
        .data;
    for (mapping, stream) in [
        (field(&transactions[0], "read_mapping"), false),
        (field(tx, "read_mapping"), true),
    ] {
        for (role, offset_key, expected) in [
            ("request", "request_address_adu_offset", &[0, 0][..]),
            ("request", "request_quantity_adu_offset", &[0, 9]),
            ("response", "response_values_adu_offset", &[255, 1]),
        ] {
            let reference = field(mapping, role);
            let spans: &[SourceSpan] = if stream {
                let Json::String(sequence) = reference else {
                    panic!("missing event id")
                };
                let event = &streaming.events[sequence.parse::<usize>().unwrap() - 1];
                assert_eq!(event.kind, EventKind::Message);
                assert_eq!(field(&event.data, "role"), &Json::from(role));
                &event.evidence.spans
            } else {
                let Json::Number(app) = field(reference, "application") else {
                    panic!("missing application")
                };
                let Json::Number(index) = field(reference, "message") else {
                    panic!("missing message")
                };
                let ApplicationData::Modbus(data) = &snapshot.applications[*app as usize].data
                else {
                    panic!("wrong protocol")
                };
                let message = &data.messages[*index as usize];
                assert_eq!(message.role.as_str(), role);
                message.raw.spans()
            };
            let reconstructed: Vec<_> = spans
                .iter()
                .flat_map(|s| {
                    packets[&s.packet.frame][s.packet_start..s.packet_start + s.end - s.start]
                        .iter()
                        .copied()
                })
                .collect();
            let Json::Number(offset) = field(mapping, offset_key) else {
                panic!("missing wire offset")
            };
            let start = *offset as usize;
            assert_eq!(&reconstructed[start..start + expected.len()], expected);
        }
    }
}

#[test]
fn uncertain_tcp_data_blocks_affected_generations_and_preserves_a_successor() {
    let bytes = capture("modbus_generation_overlap.pcap");
    let snapshot = pcap_evidence::engine::analyze(&bytes, Default::default()).unwrap();
    assert_eq!(
        snapshot
            .flows
            .iter()
            .filter(|flow| flow.uncertain_payload.is_some())
            .count(),
        2
    );
    let pairs: Vec<_> = snapshot
        .transactions
        .iter()
        .filter(|tx| tx.status == "candidate_pair")
        .collect();
    assert_eq!(pairs.len(), 1);
    assert_eq!(
        snapshot.flows[pairs[0].flow].packets.last().unwrap().frame,
        11
    );
    let out = run(&bytes, Default::default());
    assert_eq!(
        out.events
            .iter()
            .filter(|e| e.data.encode().contains("read_mapping"))
            .count(),
        1
    );

    // Remove the competing SYN, then snap the last four payload bytes on frame 6.
    let mut records = Vec::new();
    let mut offset = 24;
    while offset < bytes.len() {
        let n = u32::from_le_bytes(bytes[offset + 8..offset + 12].try_into().unwrap()) as usize;
        records.push(&bytes[offset..offset + 16 + n]);
        offset += 16 + n;
    }
    let mut snapped = bytes[..24].to_vec();
    for record in &records[..5] {
        snapped.extend_from_slice(record);
    }
    let mut tail = records[6][..records[6].len() - 4].to_vec();
    let captured = (tail.len() - 16) as u32;
    tail[8..12].copy_from_slice(&captured.to_le_bytes());
    snapped.extend(tail);
    let snapshot = pcap_evidence::engine::analyze(&snapped, Default::default()).unwrap();
    assert_eq!(snapshot.flows[0].uncertain_payload.unwrap().frame, 6);
    assert!(!pcap_evidence::report::analysis(&snapshot, false)
        .encode()
        .contains("read_mapping"));
    assert!(!run(&snapped, Default::default())
        .events
        .iter()
        .any(|e| e.data.encode().contains("read_mapping")));
}

#[test]
fn device_competitors_and_echo_disagreements_reach_both_correlators() {
    let bytes = capture("modbus_interleaved.pcap");
    let root = pcap_evidence::engine::analyze(&bytes, Default::default()).unwrap();
    let root_report = pcap_evidence::report::analysis(&root, false);
    let Json::Array(root_txs) = field(&root_report, "transaction_candidates") else {
        unreachable!()
    };
    let root_groups: Vec<_> = root_txs
        .iter()
        .filter(|t| field(t, "status") != &Json::from("unclassified"))
        .collect();
    let stream = run(&bytes, Default::default());
    let groups: Vec<_> = stream
        .events
        .iter()
        .filter(|e| e.kind == EventKind::Transaction)
        .collect();
    assert_eq!((root_groups.len(), groups.len()), (8, 8));
    for (index, name) in [
        "starting_address_zero_based",
        "register_u16",
        "read_category",
        "first_object_id",
    ]
    .into_iter()
    .enumerate()
    {
        let expected = Json::array([Json::from(name)]);
        assert_eq!(field(root_groups[index], "disagreeing_fields"), &expected);
        assert_eq!(field(&groups[index].data, "disagreeing_fields"), &expected);
    }
    for i in [4, 5, 7] {
        assert_eq!(
            field(root_groups[i], "status"),
            &Json::from("candidate_pair")
        );
        assert_eq!(groups[i].status, EvidenceStatus::Candidate);
    }
    assert_eq!(groups[6].status, EvidenceStatus::Ambiguous);
    assert_eq!(groups[6].related_events.len(), 3);
    let opaque = groups[6]
        .related_events
        .iter()
        .filter(|id| {
            let event = &stream.events[**id as usize - 1];
            field(&event.data, "semantics_supported") == &Json::Bool(false)
        })
        .count();
    assert_eq!(opaque, 1);
    let Json::Array(blockers) = field(root_groups[6], "competing_observations") else {
        unreachable!()
    };
    assert_eq!(blockers.len(), 1);
}

#[path = "../../tests/support/tiny_capture.rs"]
mod tiny_capture;

#[test]
fn snapped_headers_follow_their_tunnel_and_later_tcp_generation() {
    use tiny_capture::{capture, tcp, tunneled};
    let req = [0, 72, 0, 0, 0, 6, 3, 3, 0, 9, 0, 1];
    let rsp = [0, 72, 0, 0, 0, 5, 3, 3, 2, 0x12, 0x34];
    for kind in ["plain", "gre", "vxlan", "geneve"] {
        let wrap = |vni, reverse, bytes: Vec<u8>| {
            if kind == "plain" {
                bytes
            } else {
                tunneled(kind, vni, reverse, &bytes)
            }
        };
        for (same_path, same_sequence, snap, expected) in [
            (true, true, true, 0),
            (true, true, false, 0),
            (true, false, true, 1),
            (false, true, true, 1),
        ] {
            if kind == "plain" && !same_path {
                continue;
            }
            let seq = if same_sequence { 1013 } else { 1_000_000_001 };
            let mut first = wrap(
                if same_path { 7 } else { 8 },
                false,
                tcp(false, 1001, 5001, 0x18, &req),
            );
            let original = first.len() as u32;
            if snap {
                first.truncate(first.len() - 4);
            }
            let mut bytes = capture(&[
                first,
                wrap(7, false, tcp(false, seq, 5001, 0x18, &req)),
                wrap(7, true, tcp(true, 5001, seq + 12, 0x18, &rsp)),
            ]);
            bytes[36..40].copy_from_slice(&original.to_le_bytes());
            let mut config = StreamConfig::default();
            config.base.modbus_ports = vec![2000];
            if kind == "plain" {
                let root = pcap_evidence::engine::analyze(&bytes, config.base.clone()).unwrap();
                assert_eq!(
                    pcap_evidence::report::analysis(&root, false)
                        .encode()
                        .matches("read_mapping")
                        .count(),
                    expected
                );
            }
            let out = run(&bytes, config);
            assert!(out
                .events
                .iter()
                .any(|e| e.kind == EventKind::Message && e.protocol.as_deref() == Some("modbus")));
            let count = out
                .events
                .iter()
                .filter(|e| {
                    e.kind == EventKind::Transaction && e.data.encode().contains("read_mapping")
                })
                .count();
            assert_eq!(
                count, expected,
                "{kind} same_path={same_path} same_sequence={same_sequence} snap={snap}"
            );
        }
    }
}

#[test]
fn dropped_tcp_data_only_invalidates_plausible_modbus_generations() {
    use tiny_capture::{capture, tcp};
    let request = [0, 1, 0, 0, 0, 6, 1, 3, 0, 9, 0, 1];
    let response = [0, 1, 0, 0, 0, 5, 1, 3, 2, 0x12, 0x34];
    let exchange = |seq, peer| {
        vec![
            tcp(false, seq, 0, 2, &[]),
            tcp(true, peer, seq + 1, 0x12, &[]),
            tcp(false, seq + 1, peer + 1, 0x18, &request),
            tcp(true, peer + 1, seq + 13, 0x18, &response),
        ]
    };
    let mut config = StreamConfig::default();
    config.base.modbus_ports = vec![2000];
    config.window_payload = 32;
    for (case, expected) in [
        ("control", 2),
        ("future", 1),
        ("tcp-options", 1),
        ("ack-options", 2),
        ("first-fragment", 1),
        ("noninitial-fragment", 2),
        ("incomplete-reassembly", 1),
        ("oversized", 1),
    ] {
        let mut frames = exchange(1000, 5000);
        let index = frames.len();
        let start = 1_000_000_000;
        let peer = 2_000_000_000;
        let mut tail = tcp(false, 1013, 5012, 0x18, &request);
        let mut snapped_length = None;
        match case {
            "incomplete-reassembly" => tail = tiny_capture::ipv4_fragment(&tail, 0..24, true),
            "future" => tail = tcp(false, start + 13, peer + 12, 0x18, &request),
            "oversized" => tail = tcp(false, 1013, 5012, 0x18, &request.repeat(3)),
            "tcp-options" | "ack-options" | "first-fragment" | "noninitial-fragment" => {
                if case.ends_with("options") {
                    if case == "ack-options" {
                        tail = tcp(false, 1013, 5012, 0x10, &[]);
                    }
                    tail[46] = 0x60;
                    tail.splice(54..54, [1; 4]);
                } else {
                    tail.truncate(58);
                    let bits = if case == "first-fragment" {
                        0x2000u16
                    } else {
                        3
                    };
                    tail[20..22].copy_from_slice(&bits.to_be_bytes());
                }
                let total = (tail.len() - 14) as u16;
                tail[16..18].copy_from_slice(&total.to_be_bytes());
                tail[24..26].fill(0);
                let sum = pcap_evidence::wire::internet_checksum(&tail[14..34]);
                tail[24..26].copy_from_slice(&sum.to_be_bytes());
                snapped_length = Some(tail.len() as u32);
                tail.truncate(54);
            }
            _ => {}
        }
        if case != "control" {
            frames.push(tail);
        }
        frames.extend(exchange(start, peer));
        let mut raw = capture(&frames);
        if let Some(original) = snapped_length {
            let record = 24 + frames[..index].iter().map(|f| f.len() + 16).sum::<usize>();
            raw[record + 12..record + 16].copy_from_slice(&original.to_le_bytes());
        }
        // Keep each exchange in one window. Only the deliberate oversized
        // segment exceeds it; the successor starts a fresh window as needed.
        let mut limits = config.clone();
        if case != "oversized" {
            limits.window_payload = 4096;
        }
        let snapshot = pcap_evidence::engine::analyze(&raw, limits.base.clone()).unwrap();
        assert_eq!(
            pcap_evidence::report::analysis(&snapshot, false)
                .encode()
                .matches("read_mapping")
                .count(),
            expected,
            "snapshot {case}"
        );
        let events = run(&raw, limits).events;
        assert_eq!(
            events
                .iter()
                .filter(|e| e.data.encode().contains("read_mapping"))
                .count(),
            expected,
            "stream {case}"
        );
    }
}

#[test]
fn successfully_reassembled_tcp_releases_its_provisional_header() {
    use tiny_capture::{capture, ipv4_fragment, tcp, tunneled};
    let request = tcp(false, 101, 501, 0x18, &[0, 1, 0, 0, 0, 6, 1, 3, 0, 9, 0, 1]);
    let response = tcp(
        true,
        501,
        113,
        0x18,
        &[0, 1, 0, 0, 0, 5, 1, 3, 2, 0x12, 0x34],
    );
    let mut config = StreamConfig::default();
    config.base.modbus_ports = vec![2000];
    for tunnel in [false, true] {
        let wrap = |p: Vec<u8>, reverse| {
            if tunnel {
                tunneled("gre", 7, reverse, &p)
            } else {
                p
            }
        };
        let req = wrap(request.clone(), false);
        let length = req.len() - 34;
        let start = if tunnel { 48 } else { 24 };
        let first = ipv4_fragment(&req, 0..start, true);
        let last = ipv4_fragment(&req, start..length, false);
        for fragments in [[first.clone(), last.clone()], [last.clone(), first.clone()]] {
            let bytes = capture(&[
                wrap(tcp(false, 100, 0, 2, &[]), false),
                wrap(tcp(true, 500, 101, 0x12, &[]), true),
                fragments[0].clone(),
                fragments[1].clone(),
                wrap(response.clone(), true),
            ]);
            if !tunnel {
                let analysis = pcap_evidence::engine::analyze(&bytes, config.base.clone()).unwrap();
                assert!(analysis.flows[0].uncertain_payload.is_none());
                assert_eq!(
                    pcap_evidence::report::analysis(&analysis, false)
                        .encode()
                        .matches("read_mapping")
                        .count(),
                    1
                );
            }
            assert_eq!(
                run(&bytes, config.clone())
                    .events
                    .iter()
                    .filter(|e| e.data.encode().contains("read_mapping"))
                    .count(),
                1
            );
        }
    }
}
