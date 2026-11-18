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
                let ApplicationData::Modbus(data) = &snapshot.applications()[*app as usize].data
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
            .flows()
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
        snapshot.flows()[pairs[0].flow]
            .packets
            .last()
            .unwrap()
            .frame,
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
    assert_eq!(snapshot.flows()[0].uncertain_payload.unwrap().frame, 6);
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
        ("split-header", 1),
        ("split-header-reversed", 1),
        ("split-header-gap", 2),
        ("oversized", 1),
    ] {
        let mut frames = exchange(1000, 5000);
        let index = frames.len();
        let start = 1_000_000_000;
        let peer = 2_000_000_000;
        let mut tail = tcp(false, 1013, 5012, 0x18, &request);
        let mut snapped_length = None;
        match case {
            "split-header" | "split-header-reversed" | "split-header-gap" => {
                let first = tiny_capture::ipv4_fragment(&tail, 0..8, true);
                let second_start = if case == "split-header-gap" { 16 } else { 8 };
                let second =
                    tiny_capture::ipv4_fragment(&tail, second_start..second_start + 8, true);
                tail = if case == "split-header-reversed" {
                    frames.push(second);
                    first
                } else {
                    frames.push(first);
                    second
                };
            }
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
        if matches!(
            case,
            "split-header" | "split-header-reversed" | "split-header-gap"
        ) {
            let mut tight = limits.clone();
            tight.base.limits.max_fragments_per_set = 1;
            let events = run(&raw, tight).events;
            assert!(events
                .iter()
                .any(|e| e.data.encode().contains("fragment_context_reset")));
            assert_eq!(
                events
                    .iter()
                    .filter(|e| e.data.encode().contains("read_mapping"))
                    .count(),
                expected,
                "refused {case}"
            );
        }
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
        let mut cases = vec![
            vec![first.clone(), last.clone()],
            vec![last.clone(), first.clone()],
            vec![first.clone(), first.clone(), last.clone()],
            vec![last.clone(), last, first],
        ];
        if tunnel {
            let inner_first = wrap(ipv4_fragment(&request, 0..24, true), false);
            let inner_last = wrap(ipv4_fragment(&request, 24..32, false), false);
            let outer_first = ipv4_fragment(&inner_first, 0..24, true);
            let outer_last = ipv4_fragment(&inner_first, 24..inner_first.len() - 34, false);
            cases.push(vec![
                outer_first.clone(),
                outer_last.clone(),
                inner_last.clone(),
            ]);
            cases.push(vec![outer_last, outer_first, inner_last]);
        }
        for fragments in cases {
            let mut frames = vec![
                wrap(tcp(false, 100, 0, 2, &[]), false),
                wrap(tcp(true, 500, 101, 0x12, &[]), true),
            ];
            frames.extend(fragments);
            frames.push(wrap(response.clone(), true));
            let bytes = capture(&frames);
            if !tunnel {
                let analysis = pcap_evidence::engine::analyze(&bytes, config.base.clone()).unwrap();
                assert!(analysis.flows()[0].uncertain_payload.is_none());
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

#[test]
fn window_cut_accounts_for_pending_and_omitted_tcp_headers() {
    use tiny_capture::{capture, ipv4_fragment, tcp};
    let req = [0, 1, 0, 0, 0, 6, 1, 3, 0, 9, 0, 1];
    let rsp = [0, 1, 0, 0, 0, 5, 1, 3, 2, 0x12, 0x34];
    let pair = vec![
        tcp(false, 100, 0, 2, &[]),
        tcp(true, 500, 101, 0x12, &[]),
        tcp(false, 101, 501, 0x10, &[]),
        tcp(false, 101, 501, 0x18, &req),
        tcp(true, 501, 113, 0x18, &rsp),
    ];
    let tail = tcp(false, 113, 512, 0x18, &req);
    let mut config = StreamConfig::default();
    config.base.modbus_ports = vec![2000];
    config.window_packets = pair.len();
    for count in [0, 1, 5, 6] {
        let mut frames = pair.clone();
        for _ in 0..count {
            frames.push(ipv4_fragment(&tail, 0..24, true));
        }
        let events = run(&capture(&frames), config.clone()).events;
        assert_eq!(
            events
                .iter()
                .any(|e| e.data.encode().contains("read_mapping")),
            count == 0
        );
    }
    config.base.checksum_policy = pcap_evidence::wire::ChecksumPolicy::RequireValid;
    for valid in [true, false] {
        let mut segment = tail.clone();
        if !valid {
            segment[50] ^= 1;
        }
        let mut whole = pair.clone();
        whole.push(segment.clone());
        let mut fragmented = pair.clone();
        fragmented.push(ipv4_fragment(&segment, 24..32, false));
        fragmented.push(ipv4_fragment(&segment, 0..24, true));
        for frames in [whole, fragmented] {
            let events = run(&capture(&frames), config.clone()).events;
            assert_eq!(
                events
                    .iter()
                    .filter(|e| e.data.encode().contains("read_mapping"))
                    .count(),
                1
            );
        }
    }
    let mut frames = pair.clone();
    frames.push(tail[..54].to_vec());
    let mut raw = capture(&frames);
    let record = capture(&pair).len();
    raw[record + 12..record + 16].copy_from_slice(&(tail.len() as u32).to_le_bytes());
    let events = run(&raw, config).events;
    assert!(!events
        .iter()
        .any(|e| e.data.encode().contains("read_mapping")));
}

#[test]
fn strict_checksum_adjudication_releases_only_completed_reassembly() {
    use tiny_capture::{capture, ipv4_fragment, tcp};
    let req = [0, 1, 0, 0, 0, 6, 1, 3, 0, 9, 0, 1];
    let mut tail = tcp(false, 113, 512, 0x18, &req);
    tail[50] ^= 1;
    let mut config = StreamConfig::default();
    config.base.modbus_ports = vec![2000];
    config.base.checksum_policy = pcap_evidence::wire::ChecksumPolicy::RequireValid;
    let first = ipv4_fragment(&tail, 0..24, true);
    let last = ipv4_fragment(&tail, 24..32, false);
    let routed_first = tiny_capture::routed_ipv4(&first);
    let routed_last = tiny_capture::routed_ipv4(&last);
    let mut bad_ip = tail.clone();
    bad_ip[24] ^= 1;
    let original = tail.len() as u32;
    for (extra, original_length, paired) in [
        (vec![tail.clone()], None, true),
        (vec![first.clone(), last], None, true),
        (vec![first], None, false),
        (vec![ipv4_fragment(&tail, 0..16, true)], None, false),
        (vec![tail[..48].to_vec()], Some(original), false),
        (vec![bad_ip[..48].to_vec()], Some(original), true),
        (vec![routed_first, routed_last], None, true),
    ] {
        let mut frames = vec![
            tcp(false, 100, 0, 2, &[]),
            tcp(true, 500, 101, 0x12, &[]),
            tcp(false, 101, 501, 0x18, &req),
            tcp(
                true,
                501,
                113,
                0x18,
                &[0, 1, 0, 0, 0, 5, 1, 3, 2, 0x12, 0x34],
            ),
        ];
        let record = capture(&frames).len();
        frames.extend(extra);
        let mut raw = capture(&frames);
        if let Some(original) = original_length {
            raw[record + 12..record + 16].copy_from_slice(&original.to_le_bytes());
        }
        let snapshot = pcap_evidence::engine::analyze(&raw, config.base.clone()).unwrap();
        assert_eq!(
            pcap_evidence::report::analysis(&snapshot, false)
                .encode()
                .contains("read_mapping"),
            paired
        );
        let events = run(&raw, config.clone()).events;
        assert_eq!(
            events
                .iter()
                .any(|e| e.data.encode().contains("read_mapping")),
            paired
        );
        if !paired {
            let loss = events
                .iter()
                .find(|e| e.data.encode().contains("tcp_generation_payload_uncertain"))
                .unwrap();
            let request = events
                .iter()
                .find(|e| e.kind == EventKind::Message)
                .unwrap();
            assert!(loss.session.is_some());
            assert_eq!(loss.session, request.session);
            assert!(loss.data.encode().contains("\"window\""));
        }
    }
}

#[test]
fn native_modbus_limits_apply_across_stream_directions() {
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../fixtures/semantics/modbus_fc23_split.pcap");
    for (bytes, messages, issue) in [
        ("19", "2", None),
        ("18", "2", Some("modbus_application_bytes")),
        ("19", "1", Some("modbus_protocol_messages")),
    ] {
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_pcap-stream"))
            .arg("analyze")
            .arg(&fixture)
            .args([
                "--source-bytes",
                "4096",
                "--window-bytes",
                "512",
                "--window-packets",
                "32",
                "--event-bytes",
                "262144",
                "--application-bytes",
                bytes,
                "--native-messages",
                messages,
            ])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let events = String::from_utf8(output.stdout).unwrap();
        assert!(events.lines().last().unwrap().contains("capture.complete"));
        assert_eq!(events.contains("\"read_mapping\""), issue.is_none());
        if let Some(code) = issue {
            assert!(events.contains(code));
            assert_eq!(events.matches("\"kind\":\"protocol.message\"").count(), 1);
        }
    }
}

#[test]
fn native_message_budget_admits_earliest_completed_exchange() {
    use tiny_capture::{capture, tcp};
    let req = [0, 1, 0, 0, 0, 6, 1, 3, 0, 9, 0, 1];
    let rsp = [0, 1, 0, 0, 0, 5, 1, 3, 2, 0x12, 0x34];
    for (second_id, limit, expected_pairs) in [(2, 2, 1), (1, 2, 0), (2, 4, 2)] {
        let mut next_req = req;
        next_req[1] = second_id;
        next_req[9] = 17;
        let mut next_rsp = rsp;
        next_rsp[1] = second_id;
        let raw = capture(&[
            tcp(false, 100, 0, 2, &[]),
            tcp(true, 500, 101, 0x12, &[]),
            tcp(false, 101, 501, 0x18, &req),
            tcp(true, 501, 113, 0x18, &rsp),
            tcp(false, 113, 512, 0x18, &next_req),
            tcp(true, 512, 125, 0x18, &next_rsp),
        ]);
        let mut config = StreamConfig::default();
        config.base.modbus_ports = vec![2000];
        config.base.limits.max_protocol_messages = limit;
        let events = run(&raw, config).events;
        let frames: Vec<_> = events
            .iter()
            .filter(|e| e.kind == EventKind::Message)
            .map(|e| e.evidence.packets[0].frame)
            .collect();
        assert_eq!(frames, (3..3 + limit as u64).collect::<Vec<_>>());
        let mappings: Vec<_> = events
            .iter()
            .filter(|e| e.data.encode().contains("read_mapping"))
            .collect();
        assert_eq!(mappings.len(), expected_pairs);
        if limit == 2 && second_id == 2 {
            assert!(mappings[0]
                .data
                .encode()
                .contains("\"starting_address_zero_based\":9"));
        }
    }
}

#[test]
fn gre_checksum_rejection_resolves_only_completed_fragment_sets() {
    use pcap_evidence::wire::internet_checksum;
    use tiny_capture::{capture, ipv4_fragment, tcp, tunneled};
    let req = [0, 1, 0, 0, 0, 6, 1, 3, 0, 9, 0, 1];
    let rsp = [0, 1, 0, 0, 0, 5, 1, 3, 2, 0x12, 0x34];
    let wrap = |frame: Vec<u8>, reverse| tunneled("gre", 7, reverse, &frame);
    let pair = [
        wrap(tcp(false, 100, 0, 2, &[]), false),
        wrap(tcp(true, 500, 101, 0x12, &[]), true),
        wrap(tcp(false, 101, 501, 0x18, &req), false),
        wrap(tcp(true, 501, 113, 0x18, &rsp), true),
    ];
    let mut good = wrap(tcp(false, 113, 512, 0x18, &req), false);
    good[34] |= 0x80;
    good.splice(38..38, [0; 4]);
    let payload_len = good.len() - 34;
    good[16..18].copy_from_slice(&((20 + payload_len) as u16).to_be_bytes());
    good[24..26].fill(0);
    let ip_checksum = internet_checksum(&good[14..34]);
    good[24..26].copy_from_slice(&ip_checksum.to_be_bytes());
    let gre_checksum = internet_checksum(&good[34..]);
    good[38..40].copy_from_slice(&gre_checksum.to_be_bytes());
    let mut bad = good.clone();
    bad[38] ^= 1;
    let first = ipv4_fragment(&bad, 0..56, true);
    let last = ipv4_fragment(&bad, 56..payload_len, false);
    for (tail, paired) in [
        (vec![good], false),
        (vec![bad], true),
        (vec![first.clone()], false),
        (vec![first, last], true),
    ] {
        let mut frames = pair.to_vec();
        frames.extend(tail);
        let mut config = StreamConfig::default();
        config.base.modbus_ports = vec![2000];
        config.base.checksum_policy = pcap_evidence::wire::ChecksumPolicy::RequireValid;
        let events = run(&capture(&frames), config).events;
        assert_eq!(
            events
                .iter()
                .any(|e| e.data.encode().contains("read_mapping")),
            paired
        );
    }
}

#[test]
fn snapped_opening_syn_uses_the_observed_initial_sequence_number() {
    use tiny_capture::{capture, tcp};
    let req = [0, 1, 0, 0, 0, 6, 1, 3, 0, 9, 0, 1];
    let rsp = [0, 1, 0, 0, 0, 5, 1, 3, 2, 0x12, 0x34];
    let prior = [
        tcp(false, 100, 0, 2, &[]),
        tcp(true, 500, 101, 0x12, &[]),
        tcp(false, 101, 501, 0x18, &req),
        tcp(true, 501, 113, 0x18, &rsp),
    ];
    for (syn, prior_eligible) in [(100, false), (110, true)] {
        let mut frames = prior.to_vec();
        let opening = tcp(false, syn, 0, 2, &req);
        frames.push(opening[..54].to_vec());
        let mut raw = capture(&frames);
        let record = capture(&prior).len();
        raw[record + 12..record + 16].copy_from_slice(&(opening.len() as u32).to_le_bytes());
        let mut config = StreamConfig::default();
        config.base.modbus_ports = vec![2000];
        let root = pcap_evidence::engine::analyze(&raw, config.base.clone()).unwrap();
        assert_eq!(
            pcap_evidence::report::analysis(&root, false)
                .encode()
                .contains("read_mapping"),
            prior_eligible
        );
        assert_eq!(
            run(&raw, config)
                .events
                .iter()
                .any(|e| e.data.encode().contains("read_mapping")),
            prior_eligible
        );
    }
}

#[test]
fn snapped_vxlan_respects_the_outer_ipv6_udp_checksum_policy() {
    use pcap_evidence::wire::{internet_checksum, ChecksumPolicy};
    use tiny_capture::{capture, tcp, tunneled};
    let wrap = |reverse, inner: Vec<u8>| {
        let outer = tunneled("vxlan", 7, reverse, &inner);
        let mut udp = outer[34..].to_vec();
        let mut ip = vec![0; 40];
        ip[0] = 0x60;
        ip[4..6].copy_from_slice(&(udp.len() as u16).to_be_bytes());
        ip[6] = 17;
        ip[7] = 64;
        ip[23] = if reverse { 2 } else { 1 };
        ip[39] = if reverse { 1 } else { 2 };
        let mut pseudo = ip[8..].to_vec();
        pseudo.extend_from_slice(&(udp.len() as u32).to_be_bytes());
        pseudo.extend_from_slice(&[0, 0, 0, 17]);
        pseudo.extend_from_slice(&udp);
        let sum = internet_checksum(&pseudo);
        udp[6..8].copy_from_slice(&(if sum == 0 { u16::MAX } else { sum }).to_be_bytes());
        let mut frame = vec![0; 12];
        frame.extend_from_slice(&[0x86, 0xdd]);
        frame.extend(ip);
        frame.extend(udp);
        frame
    };
    let req = [0, 1, 0, 0, 0, 6, 1, 3, 0, 9, 0, 1];
    let rsp = [0, 1, 0, 0, 0, 5, 1, 3, 2, 0x12, 0x34];
    let pair = [
        wrap(false, tcp(false, 100, 0, 2, &[])),
        wrap(true, tcp(true, 500, 101, 0x12, &[])),
        wrap(false, tcp(false, 101, 501, 0x18, &req)),
        wrap(true, tcp(true, 501, 113, 0x18, &rsp)),
    ];
    for zero in [true, false] {
        let mut tail = wrap(false, tcp(false, 113, 512, 0x18, &req));
        if zero {
            tail[60..62].fill(0);
        }
        let full = tail.len() as u32;
        tail.truncate(tail.len() - req.len());
        let mut frames = pair.to_vec();
        frames.push(tail);
        let mut raw = capture(&frames);
        let at = capture(&pair).len();
        raw[at + 12..at + 16].copy_from_slice(&full.to_le_bytes());
        for policy in [ChecksumPolicy::Observe, ChecksumPolicy::RequireValid] {
            let mut config = StreamConfig::default();
            config.base.modbus_ports = vec![2000];
            config.base.checksum_policy = policy;
            let events = run(&raw, config).events;
            assert_eq!(
                events
                    .iter()
                    .any(|e| e.data.encode().contains("read_mapping")),
                zero && policy == ChecksumPolicy::RequireValid
            );
        }
    }
}

#[test]
fn future_syn_bounds_an_earlier_omitted_payload_across_wraparound() {
    use tiny_capture::{capture, tcp};
    let req = [0, 1, 0, 0, 0, 6, 1, 3, 0, 9, 0, 1];
    let rsp = [0, 1, 0, 0, 0, 5, 1, 3, 2, 0x12, 0x34];
    for (sequence, paired) in [(u32::MAX, true), (0, false), (1, false)] {
        let omitted = tcp(false, sequence, 501, 0x18, &req);
        let mut raw = capture(&[
            omitted[..54].to_vec(),
            tcp(false, u32::MAX, 0, 2, &[]),
            tcp(true, 500, 0, 0x12, &[]),
            tcp(false, 0, 501, 0x18, &req),
            tcp(true, 501, 12, 0x18, &rsp),
        ]);
        raw[36..40].copy_from_slice(&(omitted.len() as u32).to_le_bytes());
        let mut config = StreamConfig::default();
        config.base.modbus_ports = vec![2000];
        let root = pcap_evidence::engine::analyze(&raw, config.base.clone()).unwrap();
        assert_eq!(
            pcap_evidence::report::analysis(&root, false)
                .encode()
                .contains("read_mapping"),
            paired
        );
        assert_eq!(
            run(&raw, config)
                .events
                .iter()
                .any(|e| e.data.encode().contains("read_mapping")),
            paired
        );
    }
}

#[test]
fn udp_tunnel_loss_respects_enclosing_lengths() {
    use tiny_capture::{capture, ipv4_fragment, tcp, tunneled};
    let req = [0, 1, 0, 0, 0, 6, 1, 3, 0, 9, 0, 1];
    let rsp = [0, 1, 0, 0, 0, 5, 1, 3, 2, 0x12, 0x34];
    let wrap = |reverse, frame: Vec<u8>| tunneled("vxlan", 7, reverse, &frame);
    let pair = [
        wrap(false, tcp(false, 100, 0, 2, &[])),
        wrap(true, tcp(true, 500, 101, 0x12, &[])),
        wrap(false, tcp(false, 101, 501, 0x18, &req)),
        wrap(true, tcp(true, 501, 113, 0x18, &rsp)),
    ];
    let mut tail = wrap(false, tcp(false, 113, 512, 0x18, &req));
    let ip_len = tail.len() - 34;
    let mut config = StreamConfig::default();
    config.base.modbus_ports = vec![2000];
    for udp_len in [ip_len, ip_len + 1, ip_len - 1] {
        tail[38..40].copy_from_slice(&(udp_len as u16).to_be_bytes());
        let first = ipv4_fragment(&tail, 0..72, true);
        let last = ipv4_fragment(&tail, 72..ip_len, false);
        let before_gap = ipv4_fragment(&tail, 0..64, true);
        for (suffix, snapped, paired) in [
            (vec![tail.clone()], false, udp_len != ip_len),
            (
                vec![tail[..tail.len() - 8].to_vec()],
                true,
                udp_len != ip_len,
            ),
            (vec![first.clone()], false, udp_len < ip_len),
            (
                vec![before_gap.clone(), last.clone()],
                false,
                udp_len != ip_len,
            ),
            (vec![last.clone(), before_gap], false, udp_len != ip_len),
            (vec![first.clone(), last.clone()], false, udp_len != ip_len),
            (vec![last, first], false, udp_len != ip_len),
        ] {
            let mut frames = pair.to_vec();
            frames.extend(suffix);
            let mut bytes = capture(&frames);
            if snapped {
                let at = capture(&pair).len();
                bytes[at + 12..at + 16].copy_from_slice(&(tail.len() as u32).to_le_bytes());
            }
            let observed = run(&bytes, config.clone())
                .events
                .iter()
                .any(|e| e.data.encode().contains("read_mapping"));
            assert_eq!(
                observed,
                paired,
                "UDP length {udp_len}, {} frames, snapped {snapped}",
                frames.len()
            );
        }
    }
}

#[test]
fn late_predecessor_payload_does_not_belong_to_a_known_successor() {
    use tiny_capture::{capture, tcp};
    let request = [0, 1, 0, 0, 0, 6, 1, 3, 0, 9, 0, 1];
    let response = [0, 1, 0, 0, 0, 5, 1, 3, 2, 0x12, 0x34];
    let exchange = |syn: u32, peer: u32, addr: u8| {
        let mut query = request;
        query[9] = addr;
        vec![
            tcp(false, syn, 0, 2, &[]),
            tcp(true, peer, syn + 1, 0x12, &[]),
            tcp(false, syn + 1, peer + 1, 0x18, &query),
            tcp(true, peer + 1, syn + 13, 0x18, &response),
        ]
    };
    let old = 0xffff1000u32;
    let peer = 0xfffd1000u32;
    let next = old.wrapping_add(4 * 1024 * 1024 + 8);
    let other = peer.wrapping_add(4 * 1024 * 1024 + 8);
    for snap in [false, true] {
        let mut frames = exchange(old, peer, 9);
        frames.extend(exchange(next, other, 17));
        let record = capture(&frames).len();
        let late = tcp(false, old + 13, peer + 12, 0x18, &request);
        let len = late.len() as u32;
        frames.push(if snap { late[..48].to_vec() } else { late });
        let mut bytes = capture(&frames);
        bytes[record + 12..record + 16].copy_from_slice(&len.to_le_bytes());
        let mut config = StreamConfig::default();
        config.base.modbus_ports = vec![2000];
        let root = pcap_evidence::engine::analyze(&bytes, config.base.clone()).unwrap();
        let report = pcap_evidence::report::analysis(&root, false).encode();
        assert_eq!(report.matches("read_mapping").count(), 1);
        assert!(report.contains(r#""starting_address_zero_based":17"#));
        let mapped: Vec<_> = run(&bytes, config)
            .events
            .into_iter()
            .filter(|e| e.data.encode().contains("read_mapping"))
            .collect();
        assert_eq!(mapped.len(), 1);
        assert!(mapped[0]
            .data
            .encode()
            .contains(r#""starting_address_zero_based":17"#));
    }
}

#[test]
fn data_on_a_syn_ack_must_match_the_observed_server_isn() {
    use tiny_capture::{capture, tcp};
    let req = [0, 1, 0, 0, 0, 6, 1, 3, 0, 9, 0, 1];
    let rsp = [0, 1, 0, 0, 0, 5, 1, 3, 2, 0x12, 0x34];
    let pair = [
        tcp(false, 100, 0, 2, &[]),
        tcp(true, 500, 101, 0x12, &[]),
        tcp(false, 101, 501, 0x18, &req),
        tcp(true, 501, 113, 0x18, &rsp),
    ];
    let mut different = rsp;
    different[10] ^= 1;
    for isn in [500, 502] {
        for snapped in [false, true] {
            let extra = tcp(true, isn, 101, 0x12, &different);
            let len = extra.len() as u32;
            let mut frames = pair.to_vec();
            frames.push(if snapped { extra[..54].to_vec() } else { extra });
            let mut raw = capture(&frames);
            let at = capture(&pair).len();
            raw[at + 12..at + 16].copy_from_slice(&len.to_le_bytes());
            let mut c = StreamConfig::default();
            c.base.modbus_ports = vec![2000];
            let root = pcap_evidence::engine::analyze(&raw, c.base.clone()).unwrap();
            assert_eq!(
                pcap_evidence::report::analysis(&root, false)
                    .encode()
                    .contains("read_mapping"),
                isn != 500
            );
            assert_eq!(
                run(&raw, c)
                    .events
                    .iter()
                    .any(|e| e.data.encode().contains("read_mapping")),
                isn != 500
            );
        }
    }
    // The client SYN exists, but the server ISN is still unknown at observation.
    for isn in [500, 502] {
        let extra = tcp(true, isn, 101, 0x12, &different);
        let mut frames = pair.to_vec();
        frames.insert(1, extra[..54].to_vec());
        let mut bytes = capture(&frames);
        let at = capture(&pair[..1]).len();
        bytes[at + 12..at + 16].copy_from_slice(&(extra.len() as u32).to_le_bytes());
        let mut c = StreamConfig::default();
        c.base.modbus_ports = vec![2000];
        let root = pcap_evidence::engine::analyze(&bytes, c.base.clone()).unwrap();
        assert_eq!(
            pcap_evidence::report::analysis(&root, false)
                .encode()
                .contains("read_mapping"),
            isn != 500
        );
        assert_eq!(
            run(&bytes, c)
                .events
                .iter()
                .any(|e| e.data.encode().contains("read_mapping")),
            isn != 500
        );
    }
}

#[test]
fn rejected_reassembly_returns_the_window_slot_before_the_response() {
    use tiny_capture::{capture, ipv4_fragment, tcp};
    let req = [0, 1, 0, 0, 0, 6, 1, 3, 0, 9, 0, 1];
    let rsp = [0, 1, 0, 0, 0, 5, 1, 3, 2, 0x12, 0x34];
    let mut rejected = tcp(false, 113, 501, 0x18, &req);
    rejected[50] ^= 1;
    let first = ipv4_fragment(&rejected, 0..24, true);
    let last = ipv4_fragment(&rejected, 24..32, false);
    for (middle, eligible) in [
        (vec![rejected], true),
        (vec![first.clone(), last.clone()], true),
        (vec![last, first.clone()], true),
        (vec![first], false),
    ] {
        let mut frames = vec![
            tcp(false, 100, 0, 2, &[]),
            tcp(true, 500, 101, 0x12, &[]),
            tcp(false, 101, 501, 0x18, &req),
        ];
        frames.extend(middle);
        frames.push(tcp(true, 501, 113, 0x18, &rsp));
        let mut c = StreamConfig::default();
        c.base.modbus_ports = vec![2000];
        c.base.checksum_policy = pcap_evidence::wire::ChecksumPolicy::RequireValid;
        c.window_packets = 4;
        let events = run(&capture(&frames), c).events;
        assert_eq!(
            events
                .iter()
                .any(|e| e.data.encode().contains("read_mapping")),
            eligible
        );
    }
}

#[test]
fn definitive_fragment_rejection_restores_window_activity() {
    use tiny_capture::{capture, ipv4_fragment, tcp};
    let request = [0, 1, 0, 0, 0, 6, 1, 3, 0, 9, 0, 1];
    let response = [0, 1, 0, 0, 0, 5, 1, 3, 2, 0x12, 0x34];
    let mut rejected = tcp(false, 113, 501, 0x18, &request);
    rejected[50] ^= 1;
    let first = ipv4_fragment(&rejected, 0..24, true);
    let last = ipv4_fragment(&rejected, 24..32, false);
    // Use unrelated records to keep the two representations at the same ages.
    let other = tiny_capture::tunneled("gre", 7, false, &tcp(false, 200, 0, 2, &[]));
    let reply = tcp(true, 501, 113, 0x18, &response);
    for tail in [
        vec![rejected, other.clone(), other.clone(), reply.clone()],
        vec![first.clone(), last.clone(), other.clone(), reply.clone()],
        vec![first, other.clone(), other, reply, last],
    ] {
        let mut frames = vec![
            tcp(false, 100, 0, 2, &[]),
            tcp(true, 500, 101, 0x12, &[]),
            tcp(false, 101, 501, 0x18, &request),
        ];
        frames.extend(tail);
        for (idle_frames, idle_secs, expected_cut) in [
            (3, 60, Some("idle_frame_boundary")),
            (8, 3, Some("idle_time_boundary")),
            (8, 60, None),
        ] {
            let mut c = StreamConfig {
                idle_frames,
                ..StreamConfig::default()
            };
            c.base.idle_timeout_ns = idle_secs * 1_000_000_000;
            c.base.modbus_ports = vec![2000];
            c.base.checksum_policy = pcap_evidence::wire::ChecksumPolicy::RequireValid;
            let events = run(&capture(&frames), c).events;
            assert_eq!(
                events
                    .iter()
                    .any(|e| e.data.encode().contains("read_mapping")),
                expected_cut.is_none()
            );
            if let Some(reason) = expected_cut {
                assert!(events.iter().any(|e| e.data.encode().contains(reason)));
            }
        }
    }
}

#[test]
fn late_server_syn_excludes_predecessor_data_without_losing_the_response() {
    use tiny_capture::{capture, tcp};
    let request = [0, 1, 0, 0, 0, 6, 1, 3, 0, 9, 0, 1];
    let response = [0, 1, 0, 0, 0, 5, 1, 3, 2, 0x12, 0x34];
    for predecessor_first in [true, false] {
        let mut frames = vec![
            tcp(false, 100, 0, 2, &[]),
            tcp(true, 500, 101, 0x12, &[]),
            tcp(true, 470, 101, 0x18, &response),
            tcp(false, 101, 501, 0x18, &request),
            tcp(true, 501, 113, 0x18, &response),
        ];
        if predecessor_first {
            frames.swap(1, 2);
        }
        let mut c = StreamConfig::default();
        c.base.modbus_ports = vec![2000];
        let raw = capture(&frames);
        let root = pcap_evidence::engine::analyze(&raw, c.base.clone()).unwrap();
        let reason = if predecessor_first {
            "stream_position_outside_syn_span"
        } else {
            "sequence_outside_known_generations"
        };
        assert!(pcap_evidence::report::analysis(&root, false)
            .encode()
            .contains(reason));
        assert!(root.flows()[0].reconstruction_errors.is_empty());
        let stream = root.flows()[0].streams[1].as_ref().unwrap();
        assert_eq!(stream.chunks[0].bytes.spans()[0].packet.frame, 5);
        assert!(root
            .transactions
            .iter()
            .any(|t| t.status == "candidate_pair"));
        let events = run(&raw, c).events;
        assert!(events.iter().any(|e| e.data.encode().contains(reason)));
        assert!(events
            .iter()
            .any(|e| e.data.encode().contains("read_mapping")));
    }
}

#[test]
fn fin_uses_the_stream_lower_bound_before_and_after_the_syn_ack() {
    use tiny_capture::{capture, tcp};
    let request = [0, 1, 0, 0, 0, 6, 1, 3, 0, 9, 0, 1];
    let response = [0, 1, 0, 0, 0, 5, 1, 3, 2, 0x12, 0x34];
    for fin_seq in [480, 512] {
        for fin_first in [false, true] {
            let mut frames = vec![
                tcp(false, 100, 0, 2, &[]),
                tcp(true, 500, 101, 0x12, &[]),
                tcp(true, fin_seq, 101, 0x11, &[]),
                tcp(false, 101, 501, 0x18, &request),
                tcp(true, 501, 113, 0x18, &response),
            ];
            if fin_first {
                frames.swap(1, 2);
            }
            let source = capture(&frames);
            let mut config = StreamConfig::default();
            config.base.modbus_ports = vec![2000];
            let snapshot = pcap_evidence::engine::analyze(&source, config.base.clone()).unwrap();
            let flow = &snapshot.flows()[0];
            assert!(flow.reconstruction_errors.is_empty());
            assert_eq!(
                flow.streams[1].as_ref().unwrap().chunks[0].bytes.data(),
                &response
            );
            assert_eq!(
                flow.outside_syn_span.len(),
                usize::from(fin_first && fin_seq == 480)
            );
            assert!(snapshot
                .transactions
                .iter()
                .any(|t| t.status == "candidate_pair"));
            let events = run(&source, config).events;
            assert!(events
                .iter()
                .any(|e| e.data.encode().contains("read_mapping")));
        }
    }
}

mod provisional_transport {
    use super::*;
    use tiny_capture::{capture, ipv4_fragment, tcp};

    const REQUEST: &[u8] = &[0, 1, 0, 0, 0, 6, 1, 3, 0, 9, 0, 1];
    const RESPONSE: &[u8] = &[0, 1, 0, 0, 0, 5, 1, 3, 2, 0x12, 0x34];

    fn config() -> StreamConfig {
        let mut config = StreamConfig::default();
        config.base.modbus_ports = vec![2000];
        config
    }

    fn assert_pair(
        source: &[u8],
        config: StreamConfig,
        expected: bool,
    ) -> pcap_evidence::engine::Analysis {
        let root = pcap_evidence::engine::analyze(source, config.base.clone()).unwrap();
        assert_eq!(
            pcap_evidence::report::analysis(&root, false)
                .encode()
                .contains("read_mapping"),
            expected
        );
        assert_eq!(
            run(source, config)
                .events
                .iter()
                .any(|e| e.data.encode().contains("read_mapping")),
            expected
        );
        root
    }

    fn timed_capture(frames: &[Vec<u8>], seconds: &[u32]) -> Vec<u8> {
        assert_eq!(frames.len(), seconds.len());
        let mut source = capture(frames);
        let mut record = 24;
        for (frame, time) in frames.iter().zip(seconds) {
            source[record..record + 4].copy_from_slice(&time.to_le_bytes());
            record += 16 + frame.len();
        }
        source
    }

    #[test]
    fn completing_fragment_is_adjudicated_before_idle_frame_expiry() {
        let mut duplicate = tcp(false, 113, 501, 0x18, REQUEST);
        duplicate[50] ^= 1;
        let first = ipv4_fragment(&duplicate, 0..24, true);
        let last = ipv4_fragment(&duplicate, 24..32, false);
        let unrelated = tiny_capture::tunneled("gre", 7, false, &tcp(false, 200, 0, 2, &[]));
        for (tail, paired) in [
            (vec![first.clone(), last], true),
            (vec![first, unrelated], false),
            (vec![duplicate.clone(), duplicate], true),
        ] {
            let mut frames = vec![
                tcp(false, 100, 0, 2, &[]),
                tcp(true, 500, 101, 0x12, &[]),
                tcp(false, 101, 501, 0x18, REQUEST),
                tcp(true, 501, 113, 0x18, RESPONSE),
            ];
            frames.extend(tail);
            let mut c = config();
            c.idle_frames = 1;
            c.base.checksum_policy = pcap_evidence::wire::ChecksumPolicy::RequireValid;
            assert_pair(&capture(&frames), c, paired);
        }
    }

    #[test]
    fn provisional_loss_uses_the_final_admitted_idle_interval() {
        let extra = tcp(false, 113, 501, 0x18, REQUEST);
        let first = ipv4_fragment(&extra, 0..24, true);
        for response_first in [false, true] {
            for (fragment_time, response_time, paired) in [
                (124, 123, false),
                (243, 123, false),
                (244, 123, true),
                (124, 124, false),
            ] {
                let mut frames = vec![
                    tcp(false, 100, 0, 2, &[]),
                    tcp(true, 500, 101, 0x12, &[]),
                    tcp(false, 101, 501, 0x18, REQUEST),
                    first.clone(),
                    tcp(true, 501, 113, 0x18, RESPONSE),
                ];
                let mut seconds = [0, 1, 3, fragment_time, response_time];
                if response_first {
                    frames.swap(3, 4);
                    seconds.swap(3, 4);
                }
                let root = assert_pair(&timed_capture(&frames, &seconds), config(), paired);
                if response_time == 123 {
                    assert_eq!(root.flows().len(), 1);
                    assert_eq!(root.flows()[0].uncertain_payload.is_some(), !paired);
                }
            }
        }
    }

    #[test]
    fn peer_syn_ack_replaces_a_provisional_origin_beyond_the_span() {
        for fin_seq in [372, 373, 630] {
            for fin_first in [true, false] {
                let mut frames = vec![
                    tcp(false, 100, 0, 2, &[]),
                    tcp(true, 500, 101, 0x12, &[]),
                    tcp(true, fin_seq, 101, 0x11, &[]),
                    tcp(false, 101, 501, 0x18, REQUEST),
                    tcp(true, 501, 113, 0x18, RESPONSE),
                ];
                if fin_first {
                    frames.swap(1, 2);
                }
                let mut c = config();
                c.base.limits.max_stream_span = 128;
                c.window_payload = 128;
                assert_eq!(assert_pair(&capture(&frames), c, true).flows().len(), 1);
            }
        }
        // Both client SYN extents include the acknowledged position.
        let frames = [
            tcp(false, 100, 0, 2, REQUEST),
            tcp(true, 372, 101, 0x11, &[]),
            tcp(false, 107, 0, 2, &[]),
            tcp(true, 500, 108, 0x12, &[]),
        ];
        let mut c = config();
        c.base.limits.max_stream_span = 128;
        c.window_payload = 128;
        let root = pcap_evidence::engine::analyze(&capture(&frames), c.base.clone()).unwrap();
        assert!(matches!(&root.packets.last().unwrap().disposition,
            pcap_evidence::engine::Disposition::Ambiguous { flows } if flows == &[0,1]));
        assert!(run(&capture(&frames), c)
            .events
            .iter()
            .any(|e| e.data.encode().contains("ambiguous_generation")));
    }

    #[test]
    fn syn_ack_matches_only_the_observed_peer_syn_extent() {
        for isn in [100u32, u32::MAX - 5] {
            for origin in [None, Some(372)] {
                for offset in [0, 1, 6, 13, 14] {
                    let mut frames = vec![tcp(false, isn, 0, 2, REQUEST)];
                    if let Some(origin) = origin {
                        frames.push(tcp(true, origin, isn.wrapping_add(1), 0x11, &[]));
                    }
                    frames.push(tcp(true, 500, isn.wrapping_add(offset), 0x12, &[]));
                    frames.push(tcp(true, 501, isn.wrapping_add(13), 0x18, RESPONSE));
                    let source = capture(&frames);
                    let mut c = config();
                    c.base.limits.max_stream_span = 128;
                    c.window_payload = 128;
                    let root = pcap_evidence::engine::analyze(&source, c.base.clone()).unwrap();
                    let verified = (1..=13).contains(&offset);
                    assert_eq!(
                        root.transactions
                            .iter()
                            .any(|t| t.status == "candidate_pair"),
                        verified
                    );
                    assert_eq!(
                        run(&source, c).events.iter().any(|e| {
                            e.kind == EventKind::Transaction
                                && e.data.encode().contains("\"status\":\"candidate_pair\"")
                        }),
                        verified
                    );
                }
            }
        }
    }

    #[test]
    fn refusing_a_complete_fragment_set_respects_the_checksum_policy() {
        for tunnel in [false, true] {
            let wrap = |frame: Vec<u8>, reverse| {
                if tunnel {
                    tiny_capture::tunneled("vxlan", 7, reverse, &frame)
                } else {
                    frame
                }
            };
            for invalid in [false, true] {
                let mut duplicate = wrap(tcp(false, 113, 501, 0x18, REQUEST), false);
                if invalid {
                    let checksum = if tunnel { 40 } else { 50 };
                    duplicate[checksum] ^= 1;
                }
                let size = duplicate.len() - 34;
                let split = if tunnel { 72 } else { 24 };
                for tail_first in [false, true] {
                    let mut pieces = [
                        ipv4_fragment(&duplicate, 0..split, true),
                        ipv4_fragment(&duplicate, split..size, false),
                    ];
                    if tail_first {
                        pieces.reverse();
                    }
                    let mut frames = vec![
                        wrap(tcp(false, 100, 0, 2, &[]), false),
                        wrap(tcp(true, 500, 101, 0x12, &[]), true),
                        wrap(tcp(false, 101, 501, 0x18, REQUEST), false),
                        wrap(tcp(true, 501, 113, 0x18, RESPONSE), true),
                    ];
                    frames.extend(pieces);
                    for strict in [false, true] {
                        let mut c = config();
                        c.base.limits.max_fragments_per_set = 1;
                        if strict {
                            c.base.checksum_policy =
                                pcap_evidence::wire::ChecksumPolicy::RequireValid;
                        }
                        let events = run(&capture(&frames), c).events;
                        assert!(events
                            .iter()
                            .any(|e| e.data.encode().contains("fragment_context_reset")));
                        assert_eq!(
                            events
                                .iter()
                                .any(|e| e.data.encode().contains("read_mapping")),
                            strict && invalid
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn oversized_reassembly_uses_the_generation_at_completion() {
        let mut next = REQUEST.to_vec();
        next[9] = 11;
        let large = tcp(false, 113, 512, 0x18, &REQUEST.repeat(4));
        let first = ipv4_fragment(&large, 0..24, true);
        let last = ipv4_fragment(&large, 24..68, false);
        for completion in [123, 124] {
            for fragments in [
                vec![large.clone()],
                vec![first.clone(), last.clone()],
                vec![last.clone(), first.clone()],
            ] {
                let mut frames = vec![
                    tcp(false, 100, 0, 2, &[]),
                    tcp(true, 500, 101, 0x12, &[]),
                    tcp(false, 101, 501, 0x18, REQUEST),
                    tcp(true, 501, 113, 0x18, RESPONSE),
                    tcp(false, 100_000_000, 0, 2, &[]),
                    tcp(true, 200_000_000, 100_000_001, 0x12, &[]),
                ];
                let mut seconds = vec![0, 1, 2, 3, 121, 122];
                if fragments.len() == 2 {
                    seconds.push(122);
                }
                frames.extend(fragments);
                frames.push(tcp(false, 100_000_001, 200_000_001, 0x18, &next));
                frames.push(tcp(true, 200_000_001, 100_000_013, 0x18, RESPONSE));
                seconds.extend([completion, 126, 127]);
                let mut c = config();
                c.window_payload = 46;
                let events = run(&timed_capture(&frames, &seconds), c).events;
                let addresses: Vec<_> = events
                    .iter()
                    .filter(|e| {
                        e.kind == EventKind::Transaction && e.data.encode().contains("read_mapping")
                    })
                    .map(|e| e.data.encode())
                    .collect();
                assert!(addresses
                    .iter()
                    .any(|v| v.contains("\"starting_address_zero_based\":11")));
                assert_eq!(
                    addresses
                        .iter()
                        .any(|v| v.contains("\"starting_address_zero_based\":9")),
                    completion > 123
                );
            }
        }
    }

    #[test]
    fn omitted_syn_ack_matches_the_final_extent_of_the_peer_syn() {
        for early_data in [false, true] {
            for (ack, paired) in [(100, true), (101, false), (113, false), (114, true)] {
                let syn = tcp(false, 100, 0, 2, REQUEST);
                let partial = tcp(true, 500, ack, 0x12, RESPONSE);
                let mut frames = vec![tcp(false, 100, 0, 2, &[]), tcp(true, 500, 101, 0x12, &[])];
                if early_data {
                    frames.push(syn.clone());
                }
                let record = capture(&frames).len();
                frames.push(partial[..54].to_vec());
                if !early_data {
                    frames.push(syn);
                }
                frames.push(tcp(true, 501, 113, 0x18, RESPONSE));
                let mut source = capture(&frames);
                source[record + 12..record + 16]
                    .copy_from_slice(&(partial.len() as u32).to_le_bytes());
                assert_pair(&source, config(), paired);
            }
        }
    }

    #[test]
    fn exhausted_loss_attribution_aborts_before_publishing_a_pair() {
        for old_sequence in [498, 500] {
            let mut request = REQUEST.to_vec();
            request[9] = 17;
            let mut frames = vec![
                tcp(false, 1000, 0, 2, &[]),
                tcp(true, old_sequence, 2013, 0x18, RESPONSE),
                tcp(false, 2000, 0, 2, &request),
                tcp(true, 499, 2013, 0x12, RESPONSE),
            ];
            let mut omitted = Vec::new();
            for isn in [3000, 4000] {
                let frame = tcp(false, isn, 0, 2, REQUEST);
                omitted.push((capture(&frames).len(), frame.len() as u32));
                frames.push(frame[..54].to_vec());
            }
            frames.push(tcp(true, 550, 1001, 0x12, &[]));
            let mut source = capture(&frames);
            for (pos, wire_len) in omitted {
                source[pos + 12..pos + 16].copy_from_slice(&wire_len.to_le_bytes());
            }
            for checks in [5, 6, 32] {
                let mut c = config();
                c.base.limits.max_correlation_checks = checks;
                let mut out = Collect::default();
                let registry = Registry::builtins(&c).unwrap();
                let result = analyze_reader(&source[..], c, &registry, &mut out);
                if checks < 6 {
                    assert_eq!(
                        result.unwrap_err().field,
                        "unretained_tcp_generation_checks"
                    );
                    assert_eq!(out.events.last().unwrap().kind, EventKind::CaptureAborted);
                } else {
                    result.unwrap();
                    assert_eq!(out.events.last().unwrap().kind, EventKind::CaptureComplete);
                }
                assert_eq!(
                    out.events
                        .iter()
                        .any(|e| e.data.encode().contains("read_mapping")),
                    checks >= 6 && old_sequence < 500
                );
            }
        }
    }

    #[test]
    fn displaced_payload_keeps_its_original_arrival_for_later_generations() {
        let frames = [
            tcp(false, 1000, 0, 2, &[]),
            tcp(true, 500, 2013, 0x18, RESPONSE),
            tcp(false, 2000, 0, 2, REQUEST),
            tcp(true, 499, 2013, 0x12, RESPONSE),
            tcp(true, 550, 1001, 0x12, &[]),
        ];
        // The correcting SYN-ACK arrives after the second exchange, but its
        // timestamp and acknowledgement place it in the first generation.
        for (second_syn, paired) in [(121, false), (122, true)] {
            let source = timed_capture(&frames, &[0, 1, second_syn, second_syn + 1, 2]);
            let root = pcap_evidence::engine::analyze(&source, config().base).unwrap();
            assert_eq!(root.flows().len(), 2);
            assert_eq!(root.flows()[1].uncertain_payload.is_none(), paired);
            assert_eq!(
                root.transactions
                    .iter()
                    .any(|t| t.status == "candidate_pair"),
                paired
            );
        }
    }

    #[test]
    fn completed_fragment_replaces_the_provisional_loss_before_a_cut() {
        let extra = tcp(false, 113, 512, 0x18, REQUEST);
        let first = ipv4_fragment(&extra, 0..24, true);
        let last = ipv4_fragment(&extra, 24..32, false);
        for (time, bytes, cap, paired) in [
            (124, 512, 8, true),
            (123, 512, 8, false),
            (5, 28, 8, true),
            (124, 512, 1, true),
            (123, 512, 1, false),
        ] {
            for reverse in [false, true] {
                let mut frames = vec![
                    tcp(false, 100, 0, 2, &[]),
                    tcp(true, 500, 101, 0x12, &[]),
                    tcp(false, 101, 501, 0x18, REQUEST),
                    tcp(true, 501, 113, 0x18, RESPONSE),
                    first.clone(),
                    last.clone(),
                ];
                if reverse {
                    frames.swap(4, 5);
                }
                let mut c = config();
                c.window_payload = bytes;
                c.base.limits.max_fragments_per_set = cap;
                let source = timed_capture(&frames, &[0, 1, 2, 3, 4, time]);
                let events = run(&source, c).events;
                assert_eq!(
                    events
                        .iter()
                        .any(|e| e.data.encode().contains("read_mapping")),
                    paired,
                    "completion {time}, window {bytes}, cap {cap}, reverse {reverse}"
                );
            }
        }
    }

    #[test]
    fn pending_syn_ack_uses_the_same_peer_handshake_as_a_complete_segment() {
        for (ack, belongs) in [(101, true), (102, false)] {
            let syn_ack = tcp(true, 500, ack, 0x12, RESPONSE);
            let frames = [
                tcp(false, 100, 0, 2, &[]),
                tcp(true, 372, 101, 0x11, &[]),
                ipv4_fragment(&syn_ack, 0..24, true),
            ];
            let mut c = config();
            c.base.limits.max_stream_span = 128;
            c.window_payload = 128;
            let source = capture(&frames);
            let root = pcap_evidence::engine::analyze(&source, c.base.clone()).unwrap();
            assert_eq!(root.flows()[0].uncertain_payload.is_some(), belongs);
            assert_eq!(
                run(&source, c)
                    .events
                    .iter()
                    .any(|e| { e.data.encode().contains("tcp_generation_payload_uncertain") }),
                belongs
            );
        }
    }

    #[test]
    fn a_late_handshake_releases_window_bytes_before_admission() {
        for on_syn in [false, true] {
            for window in [22, 23, 34] {
                let old = tcp(true, 470, 101, 0x18, RESPONSE);
                let mut frames = vec![
                    tcp(false, 100, 0, 2, &[]),
                    old,
                    tcp(false, 101, 501, 0x18, REQUEST),
                    tcp(true, 500, 101, 0x12, if on_syn { RESPONSE } else { &[] }),
                ];
                if !on_syn {
                    frames.push(tcp(true, 501, 113, 0x18, RESPONSE));
                }
                let mut c = config();
                c.window_payload = window;
                let events = run(&capture(&frames), c).events;
                assert_eq!(
                    events
                        .iter()
                        .any(|e| e.data.encode().contains("read_mapping")),
                    window >= 23,
                    "window {window}, data on SYN {on_syn}"
                );
                assert_eq!(
                    events
                        .iter()
                        .any(|e| e.data.encode().contains("reconstruction_window_budget")),
                    window < 23
                );
            }
        }
    }

    #[test]
    fn correcting_one_window_does_not_evict_an_independent_tuple() {
        let frames = [
            tiny_capture::tunneled("gre", 7, false, &tcp(false, 100, 0, 2, &[])),
            tiny_capture::tunneled("gre", 7, false, &tcp(false, 101, 501, 0x18, REQUEST)),
            tcp(false, 100, 0, 2, &[]),
            tcp(true, 470, 101, 0x18, RESPONSE),
            tcp(false, 101, 501, 0x18, REQUEST),
            tcp(true, 500, 101, 0x12, RESPONSE),
        ];
        let mut c = config();
        c.window_payload = 35;
        c.max_active_payload = 35;
        let events = run(&capture(&frames), c).events;
        assert!(events
            .iter()
            .any(|e| e.data.encode().contains("read_mapping")));
        assert!(!events
            .iter()
            .any(|e| e.data.encode().contains("active_state_budget")));
    }

    #[test]
    fn loss_uses_the_final_syn_span_in_both_arrival_orders() {
        for after_syn in [false, true] {
            for seq in [512, 629, 630] {
                let mut frames = vec![tcp(false, 100, 0, 2, &[]), tcp(true, 374, 101, 0x11, &[])];
                let syn = tcp(true, 500, 101, 0x12, &[]);
                let omitted = tcp(true, seq, 113, 0x18, RESPONSE);
                if after_syn {
                    frames.push(syn.clone());
                }
                let record = capture(&frames).len();
                frames.push(omitted[..54].to_vec());
                if !after_syn {
                    frames.push(syn);
                }
                frames.push(tcp(false, 101, 501, 0x18, REQUEST));
                frames.push(tcp(true, 501, 113, 0x18, RESPONSE));
                let mut bytes = capture(&frames);
                bytes[record + 12..record + 16]
                    .copy_from_slice(&(omitted.len() as u32).to_le_bytes());
                let mut c = config();
                c.base.limits.max_stream_span = 128;
                c.window_payload = 128;
                let root = assert_pair(&bytes, c, seq > 629);
                assert_eq!(root.flows()[0].uncertain_payload.is_some(), seq <= 629);
            }
        }
    }

    #[test]
    fn retained_data_outside_the_final_span_cannot_discard_an_in_span_response() {
        for before_syn in [true, false] {
            let mut frames = vec![
                tcp(false, 100, 0, 2, &[]),
                tcp(true, 565, 101, 0x10, &[]),
                tcp(true, 500, 101, 0x12, &[]),
                tcp(true, 630, 101, 0x18, RESPONSE),
                tcp(false, 101, 501, 0x18, REQUEST),
                tcp(true, 501, 113, 0x18, RESPONSE),
            ];
            if before_syn {
                frames.swap(2, 3);
            }
            let mut c = config();
            c.base.limits.max_stream_span = 128;
            c.window_payload = 128;
            let root = assert_pair(&capture(&frames), c, true);
            assert_eq!(
                root.flows()[0].outside_syn_span.len(),
                usize::from(before_syn)
            );
            assert!(root.flows()[0].reconstruction_errors.is_empty());
        }
    }

    #[test]
    fn fully_observed_empty_fin_preserves_payload_evidence_under_ambiguous_assignment() {
        let fin = tcp(true, 513, 113, 0x11, &[]);
        let first = ipv4_fragment(&fin, 0..16, true);
        let last = ipv4_fragment(&fin, 16..20, false);
        for (tail, complete) in [
            (vec![fin], true),
            (vec![first.clone()], false),
            (vec![first, last], true),
        ] {
            let mut frames = vec![
                tcp(false, 100, 0, 2, &[]),
                tcp(true, 500, 101, 0x12, &[]),
                tcp(false, 101, 501, 0x18, REQUEST),
                tcp(true, 501, 113, 0x18, RESPONSE),
                tcp(false, 112, 0, 2, &[]),
                tcp(true, 512, 113, 0x12, &[]),
            ];
            frames.extend(tail);
            let root = assert_pair(&capture(&frames), config(), complete);
            assert_eq!(root.flows().len(), 2);
            if complete {
                assert!(matches!(&root.packets.last().unwrap().disposition,
                    pcap_evidence::engine::Disposition::Ambiguous {flows} if flows.len()==2));
            }
        }
    }

    #[test]
    fn a_delayed_syn_ack_can_disprove_a_provisional_close() {
        for (server_fin, acknowledgement, count) in [(480, 101, 1), (512, 101, 2), (480, 99, 2)] {
            let frames = [
                tcp(false, 100, 0, 2, &[]),
                tcp(true, server_fin, 101, 0x11, &[]),
                tcp(false, 101, 501, 0x18, REQUEST),
                tcp(false, 113, 501, 0x11, &[]),
                tcp(true, 500, acknowledgement, 0x12, &[]),
                tcp(true, 501, 113, 0x18, RESPONSE),
            ];
            let root = assert_pair(&capture(&frames), config(), count == 1);
            assert_eq!(root.flows().len(), count);
            assert_eq!(root.flows()[0].closed, count == 2);
        }
    }

    #[test]
    fn undecided_fragment_timestamp_cannot_cut_the_window() {
        let mut bad = tcp(false, 113, 501, 0x18, REQUEST);
        bad[50] ^= 1;
        for (response_time, eligible) in [(8000, true), (8001, false)] {
            for fragmented in [false, true] {
                let mut frames = vec![
                    tcp(false, 100, 0, 2, &[]),
                    tcp(true, 500, 101, 0x12, &[]),
                    tcp(false, 101, 501, 0x10, &[]),
                    tcp(false, 101, 501, 0x18, REQUEST),
                ];
                frames.push(if fragmented {
                    ipv4_fragment(&bad, 0..24, true)
                } else {
                    bad.clone()
                });
                frames.push(tcp(true, 501, 113, 0x18, RESPONSE));
                if fragmented {
                    frames.push(ipv4_fragment(&bad, 24..32, false));
                }
                let mut source = capture(&frames);
                let mut at = 24;
                for (frame, micros) in
                    frames
                        .iter()
                        .zip([0u32, 1000, 2000, 3000, 9000, response_time, 10000])
                {
                    source[at..at + 4].copy_from_slice(&1u32.to_le_bytes());
                    source[at + 4..at + 8].copy_from_slice(&micros.to_le_bytes());
                    at += 16 + frame.len();
                }
                let mut c = config();
                c.base.idle_timeout_ns = 5_000_000;
                c.base.checksum_policy = pcap_evidence::wire::ChecksumPolicy::RequireValid;
                let events = run(&source, c).events;
                assert_eq!(
                    events
                        .iter()
                        .any(|e| e.data.encode().contains("read_mapping")),
                    eligible
                );
                assert_eq!(
                    events
                        .iter()
                        .any(|e| e.data.encode().contains("idle_time_boundary")),
                    !eligible
                );
            }
        }
    }
}
