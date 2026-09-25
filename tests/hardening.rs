//! Regression specifications for the hardening candidate. These are authored native tests;
//! the bundle receipt separately states whether they were actually executed.
mod common;
use common::*;
use pcap_evidence::capture::{Decode, Decoder, Endian, ParseMode};
use pcap_evidence::checksum::InternetChecksum;
use pcap_evidence::correlate;
use pcap_evidence::datagram;
use pcap_evidence::dnp3;
use pcap_evidence::engine::{self, ApplicationAnalysis, ApplicationData, Config, Disposition};
use pcap_evidence::fragment::{FragmentOutcome, FragmentReassembler};
use pcap_evidence::modbus::{self, Role};
use pcap_evidence::protocol::*;
use pcap_evidence::provenance::EvidenceBytes;
use pcap_evidence::tcp::{Assignment, OverlapPolicy, StreamAssembler, TcpTracker};
use pcap_evidence::time::Timestamp;
use pcap_evidence::wire::{self, Checksum, Datagram, FragmentInfo};
use pcap_evidence::writer::PcapWriter;
use pcap_evidence::{ErrorCode, Limits};

fn naive_checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u64;
    for pair in bytes.chunks(2) {
        sum += (u64::from(pair[0]) << 8) + u64::from(*pair.get(1).unwrap_or(&0));
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}
fn independent_crc(bytes: &[u8]) -> u16 {
    // MSB-first polynomial, reflected input/output. Candidate uses an LSB loop.
    let mut crc = 0u16;
    for byte in bytes {
        crc ^= u16::from(byte.reverse_bits()) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 {
                (crc << 1) ^ 0x3d65
            } else {
                crc << 1
            };
        }
    }
    (!crc).reverse_bits()
}
fn dnp_frame(user: &[u8], source: u16, destination: u16) -> Vec<u8> {
    assert!(user.len() <= 250);
    let mut out = vec![5, 0x64, (user.len() + 5) as u8, 0xc4];
    out.extend_from_slice(&destination.to_le_bytes());
    out.extend_from_slice(&source.to_le_bytes());
    let crc = independent_crc(&out);
    out.extend_from_slice(&crc.to_le_bytes());
    for block in user.chunks(16) {
        out.extend_from_slice(block);
        out.extend_from_slice(&independent_crc(block).to_le_bytes());
    }
    out
}
fn adu(pdu: &[u8]) -> Vec<u8> {
    let mut out = vec![0, 42, 0, 0];
    out.extend_from_slice(&((pdu.len() + 1) as u16).to_be_bytes());
    out.push(1);
    out.extend_from_slice(pdu);
    out
}
fn fragment(frame: u64, offset: usize, more: bool, protocol: u8, bytes: &[u8]) -> Datagram {
    Datagram {
        scope: scope(),
        source: "2001:db8::1".parse().unwrap(),
        destination: "2001:db8::2".parse().unwrap(),
        protocol,
        ipv6: true,
        network_header_len: 48,
        fragment: Some(FragmentInfo {
            id: 123,
            offset,
            more,
        }),
        payload: EvidenceBytes::from_packet(bytes, id(frame), 0),
        ip_checksum: Checksum::NotPresent,
    }
}
fn udp_capture(payloads: &[Vec<u8>]) -> Vec<u8> {
    let mut writer = PcapWriter::new(
        Vec::new(),
        Endian::Little,
        false,
        228,
        65535,
        Limits::default(),
    )
    .unwrap();
    for (i, payload) in payloads.iter().enumerate() {
        let mut packet = vec![0u8; 28];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&((28 + payload.len()) as u16).to_be_bytes());
        packet[8] = 64;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&[10, 0, 0, 1]);
        packet[16..20].copy_from_slice(&[10, 0, 0, 2]);
        packet[20..22].copy_from_slice(&12000u16.to_be_bytes());
        packet[22..24].copy_from_slice(&20000u16.to_be_bytes());
        packet[24..26].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        let checksum = naive_checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&checksum.to_be_bytes());
        packet.extend_from_slice(payload);
        writer
            .packet(
                Timestamp::legacy(i as u32 + 1, 0, false).unwrap(),
                packet.len() as u32,
                &packet,
            )
            .unwrap();
    }
    writer.finish().unwrap()
}

#[test]
fn incremental_checksum_matches_independent_oracle_for_every_split() {
    for length in 0..258 {
        let bytes: Vec<_> = (0..length).map(|n| ((n * 31 + 7) % 256) as u8).collect();
        for cut in 0..=length {
            let mut sum = InternetChecksum::new();
            sum.update(&bytes[..cut]);
            sum.update(&[]);
            sum.update(&bytes[cut..]);
            assert_eq!(
                sum.finish(),
                naive_checksum(&bytes),
                "length {length}, split {cut}"
            );
        }
    }
}
#[test]
fn checksum_odd_byte_survives_snapshot_and_empty_updates() {
    let mut sum = InternetChecksum::new();
    sum.update(&[0xab]);
    assert_eq!(sum.finish(), 0x54ff);
    sum.update(&[]);
    sum.update(&[0xcd]);
    assert_eq!(sum.finish(), 0x5432);
}
#[test]
fn independent_dnp_builder_matches_published_crc_check_value() {
    assert_eq!(independent_crc(b"123456789"), 0xea82);
}
#[test]
fn decoder_rejects_overflowing_public_offsets_without_panicking() {
    let decoder = Decoder::new(Limits::default(), ParseMode::Strict).unwrap();
    assert_eq!(
        decoder
            .required(&[0xd4, 0xc3, 0xb2, 0xa1], u64::MAX)
            .unwrap_err()
            .code,
        ErrorCode::LimitExceeded
    );
}
#[test]
fn finite_section_length_alignment_is_owned_by_shb_decoder() {
    for declared in [1i64, 2, 3, 5] {
        let mut raw = Vec::new();
        for n in [0x0a0d0d0a, 28, 0x1a2b3c4d] {
            Endian::Little.put_u32(n, &mut raw);
        }
        Endian::Little.put_u16(1, &mut raw);
        Endian::Little.put_u16(0, &mut raw);
        raw.extend_from_slice(&declared.to_le_bytes());
        Endian::Little.put_u32(28, &mut raw);
        let mut decoder = Decoder::new(Limits::default(), ParseMode::Strict).unwrap();
        let error = decoder
            .decode(&raw, 0)
            .err()
            .expect("SHB itself must reject");
        assert_eq!(error.code, ErrorCode::InvalidLength);
        assert_eq!(error.field, "section_length");
        raw[16..24].copy_from_slice(&0i64.to_le_bytes());
        let mut valid = Decoder::new(Limits::default(), ParseMode::Strict).unwrap();
        assert!(matches!(valid.decode(&raw, 0).unwrap(), Decode::Record(_)));
        valid.finish(28).unwrap();
    }
}
#[test]
fn ipv6_nonzero_next_header_does_not_split_reassembly_identity() {
    let mut r = FragmentReassembler::new(Limits::default());
    assert!(matches!(
        r.push(fragment(1, 8, false, 6, b"ijklmnop"), 1).unwrap(),
        FragmentOutcome::Pending
    ));
    match r.push(fragment(2, 0, true, 17, b"abcdefgh"), 2).unwrap() {
        FragmentOutcome::Complete(d, ids) => {
            assert_eq!(d.protocol, 17);
            assert_eq!(d.payload.data(), b"abcdefghijklmnop");
            assert_eq!(ids.len(), 2);
        }
        _ => panic!("offset-zero Next Header must govern one complete datagram"),
    }
}
#[test]
fn ipv6_next_header_variation_cannot_hide_an_overlap() {
    let mut r = FragmentReassembler::new(Limits::default());
    r.push(fragment(1, 0, true, 17, b"abcdefgh"), 1).unwrap();
    match r.push(fragment(2, 0, true, 6, b"XXXXXXXX"), 2).unwrap() {
        FragmentOutcome::Rejected(n) => assert_eq!(n.code, "ipv6_overlapping_fragments"),
        _ => panic!("overlap must not create a separate protocol-keyed set"),
    }
}
#[test]
fn fragment_deadline_keeps_original_strict_boundary() {
    let limits = Limits {
        fragment_frame_lifetime: 2,
        ..Limits::default()
    };
    let mut r = FragmentReassembler::new(limits);
    r.push(fragment(10, 0, true, 17, b"abcdefgh"), 10).unwrap();
    assert!(r.expire(12).is_empty());
    assert_eq!(r.expire(13)[0].code, "fragment_expired");
    assert!(r.expire(14).is_empty());
}
#[test]
fn ipv6_empty_no_next_header_with_link_padding_is_not_jumbo() {
    let mut packet = vec![0; 60];
    packet[12..14].copy_from_slice(&0x86ddu16.to_be_bytes());
    packet[14] = 0x60;
    packet[20] = 59; // IPv6 No Next Header; 6 bytes L2 padding.
    let decoded = wire::decode_packet(1, &packet, id(1), scope()).unwrap();
    assert!(decoded.payload.is_empty());
    assert_eq!(decoded.protocol, 59);
}
#[test]
fn evidence_slices_and_appends_preserve_every_source_offset() {
    let mut bytes = EvidenceBytes::default();
    for frame in 1..=1000 {
        bytes
            .append(
                &EvidenceBytes::from_packet(&[frame as u8], id(frame), 10),
                1000,
            )
            .unwrap();
    }
    assert!(bytes.validate());
    let view = bytes.slice(990..1000).unwrap();
    assert_eq!(view.spans().len(), 10);
    assert_eq!(view.spans()[0].packet.frame, 991);
    assert_eq!(view.spans()[0].packet_start, 10);
    assert!(view.validate());
}
#[test]
fn invalid_source_offset_cannot_be_laundered_by_empty_slice() {
    let invalid = EvidenceBytes::from_packet(b"X", id(1), usize::MAX);
    assert!(!invalid.validate());
    assert!(invalid.slice(0..0).is_err());
    assert!(EvidenceBytes::default().append(&invalid, 10).is_err());
}
#[test]
fn failed_evidence_append_preserves_bytes_and_spans() {
    let mut bytes = EvidenceBytes::from_packet(b"A", id(1), 0);
    let before = bytes.clone();
    assert!(bytes
        .append(&EvidenceBytes::from_packet(b"BC", id(2), 0), 2)
        .is_err());
    assert_eq!(bytes, before);
}
#[test]
fn fin_seen_before_payload_cannot_be_forgotten() {
    let mut s = StreamAssembler::new(None, Limits::default());
    s.end_at(1010).unwrap();
    s.push(1011, evidence(b"X", 2)).unwrap();
    assert_eq!(
        s.finish(OverlapPolicy::RejectConflict).unwrap_err().code,
        ErrorCode::SequenceAmbiguous
    );
}
#[test]
fn earlier_payload_after_fin_observation_is_still_reconstructible() {
    let mut s = StreamAssembler::new(None, Limits::default());
    s.end_at(1010).unwrap();
    s.push(1000, evidence(b"0123456789", 2)).unwrap();
    let result = s.finish(OverlapPolicy::RejectConflict).unwrap();
    assert_eq!(result.chunks[0].offset, -10);
    assert_eq!(result.chunks[0].bytes.data(), b"0123456789");
}
#[test]
fn expired_identical_syn_creates_new_generation_but_live_retransmission_does_not() {
    for (second_time, expected) in [(Some(10), 0), (Some(11), 1), (None, 0)] {
        let mut tracker = TcpTracker::new(Limits::default(), 10).unwrap();
        tracker
            .ingest(scope(), id(1), Some(0), segment(100, 0, 2, b"", 1))
            .unwrap();
        let result = tracker
            .ingest(scope(), id(2), second_time, segment(100, 0, 2, b"", 2))
            .unwrap();
        assert!(matches!(result, Assignment::Assigned { flow_id, .. } if flow_id == expected));
    }
}
#[test]
fn payload_budget_error_does_not_leave_a_phantom_tcp_generation() {
    let limits = Limits {
        max_retained_payload: 1,
        ..Limits::default()
    };
    let mut tracker = TcpTracker::new(limits, 10).unwrap();
    assert!(tracker
        .ingest(scope(), id(1), Some(0), segment(100, 0, 2, b"AB", 1))
        .is_err());
    assert!(tracker
        .finish(OverlapPolicy::RejectConflict)
        .unwrap()
        .is_empty());
}
#[test]
fn malformed_modbus_quantities_counts_and_values_are_not_validated() {
    let cases: &[(Role, &[u8])] = &[
        (Role::Request, &[3, 0, 0, 0, 0]),
        (Role::Request, &[3, 0, 0, 0, 126]),
        (Role::Request, &[3, 0xff, 0xff, 0, 2]),
        (Role::Request, &[5, 0, 0, 0x12, 0x34]),
        (Role::Request, &[15, 0, 0, 0, 9, 1, 0xff]),
        (Role::Request, &[16, 0, 0, 0, 2, 2, 0, 0]),
        (Role::Response, &[3, 3, 0, 1, 2]),
        (Role::Response, &[1, 0]),
        (Role::Response, &[0x83, 0]),
    ];
    for (role, pdu) in cases {
        let result = modbus::decode(&stream(&adu(pdu)), *role, &Limits::default()).unwrap();
        assert_eq!(result.messages.len(), 1);
        assert!(!result.messages[0].shape_valid, "{pdu:?}");
    }
}
#[test]
fn valid_modbus_boundary_quantities_still_pass() {
    for pdu in [
        vec![3, 0, 0, 0, 125],
        vec![3, 0xff, 0xff, 0, 1],
        vec![1, 0, 0, 7, 0xd0],
        vec![5, 0, 0, 0xff, 0],
    ] {
        let result =
            modbus::decode(&stream(&adu(&pdu)), Role::Request, &Limits::default()).unwrap();
        assert!(result.messages[0].shape_valid, "{pdu:?}");
        assert!(result.issues.is_empty());
    }
}
#[test]
fn modbus_budget_includes_issues_and_messages_before_emitting() {
    let limits = Limits {
        max_protocol_messages: 1,
        ..Limits::default()
    };
    assert!(modbus::decode(&stream(&adu(&[0x41])), Role::Request, &limits).is_err());
    assert!(modbus::decode(&stream(&adu(&[6, 0, 0, 0, 1])), Role::Request, &limits).is_ok());
    let limits = Limits {
        max_protocol_messages: 2,
        ..limits
    };
    let result = modbus::decode(&stream(&adu(&[0x41])), Role::Request, &limits).unwrap();
    assert_eq!(result.messages.len() + result.issues.len(), 2);
}
#[test]
fn modbus_adu_respects_application_byte_limit() {
    let bytes = adu(&[6, 0, 0, 0, 1]);
    assert!(modbus::decode(
        &stream(&bytes),
        Role::Request,
        &Limits {
            max_application_bytes: 11,
            ..Limits::default()
        }
    )
    .is_err());
    assert!(modbus::decode(
        &stream(&bytes),
        Role::Request,
        &Limits {
            max_application_bytes: 12,
            ..Limits::default()
        }
    )
    .is_ok());
}
#[test]
fn modbus_pairing_checks_response_size_not_just_transaction_id() {
    let req = modbus::decode(
        &stream(&adu(&[3, 0, 0, 0, 2])),
        Role::Request,
        &Limits::default(),
    )
    .unwrap();
    let rsp = modbus::decode(
        &stream(&adu(&[3, 2, 0, 1])),
        Role::Response,
        &Limits::default(),
    )
    .unwrap();
    assert!(!modbus::response_matches(
        &req.messages[0],
        &rsp.messages[0]
    ));
    let apps = vec![
        ApplicationAnalysis {
            flow: 0,
            direction: 0,
            protocol: "modbus",
            data: ApplicationData::Modbus(req),
        },
        ApplicationAnalysis {
            flow: 0,
            direction: 1,
            protocol: "modbus",
            data: ApplicationData::Modbus(rsp),
        },
    ];
    assert_eq!(
        correlate::transactions(&apps, &Limits::default()).unwrap()[0].status,
        "inconsistent_response"
    );
}
#[test]
fn invalid_modbus_request_does_not_become_a_response_reference() {
    let parsed = modbus::decode(
        &stream(&adu(&[3, 0, 0, 0, 0])),
        Role::Request,
        &Limits::default(),
    )
    .unwrap();
    let apps = [ApplicationAnalysis {
        flow: 0,
        direction: 0,
        protocol: "modbus",
        data: ApplicationData::Modbus(parsed),
    }];
    let transactions = correlate::transactions(&apps, &Limits::default()).unwrap();
    assert_eq!(transactions[0].requests.len(), 1);
    assert!(transactions[0].responses.is_empty());
}
#[test]
fn dnp_transport_gap_cannot_bridge_application_fragments() {
    let mut bytes = dnp_frame(&[0xc0, 0x8f, 0x81, 0, 0, b'A'], 2, 1);
    bytes.extend(dnp_frame(&[0x41, 0x40, 0x81], 2, 1));
    bytes.extend(dnp_frame(&[0x83, 0, 0, b'X'], 2, 1)); // missing transport sequence 2
    bytes.extend(dnp_frame(&[0xc4, 0x40, 0x81, 0, 0, b'B'], 2, 1));
    let parsed = dnp3::decode(&stream(&bytes), &Limits::default()).unwrap();
    assert!(parsed.messages.iter().all(|m| !m.complete));
    assert!(parsed
        .issues
        .iter()
        .any(|i| i.code == "orphan_dnp3_application_fragment"));
}
#[test]
fn valid_dnp_application_wrap_and_other_address_pair_survive() {
    let mut bytes = dnp_frame(&[0xc0, 0x8f, 0x81, 0, 0, b'A'], 2, 1);
    bytes.extend(dnp_frame(&[0x41, 0x40, 0x81], 4, 3));
    bytes.extend(dnp_frame(&[0x83, 0, 0, b'X'], 4, 3));
    bytes.extend(dnp_frame(&[0xc4, 0x40, 0x81, 0, 0, b'B'], 2, 1));
    let parsed = dnp3::decode(&stream(&bytes), &Limits::default()).unwrap();
    assert!(parsed
        .messages
        .iter()
        .any(|m| m.complete && m.objects.data() == b"AB"));
}
#[test]
fn first_dnp_transport_segment_obeys_application_limit() {
    let bytes = dnp_frame(&[0xc0, 0xc0, 0x81, 0, 0, b'A'], 2, 1);
    assert!(dnp3::decode(
        &stream(&bytes),
        &Limits {
            max_application_bytes: 4,
            ..Limits::default()
        }
    )
    .is_err());
    assert!(dnp3::decode(
        &stream(&bytes),
        &Limits {
            max_application_bytes: 5,
            ..Limits::default()
        }
    )
    .is_ok());
}
#[test]
fn dnp_public_stream_offset_overflow_is_typed_not_a_panic() {
    let mut bytes = vec![0];
    bytes.extend(dnp_frame(&[0xc0, 0xc0, 1], 1, 2));
    let error = dnp3::parse_link(&evidence(&bytes, 1), 1, i64::MAX)
        .err()
        .unwrap();
    assert_eq!(error.code, ErrorCode::LimitExceeded);
}
#[test]
fn udp_dnp3_reaches_engine_and_report_with_original_contributors() {
    let capture = udp_capture(&[dnp_frame(&[0xc0, 0xc0, 1, 0x3c, 2, 6], 1, 2)]);
    let parsed = engine::analyze(&capture, Config::default()).unwrap();
    assert_eq!(parsed.datagrams.len(), 1);
    assert!(parsed.flows.is_empty());
    assert!(matches!(parsed.packets[0].disposition, Disposition::Udp));
    assert_eq!(parsed.datagrams[0].packets, vec![parsed.packets[0].id]);
    let dnp = parsed.datagrams[0].data.as_ref().unwrap();
    assert_eq!(dnp.messages.len(), 1);
    assert!(dnp.messages[0].complete);
    let json = pcap_evidence::report::analysis(&parsed, true).encode();
    assert!(json.contains("udp_applications"));
    assert!(json.contains("single_udp_datagram_no_cross_datagram_state"));
}
#[test]
fn independent_udp_datagrams_never_supply_a_reliable_byte_stream() {
    let first = evidence(&dnp_frame(&[0x40, 0xc0, 1], 1, 2), 1);
    let last = evidence(&dnp_frame(&[0x81, 0x3c, 2, 6], 1, 2), 2);
    for bytes in [&first, &last] {
        let parsed = datagram::decode_dnp3_datagram(bytes, &Limits::default()).unwrap();
        assert!(parsed.messages.iter().all(|m| !m.complete));
        assert!(!parsed.issues.is_empty());
    }
}
#[test]
fn dnp_probe_checks_all_crcs_and_does_not_require_a_standard_port() {
    let mut frame = dnp_frame(&[0xc0, 0xc0, 1], 1, 2);
    let inspect = |bytes: &[u8]| {
        Dnp3Probe.probe(&ProbeInput {
            transport: ProbeTransport::Tcp,
            source_port: 1234,
            destination_port: 4321,
            prefix: bytes,
        })
    };
    assert!(matches!(
        inspect(&frame),
        ProbeResult::Match {
            strength: ProbeStrength::CompleteFrameChecksums,
            ..
        }
    ));
    frame[10] ^= 1;
    assert_eq!(inspect(&frame), ProbeResult::NoMatch);
}

#[test]
fn dnp_reserved_and_unknown_link_controls_remain_explicit_diagnostics() {
    let mut primary = dnp_frame(&[], 1, 2);
    primary[3] = 0xc5; // primary function 5 is outside the defined link catalog
    let primary_crc = independent_crc(&primary[..8]);
    primary[8..10].copy_from_slice(&primary_crc.to_le_bytes());

    let mut secondary = dnp_frame(&[], 2, 1);
    secondary[3] = 0xa2; // secondary reserved bit plus unknown function 2
    let secondary_crc = independent_crc(&secondary[..8]);
    secondary[8..10].copy_from_slice(&secondary_crc.to_le_bytes());

    let mut bytes = primary;
    bytes.extend_from_slice(&secondary);
    let parsed = dnp3::decode(&stream(&bytes), &Limits::default()).unwrap();

    assert_eq!(parsed.frames.len(), 2);
    assert!(parsed
        .issues
        .iter()
        .any(|issue| issue.code == "dnp3_reserved_link_control_bit"));
    assert_eq!(
        parsed
            .issues
            .iter()
            .filter(|issue| issue.code == "dnp3_reserved_link_control_bit")
            .count(),
        1
    );
    assert_eq!(
        parsed
            .issues
            .iter()
            .filter(|issue| issue.code == "unsupported_dnp3_link_function")
            .count(),
        2
    );
    assert!(parsed.messages.is_empty());
}
#[test]
fn modbus_probe_is_explicitly_weak_and_tcp_only() {
    let bytes = adu(&[3, 0, 0, 0, 1]);
    let input = ProbeInput {
        transport: ProbeTransport::Tcp,
        source_port: 1234,
        destination_port: 4321,
        prefix: &bytes,
    };
    assert!(matches!(
        ModbusProbe.probe(&input),
        ProbeResult::Match {
            strength: ProbeStrength::HeaderStructure,
            ..
        }
    ));
    assert_eq!(
        ModbusProbe.probe(&ProbeInput {
            transport: ProbeTransport::Udp,
            ..input
        }),
        ProbeResult::NoMatch
    );
}
#[test]
fn probe_registry_bounds_and_duplicate_names_are_explicit() {
    let mut registry = ProbeRegistry::new(1, 1).unwrap();
    registry.register(Box::new(Dnp3Probe)).unwrap();
    assert!(registry.register(Box::new(Dnp3Probe)).is_err());
    assert!(registry
        .inspect(&ProbeInput {
            transport: ProbeTransport::Tcp,
            source_port: 0,
            destination_port: 0,
            prefix: &[5, 0x64]
        })
        .is_err());
}

#[test]
fn rejected_fragment_admission_does_not_leave_state_or_contributors() {
    let mut r = FragmentReassembler::new(Limits {
        max_retained_payload: 4,
        ..Limits::default()
    });
    assert!(r.push(fragment(1, 0, true, 17, b"abcdefgh"), 1).is_err());
    assert!(r.finish().is_empty());
    let mut valid = FragmentReassembler::new(Limits {
        max_retained_payload: 8,
        ..Limits::default()
    });
    assert!(matches!(
        valid
            .push(fragment(1, 0, true, 17, b"abcdefgh"), 1)
            .unwrap(),
        FragmentOutcome::Pending
    ));
    assert_eq!(valid.finish()[0].packets, vec![id(1)]);
}

#[test]
fn fragment_budget_failure_does_not_change_existing_terminal_length() {
    let mut r = FragmentReassembler::new(Limits {
        max_retained_payload: 12,
        ..Limits::default()
    });
    r.push(fragment(1, 0, true, 17, b"abcdefgh"), 1).unwrap();
    assert!(r.push(fragment(2, 8, false, 17, b"ijklmnop"), 2).is_err());
    match r.push(fragment(3, 8, false, 17, b"ijkl"), 3).unwrap() {
        FragmentOutcome::Complete(d, contributors) => {
            assert_eq!(d.payload.data(), b"abcdefghijkl");
            assert_eq!(contributors, vec![id(1), id(3)]);
        }
        _ => {
            panic!("rejected 16-byte terminal candidate must not poison a valid 12-byte completion")
        }
    }
}

#[test]
fn valid_modbus_response_matches_but_forged_flags_do_not_authorize_unknown_functions() {
    let req = modbus::decode(
        &stream(&adu(&[3, 0, 0, 0, 2])),
        Role::Request,
        &Limits::default(),
    )
    .unwrap();
    let rsp = modbus::decode(
        &stream(&adu(&[3, 4, 0, 1, 0, 2])),
        Role::Response,
        &Limits::default(),
    )
    .unwrap();
    assert!(modbus::response_matches(&req.messages[0], &rsp.messages[0]));
    let mut unknown_req =
        modbus::decode(&stream(&adu(&[0x41])), Role::Request, &Limits::default()).unwrap();
    let mut unknown_rsp = modbus::decode(
        &stream(&adu(&[0xc1, 2])),
        Role::Response,
        &Limits::default(),
    )
    .unwrap();
    unknown_req.messages[0].semantics_supported = true;
    unknown_rsp.messages[0].semantics_supported = true;
    assert!(!modbus::response_matches(
        &unknown_req.messages[0],
        &unknown_rsp.messages[0]
    ));
    let mut forged = req.messages[0].clone();
    forged.transaction = 99;
    assert!(!modbus::response_matches(&forged, &rsp.messages[0]));
}

#[test]
fn crc_failure_in_udp_is_a_diagnostic_not_a_clean_application() {
    let mut frame = dnp_frame(&[0xc0, 0xc0, 1], 1, 2);
    frame[10] ^= 1;
    let analysis = engine::analyze(&udp_capture(&[frame]), Config::default()).unwrap();
    assert_eq!(analysis.datagrams.len(), 1);
    assert!(analysis.has_diagnostics());
    assert!(analysis.datagrams[0]
        .data
        .as_ref()
        .unwrap()
        .messages
        .is_empty());
}

#[test]
fn probe_request_for_unreachable_prefix_is_a_budget_error() {
    let mut registry = ProbeRegistry::new(1, 1).unwrap();
    registry.register(Box::new(Dnp3Probe)).unwrap();
    let error = registry
        .inspect(&ProbeInput {
            transport: ProbeTransport::Tcp,
            source_port: 0,
            destination_port: 0,
            prefix: &[5],
        })
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::LimitExceeded);
}

#[test]
fn engine_does_not_silently_choose_between_conflicting_protocol_endpoints() {
    // The fixture's Modbus service is 502 and client port is read from the first
    // observed flow. Configuring that distinct port as DNP3 creates a conflict.
    let capture = fixture("modbus_tcp.pcap");
    let initial = engine::analyze(&capture, Config::default()).unwrap();
    let flow = &initial.flows[0];
    let other = if flow.key.a.port == 502 {
        flow.key.b.port
    } else {
        flow.key.a.port
    };
    let config = Config {
        dnp3_ports: vec![other],
        ..Config::default()
    };
    let analysis = engine::analyze(&capture, config).unwrap();
    assert!(!analysis.applications.is_empty());
    assert!(analysis
        .applications
        .iter()
        .all(|app| app.protocol == "ambiguous" && matches!(app.data, ApplicationData::Failed(_))));
    assert!(analysis.transactions.is_empty());
}
