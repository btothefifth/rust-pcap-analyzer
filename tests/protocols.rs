mod common;
use common::*;
use pcap_evidence::dnp3::{self, MessageClass};
use pcap_evidence::engine::{analyze, ApplicationData, Config, Disposition};
use pcap_evidence::modbus::{self, Role};
use pcap_evidence::tcp::{OverlapPolicy, StreamAssembler};
use pcap_evidence::Limits;

#[test]
fn dnp_crc_matches_external_check_vector() {
    assert_eq!(dnp3::crc16_dnp(b"123456789"), 0xea82);
}
#[test]
fn dnp_transport_sequence_63_to_0_reassembles() {
    let parsed = dnp3::decode(
        &stream(&fixture("dnp3_transport_wrap.bin")),
        &Limits::default(),
    )
    .unwrap();
    assert_eq!(parsed.frames.len(), 2);
    assert_eq!(parsed.fragments.len(), 1);
    assert_eq!(parsed.messages.len(), 1);
    assert_eq!(parsed.messages[0].objects.data(), &[0x3c, 2, 6]);
    assert!(parsed.messages[0].complete);
    assert_eq!(parsed.messages[0].class, MessageClass::Request);
    assert!(parsed.issues.is_empty());
}
#[test]
fn dnp_application_sequence_15_to_0_keeps_fragment_boundaries() {
    let parsed = dnp3::decode(
        &stream(&fixture("dnp3_application_wrap.bin")),
        &Limits::default(),
    )
    .unwrap();
    assert_eq!(parsed.fragments.len(), 2);
    assert_eq!(parsed.messages.len(), 1);
    assert_eq!(parsed.messages[0].objects.data(), b"AB");
    assert!(parsed.messages[0].complete);
    assert_eq!(parsed.messages[0].first_sequence, 15);
    assert_eq!(parsed.messages[0].fragments, vec![0, 1]);
}
#[test]
fn bad_link_between_application_fragments_cannot_bridge_to_success() {
    let parsed = dnp3::decode(
        &stream(&fixture("dnp3_interrupted.bin")),
        &Limits::default(),
    )
    .unwrap();
    assert!(parsed.messages.iter().all(|m| !m.complete));
    assert!(parsed.issues.iter().any(|i| i.code == "dnp3_crc_failure"));
    assert!(parsed
        .issues
        .iter()
        .any(|i| i.code == "orphan_dnp3_application_fragment"));
}
#[test]
fn tcp_gap_never_crosses_a_dnp_transport_assembly() {
    let data = fixture("dnp3_transport_wrap.bin");
    let (_, first_length) = dnp3::parse_link(&evidence(&data, 1), 0, 0).unwrap();
    let mut s = StreamAssembler::new(Some(1000), Limits::default());
    s.push(1001, evidence(&data[..first_length], 1)).unwrap();
    s.push(
        1002 + first_length as u32,
        evidence(&data[first_length..], 2),
    )
    .unwrap();
    let parsed = dnp3::decode(
        &s.finish(OverlapPolicy::RejectConflict).unwrap(),
        &Limits::default(),
    )
    .unwrap();
    assert!(parsed.messages.is_empty());
    assert!(parsed
        .issues
        .iter()
        .any(|i| i.code == "incomplete_dnp3_transport_at_gap_or_eof"));
}
#[test]
fn end_to_end_dnp_reorders_tcp_deduplicates_and_separates_unsolicited() {
    let analysis = analyze(&fixture("dnp3_tcp.pcap"), Config::default()).unwrap();
    assert_eq!(analysis.packets.len(), 10);
    assert_eq!(analysis.flows.len(), 1);
    assert!(analysis
        .packets
        .iter()
        .all(|p| matches!(p.disposition, Disposition::Tcp { flow: 0, .. })));
    assert_eq!(analysis.flows[0].packets.len(), 10);
    assert!(analysis.flows[0].reconstruction_errors.is_empty());
    let messages: Vec<_> = analysis
        .applications
        .iter()
        .filter_map(|a| match &a.data {
            ApplicationData::Dnp3(d) => Some(&d.messages),
            _ => None,
        })
        .flatten()
        .collect();
    assert_eq!(messages.len(), 3);
    assert_eq!(
        messages
            .iter()
            .filter(|m| m.class == MessageClass::Unsolicited)
            .count(),
        1
    );
    assert_eq!(
        messages
            .iter()
            .find(|m| m.class == MessageClass::Request)
            .unwrap()
            .objects
            .data(),
        &[0x3c, 2, 6]
    );
    assert_eq!(
        analysis
            .transactions
            .iter()
            .filter(|t| t.status == "candidate_pair")
            .count(),
        1
    );
    assert_eq!(
        analysis
            .transactions
            .iter()
            .filter(|t| t.status == "unsolicited")
            .count(),
        1
    );
}
#[test]
fn crc_failure_report_does_not_reject_unrelated_valid_unsolicited_message() {
    let analysis = analyze(&fixture("dnp3_bad_crc.pcap"), Config::default()).unwrap();
    assert!(analysis.has_diagnostics());
    let mut unsolicited = 0;
    let mut responses = 0;
    for a in &analysis.applications {
        if let ApplicationData::Dnp3(d) = &a.data {
            unsolicited += d
                .messages
                .iter()
                .filter(|m| m.class == MessageClass::Unsolicited)
                .count();
            responses += d
                .messages
                .iter()
                .filter(|m| m.class == MessageClass::Response)
                .count();
        }
    }
    assert_eq!(unsolicited, 1);
    assert_eq!(responses, 0);
}
#[test]
fn modbus_coalesced_pdus_and_function_shapes() {
    let result = modbus::decode(
        &stream(&fixture("modbus_messages.bin")),
        Role::Request,
        &Limits::default(),
    )
    .unwrap();
    assert_eq!(result.messages.len(), 2);
    assert!(result.issues.is_empty());
    assert_eq!(result.messages[0].transaction, 42);
    assert_eq!(result.messages[1].transaction, 43);
    assert!(result
        .messages
        .iter()
        .all(|m| m.shape_valid && m.boundary_verified));
}
#[test]
fn modbus_server_initiated_tcp_does_not_invert_protocol_roles() {
    let analysis = analyze(&fixture("modbus_tcp.pcap"), Config::default()).unwrap();
    assert_eq!(analysis.flows.len(), 1);
    let messages: Vec<_> = analysis
        .applications
        .iter()
        .filter_map(|a| match &a.data {
            ApplicationData::Modbus(m) => Some(&m.messages),
            _ => None,
        })
        .flatten()
        .collect();
    assert_eq!(messages.len(), 2);
    assert_eq!(
        messages.iter().filter(|m| m.role == Role::Request).count(),
        1
    );
    assert_eq!(
        messages.iter().filter(|m| m.role == Role::Response).count(),
        1
    );
    assert_eq!(analysis.transactions[0].status, "candidate_pair");
}
#[test]
fn modbus_inconsistent_mbap_stops_not_speculatively_resynchronizes() {
    let mut bytes = fixture("modbus_messages.bin");
    bytes[4..6].copy_from_slice(&1u16.to_be_bytes());
    let result = modbus::decode(&stream(&bytes), Role::Request, &Limits::default()).unwrap();
    assert!(result.messages.is_empty());
    assert_eq!(result.issues[0].code, "modbus_framing_lost");
}
#[test]
fn modbus_midstream_boundary_is_not_claimed_verified() {
    let mut input = stream(&fixture("modbus_messages.bin"));
    input.anchored_by_syn = false;
    let result = modbus::decode(&input, Role::Request, &Limits::default()).unwrap();
    assert_eq!(result.messages.len(), 2);
    assert!(result.messages.iter().all(|m| !m.boundary_verified));
}
#[test]
fn end_to_end_fragmentation_keeps_all_packet_dispositions_terminal() {
    let analysis = analyze(&fixture("ipv4_fragments.pcap"), Config::default()).unwrap();
    assert_eq!(analysis.packets.len(), 2);
    assert!(analysis
        .packets
        .iter()
        .all(|p| matches!(p.disposition, Disposition::Udp)));
    assert!(analysis.fragment_notices.is_empty());
    assert_eq!(analysis.packets[0].source, analysis.packets[1].source);
    assert!(analysis.packets[0].source.is_some());
}
#[test]
fn unsupported_link_is_retained_as_evidence_not_dropped() {
    let analysis = analyze(&fixture("unknown_link.pcap"), Config::default()).unwrap();
    assert_eq!(analysis.packets.len(), 1);
    assert!(matches!(
        &analysis.packets[0].disposition,
        Disposition::Rejected {
            code: "unsupported_link",
            ..
        }
    ));
    assert!(analysis.has_diagnostics());
}
#[test]
fn independent_tcp_conflict_fixture_reaches_real_pipeline() {
    let analysis = analyze(&fixture("conflicting_tcp.pcap"), Config::default()).unwrap();
    let stream = analysis.flows[0].streams[0].as_ref().unwrap();
    assert_eq!(stream.chunks[0].bytes.data(), b"abc");
    assert_eq!((stream.conflicts[0].start, stream.conflicts[0].end), (3, 6));
    assert!(analysis.has_diagnostics());
}
