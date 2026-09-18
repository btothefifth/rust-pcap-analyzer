mod common;
use common::*;
use pcap_evidence::fragment::{FragmentOutcome, FragmentReassembler};
use pcap_evidence::provenance::EvidenceBytes;
use pcap_evidence::tcp::*;
use pcap_evidence::wire::*;
use pcap_evidence::{ErrorCode, Limits};

#[test]
fn sequence_wrap_and_half_space_ambiguity() {
    assert_eq!(sequence_delta(3, u32::MAX - 2).unwrap(), 6);
    assert_eq!(sequence_delta(u32::MAX - 2, 3).unwrap(), -6);
    assert_eq!(
        sequence_delta(0x8000_0000, 0).unwrap_err().code,
        ErrorCode::SequenceAmbiguous
    );
}
#[test]
fn out_of_order_and_identical_retransmission_do_not_duplicate_stream() {
    let mut s = StreamAssembler::new(Some(1000), Limits::default());
    s.push(1004, evidence(b"def", 1)).unwrap();
    s.push(1001, evidence(b"abc", 2)).unwrap();
    s.push(1001, evidence(b"abc", 3)).unwrap();
    let r = s.finish(OverlapPolicy::RejectConflict).unwrap();
    assert_eq!(r.chunks.len(), 1);
    assert_eq!(r.chunks[0].bytes.data(), b"abcdef");
    assert_eq!(r.duplicate_observed_bytes, 3);
    assert!(r.gaps.is_empty());
    assert_eq!(r.chunks[0].bytes.spans()[0].packet.frame, 2);
    assert!(r.chunks[0].bytes.validate());
}
#[test]
fn conflicting_overlap_is_an_explicit_gap_not_fabricated_payload() {
    let mut s = StreamAssembler::new(Some(1000), Limits::default());
    s.push(1001, evidence(b"abcdef", 1)).unwrap();
    s.push(1004, evidence(b"XYZ", 2)).unwrap();
    let r = s.finish(OverlapPolicy::RejectConflict).unwrap();
    assert_eq!(r.chunks[0].bytes.data(), b"abc");
    assert_eq!(r.chunks.len(), 1);
    assert_eq!((r.gaps[0].start, r.gaps[0].end), (3, 6));
    assert_eq!(r.gaps[0].reason, "conflicting_capture_bytes");
    assert_eq!(r.conflicts[0].packets, vec![id(1), id(2)]);
}
#[test]
fn explicit_first_last_policies_preserve_conflict_diagnostics() {
    for (policy, expected) in [
        (OverlapPolicy::FirstObserved, &b"abcdef"[..]),
        (OverlapPolicy::LastObserved, &b"abcXYZ"[..]),
    ] {
        let mut s = StreamAssembler::new(Some(1000), Limits::default());
        s.push(1001, evidence(b"abcdef", 1)).unwrap();
        s.push(1004, evidence(b"XYZ", 2)).unwrap();
        let r = s.finish(policy).unwrap();
        assert_eq!(r.chunks[0].bytes.data(), expected);
        assert_eq!(r.conflicts.len(), 1);
        assert!(r.gaps.is_empty());
    }
}
#[test]
fn missing_middle_keeps_two_contiguous_chunks() {
    let mut s = StreamAssembler::new(Some(1000), Limits::default());
    s.push(1001, evidence(b"abc", 1)).unwrap();
    s.push(1007, evidence(b"ghi", 2)).unwrap();
    let r = s.finish(OverlapPolicy::RejectConflict).unwrap();
    assert_eq!(r.chunks.len(), 2);
    assert_eq!(r.chunks[1].offset, 6);
    assert_eq!((r.gaps[0].start, r.gaps[0].end), (3, 6));
}
#[test]
fn syn_and_fin_expose_missing_edges() {
    let mut s = StreamAssembler::new(Some(1000), Limits::default());
    s.push(1004, evidence(b"def", 1)).unwrap();
    s.end_at(1010).unwrap();
    let r = s.finish(OverlapPolicy::RejectConflict).unwrap();
    assert_eq!(r.gaps.len(), 2);
    assert_eq!((r.gaps[0].start, r.gaps[0].end), (0, 3));
    assert_eq!((r.gaps[1].start, r.gaps[1].end), (6, 9));
}
#[test]
fn no_payload_with_observed_syn_fin_still_reports_missing_bytes() {
    let mut s = StreamAssembler::new(Some(10), Limits::default());
    s.end_at(20).unwrap();
    let r = s.finish(OverlapPolicy::RejectConflict).unwrap();
    assert!(r.chunks.is_empty());
    assert_eq!((r.gaps[0].start, r.gaps[0].end), (0, 9));
}
#[test]
fn data_after_fin_position_cannot_be_called_a_valid_stream() {
    let mut s = StreamAssembler::new(Some(1000), Limits::default());
    s.push(1001, evidence(b"abcdef", 1)).unwrap();
    s.end_at(1004).unwrap();
    assert_eq!(
        s.finish(OverlapPolicy::RejectConflict).unwrap_err().code,
        ErrorCode::SequenceAmbiguous
    );
}
#[test]
fn payload_before_syn_and_excessive_span_rejected() {
    let mut s = StreamAssembler::new(Some(1000), Limits::default());
    assert!(s.push(999, evidence(b"x", 1)).is_err());
    assert_eq!(
        s.push(1001 + 5 * 1024 * 1024, evidence(b"x", 2))
            .unwrap_err()
            .code,
        ErrorCode::LimitExceeded
    );
}
#[test]
fn connection_reuse_creates_generation_and_same_syn_is_not_recounted() {
    let mut t = TcpTracker::new(Limits::default(), 120_000_000_000).unwrap();
    let first = t
        .ingest(scope(), id(1), Some(0), segment(1000, 0, 2, b"", 1))
        .unwrap();
    let repeat = t
        .ingest(scope(), id(2), Some(1), segment(1000, 0, 2, b"", 2))
        .unwrap();
    assert!(matches!(first, Assignment::Assigned { flow_id: 0, .. }));
    assert!(matches!(repeat, Assignment::Assigned { flow_id: 0, .. }));
    let next = t
        .ingest(scope(), id(3), Some(2), segment(20_000_000, 0, 2, b"", 3))
        .unwrap();
    assert!(matches!(next, Assignment::Assigned { flow_id: 1, .. }));
    let flows = t.finish(OverlapPolicy::RejectConflict).unwrap();
    assert_eq!(flows.len(), 2);
    assert_eq!(flows[1].generation, 2);
}
#[test]
fn closed_generation_does_not_absorb_post_close_non_syn() {
    let mut t = TcpTracker::new(Limits::default(), 120_000_000_000).unwrap();
    t.ingest(scope(), id(1), Some(0), segment(1000, 0, 2, b"", 1))
        .unwrap();
    t.ingest(scope(), id(2), Some(1), segment(1001, 0, 0x14, b"", 2))
        .unwrap();

    let after_close = t
        .ingest(scope(), id(3), Some(2), segment(1001, 0, 0x10, b"late", 3))
        .unwrap();
    assert!(matches!(
        after_close,
        Assignment::Unassigned {
            reason: "closed_generation_requires_syn"
        }
    ));

    let next = t
        .ingest(scope(), id(4), Some(3), segment(9000, 0, 2, b"", 4))
        .unwrap();
    assert!(matches!(next, Assignment::Assigned { flow_id: 1, .. }));
    let flows = t.finish(OverlapPolicy::RejectConflict).unwrap();
    assert_eq!(flows.len(), 2);
    assert!(flows[0].closed);
    assert_eq!(flows[1].generation, 2);
    assert_eq!(
        flows[0].packets.iter().map(|p| p.frame).collect::<Vec<_>>(),
        vec![1, 2]
    );
}
#[test]
fn exact_final_ack_stays_with_two_sided_fin_generation() {
    let mut t = TcpTracker::new(Limits::default(), 120_000_000_000).unwrap();
    t.ingest(scope(), id(1), Some(0), segment(1000, 0, 2, b"", 1))
        .unwrap();

    let mut server_syn_ack = segment(5000, 1001, 0x12, b"", 2);
    server_syn_ack.source = endpoint("10.0.0.2", 20000);
    server_syn_ack.destination = endpoint("10.0.0.1", 40000);
    t.ingest(scope(), id(2), Some(1), server_syn_ack).unwrap();
    t.ingest(scope(), id(3), Some(2), segment(1001, 5001, 0x10, b"", 3))
        .unwrap();
    t.ingest(scope(), id(4), Some(3), segment(1001, 5001, 0x11, b"", 4))
        .unwrap();

    let mut server_fin = segment(5001, 1002, 0x11, b"", 5);
    server_fin.source = endpoint("10.0.0.2", 20000);
    server_fin.destination = endpoint("10.0.0.1", 40000);
    t.ingest(scope(), id(5), Some(4), server_fin).unwrap();

    let final_ack = t
        .ingest(scope(), id(6), Some(5), segment(1002, 5002, 0x10, b"", 6))
        .unwrap();
    assert!(matches!(final_ack, Assignment::Assigned { flow_id: 0, .. }));

    let unrelated_ack = t
        .ingest(scope(), id(7), Some(6), segment(1002, 9000, 0x10, b"", 7))
        .unwrap();
    assert!(matches!(
        unrelated_ack,
        Assignment::Unassigned {
            reason: "closed_generation_requires_syn"
        }
    ));
    let flows = t.finish(OverlapPolicy::RejectConflict).unwrap();
    assert_eq!(
        flows[0].packets.iter().map(|p| p.frame).collect::<Vec<_>>(),
        vec![1, 2, 3, 4, 5, 6]
    );
}
#[test]
fn nearby_generations_leave_ambiguous_segment_unassigned() {
    let mut t = TcpTracker::new(Limits::default(), 100).unwrap();
    t.ingest(scope(), id(1), Some(0), segment(1000, 0, 2, b"", 1))
        .unwrap();
    t.ingest(scope(), id(2), Some(1), segment(2000, 0, 2, b"", 2))
        .unwrap();
    let a = t
        .ingest(scope(), id(3), Some(2), segment(2100, 0, 0x10, b"x", 3))
        .unwrap();
    assert!(
        matches!(a, Assignment::Ambiguous { candidate_flow_ids } if candidate_flow_ids == vec![0, 1])
    );
}
#[test]
fn interface_and_vlan_identity_do_not_merge_flows() {
    let mut t = TcpTracker::new(Limits::default(), 100).unwrap();
    let scopes = [
        scope(),
        Scope {
            interface: 1,
            ..scope()
        },
        Scope {
            vlans: vec![7],
            ..scope()
        },
    ];
    for (i, scope) in scopes.into_iter().enumerate() {
        t.ingest(
            scope,
            id(i as u64 + 1),
            Some(0),
            segment(1000, 0, 2, b"", i as u64 + 1),
        )
        .unwrap();
    }
    assert_eq!(t.finish(OverlapPolicy::RejectConflict).unwrap().len(), 3);
}
#[test]
fn unknown_time_does_not_trigger_idle_expiry_or_time_zero() {
    let mut t = TcpTracker::new(Limits::default(), 100).unwrap();
    t.ingest(scope(), id(1), None, segment(1000, 0, 2, b"", 1))
        .unwrap();
    t.ingest(
        scope(),
        id(2),
        Some(i128::MAX),
        segment(1001, 0, 0x10, b"x", 2),
    )
    .unwrap();
    let flows = t.finish(OverlapPolicy::RejectConflict).unwrap();
    assert_eq!(flows.len(), 1);
    assert!(flows[0].anomalies.contains(&"packet_time_unavailable"));
}
fn fragment(start: usize, more: bool, data: &[u8], frame: u64, ipv6: bool) -> Datagram {
    Datagram {
        scope: scope(),
        source: if ipv6 {
            "::1".parse().unwrap()
        } else {
            "10.0.0.1".parse().unwrap()
        },
        destination: if ipv6 {
            "::2".parse().unwrap()
        } else {
            "10.0.0.2".parse().unwrap()
        },
        protocol: 17,
        ipv6,
        network_header_len: if ipv6 { 48 } else { 20 },
        fragment: Some(FragmentInfo {
            id: 7,
            offset: start,
            more,
        }),
        payload: evidence(data, frame),
        ip_checksum: Checksum::Valid,
    }
}
#[test]
fn fragment_out_of_order_assembly_conserves_every_packet_reference() {
    let mut r = FragmentReassembler::new(Limits::default());
    assert!(matches!(
        r.push(fragment(8, false, b"ijklmnop", 1, false), 1)
            .unwrap(),
        FragmentOutcome::Pending
    ));
    match r.push(fragment(0, true, b"abcdefgh", 2, false), 2).unwrap() {
        FragmentOutcome::Complete(d, packets) => {
            assert_eq!(d.payload.data(), b"abcdefghijklmnop");
            assert_eq!(packets, vec![id(1), id(2)]);
            assert!(d.payload.validate());
            assert_eq!(d.payload.spans()[0].packet.frame, 2);
        }
        _ => panic!("expected completed datagram"),
    }
}
#[test]
fn conflicting_ipv4_fragments_quarantine_set() {
    let mut r = FragmentReassembler::new(Limits::default());
    r.push(fragment(0, true, b"abcdefgh", 1, false), 1).unwrap();
    assert!(matches!(
        r.push(fragment(0, true, b"ABCDEFGH", 2, false), 2).unwrap(),
        FragmentOutcome::Rejected(_)
    ));
    assert!(matches!(
        r.push(fragment(8, false, b"ijklmnop", 3, false), 3)
            .unwrap(),
        FragmentOutcome::Rejected(_)
    ));
    assert_eq!(r.finish()[0].code, "fragment_quarantine_at_eof");
}
#[test]
fn identical_ipv6_overlaps_are_still_rejected() {
    let mut r = FragmentReassembler::new(Limits::default());
    r.push(fragment(0, true, b"abcdefgh", 1, true), 1).unwrap();
    assert!(
        matches!(r.push(fragment(0, true, b"abcdefgh", 2, true), 2).unwrap(), FragmentOutcome::Rejected(n) if n.code == "ipv6_overlapping_fragments")
    );
}
#[test]
fn identical_ipv4_fragment_duplicate_is_preserved_as_observation() {
    let mut r = FragmentReassembler::new(Limits::default());
    r.push(fragment(0, true, b"abcdefgh", 1, false), 1).unwrap();
    r.push(fragment(0, true, b"abcdefgh", 2, false), 2).unwrap();
    assert!(
        matches!(r.push(fragment(8, false, b"ijklmnop", 3, false), 3).unwrap(),
        FragmentOutcome::Complete(_, packets) if packets == vec![id(1), id(2), id(3)])
    );
}
#[test]
fn fragment_expiry_is_explicit_and_uses_capture_progress_not_wall_clock() {
    let limits = Limits {
        fragment_frame_lifetime: 2,
        ..Limits::default()
    };
    let mut r = FragmentReassembler::new(limits);
    r.push(fragment(0, true, b"abcdefgh", 1, false), 1).unwrap();
    assert!(r.expire(3).is_empty());
    assert_eq!(r.expire(4)[0].packets, vec![id(1)]);
    assert!(r.finish().is_empty());
}
#[test]
fn provenance_clipping_and_append_are_exact_and_nonmutating_on_rejection() {
    let mut bytes = evidence(b"abcdefgh", 1);
    let sliced = bytes.slice(2..6).unwrap();
    assert_eq!(sliced.data(), b"cdef");
    assert_eq!(sliced.spans()[0].packet_start, 56);
    let before = bytes.clone();
    assert!(bytes.append(&sliced, 9).is_err());
    assert_eq!(bytes, before);
    bytes.append(&evidence(b"ijkl", 2), 12).unwrap();
    assert!(bytes.validate());
    assert_eq!(bytes.slice(6..10).unwrap().packets(), vec![id(1), id(2)]);
    let invalid_start = 5usize;
    let invalid_end = 4usize;
    assert!(bytes.slice(invalid_start..invalid_end).is_err());
    assert!(EvidenceBytes::default().validate());
}
