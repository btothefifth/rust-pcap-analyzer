mod common;
use common::*;
use pcap_evidence::capture::{CaptureIter, ParseMode};
use pcap_evidence::wire::*;
use pcap_evidence::{ErrorCode, Limits};
fn packet() -> Vec<u8> {
    let bytes = fixture("ethernet_udp_le_us.pcap");
    let parsed: Vec<_> = CaptureIter::new(&bytes, Limits::default(), ParseMode::Strict)
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    parsed[1].packet().unwrap().1.to_vec()
}
#[test]
fn ethernet_ipv4_udp_checksum_and_payload() {
    let net = decode_packet(1, &packet(), id(1), scope()).unwrap();
    assert_eq!(net.ip_checksum, Checksum::Valid);
    let transport = decode_transport(&net, ChecksumPolicy::RequireValid).unwrap();
    match transport {
        Transport::Udp(u) => {
            assert_eq!(u.source.port, 12000);
            assert_eq!(u.destination.port, 12001);
            assert_eq!(u.payload.data(), b"evidence");
            assert_eq!(u.checksum, Checksum::Valid);
            assert_eq!(u.payload.spans()[0].packet_start, 42);
        }
        _ => panic!("UDP expected"),
    }
}
#[test]
fn vlan_and_double_vlan_shift_offsets_without_changing_payload() {
    let raw = packet();
    for tags in [vec![7u16], vec![7u16, 42]] {
        let mut tagged = raw[..12].to_vec();
        tagged.extend_from_slice(&0x8100u16.to_be_bytes());
        for (i, tag) in tags.iter().enumerate() {
            tagged.extend_from_slice(&tag.to_be_bytes());
            tagged.extend_from_slice(
                &(if i + 1 == tags.len() {
                    0x0800u16
                } else {
                    0x8100u16
                })
                .to_be_bytes(),
            );
        }
        tagged.extend_from_slice(&raw[14..]);
        let net = decode_packet(1, &tagged, id(1), scope()).unwrap();
        assert_eq!(net.scope.vlans, tags);
        assert!(
            matches!(decode_transport(&net, ChecksumPolicy::RequireValid).unwrap(), Transport::Udp(u) if u.payload.data() == b"evidence")
        );
    }
}
#[test]
fn sll_sll2_raw_and_loopback_use_their_own_header_sizes() {
    let original = packet();
    let ip = &original[14..];
    for link in [0, 101, 108, 113, 228, 276] {
        let mut data = match link {
            0 => 2u32.to_le_bytes().to_vec(),
            108 => 2u32.to_be_bytes().to_vec(),
            113 => {
                let mut h = vec![0; 16];
                h[14..16].copy_from_slice(&0x0800u16.to_be_bytes());
                h
            }
            276 => {
                let mut h = vec![0; 20];
                h[..2].copy_from_slice(&0x0800u16.to_be_bytes());
                h
            }
            _ => vec![],
        };
        data.extend_from_slice(ip);
        let net = decode_packet(link, &data, id(1), scope()).unwrap();
        assert!(
            matches!(decode_transport(&net, ChecksumPolicy::RequireValid).unwrap(), Transport::Udp(u) if u.payload.data() == b"evidence")
        );
    }
}
#[test]
fn invalid_checksum_can_be_observed_without_silent_packet_loss() {
    let mut data = packet();
    data[49] ^= 1;
    let net = decode_packet(1, &data, id(1), scope()).unwrap();
    assert!(
        matches!(decode_transport(&net, ChecksumPolicy::Observe).unwrap(), Transport::Udp(u) if u.checksum == Checksum::Invalid)
    );
    assert_eq!(
        decode_transport(&net, ChecksumPolicy::RequireValid)
            .unwrap_err()
            .code,
        ErrorCode::Checksum
    );
}
#[test]
fn original_length_never_authorizes_read_beyond_captured_bytes() {
    let data = packet();
    assert_eq!(
        decode_packet(1, &data[..40], id(1), scope())
            .unwrap_err()
            .code,
        ErrorCode::Truncated
    );
}
#[test]
fn ipv6_extension_length_is_checked_before_dereference() {
    let mut data = vec![0; 48];
    data[0] = 0x60;
    data[4..6].copy_from_slice(&8u16.to_be_bytes());
    data[6] = 0;
    data[40] = 17;
    data[41] = 255;
    assert_eq!(
        decode_packet(229, &data, id(1), scope()).unwrap_err().code,
        ErrorCode::Truncated
    );
}
#[test]
fn ipv6_atomic_fragment_not_queued_for_other_fragments() {
    let mut data = vec![0; 56];
    data[0] = 0x60;
    data[4..6].copy_from_slice(&16u16.to_be_bytes());
    data[6] = 44;
    data[40] = 17;
    data[44..48].copy_from_slice(&7u32.to_be_bytes());
    data[48..50].copy_from_slice(&1u16.to_be_bytes());
    data[50..52].copy_from_slice(&2u16.to_be_bytes());
    data[52..54].copy_from_slice(&8u16.to_be_bytes());
    let net = decode_packet(229, &data, id(1), scope()).unwrap();
    assert!(net.fragment.is_none());
    assert!(
        matches!(decode_transport(&net, ChecksumPolicy::Observe).unwrap(), Transport::Udp(u) if u.checksum == Checksum::Invalid)
    );
}
#[test]
fn ipv6_zero_checksum_is_not_ipv4_optional_checksum_semantics() {
    let mut data = packet();
    data[40..42].fill(0);
    let net = decode_packet(1, &data, id(1), scope()).unwrap();
    assert!(
        matches!(decode_transport(&net, ChecksumPolicy::RequireValid).unwrap(), Transport::Udp(u) if u.checksum == Checksum::NotPresent)
    );
}
#[test]
fn unknown_ether_type_is_typed_not_guessed_as_ip() {
    let mut data = packet();
    data[12..14].copy_from_slice(&0x0806u16.to_be_bytes());
    assert_eq!(
        decode_packet(1, &data, id(1), scope()).unwrap_err().code,
        ErrorCode::UnsupportedNetwork
    );
}

fn ipv6_udp(next: u8, extension: &[u8], checksum: u16) -> Vec<u8> {
    let mut data = vec![0; 40];
    data[0] = 0x60;
    data[4..6].copy_from_slice(&((extension.len() + 8) as u16).to_be_bytes());
    data[6] = next;
    data[8..24].copy_from_slice(
        &"2001:db8::1"
            .parse::<std::net::Ipv6Addr>()
            .unwrap()
            .octets(),
    );
    data[24..40].copy_from_slice(
        &"2001:db8::2"
            .parse::<std::net::Ipv6Addr>()
            .unwrap()
            .octets(),
    );
    data.extend_from_slice(extension);
    data.extend_from_slice(&[0, 1, 0, 2, 0, 8]);
    data.extend_from_slice(&checksum.to_be_bytes());
    data
}

fn type2_routing(next: u8) -> Vec<u8> {
    let mut extension = vec![next, 2, 2, 1, 0, 0, 0, 0];
    extension.extend_from_slice(
        &"2001:db8::3"
            .parse::<std::net::Ipv6Addr>()
            .unwrap()
            .octets(),
    );
    extension
}

fn assert_unchecked(datagram: &Datagram) {
    assert!(
        matches!(decode_transport(datagram, ChecksumPolicy::Observe).unwrap(), Transport::Udp(u) if u.checksum == Checksum::NotChecked)
    );
    let error = decode_transport(datagram, ChecksumPolicy::RequireValid).unwrap_err();
    assert_eq!(error.code, ErrorCode::UnsupportedNetwork);
    assert_eq!(error.field, "transport_checksum_operands");
}

#[test]
fn ipv6_routing_checksum_operands_are_unsupported_instead_of_invalid() {
    // RFC 8200 8.1 / RFC 6275 6.4.1. Independent one's-complement
    // arithmetic: src ::1 + final dst ::3 + pseudo-header + UDP = 0x5b9a.
    // Its complement is 0xa465; the in-flight base destination is ::2.
    let data = ipv6_udp(43, &type2_routing(17), 0xa465);
    assert_eq!(data.len(), 72);
    let net = decode_packet(229, &data, id(1), scope()).unwrap();
    assert_eq!(
        net.destination,
        "2001:db8::2".parse::<std::net::IpAddr>().unwrap()
    );
    assert_eq!(net.checksum_context, ChecksumContext::Unsupported);
    assert_unchecked(&net);

    let mut tcp = data[..64].to_vec();
    tcp[40] = 6;
    tcp[4..6].copy_from_slice(&44u16.to_be_bytes());
    let mut segment = vec![0; 20];
    segment[..4].copy_from_slice(&[0, 1, 0, 2]);
    segment[12] = 0x50;
    segment[13] = 2;
    // Independent sum with final destination ::3 is 0xab95.
    segment[16..18].copy_from_slice(&0x546au16.to_be_bytes());
    tcp.extend_from_slice(&segment);
    let tcp = decode_packet(229, &tcp, id(5), scope()).unwrap();
    assert!(
        matches!(decode_transport(&tcp, ChecksumPolicy::Observe).unwrap(), Transport::Tcp(t) if t.checksum == Checksum::NotChecked)
    );
    assert_eq!(
        decode_transport(&tcp, ChecksumPolicy::RequireValid)
            .unwrap_err()
            .code,
        ErrorCode::UnsupportedNetwork
    );

    // An IPv6 UDP checksum of zero remains definitively invalid, even when
    // the pseudo-header operands are otherwise unavailable.
    let zero = decode_packet(229, &ipv6_udp(43, &type2_routing(17), 0), id(6), scope()).unwrap();
    assert!(
        matches!(decode_transport(&zero, ChecksumPolicy::Observe).unwrap(), Transport::Udp(u) if u.checksum == Checksum::Invalid)
    );
    assert_eq!(
        decode_transport(&zero, ChecksumPolicy::RequireValid)
            .unwrap_err()
            .code,
        ErrorCode::Checksum
    );

    // Do not accidentally confer support by a coincidentally matching base
    // checksum, zero Segments Left, or another routing type.
    for ty in [0, 2, 4, 255] {
        let mut extension = type2_routing(17);
        extension[2] = ty;
        extension[3] = 0;
        assert_unchecked(
            &decode_packet(229, &ipv6_udp(43, &extension, 0xa466), id(2), scope()).unwrap(),
        );
    }

    // The closest supported path keeps real checksum validation.
    let plain = decode_packet(229, &ipv6_udp(17, &[], 0xa466), id(3), scope()).unwrap();
    assert_eq!(plain.checksum_context, ChecksumContext::BaseAddresses);
    assert!(
        matches!(decode_transport(&plain, ChecksumPolicy::RequireValid).unwrap(), Transport::Udp(u) if u.checksum == Checksum::Valid)
    );
    let mut damaged = ipv6_udp(17, &[], 0xa466);
    damaged[41] ^= 1;
    let damaged = decode_packet(229, &damaged, id(4), scope()).unwrap();
    assert!(
        matches!(decode_transport(&damaged, ChecksumPolicy::Observe).unwrap(), Transport::Udp(u) if u.checksum == Checksum::Invalid)
    );
}

#[test]
fn checksum_context_survives_fragment_reassembly_and_post_fragment_extensions() {
    use pcap_evidence::fragment::{FragmentOutcome, FragmentReassembler};
    // Put a routing header before the fragment header, then split the UDP
    // datagram at eight bytes. The second fragment retains the same context.
    let extension = type2_routing(44);
    let mut data = ipv6_udp(43, &extension, 0xa465);
    data.splice(64..64, [17, 0, 0, 1, 0, 0, 0, 7]);
    data[4..6].copy_from_slice(&40u16.to_be_bytes());
    let mut tail = data[..72].to_vec();
    tail.extend_from_slice(b"evidence");
    tail[66..68].copy_from_slice(&8u16.to_be_bytes());
    let mut fragments = FragmentReassembler::new(Limits::default());
    assert!(matches!(
        fragments
            .push(decode_packet(229, &tail, id(1), scope()).unwrap(), 1)
            .unwrap(),
        FragmentOutcome::Pending
    ));
    let first = decode_packet(229, &data, id(2), scope()).unwrap();
    let FragmentOutcome::Complete(joined, _) = fragments.push(first, 2).unwrap() else {
        panic!("fragments must join")
    };
    assert_eq!(joined.checksum_context, ChecksumContext::Unsupported);
    assert_unchecked(&joined);

    // Reach the transport decoder's extension scan after real fragment
    // reconstruction. This structural input is not a claim of valid extension
    // ordering: routing operand semantics stay unsupported at either scan.
    let full = ipv6_udp(43, &type2_routing(17), 0xa465);
    let fragment = |offset: u16, more: bool, payload: &[u8], frame| {
        let mut raw = full[..40].to_vec();
        raw[6] = 44;
        raw[4..6].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        raw.extend_from_slice(&[43, 0]);
        raw.extend_from_slice(&(offset | u16::from(more)).to_be_bytes());
        raw.extend_from_slice(&8u32.to_be_bytes());
        raw.extend_from_slice(payload);
        decode_packet(229, &raw, id(frame), scope()).unwrap()
    };
    let mut fragments = FragmentReassembler::new(Limits::default());
    assert!(matches!(
        fragments
            .push(fragment(0, true, &full[40..56], 3), 3)
            .unwrap(),
        FragmentOutcome::Pending
    ));
    let FragmentOutcome::Complete(joined, _) = fragments
        .push(fragment(16, false, &full[56..], 4), 4)
        .unwrap()
    else {
        panic!("post-fragment extensions must join")
    };
    assert_eq!(joined.checksum_context, ChecksumContext::BaseAddresses);
    assert_unchecked(&joined);
}

#[test]
fn checksum_affected_home_address_and_source_route_options_remain_unchecked() {
    // RFC 6275 6.3 alignment: PadN ends at offset six; Home Address TLV
    // then consumes 18 bytes. UDP checksum uses home source ::3 (0xa464).
    let mut options = vec![17, 2, 1, 2, 0, 0, 0xc9, 16];
    options.extend_from_slice(
        &"2001:db8::3"
            .parse::<std::net::Ipv6Addr>()
            .unwrap()
            .octets(),
    );
    assert_unchecked(&decode_packet(229, &ipv6_udp(60, &options, 0xa464), id(1), scope()).unwrap());
    let padding = [17, 0, 1, 4, 0, 0, 0, 0];
    let net = decode_packet(229, &ipv6_udp(60, &padding, 0xa466), id(2), scope()).unwrap();
    assert!(
        matches!(decode_transport(&net, ChecksumPolicy::RequireValid).unwrap(), Transport::Udp(u) if u.checksum == Checksum::Valid)
    );
    let malformed = [17, 0, 1, 5, 0, 0, 0, 0];
    assert_eq!(
        decode_packet(229, &ipv6_udp(60, &malformed, 0xa466), id(3), scope())
            .unwrap_err()
            .code,
        ErrorCode::Truncated
    );

    for ty in [131, 137] {
        let mut ip = packet()[14..].to_vec();
        ip.splice(20..20, [ty, 7, 4, 10, 0, 0, 3, 0]);
        ip[0] = 0x47;
        let total = ip.len() as u16;
        ip[2..4].copy_from_slice(&total.to_be_bytes());
        ip[10..12].fill(0);
        let checksum = internet_checksum(&ip[..28]);
        ip[10..12].copy_from_slice(&checksum.to_be_bytes());
        assert_unchecked(&decode_packet(228, &ip, id(4), scope()).unwrap());
    }
}

fn sll2(ip: &[u8], interface: u32) -> Vec<u8> {
    let mut data = vec![0; 20];
    data[..2].copy_from_slice(&0x0800u16.to_be_bytes());
    data[4..8].copy_from_slice(&interface.to_be_bytes());
    data.extend_from_slice(ip);
    data
}

#[test]
fn sll2_interfaces_partition_real_fragment_reassembly_and_preserve_container_scope() {
    use pcap_evidence::fragment::{FragmentOutcome, FragmentReassembler};
    let mut first = packet()[14..42].to_vec();
    first[2..4].copy_from_slice(&28u16.to_be_bytes());
    first[4..6].copy_from_slice(&7u16.to_be_bytes());
    first[6..8].copy_from_slice(&0x2000u16.to_be_bytes());
    let mut last = first[..20].to_vec();
    last.extend_from_slice(b"evidence");
    last[6..8].copy_from_slice(&1u16.to_be_bytes());
    let mut fragments = FragmentReassembler::new(Limits::default());
    let mut container = scope();
    container.section = 4;
    container.interface = 9;
    let decode = |ip: &[u8], nic, frame| {
        decode_packet(276, &sll2(ip, nic), id(frame), container.clone()).unwrap()
    };
    assert!(matches!(
        fragments.push(decode(&first, 2, 1), 1).unwrap(),
        FragmentOutcome::Pending
    ));
    assert!(matches!(
        fragments.push(decode(&last, 3, 2), 2).unwrap(),
        FragmentOutcome::Pending
    ));
    let FragmentOutcome::Complete(joined, packets) =
        fragments.push(decode(&last, 2, 3), 3).unwrap()
    else {
        panic!("same NIC must complete")
    };
    assert_eq!(joined.scope.section, 4);
    assert_eq!(joined.scope.interface, 9);
    assert_eq!(joined.scope.link_interface, Some(2));
    assert_eq!(packets, vec![id(1), id(3)]);
    assert_eq!(&joined.payload.data()[8..], b"evidence");
    let FragmentOutcome::Complete(joined, packets) =
        fragments.push(decode(&first, 3, 4), 4).unwrap()
    else {
        panic!("second NIC must complete independently")
    };
    assert_eq!(joined.scope.link_interface, Some(3));
    assert_eq!(packets, vec![id(2), id(4)]);
    assert!(fragments.finish().is_empty());

    let mut other_container = container.clone();
    other_container.interface = 2;
    let a = decode_packet(276, &sll2(&first, 3), id(5), other_container).unwrap();
    let mut other_container = container;
    other_container.interface = 3;
    let b = decode_packet(276, &sll2(&last, 2), id(6), other_container).unwrap();
    assert_ne!(a.scope, b.scope);
    let mut fragments = FragmentReassembler::new(Limits::default());
    assert!(matches!(
        fragments.push(a, 5).unwrap(),
        FragmentOutcome::Pending
    ));
    assert!(matches!(
        fragments.push(b, 6).unwrap(),
        FragmentOutcome::Pending
    ));
    assert_eq!(fragments.finish().len(), 2);
}

#[test]
fn sll2_interfaces_partition_actual_tcp_generations() {
    use pcap_evidence::tcp::{OverlapPolicy, TcpTracker};
    let mut ip = packet()[14..34].to_vec();
    ip[2..4].copy_from_slice(&40u16.to_be_bytes());
    ip[9] = 6;
    let mut tcp = vec![0; 20];
    tcp[..4].copy_from_slice(&[0, 1, 0, 2]);
    tcp[4..8].copy_from_slice(&100u32.to_be_bytes());
    tcp[12] = 0x50;
    tcp[13] = 2;
    ip.extend_from_slice(&tcp);
    let mut tracker = TcpTracker::new(Limits::default(), 1_000_000).unwrap();
    for (frame, nic) in [(1, 2), (2, 3), (3, 2)] {
        let net = decode_packet(276, &sll2(&ip, nic), id(frame), scope()).unwrap();
        let Transport::Tcp(segment) = decode_transport(&net, ChecksumPolicy::Observe).unwrap()
        else {
            panic!("TCP expected")
        };
        tracker.ingest(net.scope, id(frame), None, segment).unwrap();
    }
    let flows = tracker.finish(OverlapPolicy::RejectConflict).unwrap();
    assert_eq!(flows.len(), 2);
    assert_eq!(flows[0].key.scope.link_interface, Some(2));
    assert_eq!(flows[0].packets, vec![id(1), id(3)]);
    assert_eq!(flows[1].key.scope.link_interface, Some(3));
    assert_eq!(flows[1].packets, vec![id(2)]);

    // The real capture engine and report retain the same namespace split.
    let capture = capture_packets(276, &[sll2(&ip, 2), sll2(&ip, 3), sll2(&ip, 2)]);
    let analysis =
        pcap_evidence::engine::analyze(&capture, pcap_evidence::engine::Config::default()).unwrap();
    assert_eq!(analysis.flows.len(), 2);
    let report = pcap_evidence::report::analysis(&analysis, false).encode();
    assert!(report.contains("\"link_interface\":2"));
    assert!(report.contains("\"link_interface\":3"));
}

fn capture_packets(link: u32, packets: &[Vec<u8>]) -> Vec<u8> {
    let mut capture = vec![];
    capture.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes());
    capture.extend_from_slice(&2u16.to_le_bytes());
    capture.extend_from_slice(&4u16.to_le_bytes());
    for value in [0, 0, 65_535, link] {
        capture.extend_from_slice(&value.to_le_bytes());
    }
    for (i, packet) in packets.iter().enumerate() {
        for value in [1, i as u32, packet.len() as u32, packet.len() as u32] {
            capture.extend_from_slice(&value.to_le_bytes());
        }
        capture.extend_from_slice(packet);
    }
    capture
}

#[test]
fn real_engine_reports_unsupported_checksum_operands_without_false_invalid_warning() {
    use pcap_evidence::engine::{analyze, Config, Disposition};
    let capture = capture_packets(229, &[ipv6_udp(43, &type2_routing(17), 0xa465)]);
    let observed = analyze(&capture, Config::default()).unwrap();
    assert!(matches!(observed.packets[0].disposition, Disposition::Udp));
    assert_eq!(
        observed.packets[0].warnings,
        vec!["unsupported_udp_checksum_operands"]
    );
    let strict = analyze(
        &capture,
        Config {
            checksum_policy: ChecksumPolicy::RequireValid,
            ..Config::default()
        },
    )
    .unwrap();
    assert!(
        matches!(&strict.packets[0].disposition, Disposition::Rejected { code, detail } if *code == "unsupported_network" && detail.contains("transport_checksum_operands"))
    );
}
