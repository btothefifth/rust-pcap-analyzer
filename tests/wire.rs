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
