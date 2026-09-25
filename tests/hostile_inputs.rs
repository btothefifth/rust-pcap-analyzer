mod common;
use common::*;
use pcap_evidence::capture::{CaptureIter, ParseMode};
use pcap_evidence::engine::{analyze, Config};
use pcap_evidence::tcp::{OverlapPolicy, StreamAssembler};
use pcap_evidence::{dnp3, wire, Limits};
fn check_capture(bytes: &[u8]) {
    let limits = Limits {
        max_input_bytes: 16384,
        max_records: 128,
        max_packet_bytes: 8192,
        max_block_bytes: 8192,
        ..Limits::default()
    };
    for mode in [ParseMode::Strict, ParseMode::Evidence] {
        if let Ok(iter) = CaptureIter::new(bytes, limits.clone(), mode) {
            for (i, item) in iter.enumerate() {
                assert!(i <= limits.max_records);
                if let Ok(record) = item {
                    assert!(!record.raw().is_empty());
                    if let Some((p, data)) = record.packet() {
                        assert_eq!(p.captured_len as usize, data.len());
                    }
                }
            }
        }
    }
}
#[test]
fn every_fixture_prefix_is_bounded_and_never_panics() {
    for name in [
        "ethernet_udp_le_us.pcap",
        "mixed_sections.pcapng",
        "dnp3_tcp.pcap",
    ] {
        let source = fixture(name);
        for n in 0..=source.len() {
            check_capture(&source[..n]);
        }
    }
}
#[test]
fn mutate_every_capture_byte_preserves_safe_termination() {
    for name in ["ethernet_udp_le_us.pcap", "mixed_sections.pcapng"] {
        let mut bytes = fixture(name);
        for i in 0..bytes.len() {
            for mask in [1u8, 0x80, 0xff] {
                bytes[i] ^= mask;
                check_capture(&bytes);
                bytes[i] ^= mask;
            }
        }
    }
}
#[test]
fn deterministic_arbitrary_bytes_exercise_public_read_boundaries() {
    let mut rng = 0x81726354abcdef01u64;
    for length in 0..256 {
        let mut bytes = vec![0; length];
        for b in &mut bytes {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            *b = rng as u8;
        }
        check_capture(&bytes);
        for link in [0, 1, 101, 108, 113, 228, 229, 276, 65000] {
            let _ = wire::decode_packet(link, &bytes, id(1), scope());
        }
        let _ = dnp3::decode(&stream(&bytes), &Limits::default());
    }
}
#[test]
fn tiny_resource_budget_rejects_not_silently_truncates() {
    let limits = Limits {
        max_retained_payload: 3,
        ..Limits::default()
    };
    let mut s = StreamAssembler::new(Some(1000), limits);
    s.push(1001, evidence(b"abc", 1)).unwrap();
    assert!(s.push(1001, evidence(b"abc", 2)).is_err());
    assert_eq!(
        s.finish(OverlapPolicy::RejectConflict).unwrap().chunks[0]
            .bytes
            .data(),
        b"abc"
    );
    let config = Config {
        limits: Limits {
            max_flows: 1,
            max_protocol_messages: 1,
            ..Limits::default()
        },
        ..Config::default()
    };
    let result = analyze(&fixture("dnp3_tcp.pcap"), config).unwrap();
    assert!(result.has_diagnostics());
}
