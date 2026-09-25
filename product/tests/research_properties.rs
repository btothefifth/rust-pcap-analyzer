//! Deterministic property sweeps; no third-party parser supplies expected results.
//! These tests are native-source additions, not evidence of a completed fuzz campaign.
use pcap_evidence::{
    capture::{CaptureReader, ParseMode},
    provenance::{EvidenceBytes, PacketId},
    tcp::{OverlapPolicy, StreamAssembler},
    Limits,
};
use pcap_evidence_product::protocols::Protocol;
use std::io::{self, Read};

fn outcome(protocol: Protocol, bytes: &[u8]) -> String {
    match protocol.decode(bytes) {
        Ok(d) => {
            assert!(d.consumed > 0 && d.consumed <= bytes.len());
            assert_eq!(d.protocol, protocol);
            d.json()
                .encode_bounded(2 * 1024 * 1024)
                .expect("bounded decoded fields")
        }
        Err(e) => e.to_string(),
    }
}

#[test]
fn all_protocol_mutations_are_deterministic() {
    let fixtures: &[(Protocol, &[u8])] = &[
        (Protocol::Netflow9, include_bytes!("fixtures/netflow9.bin")),
        (Protocol::Bgp, include_bytes!("fixtures/bgp.bin")),
        (Protocol::Snmp, include_bytes!("fixtures/snmp.bin")),
        (Protocol::Ftp, include_bytes!("fixtures/ftp.bin")),
        (Protocol::Tftp, include_bytes!("fixtures/tftp.bin")),
        (Protocol::Pop3, include_bytes!("fixtures/pop3.bin")),
        (Protocol::Imap, include_bytes!("fixtures/imap.bin")),
        (Protocol::Telnet, include_bytes!("fixtures/telnet.bin")),
        (Protocol::Sip, include_bytes!("fixtures/sip.bin")),
        (Protocol::Rtp, include_bytes!("fixtures/rtp.bin")),
        (Protocol::Pptp, include_bytes!("fixtures/pptp.bin")),
        (Protocol::BacnetIp, include_bytes!("fixtures/bacnet_ip.bin")),
        (Protocol::Enip, include_bytes!("fixtures/enip_cip.bin")),
        (Protocol::Mms, include_bytes!("fixtures/mms.bin")),
        (Protocol::Iec104, include_bytes!("fixtures/iec104.bin")),
        (Protocol::S7, include_bytes!("fixtures/s7.bin")),
        (Protocol::HartIp, include_bytes!("fixtures/hart_ip.bin")),
        (Protocol::FinsUdp, include_bytes!("fixtures/fins_udp.bin")),
        (Protocol::FinsTcp, include_bytes!("fixtures/fins_tcp.bin")),
        (Protocol::Ads, include_bytes!("fixtures/ads.bin")),
        (Protocol::OpcUa, include_bytes!("fixtures/opcua_tcp.bin")),
        (Protocol::Melsec, include_bytes!("fixtures/melsec_3e.bin")),
        (
            Protocol::Synchrophasor,
            include_bytes!("fixtures/c37118.bin"),
        ),
    ];
    for &(protocol, bytes) in fixtures {
        if !protocol.compiled() {
            continue;
        }
        for end in 0..=bytes.len() {
            assert_eq!(
                outcome(protocol, &bytes[..end]),
                outcome(protocol, &bytes[..end])
            );
        }
        for index in 0..bytes.len() {
            for mask in [1u8, 0x80, 0xff] {
                let mut mutated = bytes.to_vec();
                mutated[index] ^= mask;
                assert_eq!(outcome(protocol, &mutated), outcome(protocol, &mutated));
            }
        }
    }
}

#[test]
fn all_layer_adversarial_inputs() {
    use pcap_evidence::wire::Scope;
    use pcap_evidence_stream::network;
    let id = PacketId {
        capture: [0; 32],
        frame: 1,
        record_offset: 24,
    };
    for length in 0..256usize {
        let mut bytes = vec![0u8; length];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(37).wrapping_add(length as u8);
        }
        for link in [0u32, 1, 101, 108, 113, 127, 165, 228, 229, 276] {
            let input = EvidenceBytes::from_packet(&bytes, id, 0);
            let scope = Scope {
                section: 0,
                interface: 0,
                vlans: Vec::new(),
            };
            let a = network::decode(link, &input, scope.clone());
            let b = network::decode(link, &input, scope);
            assert_eq!(a.is_ok(), b.is_ok());
            if let (Err(a), Err(b)) = (a, b) {
                assert_eq!(a.to_string(), b.to_string());
            }
        }
    }
}

#[test]
fn tcp_sequence_wrap_reordering_and_duplicate_invariants() {
    let id = |frame| PacketId {
        capture: [1; 32],
        frame,
        record_offset: 24,
    };
    for syn in [1000u32, u32::MAX - 3] {
        for order in [
            [0, 1, 2],
            [2, 0, 1],
            [1, 2, 0],
            [2, 1, 0],
            [0, 2, 1],
            [1, 0, 2],
        ] {
            let mut stream = StreamAssembler::new(Some(syn), Limits::default());
            let parts: [&[u8]; 3] = [b"ab", b"cd", b"ef"];
            for i in order {
                stream
                    .push(
                        syn.wrapping_add(1 + 2 * i as u32),
                        EvidenceBytes::from_packet(parts[i], id(i as u64 + 1), 0),
                    )
                    .unwrap();
            }
            stream
                .push(
                    syn.wrapping_add(3),
                    EvidenceBytes::from_packet(b"cd", id(4), 0),
                )
                .unwrap();
            let r = stream.finish(OverlapPolicy::RejectConflict).unwrap();
            assert!(r.gaps.is_empty());
            assert!(r.conflicts.is_empty());
            let bytes: Vec<_> = r
                .chunks
                .iter()
                .flat_map(|c| c.bytes.data().iter().copied())
                .collect();
            assert_eq!(bytes, b"abcdef");
            assert_eq!(r.duplicate_observed_bytes, 2);
        }
    }
}

#[test]
fn tcp_conflicts_remain_gaps_not_majority_selected_bytes() {
    let id = |frame| PacketId {
        capture: [1; 32],
        frame,
        record_offset: 24,
    };
    let mut stream = StreamAssembler::new(Some(1000), Limits::default());
    for frame in 1..=4 {
        stream
            .push(1001, EvidenceBytes::from_packet(b"abc", id(frame), 0))
            .unwrap();
    }
    stream
        .push(1001, EvidenceBytes::from_packet(b"axc", id(5), 0))
        .unwrap();
    let r = stream.finish(OverlapPolicy::RejectConflict).unwrap();
    assert!(!r.conflicts.is_empty());
    assert!(!r.gaps.is_empty());
}

struct ShortReads<'a> {
    bytes: &'a [u8],
    step: usize,
}
impl Read for ShortReads<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let n = out.len().min(self.step).min(self.bytes.len());
        out[..n].copy_from_slice(&self.bytes[..n]);
        self.bytes = &self.bytes[n..];
        Ok(n)
    }
}
#[test]
fn reader_chunking_preserves_record_bytes() {
    for bytes in [
        &include_bytes!("../research/fixtures/pcap_le_us.pcap")[..],
        &include_bytes!("../research/fixtures/pcap_be_us.pcap")[..],
        &include_bytes!("../research/fixtures/pcap_le_ns.pcap")[..],
        &include_bytes!("../research/fixtures/pcap_be_ns.pcap")[..],
        &include_bytes!("../research/fixtures/pcapng.valid.pcap")[..],
    ] {
        let baseline: Vec<_> = CaptureReader::new(bytes, Limits::default(), ParseMode::Strict)
            .unwrap()
            .map(|r| r.unwrap().raw().to_vec())
            .collect();
        for step in 1..=31 {
            let actual: Vec<_> = CaptureReader::new(
                ShortReads { bytes, step },
                Limits::default(),
                ParseMode::Strict,
            )
            .unwrap()
            .map(|r| r.unwrap().raw().to_vec())
            .collect();
            assert_eq!(actual, baseline);
        }
    }
}
