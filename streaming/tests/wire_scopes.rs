use pcap_evidence::{
    fragment::{FragmentOutcome, FragmentReassembler},
    provenance::{EvidenceBytes, PacketId},
    wire::{self, Checksum, ChecksumContext, ChecksumPolicy, Scope, Transport},
    Limits,
};
use pcap_evidence_stream::{
    analyze_reader, network, Event, EventKind, EventSink, EvidenceStatus, Registry, Result,
    StreamConfig,
};

fn scope() -> Scope {
    Scope {
        section: 4,
        interface: 9,
        link_interface: None,
        vlans: vec![],
    }
}
fn id(frame: u64) -> PacketId {
    PacketId {
        capture: [1; 32],
        frame,
        record_offset: frame * 100,
    }
}
fn raw(bytes: &[u8], frame: u64) -> EvidenceBytes {
    EvidenceBytes::from_packet(bytes, id(frame), 0)
}
fn sll2(ether_type: u16, nic: u32, payload: &[u8]) -> Vec<u8> {
    let mut data = vec![0; 20];
    data[..2].copy_from_slice(&ether_type.to_be_bytes());
    data[4..8].copy_from_slice(&nic.to_be_bytes());
    data.extend_from_slice(payload);
    data
}
fn ipv4_udp() -> Vec<u8> {
    let mut ip = vec![0; 20];
    ip[0] = 0x45;
    ip[2..4].copy_from_slice(&28u16.to_be_bytes());
    ip[8] = 64;
    ip[9] = 17;
    ip[12..16].copy_from_slice(&[10, 0, 0, 1]);
    ip[16..20].copy_from_slice(&[10, 0, 0, 2]);
    let check = wire::internet_checksum(&ip);
    ip[10..12].copy_from_slice(&check.to_be_bytes());
    ip.extend_from_slice(&[0, 1, 0, 2, 0, 8, 0, 0]);
    ip
}
fn ipv6_routed_udp() -> Vec<u8> {
    let mut ip = vec![0; 40];
    ip[0] = 0x60;
    ip[4..6].copy_from_slice(&32u16.to_be_bytes());
    ip[6] = 43;
    ip[8..24].copy_from_slice(
        &"2001:db8::1"
            .parse::<std::net::Ipv6Addr>()
            .unwrap()
            .octets(),
    );
    ip[24..40].copy_from_slice(
        &"2001:db8::2"
            .parse::<std::net::Ipv6Addr>()
            .unwrap()
            .octets(),
    );
    ip.extend_from_slice(&[17, 2, 2, 1, 0, 0, 0, 0]);
    ip.extend_from_slice(
        &"2001:db8::3"
            .parse::<std::net::Ipv6Addr>()
            .unwrap()
            .octets(),
    );
    // Independent sum with final destination ::3 is 0x5b9a.
    ip.extend_from_slice(&[0, 1, 0, 2, 0, 8, 0xa4, 0x65]);
    ip
}
fn capture(link: u32, packets: &[Vec<u8>]) -> Vec<u8> {
    let mut bytes = vec![];
    bytes.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes());
    bytes.extend_from_slice(&2u16.to_le_bytes());
    bytes.extend_from_slice(&4u16.to_le_bytes());
    for value in [0, 0, 65_535, link] {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    for (frame, packet) in packets.iter().enumerate() {
        for value in [1, frame as u32, packet.len() as u32, packet.len() as u32] {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        bytes.extend_from_slice(packet);
    }
    bytes
}
#[derive(Default)]
struct Collect(Vec<Event>);
impl EventSink for Collect {
    fn run_id(&self) -> &str {
        "wire-scopes"
    }
    fn emit(&mut self, event: &Event) -> Result<u64> {
        self.0.push(event.clone());
        Ok(self.0.len() as u64)
    }
}

#[test]
fn sll2_scope_survives_direct_and_mpls_decode_and_real_stream_keys() {
    let ip = ipv4_udp();
    for mpls in [false, true] {
        let mut payload = if mpls {
            0x00010140u32.to_be_bytes().to_vec()
        } else {
            vec![]
        };
        payload.extend_from_slice(&ip);
        let ty = if mpls { 0x8847 } else { 0x0800 };
        let first = sll2(ty, 2, &payload);
        let network::Decoded::Ip(decoded, _) =
            network::decode(276, &raw(&first, 1), scope()).unwrap()
        else {
            panic!("IP expected")
        };
        assert_eq!(decoded.scope.section, 4);
        assert_eq!(decoded.scope.interface, 9);
        assert_eq!(decoded.scope.link_interface, Some(2));
        assert_eq!(
            decoded.payload.spans()[0].packet_start,
            if mpls { 44 } else { 40 }
        );

        let packets = [first.clone(), sll2(ty, 3, &payload), first];
        let config = StreamConfig::default();
        let registry = Registry::builtins(&config).unwrap();
        let mut output = Collect::default();
        let summary = analyze_reader(
            capture(276, &packets).as_slice(),
            config,
            &registry,
            &mut output,
        )
        .unwrap();
        assert_eq!(summary.windows, 2);
        let starts: Vec<_> = output
            .0
            .iter()
            .filter(|event| event.kind == EventKind::FlowStart)
            .collect();
        assert_eq!(starts.len(), 2);
        assert!(starts[0].data.encode().contains("\"link_interface\":2"));
        assert!(starts[1].data.encode().contains("\"link_interface\":3"));
    }
}

#[test]
fn normalization_retains_checksum_context_before_removing_fragmentable_extensions() {
    let full = ipv6_routed_udp();
    let fragment = |offset: u16, more: bool, payload: &[u8], frame| {
        let mut bytes = full[..40].to_vec();
        bytes[6] = 44;
        bytes[4..6].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        bytes.extend_from_slice(&[43, 0]);
        bytes.extend_from_slice(&(offset | u16::from(more)).to_be_bytes());
        bytes.extend_from_slice(&7u32.to_be_bytes());
        bytes.extend_from_slice(payload);
        wire::decode_packet(229, &bytes, id(frame), scope()).unwrap()
    };
    let mut fragments = FragmentReassembler::new(Limits::default());
    assert!(matches!(
        fragments
            .push(fragment(0, true, &full[40..56], 1), 1)
            .unwrap(),
        FragmentOutcome::Pending
    ));
    let FragmentOutcome::Complete(joined, _) = fragments
        .push(fragment(16, false, &full[56..], 2), 2)
        .unwrap()
    else {
        panic!("fragments must complete")
    };
    assert_eq!(joined.checksum_context, ChecksumContext::BaseAddresses);
    let normalized = network::normalize(joined).unwrap();
    assert_eq!(normalized.protocol, 17);
    assert_eq!(normalized.checksum_context, ChecksumContext::Unsupported);
    assert!(
        matches!(wire::decode_transport(&normalized, ChecksumPolicy::Observe).unwrap(), Transport::Udp(udp) if udp.checksum == Checksum::NotChecked)
    );
    assert_eq!(
        wire::decode_transport(&normalized, ChecksumPolicy::RequireValid)
            .unwrap_err()
            .field,
        "transport_checksum_operands"
    );
}

#[test]
fn stream_checksum_diagnostics_distinguish_unsupported_operands_from_invalid_bytes() {
    let bytes = capture(229, &[ipv6_routed_udp()]);
    let config = StreamConfig::default();
    let registry = Registry::builtins(&config).unwrap();
    let mut output = Collect::default();
    let summary = analyze_reader(bytes.as_slice(), config, &registry, &mut output).unwrap();
    assert_eq!(summary.windows, 1);
    assert!(output
        .0
        .iter()
        .any(|event| event.kind == EventKind::Diagnostic
            && event.status == EvidenceStatus::Unsupported
            && event
                .data
                .encode()
                .contains("unsupported_transport_checksum_operands")));
    assert!(!output.0.iter().any(|event| event
        .data
        .encode()
        .contains("invalid_transport_checksum_observed")));

    let mut config = StreamConfig::default();
    config.base.checksum_policy = ChecksumPolicy::RequireValid;
    let registry = Registry::builtins(&config).unwrap();
    let mut output = Collect::default();
    let summary = analyze_reader(bytes.as_slice(), config, &registry, &mut output).unwrap();
    assert_eq!(summary.windows, 0);
    assert!(output
        .0
        .iter()
        .any(|event| event.kind == EventKind::Diagnostic
            && event.status == EvidenceStatus::Rejected
            && event.data.encode().contains("transport_checksum_operands")));
}
