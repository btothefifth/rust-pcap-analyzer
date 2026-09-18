#[cfg(feature = "binary")]
use pcap_evidence::json::Json;
#[cfg(feature = "extensions")]
use pcap_evidence::protocol::{ProbeInput, ProbeResult, ProbeTransport};
use pcap_evidence_product::{layer, protocols::ber};
#[cfg(feature = "extensions")]
use pcap_evidence_product::{protocols::Protocol, registry::FramingPlugin};
#[cfg(feature = "extensions")]
use pcap_evidence_stream::plugin::ProtocolDetector;
#[test]
fn ber_indefinite_is_not_silently_repaired() {
    assert!(ber(&[0x30, 0x80, 0, 0]).is_err());
}
#[test]
fn ber_depth_limit() {
    let mut b = vec![5, 0];
    for _ in 0..20 {
        let mut n = vec![0x30, b.len() as u8];
        n.extend(b);
        b = n;
    }
    assert!(ber(&b).is_err());
}
#[cfg(feature = "extensions")]
#[test]
fn content_detection_is_not_bound_to_standard_ports() {
    let i = ProbeInput {
        transport: ProbeTransport::Tcp,
        source_port: 62000,
        destination_port: 62001,
        prefix: b"NOOP\r\n",
    };
    assert!(matches!(
        FramingPlugin(Protocol::Ftp).detect(&i),
        ProbeResult::Match { .. }
    ));
    assert!(matches!(
        FramingPlugin(Protocol::Pop3).detect(&i),
        ProbeResult::Match { .. }
    ));
}
#[test]
fn ethernet_truncation_has_typed_failure() {
    for len in 0..14 {
        assert!(layer::decode(1, &vec![0; len]).is_err());
    }
}
#[cfg(feature = "binary")]
#[test]
fn binary_tlv_scalar_golden() {
    assert_eq!(
        pcap_evidence_product::tlv::encode(&Json::Number(258), 100).unwrap(),
        vec![2, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 1, 2]
    );
    assert!(pcap_evidence_product::tlv::encode(&Json::String("large".into()), 2).is_err());
}
