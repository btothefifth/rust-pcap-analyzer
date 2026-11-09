#[cfg(any(
    feature = "standard",
    feature = "extensions",
    feature = "industrial",
    feature = "industrial-full"
))]
use pcap_evidence_product::protocols::Protocol;

#[cfg(feature = "standard")]
#[test]
fn netflow9_framing_known_answer() {
    let bytes = include_bytes!("fixtures/netflow9.bin");
    let d = Protocol::Netflow9
        .decode(bytes)
        .expect("independent framing fixture");
    assert_eq!(d.consumed, bytes.len());
    assert!(d
        .fields
        .iter()
        .all(|f| f.start <= f.end && f.end <= d.consumed));
    assert_eq!(d.support, "metadata-only");
    for end in 0..2 {
        assert!(Protocol::Netflow9.decode(&bytes[..end]).is_err());
    }
}

#[cfg(feature = "extensions")]
#[test]
fn bgp_framing_known_answer() {
    let bytes = include_bytes!("fixtures/bgp.bin");
    let d = Protocol::Bgp
        .decode(bytes)
        .expect("independent framing fixture");
    assert_eq!(d.consumed, bytes.len());
    assert!(d
        .fields
        .iter()
        .all(|f| f.start <= f.end && f.end <= d.consumed));
    assert_eq!(d.support, "metadata-only");
    for end in 0..2 {
        assert!(Protocol::Bgp.decode(&bytes[..end]).is_err());
    }
}

#[cfg(feature = "extensions")]
#[test]
fn snmp_framing_known_answer() {
    let bytes = include_bytes!("fixtures/snmp.bin");
    let d = Protocol::Snmp
        .decode(bytes)
        .expect("independent framing fixture");
    assert_eq!(d.consumed, bytes.len());
    assert!(d
        .fields
        .iter()
        .all(|f| f.start <= f.end && f.end <= d.consumed));
    assert_eq!(d.support, "metadata-only");
    for end in 0..2 {
        assert!(Protocol::Snmp.decode(&bytes[..end]).is_err());
    }
}

#[cfg(feature = "extensions")]
#[test]
fn ftp_framing_known_answer() {
    let bytes = include_bytes!("fixtures/ftp.bin");
    let d = Protocol::Ftp
        .decode(bytes)
        .expect("independent framing fixture");
    assert_eq!(d.consumed, bytes.len());
    assert!(d
        .fields
        .iter()
        .all(|f| f.start <= f.end && f.end <= d.consumed));
    assert_eq!(d.support, "metadata-only");
    for end in 0..2 {
        assert!(Protocol::Ftp.decode(&bytes[..end]).is_err());
    }
}

#[cfg(feature = "extensions")]
#[test]
fn pop3_framing_known_answer() {
    let bytes = include_bytes!("fixtures/pop3.bin");
    let d = Protocol::Pop3
        .decode(bytes)
        .expect("independent framing fixture");
    assert_eq!(d.consumed, bytes.len());
    assert!(d
        .fields
        .iter()
        .all(|f| f.start <= f.end && f.end <= d.consumed));
    assert_eq!(d.support, "metadata-only");
    for end in 0..2 {
        assert!(Protocol::Pop3.decode(&bytes[..end]).is_err());
    }
}

#[cfg(feature = "extensions")]
#[test]
fn imap_framing_known_answer() {
    let bytes = include_bytes!("fixtures/imap.bin");
    let d = Protocol::Imap
        .decode(bytes)
        .expect("independent framing fixture");
    assert_eq!(d.consumed, bytes.len());
    assert!(d
        .fields
        .iter()
        .all(|f| f.start <= f.end && f.end <= d.consumed));
    assert_eq!(d.support, "metadata-only");
    for end in 0..2 {
        assert!(Protocol::Imap.decode(&bytes[..end]).is_err());
    }
}

#[cfg(feature = "extensions")]
#[test]
fn telnet_framing_known_answer() {
    let bytes = include_bytes!("fixtures/telnet.bin");
    let d = Protocol::Telnet
        .decode(bytes)
        .expect("independent framing fixture");
    assert_eq!(d.consumed, bytes.len());
    assert!(d
        .fields
        .iter()
        .all(|f| f.start <= f.end && f.end <= d.consumed));
    assert_eq!(d.support, "metadata-only");
    for end in 0..2 {
        assert!(Protocol::Telnet.decode(&bytes[..end]).is_err());
    }
}

#[cfg(feature = "extensions")]
#[test]
fn tftp_framing_known_answer() {
    let bytes = include_bytes!("fixtures/tftp.bin");
    let d = Protocol::Tftp
        .decode(bytes)
        .expect("independent framing fixture");
    assert_eq!(d.consumed, bytes.len());
    assert!(d
        .fields
        .iter()
        .all(|f| f.start <= f.end && f.end <= d.consumed));
    assert_eq!(d.support, "metadata-only");
    for end in 0..2 {
        assert!(Protocol::Tftp.decode(&bytes[..end]).is_err());
    }
}

#[cfg(feature = "extensions")]
#[test]
fn sip_framing_known_answer() {
    let bytes = include_bytes!("fixtures/sip.bin");
    let d = Protocol::Sip
        .decode(bytes)
        .expect("independent framing fixture");
    assert_eq!(d.consumed, bytes.len());
    assert!(d
        .fields
        .iter()
        .all(|f| f.start <= f.end && f.end <= d.consumed));
    assert_eq!(d.support, "metadata-only");
    for end in 0..2 {
        assert!(Protocol::Sip.decode(&bytes[..end]).is_err());
    }
}

#[cfg(feature = "extensions")]
#[test]
fn rtp_framing_known_answer() {
    let bytes = include_bytes!("fixtures/rtp.bin");
    let d = Protocol::Rtp
        .decode(bytes)
        .expect("independent framing fixture");
    assert_eq!(d.consumed, bytes.len());
    assert!(d
        .fields
        .iter()
        .all(|f| f.start <= f.end && f.end <= d.consumed));
    assert_eq!(d.support, "metadata-only");
    for end in 0..2 {
        assert!(Protocol::Rtp.decode(&bytes[..end]).is_err());
    }
}

#[cfg(feature = "extensions")]
#[test]
fn pptp_framing_known_answer() {
    let bytes = include_bytes!("fixtures/pptp.bin");
    let d = Protocol::Pptp
        .decode(bytes)
        .expect("independent framing fixture");
    assert_eq!(d.consumed, bytes.len());
    assert!(d
        .fields
        .iter()
        .all(|f| f.start <= f.end && f.end <= d.consumed));
    assert_eq!(d.support, "metadata-only");
    for end in 0..2 {
        assert!(Protocol::Pptp.decode(&bytes[..end]).is_err());
    }
}

#[cfg(feature = "industrial")]
#[test]
fn bacnet_ip_framing_known_answer() {
    let bytes = include_bytes!("fixtures/bacnet_ip.bin");
    let d = Protocol::BacnetIp
        .decode(bytes)
        .expect("independent framing fixture");
    assert_eq!(d.consumed, bytes.len());
    assert!(d
        .fields
        .iter()
        .all(|f| f.start <= f.end && f.end <= d.consumed));
    assert_eq!(d.support, "implemented-partial");
    for end in 0..2 {
        assert!(Protocol::BacnetIp.decode(&bytes[..end]).is_err());
    }
}

#[cfg(feature = "industrial")]
#[test]
fn enip_cip_framing_known_answer() {
    let bytes = include_bytes!("fixtures/enip_cip.bin");
    let d = Protocol::Enip
        .decode(bytes)
        .expect("independent framing fixture");
    assert_eq!(d.consumed, bytes.len());
    assert!(d
        .fields
        .iter()
        .all(|f| f.start <= f.end && f.end <= d.consumed));
    assert_eq!(d.support, "metadata-only");
    for end in 0..2 {
        assert!(Protocol::Enip.decode(&bytes[..end]).is_err());
    }
}

#[cfg(feature = "industrial")]
#[test]
fn mms_framing_known_answer() {
    let bytes = include_bytes!("fixtures/mms.bin");
    let d = Protocol::Mms
        .decode(bytes)
        .expect("independent framing fixture");
    assert_eq!(d.consumed, bytes.len());
    assert!(d
        .fields
        .iter()
        .all(|f| f.start <= f.end && f.end <= d.consumed));
    assert_eq!(d.support, "metadata-only");
    for end in 0..2 {
        assert!(Protocol::Mms.decode(&bytes[..end]).is_err());
    }
}

#[cfg(feature = "industrial-full")]
#[test]
fn iec104_framing_known_answer() {
    let bytes = include_bytes!("fixtures/iec104.bin");
    let d = Protocol::Iec104
        .decode(bytes)
        .expect("independent framing fixture");
    assert_eq!(d.consumed, bytes.len());
    assert!(d
        .fields
        .iter()
        .all(|f| f.start <= f.end && f.end <= d.consumed));
    assert_eq!(d.support, "metadata-only");
    for end in 0..2 {
        assert!(Protocol::Iec104.decode(&bytes[..end]).is_err());
    }
}

#[cfg(feature = "industrial-full")]
#[test]
fn s7_framing_known_answer() {
    let bytes = include_bytes!("fixtures/s7.bin");
    let d = Protocol::S7
        .decode(bytes)
        .expect("independent framing fixture");
    assert_eq!(d.consumed, bytes.len());
    assert!(d
        .fields
        .iter()
        .all(|f| f.start <= f.end && f.end <= d.consumed));
    assert_eq!(d.support, "metadata-only");
    for end in 0..2 {
        assert!(Protocol::S7.decode(&bytes[..end]).is_err());
    }
}

#[cfg(feature = "industrial-full")]
#[test]
fn hart_ip_framing_known_answer() {
    let bytes = include_bytes!("fixtures/hart_ip.bin");
    let d = Protocol::HartIp
        .decode(bytes)
        .expect("independent framing fixture");
    assert_eq!(d.consumed, bytes.len());
    assert!(d
        .fields
        .iter()
        .all(|f| f.start <= f.end && f.end <= d.consumed));
    assert_eq!(d.support, "metadata-only");
    for end in 0..2 {
        assert!(Protocol::HartIp.decode(&bytes[..end]).is_err());
    }
}

#[cfg(feature = "industrial-full")]
#[test]
fn fins_udp_framing_known_answer() {
    let bytes = include_bytes!("fixtures/fins_udp.bin");
    let d = Protocol::FinsUdp
        .decode(bytes)
        .expect("independent framing fixture");
    assert_eq!(d.consumed, bytes.len());
    assert!(d
        .fields
        .iter()
        .all(|f| f.start <= f.end && f.end <= d.consumed));
    assert_eq!(d.support, "metadata-only");
    for end in 0..2 {
        assert!(Protocol::FinsUdp.decode(&bytes[..end]).is_err());
    }
}

#[cfg(feature = "industrial-full")]
#[test]
fn fins_tcp_framing_known_answer() {
    let bytes = include_bytes!("fixtures/fins_tcp.bin");
    let d = Protocol::FinsTcp
        .decode(bytes)
        .expect("independent framing fixture");
    assert_eq!(d.consumed, bytes.len());
    assert!(d
        .fields
        .iter()
        .all(|f| f.start <= f.end && f.end <= d.consumed));
    assert_eq!(d.support, "metadata-only");
    for end in 0..2 {
        assert!(Protocol::FinsTcp.decode(&bytes[..end]).is_err());
    }
}

#[cfg(feature = "industrial-full")]
#[test]
fn ads_framing_known_answer() {
    let bytes = include_bytes!("fixtures/ads.bin");
    let d = Protocol::Ads
        .decode(bytes)
        .expect("independent framing fixture");
    assert_eq!(d.consumed, bytes.len());
    assert!(d
        .fields
        .iter()
        .all(|f| f.start <= f.end && f.end <= d.consumed));
    assert_eq!(d.support, "metadata-only");
    for end in 0..2 {
        assert!(Protocol::Ads.decode(&bytes[..end]).is_err());
    }
}

#[cfg(feature = "industrial-full")]
#[test]
fn opcua_tcp_framing_known_answer() {
    let bytes = include_bytes!("fixtures/opcua_tcp.bin");
    let d = Protocol::OpcUa
        .decode(bytes)
        .expect("independent framing fixture");
    assert_eq!(d.consumed, bytes.len());
    assert!(d
        .fields
        .iter()
        .all(|f| f.start <= f.end && f.end <= d.consumed));
    assert_eq!(d.support, "metadata-only");
    for end in 0..2 {
        assert!(Protocol::OpcUa.decode(&bytes[..end]).is_err());
    }
}

#[cfg(feature = "industrial-full")]
#[test]
fn melsec_3e_framing_known_answer() {
    let bytes = include_bytes!("fixtures/melsec_3e.bin");
    let d = Protocol::Melsec
        .decode(bytes)
        .expect("independent framing fixture");
    assert_eq!(d.consumed, bytes.len());
    assert!(d
        .fields
        .iter()
        .all(|f| f.start <= f.end && f.end <= d.consumed));
    assert_eq!(d.support, "metadata-only");
    for end in 0..2 {
        assert!(Protocol::Melsec.decode(&bytes[..end]).is_err());
    }
}

#[cfg(feature = "industrial-full")]
#[test]
fn c37118_framing_known_answer() {
    let bytes = include_bytes!("fixtures/c37118.bin");
    let d = Protocol::Synchrophasor
        .decode(bytes)
        .expect("independent framing fixture");
    assert_eq!(d.consumed, bytes.len());
    assert!(d
        .fields
        .iter()
        .all(|f| f.start <= f.end && f.end <= d.consumed));
    assert_eq!(d.support, "metadata-only");
    for end in 0..2 {
        assert!(Protocol::Synchrophasor.decode(&bytes[..end]).is_err());
    }
}

#[cfg(feature = "extensions")]
#[test]
fn imap_numeric_untagged_replies_preserve_verb_spans() {
    for (raw, verb) in [
        (b"* 23 EXISTS\r\n".as_slice(), "EXISTS"),
        (b"* 2 EXPUNGE\r\n".as_slice(), "EXPUNGE"),
        (b"* 1 FETCH (FLAGS (\\Seen))\r\n".as_slice(), "FETCH"),
        (b"*  0  RECENT\r\n".as_slice(), "RECENT"),
        (b"* OK ready\r\n".as_slice(), "OK"),
        (b"a047 OK done\r\n".as_slice(), "OK"),
    ] {
        let decoded = Protocol::Imap.decode(raw).unwrap();
        let field = decoded.fields.iter().find(|f| f.name == "verb").unwrap();
        assert_eq!(&raw[field.start..field.end], verb.as_bytes());
        assert_eq!(field.value, pcap_evidence::json::Json::from(verb));
    }
    for raw in [b"* 23\r\n".as_slice(), b"* 23 NOPE\r\n", b"* 23 OK\r\n"] {
        assert!(Protocol::Imap.decode(raw).is_err());
    }
}

#[cfg(feature = "extensions")]
#[test]
fn sip_header_separator_whitespace_preserves_length_checks() {
    for header in [
        "Content-Length : 0",
        "Content-Length\t: 0",
        "l : 0",
        "L\t : 0",
    ] {
        let raw = format!("OPTIONS sip:a@example.test SIP/2.0\r\n{header}\r\n\r\n");
        assert_eq!(
            Protocol::Sip.decode(raw.as_bytes()).unwrap().consumed,
            raw.len()
        );
        let conflict =
            format!("OPTIONS sip:a@example.test SIP/2.0\r\nContent-Length: 1\r\n{header}\r\n\r\nx");
        assert!(Protocol::Sip.decode(conflict.as_bytes()).is_err());
    }
    for header in [": x", "Bad Name: x", "Bad@: x", " Content-Length: 0"] {
        let raw =
            format!("OPTIONS sip:a@example.test SIP/2.0\r\n{header}\r\nContent-Length: 0\r\n\r\n");
        assert!(Protocol::Sip.decode(raw.as_bytes()).is_err());
    }
}
