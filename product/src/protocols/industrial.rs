//! Conservative envelope subsets. Recognition never establishes device semantics.
use super::{common::*, Decoded, Protocol};
use pcap_evidence::{Error, ErrorCode, Result};
pub fn decode(p: Protocol, b: &[u8]) -> Result<Decoded> {
    match p {
        Protocol::BacnetIp => bacnet_ip(b),
        Protocol::BacnetMstp => mstp(b),
        Protocol::Enip => enip(b),
        Protocol::Goose | Protocol::SampledValues => iec61850(p, b),
        Protocol::Mms => mms(b),
        Protocol::Iec104 => iec104(b),
        Protocol::S7 => s7(b),
        Protocol::HartIp => hart(b),
        Protocol::FinsUdp => fins_udp(b),
        Protocol::FinsTcp => fins_tcp(b),
        Protocol::Ads => ads(b),
        Protocol::OpcUa => opc(b),
        Protocol::Melsec => melsec(b),
        Protocol::Synchrophasor => phasor(b),
        Protocol::Ethercat => ethercat(b),
        Protocol::Profinet => profinet(b),
        Protocol::Powerlink => powerlink(b),
        _ => Err(bad("industrial", "wrong dispatch")),
    }
}
fn bacnet_ip(b: &[u8]) -> Result<Decoded> {
    need(b, 4, "bvlc")?;
    if b[0] != 0x81 || b[1] > 11 {
        return Err(bad("bvlc", "unsupported BVLC type/function"));
    }
    let n = usize::from(be16(b, 2));
    if n < 4 {
        return Err(bad("bvlc", "length below header"));
    }
    need(b, n, "bvlc")?;
    let mut d = Decoded::new(Protocol::BacnetIp, n)
        .num("bvlc_function", b[1], 1, 2)
        .num("bvlc_length", n as u64, 2, 4);
    let mut at = match b[1] {
        4 => {
            need(&b[..n], 10, "bvlc_forwarded")?;
            10
        }
        9..=11 => 4,
        _ => {
            d.issues.push("bvlc_management_payload_opaque");
            return Ok(d);
        }
    };
    need(&b[..n], at + 2, "npdu")?;
    if b[at] != 1 {
        return Err(bad("npdu", "version outside subset"));
    }
    let ctl = b[at + 1];
    if ctl & 0x50 != 0 {
        return Err(bad("npdu", "reserved control bits"));
    }
    d = d.num("npdu_control", ctl, at + 1, at + 2);
    at += 2;
    if ctl & 0x20 != 0 {
        need(&b[..n], at + 3, "npdu_destination")?;
        let k = usize::from(b[at + 2]);
        at += 3;
        need(&b[..n], at + k, "npdu_destination")?;
        at += k;
    }
    if ctl & 0x08 != 0 {
        need(&b[..n], at + 3, "npdu_source")?;
        let k = usize::from(b[at + 2]);
        if k == 0 {
            return Err(bad("npdu_source", "empty source address"));
        }
        at += 3;
        need(&b[..n], at + k, "npdu_source")?;
        at += k;
    }
    if ctl & 0x20 != 0 {
        need(&b[..n], at + 1, "npdu_hop")?;
        at += 1;
    }
    need(&b[..n], at + 1, "npdu_payload")?;
    if ctl & 0x80 != 0 {
        d = d.num("network_message_type", b[at], at, at + 1);
        if b[at] >= 0x80 {
            need(&b[..n], at + 3, "npdu_vendor")?;
        }
        d.issues.push("network_message_body_opaque");
    } else {
        let ty = b[at] >> 4;
        let header = match ty {
            0 => {
                if b[at] & 8 != 0 {
                    6
                } else {
                    4
                }
            }
            1 => 2,
            2 => 3,
            3 => {
                if b[at] & 8 != 0 {
                    5
                } else {
                    3
                }
            }
            4 => 4,
            5 => 3,
            6 | 7 => 3,
            _ => return Err(bad("apdu", "unknown PDU type")),
        };
        need(&b[..n], at + header, "apdu")?;
        d = d.num("apdu_type", ty, at, at + 1);
        d.issues.push("bacnet_service_and_object_semantics_opaque");
    }
    Ok(d)
}
fn header_crc(b: &[u8]) -> u8 {
    let mut c = 0xffu8;
    for &v in b {
        c ^= v;
        for _ in 0..8 {
            c = if c & 1 != 0 { (c >> 1) ^ 0x81 } else { c >> 1 };
        }
    }
    c ^ 0xff
}
fn mstp(b: &[u8]) -> Result<Decoded> {
    need(b, 8, "mstp_header")?;
    if b[..2] != [0x55, 0xff] {
        return Err(bad("mstp", "bad preamble"));
    }
    if b[2] > 7 {
        return Err(Error::new(
            ErrorCode::UnsupportedTransport,
            2,
            "mstp_type",
            "extended MS/TP outside legacy subset",
        ));
    }
    if header_crc(&b[2..7]) != b[7] {
        return Err(Error::new(
            ErrorCode::Checksum,
            7,
            "mstp_header_crc",
            "CRC mismatch",
        ));
    }
    let len = usize::from(be16(b, 5));
    if len > 501 {
        return Err(bad("mstp_length", "legacy payload exceeds 501"));
    }
    let n = 8 + len + if len > 0 { 2 } else { 0 };
    need(b, n, "mstp_data")?;
    if len > 0 && crc16(&b[8..8 + len], 0x8408, 0xffff, true, 0xffff) != le16(b, 8 + len) {
        return Err(Error::new(
            ErrorCode::Checksum,
            (8 + len) as u64,
            "mstp_data_crc",
            "CRC mismatch",
        ));
    }
    Ok(Decoded::new(Protocol::BacnetMstp, n)
        .num("frame_type", b[2], 2, 3)
        .num("destination", b[3], 3, 4)
        .num("source", b[4], 4, 5)
        .num("data_length", len as u64, 5, 7))
}
fn enip(b: &[u8]) -> Result<Decoded> {
    need(b, 24, "enip_header")?;
    let cmd = le16(b, 0);
    if ![0x63, 0x64, 0x65, 0x66, 0x6f, 0x70, 0x72, 0x73].contains(&cmd) {
        return Err(bad("enip_command", "outside supported envelope commands"));
    }
    if le32(b, 20) != 0 {
        return Err(bad("enip_options", "reserved options set"));
    }
    let n = 24 + usize::from(le16(b, 2));
    need(b, n, "enip_length")?;
    let mut d = Decoded::new(Protocol::Enip, n)
        .num("command", cmd, 0, 2)
        .num("session_handle", le32(b, 4), 4, 8)
        .num("status", le32(b, 8), 8, 12);
    if [0x6f, 0x70].contains(&cmd) {
        need(&b[..n], 32, "enip_cpf")?;
        let count = usize::from(le16(b, 30));
        if count > 64 {
            return Err(Error::limit("cpf_items"));
        }
        let mut at = 32;
        let mut cip = 0;
        for _ in 0..count {
            need(&b[..n], at + 4, "cpf_item")?;
            let ty = le16(b, at);
            let len = usize::from(le16(b, at + 2));
            at += 4;
            need(&b[..n], at + len, "cpf_data")?;
            if ty == 0xb2 {
                let c = &b[at..at + len];
                need(c, 2, "cip_header")?;
                if c[0] & 0x80 != 0 {
                    need(c, 4, "cip_response")?;
                    if c[1] != 0 {
                        return Err(bad("cip_reserved", "reserved response octet"));
                    }
                    need(c, 4 + usize::from(c[3]) * 2, "cip_status")?;
                } else {
                    need(c, 2 + usize::from(c[1]) * 2, "cip_path")?;
                }
                cip += 1;
            }
            at += len;
        }
        if at != n {
            return Err(bad("cpf_length", "trailing CPF bytes"));
        }
        d = d
            .num("cpf_items", count as u64, 30, 32)
            .text("cip_messages", cip.to_string(), 32, n);
        d.issues
            .push("cip_paths_objects_and_connection_semantics_opaque");
    } else {
        d.issues.push("encapsulation_command_body_opaque");
    }
    Ok(d)
}
fn iec61850(p: Protocol, b: &[u8]) -> Result<Decoded> {
    need(b, 8, "iec61850_header")?;
    let n = usize::from(be16(b, 2));
    if n < 10 {
        return Err(bad("iec61850_length", "length below BER envelope"));
    }
    need(b, n, "iec61850_payload")?;
    // Nonzero reserved words can describe extensions; preserve as unsupported rather than guessing.
    if be16(b, 4) != 0 || be16(b, 6) != 0 {
        return Err(Error::new(
            ErrorCode::UnsupportedTransport,
            4,
            "iec61850_reserved",
            "security/extension words outside subset",
        ));
    }
    let tree = ber(&b[8..n])?;
    let tag = if p == Protocol::Goose { 0x61 } else { 0x60 };
    if tree.tag != tag || tree.end != n - 8 {
        return Err(bad("iec61850_ber", "wrong tag or trailing bytes"));
    }
    let mut d = Decoded::new(p, n)
        .num("app_id", be16(b, 0), 0, 2)
        .num("length", n as u64, 2, 4)
        .num("ber_children", tree.children.len() as u64, 8, n);
    for c in &tree.children {
        let name = match (p, c.tag) {
            (Protocol::Goose, 0x85) => Some("state_number"),
            (Protocol::Goose, 0x86) => Some("sequence_number"),
            (Protocol::SampledValues, 0x80) => Some("asdu_count"),
            _ => None,
        };
        if let Some(name) = name {
            d = d.num(name, ber_uint(&b[8..n], c)?, 8 + c.value_start, 8 + c.end);
        }
    }
    d.issues
        .push("constrained_ber_envelope_not_complete_iec61850_semantics");
    Ok(d)
}
fn mms(b: &[u8]) -> Result<Decoded> {
    let t = ber(b)?;
    if !(0xa0..=0xad).contains(&t.tag) {
        return Err(bad("mms_pdu", "MMS envelope tag outside subset"));
    }
    let mut d = Decoded::new(Protocol::Mms, t.end).num("pdu_tag", t.tag, 0, 1);
    if let Some(c) = t.children.first().filter(|c| c.tag == 2) {
        d = d.num("invoke_id", ber_uint(b, c)?, c.value_start, c.end);
    }
    d.issues
        .push("mms_service_and_iso_presentation_layers_not_decoded");
    Ok(d)
}
fn iec104(b: &[u8]) -> Result<Decoded> {
    need(b, 6, "iec104_header")?;
    let len = usize::from(b[1]);
    if b[0] != 0x68 || !(4..=253).contains(&len) {
        return Err(bad("iec104", "invalid start or length"));
    }
    let n = len + 2;
    need(b, n, "iec104_apdu")?;
    let mut d = Decoded::new(Protocol::Iec104, n);
    if b[2] & 1 == 0 {
        if b[4] & 1 != 0 {
            return Err(bad("iec104_sequence", "odd receive sequence"));
        }
        d = d
            .text("format", "I", 2, 6)
            .num("send_sequence", le16(b, 2) >> 1, 2, 4)
            .num("receive_sequence", le16(b, 4) >> 1, 4, 6);
        d.issues.push("asdu_body_opaque");
    } else if b[2] & 3 == 1 {
        if len != 4 || b[2] != 1 || b[3] != 0 || b[4] & 1 != 0 {
            return Err(bad("iec104_s", "invalid S frame"));
        }
        d = d
            .text("format", "S", 2, 6)
            .num("receive_sequence", le16(b, 4) >> 1, 4, 6);
    } else {
        if len != 4 || ![7, 11, 19, 35, 67, 131].contains(&b[2]) || b[3..6] != [0, 0, 0] {
            return Err(bad("iec104_u", "invalid U frame"));
        }
        d = d.text("format", "U", 2, 6).num("control", b[2], 2, 3);
    }
    Ok(d)
}
fn s7(b: &[u8]) -> Result<Decoded> {
    need(b, 7, "tpkt_cotp")?;
    if b[0] != 3 || b[1] != 0 {
        return Err(bad("tpkt", "version/reserved invalid"));
    }
    let n = usize::from(be16(b, 2));
    if n < 17 {
        return Err(bad("s7_length", "short TPKT"));
    }
    need(b, n, "tpkt_length")?;
    let cp = usize::from(b[4]);
    if cp < 2 {
        return Err(bad("cotp", "short COTP"));
    }
    let at = 5 + cp;
    need(&b[..n], at + 10, "s7_header")?;
    if b[5] != 0xf0 || b[6] != 0x80 {
        return Err(Error::new(
            ErrorCode::UnsupportedTransport,
            5,
            "cotp",
            "only complete COTP data TPDU supported",
        ));
    }
    if b[at] != 0x32 || ![1, 2, 3, 7].contains(&b[at + 1]) {
        return Err(bad("s7", "unknown S7 header"));
    }
    let header = if b[at + 1] == 2 || b[at + 1] == 3 {
        12
    } else {
        10
    };
    need(&b[..n], at + header, "s7_ack")?;
    let par = usize::from(be16(b, at + 6));
    let data = usize::from(be16(b, at + 8));
    if at + header + par + data != n {
        return Err(bad("s7_lengths", "parameter/data lengths disagree"));
    }
    let mut d = Decoded::new(Protocol::S7, n)
        .num("rosctr", b[at + 1], at + 1, at + 2)
        .num("pdu_reference", be16(b, at + 4), at + 4, at + 6)
        .num("parameter_length", par as u64, at + 6, at + 8)
        .num("data_length", data as u64, at + 8, at + 10);
    d.issues.push("s7_function_parameters_opaque");
    Ok(d)
}
fn hart(b: &[u8]) -> Result<Decoded> {
    need(b, 8, "hart_ip")?;
    if b[0] != 1 || b[1] > 2 {
        return Err(bad("hart_ip", "version/type outside subset"));
    }
    let n = usize::from(be16(b, 6));
    if n < 8 {
        return Err(bad("hart_ip_length", "length below header"));
    }
    need(b, n, "hart_ip_body")?;
    Ok(Decoded::new(Protocol::HartIp, n)
        .num("version", b[0], 0, 1)
        .num("message_type", b[1], 1, 2)
        .num("message_id", b[2], 2, 3)
        .num("status", b[3], 3, 4)
        .num("sequence", be16(b, 4), 4, 6))
}
fn fins_udp(b: &[u8]) -> Result<Decoded> {
    need(b, 12, "fins_udp")?;
    if b[0] & 0x80 == 0 || b[1] != 0 || b[2] > 7 {
        return Err(bad("fins_udp", "invalid fixed FINS header"));
    }
    let response = b[0] & 0x40 != 0;
    if response {
        need(b, 14, "fins_response")?;
    }
    let mut d = Decoded::new(Protocol::FinsUdp, b.len())
        .num("control", b[0], 0, 1)
        .num("service_id", b[9], 9, 10)
        .num("command", be16(b, 10), 10, 12);
    d.issues.push("fins_command_body_opaque");
    Ok(d)
}
fn fins_tcp(b: &[u8]) -> Result<Decoded> {
    need(b, 16, "fins_tcp")?;
    if &b[..4] != b"FINS" {
        return Err(bad("fins_tcp", "signature mismatch"));
    }
    let len = usize::try_from(be32(b, 4)).map_err(|_| Error::limit("fins_length"))?;
    if len < 8 {
        return Err(bad("fins_length", "length below header"));
    }
    let n = len
        .checked_add(8)
        .ok_or_else(|| Error::limit("fins_length"))?;
    need(b, n, "fins_body")?;
    Ok(Decoded::new(Protocol::FinsTcp, n)
        .num("command", be32(b, 8), 8, 12)
        .num("error_code", be32(b, 12), 12, 16))
}
fn ads(b: &[u8]) -> Result<Decoded> {
    need(b, 38, "ams_tcp")?;
    if le16(b, 0) != 0 {
        return Err(bad("ams_tcp", "reserved field nonzero"));
    }
    let len = usize::try_from(le32(b, 2)).map_err(|_| Error::limit("ams_length"))?;
    if len < 32 {
        return Err(bad("ams_length", "length below AMS header"));
    }
    let n = len
        .checked_add(6)
        .ok_or_else(|| Error::limit("ams_length"))?;
    need(b, n, "ams_body")?;
    if usize::try_from(le32(b, 26)).ok() != Some(n - 38) {
        return Err(bad("ams_data_length", "payload length disagrees"));
    }
    if !(1..=9).contains(&le16(b, 22)) {
        return Err(bad("ams_command", "command outside subset"));
    }
    Ok(Decoded::new(Protocol::Ads, n)
        .num("command", le16(b, 22), 22, 24)
        .num("state_flags", le16(b, 24), 24, 26)
        .num("error_code", le32(b, 30), 30, 34)
        .num("invoke_id", le32(b, 34), 34, 38))
}
fn opc(b: &[u8]) -> Result<Decoded> {
    need(b, 8, "opcua_tcp")?;
    if !matches!(
        &b[..3],
        b"HEL" | b"ACK" | b"ERR" | b"RHE" | b"OPN" | b"MSG" | b"CLO"
    ) || ![b'F', b'C', b'A'].contains(&b[3])
    {
        return Err(bad("opcua_tcp", "message/chunk type outside subset"));
    }
    let n = usize::try_from(le32(b, 4)).map_err(|_| Error::limit("opcua_length"))?;
    if n < 8 {
        return Err(bad("opcua_length", "length below header"));
    }
    need(b, n, "opcua_chunk")?;
    let mut d = Decoded::new(Protocol::OpcUa, n)
        .text(
            "message_type",
            String::from_utf8_lossy(&b[..3]).to_string(),
            0,
            3,
        )
        .num("chunk_type", b[3], 3, 4);
    if &b[..3] == b"HEL" {
        need(&b[..n], 32, "opcua_hello")?;
        let url = le32(b, 28);
        if url != u32::MAX && usize::try_from(url).ok().and_then(|x| x.checked_add(32)) != Some(n) {
            return Err(bad("opcua_hello", "endpoint length mismatch"));
        }
        d = d.num("protocol_version", le32(b, 8), 8, 12);
    }
    d.issues
        .push("no_secure_channel_decryption_or_message_assembly");
    Ok(d)
}
fn melsec(b: &[u8]) -> Result<Decoded> {
    need(b, 11, "melsec_3e")?;
    if b[..2] != [0x50, 0] && b[..2] != [0xd0, 0] {
        return Err(bad("melsec_3e", "only binary 3E supported"));
    }
    let n = 9 + usize::from(le16(b, 7));
    need(b, n, "melsec_body")?;
    let req = b[0] == 0x50;
    if req {
        need(&b[..n], 15, "melsec_request")?;
    } else if n < 11 {
        return Err(bad("melsec_response", "missing end code"));
    }
    let d = Decoded::new(Protocol::Melsec, n)
        .num("network", b[2], 2, 3)
        .num("station", b[6], 6, 7);
    Ok(if req {
        d.num("command", le16(b, 11), 11, 13)
            .num("subcommand", le16(b, 13), 13, 15)
    } else {
        d.num("end_code", le16(b, 9), 9, 11)
    })
}
fn phasor(b: &[u8]) -> Result<Decoded> {
    need(b, 16, "c37118")?;
    if b[0] != 0xaa || b[1] & 0x80 != 0 || b[1] & 15 == 0 {
        return Err(bad("c37118", "sync/version outside subset"));
    }
    let n = usize::from(be16(b, 2));
    if n < 16 {
        return Err(bad("c37118_length", "length below header and CRC"));
    }
    need(b, n, "c37118_frame")?;
    if crc16(&b[..n - 2], 0x1021, 0xffff, false, 0) != be16(b, n - 2) {
        return Err(Error::new(
            ErrorCode::Checksum,
            (n - 2) as u64,
            "c37118_crc",
            "CRC mismatch",
        ));
    }
    Ok(Decoded::new(Protocol::Synchrophasor, n)
        .num("frame_type", (b[1] >> 4) & 7, 1, 2)
        .num("version", b[1] & 15, 1, 2)
        .num("id_code", be16(b, 4), 4, 6)
        .num("seconds", be32(b, 6), 6, 10)
        .num("fraction_word", be32(b, 10), 10, 14))
}
fn ethercat(b: &[u8]) -> Result<Decoded> {
    need(b, 2, "ethercat")?;
    let hdr = le16(b, 0);
    if hdr >> 12 != 1 || hdr & 0x0800 != 0 {
        return Err(bad("ethercat_header", "unsupported type or reserved bit"));
    }
    let n = 2 + usize::from(hdr & 0x7ff);
    need(b, n, "ethercat_frame")?;
    let mut at = 2;
    let mut count = 0u64;
    while at < n {
        if count >= 128 {
            return Err(Error::limit("ethercat_datagrams"));
        }
        need(&b[..n], at + 10, "ethercat_datagram")?;
        let flags = le16(b, at + 6);
        let len = usize::from(flags & 0x7ff);
        let end = at + 12 + len;
        need(&b[..n], end, "ethercat_data")?;
        if (flags & 0x8000 != 0) != (end < n) {
            return Err(bad(
                "ethercat_more",
                "continuation disagrees with frame boundary",
            ));
        }
        count += 1;
        at = end;
    }
    Ok(Decoded::new(Protocol::Ethercat, n)
        .num("datagrams", count, 2, n)
        .num("frame_length", (n - 2) as u64, 0, 2))
}
fn profinet(b: &[u8]) -> Result<Decoded> {
    need(b, 6, "profinet_rt")?;
    let id = be16(b, 0);
    if !(0x8000..=0xfbff).contains(&id) {
        return Err(Error::new(
            ErrorCode::UnsupportedTransport,
            0,
            "profinet_rt",
            "non-cyclic frame outside metadata subset",
        ));
    }
    let n = b.len();
    let mut d = Decoded::new(Protocol::Profinet, n)
        .num("frame_id", id, 0, 2)
        .num("cycle_counter", be16(b, n - 4), n - 4, n - 2)
        .num("data_status", b[n - 2], n - 2, n - 1)
        .num("transfer_status", b[n - 1], n - 1, n);
    d.issues
        .push("device_layout_and_padding_require_external_configuration");
    Ok(d)
}
fn powerlink(b: &[u8]) -> Result<Decoded> {
    need(b, 3, "powerlink")?;
    let ty = b[0] & 0x7f;
    if ![1, 3, 4, 5, 6, 7].contains(&ty) {
        return Err(bad("powerlink", "message type outside subset"));
    }
    let mut d = Decoded::new(Protocol::Powerlink, b.len())
        .num("message_type", ty, 0, 1)
        .num("destination", b[1], 1, 2)
        .num("source", b[2], 2, 3);
    d.issues.push("powerlink_message_specific_body_not_decoded");
    Ok(d)
}
