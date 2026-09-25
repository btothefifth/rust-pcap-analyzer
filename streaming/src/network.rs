//! Bounded link/tunnel extensions. Inner payloads are sliced from EvidenceBytes,
//! never copied into a fabricated packet identity. Tunnel paths isolate namespaces.
use crate::{malformed, Error, Result};
use pcap_evidence::{
    json::Json,
    provenance::EvidenceBytes,
    wire::{self, Datagram, Scope},
};
use std::net::IpAddr;

pub enum Decoded {
    Ip(Datagram, Vec<String>),
    Metadata {
        protocol: &'static str,
        data: Json,
        supported: bool,
    },
}
fn need(b: &[u8], n: usize, field: &'static str) -> Result<()> {
    if b.len() < n {
        Err(malformed(field, "truncated header or payload"))
    } else {
        Ok(())
    }
}
fn u16be(b: &[u8], p: usize) -> u16 {
    u16::from_be_bytes([b[p], b[p + 1]])
}
fn u32be(b: &[u8], p: usize) -> u32 {
    u32::from_be_bytes([b[p], b[p + 1], b[p + 2], b[p + 3]])
}
fn hex(b: &[u8]) -> String {
    pcap_evidence::sha256::hex(b)
}

pub fn decode(link: u32, raw: &EvidenceBytes, scope: Scope) -> Result<Decoded> {
    if !raw.validate() {
        return Err(malformed("provenance", "invalid input spans"));
    }
    if link == 127 || link == 105 {
        return wireless(link, raw, scope);
    }
    let b = raw.data();
    let mut scoped = scope.clone();
    let layout = match link {
        1 => {
            need(b, 14, "ethernet")?;
            Some((14, u16be(b, 12)))
        }
        113 => {
            need(b, 16, "sll")?;
            Some((16, u16be(b, 14)))
        }
        276 => {
            need(b, 20, "sll2")?;
            Some((20, u16be(b, 0)))
        }
        _ => None,
    };
    if let Some((mut p, mut ty)) = layout {
        while [0x8100, 0x88a8, 0x9100].contains(&ty) {
            if scoped.vlans.len() >= 8 {
                return Err(Error::limit("vlan_depth"));
            }
            need(b, p + 4, "vlan")?;
            scoped.vlans.push(u16be(b, p) & 0x0fff);
            ty = u16be(b, p + 2);
            p += 4;
        }
        if ty == 0x0806 {
            return arp(&b[p..]);
        }
        if ty == 0x8847 || ty == 0x8848 {
            return mpls(&raw.slice(p..raw.len())?, scoped);
        }
    }
    Ok(Decoded::Ip(decode_ip(link, raw, scope)?, Vec::new()))
}
fn decode_ip(link: u32, raw: &EvidenceBytes, scope: Scope) -> Result<Datagram> {
    let id = raw
        .spans()
        .first()
        .ok_or_else(|| malformed("network", "empty network packet"))?
        .packet;
    let mut d = wire::decode_packet(link, raw.data(), id, scope)?;
    // wire::decode_packet made a temporary single-span view. Rebind its relative
    // offsets through the ORIGINAL evidence (possibly several IP fragments).
    let start = d
        .payload
        .spans()
        .first()
        .map_or(raw.len(), |s| s.packet_start);
    let end = start
        .checked_add(d.payload.len())
        .ok_or_else(|| Error::limit("network_offset"))?;
    d.payload = raw.slice(start..end)?;
    Ok(d)
}
fn arp(b: &[u8]) -> Result<Decoded> {
    need(b, 8, "arp")?;
    let h = usize::from(b[4]);
    let p = usize::from(b[5]);
    if h == 0 || p == 0 || h > 32 || p > 32 {
        return Err(malformed("arp", "unsupported address length"));
    }
    let total = 8 + 2 * (h + p);
    need(b, total, "arp_addresses")?;
    let protocol = u16be(b, 2);
    let ip = |x: &[u8]| -> String {
        if protocol == 0x0800 && x.len() == 4 {
            format!("{}.{}.{}.{}", x[0], x[1], x[2], x[3])
        } else {
            hex(x)
        }
    };
    Ok(Decoded::Metadata {
        protocol: "arp",
        supported: true,
        data: Json::object([
            ("hardware_type", u16be(b, 0).into()),
            ("protocol_type", protocol.into()),
            ("opcode", u16be(b, 6).into()),
            ("sender_hardware", hex(&b[8..8 + h]).into()),
            ("sender_protocol", ip(&b[8 + h..8 + h + p]).into()),
            ("target_hardware", hex(&b[8 + h + p..8 + 2 * h + p]).into()),
            ("target_protocol", ip(&b[8 + 2 * h + p..total]).into()),
        ]),
    })
}
fn mpls(raw: &EvidenceBytes, scope: Scope) -> Result<Decoded> {
    let b = raw.data();
    let mut labels = Vec::new();
    let mut p = 0;
    loop {
        if labels.len() >= 16 {
            return Err(Error::limit("mpls_depth"));
        }
        need(b, p + 4, "mpls")?;
        let word = u32be(b, p);
        p += 4;
        labels.push(word >> 12);
        if word & 0x100 != 0 {
            break;
        }
    }
    need(b, p + 1, "mpls_payload")?;
    let link = match b[p] >> 4 {
        4 => 228,
        6 => 229,
        _ => {
            return Ok(Decoded::Metadata {
                protocol: "mpls",
                supported: false,
                data: Json::object([
                    ("reason", "non_ip_or_pseudowire_payload_not_decoded".into()),
                    ("labels", Json::array(labels.into_iter().map(Json::from))),
                ]),
            })
        }
    };
    let path = format!("mpls:{labels:?}");
    Ok(Decoded::Ip(
        decode_ip(link, &raw.slice(p..raw.len())?, scope)?,
        vec![path],
    ))
}
fn wireless(link: u32, raw: &EvidenceBytes, scope: Scope) -> Result<Decoded> {
    let b = raw.data();
    let mut start = 0usize;
    let mut end = b.len();
    let mut flags = 0u8;
    if link == 127 {
        need(b, 8, "radiotap")?;
        if b[0] != 0 {
            return Err(malformed("radiotap", "unsupported version"));
        }
        start = usize::from(u16::from_le_bytes([b[2], b[3]]));
        if start < 8 {
            return Err(malformed("radiotap", "invalid header length"));
        }
        need(b, start, "radiotap")?;
        let present = u32::from_le_bytes([b[4], b[5], b[6], b[7]]);
        let mut at = 4;
        let mut word = present;
        let mut words = 0;
        loop {
            words += 1;
            if words > 16 {
                return Err(Error::limit("radiotap_present_words"));
            }
            at += 4;
            if word & 0x8000_0000 == 0 {
                break;
            }
            need(&b[..start], at + 4, "radiotap_present")?;
            word = u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]]);
        }
        if present & 1 != 0 {
            at = (at + 7) & !7;
            need(&b[..start], at + 8, "radiotap_tsft")?;
            at += 8;
        }
        if present & 2 != 0 {
            need(&b[..start], at + 1, "radiotap_flags")?;
            flags = b[at];
        }
        if flags & 0x10 != 0 {
            end = end
                .checked_sub(4)
                .ok_or_else(|| malformed("radiotap", "missing FCS"))?;
        }
        if start > end {
            return Err(malformed("radiotap", "FCS overlaps radiotap header"));
        }
    }
    need(&b[..end], start + 24, "80211")?;
    let fc = u16::from_le_bytes([b[start], b[start + 1]]);
    let subtype = (fc >> 4) & 15;
    let typ = (fc >> 2) & 3;
    let unsupported = |reason: &'static str| {
        Ok(Decoded::Metadata {
            protocol: "802.11",
            supported: false,
            data: Json::object([
                ("reason", reason.into()),
                ("frame_control", fc.into()),
                ("radiotap_length", start.into()),
            ]),
        })
    };
    if fc & 3 != 0 || typ != 2 || subtype & 4 != 0 {
        return unsupported("non_data_or_null_frame");
    }
    if fc & 0x4000 != 0 {
        return unsupported("encrypted_80211_not_decrypted");
    }
    if flags & 0x40 != 0 {
        return unsupported("radiotap_reports_bad_fcs");
    }
    if fc & 0x0400 != 0 || b[start + 22] & 15 != 0 {
        return unsupported("80211_fragmentation_not_reassembled");
    }
    let both = fc & 0x0300 == 0x0300;
    let mut length = 24 + usize::from(both) * 6;
    if subtype & 8 != 0 {
        need(&b[..end], start + length + 2, "80211_qos")?;
        if b[start + length] & 0x80 != 0 {
            return unsupported("amsdu_not_deaggregated");
        }
        length += 2;
        if fc & 0x8000 != 0 {
            length += 4;
        }
    }
    if flags & 0x20 != 0 {
        length = (length + 3) & !3;
    }
    let p = start + length;
    need(&b[..end], p + 8, "80211_llc_snap")?;
    if b[p..p + 3] != [0xaa, 0xaa, 3]
        || ![&[0, 0, 0][..], &[0, 0, 0xf8][..]].contains(&&b[p + 3..p + 6])
    {
        return unsupported("non_snap_payload");
    }
    let ty = u16be(b, p + 6);
    let mut out = ethertype(ty, &raw.slice(p + 8..end)?, scope)?;
    if let Decoded::Ip(_, path) = &mut out {
        // Preserve capture-layer namespace instead of merging all WLAN traffic.
        let bssid = match fc & 0x0300 {
            0 => &b[start + 16..start + 22],
            0x0100 => &b[start + 4..start + 10],
            0x0200 => &b[start + 10..start + 16],
            _ => &b[start + 4..start + 10],
        };
        path.insert(0, format!("wlan:{}", hex(bssid)));
    }
    Ok(out)
}
fn ethertype(ty: u16, raw: &EvidenceBytes, scope: Scope) -> Result<Decoded> {
    match ty {
        0x0800 => Ok(Decoded::Ip(decode_ip(228, raw, scope)?, vec![])),
        0x86dd => Ok(Decoded::Ip(decode_ip(229, raw, scope)?, vec![])),
        0x6558 => decode(1, raw, scope),
        0x8847 | 0x8848 => mpls(raw, scope),
        0x0806 => arp(raw.data()),
        _ => Ok(Decoded::Metadata {
            protocol: "ethernet",
            supported: false,
            data: Json::object([
                ("reason", "unsupported_inner_ethertype".into()),
                ("ethertype", ty.into()),
            ]),
        }),
    }
}
/// Reassembled IPv6 payload can still contain post-fragment extension headers.
pub fn normalize(mut d: Datagram) -> Result<Datagram> {
    if d.fragment.is_some() {
        return Err(malformed("network", "normalize only after reassembly"));
    }
    if !d.ipv6 {
        return Ok(d);
    }
    let mut p = 0usize;
    let mut next = d.protocol;
    let b = d.payload.data();
    let mut depth = 0;
    while [0, 43, 51, 60].contains(&next) {
        depth += 1;
        if depth > 16 {
            return Err(Error::limit("ipv6_extension_depth"));
        }
        need(b, p + 2, "ipv6_extension")?;
        let n = if next == 51 {
            (usize::from(b[p + 1]) + 2) * 4
        } else {
            (usize::from(b[p + 1]) + 1) * 8
        };
        need(b, p + n, "ipv6_extension")?;
        next = b[p];
        p += n;
    }
    if next == 44 {
        return Err(malformed("ipv6_fragment", "nested fragment header"));
    }
    d.protocol = next;
    d.payload = d.payload.slice(p..d.payload.len())?;
    d.network_header_len = d
        .network_header_len
        .checked_add(p)
        .ok_or_else(|| Error::limit("network_header"))?;
    Ok(d)
}
/// An optional validated encapsulation. Port hints select VXLAN/Geneve framing;
/// conflicting hints, unknown critical options, GRE routing/version extensions,
/// and encrypted tunnels never authorize inner decoding.
pub fn peel(d: &Datagram) -> Result<Option<(Decoded, String)>> {
    let b = d.payload.data();
    let (ty, start, label) = if d.protocol == 47 {
        need(b, 4, "gre")?;
        let f = u16be(b, 0);
        let ty = u16be(b, 2);
        if f & !0xb000 != 0 {
            return Err(malformed(
                "gre",
                "routing/version/reserved flags not supported",
            ));
        }
        let mut p = 4;
        let mut key = None;
        if f & 0x8000 != 0 {
            need(b, p + 4, "gre_checksum")?;
            if u16be(b, p + 2) != 0 || wire::internet_checksum(b) != 0 {
                return Err(malformed(
                    "gre_checksum",
                    "invalid checksum or reserved field",
                ));
            }
            p += 4;
        }
        if f & 0x2000 != 0 {
            need(b, p + 4, "gre_key")?;
            key = Some(u32be(b, p));
            p += 4;
        }
        if f & 0x1000 != 0 {
            need(b, p + 4, "gre_sequence")?;
            p += 4;
        }
        (ty, p, format!("gre:{key:?}"))
    } else if d.protocol == 17 {
        need(b, 8, "udp_tunnel")?;
        let src = u16be(b, 0);
        let dst = u16be(b, 2);
        let n = usize::from(u16be(b, 4));
        if n < 8 || n > b.len() {
            return Err(malformed("udp_tunnel", "invalid UDP length"));
        }
        let vx = src == 4789 || dst == 4789;
        let ge = src == 6081 || dst == 6081;
        if vx && ge {
            return Err(malformed("udp_tunnel", "ambiguous tunnel hints"));
        }
        if !vx && !ge {
            return Ok(None);
        }
        let t = &b[8..n];
        need(t, 8, "udp_tunnel_header")?;
        let vni = (u32::from(t[4]) << 16) | (u32::from(t[5]) << 8) | u32::from(t[6]);
        if vx {
            if t[0] != 8 || t[1..4] != [0, 0, 0] || t[7] != 0 {
                return Err(malformed("vxlan", "unsupported flags/reserved bits"));
            }
            // Honor UDP length rather than accidentally decoding trailing IP bytes.
            return Ok(Some((
                ethertype(0x6558, &d.payload.slice(16..n)?, d.scope.clone())?,
                tunnel_key(d, &format!("vxlan:{vni}")),
            )));
        }
        if t[0] >> 6 != 0 || t[1] & 0x3f != 0 || t[7] != 0 {
            return Err(malformed("geneve", "unsupported version/reserved bits"));
        }
        let options = usize::from(t[0] & 0x3f) * 4;
        need(t, 8 + options, "geneve_options")?;
        let mut p = 8;
        let mut critical = false;
        while p < 8 + options {
            need(&t[..8 + options], p + 4, "geneve_option")?;
            if t[p + 3] & 0xe0 != 0 {
                return Err(malformed("geneve_option", "reserved option bits"));
            }
            critical |= t[p + 2] & 0x80 != 0;
            let size = 4 + usize::from(t[p + 3] & 31) * 4;
            need(&t[..8 + options], p + size, "geneve_option")?;
            p += size;
        }
        if critical || t[1] & 0x40 != 0 {
            return Err(malformed(
                "geneve",
                "unknown critical option not interpreted",
            ));
        }
        if t[1] & 0x80 != 0 {
            return Err(malformed(
                "geneve",
                "OAM payload not treated as user traffic",
            ));
        }
        return Ok(Some((
            ethertype(
                u16be(t, 2),
                &d.payload.slice(16 + options..n)?,
                d.scope.clone(),
            )?,
            tunnel_key(d, &format!("geneve:{vni}")),
        )));
    } else {
        return Ok(None);
    };
    Ok(Some((
        ethertype(
            ty,
            &d.payload.slice(start..d.payload.len())?,
            d.scope.clone(),
        )?,
        tunnel_key(d, &label),
    )))
}
fn tunnel_key(d: &Datagram, label: &str) -> String {
    let (a, b) = if d.source <= d.destination {
        (d.source, d.destination)
    } else {
        (d.destination, d.source)
    };
    format!("{label}@{a},{b}")
}
/// ICMP and SCTP metadata, not ICMP sessions or SCTP association reassembly.
pub fn transport_metadata(d: &Datagram) -> Result<Option<(&'static str, Json)>> {
    let b = d.payload.data();
    match d.protocol {
        1 | 58 => {
            need(b, 4, "icmp")?;
            let valid = if d.protocol == 1 {
                wire::internet_checksum(b) == 0
            } else {
                let mut c = pcap_evidence::checksum::InternetChecksum::new();
                match (d.source, d.destination) {
                    (IpAddr::V6(a), IpAddr::V6(z)) => {
                        c.update(&a.octets());
                        c.update(&z.octets());
                    }
                    _ => return Err(malformed("icmpv6", "wrong address family")),
                }
                c.update(&(b.len() as u32).to_be_bytes());
                c.update(&[0, 0, 0, 58]);
                c.update(b);
                c.finish() == 0
            };
            let echo = if (d.protocol == 1 && [0, 8].contains(&b[0]))
                || (d.protocol == 58 && [128, 129].contains(&b[0]))
            {
                need(b, 8, "icmp_echo")?;
                Json::object([
                    ("identifier", u16be(b, 4).into()),
                    ("sequence", u16be(b, 6).into()),
                ])
            } else {
                Json::Null
            };
            Ok(Some((
                if d.protocol == 1 { "icmp" } else { "icmpv6" },
                Json::object([
                    ("type", b[0].into()),
                    ("code", b[1].into()),
                    ("checksum_valid", valid.into()),
                    ("echo", echo),
                ]),
            )))
        }
        132 => {
            need(b, 12, "sctp")?;
            let mut p = 12;
            let mut chunks = Vec::new();
            while p < b.len() {
                if chunks.len() >= 256 {
                    return Err(Error::limit("sctp_chunks"));
                }
                need(b, p + 4, "sctp_chunk")?;
                let n = usize::from(u16be(b, p + 2));
                if n < 4 {
                    return Err(malformed("sctp_chunk", "length smaller than header"));
                }
                need(b, p + n, "sctp_chunk")?;
                let data = if b[p] == 0 {
                    if n < 16 {
                        return Err(malformed("sctp_data", "truncated DATA chunk"));
                    }
                    Json::object([
                        ("tsn", u32be(b, p + 4).into()),
                        ("stream_id", u16be(b, p + 8).into()),
                        ("stream_sequence", u16be(b, p + 10).into()),
                        ("ppid", u32be(b, p + 12).into()),
                    ])
                } else {
                    Json::Null
                };
                chunks.push(Json::object([
                    ("type", b[p].into()),
                    ("flags", b[p + 1].into()),
                    ("length", n.into()),
                    ("data_header", data),
                ]));
                p += (n + 3) & !3;
                need(b, p, "sctp_padding")?;
            }
            let actual = u32::from_le_bytes([b[8], b[9], b[10], b[11]]);
            let mut crc = !0u32;
            for (i, &x) in b.iter().enumerate() {
                crc ^= u32::from(if (8..12).contains(&i) { 0 } else { x });
                for _ in 0..8 {
                    crc = if crc & 1 != 0 {
                        (crc >> 1) ^ 0x82f6_3b78
                    } else {
                        crc >> 1
                    };
                }
            }
            Ok(Some((
                "sctp",
                Json::object([
                    ("source_port", u16be(b, 0).into()),
                    ("destination_port", u16be(b, 2).into()),
                    ("verification_tag", u32be(b, 4).into()),
                    ("crc32c_valid", (!crc == actual).into()),
                    ("chunks", Json::Array(chunks)),
                    ("association_reassembly", "not_implemented".into()),
                ]),
            )))
        }
        _ => Ok(None),
    }
}
