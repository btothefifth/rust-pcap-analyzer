//! Link/network/transport parsing. Never assumes every link type is Ethernet.
use crate::error::require;
use crate::provenance::{EvidenceBytes, PacketId};
use crate::{Error, ErrorCode, Result};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Scope {
    pub section: u32,
    pub interface: u32,
    pub vlans: Vec<u16>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Endpoint {
    pub address: IpAddr,
    pub port: u16,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Checksum {
    Valid,
    Invalid,
    NotPresent,
    NotChecked,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChecksumPolicy {
    Observe,
    RequireValid,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FragmentInfo {
    pub id: u32,
    pub offset: usize,
    pub more: bool,
}
#[derive(Clone, Debug)]
pub struct Datagram {
    pub scope: Scope,
    pub source: IpAddr,
    pub destination: IpAddr,
    pub protocol: u8,
    pub ipv6: bool,
    pub network_header_len: usize,
    pub fragment: Option<FragmentInfo>,
    pub payload: EvidenceBytes,
    pub ip_checksum: Checksum,
}
#[derive(Clone, Debug)]
pub struct TcpSegment {
    pub source: Endpoint,
    pub destination: Endpoint,
    pub sequence: u32,
    pub acknowledgement: u32,
    pub flags: u8,
    pub checksum: Checksum,
    pub payload: EvidenceBytes,
}
impl TcpSegment {
    pub fn syn(&self) -> bool {
        self.flags & 0x02 != 0
    }
    pub fn ack(&self) -> bool {
        self.flags & 0x10 != 0
    }
    pub fn fin(&self) -> bool {
        self.flags & 0x01 != 0
    }
    pub fn rst(&self) -> bool {
        self.flags & 0x04 != 0
    }
    pub fn data_sequence(&self) -> u32 {
        self.sequence.wrapping_add(u32::from(self.syn()))
    }
}
#[derive(Clone, Debug)]
pub struct UdpDatagram {
    pub source: Endpoint,
    pub destination: Endpoint,
    pub checksum: Checksum,
    pub payload: EvidenceBytes,
}
#[derive(Clone, Debug)]
pub enum Transport {
    Tcp(TcpSegment),
    Udp(UdpDatagram),
}

fn be16(b: &[u8]) -> u16 {
    u16::from_be_bytes([b[0], b[1]])
}
fn be32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}
fn bad(field: &'static str, detail: &str) -> Error {
    Error::new(ErrorCode::MalformedPacket, 0, field, detail)
}

pub fn decode_packet(
    link_type: u32,
    packet: &[u8],
    id: PacketId,
    mut scope: Scope,
) -> Result<Datagram> {
    let (mut start, mut ether_type) = match link_type {
        1 => {
            require(packet, 14, id.record_offset, "ethernet")?;
            (14, be16(&packet[12..14]))
        }
        113 => {
            require(packet, 16, id.record_offset, "linux_sll")?;
            (16, be16(&packet[14..16]))
        }
        276 => {
            require(packet, 20, id.record_offset, "linux_sll2")?;
            (20, be16(&packet[..2]))
        }
        101 => {
            require(packet, 1, id.record_offset, "raw_ip")?;
            (
                0,
                if packet[0] >> 4 == 4 {
                    0x0800
                } else if packet[0] >> 4 == 6 {
                    0x86dd
                } else {
                    return Err(bad("raw_ip", "unknown version"));
                },
            )
        }
        228 => (0, 0x0800),
        229 => (0, 0x86dd),
        0 | 108 => {
            require(packet, 4, id.record_offset, "loopback")?;
            let network = be32(&packet[..4]);
            let host = u32::from_le_bytes([packet[0], packet[1], packet[2], packet[3]]);
            // DLT_NULL records the originating host's family in native order;
            // DLT_LOOP uses network order. Recognized families are disjoint here.
            let family = if link_type == 108 || [2, 10, 24, 28, 30].contains(&network) {
                network
            } else {
                host
            };
            (
                4,
                match family {
                    2 => 0x0800,
                    10 | 24 | 28 | 30 => 0x86dd,
                    _ => return Err(bad("loopback", "unsupported address family")),
                },
            )
        }
        _ => {
            return Err(Error::new(
                ErrorCode::UnsupportedLink,
                id.record_offset,
                "link_type",
                format!("LINKTYPE {link_type} has no decoder"),
            ))
        }
    };
    while ether_type == 0x8100 || ether_type == 0x88a8 || ether_type == 0x9100 {
        if scope.vlans.len() >= 8 {
            return Err(Error::limit("vlan_depth"));
        }
        require(packet, start + 4, id.record_offset, "vlan")?;
        scope.vlans.push(be16(&packet[start..start + 2]) & 0x0fff);
        ether_type = be16(&packet[start + 2..start + 4]);
        start += 4;
    }
    match ether_type {
        0x0800 => ipv4(packet, start, id, scope),
        0x86dd => ipv6(packet, start, id, scope),
        _ => Err(Error::new(
            ErrorCode::UnsupportedNetwork,
            id.record_offset + start as u64,
            "ether_type",
            format!("0x{ether_type:04x}"),
        )),
    }
}

fn ipv4(packet: &[u8], start: usize, id: PacketId, scope: Scope) -> Result<Datagram> {
    require(packet, start + 20, id.record_offset, "ipv4")?;
    let b = &packet[start..];
    if b[0] >> 4 != 4 {
        return Err(bad("ipv4", "version mismatch"));
    }
    let header = usize::from(b[0] & 15) * 4;
    if header < 20 {
        return Err(bad("ipv4_ihl", "header shorter than 20 bytes"));
    }
    require(b, header, id.record_offset + start as u64, "ipv4_options")?;
    let total = usize::from(be16(&b[2..4]));
    if total < header {
        return Err(bad("ipv4_total_length", "length smaller than header"));
    }
    require(b, total, id.record_offset + start as u64, "ipv4_payload")?;
    let flags = be16(&b[6..8]);
    let off = usize::from(flags & 0x1fff) * 8;
    let more = flags & 0x2000 != 0;
    if flags & 0x8000 != 0 {
        return Err(bad("ipv4_flags", "reserved flag set"));
    }
    if more && (total - header) % 8 != 0 {
        return Err(bad(
            "ipv4_fragment",
            "non-final fragment length not a multiple of 8",
        ));
    }
    if (more || off != 0) && total == header {
        return Err(bad("ipv4_fragment", "empty fragment"));
    }
    if off.checked_add(total - header).is_none_or(|n| n > 65_535) {
        return Err(bad("ipv4_fragment", "fragment range too large"));
    }
    let source = IpAddr::V4(Ipv4Addr::new(b[12], b[13], b[14], b[15]));
    let destination = IpAddr::V4(Ipv4Addr::new(b[16], b[17], b[18], b[19]));
    Ok(Datagram {
        scope,
        source,
        destination,
        protocol: b[9],
        ipv6: false,
        network_header_len: header,
        fragment: if more || off != 0 {
            Some(FragmentInfo {
                id: u32::from(be16(&b[4..6])),
                offset: off,
                more,
            })
        } else {
            None
        },
        payload: EvidenceBytes::from_packet(&b[header..total], id, start + header),
        ip_checksum: if internet_checksum(&b[..header]) == 0 {
            Checksum::Valid
        } else {
            Checksum::Invalid
        },
    })
}
fn ipv6(packet: &[u8], start: usize, id: PacketId, scope: Scope) -> Result<Datagram> {
    require(packet, start + 40, id.record_offset, "ipv6")?;
    let b = &packet[start..];
    if b[0] >> 4 != 6 {
        return Err(bad("ipv6", "version mismatch"));
    }
    let n = usize::from(be16(&b[4..6]));
    if n == 0 && b[6] == 0 && b.len() > 40 {
        return Err(Error::new(
            ErrorCode::UnsupportedNetwork,
            id.record_offset,
            "ipv6_jumbo",
            "jumbogram semantics are not implemented",
        ));
    }
    let total = 40 + n;
    require(b, total, id.record_offset + start as u64, "ipv6_payload")?;
    let mut s = [0u8; 16];
    let mut d = [0u8; 16];
    s.copy_from_slice(&b[8..24]);
    d.copy_from_slice(&b[24..40]);
    let mut next = b[6];
    let mut p = 40;
    let mut fragment = None;
    let mut depth = 0;
    while [0, 43, 44, 51, 60].contains(&next) {
        depth += 1;
        if depth > 16 {
            return Err(Error::limit("ipv6_extension_depth"));
        }
        require(
            &b[..total],
            p + 2,
            id.record_offset + start as u64,
            "ipv6_extension",
        )?;
        if next == 44 {
            require(
                &b[..total],
                p + 8,
                id.record_offset + start as u64,
                "ipv6_fragment",
            )?;
            let bits = be16(&b[p + 2..p + 4]);
            if bits & 0x0006 != 0 || b[p + 1] != 0 {
                return Err(bad("ipv6_fragment", "reserved bits set"));
            }
            let off = usize::from(bits & 0xfff8);
            let more = bits & 1 != 0;
            let frag_id = be32(&b[p + 4..p + 8]);
            next = b[p];
            p += 8;
            if more && (total - p) % 8 != 0 {
                return Err(bad(
                    "ipv6_fragment",
                    "non-final fragment length not a multiple of 8",
                ));
            }
            // Atomic fragments are passed through rather than combined with other traffic.
            if more || off != 0 {
                if total == p {
                    return Err(bad("ipv6_fragment", "empty fragment"));
                }
                fragment = Some(FragmentInfo {
                    id: frag_id,
                    offset: off,
                    more,
                });
                break;
            }
            continue;
        }
        let ext = if next == 51 {
            (usize::from(b[p + 1]) + 2) * 4
        } else {
            (usize::from(b[p + 1]) + 1) * 8
        };
        require(
            &b[..total],
            p + ext,
            id.record_offset + start as u64,
            "ipv6_extension_length",
        )?;
        next = b[p];
        p += ext;
    }
    Ok(Datagram {
        scope,
        source: IpAddr::V6(Ipv6Addr::from(s)),
        destination: IpAddr::V6(Ipv6Addr::from(d)),
        protocol: next,
        ipv6: true,
        network_header_len: p,
        fragment,
        payload: EvidenceBytes::from_packet(&b[p..total], id, start + p),
        ip_checksum: Checksum::NotPresent,
    })
}

pub fn decode_transport(datagram: &Datagram, policy: ChecksumPolicy) -> Result<Transport> {
    if datagram.fragment.is_some() {
        return Err(bad(
            "fragment",
            "reassemble IP fragments before parsing transport",
        ));
    }
    if policy == ChecksumPolicy::RequireValid && datagram.ip_checksum == Checksum::Invalid {
        return Err(Error::new(
            ErrorCode::Checksum,
            0,
            "ipv4",
            "invalid IPv4 checksum",
        ));
    }
    let mut protocol = datagram.protocol;
    let mut prefix = 0;
    let all = datagram.payload.data();
    let mut depth = 0;
    // Fragmentable IPv6 extension headers can follow the Fragment header.
    while datagram.ipv6 && [0, 43, 51, 60].contains(&protocol) {
        depth += 1;
        if depth > 16 {
            return Err(Error::limit("ipv6_extension_depth"));
        }
        require(all, prefix + 2, 0, "ipv6_post_fragment_extension")?;
        let n = if protocol == 51 {
            (usize::from(all[prefix + 1]) + 2) * 4
        } else {
            (usize::from(all[prefix + 1]) + 1) * 8
        };
        require(all, prefix + n, 0, "ipv6_post_fragment_extension")?;
        protocol = all[prefix];
        prefix += n;
    }
    let data = &all[prefix..];
    match protocol {
        6 => {
            require(data, 20, 0, "tcp")?;
            let header = usize::from(data[12] >> 4) * 4;
            if header < 20 {
                return Err(bad("tcp_offset", "data offset smaller than fixed header"));
            }
            require(data, header, 0, "tcp_options")?;
            let checksum = transport_checksum(datagram.source, datagram.destination, 6, data)?;
            if policy == ChecksumPolicy::RequireValid && checksum != Checksum::Valid {
                return Err(Error::new(
                    ErrorCode::Checksum,
                    0,
                    "tcp",
                    "invalid checksum; capture offload may be relevant",
                ));
            }
            Ok(Transport::Tcp(TcpSegment {
                source: Endpoint {
                    address: datagram.source,
                    port: be16(&data[..2]),
                },
                destination: Endpoint {
                    address: datagram.destination,
                    port: be16(&data[2..4]),
                },
                sequence: be32(&data[4..8]),
                acknowledgement: be32(&data[8..12]),
                flags: data[13],
                checksum,
                payload: datagram.payload.slice(prefix + header..all.len())?,
            }))
        }
        17 => {
            require(data, 8, 0, "udp")?;
            let len = usize::from(be16(&data[4..6]));
            if len < 8 {
                return Err(bad(
                    "udp_length",
                    "UDP length smaller than header or unsupported jumbogram",
                ));
            }
            require(data, len, 0, "udp_payload")?;
            let checksum = if be16(&data[6..8]) == 0 {
                if datagram.ipv6 {
                    Checksum::Invalid
                } else {
                    Checksum::NotPresent
                }
            } else {
                transport_checksum(datagram.source, datagram.destination, 17, &data[..len])?
            };
            if policy == ChecksumPolicy::RequireValid && checksum == Checksum::Invalid {
                return Err(Error::new(
                    ErrorCode::Checksum,
                    0,
                    "udp",
                    "invalid UDP checksum",
                ));
            }
            Ok(Transport::Udp(UdpDatagram {
                source: Endpoint {
                    address: datagram.source,
                    port: be16(&data[..2]),
                },
                destination: Endpoint {
                    address: datagram.destination,
                    port: be16(&data[2..4]),
                },
                checksum,
                payload: datagram.payload.slice(prefix + 8..prefix + len)?,
            }))
        }
        _ => Err(Error::new(
            ErrorCode::UnsupportedTransport,
            0,
            "ip_protocol",
            format!("protocol {protocol} is not decoded"),
        )),
    }
}

pub fn internet_checksum(data: &[u8]) -> u16 {
    let mut checksum = crate::checksum::InternetChecksum::new();
    checksum.update(data);
    checksum.finish()
}
fn transport_checksum(src: IpAddr, dst: IpAddr, protocol: u8, bytes: &[u8]) -> Result<Checksum> {
    let mut checksum = crate::checksum::InternetChecksum::new();
    match (src, dst) {
        (IpAddr::V4(a), IpAddr::V4(b)) => {
            let len = u16::try_from(bytes.len())
                .map_err(|_| bad("transport_length", "IPv4 transport exceeds 65535"))?;
            checksum.update(&a.octets());
            checksum.update(&b.octets());
            checksum.update(&[0, protocol]);
            checksum.update(&len.to_be_bytes());
        }
        (IpAddr::V6(a), IpAddr::V6(b)) => {
            let len = u32::try_from(bytes.len())
                .map_err(|_| bad("transport_length", "IPv6 transport too large"))?;
            checksum.update(&a.octets());
            checksum.update(&b.octets());
            checksum.update(&len.to_be_bytes());
            checksum.update(&[0, 0, 0, protocol]);
        }
        _ => {
            return Err(bad(
                "address_family",
                "mixed source/destination address families",
            ))
        }
    }
    checksum.update(bytes);
    Ok(if checksum.finish() == 0 {
        Checksum::Valid
    } else {
        Checksum::Invalid
    })
}
