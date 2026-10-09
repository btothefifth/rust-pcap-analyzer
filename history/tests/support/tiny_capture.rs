//! Small generated packet witnesses shared by history regression consumers.
#![allow(dead_code)]
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT: AtomicU64 = AtomicU64::new(0);
pub struct Temp(pub PathBuf);
impl Temp {
    pub fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "pcap-history-feedback-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    pub fn source(&self, packets: &[Vec<u8>]) -> PathBuf {
        let path = self.0.join("source.pcap");
        fs::write(&path, capture(packets)).unwrap();
        path
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
pub fn capture(packets: &[Vec<u8>]) -> Vec<u8> {
    let mut bytes = vec![0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0];
    bytes.extend_from_slice(&[0; 8]);
    bytes.extend_from_slice(&65535u32.to_le_bytes());
    bytes.extend_from_slice(&1u32.to_le_bytes());
    for (i, packet) in packets.iter().enumerate() {
        bytes.extend_from_slice(&(i as u32 + 1).to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&(packet.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&(packet.len() as u32).to_le_bytes());
        bytes.extend_from_slice(packet);
    }
    bytes
}
pub fn sll2(interface: u32, ethernet_packet: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0x08, 0, 0, 0];
    bytes.extend_from_slice(&interface.to_be_bytes());
    bytes.extend_from_slice(&[0, 1, 0, 6]);
    bytes.extend_from_slice(&[0; 8]);
    bytes.extend_from_slice(&ethernet_packet[14..]);
    bytes
}
pub fn routed_ipv4(ethernet_packet: &[u8]) -> Vec<u8> {
    let original = &ethernet_packet[14..];
    let mut ip = original[..20].to_vec();
    ip[0] = 0x47;
    ip[2..4].copy_from_slice(&u16::try_from(original.len() + 8).unwrap().to_be_bytes());
    ip[10..12].fill(0);
    // LSRR changes the pseudo-header destination; no final-operand inference.
    ip.extend_from_slice(&[131, 7, 4, 198, 51, 100, 9, 0]);
    let sum = checksum(&ip);
    ip[10..12].copy_from_slice(&sum.to_be_bytes());
    ip.extend_from_slice(&original[20..]);
    ethernet(&ip)
}
fn checksum(bytes: &[u8]) -> u16 {
    let sum = bytes.chunks(2).fold(0u32, |sum, pair| {
        sum + ((u32::from(pair[0]) << 8) | pair.get(1).copied().map_or(0, u32::from))
    });
    let folded = (sum & 0xffff) + (sum >> 16);
    !((folded & 0xffff) + (folded >> 16)) as u16
}
fn ipv4(source: [u8; 4], destination: [u8; 4], protocol: u8, payload: &[u8]) -> Vec<u8> {
    let mut header = vec![0x45, 0];
    header.extend_from_slice(&u16::try_from(20 + payload.len()).unwrap().to_be_bytes());
    header.extend_from_slice(&[0, 0, 0, 0, 64, protocol, 0, 0]);
    header.extend_from_slice(&source);
    header.extend_from_slice(&destination);
    let sum = checksum(&header);
    header[10..12].copy_from_slice(&sum.to_be_bytes());
    header.extend_from_slice(payload);
    header
}
fn ethernet(payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0; 12];
    bytes.extend_from_slice(&0x0800u16.to_be_bytes());
    bytes.extend_from_slice(payload);
    bytes
}
pub fn tcp(
    reverse: bool,
    sequence: u32,
    acknowledgment: u32,
    flags: u8,
    payload: &[u8],
) -> Vec<u8> {
    let (source, destination, a, b) = if reverse {
        ([10, 0, 0, 2], [10, 0, 0, 1], 2000u16, 1000u16)
    } else {
        ([10, 0, 0, 1], [10, 0, 0, 2], 1000u16, 2000u16)
    };
    let mut segment = Vec::new();
    segment.extend_from_slice(&a.to_be_bytes());
    segment.extend_from_slice(&b.to_be_bytes());
    segment.extend_from_slice(&sequence.to_be_bytes());
    segment.extend_from_slice(&acknowledgment.to_be_bytes());
    segment.extend_from_slice(&[0x50, flags, 0x20, 0, 0, 0, 0, 0]);
    segment.extend_from_slice(payload);
    let mut pseudo = Vec::from(source);
    pseudo.extend_from_slice(&destination);
    pseudo.extend_from_slice(&[0, 6]);
    pseudo.extend_from_slice(&(segment.len() as u16).to_be_bytes());
    pseudo.extend_from_slice(&segment);
    let sum = checksum(&pseudo);
    segment[16..18].copy_from_slice(&sum.to_be_bytes());
    ethernet(&ipv4(source, destination, 6, &segment))
}
pub fn tunneled(kind: &str, identity: u32, reverse: bool, inner: &[u8]) -> Vec<u8> {
    let (source, destination) = if reverse {
        ([192, 0, 2, 2], [192, 0, 2, 1])
    } else {
        ([192, 0, 2, 1], [192, 0, 2, 2])
    };
    if kind == "gre" {
        let mut payload = Vec::from([0x20, 0, 0x08, 0]);
        payload.extend_from_slice(&identity.to_be_bytes());
        payload.extend_from_slice(&inner[14..]);
        return ethernet(&ipv4(source, destination, 47, &payload));
    }
    let port = if kind == "vxlan" { 4789u16 } else { 6081u16 };
    let mut payload = Vec::new();
    for p in if reverse {
        [port, 40000]
    } else {
        [40000, port]
    } {
        payload.extend_from_slice(&p.to_be_bytes());
    }
    payload.extend_from_slice(&(16u16 + inner.len() as u16).to_be_bytes());
    payload.extend_from_slice(&[0, 0]); // IPv4 UDP checksum absent, not invented.
    payload.extend_from_slice(if kind == "vxlan" {
        &[8, 0, 0, 0]
    } else {
        &[0, 0, 0x65, 0x58]
    });
    payload.extend_from_slice(&identity.to_be_bytes()[1..]);
    payload.push(0);
    payload.extend_from_slice(inner);
    ethernet(&ipv4(source, destination, 17, &payload))
}
