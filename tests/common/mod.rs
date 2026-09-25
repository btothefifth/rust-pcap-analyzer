#![allow(dead_code)]
use pcap_evidence::provenance::{EvidenceBytes, PacketId};
use pcap_evidence::tcp::{OverlapPolicy, StreamAssembler, StreamResult};
use pcap_evidence::wire::{Checksum, Endpoint, Scope, TcpSegment};
use pcap_evidence::Limits;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
pub fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(name),
    )
    .unwrap()
}
pub fn id(frame: u64) -> PacketId {
    PacketId {
        capture: [7; 32],
        frame,
        record_offset: frame * 100,
    }
}
pub fn evidence(data: &[u8], frame: u64) -> EvidenceBytes {
    EvidenceBytes::from_packet(data, id(frame), 54)
}
pub fn scope() -> Scope {
    Scope {
        section: 0,
        interface: 0,
        vlans: vec![],
    }
}
pub fn endpoint(ip: &str, port: u16) -> Endpoint {
    Endpoint {
        address: ip.parse().unwrap(),
        port,
    }
}
pub fn segment(seq: u32, ack: u32, flags: u8, data: &[u8], frame: u64) -> TcpSegment {
    TcpSegment {
        source: endpoint("10.0.0.1", 40000),
        destination: endpoint("10.0.0.2", 20000),
        sequence: seq,
        acknowledgement: ack,
        flags,
        checksum: Checksum::Valid,
        payload: evidence(data, frame),
    }
}
pub fn stream(data: &[u8]) -> StreamResult {
    let mut s = StreamAssembler::new(Some(1000), Limits::default());
    s.push(1001, evidence(data, 1)).unwrap();
    s.finish(OverlapPolicy::RejectConflict).unwrap()
}
static SERIAL: AtomicU64 = AtomicU64::new(0);
pub struct Temp(pub PathBuf);
impl Temp {
    pub fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "pcap-evidence-test-{}-{}",
            std::process::id(),
            SERIAL.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
