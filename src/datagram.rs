//! Datagram-local DNP3 analysis. Each invocation has fresh reconstruction state.
//! No UDP ordering, reliability, connection generation, or cross-datagram
//! transaction identity is invented. Multi-datagram fragments remain incomplete.
use crate::dnp3::{self, Dnp3Result};
use crate::provenance::{EvidenceBytes, PacketId};
use crate::tcp::{StreamChunk, StreamResult};
use crate::wire::{Scope, UdpDatagram};
use crate::{Error, ErrorCode, Limits, Result};

#[derive(Clone, Debug)]
pub struct DatagramAnalysis {
    pub scope: Scope,
    pub source: crate::wire::Endpoint,
    pub destination: crate::wire::Endpoint,
    pub packets: Vec<PacketId>,
    pub payload: EvidenceBytes,
    pub data: Result<Dnp3Result>,
}

pub fn decode_dnp3_datagram(bytes: &EvidenceBytes, limits: &Limits) -> Result<Dnp3Result> {
    limits.validate()?;
    if bytes.len() > limits.max_application_bytes {
        return Err(Error::limit("dnp3_datagram_bytes"));
    }
    if !bytes.validate() {
        return Err(Error::new(
            ErrorCode::Invariant,
            0,
            "provenance",
            "invalid datagram source spans",
        ));
    }
    let stream = StreamResult {
        base_sequence: None,
        anchored_by_syn: false,
        chunks: if bytes.is_empty() {
            Vec::new()
        } else {
            vec![StreamChunk {
                offset: 0,
                bytes: bytes.clone(),
            }]
        },
        gaps: Vec::new(),
        conflicts: Vec::new(),
        duplicate_observed_bytes: 0,
    };
    dnp3::decode(&stream, limits)
}

/// Configured-port selection only. A successful result can contain incomplete
/// fragments/issues; that fact must be preserved by every downstream report.
pub fn analyze_udp(
    scope: &Scope,
    datagram: &UdpDatagram,
    contributors: &[PacketId],
    dnp3_ports: &[u16],
    limits: &Limits,
) -> Result<Option<DatagramAnalysis>> {
    limits.validate()?;
    if !dnp3_ports.contains(&datagram.source.port)
        && !dnp3_ports.contains(&datagram.destination.port)
    {
        return Ok(None);
    }
    if datagram.payload.is_empty() {
        return Ok(None);
    }
    if contributors.is_empty() {
        return Err(Error::new(
            ErrorCode::Invariant,
            0,
            "udp_evidence",
            "source contributors are required",
        ));
    }
    // IP fragmentation may introduce several contributors to one UDP datagram.
    let mut packets = contributors.to_vec();
    packets.extend(datagram.payload.packets());
    packets.sort();
    packets.dedup();
    Ok(Some(DatagramAnalysis {
        scope: scope.clone(),
        source: datagram.source,
        destination: datagram.destination,
        packets,
        payload: datagram.payload.clone(),
        data: decode_dnp3_datagram(&datagram.payload, limits),
    }))
}
