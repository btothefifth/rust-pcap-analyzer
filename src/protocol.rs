//! Bounded, advisory protocol probes. A structural match is NOT a dispatch rule,
//! authenticated identity, calibrated probability, or authorization to correlate.
//!
//! Callers explicitly supply a contiguous prefix. Never concatenate across TCP
//! gaps or UDP datagrams to obtain a match. The engine's configured-port policy
//! is selected by detection.rs: all content matches are retained; configured
//! ports are an explicitly reported compatibility fallback, not authentication.
use crate::dnp3::crc16_dnp;
use crate::{Error, ErrorCode, Result};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProbeTransport {
    Tcp,
    Udp,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProbeStrength {
    /// Header layout only. Other protocols and random input can match.
    HeaderStructure,
    /// A complete frame with every link CRC checked; still not authentication.
    CompleteFrameChecksums,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProbeResult {
    NoMatch,
    /// Number of contiguous bytes required from the start, not bytes to append.
    NeedMore {
        minimum_total: usize,
    },
    Match {
        protocol: &'static str,
        strength: ProbeStrength,
        examined_bytes: usize,
        reason: &'static str,
    },
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProbeObservation {
    pub probe: &'static str,
    pub result: ProbeResult,
}
pub struct ProbeInput<'a> {
    pub transport: ProbeTransport,
    pub source_port: u16,
    pub destination_port: u16,
    pub prefix: &'a [u8],
}

/// Extension boundary for independent, read-only probes. Implementations must
/// inspect only the supplied prefix and not perform network or filesystem I/O.
/// In-process third-party code is trusted code, not sandboxed by this trait.
pub trait ProtocolProbe: Send + Sync {
    fn name(&self) -> &'static str;
    fn probe(&self, input: &ProbeInput<'_>) -> ProbeResult;
}

pub struct ProbeRegistry {
    probes: Vec<Box<dyn ProtocolProbe>>,
    max_probes: usize,
    max_prefix_bytes: usize,
}
impl ProbeRegistry {
    pub fn new(max_probes: usize, max_prefix_bytes: usize) -> Result<Self> {
        if max_probes == 0 || max_prefix_bytes == 0 {
            return Err(Error::new(
                ErrorCode::Usage,
                0,
                "protocol_probe_limits",
                "limits must be positive",
            ));
        }
        Ok(Self {
            probes: Vec::new(),
            max_probes,
            max_prefix_bytes,
        })
    }
    pub fn builtins() -> Result<Self> {
        let mut registry = Self::new(16, 4096)?;
        registry.register(Box::new(Dnp3Probe))?;
        registry.register(Box::new(ModbusProbe))?;
        Ok(registry)
    }
    pub fn register(&mut self, probe: Box<dyn ProtocolProbe>) -> Result<()> {
        let name = probe.name();
        if name.is_empty() || self.probes.iter().any(|p| p.name() == name) {
            return Err(Error::new(
                ErrorCode::Usage,
                0,
                "protocol_probe",
                "probe names must be nonempty and unique",
            ));
        }
        if self.probes.len() >= self.max_probes {
            return Err(Error::limit("protocol_probes"));
        }
        self.probes.push(probe);
        Ok(())
    }
    pub fn inspect(&self, input: &ProbeInput<'_>) -> Result<Vec<ProbeObservation>> {
        // Reject explicitly rather than silently inspecting a shorter prefix.
        if input.prefix.len() > self.max_prefix_bytes {
            return Err(Error::limit("protocol_probe_prefix"));
        }
        let mut output = Vec::with_capacity(self.probes.len());
        for probe in &self.probes {
            let result = probe.probe(input);
            match &result {
                ProbeResult::NeedMore { minimum_total } if *minimum_total <= input.prefix.len() => {
                    return Err(Error::new(
                        ErrorCode::Invariant,
                        0,
                        "protocol_probe",
                        "NeedMore must require strictly more input",
                    ));
                }
                ProbeResult::NeedMore { minimum_total }
                    if *minimum_total > self.max_prefix_bytes =>
                {
                    return Err(Error::limit("protocol_probe_prefix"));
                }
                ProbeResult::Match {
                    examined_bytes,
                    protocol,
                    ..
                } if *examined_bytes == 0
                    || *examined_bytes > input.prefix.len()
                    || protocol.is_empty() =>
                {
                    return Err(Error::new(
                        ErrorCode::Invariant,
                        0,
                        "protocol_probe",
                        "invalid successful probe extent or protocol name",
                    ));
                }
                _ => {}
            }
            output.push(ProbeObservation {
                probe: probe.name(),
                result,
            });
        }
        // Return every result in registration order. Never silently pick a winner
        // when several probes match the same input.
        Ok(output)
    }
}

pub struct Dnp3Probe;
impl ProtocolProbe for Dnp3Probe {
    fn name(&self) -> &'static str {
        "dnp3_link_crc"
    }
    fn probe(&self, input: &ProbeInput<'_>) -> ProbeResult {
        let b = input.prefix;
        if b.is_empty() {
            return ProbeResult::NeedMore { minimum_total: 2 };
        }
        if b[0] != 0x05 {
            return ProbeResult::NoMatch;
        }
        if b.len() < 2 {
            return ProbeResult::NeedMore { minimum_total: 2 };
        }
        if b[1] != 0x64 {
            return ProbeResult::NoMatch;
        }
        if b.len() < 3 {
            return ProbeResult::NeedMore { minimum_total: 3 };
        }
        if b[2] < 5 {
            return ProbeResult::NoMatch;
        }
        if b.len() < 10 {
            return ProbeResult::NeedMore { minimum_total: 10 };
        }
        if crc16_dnp(&b[..8]) != u16::from_le_bytes([b[8], b[9]]) {
            return ProbeResult::NoMatch;
        }
        let user_len = usize::from(b[2]) - 5;
        let total = 10 + user_len + 2 * user_len.div_ceil(16);
        if b.len() < total {
            return ProbeResult::NeedMore {
                minimum_total: total,
            };
        }
        let mut at = 10;
        let mut remaining = user_len;
        while remaining > 0 {
            let count = remaining.min(16);
            if crc16_dnp(&b[at..at + count])
                != u16::from_le_bytes([b[at + count], b[at + count + 1]])
            {
                return ProbeResult::NoMatch;
            }
            at += count + 2;
            remaining -= count;
        }
        ProbeResult::Match {
            protocol: "dnp3",
            strength: ProbeStrength::CompleteFrameChecksums,
            examined_bytes: total,
            reason: "complete_link_frame_with_valid_header_and_data_crcs",
        }
    }
}

pub struct ModbusProbe;
impl ProtocolProbe for ModbusProbe {
    fn name(&self) -> &'static str {
        "modbus_tcp_mbap"
    }
    fn probe(&self, input: &ProbeInput<'_>) -> ProbeResult {
        if input.transport != ProbeTransport::Tcp {
            return ProbeResult::NoMatch;
        }
        let b = input.prefix;
        if b.len() < 4 {
            return ProbeResult::NeedMore { minimum_total: 4 };
        }
        if b[2..4] != [0, 0] {
            return ProbeResult::NoMatch;
        }
        if b.len() < 6 {
            return ProbeResult::NeedMore { minimum_total: 6 };
        }
        let length = usize::from(u16::from_be_bytes([b[4], b[5]]));
        if !(2..=254).contains(&length) {
            return ProbeResult::NoMatch;
        }
        let total = 6 + length;
        if b.len() < total {
            return ProbeResult::NeedMore {
                minimum_total: total,
            };
        }
        let function = b[7] & 0x7f;
        if function == 0 {
            return ProbeResult::NoMatch;
        }
        ProbeResult::Match {
            protocol: "modbus",
            strength: ProbeStrength::HeaderStructure,
            examined_bytes: total,
            reason: "plausible_complete_mbap_frame_not_a_unique_protocol_signature",
        }
    }
}
