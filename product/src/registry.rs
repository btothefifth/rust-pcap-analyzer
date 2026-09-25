//! Additional trusted in-process analyzers. No consensus and no port-only identity.
use crate::protocols::{Protocol, MAX_FRAME};
use pcap_evidence::{
    protocol::{ProbeInput, ProbeResult, ProbeStrength, ProbeTransport},
    provenance::EvidenceBytes,
    Error, ErrorCode, Result,
};
use pcap_evidence_stream::{
    plugin::{
        AnalyzerLimits, AnalyzerPlugin, DatagramAnalyzer, DatagramInput, Output, ProtocolDetector,
        StreamAnalyzer, StreamInput,
    },
    Registry, StreamConfig,
};

pub fn registry(c: &StreamConfig, profile: &str) -> Result<Registry> {
    if !["it-light", "it-full", "ics-core", "ics-full"].contains(&profile) {
        return Err(Error::new(
            ErrorCode::Usage,
            0,
            "profile",
            "unknown analysis profile",
        ));
    }
    let mut r = Registry::builtins(c)?;
    for &p in Protocol::ALL {
        let include = match profile {
            "it-light" => p.feature() == "standard",
            "it-full" => ["standard", "extensions"].contains(&p.feature()),
            "ics-core" => p.feature() != "industrial-full" && p.feature() != "extensions",
            _ => true,
        };
        if include && p.compiled() && p.transport() != "link" {
            r.register(Box::new(FramingPlugin(p)))?;
        }
    }
    Ok(r)
}
pub fn signature(p: Protocol, b: &[u8]) -> bool {
    if b.is_empty() {
        return false;
    }
    match p {
        Protocol::Bgp => b.len() >= 16 && b[..16].iter().all(|x| *x == 0xff),
        Protocol::Netflow9 => b.starts_with(&[0, 9]),
        Protocol::Snmp => b[0] == 0x30,
        Protocol::BacnetIp => b[0] == 0x81,
        Protocol::Enip => {
            b.len() >= 2
                && [0x63, 0x64, 0x65, 0x66, 0x6f, 0x70, 0x72, 0x73]
                    .contains(&u16::from_le_bytes([b[0], b[1]]))
        }
        Protocol::Mms => (0xa0..=0xad).contains(&b[0]),
        Protocol::Iec104 => b[0] == 0x68,
        Protocol::S7 => b.starts_with(&[3, 0]),
        Protocol::HartIp => b.len() >= 2 && b[0] == 1 && b[1] <= 2,
        Protocol::FinsTcp => b.starts_with(b"FINS"),
        Protocol::FinsUdp => b.len() >= 3 && b[0] & 0x80 != 0 && b[1] == 0 && b[2] <= 7,
        Protocol::Ads => b.starts_with(&[0, 0]),
        Protocol::OpcUa => {
            b.len() >= 3
                && matches!(
                    &b[..3],
                    b"HEL" | b"ACK" | b"ERR" | b"RHE" | b"OPN" | b"MSG" | b"CLO"
                )
        }
        Protocol::Melsec => b.starts_with(&[0x50, 0]) || b.starts_with(&[0xd0, 0]),
        Protocol::Synchrophasor => b[0] == 0xaa,
        Protocol::Rtp => b[0] >> 6 == 2,
        Protocol::Tftp => b.len() >= 2 && b[0] == 0 && (1..=6).contains(&b[1]),
        Protocol::Pptp => b.len() >= 8 && b[4..8] == [0x1a, 0x2b, 0x3c, 0x4d],
        Protocol::Telnet => b[0] == 0xff,
        // A completed command/status line or SIP header must validate before matching.
        Protocol::Ftp | Protocol::Pop3 | Protocol::Imap | Protocol::Sip => true,
        _ => false,
    }
}
pub struct FramingPlugin(pub Protocol);
impl ProtocolDetector for FramingPlugin {
    fn protocol(&self) -> &'static str {
        self.0.name()
    }
    fn detect(&self, i: &ProbeInput<'_>) -> ProbeResult {
        if (self.0.transport() == "tcp") != (i.transport == ProbeTransport::Tcp)
            || !signature(self.0, i.prefix)
        {
            return ProbeResult::NoMatch;
        }
        match self.0.decode(i.prefix) {
            Ok(d) => ProbeResult::Match {
                protocol: self.0.name(),
                strength: ProbeStrength::HeaderStructure,
                examined_bytes: d.consumed,
                reason: "validated_envelope_candidate_not_endpoint_or_full_semantic_proof",
            },
            Err(e) if e.code == ErrorCode::Truncated && i.prefix.len() < MAX_FRAME => {
                ProbeResult::NeedMore {
                    minimum_total: i.prefix.len() + 1,
                }
            }
            _ => ProbeResult::NoMatch,
        }
    }
}
impl AnalyzerPlugin for FramingPlugin {
    fn stream(&self, l: AnalyzerLimits) -> Option<Box<dyn StreamAnalyzer>> {
        if self.0.transport() != "tcp" {
            None
        } else {
            Some(Box::new(Stream {
                p: self.0,
                limit: l.max_buffer_bytes.min(MAX_FRAME),
                pending: EvidenceBytes::default(),
                offset: None,
                work: 0,
                work_limit: l.max_work_bytes,
                failed: false,
            }))
        }
    }
    fn datagram(&self, l: AnalyzerLimits) -> Option<Box<dyn DatagramAnalyzer>> {
        if self.0.transport() != "udp" {
            None
        } else {
            Some(Box::new(Datagram {
                p: self.0,
                limit: l.max_buffer_bytes.min(MAX_FRAME),
            }))
        }
    }
}
struct Stream {
    p: Protocol,
    limit: usize,
    pending: EvidenceBytes,
    offset: Option<i64>,
    work: usize,
    work_limit: usize,
    failed: bool,
}
impl Stream {
    fn drain(&mut self, out: &mut Output<'_>, final_input: bool) -> Result<()> {
        while !self.pending.is_empty() && !self.failed {
            self.work = self
                .work
                .checked_add(self.pending.len())
                .ok_or_else(|| Error::limit("plugin_work"))?;
            if self.work > self.work_limit {
                return Err(Error::limit("plugin_work"));
            }
            match self.p.decode(self.pending.data()) {
                Ok(d) => {
                    let at = self.offset.unwrap_or(0);
                    let end = at
                        .checked_add(d.consumed as i64)
                        .ok_or_else(|| Error::limit("stream_offset"))?;
                    let bytes = self.pending.slice(0..d.consumed)?;
                    out.message(self.p.name(), &bytes, Some((at, end)), d.json(), None, true)?;
                    self.pending = self.pending.slice(d.consumed..self.pending.len())?;
                    self.offset = Some(end);
                }
                Err(e) if e.code == ErrorCode::Truncated && !final_input => break,
                Err(e) => {
                    out.issue(self.p.name(), e.to_string(), &self.pending)?;
                    self.pending = EvidenceBytes::default();
                    self.failed = true;
                }
            }
        }
        Ok(())
    }
}
impl StreamAnalyzer for Stream {
    fn push(&mut self, i: &StreamInput<'_>, out: &mut Output<'_>) -> Result<()> {
        if self.failed {
            return Ok(());
        }
        if let Some(at) = self.offset {
            if at.checked_add(self.pending.len() as i64) != Some(i.offset) {
                self.gap("noncontiguous_analyzer_input", out)?;
            }
        }
        if self.offset.is_none() {
            self.offset = Some(i.offset);
        }
        // Chunks are bounded by the engine. Process in smaller pieces to avoid retaining a whole stream.
        let mut pos = 0;
        while pos < i.bytes.len() {
            let room = self.limit.saturating_sub(self.pending.len());
            if room == 0 {
                return Err(Error::limit("plugin_pending"));
            }
            let n = room.min(i.bytes.len() - pos);
            self.pending
                .append(&i.bytes.slice(pos..pos + n)?, self.limit)?;
            pos += n;
            self.drain(out, false)?;
            if self.failed {
                break;
            }
        }
        Ok(())
    }
    fn gap(&mut self, reason: &str, out: &mut Output<'_>) -> Result<()> {
        if !self.pending.is_empty() {
            out.issue(self.p.name(), format!("state_cut:{reason}"), &self.pending)?;
        }
        self.pending = EvidenceBytes::default();
        self.offset = None;
        self.failed = false;
        Ok(())
    }
    fn finish(&mut self, out: &mut Output<'_>) -> Result<()> {
        self.drain(out, true)
    }
    fn retained_bytes(&self) -> usize {
        self.pending.len()
    }
}
struct Datagram {
    p: Protocol,
    limit: usize,
}
impl DatagramAnalyzer for Datagram {
    fn analyze(&mut self, i: &DatagramInput<'_>, out: &mut Output<'_>) -> Result<()> {
        if i.bytes.len() > self.limit {
            return Err(Error::limit("plugin_datagram"));
        }
        let d = self.p.decode(i.bytes.data())?;
        let bytes = i.bytes.slice(0..d.consumed)?;
        out.message(self.p.name(), &bytes, None, d.json(), None, true)?;
        if d.consumed != i.bytes.len() {
            out.issue(
                self.p.name(),
                "trailing_datagram_bytes_not_interpreted",
                &i.bytes.slice(d.consumed..i.bytes.len())?,
            )?;
        }
        Ok(())
    }
    fn retained_bytes(&self) -> usize {
        0
    }
}
