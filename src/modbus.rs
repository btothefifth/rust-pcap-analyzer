//! Modbus/TCP MBAP framing with bounded common-function validation.
//! Roles are explicit configuration, not guesses based on TCP initiator.
pub(crate) mod pdu;
pub(crate) mod transaction;
use crate::dnp3::ProtocolIssue;
use crate::provenance::EvidenceBytes;
use crate::tcp::StreamResult;
use crate::{Error, ErrorCode, Limits, Result};
pub use transaction::{correlation_token, mismatch_fields, pair_projection};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Role {
    Request,
    Response,
    Unknown,
}
impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Request => "request",
            Self::Response => "response",
            Self::Unknown => "unknown",
        }
    }
}
#[derive(Clone, Debug)]
pub struct ModbusMessage {
    pub stream_offset: i64,
    pub transaction: u16,
    pub unit: u8,
    pub function: u8,
    pub role: Role,
    pub shape_valid: bool,
    pub semantics_supported: bool,
    pub boundary_verified: bool,
    pub raw: EvidenceBytes,
    parsed: std::sync::Arc<Interpretation>,
}
#[derive(Debug)]
struct Interpretation {
    role: Role,
    bytes: Box<[u8]>,
    pdu: Result<pdu::Pdu>,
    other_role: Option<Result<pdu::Pdu>>,
}
impl ModbusMessage {
    /// Decode one complete MBAP frame. The caller supplies the direction and
    /// the observed alignment. A malformed PDU retains its raw frame.
    ///
    /// ```
    /// use pcap_evidence::modbus::{ModbusMessage, ModbusResult, Role};
    /// use pcap_evidence::provenance::{EvidenceBytes, PacketId};
    ///
    /// let source = PacketId { capture: [7; 32], frame: 1, record_offset: 24 };
    /// let raw = EvidenceBytes::from_packet(&[0, 1, 0, 0, 0, 6, 1, 3, 0, 8, 0, 1], source, 54);
    /// let message = ModbusMessage::from_adu(raw, Role::Request, 0, true)?;
    /// assert_eq!((message.transaction, message.function), (1, 3));
    /// let mut result = ModbusResult::default();
    /// result.messages.push(message);
    /// # Ok::<(), pcap_evidence::Error>(())
    /// ```
    pub fn from_adu(
        raw: EvidenceBytes,
        role: Role,
        stream_offset: i64,
        boundary_verified: bool,
    ) -> Result<Self> {
        let bytes = raw.data();
        if !raw.validate() {
            return Err(Error::new(
                ErrorCode::Invariant,
                0,
                "provenance",
                "invalid Modbus source spans",
            ));
        }
        crate::semantics::modbus::envelope(bytes)?;
        stream_offset
            .checked_add(bytes.len() as i64)
            .ok_or_else(|| Error::limit("stream_offset"))?;
        let parse_role = if role == Role::Unknown {
            Role::Request
        } else {
            role
        };
        let pdu = pdu::parse(&bytes[7..], parse_role);
        let other_role = (role == Role::Unknown).then(|| pdu::parse(&bytes[7..], Role::Response));
        let valid = pdu.as_ref().is_ok_and(pdu::Pdu::complete)
            || other_role
                .as_ref()
                .is_some_and(|r| r.as_ref().is_ok_and(pdu::Pdu::complete));
        let parsed = std::sync::Arc::new(Interpretation {
            role: parse_role,
            bytes: bytes.into(),
            pdu,
            other_role,
        });
        let supported = pdu::supported(&bytes[7..]) && role != Role::Unknown;
        Ok(Self {
            parsed,
            stream_offset,
            transaction: be16(&bytes[..2]),
            unit: bytes[6],
            function: bytes[7],
            role,
            shape_valid: valid,
            semantics_supported: supported,
            boundary_verified,
            raw,
        })
    }
    pub(crate) fn mbap_matches_fields(&self) -> bool {
        let raw = self.raw.data();
        crate::semantics::modbus::envelope(raw).is_ok()
            && self.transaction == be16(&raw[..2])
            && self.unit == raw[6]
            && self.function == raw[7]
    }

    fn cached_interpretation(&self, role: Role) -> Option<&Result<pdu::Pdu>> {
        if self.raw.data() != self.parsed.bytes.as_ref() {
            return None;
        }
        if self.parsed.role == role {
            Some(&self.parsed.pdu)
        } else if role == Role::Response {
            self.parsed.other_role.as_ref()
        } else {
            None
        }
    }

    pub(crate) fn interpretation(&self, role: Role) -> Result<pdu::Pdu> {
        self.cached_interpretation(role)
            .cloned()
            .unwrap_or_else(|| pdu::parse(self.raw.data().get(7..).unwrap_or_default(), role))
    }

    pub(crate) fn pairable_pdu(&self) -> bool {
        let bytes = self.raw.data().get(7..).unwrap_or_default();
        if self.role == Role::Unknown || !pdu::supported(bytes) {
            return false;
        }
        match self.cached_interpretation(self.role) {
            Some(result) => result.as_ref().is_ok_and(pdu::Pdu::complete),
            None => pdu::parse(bytes, self.role)
                .as_ref()
                .is_ok_and(pdu::Pdu::complete),
        }
    }

    pub(crate) fn binding(&self) -> MessageBinding {
        MessageBinding {
            parsed: self.parsed.clone(),
            spans: self.raw.spans().into(),
            boundary: self.boundary_verified,
            stream_offset: self.stream_offset,
        }
    }
}
#[derive(Clone, Debug)]
pub(crate) struct MessageBinding {
    parsed: std::sync::Arc<Interpretation>,
    spans: Box<[crate::provenance::SourceSpan]>,
    boundary: bool,
    stream_offset: i64,
}
impl MessageBinding {
    pub(crate) fn matches(&self, message: &ModbusMessage) -> bool {
        let raw = message.raw.data();
        std::sync::Arc::ptr_eq(&self.parsed, &message.parsed)
            && self.parsed.bytes.as_ref() == raw
            && self.spans.as_ref() == message.raw.spans()
            && message.role == self.parsed.role
            && message.stream_offset == self.stream_offset
            && message.boundary_verified == self.boundary
            && message.shape_valid
            && message.semantics_supported
            && message.transaction == be16(&raw[..2])
            && message.unit == raw[6]
            && message.function == raw[7]
    }
}
#[derive(Clone, Debug, Default)]
pub struct ModbusResult {
    pub messages: Vec<ModbusMessage>,
    pub issues: Vec<ProtocolIssue>,
    pub(crate) unfinished: Vec<([u8; 32], String, usize)>,
}
/// Captured portion of a transaction key. Unreadable MBAP framing leaves the
/// entire connection in scope; a known function narrows it to one group.
pub fn transaction_prefix(header: &[u8]) -> String {
    if header.get(2).is_some_and(|v| *v != 0)
        || header.get(3).is_some_and(|v| *v != 0)
        || header.get(4).is_some_and(|v| *v != 0)
        || header.get(5).is_some_and(|n| !(2..=254).contains(n))
    {
        return String::new();
    }
    match header {
        [] => String::new(),
        [hi] => format!("hi-{hi}"),
        [hi, lo, ..] => {
            let tx = u16::from_be_bytes([*hi, *lo]);
            match (header.get(6), header.get(7)) {
                (Some(unit), Some(function)) => format!("{tx}:{unit}:{}", function & 0x7f),
                (Some(unit), None) => format!("{tx}:{unit}"),
                _ => tx.to_string(),
            }
        }
    }
}

/// A non-device MEI cannot explain a device-identification response. An
/// exception omits the MEI and can still belong to an opaque request.
pub fn observation_prefix(header: &[u8], role: Role) -> String {
    let mut key = transaction_prefix(header);
    if !key.is_empty() && header.get(7) == Some(&43) && header.get(8).is_some_and(|mei| *mei != 14)
    {
        key.push_str(if role == Role::Response {
            ":opaque-response"
        } else {
            ":opaque-request"
        });
    }
    key
}

pub struct CompetingEvidence<W>(std::collections::BTreeMap<String, Vec<W>>);
impl<W> Default for CompetingEvidence<W> {
    fn default() -> Self {
        Self(Default::default())
    }
}
impl<W: Copy> CompetingEvidence<W> {
    pub fn record(&mut self, key: String, witness: W) {
        self.0.entry(key).or_default().push(witness);
    }
    /// Expand only matching observations and charge every emitted reference.
    pub fn witnesses(&self, key: &str, exception: bool, remaining: &mut usize) -> Result<Vec<W>> {
        let mut witnesses = Vec::new();
        let mut add = |prefix: &str| -> Result<()> {
            if let Some(items) = self.0.get(prefix) {
                *remaining = remaining
                    .checked_sub(items.len())
                    .ok_or_else(|| Error::limit("modbus_competing_references"))?;
                witnesses.extend_from_slice(items);
            }
            Ok(())
        };
        add(key)?;
        if let Some((tx_unit, _)) = key.rsplit_once(':') {
            if let Some((tx, _)) = tx_unit.split_once(':') {
                add(tx_unit)?;
                add(tx)?;
                if let Ok(id) = tx.parse::<u16>() {
                    add(&format!("hi-{}", id >> 8))?;
                }
            }
        }
        add("")?;
        if exception {
            add(&format!("{key}:opaque-request"))?;
        }
        Ok(witnesses)
    }
}
fn be16(b: &[u8]) -> u16 {
    u16::from_be_bytes([b[0], b[1]])
}
fn capacity(out: &ModbusResult, additions: usize, limits: &Limits) -> Result<()> {
    let used = out
        .messages
        .len()
        .checked_add(out.issues.len())
        .and_then(|n| n.checked_add(additions))
        .ok_or_else(|| Error::limit("modbus_messages"))?;
    if used > limits.max_protocol_messages {
        return Err(Error::limit("modbus_messages"));
    }
    Ok(())
}
fn add_issue(
    out: &mut ModbusResult,
    code: &'static str,
    bytes: &EvidenceBytes,
    at: i64,
    limits: &Limits,
) -> Result<()> {
    capacity(out, 1, limits)?;
    out.issues.push(ProtocolIssue {
        code,
        packets: bytes.packets(),
        stream_offset: at,
    });
    Ok(())
}
fn incomplete(
    out: &mut ModbusResult,
    code: &'static str,
    bytes: &EvidenceBytes,
    at: i64,
    limits: &Limits,
    role: Role,
) -> Result<()> {
    let index = out.issues.len();
    add_issue(out, code, bytes, at, limits)?;
    if let Some(capture) = bytes.capture_scope() {
        let key = if code == "modbus_framing_lost" {
            String::new()
        } else {
            observation_prefix(bytes.data(), role)
        };
        out.unfinished.push((capture, key, index));
    }
    Ok(())
}
pub fn decode(stream: &StreamResult, role: Role, limits: &Limits) -> Result<ModbusResult> {
    limits.validate()?;
    let mut out = ModbusResult::default();
    for chunk in &stream.chunks {
        let len = i64::try_from(chunk.bytes.len()).map_err(|_| Error::limit("stream_offset"))?;
        chunk
            .offset
            .checked_add(len)
            .ok_or_else(|| Error::limit("stream_offset"))?;
        if !chunk.bytes.validate() {
            return Err(Error::new(
                ErrorCode::Invariant,
                0,
                "provenance",
                "invalid Modbus source spans",
            ));
        }
        let mut p = 0;
        let verified = stream.anchored_by_syn && chunk.offset == 0;
        if !verified {
            add_issue(
                &mut out,
                "modbus_start_boundary_unverified",
                &chunk.bytes,
                chunk.offset,
                limits,
            )?;
        }
        while p < chunk.bytes.len() {
            let bytes = &chunk.bytes.data()[p..];
            let at = chunk.offset + p as i64;
            if bytes.len() < 7 {
                incomplete(
                    &mut out,
                    "truncated_modbus_mbap",
                    &chunk.bytes.slice(p..chunk.bytes.len())?,
                    at,
                    limits,
                    role,
                )?;
                break;
            }
            let length = usize::from(be16(&bytes[4..6]));
            if be16(&bytes[2..4]) != 0 || !(2..=254).contains(&length) {
                incomplete(
                    &mut out,
                    "modbus_framing_lost",
                    &chunk.bytes.slice(p..chunk.bytes.len())?,
                    at,
                    limits,
                    role,
                )?;
                break; // No safe arbitrary resynchronization signature exists.
            }
            let total = length + 6;
            if total > limits.max_application_bytes {
                return Err(Error::limit("modbus_adu_bytes"));
            }
            if bytes.len() < total {
                incomplete(
                    &mut out,
                    "truncated_modbus_adu",
                    &chunk.bytes.slice(p..chunk.bytes.len())?,
                    at,
                    limits,
                    role,
                )?;
                break;
            }
            let raw = chunk.bytes.slice(p..p + total)?;
            let message = ModbusMessage::from_adu(raw, role, at, verified)?;
            capacity(
                &out,
                1 + usize::from(!message.semantics_supported) + usize::from(!message.shape_valid),
                limits,
            )?;
            if !message.semantics_supported {
                add_issue(
                    &mut out,
                    "unsupported_modbus_function_or_role",
                    &message.raw,
                    at,
                    limits,
                )?;
            }
            if !message.shape_valid {
                add_issue(
                    &mut out,
                    "invalid_modbus_pdu_shape",
                    &message.raw,
                    at,
                    limits,
                )?;
            }
            out.messages.push(message);
            p += total;
        }
    }
    Ok(out)
}

/// Validates common-function request/response consistency without asserting
/// causality. Requires valid framed messages; unknown functions return false.
/// Identifier reuse, capture ordering, and device semantics remain caller-owned.
pub fn response_matches(request: &ModbusMessage, response: &ModbusMessage) -> bool {
    pair_summaries(request, response).is_some_and(|(a, b)| a.agrees(&b))
}

pub(crate) fn pair_summaries(
    request: &ModbusMessage,
    response: &ModbusMessage,
) -> Option<(transaction::Summary, transaction::Summary)> {
    if !request.raw.validate()
        || !response.raw.validate()
        || request.role != Role::Request
        || response.role != Role::Response
        || request.transaction != response.transaction
        || request.unit != response.unit
        || request.function != (response.function & 0x7f)
    {
        return None;
    }
    if !request.mbap_matches_fields() || !response.mbap_matches_fields() {
        return None;
    }
    let req = request.raw.data();
    let rsp = response.raw.data();
    if !pdu::supported(&req[7..]) || !pdu::supported(&rsp[7..]) {
        return None;
    }
    Some((
        transaction::Summary::from_pdu(&req[7..], &request.interpretation(Role::Request).ok()?)?,
        transaction::Summary::from_pdu(&rsp[7..], &response.interpretation(Role::Response).ok()?)?,
    ))
}

#[cfg(test)]
mod tests {
    #[test]
    fn snapshot_parses_each_configured_role_once() {
        super::pdu::PARSES.with(|n| n.set(0));
        let snapshot = crate::engine::analyze(
            include_bytes!("../fixtures/semantics/modbus_fc23_split.pcap"),
            Default::default(),
        )
        .unwrap();
        assert!(crate::report::analysis(&snapshot, false)
            .encode()
            .contains("read_mapping"));
        super::pdu::PARSES.with(|n| assert_eq!(n.replace(0), 2));
        let ambiguous = crate::engine::Config {
            modbus_ports: vec![41000, 502],
            ..Default::default()
        };
        let snapshot = crate::engine::analyze(
            include_bytes!("../fixtures/semantics/modbus_fc23_split.pcap"),
            ambiguous,
        )
        .unwrap();
        assert!(crate::report::analysis(&snapshot, false)
            .encode()
            .contains("unresolved_role"));
        super::pdu::PARSES.with(|n| assert_eq!(n.get(), 4));
    }
}
