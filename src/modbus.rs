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
}
#[derive(Clone, Debug, Default)]
pub struct ModbusResult {
    pub messages: Vec<ModbusMessage>,
    pub issues: Vec<ProtocolIssue>,
    pub(crate) unfinished: Vec<([u8; 32], String)>,
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

/// Check only the five possible levels of MBAP evidence for this group.
pub fn competing_prefix(key: &str, mut contains: impl FnMut(&str) -> bool) -> bool {
    let Some((tx_unit, _)) = key.rsplit_once(':') else {
        return false;
    };
    let Some((tx, _)) = tx_unit.split_once(':') else {
        return false;
    };
    let Ok(id) = tx.parse::<u16>() else {
        return false;
    };
    contains(key)
        || contains(tx_unit)
        || contains(tx)
        || contains(&format!("hi-{}", id >> 8))
        || contains("")
}

/// An exception to an encapsulated interface request omits its MEI type.
pub fn other_mei(bytes: &[u8]) -> bool {
    bytes.first() == Some(&43) && bytes.get(1).is_some_and(|mei| *mei != 14)
}

fn be16(b: &[u8]) -> u16 {
    u16::from_be_bytes([b[0], b[1]])
}
fn pdu_shape(bytes: &[u8], role: Role) -> bool {
    match role {
        Role::Unknown => [Role::Request, Role::Response]
            .into_iter()
            .any(|r| pdu::parse(bytes, r).is_ok()),
        _ => pdu::parse(bytes, role).is_ok(),
    }
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
    if matches!(
        code,
        "modbus_framing_lost" | "truncated_modbus_mbap" | "truncated_modbus_adu"
    ) {
        if let Some(span) = bytes.spans().first() {
            let prefix = if code == "modbus_framing_lost" {
                String::new()
            } else {
                transaction_prefix(bytes.data())
            };
            out.unfinished.push((span.packet.capture, prefix));
        }
    }
    out.issues.push(ProtocolIssue {
        code,
        packets: bytes.packets(),
        stream_offset: at,
    });
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
                add_issue(
                    &mut out,
                    "truncated_modbus_mbap",
                    &chunk.bytes.slice(p..chunk.bytes.len())?,
                    at,
                    limits,
                )?;
                break;
            }
            let length = usize::from(be16(&bytes[4..6]));
            if be16(&bytes[2..4]) != 0 || !(2..=254).contains(&length) {
                add_issue(
                    &mut out,
                    "modbus_framing_lost",
                    &chunk.bytes.slice(p..chunk.bytes.len())?,
                    at,
                    limits,
                )?;
                break; // No safe arbitrary resynchronization signature exists.
            }
            let total = length + 6;
            if total > limits.max_application_bytes {
                return Err(Error::limit("modbus_adu_bytes"));
            }
            if bytes.len() < total {
                add_issue(
                    &mut out,
                    "truncated_modbus_adu",
                    &chunk.bytes.slice(p..chunk.bytes.len())?,
                    at,
                    limits,
                )?;
                break;
            }
            let valid = pdu_shape(&bytes[7..total], role);
            let supported = pdu::supported(&bytes[7..total]) && role != Role::Unknown;
            capacity(
                &out,
                1 + usize::from(!supported) + usize::from(!valid),
                limits,
            )?;
            let raw = chunk.bytes.slice(p..p + total)?;
            if !supported {
                add_issue(
                    &mut out,
                    "unsupported_modbus_function_or_role",
                    &raw,
                    at,
                    limits,
                )?;
            }
            if !valid {
                add_issue(&mut out, "invalid_modbus_pdu_shape", &raw, at, limits)?;
            }
            out.messages.push(ModbusMessage {
                stream_offset: at,
                transaction: be16(&bytes[..2]),
                unit: bytes[6],
                function: bytes[7],
                role,
                shape_valid: valid,
                semantics_supported: supported,
                boundary_verified: verified,
                raw,
            });
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
    if !pdu::supported(request.raw.data().get(7..).unwrap_or_default())
        || !request.raw.validate()
        || !response.raw.validate()
        || request.role != Role::Request
        || response.role != Role::Response
        || !request.shape_valid
        || !response.shape_valid
        || !request.semantics_supported
        || !response.semantics_supported
        || request.transaction != response.transaction
        || request.unit != response.unit
        || request.function != (response.function & 0x7f)
    {
        return None;
    }
    fn metadata_agrees(message: &ModbusMessage) -> bool {
        let raw = message.raw.data();
        raw.len() >= 8
            && be16(&raw[2..4]) == 0
            && usize::from(be16(&raw[4..6])) + 6 == raw.len()
            && message.transaction == be16(&raw[..2])
            && message.unit == raw[6]
            && message.function == raw[7]
    }
    if !metadata_agrees(request) || !metadata_agrees(response) {
        return None;
    }
    let req = request.raw.data();
    let rsp = response.raw.data();
    Some((
        transaction::Summary::parse(&req[7..], Role::Request)?,
        transaction::Summary::parse(&rsp[7..], Role::Response)?,
    ))
}
