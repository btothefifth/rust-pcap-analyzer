//! Modbus/TCP MBAP framing with bounded common-function validation.
//! Roles are explicit configuration, not guesses based on TCP initiator.
use crate::dnp3::ProtocolIssue;
use crate::provenance::EvidenceBytes;
use crate::tcp::StreamResult;
use crate::{Error, ErrorCode, Limits, Result};

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
}
fn be16(b: &[u8]) -> u16 {
    u16::from_be_bytes([b[0], b[1]])
}
fn quantity(pdu: &[u8], max: u16) -> bool {
    if pdu.len() < 5 {
        return false;
    }
    let start = u32::from(be16(&pdu[1..3]));
    let count = be16(&pdu[3..5]);
    (1..=max).contains(&count) && start + u32::from(count) <= 65_536
}

fn pdu_shape(pdu: &[u8], role: Role) -> bool {
    let Some(&f) = pdu.first() else {
        return false;
    };
    if f & 0x7f == 0 {
        return false;
    }
    if role == Role::Unknown {
        return pdu_shape(pdu, Role::Request) || pdu_shape(pdu, Role::Response);
    }
    if f & 0x80 != 0 {
        return role == Role::Response && pdu.len() == 2 && matches!(pdu[1], 1..=6 | 8 | 10 | 11);
    }
    match (f, role) {
        (1 | 2, Role::Request) => pdu.len() == 5 && quantity(pdu, 2000),
        (3 | 4, Role::Request) => pdu.len() == 5 && quantity(pdu, 125),
        (1 | 2, Role::Response) => {
            pdu.len() >= 3 && pdu[1] <= 250 && usize::from(pdu[1]) == pdu.len() - 2
        }
        (3 | 4, Role::Response) => {
            pdu.len() >= 4
                && pdu[1] <= 250
                && pdu[1] % 2 == 0
                && usize::from(pdu[1]) == pdu.len() - 2
        }
        (5, _) => pdu.len() == 5 && matches!(be16(&pdu[3..5]), 0x0000 | 0xff00),
        (6, _) => pdu.len() == 5,
        (15, Role::Request) => {
            pdu.len() >= 7
                && quantity(pdu, 1968)
                && usize::from(pdu[5]) == usize::from(be16(&pdu[3..5])).div_ceil(8)
                && usize::from(pdu[5]) == pdu.len() - 6
        }
        (16, Role::Request) => {
            pdu.len() >= 8
                && quantity(pdu, 123)
                && usize::from(pdu[5]) == 2 * usize::from(be16(&pdu[3..5]))
                && usize::from(pdu[5]) == pdu.len() - 6
        }
        (15, Role::Response) => pdu.len() == 5 && quantity(pdu, 1968),
        (16, Role::Response) => pdu.len() == 5 && quantity(pdu, 123),
        _ => true, // Framed unknown functions stay opaque and are not paired.
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
            let supported = matches!(bytes[7] & 0x7f, 1..=6 | 15 | 16) && role != Role::Unknown;
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
    if !matches!(request.function, 1..=6 | 15 | 16)
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
        return false;
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
        return false;
    }
    let req = request.raw.data();
    let rsp = response.raw.data();
    // The fields are public, so do not trust shape_valid as a bounds check.
    if req.len() < 8 || rsp.len() < 8 {
        return false;
    }
    if !pdu_shape(&req[7..], Role::Request) || !pdu_shape(&rsp[7..], Role::Response) {
        return false;
    }
    if response.function & 0x80 != 0 {
        return true;
    }
    match request.function {
        1 | 2 if req.len() == 12 && rsp.len() >= 9 => {
            usize::from(rsp[8]) == usize::from(be16(&req[10..12])).div_ceil(8)
        }
        3 | 4 if req.len() == 12 && rsp.len() >= 9 => {
            usize::from(rsp[8]) == 2 * usize::from(be16(&req[10..12]))
        }
        5 | 6 | 15 | 16 if req.len() >= 12 && rsp.len() == 12 => req[8..12] == rsp[8..12],
        _ => false,
    }
}
