//! Device-agnostic Modbus/TCP fields. Addresses are zero-based wire addresses;
//! no register map, scaling, host endian convention, physical effect, or device
//! identity is inferred. A read-bit response alone cannot reveal the bit count.
use super::{fail, need, uint, Field, Limits, Record, Report, Status, Value};
use crate::{json::Json, modbus::Role, provenance::EvidenceBytes, ErrorCode, Result};

fn num(name: &'static str, value: u64, start: usize, end: usize) -> Field {
    Field::new(name, Value::Unsigned(value), start..end)
}
fn invalid(at: usize, code: &'static str) -> crate::Error {
    fail(ErrorCode::InvalidLength, at, code)
}
fn quantity(b: &[u8], max: u64) -> Result<(u64, u64)> {
    need(b, 8, 4, "modbus_address_quantity_truncated")?;
    let first = uint(b, 8, 2, false);
    let count = uint(b, 10, 2, false);
    if count == 0 || count > max || first + count > 65_536 {
        return Err(invalid(8, "modbus_address_quantity_range"));
    }
    Ok((first, count))
}
fn exact(b: &[u8], expected: usize) -> Result<()> {
    if b.len() != expected {
        Err(invalid(0, "modbus_pdu_shape"))
    } else {
        Ok(())
    }
}
fn address_fields(b: &[u8], max: u64) -> Result<Vec<Field>> {
    let (first, count) = quantity(b, max)?;
    Ok(vec![
        num("starting_address_zero_based", first, 8, 10),
        num("quantity", count, 10, 12),
    ])
}
fn registers(
    out: &mut Report<'_>,
    b: &[u8],
    at: usize,
    count: usize,
    first: Option<u64>,
    address_range: std::ops::Range<usize>,
) -> Result<()> {
    for i in 0..count {
        let p = at + i * 2;
        need(b, p, 2, "modbus_register_truncated")?;
        let mut fields = vec![num("register_u16", uint(b, p, 2, false), p, p + 2)];
        if let Some(first) = first {
            fields.push(Field::derived(
                "address_zero_based",
                first + i as u64,
                address_range.clone(),
                "starting_address_plus_record_ordinal",
            ));
        }
        out.add(Record::new("register", p..p + 2, fields))?;
        out.advance(p + 2);
    }
    Ok(())
}
fn decode_body(b: &[u8], role: Role, out: &mut Report<'_>) -> Result<()> {
    need(b, 0, 8, "modbus_mbap_truncated")?;
    let len = uint(b, 4, 2, false) as usize;
    if uint(b, 2, 2, false) != 0 || !(2..=254).contains(&len) {
        return Err(invalid(2, "modbus_mbap_fields"));
    }
    if b.len() < len + 6 {
        return Err(fail(ErrorCode::Truncated, b.len(), "modbus_adu_truncated"));
    }
    if b.len() != len + 6 {
        return Err(invalid(4, "modbus_exactly_one_adu_required"));
    }
    let function = b[7];
    out.add(Record::new(
        "mbap",
        0..8,
        vec![
            num("transaction_id", uint(b, 0, 2, false), 0, 2),
            num("protocol_id", 0, 2, 4),
            num("length", len as u64, 4, 6),
            num("unit_id", b[6].into(), 6, 7),
            num("function", function.into(), 7, 8),
        ],
    ))?;
    out.advance(8);
    if role == Role::Unknown {
        return Err(fail(
            ErrorCode::UnsupportedTransport,
            8,
            "modbus_role_not_supplied",
        ));
    }
    if !matches!(function & 0x7f, 1..=6 | 15 | 16) {
        return Err(fail(
            ErrorCode::UnsupportedTransport,
            7,
            "modbus_function_outside_field_subset",
        ));
    }
    if function & 0x80 != 0 {
        exact(b, 9)?;
        if role != Role::Response || !matches!(b[8], 1..=6 | 8 | 10 | 11) {
            return Err(invalid(8, "modbus_exception_role_or_code"));
        }
        out.add(Record::new(
            "exception_response",
            8..9,
            vec![num("exception_code", b[8].into(), 8, 9)],
        ))?;
        out.advance(9);
        return Ok(());
    }
    match (function, role) {
        (1..=4, Role::Request) => {
            exact(b, 12)?;
            let fields = address_fields(b, if function <= 2 { 2000 } else { 125 })?;
            out.add(Record::new("read_request", 8..12, fields))?;
        }
        (1..=4, Role::Response) => {
            need(b, 8, 1, "modbus_byte_count_truncated")?;
            let count = usize::from(b[8]);
            if count == 0
                || count > 250
                || b.len() != 9 + count
                || (function >= 3 && count % 2 != 0)
            {
                return Err(invalid(8, "modbus_read_response_byte_count"));
            }
            out.add(Record::new(
                "read_response",
                8..9,
                vec![num("byte_count", count as u64, 8, 9)],
            ))?;
            out.advance(9);
            if function >= 3 {
                registers(out, b, 9, count / 2, None, 0..0)?;
            } else {
                // Do not expand an arbitrary padded last octet into extra coils.
                for i in 0..count {
                    let at = 9 + i;
                    out.add(Record::new(
                        "packed_response_octet",
                        at..at + 1,
                        vec![num("packed_lsb_first", b[at].into(), at, at + 1)],
                    ))?;
                    out.advance(at + 1);
                }
                out.warn(
                    "requested_bit_count_and_addresses_require_request",
                    9..b.len(),
                );
            }
        }
        (5 | 6, _) => {
            exact(b, 12)?;
            let value = uint(b, 10, 2, false);
            if function == 5 && !matches!(value, 0 | 0xff00) {
                return Err(invalid(10, "modbus_single_coil_encoding"));
            }
            let mut fields = vec![
                num("address_zero_based", uint(b, 8, 2, false), 8, 10),
                num("wire_value", value, 10, 12),
            ];
            if function == 5 {
                fields.push(Field::new(
                    "coil_value",
                    Value::Boolean(value == 0xff00),
                    10..12,
                ));
            }
            out.add(Record::new(
                if role == Role::Request {
                    "write_request"
                } else {
                    "write_echo_response"
                },
                8..12,
                fields,
            ))?;
        }
        (15 | 16, Role::Response) => {
            exact(b, 12)?;
            out.add(Record::new(
                "write_echo_response",
                8..12,
                address_fields(b, if function == 15 { 1968 } else { 123 })?,
            ))?;
        }
        (15 | 16, Role::Request) => {
            need(b, 8, 5, "modbus_write_header_truncated")?;
            let (first, count) = quantity(b, if function == 15 { 1968 } else { 123 })?;
            let count = count as usize;
            let expected = if function == 15 {
                count.div_ceil(8)
            } else {
                count * 2
            };
            if usize::from(b[12]) != expected || b.len() != 13 + expected {
                return Err(invalid(12, "modbus_write_byte_count"));
            }
            let mut fields = address_fields(b, if function == 15 { 1968 } else { 123 })?;
            fields.push(num("byte_count", expected as u64, 12, 13));
            out.add(Record::new("write_multiple_request", 8..13, fields))?;
            out.advance(13);
            if function == 16 {
                registers(out, b, 13, count, Some(first), 8..10)?;
            } else {
                if count > out.limits.max_records.saturating_sub(out.records.len()) {
                    return Err(fail(
                        ErrorCode::LimitExceeded,
                        13,
                        "modbus_coil_record_budget",
                    ));
                }
                for i in 0..count {
                    let at = 13 + i / 8;
                    let bit = (i % 8) as u8;
                    out.add(Record::new(
                        "coil",
                        at..at + 1,
                        vec![
                            Field::derived(
                                "address_zero_based",
                                first + i as u64,
                                8..10,
                                "starting_address_plus_record_ordinal",
                            ),
                            Field::bit_field("value", b[at] & (1 << bit) != 0, at, bit),
                        ],
                    ))?;
                }
                // FC15's zero-fill recommendation is not promoted to a MUST.
                if !padding_is_zero(count as u16, &b[13..]) {
                    out.warn(
                        "write_unused_bits_nonzero_recommendation",
                        b.len() - 1..b.len(),
                    );
                }
            }
        }
        _ => {
            return Err(fail(
                ErrorCode::UnsupportedTransport,
                8,
                "modbus_role_outside_subset",
            ))
        }
    }
    out.advance(b.len());
    Ok(())
}
pub fn decode(source: &EvidenceBytes, role: Role, limits: Limits) -> Result<Report<'_>> {
    let mut out = Report::new(source, "modbus", role.as_str(), limits)?;
    if let Err(e) = decode_body(source.data(), role, &mut out) {
        let at = out.consumed();
        out.stop(e, at);
    }
    Ok(out)
}
/// Unknown direction yields two explicitly attributed interpretations, including
/// rejected alternatives. No array element is silently selected as authoritative.
pub fn alternatives_json(source: &EvidenceBytes, role: Role, limits: Limits) -> Json {
    let roles: &[Role] = if role == Role::Unknown {
        &[Role::Request, Role::Response]
    } else {
        std::slice::from_ref(&role)
    };
    let result = Json::object([
        ("schema", "pcap-evidence.modbus-alternatives.v1".into()),
        (
            "selection",
            if role == Role::Unknown {
                "unresolved_role"
            } else {
                "caller_supplied_role"
            }
            .into(),
        ),
        (
            "interpretations",
            Json::array(
                roles
                    .iter()
                    .map(|r| super::as_json(decode(source, *r, limits.clone()))),
            ),
        ),
        ("device_effect_established", false.into()),
    ]);
    match result.encode_bounded(limits.max_json_bytes) {
        Ok(_) => result,
        Err(e) => Json::object([
            ("schema", "pcap-evidence.modbus-alternatives.v1".into()),
            ("status", "limit_exceeded".into()),
            ("error", crate::report::error(&e)),
        ]),
    }
}
/// Used only with a validated request quantity. Empty data and mismatched byte
/// counts fail. It says nothing about device acceptance, timing, or causality.
pub fn padding_is_zero(quantity: u16, bytes: &[u8]) -> bool {
    if quantity == 0 || bytes.len() != usize::from(quantity).div_ceil(8) {
        return false;
    }
    let used = quantity % 8;
    used == 0
        || bytes
            .last()
            .is_some_and(|last| last & (0xffu8 << used) == 0)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PairStatus {
    ConsistentWithinSubset,
    Inconsistent,
    NotComparable,
}
/// Caller-selected pair only: the API never searches captures or attaches a
/// response to a request. Request and response provenance remain separate.
pub fn check_pair(
    request: &crate::modbus::ModbusMessage,
    response: &crate::modbus::ModbusMessage,
    limits: Limits,
) -> Result<PairStatus> {
    let a = decode(&request.raw, Role::Request, limits.clone())?;
    let b = decode(&response.raw, Role::Response, limits)?;
    if a.status() == Status::Unsupported
        || b.status() == Status::Unsupported
        || a.status() == Status::Limited
        || b.status() == Status::Limited
    {
        return Ok(PairStatus::NotComparable);
    }
    if a.status() != Status::DecodedSubset || b.status() != Status::DecodedSubset {
        return Ok(PairStatus::Inconsistent);
    }
    // Root matching also validates public metadata/role flags against source bytes.
    Ok(if crate::modbus::response_matches(request, response) {
        PairStatus::ConsistentWithinSubset
    } else {
        PairStatus::Inconsistent
    })
}

/// Versioned correlation metadata emitted by the trusted streaming adapter. This
/// preserves request count and response padding without retaining payload bytes.
/// Other common-function compatibility tokens keep their existing equality rule.
pub fn compatibility_matches(request: &str, response: &str) -> bool {
    const PREFIX: &str = "modbus-bits-v1:";
    if request.is_empty() || response.is_empty() {
        return true;
    } // Existing exception-response wildcard.
    if !request.starts_with(PREFIX) && !response.starts_with(PREFIX) {
        return request == response;
    }
    let Some(q) = request
        .strip_prefix("modbus-bits-v1:quantity:")
        .and_then(|n| n.parse::<u16>().ok())
    else {
        return false;
    };
    let Some(body) = response.strip_prefix("modbus-bits-v1:response:") else {
        return false;
    };
    let Some((count, last)) = body.split_once(':') else {
        return false;
    };
    let (Ok(count), Ok(last)) = (count.parse::<usize>(), last.parse::<u8>()) else {
        return false;
    };
    if q == 0 || q > 2000 || count != usize::from(q).div_ceil(8) {
        return false;
    }
    q % 8 == 0 || last & (0xffu8 << (q % 8)) == 0
}
