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
fn address_fields(first: u16, count: u16) -> Vec<Field> {
    vec![
        num("starting_address_zero_based", first.into(), 8, 10),
        num("quantity", count.into(), 10, 12),
    ]
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
use crate::modbus::{
    pdu::{self, Pdu},
    transaction::Summary,
};

fn envelope(b: &[u8]) -> Result<()> {
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
    Ok(())
}

fn decode_body<'a>(
    b: &'a [u8],
    role: Role,
    out: &mut Report<'_>,
    parse: impl FnOnce() -> Result<Pdu<'a>>,
) -> Result<()> {
    envelope(b)?;
    let len = b.len() - 6;
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
    if !pdu::supported(&b[7..]) {
        return Err(fail(
            ErrorCode::UnsupportedTransport,
            7,
            "modbus_function_outside_field_subset",
        ));
    }
    match parse()? {
        Pdu::Exception(code) => {
            out.add(Record::new(
                "exception_response",
                8..9,
                vec![num("exception_code", code.into(), 8, 9)],
            ))?;
            out.advance(9);
        }
        Pdu::Read { start, count } => {
            let fields = address_fields(start, count);
            out.add(Record::new("read_request", 8..12, fields))?;
        }
        Pdu::ReadData(data) => {
            let count = data.len();
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
        Pdu::Single => {
            let value = uint(b, 10, 2, false);
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
        Pdu::WriteAck { start, count } => {
            out.add(Record::new(
                "write_echo_response",
                8..12,
                address_fields(start, count),
            ))?;
        }
        Pdu::Multiple { start, count, data } => {
            let mut fields = address_fields(start, count);
            let first = u64::from(start);
            let count = usize::from(count);
            let expected = data.len();
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
        Pdu::Mask => {
            out.add(Record::new(
                "mask_write_register",
                8..14,
                vec![
                    num("address_zero_based", uint(b, 8, 2, false), 8, 10),
                    num("and_mask", uint(b, 10, 2, false), 10, 12),
                    num("or_mask", uint(b, 12, 2, false), 12, 14),
                ],
            ))?;
        }
        Pdu::ReadWrite {
            start,
            count,
            write_start,
            write_count,
            data,
        } => {
            out.add(Record::new(
                "read_write_registers",
                8..17,
                vec![
                    num("read_start_zero_based", start.into(), 8, 10),
                    num("read_quantity", count.into(), 10, 12),
                    num("write_start_zero_based", write_start.into(), 12, 14),
                    num("write_quantity", write_count.into(), 14, 16),
                    num("byte_count", data.len() as u64, 16, 17),
                ],
            ))?;
            out.advance(17);
            registers(
                out,
                b,
                17,
                usize::from(write_count),
                Some(write_start.into()),
                12..14,
            )?;
        }
        Pdu::FifoRequest => out.add(Record::new(
            "fifo_request",
            8..10,
            vec![num("fifo_pointer_address", uint(b, 8, 2, false), 8, 10)],
        ))?,
        Pdu::FifoData(data) => {
            out.add(Record::new(
                "fifo_response",
                8..12,
                vec![
                    num("byte_count", (data.len() + 2) as u64, 8, 10),
                    num("fifo_count", (data.len() / 2) as u64, 10, 12),
                ],
            ))?;
            out.advance(12);
            registers(out, b, 12, data.len() / 2, None, 0..0)?;
        }
        Pdu::Files(records) => {
            out.add(Record::new(
                "file_record_list",
                8..9,
                vec![num("byte_count", b[8].into(), 8, 9)],
            ))?;
            out.advance(9);
            for record in records {
                let at = 7 + record.offset;
                let (width, fields) = match record.address {
                    Some((file, index)) => (
                        7,
                        vec![
                            num("reference_type", 6, at, at + 1),
                            num("file_number", file.into(), at + 1, at + 3),
                            num("record_number", index.into(), at + 3, at + 5),
                            num("record_words", record.words.into(), at + 5, at + 7),
                        ],
                    ),
                    None => (
                        2,
                        vec![
                            num("response_length", b[at].into(), at, at + 1),
                            num("reference_type", 6, at + 1, at + 2),
                        ],
                    ),
                };
                out.add(Record::new("file_record", at..at + width, fields))?;
                out.advance(at + width);
                registers(out, b, at + width, record.data.len() / 2, None, 0..0)?;
            }
        }
        Pdu::DeviceRequest => out.add(Record::new(
            "device_id_request",
            8..11,
            vec![
                num("mei_type", 14, 8, 9),
                num("read_category", b[9].into(), 9, 10),
                num("object_id", b[10].into(), 10, 11),
            ],
        ))?,
        Pdu::DevicePage(objects) => {
            out.add(Record::new(
                "device_id_page",
                8..14,
                vec![
                    num("mei_type", 14, 8, 9),
                    num("read_category", b[9].into(), 9, 10),
                    num("conformity_level", b[10].into(), 10, 11),
                    num("more_follows", b[11].into(), 11, 12),
                    num("next_object_id", b[12].into(), 12, 13),
                    num("object_count", b[13].into(), 13, 14),
                ],
            ))?;
            out.advance(14);
            for object in objects {
                let at = 7 + object.offset;
                let end = at + 2 + object.value.len();
                let mut fields = vec![
                    num("object_id", object.id.into(), at, at + 1),
                    num("object_length", object.value.len() as u64, at + 1, at + 2),
                ];
                if !object.value.is_empty() {
                    fields.push(Field::new(
                        "object_value",
                        Value::OctetsSha256 {
                            length: object.value.len(),
                            digest: crate::sha256::digest(object.value),
                        },
                        at + 2..end,
                    ));
                }
                out.add(Record::new("device_id_object", at..end, fields))?;
                out.advance(end);
            }
        }
        Pdu::Opaque => {
            return Err(fail(
                ErrorCode::UnsupportedTransport,
                7,
                "modbus_function_outside_field_subset",
            ))
        }
    }
    out.advance(b.len());
    Ok(())
}
pub fn decode(source: &EvidenceBytes, role: Role, limits: Limits) -> Result<Report<'_>> {
    decode_with(source, role, limits, || {
        pdu::parse(&source.data()[7..], role)
    })
}
fn decode_with<'a>(
    source: &'a EvidenceBytes,
    role: Role,
    limits: Limits,
    parse: impl FnOnce() -> Result<Pdu<'a>>,
) -> Result<Report<'a>> {
    let mut out = Report::new(source, "modbus", role.as_str(), limits)?;
    if let Err(e) = decode_body(source.data(), role, &mut out, parse) {
        let at = out.consumed();
        out.stop(e, at);
    }
    Ok(out)
}
/// Unknown direction yields two explicitly attributed interpretations, including
/// rejected alternatives. No array element is silently selected as authoritative.
pub fn alternatives_json(source: &EvidenceBytes, role: Role, limits: Limits) -> Json {
    render(
        role,
        &limits,
        || super::as_json(decode(source, Role::Request, limits.clone())),
        || super::as_json(decode(source, Role::Response, limits.clone())),
    )
}

/// A framed ADU received without a known direction. Keep both grammar results
/// until the caller selects a role, so correlation and fields use the same PDU.
pub struct FramedAdu<'a> {
    source: &'a EvidenceBytes,
    request: Result<Pdu<'a>>,
    response: Result<Pdu<'a>>,
}
impl<'a> FramedAdu<'a> {
    pub fn new(source: &'a EvidenceBytes) -> Result<Self> {
        envelope(source.data())?;
        let bytes = &source.data()[7..];
        Ok(Self {
            source,
            request: pdu::parse(bytes, Role::Request),
            response: pdu::parse(bytes, Role::Response),
        })
    }
    pub fn shapes(&self) -> (bool, bool) {
        (self.request.is_ok(), self.response.is_ok())
    }
    pub fn supported(&self) -> bool {
        pdu::supported(&self.source.data()[7..])
    }
    pub fn token(&self, role: Role) -> Option<String> {
        let parsed = match role {
            Role::Request => &self.request,
            Role::Response => &self.response,
            Role::Unknown => return None,
        };
        Some(Summary::from_pdu(&self.source.data()[7..], parsed.as_ref().ok()?)?.token())
    }
    pub fn fields(self, role: Role, limits: Limits) -> Json {
        let project =
            |r, result| super::as_json(decode_with(self.source, r, limits.clone(), || result));
        render(
            role,
            &limits,
            || project(Role::Request, self.request),
            || project(Role::Response, self.response),
        )
    }
}
fn render(
    role: Role,
    limits: &Limits,
    request: impl FnOnce() -> Json,
    response: impl FnOnce() -> Json,
) -> Json {
    let interpretations = match role {
        Role::Request => vec![request()],
        Role::Response => vec![response()],
        Role::Unknown => vec![request(), response()],
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
        ("interpretations", Json::Array(interpretations)),
        ("device_effect_established", false.into()),
    ]);
    match result.encoded_len_bounded(limits.max_json_bytes) {
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
/// Legacy tokens remain accepted at the public plugin boundary.
pub fn compatibility_matches(request: &str, response: &str) -> bool {
    crate::modbus::transaction::matches(request, response)
}
