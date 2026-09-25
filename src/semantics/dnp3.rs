//! DNP3 object header/value subset over source-bound object bytes. Callers must
//! supply a complete fragment or verified complete application-message assembly;
//! raw APDU headers are never joined into object bytes. The workflow extension
//! adds only group-50 variation-1/3 count-one time writes, bounded Group-70 file
//! control values, and group-60 variation-2/3/4 all-object unsolicited controls.
//! Group-0 attribute envelopes are
//! decoded only as source-bound typed/hashed evidence; attribute names, device
//! state, security meaning, and vendor semantics are never inferred. Group-70
//! free-format file objects 3--8 are decoded as bounded metadata/content-hash
//! evidence; authentication variation 2 remains opaque.
//! Other writes and unknown variable-width objects remain an undecoded tail.
use super::{fail, need, uint, Field, Limits, Record, Report, Value};
use crate::{provenance::EvidenceBytes, ErrorCode, Result};
use std::ops::Range;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Context {
    ReadHeaders,
    ResponseValues,
    ControlValues,
    TimeWriteValues,
    FileValues,
    ClassHeaders,
    UnsupportedFunction,
}
impl Context {
    pub fn from_function(function: u8) -> Self {
        match function {
            1 => Self::ReadHeaders,
            2 => Self::TimeWriteValues,
            25..=28 | 30 => Self::FileValues,
            20 | 21 => Self::ClassHeaders,
            0x81 | 0x82 => Self::ResponseValues,
            3..=6 => Self::ControlValues,
            _ => Self::UnsupportedFunction,
        }
    }
    fn name(self) -> &'static str {
        match self {
            Self::ReadHeaders => "read_object_headers",
            Self::ResponseValues => "response_object_values",
            Self::ControlValues => "control_object_values",
            Self::TimeWriteValues => "non_secure_time_write_values",
            Self::FileValues => "file_control_values",
            Self::ClassHeaders => "unsolicited_class_headers",
            Self::UnsupportedFunction => "function_not_in_subset",
        }
    }
}
#[derive(Clone, Copy)]
enum Shape {
    Packed {
        bits: u8,
    },
    Binary {
        bits: u8,
        time: usize,
    },
    Counter {
        width: usize,
        flags: bool,
        time: usize,
    },
    Analog {
        width: usize,
        flags: bool,
        float: bool,
        signed: bool,
        time: usize,
        status_last: bool,
    },
    Time {
        width: usize,
    },
    Octets {
        width: usize,
    },
    Attribute,
    ControlRelayOutput,
}
fn shape(group: u8, variation: u8) -> Option<Shape> {
    Some(match (group, variation) {
        (0, 0..=253 | 255) => Shape::Attribute,
        (1 | 10 | 80, 1) => Shape::Packed { bits: 1 },
        (3, 1) => Shape::Packed { bits: 2 },
        (1 | 10 | 80, 2) | (2 | 11 | 13, 1) => Shape::Binary { bits: 1, time: 0 },
        (4, 1) => Shape::Binary { bits: 2, time: 0 },
        (3, 2) => Shape::Binary { bits: 2, time: 0 },
        (2 | 11 | 13, 2) => Shape::Binary { bits: 1, time: 6 },
        (4, 2) => Shape::Binary { bits: 2, time: 6 },
        (2 | 11 | 13, 3) => Shape::Binary { bits: 1, time: 2 },
        (4, 3) => Shape::Binary { bits: 2, time: 2 },
        (3, 3) => Shape::Binary { bits: 2, time: 6 },
        (3, 4) => Shape::Binary { bits: 2, time: 2 },
        (20..=23, 1) => Shape::Counter {
            width: 4,
            flags: true,
            time: 0,
        },
        (20..=23, 2) => Shape::Counter {
            width: 2,
            flags: true,
            time: 0,
        },
        (21..=23, 5) => Shape::Counter {
            width: 4,
            flags: true,
            time: 6,
        },
        (21..=23, 6) => Shape::Counter {
            width: 2,
            flags: true,
            time: 6,
        },
        (20 | 21, 5 | 9) => Shape::Counter {
            width: 4,
            flags: false,
            time: 0,
        },
        (20 | 21, 6 | 10) => Shape::Counter {
            width: 2,
            flags: false,
            time: 0,
        },
        (30, 1) => Shape::Analog {
            width: 4,
            flags: true,
            float: false,
            signed: true,
            time: 0,
            status_last: false,
        },
        (30, 2) => Shape::Analog {
            width: 2,
            flags: true,
            float: false,
            signed: true,
            time: 0,
            status_last: false,
        },
        (30, 3) => Shape::Analog {
            width: 4,
            flags: false,
            float: false,
            signed: true,
            time: 0,
            status_last: false,
        },
        (30, 4) => Shape::Analog {
            width: 2,
            flags: false,
            float: false,
            signed: true,
            time: 0,
            status_last: false,
        },
        (30, 5) => Shape::Analog {
            width: 4,
            flags: true,
            float: true,
            signed: false,
            time: 0,
            status_last: false,
        },
        (30, 6) => Shape::Analog {
            width: 8,
            flags: true,
            float: true,
            signed: false,
            time: 0,
            status_last: false,
        },
        (31, 1) => Shape::Analog {
            width: 4,
            flags: true,
            float: false,
            signed: true,
            time: 0,
            status_last: false,
        },
        (31, 2) => Shape::Analog {
            width: 2,
            flags: true,
            float: false,
            signed: true,
            time: 0,
            status_last: false,
        },
        (31, 3) => Shape::Analog {
            width: 4,
            flags: true,
            float: false,
            signed: true,
            time: 6,
            status_last: false,
        },
        (31, 4) => Shape::Analog {
            width: 2,
            flags: true,
            float: false,
            signed: true,
            time: 6,
            status_last: false,
        },
        (31, 5) => Shape::Analog {
            width: 4,
            flags: false,
            float: false,
            signed: true,
            time: 0,
            status_last: false,
        },
        (31, 6) => Shape::Analog {
            width: 2,
            flags: false,
            float: false,
            signed: true,
            time: 0,
            status_last: false,
        },
        (31, 7) => Shape::Analog {
            width: 4,
            flags: true,
            float: true,
            signed: false,
            time: 0,
            status_last: false,
        },
        (31, 8) => Shape::Analog {
            width: 8,
            flags: true,
            float: true,
            signed: false,
            time: 0,
            status_last: false,
        },
        (32 | 33 | 42 | 43, 1 | 3 | 5 | 7) => Shape::Analog {
            width: 4,
            flags: true,
            float: matches!(variation, 5 | 7),
            signed: matches!(variation, 1 | 3),
            time: if matches!(variation, 3 | 7) { 6 } else { 0 },
            status_last: false,
        },
        (32 | 33 | 42 | 43, 2 | 4 | 6 | 8) => Shape::Analog {
            width: if matches!(variation, 2 | 4) { 2 } else { 8 },
            flags: true,
            float: matches!(variation, 6 | 8),
            signed: matches!(variation, 2 | 4),
            time: if matches!(variation, 4 | 8) { 6 } else { 0 },
            status_last: false,
        },
        (34, 1) => Shape::Analog {
            width: 2,
            flags: false,
            float: false,
            signed: false,
            time: 0,
            status_last: false,
        },
        (34, 2) => Shape::Analog {
            width: 4,
            flags: false,
            float: false,
            signed: false,
            time: 0,
            status_last: false,
        },
        (34, 3) => Shape::Analog {
            width: 4,
            flags: false,
            float: true,
            signed: false,
            time: 0,
            status_last: false,
        },
        (40, 1..=4) => Shape::Analog {
            width: match variation {
                1 | 3 => 4,
                2 => 2,
                4 => 8,
                _ => unreachable!(),
            },
            flags: true,
            float: matches!(variation, 3 | 4),
            signed: matches!(variation, 1 | 2),
            time: 0,
            status_last: false,
        },
        (41, 1..=4) => Shape::Analog {
            width: match variation {
                1 | 3 => 4,
                2 => 2,
                4 => 8,
                _ => unreachable!(),
            },
            flags: false,
            float: matches!(variation, 3 | 4),
            signed: matches!(variation, 1 | 2),
            time: 0,
            status_last: true,
        },
        (50, 1 | 3) | (51, 1 | 2) => Shape::Time { width: 6 },
        (52, 1 | 2) => Shape::Time { width: 2 },
        (102, 1) => Shape::Counter {
            width: 1,
            flags: false,
            time: 0,
        },
        (110 | 111, 1..=255) => Shape::Octets {
            width: variation.into(),
        },
        (12, 1) => Shape::ControlRelayOutput,
        _ => return None,
    })
}
fn known_header(g: u8, v: u8) -> bool {
    shape(g, v).is_some()
        || (g == 0 && v == 254)
        || (v == 0
            && matches!(
                g,
                1 | 2
                    | 3
                    | 4
                    | 10
                    | 11
                    | 13
                    | 20
                    | 21
                    | 22
                    | 23
                    | 30
                    | 31
                    | 32
                    | 33
                    | 34
                    | 40
                    | 41
                    | 42
                    | 43
                    | 102
                    | 110
                    | 111
            ))
        || (g == 60 && (1..=4).contains(&v))
        || (g == 70 && (2..=8).contains(&v))
}
struct Header {
    group: u8,
    variation: u8,
    qualifier: u8,
    count: Option<usize>,
    first: Option<u64>,
    prefix: usize,
    range_witness: Range<usize>,
}
fn parse_header(b: &[u8], p: &mut usize, out: &mut Report<'_>) -> Result<Header> {
    let start = *p;
    need(b, start, 3, "dnp3_object_header_truncated")?;
    let g = b[start];
    let v = b[start + 1];
    let q = b[start + 2];
    if !known_header(g, v) {
        return Err(fail(
            ErrorCode::UnsupportedTransport,
            start,
            "dnp3_group_variation_outside_subset",
        ));
    }
    let mut fields = vec![
        Field::new("group", Value::Unsigned(g.into()), start..start + 1),
        Field::new("variation", Value::Unsigned(v.into()), start + 1..start + 2),
        Field::new("qualifier", Value::Unsigned(q.into()), start + 2..start + 3),
    ];
    let at = start + 3;
    let prefix_code = q >> 4;
    let range_code = q & 0x0f;
    let (count, first, prefix, end) = match (prefix_code, range_code) {
        (0, 0..=2) => {
            let n = 1usize << usize::from(range_code);
            need(b, at, n * 2, "dnp3_range_truncated")?;
            let first = uint(b, at, n, true);
            let last = uint(b, at + n, n, true);
            if first > last {
                return Err(fail(ErrorCode::InvalidLength, at, "dnp3_inverted_range"));
            }
            let count = usize::try_from(last - first + 1)
                .map_err(|_| fail(ErrorCode::LimitExceeded, at, "dnp3_range_count"))?;
            fields.push(Field::new(
                "range_start",
                Value::Unsigned(first),
                at..at + n,
            ));
            fields.push(Field::new(
                "range_stop",
                Value::Unsigned(last),
                at + n..at + n * 2,
            ));
            (Some(count), Some(first), 0, at + n * 2)
        }
        (0, 6) => (None, None, 0, at),
        (0..=3, 7..=9) => {
            let n = 1usize << usize::from(range_code - 7);
            need(b, at, n, "dnp3_count_truncated")?;
            let count = usize::try_from(uint(b, at, n, true))
                .map_err(|_| fail(ErrorCode::LimitExceeded, at, "dnp3_count"))?;
            fields.push(Field::new(
                "count",
                Value::Unsigned(count as u64),
                at..at + n,
            ));
            let prefix = match prefix_code {
                0 => 0,
                1 => 1,
                2 => 2,
                3 => 4,
                _ => unreachable!(),
            };
            (Some(count), None, prefix, at + n)
        }
        (5, 11) if g == 70 && matches!(v, 2..=8) => {
            need(b, at, 1, "dnp3_file_object_count_truncated")?;
            let count = usize::from(b[at]);
            fields.push(Field::new(
                "count",
                Value::Unsigned(count as u64),
                at..at + 1,
            ));
            (Some(count), None, 0, at + 1)
        }
        _ => {
            return Err(fail(
                ErrorCode::UnsupportedTransport,
                start + 2,
                "dnp3_qualifier_outside_subset",
            ))
        }
    };
    out.add(Record::new("object_header", start..end, fields))?;
    *p = end;
    Ok(Header {
        group: g,
        variation: v,
        qualifier: q,
        count,
        first,
        prefix,
        range_witness: at..end,
    })
}
fn index_field(h: &Header, ordinal: usize, b: &[u8], p: usize) -> Option<Field> {
    if h.prefix > 0 {
        Some(Field::new(
            "point_index",
            Value::Unsigned(uint(b, p, h.prefix, true)),
            p..p + h.prefix,
        ))
    } else {
        h.first.map(|first| {
            Field::derived(
                "point_index",
                first + ordinal as u64,
                h.range_witness.clone(),
                "range_start_plus_record_ordinal",
            )
        })
    }
}
fn is_boolean_attribute(variation: u8) -> bool {
    matches!(
        variation,
        219 | 222 | 225 | 226 | 227 | 230 | 231 | 234 | 237
    )
}
fn need_file_object_field(
    object_end: usize,
    at: usize,
    count: usize,
    field: &'static str,
) -> Result<()> {
    let end = at
        .checked_add(count)
        .ok_or_else(|| fail(ErrorCode::InvalidLength, at, field))?;
    if end > object_end {
        return Err(fail(ErrorCode::InvalidLength, at, field));
    }
    Ok(())
}

fn file_object_fields(b: &[u8], variation: u8, base: usize, length: usize) -> Result<Vec<Field>> {
    let mut fields = vec![Field::new(
        "length",
        Value::Unsigned(length as u64),
        base..base + 2,
    )];
    let data = base + 2;
    let object_end = data
        .checked_add(length)
        .ok_or_else(|| fail(ErrorCode::InvalidLength, data, "dnp3_file_object_range"))?;
    need(b, data, length, "dnp3_file_object_truncated")?;
    match variation {
        2 => {
            return Err(fail(
                ErrorCode::UnsupportedTransport,
                data,
                "dnp3_file_authentication_opaque",
            ));
        }
        3 => {
            need_file_object_field(object_end, data, 26, "dnp3_file_command")?;
            let name_offset = usize::from(uint(b, data, 2, true) as u16);
            let name_length = usize::from(uint(b, data + 2, 2, true) as u16);
            let name_end = name_offset
                .checked_add(name_length)
                .ok_or_else(|| fail(ErrorCode::InvalidLength, data, "dnp3_file_name_range"))?;
            if name_offset != 26 || name_end != length {
                return Err(fail(ErrorCode::InvalidLength, data, "dnp3_file_name_range"));
            }
            fields.extend([
                Field::new(
                    "file_name_offset",
                    Value::Unsigned(name_offset as u64),
                    data..data + 2,
                ),
                Field::new(
                    "file_name_length",
                    Value::Unsigned(name_length as u64),
                    data + 2..data + 4,
                ),
                Field::new(
                    "creation_time",
                    Value::Milliseconds48(uint(b, data + 4, 6, true)),
                    data + 4..data + 10,
                ),
                Field::new(
                    "permissions",
                    Value::Unsigned(uint(b, data + 10, 2, true)),
                    data + 10..data + 12,
                ),
                Field::new(
                    "auth_key",
                    Value::OctetsSha256 {
                        length: 4,
                        digest: crate::sha256::digest(&b[data + 12..data + 16]),
                    },
                    data + 12..data + 16,
                ),
                Field::new(
                    "file_size",
                    Value::Unsigned(uint(b, data + 16, 4, true)),
                    data + 16..data + 20,
                ),
                Field::new(
                    "mode",
                    Value::Unsigned(uint(b, data + 20, 2, true)),
                    data + 20..data + 22,
                ),
                Field::new(
                    "maximum_block_size",
                    Value::Unsigned(uint(b, data + 22, 2, true)),
                    data + 22..data + 24,
                ),
                Field::new(
                    "request_id",
                    Value::Unsigned(uint(b, data + 24, 2, true)),
                    data + 24..data + 26,
                ),
            ]);
            if name_length > 0 {
                fields.push(Field::new(
                    "file_name",
                    Value::OctetsSha256 {
                        length: name_length,
                        digest: crate::sha256::digest(&b[data + name_offset..data + name_end]),
                    },
                    data + name_offset..data + name_end,
                ));
            }
        }
        4 => {
            need_file_object_field(object_end, data, 13, "dnp3_file_command_status")?;
            fields.extend([
                Field::new(
                    "file_handle",
                    Value::Unsigned(uint(b, data, 4, true)),
                    data..data + 4,
                ),
                Field::new(
                    "file_size",
                    Value::Unsigned(uint(b, data + 4, 4, true)),
                    data + 4..data + 8,
                ),
                Field::new(
                    "maximum_block_size",
                    Value::Unsigned(uint(b, data + 8, 2, true)),
                    data + 8..data + 10,
                ),
                Field::new(
                    "request_id",
                    Value::Unsigned(uint(b, data + 10, 2, true)),
                    data + 10..data + 12,
                ),
                Field::new(
                    "status",
                    Value::Unsigned(b[data + 12].into()),
                    data + 12..data + 13,
                ),
            ]);
            let text_length = length - 13;
            fields.push(Field::derived(
                "status_text_length",
                text_length as u64,
                data + 12..data + 13,
                "file_object_length_minus_fixed_status_header",
            ));
            if text_length > 0 {
                fields.push(Field::new(
                    "status_text",
                    Value::OctetsSha256 {
                        length: text_length,
                        digest: crate::sha256::digest(&b[data + 13..object_end]),
                    },
                    data + 13..object_end,
                ));
            }
        }
        5 => {
            need_file_object_field(object_end, data, 8, "dnp3_file_transport")?;
            fields.extend([
                Field::new(
                    "file_handle",
                    Value::Unsigned(uint(b, data, 4, true)),
                    data..data + 4,
                ),
                Field::new(
                    "block_number",
                    Value::Unsigned(uint(b, data + 4, 4, true)),
                    data + 4..data + 8,
                ),
                Field::derived(
                    "content_length",
                    (length - 8) as u64,
                    data + 4..data + 8,
                    "file_object_length_minus_fixed_transport_header",
                ),
            ]);
            if length > 8 {
                fields.push(Field::new(
                    "content",
                    Value::OctetsSha256 {
                        length: length - 8,
                        digest: crate::sha256::digest(&b[data + 8..object_end]),
                    },
                    data + 8..object_end,
                ));
            }
        }
        6 => {
            need_file_object_field(object_end, data, 9, "dnp3_file_transport_status")?;
            fields.extend([
                Field::new(
                    "file_handle",
                    Value::Unsigned(uint(b, data, 4, true)),
                    data..data + 4,
                ),
                Field::new(
                    "block_number",
                    Value::Unsigned(uint(b, data + 4, 4, true)),
                    data + 4..data + 8,
                ),
                Field::new(
                    "status",
                    Value::Unsigned(b[data + 8].into()),
                    data + 8..data + 9,
                ),
            ]);
            let text_length = length - 9;
            fields.push(Field::derived(
                "status_text_length",
                text_length as u64,
                data + 8..data + 9,
                "file_object_length_minus_fixed_status_header",
            ));
            if text_length > 0 {
                fields.push(Field::new(
                    "status_text",
                    Value::OctetsSha256 {
                        length: text_length,
                        digest: crate::sha256::digest(&b[data + 9..object_end]),
                    },
                    data + 9..object_end,
                ));
            }
        }
        7 => {
            need_file_object_field(object_end, data, 20, "dnp3_file_descriptor")?;
            let name_offset = usize::from(uint(b, data, 2, true) as u16);
            let name_length = usize::from(uint(b, data + 2, 2, true) as u16);
            let name_end = name_offset
                .checked_add(name_length)
                .ok_or_else(|| fail(ErrorCode::InvalidLength, data, "dnp3_file_name_range"))?;
            if name_offset != 20 || name_end != length {
                return Err(fail(ErrorCode::InvalidLength, data, "dnp3_file_name_range"));
            }
            fields.extend([
                Field::new(
                    "file_name_offset",
                    Value::Unsigned(name_offset as u64),
                    data..data + 2,
                ),
                Field::new(
                    "file_name_length",
                    Value::Unsigned(name_length as u64),
                    data + 2..data + 4,
                ),
                Field::new(
                    "file_type",
                    Value::Unsigned(uint(b, data + 4, 2, true)),
                    data + 4..data + 6,
                ),
                Field::new(
                    "file_size",
                    Value::Unsigned(uint(b, data + 6, 4, true)),
                    data + 6..data + 10,
                ),
                Field::new(
                    "creation_time",
                    Value::Milliseconds48(uint(b, data + 10, 6, true)),
                    data + 10..data + 16,
                ),
                Field::new(
                    "permissions",
                    Value::Unsigned(uint(b, data + 16, 2, true)),
                    data + 16..data + 18,
                ),
                Field::new(
                    "request_id",
                    Value::Unsigned(uint(b, data + 18, 2, true)),
                    data + 18..data + 20,
                ),
            ]);
            if name_length > 0 {
                fields.push(Field::new(
                    "file_name",
                    Value::OctetsSha256 {
                        length: name_length,
                        digest: crate::sha256::digest(&b[data + name_offset..object_end]),
                    },
                    data + name_offset..object_end,
                ));
            }
        }
        8 => {
            fields.push(Field::derived(
                "file_specification_length",
                length as u64,
                base..base + 2,
                "file_object_payload_length",
            ));
            fields.push(Field::new(
                "file_specification",
                Value::OctetsSha256 {
                    length,
                    digest: crate::sha256::digest(&b[data..object_end]),
                },
                data..object_end,
            ));
        }
        _ => unreachable!(),
    }
    Ok(fields)
}
fn objects(b: &[u8], p: &mut usize, h: &Header, out: &mut Report<'_>) -> Result<()> {
    let Some(count) = h.count else {
        return Err(fail(
            ErrorCode::UnsupportedTransport,
            *p,
            "dnp3_all_objects_response_has_no_count",
        ));
    };
    if count > out.limits.max_records.saturating_sub(out.records.len()) {
        return Err(fail(
            ErrorCode::LimitExceeded,
            *p,
            "dnp3_object_count_budget",
        ));
    }
    if h.group == 70 && h.qualifier == 0x5b {
        for _ in 0..count {
            let length_at = *p;
            need(b, length_at, 2, "dnp3_file_object_length_truncated")?;
            let length = usize::from(uint(b, length_at, 2, true) as u16);
            let end = length_at
                .checked_add(2)
                .and_then(|at| at.checked_add(length))
                .ok_or_else(|| {
                    fail(
                        ErrorCode::InvalidLength,
                        length_at,
                        "dnp3_file_object_range",
                    )
                })?;
            need(b, length_at + 2, length, "dnp3_file_object_truncated")?;
            let fields = file_object_fields(b, h.variation, length_at, length)?;
            out.add(Record::new("file_object", length_at..end, fields))?;
            *p = end;
        }
        return Ok(());
    }
    let s = shape(h.group, h.variation).ok_or_else(|| {
        fail(
            ErrorCode::UnsupportedTransport,
            *p,
            "dnp3_response_variation_has_no_value_width",
        )
    })?;
    if matches!(s, Shape::Attribute) {
        for ordinal in 0..count {
            let at = *p;
            need(b, at, h.prefix + 2, "dnp3_attribute_envelope_truncated")?;
            let data = at + h.prefix;
            let data_type = b[data];
            let encoded_length = usize::from(b[data + 1]);
            // Attribute-list data type 255 uses the one-byte length as an
            // offset from 256.  The ordinary list type 254 uses the raw
            // length.  Keep the encoded octet and the effective value span
            // separate so the report never loses wire identity.
            let length = if data_type == 255 {
                256 + encoded_length
            } else {
                encoded_length
            };
            let value_start = data + 2;
            need(b, value_start, length, "dnp3_attribute_value_truncated")?;
            let value_end = value_start + length;
            let mut fields = Vec::new();
            if let Some(f) = index_field(h, ordinal, b, at) {
                fields.push(f);
            }
            fields.push(Field::new(
                "data_type",
                Value::Unsigned(data_type.into()),
                data..data + 1,
            ));
            fields.push(Field::new(
                "length",
                Value::Unsigned(encoded_length as u64),
                data + 1..data + 2,
            ));
            if data_type == 255 {
                fields.push(Field::derived(
                    "value_length",
                    length as u64,
                    data + 1..data + 2,
                    "extended_attribute_length_plus_256",
                ));
            }
            let value = match data_type {
                // Keep arbitrary device metadata hash-only in semantic JSON.
                1 | 5 | 6 => Value::OctetsSha256 {
                    length,
                    digest: crate::sha256::digest(&b[value_start..value_end]),
                },
                2 => match length {
                    1 | 2 | 4 => Value::Unsigned(uint(b, value_start, length, true)),
                    _ => {
                        return Err(fail(
                            ErrorCode::UnsupportedTransport,
                            value_start,
                            "dnp3_attribute_unsigned_width",
                        ))
                    }
                },
                3 => {
                    let signed = match length {
                        1 => i64::from(b[value_start] as i8),
                        2 => i64::from(uint(b, value_start, length, true) as u16 as i16),
                        4 => i64::from(uint(b, value_start, length, true) as u32 as i32),
                        _ => {
                            return Err(fail(
                                ErrorCode::UnsupportedTransport,
                                value_start,
                                "dnp3_attribute_signed_width",
                            ))
                        }
                    };
                    if is_boolean_attribute(h.variation) && signed != 0 && signed != 1 {
                        out.warn("dnp3_attribute_boolean_non_binary", value_start..value_end);
                    }
                    if is_boolean_attribute(h.variation) && (signed == 0 || signed == 1) {
                        Value::Boolean(signed == 1)
                    } else {
                        Value::Signed(signed)
                    }
                }
                4 => match length {
                    4 => Value::Float32Bits(uint(b, value_start, length, true) as u32),
                    8 => Value::Float64Bits(uint(b, value_start, length, true)),
                    _ => {
                        return Err(fail(
                            ErrorCode::UnsupportedTransport,
                            value_start,
                            "dnp3_attribute_float_width",
                        ))
                    }
                },
                7 if length == 6 => Value::Milliseconds48(uint(b, value_start, length, true)),
                7 => {
                    return Err(fail(
                        ErrorCode::UnsupportedTransport,
                        value_start,
                        "dnp3_attribute_time_width",
                    ))
                }
                254 | 255 if length % 2 == 0 => {
                    for (ordinal, entry) in b[value_start..value_end].chunks_exact(2).enumerate() {
                        let entry_at = value_start + ordinal * 2;
                        let entry_fields = vec![
                            Field::new(
                                "variation",
                                Value::Unsigned(entry[0].into()),
                                entry_at..entry_at + 1,
                            ),
                            Field::new(
                                "properties",
                                Value::Unsigned(entry[1].into()),
                                entry_at + 1..entry_at + 2,
                            ),
                        ];
                        out.add(Record::new(
                            "attribute_list_entry",
                            entry_at..entry_at + 2,
                            entry_fields,
                        ))?;
                    }
                    fields.push(Field::derived(
                        "list_entry_count",
                        (length / 2) as u64,
                        value_start..value_end,
                        "attribute_list_pairs",
                    ));
                    Value::OctetsSha256 {
                        length,
                        digest: crate::sha256::digest(&b[value_start..value_end]),
                    }
                }
                254 | 255 => {
                    return Err(fail(
                        ErrorCode::UnsupportedTransport,
                        value_start,
                        "dnp3_attribute_list_width",
                    ))
                }
                _ => {
                    out.warn("dnp3_attribute_data_type_opaque", data..value_end);
                    Value::OctetsSha256 {
                        length,
                        digest: crate::sha256::digest(&b[value_start..value_end]),
                    }
                }
            };
            fields.push(Field::new("value", value, value_start..value_end));
            out.add(Record::new("attribute_value", at..value_end, fields))?;
            *p = value_end;
        }
        return Ok(());
    }
    if let Shape::Packed { bits } = s {
        if h.first.is_none() || h.prefix != 0 {
            return Err(fail(
                ErrorCode::UnsupportedTransport,
                *p,
                "dnp3_packed_requires_range_qualifier",
            ));
        }
        let bits = usize::from(bits);
        let bytes = (count * bits).div_ceil(8);
        need(b, *p, bytes, "dnp3_packed_truncated")?;
        for ordinal in 0..count {
            let bit_offset = ordinal * bits;
            let at = *p + bit_offset / 8;
            let mut fields = Vec::new();
            if let Some(f) = index_field(h, ordinal, b, *p) {
                fields.push(f);
            }
            if bits == 1 {
                fields.push(Field::bit_field(
                    "value",
                    b[at] & (1 << (bit_offset % 8)) != 0,
                    at,
                    (bit_offset % 8) as u8,
                ));
            } else {
                let mask = (1u8 << bits) - 1;
                fields.push(Field::new(
                    "value",
                    Value::Unsigned(u64::from((b[at] >> (bit_offset % 8)) & mask)),
                    at..at + 1,
                ));
            }
            out.add(Record::new("object_value", at..at + 1, fields))?;
        }
        *p += bytes;
        return Ok(());
    }
    let width = match s {
        Shape::Binary { time, .. } => 1 + time,
        Shape::Counter { width, flags, time } => width + usize::from(flags) + time,
        Shape::Analog {
            width,
            flags,
            time,
            status_last,
            ..
        } => width + usize::from(flags) + time + usize::from(status_last),
        Shape::Time { width } => width,
        Shape::Octets { width } => width,
        Shape::Attribute => unreachable!(),
        Shape::ControlRelayOutput => 11,
        Shape::Packed { .. } => 0,
    };
    for ordinal in 0..count {
        let at = *p;
        need(b, at, h.prefix + width, "dnp3_object_value_truncated")?;
        let mut fields = Vec::new();
        if let Some(f) = index_field(h, ordinal, b, at) {
            fields.push(f);
        }
        let data = at + h.prefix;
        match s {
            Shape::Binary { bits, time } => {
                fields.push(Field::new(
                    "flags",
                    Value::Unsigned(b[data].into()),
                    data..data + 1,
                ));
                if bits == 1 {
                    fields.push(Field::bit_field("value", b[data] & 0x80 != 0, data, 7));
                } else {
                    fields.push(Field::new(
                        "value",
                        Value::Unsigned(u64::from((b[data] >> 6) & 0x03)),
                        data..data + 1,
                    ));
                }
                if time > 0 {
                    let n = uint(b, data + 1, time, true);
                    fields.push(Field::new(
                        "time",
                        if time == 6 {
                            Value::Milliseconds48(n)
                        } else {
                            Value::RelativeMilliseconds16(n as u16)
                        },
                        data + 1..data + 1 + time,
                    ));
                }
            }
            Shape::Counter { width, flags, time } => {
                if flags {
                    fields.push(Field::new(
                        "flags",
                        Value::Unsigned(b[data].into()),
                        data..data + 1,
                    ));
                }
                let v = data + usize::from(flags);
                let n = uint(b, v, width, true);
                fields.push(Field::new("value", Value::Unsigned(n), v..v + width));
                if time > 0 {
                    let time_value = uint(b, v + width, time, true);
                    fields.push(Field::new(
                        "time",
                        if time == 6 {
                            Value::Milliseconds48(time_value)
                        } else {
                            Value::RelativeMilliseconds16(time_value as u16)
                        },
                        v + width..v + width + time,
                    ));
                }
            }
            Shape::Analog {
                width,
                flags,
                float,
                signed,
                time,
                status_last,
            } => {
                if flags {
                    fields.push(Field::new(
                        "flags",
                        Value::Unsigned(b[data].into()),
                        data..data + 1,
                    ));
                }
                let v = data + usize::from(flags);
                let n = uint(b, v, width, true);
                let value = if float {
                    if width == 4 {
                        Value::Float32Bits(n as u32)
                    } else {
                        Value::Float64Bits(n)
                    }
                } else if signed {
                    if width == 2 {
                        Value::Signed(i64::from(n as u16 as i16))
                    } else {
                        Value::Signed(i64::from(n as u32 as i32))
                    }
                } else {
                    Value::Unsigned(n)
                };
                fields.push(Field::new("value", value, v..v + width));
                if time > 0 {
                    fields.push(Field::new(
                        "time",
                        Value::Milliseconds48(uint(b, v + width, time, true)),
                        v + width..v + width + time,
                    ));
                }
                if status_last {
                    fields.push(Field::new(
                        "command_status",
                        Value::Unsigned(b[v + width].into()),
                        v + width..v + width + 1,
                    ));
                }
            }
            Shape::Time { width } => fields.push(Field::new(
                if width == 6 { "time" } else { "time_delay" },
                if width == 6 {
                    Value::Milliseconds48(uint(b, data, width, true))
                } else {
                    Value::Unsigned(uint(b, data, width, true))
                },
                data..data + width,
            )),
            Shape::Octets { width } => fields.push(Field::new(
                "value",
                Value::OctetsSha256 {
                    length: width,
                    digest: crate::sha256::digest(&b[data..data + width]),
                },
                data..data + width,
            )),
            Shape::Attribute => unreachable!(),
            Shape::ControlRelayOutput => {
                fields.extend([
                    Field::new(
                        "control_code",
                        Value::Unsigned(b[data].into()),
                        data..data + 1,
                    ),
                    Field::new(
                        "count",
                        Value::Unsigned(b[data + 1].into()),
                        data + 1..data + 2,
                    ),
                    Field::new(
                        "on_time_ms",
                        Value::Unsigned(uint(b, data + 2, 4, true)),
                        data + 2..data + 6,
                    ),
                    Field::new(
                        "off_time_ms",
                        Value::Unsigned(uint(b, data + 6, 4, true)),
                        data + 6..data + 10,
                    ),
                    Field::new(
                        "status",
                        Value::Unsigned(b[data + 10].into()),
                        data + 10..data + 11,
                    ),
                ]);
            }
            Shape::Packed { .. } => {}
        }
        out.add(Record::new(
            "object_value",
            at..at + h.prefix + width,
            fields,
        ))?;
        *p += h.prefix + width;
    }
    Ok(())
}

pub fn decode(source: &EvidenceBytes, context: Context, limits: Limits) -> Result<Report<'_>> {
    let mut out = Report::new(source, "dnp3", context.name(), limits)?;
    if context == Context::UnsupportedFunction {
        out.stop(
            fail(
                ErrorCode::UnsupportedTransport,
                0,
                "dnp3_application_function_not_in_subset",
            ),
            0,
        );
        return Ok(out);
    }
    let b = source.data();
    let mut p = 0;
    if b.is_empty()
        && matches!(
            context,
            Context::TimeWriteValues | Context::FileValues | Context::ClassHeaders
        )
    {
        out.stop(
            fail(
                ErrorCode::ProtocolFraming,
                0,
                "dnp3_workflow_objects_required",
            ),
            0,
        );
        return Ok(out);
    }
    while p < b.len() {
        let result = (|| -> Result<()> {
            let start = p;
            let h = parse_header(b, &mut p, &mut out)?;
            if context == Context::ReadHeaders
                && h.group == 0
                && h.variation == 254
                && b[start + 2] != 0
            {
                return Err(fail(
                    ErrorCode::UnsupportedTransport,
                    start + 2,
                    "dnp3_attribute_all_request_requires_range",
                ));
            }
            if context == Context::TimeWriteValues
                && !(h.group == 50
                    && matches!(h.variation, 1 | 3)
                    && b[start + 2] == 7
                    && h.count == Some(1))
            {
                return Err(fail(
                    ErrorCode::UnsupportedTransport,
                    start,
                    "dnp3_time_write_requires_g50v1_or_v3_count_one",
                ));
            }
            if context == Context::FileValues && !(h.group == 70 && h.qualifier == 0x5b) {
                return Err(fail(
                    ErrorCode::UnsupportedTransport,
                    start,
                    "dnp3_file_control_requires_group70_free_format",
                ));
            }
            if context == Context::ClassHeaders
                && (h.group != 60 || !matches!(h.variation, 2..=4) || b[start + 2] != 6)
            {
                return Err(fail(
                    ErrorCode::UnsupportedTransport,
                    start,
                    "dnp3_unsolicited_control_requires_class_all_objects",
                ));
            }
            if context == Context::ControlValues && (h.group, h.variation) != (12, 1) {
                return Err(fail(
                    ErrorCode::UnsupportedTransport,
                    p,
                    "dnp3_control_function_object_mismatch",
                ));
            }
            if matches!(context, Context::ReadHeaders | Context::ClassHeaders) {
                if h.prefix != 0 {
                    let Some(count) = h.count else {
                        return Err(fail(
                            ErrorCode::UnsupportedTransport,
                            p,
                            "dnp3_read_index_list_without_count",
                        ));
                    };
                    for ordinal in 0..count {
                        need(b, p, h.prefix, "dnp3_read_index_truncated")?;
                        let index = uint(b, p, h.prefix, true);
                        out.add(Record::new(
                            "read_point_selector",
                            p..p + h.prefix,
                            vec![Field::new(
                                "point_index",
                                Value::Unsigned(index),
                                p..p + h.prefix,
                            )],
                        ))?;
                        p += h.prefix;
                        if ordinal == count.saturating_sub(1) {
                            out.advance(p);
                        }
                    }
                }
            } else {
                objects(b, &mut p, &h, &mut out)?;
            }
            Ok(())
        })();
        if let Err(e) = result {
            out.stop(e, p);
            return Ok(out);
        }
        out.advance(p);
    }
    Ok(out)
}

pub fn fragment_json(
    fragment: &crate::dnp3::ApplicationFragment,
    limits: Limits,
) -> crate::json::Json {
    // The public fragment type is mutable by callers. Do not let a forged
    // metadata field select semantics inconsistent with its actual raw bytes.
    let result = (|| -> Result<Report<'_>> {
        let raw = fragment.raw.data();
        let header = if matches!(fragment.function, 0x81 | 0x82) {
            4
        } else {
            2
        };
        if raw.len() < header || raw[0] != fragment.control || raw[1] != fragment.function {
            return Err(fail(
                ErrorCode::Invariant,
                0,
                "dnp3_fragment_metadata_mismatch",
            ));
        }
        let expected = fragment.raw.slice(header..raw.len())?;
        if expected.data() != fragment.objects.data()
            || expected.spans() != fragment.objects.spans()
        {
            return Err(fail(
                ErrorCode::Invariant,
                header,
                "dnp3_fragment_object_witness_mismatch",
            ));
        }
        if raw[0] & 0xc0 != 0xc0 {
            let mut out = Report::new(
                &fragment.objects,
                "dnp3",
                "incomplete_application_message",
                limits,
            )?;
            out.stop(
                fail(
                    ErrorCode::Truncated,
                    0,
                    "dnp3_application_fragment_needs_assembly",
                ),
                0,
            );
            return Ok(out);
        }
        decode(
            &fragment.objects,
            Context::from_function(fragment.function),
            limits,
        )
    })();
    super::as_json(result)
}

/// Decode a complete application message assembled from verified fragments.
/// The message bytes remain source-bound, while the semantic report can span
/// an object split across application-fragment boundaries.
pub fn message_json(objects: &EvidenceBytes, function: u8, limits: Limits) -> crate::json::Json {
    super::as_json(decode(objects, Context::from_function(function), limits))
}

/// Projection adapter for a message whose completeness was decided by the root
/// reassembler. Incomplete bodies retain their exact hash/tail and never become
/// a decoded message merely because their captured prefix ends at an object.
pub fn assembled_message_json(
    objects: &EvidenceBytes,
    function: u8,
    complete: bool,
    limits: Limits,
) -> crate::json::Json {
    if complete {
        return message_json(objects, function, limits);
    }
    super::as_json((|| {
        let mut out = Report::new(objects, "dnp3", "incomplete_application_message", limits)?;
        out.stop(
            fail(
                ErrorCode::Truncated,
                0,
                "dnp3_application_message_incomplete",
            ),
            0,
        );
        Ok(out)
    })())
}
