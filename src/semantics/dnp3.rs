//! DNP3 object header/value subset. Input is ONE application's fragment object
//! region after link/transport CRC/framing processing, never joined raw fragments.
//! Only READ headers and response object values are interpreted. Control, write,
//! authentication, file, and unknown-width objects remain an undecoded tail.
use super::{fail, need, uint, Field, Limits, Record, Report, Value};
use crate::{provenance::EvidenceBytes, ErrorCode, Result};
use std::ops::Range;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Context {
    ReadHeaders,
    ResponseValues,
    UnsupportedFunction,
}
impl Context {
    pub fn from_function(function: u8) -> Self {
        match function {
            1 => Self::ReadHeaders,
            0x81 | 0x82 => Self::ResponseValues,
            _ => Self::UnsupportedFunction,
        }
    }
    fn name(self) -> &'static str {
        match self {
            Self::ReadHeaders => "read_object_headers",
            Self::ResponseValues => "response_object_values",
            Self::UnsupportedFunction => "function_not_in_subset",
        }
    }
}
#[derive(Clone, Copy)]
enum Shape {
    Packed,
    Binary {
        time: usize,
    },
    Counter {
        width: usize,
        flags: bool,
    },
    Analog {
        width: usize,
        flags: bool,
        float: bool,
    },
    Time,
}
fn shape(group: u8, variation: u8) -> Option<Shape> {
    Some(match (group, variation) {
        (1 | 10, 1) => Shape::Packed,
        (1 | 10, 2) | (2, 1) => Shape::Binary { time: 0 },
        (2, 2) => Shape::Binary { time: 6 },
        (2, 3) => Shape::Binary { time: 2 },
        (20, 1) => Shape::Counter {
            width: 4,
            flags: true,
        },
        (20, 2) => Shape::Counter {
            width: 2,
            flags: true,
        },
        (20, 5) => Shape::Counter {
            width: 4,
            flags: false,
        },
        (20, 6) => Shape::Counter {
            width: 2,
            flags: false,
        },
        (30, 1) => Shape::Analog {
            width: 4,
            flags: true,
            float: false,
        },
        (30, 2) => Shape::Analog {
            width: 2,
            flags: true,
            float: false,
        },
        (30, 3) => Shape::Analog {
            width: 4,
            flags: false,
            float: false,
        },
        (30, 4) => Shape::Analog {
            width: 2,
            flags: false,
            float: false,
        },
        (30, 5) => Shape::Analog {
            width: 4,
            flags: true,
            float: true,
        },
        (30, 6) => Shape::Analog {
            width: 8,
            flags: true,
            float: true,
        },
        (50, 1) | (51, 1 | 2) => Shape::Time,
        _ => return None,
    })
}
fn known_header(g: u8, v: u8) -> bool {
    shape(g, v).is_some()
        || (v == 0 && matches!(g, 1 | 2 | 10 | 20 | 30))
        || (g == 60 && (1..=4).contains(&v))
}
struct Header {
    group: u8,
    variation: u8,
    count: Option<usize>,
    first: Option<u16>,
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
    let (count, first, prefix, end) = match q {
        0 | 1 => {
            let n = if q == 0 { 1 } else { 2 };
            need(b, at, n * 2, "dnp3_range_truncated")?;
            let first = uint(b, at, n, true) as u16;
            let last = uint(b, at + n, n, true) as u16;
            if first > last {
                return Err(fail(ErrorCode::InvalidLength, at, "dnp3_inverted_range"));
            }
            fields.push(Field::new(
                "range_start",
                Value::Unsigned(first.into()),
                at..at + n,
            ));
            fields.push(Field::new(
                "range_stop",
                Value::Unsigned(last.into()),
                at + n..at + n * 2,
            ));
            (
                Some(usize::from(last) - usize::from(first) + 1),
                Some(first),
                0,
                at + n * 2,
            )
        }
        6 => (None, None, 0, at),
        7 | 8 | 0x17 | 0x28 => {
            let n = if matches!(q, 7 | 0x17) { 1 } else { 2 };
            need(b, at, n, "dnp3_count_truncated")?;
            let count = uint(b, at, n, true) as usize;
            fields.push(Field::new(
                "count",
                Value::Unsigned(count as u64),
                at..at + n,
            ));
            (Some(count), None, if q > 15 { n } else { 0 }, at + n)
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
                u64::from(first) + ordinal as u64,
                h.range_witness.clone(),
                "range_start_plus_record_ordinal",
            )
        })
    }
}
fn objects(b: &[u8], p: &mut usize, h: &Header, out: &mut Report<'_>) -> Result<()> {
    let Some(count) = h.count else {
        return Err(fail(
            ErrorCode::UnsupportedTransport,
            *p,
            "dnp3_all_objects_response_has_no_count",
        ));
    };
    let s = shape(h.group, h.variation).ok_or_else(|| {
        fail(
            ErrorCode::UnsupportedTransport,
            *p,
            "dnp3_response_variation_has_no_value_width",
        )
    })?;
    if count > out.limits.max_records.saturating_sub(out.records.len()) {
        return Err(fail(
            ErrorCode::LimitExceeded,
            *p,
            "dnp3_object_count_budget",
        ));
    }
    if matches!(s, Shape::Packed) {
        if h.first.is_none() || h.prefix != 0 {
            return Err(fail(
                ErrorCode::UnsupportedTransport,
                *p,
                "dnp3_packed_requires_range_qualifier",
            ));
        }
        let bytes = count.div_ceil(8);
        need(b, *p, bytes, "dnp3_packed_truncated")?;
        for ordinal in 0..count {
            let at = *p + ordinal / 8;
            let bit = (ordinal % 8) as u8;
            let mut fields = Vec::new();
            if let Some(f) = index_field(h, ordinal, b, *p) {
                fields.push(f);
            }
            fields.push(Field::bit_field("value", b[at] & (1 << bit) != 0, at, bit));
            out.add(Record::new("object_value", at..at + 1, fields))?;
        }
        *p += bytes;
        return Ok(());
    }
    let width = match s {
        Shape::Binary { time } => 1 + time,
        Shape::Counter { width, flags } | Shape::Analog { width, flags, .. } => {
            width + usize::from(flags)
        }
        Shape::Time => 6,
        Shape::Packed => 0,
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
            Shape::Binary { time } => {
                fields.push(Field::new(
                    "flags",
                    Value::Unsigned(b[data].into()),
                    data..data + 1,
                ));
                fields.push(Field::bit_field("value", b[data] & 0x80 != 0, data, 7));
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
            Shape::Counter { width, flags } | Shape::Analog { width, flags, .. } => {
                if flags {
                    fields.push(Field::new(
                        "flags",
                        Value::Unsigned(b[data].into()),
                        data..data + 1,
                    ));
                }
                let v = data + usize::from(flags);
                let n = uint(b, v, width, true);
                let value = match s {
                    Shape::Analog {
                        float: true,
                        width: 4,
                        ..
                    } => Value::Float32Bits(n as u32),
                    Shape::Analog { float: true, .. } => Value::Float64Bits(n),
                    Shape::Analog { width: 2, .. } => Value::Signed(i64::from(n as u16 as i16)),
                    Shape::Analog { .. } => Value::Signed(i64::from(n as u32 as i32)),
                    _ => Value::Unsigned(n),
                };
                fields.push(Field::new("value", value, v..v + width));
            }
            Shape::Time => fields.push(Field::new(
                "time",
                Value::Milliseconds48(uint(b, data, 6, true)),
                data..data + 6,
            )),
            Shape::Packed => {}
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
    while p < b.len() {
        let result = (|| -> Result<()> {
            let h = parse_header(b, &mut p, &mut out)?;
            if context == Context::ReadHeaders {
                if h.prefix != 0 {
                    return Err(fail(
                        ErrorCode::UnsupportedTransport,
                        p,
                        "dnp3_read_index_list_not_in_subset",
                    ));
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
        decode(
            &fragment.objects,
            Context::from_function(fragment.function),
            limits,
        )
    })();
    super::as_json(result)
}
