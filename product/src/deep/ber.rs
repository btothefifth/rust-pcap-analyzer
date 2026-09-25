//! X.690 BER structural reader. Definite/constructed-indefinite forms, bounded
//! depth and element count; no schema-free guess that a context tag is a number.
use super::model::*;
use pcap_evidence::{json::Json, Error, Result};
use std::ops::Range;
#[derive(Clone, Debug)]
pub struct Element {
    pub class: u8,
    pub tag: u32,
    pub constructed: bool,
    pub header: Range<usize>,
    pub content: Range<usize>,
    pub end: usize,
    pub indefinite: bool,
    pub children: Vec<Element>,
}
impl Element {
    pub fn is(&self, class: u8, tag: u32) -> bool {
        self.class == class && self.tag == tag
    }
    pub fn integer(&self, b: &[u8]) -> Result<i64> {
        signed(&b[self.content.clone()], false)
    }
    pub fn unsigned(&self, b: &[u8]) -> Result<u64> {
        uint(&b[self.content.clone()], false)
    }
    pub fn json(&self, b: &[u8]) -> Json {
        Json::object([
            ("class", self.class.into()),
            ("tag", self.tag.into()),
            ("constructed", self.constructed.into()),
            ("indefinite", self.indefinite.into()),
            ("start", self.header.start.to_string().into()),
            ("value_start", self.content.start.to_string().into()),
            ("value_end", self.content.end.to_string().into()),
            ("end", self.end.to_string().into()),
            (
                "raw_value_sha256",
                pcap_evidence::sha256::hex(&pcap_evidence::sha256::digest(
                    &b[self.content.clone()],
                ))
                .into(),
            ),
            (
                "children",
                Json::array(self.children.iter().map(|x| x.json(b))),
            ),
        ])
    }
}
pub fn parse(b: &[u8], limits: &Limits) -> Result<Vec<Element>> {
    limits.validate()?;
    if b.len() > limits.input_bytes {
        return Err(Error::limit("ber_input"));
    }
    let mut out = Vec::new();
    let (mut at, mut count) = (0, 0);
    while at < b.len() {
        let e = one(b, at, b.len(), 0, &mut count, limits)?;
        at = e.end;
        out.push(e);
    }
    Ok(out)
}
fn one(
    b: &[u8],
    start: usize,
    ceiling: usize,
    depth: usize,
    count: &mut usize,
    l: &Limits,
) -> Result<Element> {
    if depth >= l.depth || *count >= l.elements {
        return Err(Error::limit("ber_structure"));
    }
    *count += 1;
    if start >= ceiling {
        return Err(bad("ber", start, "missing tag"));
    }
    let first = b[start];
    let mut at = start + 1;
    let mut tag = u32::from(first & 31);
    if tag == 31 {
        tag = 0;
        let mut n = 0;
        loop {
            if at >= ceiling {
                return Err(bad("ber_tag", at, "unterminated high tag"));
            }
            let v = b[at];
            at += 1;
            n += 1;
            if n == 1 && v & 127 == 0 {
                return Err(bad("ber_tag", at - 1, "nonminimal high tag"));
            }
            if n > 5 || tag > u32::MAX >> 7 {
                return Err(Error::limit("ber_tag"));
            }
            tag = (tag << 7) | u32::from(v & 127);
            if v & 128 == 0 {
                break;
            }
        }
        if tag < 31 {
            return Err(bad("ber_tag", start, "unnecessary high tag"));
        }
    }
    if at >= ceiling {
        return Err(bad("ber_length", at, "missing length"));
    }
    let length_byte = b[at];
    at += 1;
    let constructed = first & 32 != 0;
    let class = first >> 6;
    let indefinite = length_byte == 128;
    if class == 0 && tag == 0 {
        return Err(bad("ber_eoc", start, "EOC outside indefinite terminator"));
    }
    let len = if length_byte < 128 {
        usize::from(length_byte)
    } else if indefinite {
        0
    } else {
        let n = usize::from(length_byte & 127);
        if n == 0 || n > 8 || at.checked_add(n).is_none_or(|x| x > ceiling) {
            return Err(bad("ber_length", at, "invalid long-form length"));
        }
        let value = usize::try_from(uint(&b[at..at + n], false)?)
            .map_err(|_| Error::limit("ber_length"))?;
        at += n;
        value
    };
    let value_start = at;
    let mut children = Vec::new();
    let content_end;
    let end;
    if indefinite {
        if !constructed {
            return Err(bad("ber_indefinite", start, "primitive indefinite length"));
        }
        loop {
            if at.checked_add(2).is_none_or(|n| n > ceiling) {
                return Err(bad("ber_indefinite", at, "missing EOC"));
            }
            if b[at..at + 2] == [0, 0] {
                content_end = at;
                end = at + 2;
                break;
            }
            let child = one(b, at, ceiling, depth + 1, count, l)?;
            at = child.end;
            children.push(child);
        }
    } else {
        content_end = at
            .checked_add(len)
            .filter(|n| *n <= ceiling)
            .ok_or_else(|| bad("ber_length", at, "value exceeds parent"))?;
        end = content_end;
        if constructed {
            while at < content_end {
                let child = one(b, at, content_end, depth + 1, count, l)?;
                at = child.end;
                children.push(child);
            }
        }
    }
    Ok(Element {
        class,
        tag,
        constructed,
        header: start..value_start,
        content: value_start..content_end,
        end,
        indefinite,
        children,
    })
}
/// ASN.1 OBJECT IDENTIFIER, including a multi-octet first subidentifier.
pub fn oid(b: &[u8]) -> Result<Vec<u64>> {
    if b.is_empty() || b.len() > 128 {
        return Err(bad("oid", 0, "invalid OID size"));
    }
    let mut values = Vec::new();
    let (mut value, mut count) = (0u64, 0usize);
    for &v in b {
        if count == 0 && v == 128 {
            return Err(bad("oid", 0, "nonminimal subidentifier"));
        }
        if value > u64::MAX >> 7 || count >= 10 {
            return Err(Error::limit("oid_arc"));
        }
        value = (value << 7) | u64::from(v & 127);
        count += 1;
        if v & 128 == 0 {
            values.push(value);
            value = 0;
            count = 0;
        }
    }
    if count != 0 {
        return Err(bad("oid", 0, "truncated subidentifier"));
    }
    let first = values.remove(0);
    let a = if first < 40 {
        0
    } else if first < 80 {
        1
    } else {
        2
    };
    let mut out = vec![a, first - 40 * a];
    out.extend(values);
    Ok(out)
}
/// Preserve a typed MMS Data tree. Context tags are interpreted only at this
/// schema boundary; floats remain raw IEEE encodings, time quality stays raw.
pub fn mms_data(e: &Element, b: &[u8], l: &Limits) -> Result<Json> {
    fn visit(e: &Element, b: &[u8], depth: usize, l: &Limits) -> Result<Json> {
        if depth >= l.depth {
            return Err(Error::limit("mms_data_depth"));
        }
        let raw = &b[e.content.clone()];
        let (kind, value) = if e.class != 2 {
            ("unknown_class", hex(raw))
        } else {
            match e.tag {
                1 | 2 if e.constructed => (
                    if e.tag == 1 { "array" } else { "structure" },
                    Json::array(
                        e.children
                            .iter()
                            .map(|c| visit(c, b, depth + 1, l))
                            .collect::<Result<Vec<_>>>()?,
                    ),
                ),
                3 if !e.constructed && raw.len() == 1 => ("boolean", (raw[0] != 0).into()),
                4 if !e.constructed && !raw.is_empty() => {
                    let unused = raw[0];
                    if unused > 7
                        || (raw.len() == 1 && unused != 0)
                        || raw
                            .last()
                            .is_some_and(|v| unused != 0 && v & ((1 << unused) - 1) != 0)
                    {
                        return Err(bad(
                            "mms_bit_string",
                            e.content.start,
                            "invalid unused bits",
                        ));
                    }
                    (
                        "bit_string",
                        Json::object([("unused", unused.into()), ("hex", hex(&raw[1..]))]),
                    )
                }
                5 if !e.constructed && raw.len() <= 8 && !raw.is_empty() => {
                    ("integer", signed(raw, false)?.to_string().into())
                }
                6 if !e.constructed && raw.len() <= 9 && !raw.is_empty() => {
                    let value = if raw.len() == 9 && raw[0] == 0 {
                        uint(&raw[1..], false)?
                    } else {
                        uint(raw, false)?
                    };
                    ("unsigned", value.to_string().into())
                }
                7 if !e.constructed => ("floating_point_encoding", hex(raw)),
                9 if !e.constructed => ("octet_string", hex(raw)),
                10 | 16 if !e.constructed => ("string_bytes", hex(raw)),
                12 if !e.constructed => ("binary_time_raw", hex(raw)),
                17 if !e.constructed => ("utc_time_raw", hex(raw)),
                _ => ("unsupported_data_choice", hex(raw)),
            }
        };
        Ok(Json::object([
            ("kind", kind.into()),
            ("value", value),
            ("start", e.header.start.to_string().into()),
            ("end", e.end.to_string().into()),
        ]))
    }
    visit(e, b, 0, l)
}
