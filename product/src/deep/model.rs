use pcap_evidence::{json::Json, provenance::EvidenceBytes, sha256, Error, ErrorCode, Result};
use std::ops::Range;

pub const VERSION: &str = "pcap-evidence.depth.v1";
#[derive(Clone, Debug)]
pub struct Limits {
    pub input_bytes: usize,
    pub fields: usize,
    pub elements: usize,
    pub depth: usize,
    pub spans: usize,
    pub active: usize,
    pub retained_bytes: usize,
    pub work: usize,
    pub output_bytes: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            input_bytes: 1024 * 1024,
            fields: 4096,
            elements: 1024,
            depth: 32,
            spans: 4096,
            active: 128,
            retained_bytes: 16 * 1024 * 1024,
            work: 8 * 1024 * 1024,
            output_bytes: 8 * 1024 * 1024,
        }
    }
}
impl Limits {
    pub fn validate(&self) -> Result<()> {
        if [
            self.input_bytes,
            self.fields,
            self.elements,
            self.depth,
            self.spans,
            self.active,
            self.retained_bytes,
            self.work,
            self.output_bytes,
        ]
        .contains(&0)
            || self.depth > 64
            || self.input_bytes > 64 * 1024 * 1024
            || self.fields > 65536
            || self.active > 65536
        {
            return Err(Error::limit("depth_configuration"));
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Default)]
pub struct Context {
    pub function: u8,
    /// Explicitly established security mode, never inferred from plausible plaintext.
    pub ua_security_none: bool,
    pub fcs_present: bool,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Status {
    Observed,
    Candidate,
    Incomplete,
    Unsupported,
    Ambiguous,
    Rejected,
    Limited,
}
impl Status {
    pub fn name(self) -> &'static str {
        match self {
            Self::Observed => "observed",
            Self::Candidate => "candidate",
            Self::Incomplete => "incomplete",
            Self::Unsupported => "unsupported",
            Self::Ambiguous => "ambiguous",
            Self::Rejected => "rejected",
            Self::Limited => "limited",
        }
    }
}
#[derive(Clone, Debug)]
pub struct Field {
    pub name: String,
    pub value: Json,
    pub range: Range<usize>,
    pub basis: &'static str,
}
#[derive(Clone, Debug)]
pub struct Note {
    pub status: Status,
    pub code: &'static str,
    pub range: Range<usize>,
}
#[derive(Clone, Debug)]
pub struct Report {
    pub protocol: &'static str,
    pub support: &'static str,
    pub fields: Vec<Field>,
    pub notes: Vec<Note>,
    pub evidence: EvidenceBytes,
    limits: Limits,
    work: usize,
}
impl Report {
    pub fn new(protocol: &'static str, bytes: &EvidenceBytes, limits: &Limits) -> Result<Self> {
        limits.validate()?;
        if !bytes.validate() {
            return Err(bad("depth_provenance", 0, "invalid input provenance"));
        }
        if bytes.len() > limits.input_bytes || bytes.spans().len() > limits.spans {
            return Err(Error::limit("depth_input"));
        }
        Ok(Self {
            protocol,
            support: "implemented-partial",
            fields: Vec::new(),
            notes: Vec::new(),
            evidence: bytes.clone(),
            limits: limits.clone(),
            work: 0,
        })
    }
    pub fn charge(&mut self, work: usize) -> Result<()> {
        self.work = self
            .work
            .checked_add(work)
            .ok_or_else(|| Error::limit("depth_work"))?;
        if self.work > self.limits.work {
            return Err(Error::limit("depth_work"));
        }
        Ok(())
    }
    pub fn add(
        &mut self,
        name: impl Into<String>,
        value: Json,
        range: Range<usize>,
        basis: &'static str,
    ) -> Result<()> {
        if range.start > range.end || range.end > self.evidence.len() {
            return Err(bad("depth_field_range", range.start, "outside evidence"));
        }
        if self.fields.len() >= self.limits.fields {
            return Err(Error::limit("depth_fields"));
        }
        let name = name.into();
        if name.len() > 256 {
            return Err(Error::limit("depth_field_name"));
        }
        self.charge(range.len().saturating_add(name.len()).saturating_add(1))?;
        // Exact serialization bound prevents arbitrarily large nested values.
        value.encode_bounded(self.limits.output_bytes)?;
        self.fields.push(Field {
            name,
            value,
            range,
            basis,
        });
        Ok(())
    }
    pub fn u(&mut self, name: impl Into<String>, value: u64, range: Range<usize>) -> Result<()> {
        self.add(name, value.to_string().into(), range, "wire_unsigned")
    }
    pub fn i(&mut self, name: impl Into<String>, value: i64, range: Range<usize>) -> Result<()> {
        self.add(name, value.to_string().into(), range, "wire_signed")
    }
    pub fn flag(
        &mut self,
        name: impl Into<String>,
        value: bool,
        range: Range<usize>,
    ) -> Result<()> {
        self.add(name, value.into(), range, "wire_bit")
    }
    pub fn note(
        &mut self,
        status: Status,
        code: &'static str,
        start: usize,
        end: usize,
    ) -> Result<()> {
        if start > end || end > self.evidence.len() {
            return Err(bad("depth_note_range", start, "outside evidence"));
        }
        if self.notes.len() >= self.limits.elements {
            return Err(Error::limit("depth_notes"));
        }
        self.notes.push(Note {
            status,
            code,
            range: start..end,
        });
        Ok(())
    }
    pub fn json(&self) -> Json {
        Json::object([
            ("schema", VERSION.into()),
            ("protocol", self.protocol.into()),
            ("support", self.support.into()),
            ("interpretation", "independent_bounded_subset".into()),
            ("device_effect_established", false.into()),
            ("normative_conformance_certified", false.into()),
            (
                "evidence",
                pcap_evidence_stream::events::Evidence::bytes(&self.evidence).json(),
            ),
            (
                "fields",
                Json::array(self.fields.iter().map(|f| {
                    Json::object([
                        ("name", f.name.clone().into()),
                        ("value", f.value.clone()),
                        ("start", f.range.start.to_string().into()),
                        ("end", f.range.end.to_string().into()),
                        ("basis", f.basis.into()),
                    ])
                })),
            ),
            (
                "notes",
                Json::array(self.notes.iter().map(|n| {
                    Json::object([
                        ("status", n.status.name().into()),
                        ("code", n.code.into()),
                        ("start", n.range.start.to_string().into()),
                        ("end", n.range.end.to_string().into()),
                    ])
                })),
            ),
        ])
    }
    pub fn encode(&self) -> Result<String> {
        self.json().encode_bounded(self.limits.output_bytes)
    }
}
pub fn bad(field: &'static str, offset: usize, detail: &'static str) -> Error {
    Error::new(ErrorCode::ProtocolFraming, offset as u64, field, detail)
}
pub fn need(b: &[u8], end: usize, field: &'static str) -> Result<()> {
    if end > b.len() {
        Err(Error::new(
            ErrorCode::Truncated,
            b.len() as u64,
            field,
            "incomplete field",
        ))
    } else {
        Ok(())
    }
}
pub fn le16(b: &[u8], p: usize) -> Result<u16> {
    need(
        b,
        p.checked_add(2).ok_or_else(|| Error::limit("offset"))?,
        "u16",
    )?;
    Ok(u16::from_le_bytes([b[p], b[p + 1]]))
}
pub fn be16(b: &[u8], p: usize) -> Result<u16> {
    need(
        b,
        p.checked_add(2).ok_or_else(|| Error::limit("offset"))?,
        "u16",
    )?;
    Ok(u16::from_be_bytes([b[p], b[p + 1]]))
}
pub fn le32(b: &[u8], p: usize) -> Result<u32> {
    need(
        b,
        p.checked_add(4).ok_or_else(|| Error::limit("offset"))?,
        "u32",
    )?;
    Ok(u32::from_le_bytes([b[p], b[p + 1], b[p + 2], b[p + 3]]))
}
pub fn be32(b: &[u8], p: usize) -> Result<u32> {
    need(
        b,
        p.checked_add(4).ok_or_else(|| Error::limit("offset"))?,
        "u32",
    )?;
    Ok(u32::from_be_bytes([b[p], b[p + 1], b[p + 2], b[p + 3]]))
}
pub fn uint(b: &[u8], little: bool) -> Result<u64> {
    if b.len() > 8 {
        return Err(Error::limit("integer_width"));
    }
    let mut n = 0u64;
    if little {
        for (i, x) in b.iter().enumerate() {
            n |= u64::from(*x) << (8 * i);
        }
    } else {
        for x in b {
            n = (n << 8) | u64::from(*x);
        }
    }
    Ok(n)
}
pub fn signed(b: &[u8], little: bool) -> Result<i64> {
    if b.is_empty() {
        return Err(bad("integer", 0, "empty signed integer"));
    }
    let n = uint(b, little)?;
    let shift = 64 - b.len() * 8;
    Ok(((n << shift) as i64) >> shift)
}
pub fn hex(b: &[u8]) -> Json {
    sha256::hex(b).into()
}
pub fn get<'a>(v: &'a Json, key: &str) -> Option<&'a Json> {
    match v {
        Json::Object(o) => o.iter().find(|(k, _)| *k == key).map(|(_, v)| v),
        _ => None,
    }
}
pub fn number(v: Option<&Json>) -> Result<u64> {
    match v {
        Some(Json::Number(n)) => Ok(*n),
        Some(Json::String(s)) => s
            .parse()
            .map_err(|_| bad("event_integer", 0, "bad integer")),
        _ => Err(bad("event_integer", 0, "missing integer")),
    }
}
