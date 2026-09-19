//! Bounded, additive protocol semantics over existing evidence bytes.
//!
//! These APIs do not identify protocols, reconstruct streams, pair transactions,
//! infer device behavior, or authenticate a source. The caller supplies an already
//! framed input and its interpretation context. Output retains exact witnesses.
pub mod dnp3;
pub mod modbus;

use crate::json::Json;
use crate::provenance::EvidenceBytes;
use crate::{sha256, Error, ErrorCode, Result};
use std::ops::Range;

pub const SCHEMA: &str = "pcap-evidence.semantic-subset.v1";

/// Logical work/output bounds, not a process-level memory sandbox.
#[derive(Clone, Debug)]
pub struct Limits {
    pub max_input_bytes: usize,
    pub max_records: usize,
    pub max_fields: usize,
    pub max_source_spans: usize,
    pub max_work: usize,
    pub max_json_bytes: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_input_bytes: 65_536,
            max_records: 2048,
            max_fields: 8192,
            max_source_spans: 16_384,
            max_work: 1_048_576,
            max_json_bytes: 4 * 1024 * 1024,
        }
    }
}
impl Limits {
    /// A stricter parent budget cannot accidentally authorize more semantic work.
    pub fn from_capture(limits: &crate::Limits) -> Self {
        let defaults = Self::default();
        Self {
            max_input_bytes: defaults.max_input_bytes.min(limits.max_application_bytes),
            max_records: defaults.max_records.min(limits.max_protocol_messages),
            max_fields: defaults.max_fields.min(limits.max_protocol_messages),
            ..defaults
        }
    }
    pub fn validate(&self) -> Result<()> {
        if [
            self.max_input_bytes,
            self.max_records,
            self.max_fields,
            self.max_source_spans,
            self.max_work,
            self.max_json_bytes,
        ]
        .contains(&0)
            || self.max_input_bytes > 16 * 1024 * 1024
            || self.max_records > 65_536
            || self.max_fields > 262_144
            || self.max_source_spans > 1_048_576
            || self.max_work > 64 * 1024 * 1024
            || self.max_json_bytes > 64 * 1024 * 1024
        {
            return Err(Error::new(
                ErrorCode::Usage,
                0,
                "semantic_limits",
                "zero or excessive limit",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Status {
    DecodedSubset,
    Incomplete,
    Unsupported,
    Rejected,
    Limited,
}
impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DecodedSubset => "decoded_subset",
            Self::Incomplete => "incomplete",
            Self::Unsupported => "unsupported",
            Self::Rejected => "rejected",
            Self::Limited => "limit_exceeded",
        }
    }
}

/// Floats stay IEEE bit patterns: even NaN payloads and signed zero are preserved.
/// Wire times stay raw millisecond counts, never promoted to synchronized time.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Value {
    Unsigned(u64),
    Signed(i64),
    Boolean(bool),
    Float32Bits(u32),
    Float64Bits(u64),
    Milliseconds48(u64),
    RelativeMilliseconds16(u16),
}
impl Value {
    fn kind(&self) -> &'static str {
        match self {
            Self::Unsigned(_) => "unsigned",
            Self::Signed(_) => "signed",
            Self::Boolean(_) => "boolean",
            Self::Float32Bits(_) => "ieee754_binary32_bits",
            Self::Float64Bits(_) => "ieee754_binary64_bits",
            Self::Milliseconds48(_) => "wire_milliseconds_48",
            Self::RelativeMilliseconds16(_) => "relative_milliseconds_16_unresolved",
        }
    }
    fn json(&self) -> Json {
        match self {
            Self::Unsigned(n) | Self::Milliseconds48(n) => n.to_string().into(),
            Self::Signed(n) => n.to_string().into(),
            Self::Boolean(b) => (*b).into(),
            Self::Float32Bits(n) => format!("{n:08x}").into(),
            Self::Float64Bits(n) => format!("{n:016x}").into(),
            Self::RelativeMilliseconds16(n) => n.to_string().into(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Field {
    name: &'static str,
    value: Value,
    range: Range<usize>,
    bit: Option<u8>,
    basis: &'static str,
}
impl Field {
    pub fn name(&self) -> &'static str {
        self.name
    }
    pub fn value(&self) -> &Value {
        &self.value
    }
    pub fn range(&self) -> Range<usize> {
        self.range.clone()
    }
    pub fn bit(&self) -> Option<u8> {
        self.bit
    }
    pub fn basis(&self) -> &'static str {
        self.basis
    }
    pub(crate) fn new(name: &'static str, value: Value, range: Range<usize>) -> Self {
        Self {
            name,
            value,
            range,
            bit: None,
            basis: "direct_wire_field",
        }
    }
    pub(crate) fn bit_field(name: &'static str, value: bool, byte: usize, bit: u8) -> Self {
        Self {
            name,
            value: Value::Boolean(value),
            range: byte..byte + 1,
            bit: Some(bit),
            basis: "lsb_zero_bit_position",
        }
    }
    pub(crate) fn derived(
        name: &'static str,
        value: u64,
        range: Range<usize>,
        basis: &'static str,
    ) -> Self {
        Self {
            name,
            value: Value::Unsigned(value),
            range,
            bit: None,
            basis,
        }
    }
}
#[derive(Clone, Debug)]
pub struct Record {
    kind: &'static str,
    range: Range<usize>,
    fields: Vec<Field>,
}
impl Record {
    pub fn kind(&self) -> &'static str {
        self.kind
    }
    pub fn range(&self) -> Range<usize> {
        self.range.clone()
    }
    pub fn fields(&self) -> &[Field] {
        &self.fields
    }
    pub(crate) fn new(kind: &'static str, range: Range<usize>, fields: Vec<Field>) -> Self {
        Self {
            kind,
            range,
            fields,
        }
    }
}
#[derive(Clone, Debug)]
pub struct Issue {
    pub code: &'static str,
    pub range: Range<usize>,
}

/// Fields are immutable; offsets cannot be forged after validation. Parsing
/// failure retains complete preceding records and a source-backed undecoded tail.
pub struct Report<'a> {
    source: &'a EvidenceBytes,
    protocol: &'static str,
    context: &'static str,
    limits: Limits,
    status: Status,
    consumed: usize,
    records: Vec<Record>,
    issues: Vec<Issue>,
    fields: usize,
    spans: usize,
    work: usize,
}
impl<'a> Report<'a> {
    pub fn status(&self) -> Status {
        self.status
    }
    pub fn consumed(&self) -> usize {
        self.consumed
    }
    pub fn records(&self) -> &[Record] {
        &self.records
    }
    pub fn issues(&self) -> &[Issue] {
        &self.issues
    }
    pub fn source(&self) -> &EvidenceBytes {
        self.source
    }
    pub(crate) fn new(
        source: &'a EvidenceBytes,
        protocol: &'static str,
        context: &'static str,
        limits: Limits,
    ) -> Result<Self> {
        limits.validate()?;
        if source.len() > limits.max_input_bytes || source.spans().len() > limits.max_source_spans {
            return Err(Error::limit("semantic_input"));
        }
        if !source.validate() {
            return Err(Error::new(
                ErrorCode::Invariant,
                0,
                "semantic_provenance",
                "invalid source spans",
            ));
        }
        let work = source
            .len()
            .checked_add(source.spans().len())
            .filter(|n| *n <= limits.max_work)
            .ok_or_else(|| Error::limit("semantic_work"))?;
        Ok(Self {
            source,
            protocol,
            context,
            limits,
            status: Status::DecodedSubset,
            consumed: 0,
            records: Vec::new(),
            issues: Vec::new(),
            fields: 0,
            spans: 0,
            work,
        })
    }
    pub(crate) fn add(&mut self, record: Record) -> Result<()> {
        let input = self.source.len();
        if record.range.start > record.range.end || record.range.end > input {
            return Err(Error::new(
                ErrorCode::Invariant,
                0,
                "semantic_record",
                "invalid record range",
            ));
        }
        let mut spans = 0usize;
        for f in &record.fields {
            if f.range.start >= f.range.end || f.range.end > input || f.bit.is_some_and(|n| n > 7) {
                return Err(Error::new(
                    ErrorCode::Invariant,
                    0,
                    "semantic_field",
                    "invalid field witness",
                ));
            }
            let first = self
                .source
                .spans()
                .partition_point(|s| s.end <= f.range.start);
            spans = spans
                .checked_add(
                    self.source.spans()[first..]
                        .iter()
                        .take_while(|s| s.start < f.range.end)
                        .count(),
                )
                .ok_or_else(|| Error::limit("semantic_spans"))?;
        }
        let fields = self
            .fields
            .checked_add(record.fields.len())
            .ok_or_else(|| Error::limit("semantic_fields"))?;
        let total_spans = self
            .spans
            .checked_add(spans)
            .ok_or_else(|| Error::limit("semantic_spans"))?;
        let work = self
            .work
            .checked_add(spans)
            .and_then(|n| n.checked_add(record.fields.len()))
            .ok_or_else(|| Error::limit("semantic_work"))?;
        if self.records.len() >= self.limits.max_records
            || fields > self.limits.max_fields
            || total_spans > self.limits.max_source_spans
            || work > self.limits.max_work
        {
            return Err(Error::limit("semantic_output"));
        }
        self.records.push(record);
        self.fields = fields;
        self.spans = total_spans;
        self.work = work;
        Ok(())
    }
    pub(crate) fn advance(&mut self, n: usize) {
        self.consumed = n;
    }
    pub(crate) fn warn(&mut self, code: &'static str, range: Range<usize>) {
        // Decoder-owned issue strings only; number of diagnostics is bounded.
        if self.issues.len() < self.limits.max_records {
            self.issues.push(Issue { code, range });
        } else {
            self.status = Status::Limited;
        }
    }
    pub(crate) fn stop(&mut self, error: Error, at: usize) {
        self.status = match error.code {
            ErrorCode::Truncated => Status::Incomplete,
            ErrorCode::UnsupportedTransport | ErrorCode::UnsupportedVersion => Status::Unsupported,
            ErrorCode::LimitExceeded => Status::Limited,
            _ => Status::Rejected,
        };
        self.consumed = at.min(self.source.len());
        self.warn(error.field, self.consumed..self.source.len());
    }
    pub fn json(&self) -> Result<Json> {
        let value = Json::object([
            ("schema", SCHEMA.into()),
            ("protocol", self.protocol.into()),
            ("decoder", "independent-tier-a-subset/1".into()),
            ("context", self.context.into()),
            ("status", self.status.as_str().into()),
            ("support", "implemented-partial".into()),
            ("input_length", self.source.len().to_string().into()),
            (
                "input_sha256",
                sha256::hex(&sha256::digest(self.source.data())).into(),
            ),
            ("consumed", self.consumed.to_string().into()),
            (
                "all_input_consumed",
                (self.status == Status::DecodedSubset && self.consumed == self.source.len()).into(),
            ),
            ("device_effect_established", false.into()),
            ("normative_conformance_certified", false.into()),
            (
                "source_binding",
                "inherited_from_parent_capture_or_run".into(),
            ),
            (
                "records",
                Json::array(self.records.iter().map(|r| {
                    Json::object([
                        ("kind", r.kind.into()),
                        ("range", range_json(&r.range)),
                        (
                            "fields",
                            Json::array(r.fields.iter().map(|f| {
                                Json::object([
                                    ("name", f.name.into()),
                                    ("type", f.value.kind().into()),
                                    ("value", f.value.json()),
                                    ("range", range_json(&f.range)),
                                    ("basis", f.basis.into()),
                                    ("bit", f.bit.map_or(Json::Null, Json::from)),
                                    ("evidence", witness(self.source, &f.range)),
                                ])
                            })),
                        ),
                    ])
                })),
            ),
            (
                "issues",
                Json::array(self.issues.iter().map(|i| {
                    Json::object([("code", i.code.into()), ("range", range_json(&i.range))])
                })),
            ),
            (
                "undecoded_tail",
                if self.consumed < self.source.len() {
                    Json::object([
                        ("range", range_json(&(self.consumed..self.source.len()))),
                        (
                            "evidence",
                            witness(self.source, &(self.consumed..self.source.len())),
                        ),
                    ])
                } else {
                    Json::Null
                },
            ),
        ]);
        // Exact-size guard; the temporary serialization is bounded and discarded.
        value.encode_bounded(self.limits.max_json_bytes)?;
        Ok(value)
    }
}
fn range_json(r: &Range<usize>) -> Json {
    Json::object([
        ("start", r.start.to_string().into()),
        ("end", r.end.to_string().into()),
    ])
}
fn witness(source: &EvidenceBytes, range: &Range<usize>) -> Json {
    let first = source.spans().partition_point(|s| s.end <= range.start);
    Json::object([
        (
            "sha256",
            sha256::hex(&sha256::digest(&source.data()[range.clone()])).into(),
        ),
        (
            "spans",
            Json::array(
                source.spans()[first..]
                    .iter()
                    .take_while(|s| s.start < range.end)
                    .map(|s| {
                        let a = range.start.max(s.start);
                        let b = range.end.min(s.end);
                        Json::object([
                            ("frame", s.packet.frame.to_string().into()),
                            ("record_offset", s.packet.record_offset.to_string().into()),
                            (
                                "packet_start",
                                (s.packet_start + (a - s.start)).to_string().into(),
                            ),
                            ("start", (a - range.start).to_string().into()),
                            ("end", (b - range.start).to_string().into()),
                        ])
                    }),
            ),
        ),
    ])
}

pub(crate) fn fail(code: ErrorCode, at: usize, field: &'static str) -> Error {
    Error::new(
        code,
        at as u64,
        field,
        "semantic subset stopped; tail retained without resynchronization",
    )
}
pub(crate) fn need(bytes: &[u8], at: usize, count: usize, field: &'static str) -> Result<()> {
    if at.checked_add(count).is_none_or(|n| n > bytes.len()) {
        Err(fail(ErrorCode::Truncated, at, field))
    } else {
        Ok(())
    }
}
pub(crate) fn uint(bytes: &[u8], at: usize, count: usize, little: bool) -> u64 {
    let mut n = 0u64;
    if little {
        for i in (0..count).rev() {
            n = (n << 8) | u64::from(bytes[at + i]);
        }
    } else {
        for &b in &bytes[at..at + count] {
            n = (n << 8) | u64::from(b);
        }
    }
    n
}
/// Safe nested JSON adapter: a failure is data, never a silently missing extension.
pub fn as_json(result: Result<Report<'_>>) -> Json {
    match result.and_then(|r| r.json()) {
        Ok(value) => value,
        Err(e) => Json::object([
            ("schema", SCHEMA.into()),
            (
                "status",
                if e.code == ErrorCode::LimitExceeded {
                    "limit_exceeded"
                } else {
                    "rejected"
                }
                .into(),
            ),
            ("error", crate::report::error(&e)),
            ("device_effect_established", false.into()),
        ]),
    }
}
