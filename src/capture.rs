//! One state machine for both borrowed slices and bounded streaming input.
use crate::time::{Resolution, Timestamp};
use crate::{Error, ErrorCode, Limits, Result};
use std::borrow::Cow;
use std::io::Read;

pub const SHB: u32 = 0x0a0d0d0a;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Endian {
    Little,
    Big,
}
impl Endian {
    pub(crate) fn u16(self, b: &[u8]) -> u16 {
        match self {
            Self::Little => u16::from_le_bytes([b[0], b[1]]),
            Self::Big => u16::from_be_bytes([b[0], b[1]]),
        }
    }
    pub(crate) fn u32(self, b: &[u8]) -> u32 {
        match self {
            Self::Little => u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
            Self::Big => u32::from_be_bytes([b[0], b[1], b[2], b[3]]),
        }
    }
    pub(crate) fn u64(self, b: &[u8]) -> u64 {
        let a = [b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]];
        match self {
            Self::Little => u64::from_le_bytes(a),
            Self::Big => u64::from_be_bytes(a),
        }
    }
    pub fn put_u16(self, v: u16, out: &mut Vec<u8>) {
        let b = match self {
            Self::Little => v.to_le_bytes(),
            Self::Big => v.to_be_bytes(),
        };
        out.extend_from_slice(&b);
    }
    pub fn put_u32(self, v: u32, out: &mut Vec<u8>) {
        let b = match self {
            Self::Little => v.to_le_bytes(),
            Self::Big => v.to_be_bytes(),
        };
        out.extend_from_slice(&b);
    }
    pub fn put_u64(self, v: u64, out: &mut Vec<u8>) {
        let b = match self {
            Self::Little => v.to_le_bytes(),
            Self::Big => v.to_be_bytes(),
        };
        out.extend_from_slice(&b);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Format {
    Pcap,
    PcapNg,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParseMode {
    /// Reject contradictory packet lengths and invalid legacy time fractions.
    Strict,
    /// Preserve structurally readable contradictions and emit warnings; never repair bytes.
    Evidence,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Warning {
    pub code: &'static str,
    pub offset: u64,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OptionMeta {
    pub code: u16,
    pub value_offset: usize,
    pub length: usize,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Interface {
    pub section: u32,
    pub id: u32,
    pub link_type: u32,
    pub snaplen: u32,
    pub resolution: Resolution,
    pub offset_seconds: i64,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LegacyHeader {
    pub endian: Endian,
    pub nanos: bool,
    pub snaplen: u32,
    pub link_word: u32,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PacketMeta {
    pub frame: u64,
    pub section: u32,
    pub interface: u32,
    pub link_type: u32,
    pub captured_len: u32,
    pub original_len: u32,
    pub data_offset: usize,
    pub timestamp: Option<Timestamp>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecordKind {
    LegacyHeader(LegacyHeader),
    Section {
        id: u32,
        declared_length: Option<u64>,
    },
    Interface(Interface),
    Packet(PacketMeta),
    Names {
        records: usize,
    },
    Statistics {
        interface: u32,
        timestamp: Timestamp,
    },
    Secrets {
        secrets_type: u32,
        secrets_len: u32,
    },
    Custom {
        pen: u32,
        copy_on_edit: bool,
    },
    Unknown {
        block_type: u32,
    },
}

/// Immutable raw bytes plus validated offsets. Unknown bytes remain untouched.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Record<'a> {
    offset: u64,
    endian: Endian,
    raw: Cow<'a, [u8]>,
    kind: RecordKind,
    options: Vec<OptionMeta>,
    warnings: Vec<Warning>,
}
impl Record<'_> {
    pub fn offset(&self) -> u64 {
        self.offset
    }
    pub fn endian(&self) -> Endian {
        self.endian
    }
    pub fn raw(&self) -> &[u8] {
        &self.raw
    }
    pub fn kind(&self) -> &RecordKind {
        &self.kind
    }
    pub fn options(&self) -> &[OptionMeta] {
        &self.options
    }
    pub fn warnings(&self) -> &[Warning] {
        &self.warnings
    }
    pub fn option_value(&self, option: &OptionMeta) -> Option<&[u8]> {
        let end = option.value_offset.checked_add(option.length)?;
        self.raw.get(option.value_offset..end)
    }
    pub fn packet(&self) -> Option<(&PacketMeta, &[u8])> {
        match &self.kind {
            RecordKind::Packet(p) => Some((
                p,
                &self.raw[p.data_offset..p.data_offset + p.captured_len as usize],
            )),
            _ => None,
        }
    }
    pub fn into_owned(self) -> Record<'static> {
        Record {
            offset: self.offset,
            endian: self.endian,
            raw: Cow::Owned(self.raw.into_owned()),
            kind: self.kind,
            options: self.options,
            warnings: self.warnings,
        }
    }
}

pub enum Decode<'a> {
    /// Minimum total bytes required at the current record boundary.
    NeedMore(usize),
    Record(Record<'a>),
}

pub struct Decoder {
    limits: Limits,
    mode: ParseMode,
    format: Option<Format>,
    endian: Endian,
    legacy: Option<LegacyHeader>,
    interfaces: Vec<Interface>,
    section: u32,
    sections_seen: u32,
    section_end: Option<u64>,
    next_frame: u64,
    records: usize,
}
impl Decoder {
    pub fn new(limits: Limits, mode: ParseMode) -> Result<Self> {
        limits.validate()?;
        Ok(Self {
            limits,
            mode,
            format: None,
            endian: Endian::Little,
            legacy: None,
            interfaces: Vec::new(),
            section: 0,
            sections_seen: 0,
            section_end: None,
            next_frame: 1,
            records: 0,
        })
    }
    pub fn format(&self) -> Option<Format> {
        self.format
    }
    pub fn interfaces(&self) -> &[Interface] {
        &self.interfaces
    }

    fn error(&self, code: ErrorCode, offset: u64, field: &'static str, detail: &str) -> Error {
        Error::new(code, offset, field, detail)
    }
    fn ng_endian(&self, input: &[u8], offset: u64) -> Result<Endian> {
        match &input[8..12] {
            [0x4d, 0x3c, 0x2b, 0x1a] => Ok(Endian::Little),
            [0x1a, 0x2b, 0x3c, 0x4d] => Ok(Endian::Big),
            _ => Err(self.error(
                ErrorCode::BadMagic,
                offset + 8,
                "byte_order_magic",
                "invalid PCAPNG byte-order magic",
            )),
        }
    }

    /// Does not mutate state. Never allocates a size that has not passed a budget.
    pub fn required(&self, input: &[u8], offset: u64) -> Result<usize> {
        let supplied = u64::try_from(input.len()).map_err(|_| Error::limit("file_offset"))?;
        offset
            .checked_add(supplied)
            .ok_or_else(|| Error::limit("file_offset"))?;

        if self.format.is_none() {
            if input.len() < 4 {
                return Ok(4);
            }
            if input[..4] != [0x0a, 0x0d, 0x0d, 0x0a] {
                match &input[..4] {
                    [0xd4, 0xc3, 0xb2, 0xa1]
                    | [0xa1, 0xb2, 0xc3, 0xd4]
                    | [0x4d, 0x3c, 0xb2, 0xa1]
                    | [0xa1, 0xb2, 0x3c, 0x4d] => return Ok(24),
                    _ => {
                        return Err(self.error(
                            ErrorCode::BadMagic,
                            offset,
                            "magic",
                            "not supported PCAP/PCAPNG",
                        ))
                    }
                }
            }
        } else if self.format == Some(Format::Pcap) {
            if input.len() < 16 {
                return Ok(16);
            }
            let size = self.endian.u32(&input[8..12]) as usize;
            if size > self.limits.max_packet_bytes {
                return Err(Error::limit("packet_bytes"));
            }
            return size
                .checked_add(16)
                .ok_or_else(|| Error::limit("packet_bytes"));
        }
        if input.len() < 8 {
            return Ok(8);
        }
        let is_section = input[..4] == [0x0a, 0x0d, 0x0d, 0x0a];
        if is_section && input.len() < 12 {
            return Ok(12);
        }
        let endian = if is_section {
            self.ng_endian(input, offset)?
        } else {
            self.endian
        };
        let size = endian.u32(&input[4..8]) as usize;
        if size < 12 || size % 4 != 0 || (is_section && size < 28) {
            return Err(self.error(
                ErrorCode::InvalidLength,
                offset + 4,
                "block_length",
                "block length must be aligned and meet its minimum",
            ));
        }
        if size > self.limits.max_block_bytes {
            return Err(Error::limit("block_bytes"));
        }
        Ok(size)
    }

    pub fn decode<'a>(&mut self, input: &'a [u8], offset: u64) -> Result<Decode<'a>> {
        if self.records >= self.limits.max_records {
            return Err(Error::limit("records"));
        }
        let need = self.required(input, offset)?;
        if input.len() < need {
            return Ok(Decode::NeedMore(need));
        }
        let raw = &input[..need];
        let mut warnings = Vec::new();
        let mut options = Vec::new();
        let kind;
        let mut record_endian = self.endian;
        if self.format.is_none() && raw[..4] != [0x0a, 0x0d, 0x0d, 0x0a] {
            let (endian, nanos) = match &raw[..4] {
                [0xd4, 0xc3, 0xb2, 0xa1] => (Endian::Little, false),
                [0xa1, 0xb2, 0xc3, 0xd4] => (Endian::Big, false),
                [0x4d, 0x3c, 0xb2, 0xa1] => (Endian::Little, true),
                [0xa1, 0xb2, 0x3c, 0x4d] => (Endian::Big, true),
                _ => {
                    return Err(self.error(
                        ErrorCode::BadMagic,
                        offset,
                        "magic",
                        "unsupported magic",
                    ))
                }
            };
            if endian.u16(&raw[4..6]) != 2 || endian.u16(&raw[6..8]) != 4 {
                return Err(self.error(
                    ErrorCode::UnsupportedVersion,
                    offset + 4,
                    "version",
                    "only PCAP 2.4 is supported",
                ));
            }
            let header = LegacyHeader {
                endian,
                nanos,
                snaplen: endian.u32(&raw[16..20]),
                link_word: endian.u32(&raw[20..24]),
            };
            if header.snaplen == 0 {
                return Err(self.error(
                    ErrorCode::InvalidLength,
                    offset + 16,
                    "snaplen",
                    "classic PCAP snaplen must be nonzero",
                ));
            }
            self.format = Some(Format::Pcap);
            self.endian = endian;
            record_endian = endian;
            self.legacy = Some(header.clone());
            kind = RecordKind::LegacyHeader(header);
        } else if self.format == Some(Format::Pcap) {
            let header = self.legacy.as_ref().ok_or_else(|| {
                self.error(
                    ErrorCode::Invariant,
                    offset,
                    "state",
                    "missing global header",
                )
            })?;
            let cap = self.endian.u32(&raw[8..12]);
            let orig = self.endian.u32(&raw[12..16]);
            validate_lengths(cap, orig, header.snaplen, self.mode, offset, &mut warnings)?;
            let time = Timestamp::legacy(
                self.endian.u32(&raw[0..4]),
                self.endian.u32(&raw[4..8]),
                header.nanos,
            );
            let timestamp = match time {
                Ok(t) => Some(t),
                Err(mut e) => {
                    e.offset = offset + 4;
                    if self.mode == ParseMode::Strict {
                        return Err(e);
                    }
                    warnings.push(Warning {
                        code: "invalid_timestamp_fraction",
                        offset: offset + 4,
                    });
                    None
                }
            };
            kind = RecordKind::Packet(PacketMeta {
                frame: self.next_frame,
                section: 0,
                interface: 0,
                link_type: header.link_word & 0xffff,
                captured_len: cap,
                original_len: orig,
                data_offset: 16,
                timestamp,
            });
            self.next_frame += 1;
        } else {
            let is_section = raw[..4] == [0x0a, 0x0d, 0x0d, 0x0a];
            let endian = if is_section {
                self.ng_endian(raw, offset)?
            } else {
                self.endian
            };
            record_endian = endian;
            if endian.u32(&raw[need - 4..need]) as usize != need {
                return Err(self.error(
                    ErrorCode::LengthMismatch,
                    offset + need as u64 - 4,
                    "block_trailer",
                    "leading and trailing lengths differ",
                ));
            }
            if let Some(end) = self.section_end {
                let record_end = offset
                    .checked_add(need as u64)
                    .ok_or_else(|| Error::limit("file_offset"))?;
                if (is_section && offset != end) || (!is_section && record_end > end) {
                    return Err(self.error(
                        ErrorCode::LengthMismatch,
                        offset,
                        "section_length",
                        "record violates declared section boundary",
                    ));
                }
            }
            let block = endian.u32(&raw[..4]);
            let body_end = need - 4;
            match block {
                SHB => {
                    if endian.u16(&raw[12..14]) != 1 || endian.u16(&raw[14..16]) != 0 {
                        return Err(self.error(
                            ErrorCode::UnsupportedVersion,
                            offset + 12,
                            "version",
                            "only PCAPNG section 1.0 is decoded",
                        ));
                    }
                    let declared = endian.u64(&raw[16..24]) as i64;
                    if declared < -1 {
                        return Err(self.error(
                            ErrorCode::InvalidLength,
                            offset + 16,
                            "section_length",
                            "negative section length other than -1",
                        ));
                    }

                    if declared >= 0 && declared % 4 != 0 {
                        return Err(self.error(
                            ErrorCode::InvalidLength,
                            offset + 16,
                            "section_length",
                            "finite section length must be 32-bit aligned",
                        ));
                    }
                    options = parse_options(raw, 24, body_end, endian, offset, &self.limits)?;
                    let end = if declared == -1 {
                        None
                    } else {
                        Some(
                            offset
                                .checked_add(need as u64)
                                .and_then(|v| v.checked_add(declared as u64))
                                .ok_or_else(|| Error::limit("section_length"))?,
                        )
                    };
                    let id = self.sections_seen;
                    self.sections_seen = self
                        .sections_seen
                        .checked_add(1)
                        .ok_or_else(|| Error::limit("sections"))?;
                    self.section = id;
                    self.section_end = end;
                    self.endian = endian;
                    self.interfaces.clear();
                    self.format = Some(Format::PcapNg);
                    kind = RecordKind::Section {
                        id,
                        declared_length: if declared < 0 {
                            None
                        } else {
                            Some(declared as u64)
                        },
                    };
                }
                1 => {
                    self.minimum(need, 20, offset, "interface")?;
                    if self.interfaces.len() >= self.limits.max_interfaces {
                        return Err(Error::limit("interfaces"));
                    }
                    options = parse_options(raw, 16, body_end, endian, offset, &self.limits)?;
                    let mut resolution = Resolution::Decimal(6);
                    let mut offset_seconds = 0;
                    let mut seen_resolution = false;
                    let mut seen_offset = false;
                    for opt in &options {
                        let value = &raw[opt.value_offset..opt.value_offset + opt.length];
                        if opt.code == 9 {
                            if value.len() != 1 || seen_resolution {
                                return Err(self.error(
                                    ErrorCode::InvalidOption,
                                    offset + opt.value_offset as u64,
                                    "if_tsresol",
                                    "expected one nonduplicated octet",
                                ));
                            }
                            resolution = Resolution::from_pcapng(value[0]);
                            seen_resolution = true;
                        } else if opt.code == 14 {
                            if value.len() != 8 || seen_offset {
                                return Err(self.error(
                                    ErrorCode::InvalidOption,
                                    offset + opt.value_offset as u64,
                                    "if_tsoffset",
                                    "expected one nonduplicated signed 64-bit value",
                                ));
                            }
                            offset_seconds = endian.u64(value) as i64;
                            seen_offset = true;
                        }
                    }
                    let interface = Interface {
                        section: self.section,
                        id: self.interfaces.len() as u32,
                        link_type: u32::from(endian.u16(&raw[8..10])),
                        snaplen: endian.u32(&raw[12..16]),
                        resolution,
                        offset_seconds,
                    };
                    self.interfaces.push(interface.clone());
                    kind = RecordKind::Interface(interface);
                }
                6 | 2 => {
                    self.minimum(need, 32, offset, "packet")?;
                    let id = if block == 2 {
                        u32::from(endian.u16(&raw[8..10]))
                    } else {
                        endian.u32(&raw[8..12])
                    };
                    let interface = self.interface(id, offset)?;
                    let cap = endian.u32(&raw[20..24]);
                    let orig = endian.u32(&raw[24..28]);
                    if cap as usize > self.limits.max_packet_bytes {
                        return Err(Error::limit("packet_bytes"));
                    }
                    let after = 28usize
                        .checked_add(align4(cap as usize)?)
                        .ok_or_else(|| Error::limit("packet_bytes"))?;
                    if after > body_end {
                        return Err(self.error(
                            ErrorCode::InvalidLength,
                            offset + 20,
                            "captured_length",
                            "packet extends beyond block",
                        ));
                    }
                    validate_lengths(
                        cap,
                        orig,
                        interface.snaplen,
                        self.mode,
                        offset,
                        &mut warnings,
                    )?;
                    options = parse_options(raw, after, body_end, endian, offset, &self.limits)?;
                    let ticks = (u64::from(endian.u32(&raw[12..16])) << 32)
                        | u64::from(endian.u32(&raw[16..20]));
                    kind = RecordKind::Packet(PacketMeta {
                        frame: self.next_frame,
                        section: self.section,
                        interface: id,
                        link_type: interface.link_type,
                        captured_len: cap,
                        original_len: orig,
                        data_offset: 28,
                        timestamp: Some(Timestamp {
                            ticks,
                            resolution: interface.resolution,
                            offset_seconds: interface.offset_seconds,
                        }),
                    });
                    self.next_frame += 1;
                }
                3 => {
                    self.minimum(need, 16, offset, "simple_packet")?;
                    let interface = self.interface(0, offset)?;
                    let orig = endian.u32(&raw[8..12]);
                    let cap = if interface.snaplen == 0 {
                        orig
                    } else {
                        orig.min(interface.snaplen)
                    };
                    if cap as usize > self.limits.max_packet_bytes {
                        return Err(Error::limit("packet_bytes"));
                    }
                    if 12usize.checked_add(align4(cap as usize)?) != Some(body_end) {
                        return Err(self.error(
                            ErrorCode::InvalidLength,
                            offset + 8,
                            "simple_packet",
                            "SPB size disagrees with original length and first interface snaplen",
                        ));
                    }
                    kind = RecordKind::Packet(PacketMeta {
                        frame: self.next_frame,
                        section: self.section,
                        interface: 0,
                        link_type: interface.link_type,
                        captured_len: cap,
                        original_len: orig,
                        data_offset: 12,
                        timestamp: None,
                    });
                    self.next_frame += 1;
                }
                4 => {
                    let mut p = 8usize;
                    let mut records = 0;
                    loop {
                        if p + 4 > body_end {
                            return Err(self.error(
                                ErrorCode::InvalidLength,
                                offset + p as u64,
                                "name_record",
                                "missing record terminator",
                            ));
                        }
                        let code = endian.u16(&raw[p..p + 2]);
                        let n = endian.u16(&raw[p + 2..p + 4]) as usize;
                        p += 4;
                        if code == 0 {
                            if n != 0 {
                                return Err(self.error(
                                    ErrorCode::InvalidLength,
                                    offset + p as u64 - 2,
                                    "name_record",
                                    "terminator has nonzero length",
                                ));
                            }
                            break;
                        }
                        if records >= self.limits.max_options {
                            return Err(Error::limit("name_records"));
                        }
                        let end = p
                            .checked_add(align4(n)?)
                            .ok_or_else(|| Error::limit("name_record"))?;
                        if end > body_end {
                            return Err(self.error(
                                ErrorCode::InvalidLength,
                                offset + p as u64,
                                "name_record",
                                "record exceeds block",
                            ));
                        }
                        let addr = if code == 1 {
                            4
                        } else if code == 2 {
                            16
                        } else {
                            0
                        };
                        if addr != 0 && (n <= addr || raw[p + n - 1] != 0) {
                            return Err(self.error(
                                ErrorCode::InvalidLength,
                                offset + p as u64,
                                "name_record",
                                "address and NUL-terminated names required",
                            ));
                        }
                        p = end;
                        records += 1;
                    }
                    options = parse_options(raw, p, body_end, endian, offset, &self.limits)?;
                    kind = RecordKind::Names { records };
                }
                5 => {
                    self.minimum(need, 24, offset, "statistics")?;
                    let id = endian.u32(&raw[8..12]);
                    let interface = self.interface(id, offset)?;
                    let timestamp = Timestamp {
                        ticks: (u64::from(endian.u32(&raw[12..16])) << 32)
                            | u64::from(endian.u32(&raw[16..20])),
                        resolution: interface.resolution,
                        offset_seconds: interface.offset_seconds,
                    };
                    options = parse_options(raw, 20, body_end, endian, offset, &self.limits)?;
                    kind = RecordKind::Statistics {
                        interface: id,
                        timestamp,
                    };
                }
                10 => {
                    self.minimum(need, 20, offset, "secrets")?;
                    let n = endian.u32(&raw[12..16]);
                    let end = 16usize
                        .checked_add(align4(n as usize)?)
                        .ok_or_else(|| Error::limit("secrets"))?;
                    if end > body_end {
                        return Err(self.error(
                            ErrorCode::InvalidLength,
                            offset + 12,
                            "secrets_length",
                            "secrets extend beyond block",
                        ));
                    }
                    options = parse_options(raw, end, body_end, endian, offset, &self.limits)?;
                    kind = RecordKind::Secrets {
                        secrets_type: endian.u32(&raw[8..12]),
                        secrets_len: n,
                    };
                }
                0x00000bad | 0x40000bad => {
                    self.minimum(need, 16, offset, "custom")?;
                    kind = RecordKind::Custom {
                        pen: endian.u32(&raw[8..12]),
                        copy_on_edit: block == 0x00000bad,
                    };
                }
                _ => {
                    kind = RecordKind::Unknown { block_type: block };
                }
            }
        }
        self.records += 1;
        Ok(Decode::Record(Record {
            offset,
            endian: record_endian,
            raw: Cow::Borrowed(raw),
            kind,
            options,
            warnings,
        }))
    }
    fn minimum(
        &self,
        actual: usize,
        expected: usize,
        offset: u64,
        field: &'static str,
    ) -> Result<()> {
        if actual < expected {
            Err(self.error(
                ErrorCode::InvalidLength,
                offset,
                field,
                "block shorter than fixed fields",
            ))
        } else {
            Ok(())
        }
    }
    fn interface(&self, id: u32, offset: u64) -> Result<&Interface> {
        self.interfaces.get(id as usize).ok_or_else(|| {
            self.error(
                ErrorCode::MissingInterface,
                offset + 8,
                "interface_id",
                "interface has not been declared in this section",
            )
        })
    }
    pub fn finish(&self, offset: u64) -> Result<()> {
        if self.format.is_none() {
            return Err(self.error(
                ErrorCode::Truncated,
                offset,
                "capture_header",
                "empty input is not a capture",
            ));
        }
        if let Some(end) = self.section_end {
            if end != offset {
                return Err(self.error(
                    ErrorCode::Truncated,
                    offset,
                    "section_length",
                    "EOF disagrees with declared section length",
                ));
            }
        }
        Ok(())
    }
}

fn validate_lengths(
    cap: u32,
    orig: u32,
    snap: u32,
    mode: ParseMode,
    offset: u64,
    warnings: &mut Vec<Warning>,
) -> Result<()> {
    if cap > orig || (snap != 0 && cap > snap) {
        if mode == ParseMode::Strict {
            return Err(Error::new(
                ErrorCode::InvalidLength,
                offset,
                "packet_lengths",
                "captured length exceeds original length or snaplen",
            ));
        }
        warnings.push(Warning {
            code: "contradictory_packet_lengths",
            offset,
        });
    }
    Ok(())
}
pub(crate) fn align4(n: usize) -> Result<usize> {
    n.checked_add(3)
        .map(|v| v & !3)
        .ok_or_else(|| Error::limit("alignment"))
}

fn parse_options(
    raw: &[u8],
    start: usize,
    end: usize,
    endian: Endian,
    offset: u64,
    limits: &Limits,
) -> Result<Vec<OptionMeta>> {
    let mut p = start;
    let mut out = Vec::new();
    while p < end {
        if end - p < 4 {
            return Err(Error::new(
                ErrorCode::InvalidOption,
                offset + p as u64,
                "option",
                "partial option header",
            ));
        }
        let code = endian.u16(&raw[p..p + 2]);
        let n = endian.u16(&raw[p + 2..p + 4]) as usize;
        p += 4;
        if code == 0 {
            if n != 0 {
                return Err(Error::new(
                    ErrorCode::InvalidOption,
                    offset + p as u64 - 2,
                    "option_end",
                    "terminator length must be zero",
                ));
            }
            // No typed meaning is assigned to bytes following the end marker.
            // Retaining raw record bytes preserves them for an exact archival copy.
            break;
        }
        if out.len() >= limits.max_options {
            return Err(Error::limit("options"));
        }
        let next = p
            .checked_add(align4(n)?)
            .ok_or_else(|| Error::limit("option_length"))?;
        if next > end {
            return Err(Error::new(
                ErrorCode::InvalidOption,
                offset + p as u64,
                "option_length",
                "option value/padding exceeds block",
            ));
        }
        if [2988, 2989, 19372, 19373].contains(&code) && n < 4 {
            return Err(Error::new(
                ErrorCode::InvalidOption,
                offset + p as u64,
                "custom_option",
                "custom option needs an enterprise number",
            ));
        }
        out.push(OptionMeta {
            code,
            value_offset: p,
            length: n,
        });
        p = next;
    }
    Ok(out)
}

pub struct CaptureIter<'a> {
    data: &'a [u8],
    position: usize,
    decoder: Decoder,
    terminal: bool,
}
impl<'a> CaptureIter<'a> {
    pub fn new(data: &'a [u8], limits: Limits, mode: ParseMode) -> Result<Self> {
        if data.len() > limits.max_input_bytes {
            return Err(Error::limit("input_bytes"));
        }
        Ok(Self {
            data,
            position: 0,
            decoder: Decoder::new(limits, mode)?,
            terminal: false,
        })
    }
}
impl<'a> Iterator for CaptureIter<'a> {
    type Item = Result<Record<'a>>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.terminal {
            return None;
        }
        if self.position == self.data.len() {
            self.terminal = true;
            return self.decoder.finish(self.position as u64).err().map(Err);
        }
        match self
            .decoder
            .decode(&self.data[self.position..], self.position as u64)
        {
            Ok(Decode::Record(record)) => {
                self.position += record.raw.len();
                Some(Ok(record))
            }
            Ok(Decode::NeedMore(need)) => {
                self.terminal = true;
                Some(Err(Error::new(
                    ErrorCode::Truncated,
                    self.position as u64,
                    "record",
                    format!(
                        "need {need} bytes; have {}",
                        self.data.len() - self.position
                    ),
                )))
            }
            Err(e) => {
                self.terminal = true;
                Some(Err(e))
            }
        }
    }
}
impl std::iter::FusedIterator for CaptureIter<'_> {}

/// Streaming adapter returns owned records. The slice iterator is the zero-copy path.
pub struct CaptureReader<R: Read> {
    reader: R,
    decoder: Decoder,
    buffer: Vec<u8>,
    offset: u64,
    terminal: bool,
    max_input: u64,
}
impl<R: Read> CaptureReader<R> {
    pub fn new(reader: R, limits: Limits, mode: ParseMode) -> Result<Self> {
        let max_input = limits.max_input_bytes as u64;
        Ok(Self {
            reader,
            decoder: Decoder::new(limits, mode)?,
            buffer: Vec::new(),
            offset: 0,
            terminal: false,
            max_input,
        })
    }
    pub fn into_inner(self) -> R {
        self.reader
    }
    pub fn next_record(&mut self) -> Result<Option<Record<'static>>> {
        if self.terminal {
            return Ok(None);
        }
        let result = self.read_one();
        if result.is_err() {
            self.terminal = true;
        }
        result
    }
    fn read_one(&mut self) -> Result<Option<Record<'static>>> {
        self.buffer.clear();
        loop {
            let need = self.decoder.required(&self.buffer, self.offset)?;
            if self.buffer.len() >= need {
                match self.decoder.decode(&self.buffer, self.offset)? {
                    Decode::Record(record) => {
                        let record = record.into_owned();
                        self.offset = self
                            .offset
                            .checked_add(record.raw.len() as u64)
                            .ok_or_else(|| Error::limit("file_offset"))?;
                        return Ok(Some(record));
                    }
                    Decode::NeedMore(_) => {
                        return Err(Error::new(
                            ErrorCode::Invariant,
                            self.offset,
                            "decoder",
                            "required/decode disagreement",
                        ))
                    }
                }
            }
            let old = self.buffer.len();
            let mut scratch = [0u8; 8192];
            let count = (need - old).min(scratch.len());
            let read = match self.reader.read(&mut scratch[..count]) {
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                result => result?,
            };
            if read == 0 {
                self.terminal = true;
                if old == 0 {
                    self.decoder.finish(self.offset)?;
                    return Ok(None);
                }
                return Err(Error::new(
                    ErrorCode::Truncated,
                    self.offset,
                    "record",
                    format!("EOF after {old} bytes; need {need}"),
                ));
            }
            if self
                .offset
                .checked_add((old + read) as u64)
                .is_none_or(|end| end > self.max_input)
            {
                return Err(Error::limit("input_bytes"));
            }
            self.buffer
                .try_reserve(read)
                .map_err(|_| Error::limit("read_buffer"))?;
            self.buffer.extend_from_slice(&scratch[..read]);
        }
    }
}

impl<R: Read> Iterator for CaptureReader<R> {
    type Item = Result<Record<'static>>;
    fn next(&mut self) -> Option<Self::Item> {
        match self.next_record() {
            Ok(Some(record)) => Some(Ok(record)),
            Ok(None) => None,
            Err(error) => Some(Err(error)),
        }
    }
}
impl<R: Read> std::iter::FusedIterator for CaptureReader<R> {}

/// Explicit forensic navigation only: finds a structurally valid aligned SHB.
/// The caller must record the skipped range and start a fresh decoder there.
pub fn find_next_section(
    data: &[u8],
    start: usize,
    max_scan: usize,
    limits: &Limits,
) -> Option<usize> {
    let end = data.len().min(start.saturating_add(max_scan));
    let mut p = start.checked_add(3)? & !3;
    while p.checked_add(28)? <= end {
        if data[p..p + 4] == [0x0a, 0x0d, 0x0d, 0x0a] {
            let mut decoder = Decoder::new(limits.clone(), ParseMode::Strict).ok()?;
            if let Ok(Decode::Record(record)) = decoder.decode(&data[p..end], p as u64) {
                if matches!(record.kind(), RecordKind::Section { .. }) {
                    return Some(p);
                }
            }
        }
        p = p.checked_add(4)?;
    }
    None
}
