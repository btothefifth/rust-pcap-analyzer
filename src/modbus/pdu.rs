//! Role-specific PDU grammar from Modbus Application Protocol V1.1b3 §6.
//! Offsets in this module are relative to the function byte (ADU offset 7).
use super::Role;
use crate::{Error, ErrorCode, Result};

#[derive(Clone, Debug)]
pub(crate) enum Pdu {
    Read {
        start: u16,
        count: u16,
    },
    ReadData(usize),
    Single,
    Multiple {
        start: u16,
        count: u16,
        data_len: usize,
    },
    WriteAck {
        start: u16,
        count: u16,
    },
    Mask,
    ReadWrite {
        start: u16,
        count: u16,
        write_start: u16,
        write_count: u16,
        data_len: usize,
    },
    FifoRequest,
    FifoData(usize),
    Files(Vec<FileRecord>, Option<Error>),
    DeviceRequest,
    DevicePage(Vec<Object>, Option<Error>),
    Exception(u8),
    Opaque,
}

#[derive(Clone, Debug)]
pub(crate) struct FileRecord {
    pub offset: usize,
    pub address: Option<(u16, u16)>,
    pub words: u16,
    pub data_len: usize,
}

#[derive(Clone, Debug)]
pub(crate) struct Object {
    pub offset: usize,
    pub id: u8,
    pub value_len: usize,
}

impl Pdu {
    pub(crate) fn complete(&self) -> bool {
        !matches!(self, Pdu::Files(_, Some(_)) | Pdu::DevicePage(_, Some(_)))
    }
}
fn invalid(at: usize, field: &'static str) -> Error {
    Error::new(
        ErrorCode::InvalidLength,
        (7 + at) as u64,
        field,
        "invalid Modbus PDU",
    )
}
fn byte(b: &[u8], at: usize) -> Result<u8> {
    b.get(at)
        .copied()
        .ok_or_else(|| invalid(at, "modbus_pdu_missing_field"))
}
fn word(b: &[u8], at: usize) -> Result<u16> {
    Ok(u16::from_be_bytes([byte(b, at)?, byte(b, at + 1)?]))
}
fn require(ok: bool, at: usize, field: &'static str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(invalid(at, field))
    }
}
fn exact(b: &[u8], len: usize) -> Result<()> {
    if b.len() == len {
        Ok(())
    } else {
        Err(Error::new(
            ErrorCode::InvalidLength,
            0,
            "modbus_pdu_shape",
            "unexpected PDU length",
        ))
    }
}
fn range(b: &[u8], at: usize, limit: u16) -> Result<(u16, u16)> {
    let start = word(b, at)?;
    let count = word(b, at + 2)?;
    require(
        (1..=limit).contains(&count) && u32::from(start) + u32::from(count) <= 65536,
        at,
        "modbus_address_quantity_range",
    )?;
    Ok((start, count))
}
pub(crate) fn supported(b: &[u8]) -> bool {
    matches!(b.first().map(|f| f & 0x7f), Some(1..=6 | 15 | 16 | 20..=24))
        || matches!(b, [43] | [43, 14, ..] | [0xab, ..])
}
#[cfg(test)]
std::thread_local! {pub(super) static PARSES:std::cell::Cell<usize>=const {std::cell::Cell::new(0)};}

pub(crate) fn parse(b: &[u8], role: Role) -> Result<Pdu> {
    #[cfg(test)]
    PARSES.with(|n| n.set(n.get() + 1));
    let f = byte(b, 0)?;
    require(
        b.len() <= 253 && f & 0x7f != 0 && role != Role::Unknown,
        0,
        "modbus_pdu_shape",
    )?;
    if f & 0x80 != 0 {
        exact(b, 2)?;
        require(
            role == Role::Response
                && match f & 0x7f {
                    20 | 21 => matches!(b[1], 1..=4 | 8 | 10 | 11),
                    22..=24 | 43 => matches!(b[1], 1..=4 | 10 | 11),
                    _ => matches!(b[1], 1..=6 | 8 | 10 | 11),
                },
            1,
            "modbus_exception_role_or_code",
        )?;
        return Ok(Pdu::Exception(b[1]));
    }
    let request = role == Role::Request;
    match f {
        1..=4 if request => {
            exact(b, 5)?;
            let (start, count) = range(b, 1, if f <= 2 { 2000 } else { 125 })?;
            Ok(Pdu::Read { start, count })
        }
        1..=4 | 23 if !request => {
            let n = usize::from(*b.get(1).ok_or_else(|| {
                if f == 23 {
                    return invalid(1, "modbus_pdu_missing_field");
                }
                Error::new(
                    ErrorCode::Truncated,
                    8,
                    "modbus_byte_count_truncated",
                    "missing byte count",
                )
            })?);
            require(
                (1..=250).contains(&n) && b.len() == 2 + n && (f <= 2 || n % 2 == 0),
                1,
                "modbus_read_response_byte_count",
            )?;
            Ok(Pdu::ReadData(n))
        }
        5 | 6 => {
            exact(b, 5)?;
            require(
                f != 5 || matches!(word(b, 3)?, 0 | 0xff00),
                3,
                "modbus_single_coil_encoding",
            )?;
            Ok(Pdu::Single)
        }
        15 | 16 => {
            if !request {
                exact(b, 5)?;
            } else if b.len() < 6 {
                return Err(Error::new(
                    ErrorCode::Truncated,
                    8,
                    "modbus_write_header_truncated",
                    "missing write header",
                ));
            }
            let (start, count) = range(b, 1, if f == 15 { 1968 } else { 123 })?;
            if !request {
                return Ok(Pdu::WriteAck { start, count });
            }
            let bytes = if f == 15 {
                usize::from(count).div_ceil(8)
            } else {
                usize::from(count) * 2
            };
            require(
                usize::from(byte(b, 5)?) == bytes && b.len() == 6 + bytes,
                5,
                "modbus_write_byte_count",
            )?;
            Ok(Pdu::Multiple {
                start,
                count,
                data_len: bytes,
            })
        }
        20 | 21 => file_records(b, f == 21, request),
        22 => {
            exact(b, 7)?;
            Ok(Pdu::Mask)
        }
        23 => {
            let (start, count) = range(b, 1, 125)?;
            let (write_start, write_count) = range(b, 5, 121)?;
            let bytes = usize::from(write_count) * 2;
            require(
                usize::from(byte(b, 9)?) == bytes && b.len() == 10 + bytes,
                9,
                "modbus_write_byte_count",
            )?;
            Ok(Pdu::ReadWrite {
                start,
                count,
                write_start,
                write_count,
                data_len: bytes,
            })
        }
        24 if request => {
            exact(b, 3)?;
            Ok(Pdu::FifoRequest)
        }
        24 => {
            let bytes = usize::from(word(b, 1)?);
            let count = usize::from(word(b, 3)?);
            require(
                count <= 31 && bytes == 2 + 2 * count && b.len() == 3 + bytes,
                1,
                "modbus_fifo_count",
            )?;
            Ok(Pdu::FifoData(count))
        }
        43 if byte(b, 1)? == 14 => device(b, request),
        _ => Ok(Pdu::Opaque),
    }
}

fn file_records(b: &[u8], write: bool, request: bool) -> Result<Pdu> {
    let len = usize::from(byte(b, 1)?);
    let count_error = (len == 0 || len + 2 != b.len() || (!write && len > 245))
        .then(|| invalid(1, "modbus_file_bytes"));
    let max_count = if write { len } else { len.min(245) };
    let b = &b[..b.len().min(2 + max_count)];
    let mut records = Vec::new();
    let mut offset = 2;
    let mut response_bytes = 0;
    while offset < b.len() {
        let parsed = if write || request {
            file_address_record(b, offset, write)
        } else {
            file_response_record(b, offset)
        };
        let record = match parsed {
            Ok(record) => record,
            Err(error) => return Ok(Pdu::Files(records, Some(count_error.unwrap_or(error)))),
        };
        if request && !write {
            response_bytes += 2 + 2 * usize::from(record.words);
            if response_bytes > 245 {
                return Ok(Pdu::Files(
                    records,
                    Some(invalid(offset, "modbus_file_response_size")),
                ));
            }
        }
        offset += if record.address.is_some() { 7 } else { 2 };
        offset += record.data_len;
        records.push(record);
    }
    Ok(Pdu::Files(records, count_error))
}
fn file_address_record(b: &[u8], offset: usize, write: bool) -> Result<FileRecord> {
    require(byte(b, offset)? == 6, offset, "modbus_file_reference")?;
    let file = word(b, offset + 1)?;
    let record = word(b, offset + 3)?;
    let words = word(b, offset + 5)?;
    require(
        file != 0 && words != 0 && u32::from(record) + u32::from(words) <= 10000,
        offset + 1,
        "modbus_file_range",
    )?;
    let data_len = if write { usize::from(words) * 2 } else { 0 };
    require(
        offset + 7 + data_len <= b.len(),
        offset + 7,
        "modbus_file_data",
    )?;
    Ok(FileRecord {
        offset,
        address: Some((file, record)),
        words,
        data_len,
    })
}
fn file_response_record(b: &[u8], offset: usize) -> Result<FileRecord> {
    let n = usize::from(byte(b, offset)?);
    require(
        n >= 3 && n % 2 == 1 && byte(b, offset + 1)? == 6,
        offset,
        "modbus_file_response",
    )?;
    require(offset + 1 + n <= b.len(), offset, "modbus_file_data")?;
    Ok(FileRecord {
        offset,
        address: None,
        words: (n / 2) as u16,
        data_len: n - 1,
    })
}

fn device(b: &[u8], request: bool) -> Result<Pdu> {
    let category = byte(b, 2)?;
    require((1..=4).contains(&category), 2, "modbus_device_category")?;
    if request {
        exact(b, 4)?;
        return Ok(Pdu::DeviceRequest);
    }
    let level = byte(b, 3)?;
    let more = byte(b, 4)?;
    let next = byte(b, 5)?;
    let count = byte(b, 6)?;
    require(
        matches!(level,1..=3|0x81..=0x83)
            && matches!(more, 0 | 255)
            && (more != 0 || next == 0)
            && count > 0
            && (category != 4 || (level >= 0x81 && more == 0 && count == 1)),
        3,
        "modbus_device_page",
    )?;
    let access = if category == 4 {
        level & 0x7f
    } else {
        category.min(level & 0x7f)
    };
    let permitted = |id: u8| {
        matches!(id, 0..=2) || (access >= 2 && matches!(id, 3..=6)) || (access == 3 && id >= 128)
    };
    let mut objects: Vec<Object> = Vec::new();
    let mut at = 7;
    let terminal = (|| -> Result<()> {
        for _ in 0..count {
            let id = byte(b, at)?;
            require(
                permitted(id)
                    && objects
                        .last()
                        .is_none_or(|o| o.id < id && (o.id >= 2 || id == o.id + 1)),
                at,
                "modbus_device_object_id",
            )?;
            let n = usize::from(byte(b, at + 1)?);
            let end = at + 2 + n;
            let value = b
                .get(at + 2..end)
                .ok_or_else(|| invalid(at, "modbus_device_object_length"))?;
            require(
                id > 6 || value.is_ascii(),
                at + 2,
                "modbus_device_ascii_string",
            )?;
            objects.push(Object {
                offset: at,
                id,
                value_len: value.len(),
            });
            at = end;
        }
        exact(b, at)?;
        require(
            more == 0 || (permitted(next) && objects.last().is_some_and(|o| o.id < next)),
            5,
            "modbus_device_next_id",
        )?;
        if category != 4 {
            if let Some(last) = objects.last().filter(|o| o.id < 2) {
                require(
                    more == 255 && next == last.id + 1,
                    5,
                    "modbus_missing_basic_object",
                )?;
            }
        }
        Ok(())
    })()
    .err();
    Ok(Pdu::DevicePage(objects, terminal))
}
