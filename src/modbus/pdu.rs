//! Role-specific PDU grammar from Modbus Application Protocol V1.1b3 §6.
//! Offsets in this module are relative to the function byte (ADU offset 7).
use super::Role;
use crate::{Error, ErrorCode, Result};

#[derive(Debug)]
pub(crate) enum Pdu<'a> {
    Read {
        start: u16,
        count: u16,
    },
    ReadData(&'a [u8]),
    Single,
    Multiple {
        start: u16,
        count: u16,
        data: &'a [u8],
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
        data: &'a [u8],
    },
    FifoRequest,
    FifoData(&'a [u8]),
    Files(Vec<FileRecord<'a>>),
    DeviceRequest,
    DevicePage(Vec<Object<'a>>),
    Exception(u8),
    Opaque,
}

#[derive(Debug)]
pub(crate) struct FileRecord<'a> {
    pub offset: usize,
    pub address: Option<(u16, u16)>,
    pub words: u16,
    pub data: &'a [u8],
}

#[derive(Debug)]
pub(crate) struct Object<'a> {
    pub offset: usize,
    pub id: u8,
    pub value: &'a [u8],
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
    b.get(at).copied().ok_or_else(|| {
        Error::new(
            ErrorCode::Truncated,
            (7 + at) as u64,
            "modbus_pdu_truncated",
            "missing PDU field",
        )
    })
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
    require(b.len() == len, 0, "modbus_pdu_shape")
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
        || matches!(b, [43, 14, ..] | [0xab, ..])
}
pub(crate) fn parse(b: &[u8], role: Role) -> Result<Pdu<'_>> {
    let f = byte(b, 0)?;
    require(
        b.len() <= 253 && f & 0x7f != 0 && role != Role::Unknown,
        0,
        "modbus_pdu_shape",
    )?;
    if f & 0x80 != 0 {
        exact(b, 2)?;
        require(
            role == Role::Response && matches!(b[1], 1..=6 | 8 | 10 | 11),
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
            let n = usize::from(byte(b, 1)?);
            require(
                (1..=250).contains(&n) && b.len() == 2 + n && (f <= 2 || n % 2 == 0),
                1,
                "modbus_read_response_byte_count",
            )?;
            Ok(Pdu::ReadData(&b[2..]))
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
            let (start, count) = range(b, 1, if f == 15 { 1968 } else { 123 })?;
            if !request {
                exact(b, 5)?;
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
                data: &b[6..],
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
                data: &b[10..],
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
            Ok(Pdu::FifoData(&b[5..]))
        }
        43 if byte(b, 1)? == 14 => device(b, request),
        _ => Ok(Pdu::Opaque),
    }
}

fn file_records(b: &[u8], write: bool, request: bool) -> Result<Pdu<'_>> {
    let len = usize::from(byte(b, 1)?);
    require(
        len > 0 && len + 2 == b.len() && (write || !request || len <= 245),
        1,
        "modbus_file_bytes",
    )?;
    let mut records = Vec::new();
    let mut at = 2;
    let mut expected_response = 2;
    while at < b.len() {
        let offset = at;
        if write || request {
            require(byte(b, at)? == 6, at, "modbus_file_reference")?;
            let file = word(b, at + 1)?;
            let record = word(b, at + 3)?;
            let words = word(b, at + 5)?;
            require(
                file != 0 && words != 0 && u32::from(record) + u32::from(words) <= 10000,
                at + 1,
                "modbus_file_range",
            )?;
            at += 7;
            let bytes = usize::from(words) * 2;
            let end = if write { at + bytes } else { at };
            let data = b
                .get(at..end)
                .ok_or_else(|| invalid(at, "modbus_file_data"))?;
            if !write {
                expected_response += 2 + bytes;
                require(
                    expected_response <= 253,
                    offset,
                    "modbus_file_response_size",
                )?;
            }
            records.push(FileRecord {
                offset,
                address: Some((file, record)),
                words,
                data,
            });
            at = end;
        } else {
            let n = usize::from(byte(b, at)?);
            require(
                n >= 3 && n % 2 == 1 && byte(b, at + 1)? == 6,
                at,
                "modbus_file_response",
            )?;
            at += 1 + n;
            let data = b
                .get(offset + 2..at)
                .ok_or_else(|| invalid(offset, "modbus_file_data"))?;
            records.push(FileRecord {
                offset,
                address: None,
                words: (data.len() / 2) as u16,
                data,
            });
        }
    }
    Ok(Pdu::Files(records))
}

fn device(b: &[u8], request: bool) -> Result<Pdu<'_>> {
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
    let mut objects: Vec<Object<'_>> = Vec::new();
    let mut at = 7;
    for _ in 0..count {
        let id = byte(b, at)?;
        require(
            permitted(id) && objects.last().is_none_or(|o| o.id < id),
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
            value,
        });
        at = end;
    }
    exact(b, at)?;
    require(
        more == 0 || (permitted(next) && objects.last().is_some_and(|o| o.id < next)),
        5,
        "modbus_device_next_id",
    )?;
    Ok(Pdu::DevicePage(objects))
}
