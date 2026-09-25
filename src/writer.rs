//! New-capture writers validate before each write. Exact archival copying is separate
//! from editing: unknown non-copyable extensions are not transplanted into new files.
use crate::capture::{align4, CaptureIter, Endian, Interface, ParseMode};
use crate::time::{Resolution, Timestamp};
use crate::{Error, ErrorCode, Limits, Result};
use std::io::Write;

pub struct PcapWriter<W: Write> {
    output: W,
    endian: Endian,
    nanos: bool,
    snaplen: u32,
    limits: Limits,
    failed: bool,
}
impl<W: Write> PcapWriter<W> {
    pub fn new(
        mut output: W,
        endian: Endian,
        nanos: bool,
        link_type: u16,
        snaplen: u32,
        limits: Limits,
    ) -> Result<Self> {
        limits.validate()?;
        if snaplen == 0 {
            return Err(Error::new(
                ErrorCode::InvalidLength,
                0,
                "snaplen",
                "must be nonzero",
            ));
        }
        let mut h = Vec::with_capacity(24);
        endian.put_u32(if nanos { 0xa1b23c4d } else { 0xa1b2c3d4 }, &mut h);
        endian.put_u16(2, &mut h);
        endian.put_u16(4, &mut h);
        endian.put_u32(0, &mut h);
        endian.put_u32(0, &mut h);
        endian.put_u32(snaplen, &mut h);
        endian.put_u32(u32::from(link_type), &mut h);
        output.write_all(&h)?;
        Ok(Self {
            output,
            endian,
            nanos,
            snaplen,
            limits,
            failed: false,
        })
    }
    pub fn packet(&mut self, timestamp: Timestamp, original_len: u32, data: &[u8]) -> Result<()> {
        if self.failed {
            return Err(writer_failed());
        }
        if data.len() > self.limits.max_packet_bytes
            || data.len() > self.snaplen as usize
            || data.len() > original_len as usize
        {
            return Err(Error::new(
                ErrorCode::InvalidLength,
                0,
                "packet",
                "capture length exceeds budget, snaplen, or original length",
            ));
        }
        let (sec, frac) = timestamp.legacy_parts(self.nanos)?;
        let cap = u32::try_from(data.len()).map_err(|_| Error::limit("packet_bytes"))?;
        let mut header = Vec::with_capacity(16);
        self.endian.put_u32(sec, &mut header);
        self.endian.put_u32(frac, &mut header);
        self.endian.put_u32(cap, &mut header);
        self.endian.put_u32(original_len, &mut header);
        if let Err(error) = self
            .output
            .write_all(&header)
            .and_then(|_| self.output.write_all(data))
        {
            self.failed = true;
            return Err(error.into());
        }
        Ok(())
    }
    pub fn finish(mut self) -> Result<W> {
        if self.failed {
            return Err(writer_failed());
        }
        self.output.flush()?;
        Ok(self.output)
    }
}

pub struct PcapNgWriter<W: Write> {
    output: W,
    endian: Endian,
    interfaces: Vec<Interface>,
    limits: Limits,
    failed: bool,
}
impl<W: Write> PcapNgWriter<W> {
    pub fn new(output: W, endian: Endian, limits: Limits) -> Result<Self> {
        limits.validate()?;
        let mut writer = Self {
            output,
            endian,
            interfaces: Vec::new(),
            limits,
            failed: false,
        };
        let mut body = Vec::new();
        endian.put_u32(0x1a2b3c4d, &mut body);
        endian.put_u16(1, &mut body);
        endian.put_u16(0, &mut body);
        endian.put_u64(u64::MAX, &mut body);
        writer.block(0x0a0d0d0a, &body)?;
        Ok(writer)
    }
    fn block(&mut self, ty: u32, body: &[u8]) -> Result<()> {
        if self.failed {
            return Err(writer_failed());
        }
        let total = body
            .len()
            .checked_add(12)
            .ok_or_else(|| Error::limit("block_bytes"))?;
        if total > self.limits.max_block_bytes || total % 4 != 0 {
            return Err(Error::limit("block_bytes"));
        }
        let total = u32::try_from(total).map_err(|_| Error::limit("block_bytes"))?;
        let mut header = Vec::with_capacity(8);
        self.endian.put_u32(ty, &mut header);
        self.endian.put_u32(total, &mut header);
        let mut trailer = Vec::with_capacity(4);
        self.endian.put_u32(total, &mut trailer);
        if let Err(error) = self
            .output
            .write_all(&header)
            .and_then(|_| self.output.write_all(body))
            .and_then(|_| self.output.write_all(&trailer))
        {
            self.failed = true;
            return Err(error.into());
        }
        Ok(())
    }
    pub fn interface(
        &mut self,
        link_type: u16,
        snaplen: u32,
        resolution: Resolution,
        offset_seconds: i64,
    ) -> Result<u32> {
        if self.failed {
            return Err(writer_failed());
        }
        if self.interfaces.len() >= self.limits.max_interfaces {
            return Err(Error::limit("interfaces"));
        }
        let res = resolution.to_pcapng()?;
        let id = u32::try_from(self.interfaces.len()).map_err(|_| Error::limit("interfaces"))?;
        let mut body = Vec::new();
        self.endian.put_u16(link_type, &mut body);
        self.endian.put_u16(0, &mut body);
        self.endian.put_u32(snaplen, &mut body);
        option(&mut body, self.endian, 9, &[res])?;
        let mut off = Vec::new();
        self.endian.put_u64(offset_seconds as u64, &mut off);
        option(&mut body, self.endian, 14, &off)?;
        option(&mut body, self.endian, 0, &[])?;
        self.block(1, &body)?;
        self.interfaces.push(Interface {
            section: 0,
            id,
            link_type: u32::from(link_type),
            snaplen,
            resolution,
            offset_seconds,
        });
        Ok(id)
    }
    pub fn packet(
        &mut self,
        interface_id: u32,
        timestamp: Timestamp,
        original_len: u32,
        data: &[u8],
    ) -> Result<()> {
        if self.failed {
            return Err(writer_failed());
        }
        let iface = self.interfaces.get(interface_id as usize).ok_or_else(|| {
            Error::new(
                ErrorCode::MissingInterface,
                0,
                "interface",
                "declare interface before packet",
            )
        })?;
        if timestamp.resolution != iface.resolution
            || timestamp.offset_seconds != iface.offset_seconds
        {
            return Err(Error::new(
                ErrorCode::InvalidTimestamp,
                0,
                "timestamp",
                "raw clock semantics must match the interface exactly",
            ));
        }
        if data.len() > self.limits.max_packet_bytes
            || data.len() > original_len as usize
            || (iface.snaplen != 0 && data.len() > iface.snaplen as usize)
        {
            return Err(Error::new(
                ErrorCode::InvalidLength,
                0,
                "packet",
                "invalid captured length",
            ));
        }
        let total = 20usize
            .checked_add(align4(data.len())?)
            .ok_or_else(|| Error::limit("block_bytes"))?;
        if total
            .checked_add(12)
            .is_none_or(|v| v > self.limits.max_block_bytes)
        {
            return Err(Error::limit("block_bytes"));
        }
        let cap = u32::try_from(data.len()).map_err(|_| Error::limit("packet_bytes"))?;
        let mut body = Vec::with_capacity(total);
        self.endian.put_u32(interface_id, &mut body);
        self.endian
            .put_u32((timestamp.ticks >> 32) as u32, &mut body);
        self.endian.put_u32(timestamp.ticks as u32, &mut body);
        self.endian.put_u32(cap, &mut body);
        self.endian.put_u32(original_len, &mut body);
        body.extend_from_slice(data);
        body.resize(total, 0);
        self.block(6, &body)
    }
    pub fn finish(mut self) -> Result<W> {
        if self.failed {
            return Err(writer_failed());
        }
        self.output.flush()?;
        Ok(self.output)
    }
}
fn option(body: &mut Vec<u8>, endian: Endian, code: u16, value: &[u8]) -> Result<()> {
    let len = u16::try_from(value.len()).map_err(|_| Error::limit("option"))?;
    endian.put_u16(code, body);
    endian.put_u16(len, body);
    body.extend_from_slice(value);
    let padded = align4(body.len())?;
    body.resize(padded, 0);
    Ok(())
}

/// Validate the entire immutable snapshot before publishing an exact byte copy.
/// This is not a semantic edit or a conversion to another container format.
pub fn copy_exact<W: Write>(
    input: &[u8],
    mut output: W,
    limits: Limits,
    mode: ParseMode,
) -> Result<W> {
    for record in CaptureIter::new(input, limits, mode)? {
        record?;
    }
    output.write_all(input)?;
    output.flush()?;
    Ok(output)
}

fn writer_failed() -> Error {
    Error::new(ErrorCode::Io, 0, "writer_failed", "an earlier write failed; discard this writer rather than retrying an unknown partial write")
}
