//! Canonical little-endian, length-delimited codec. No unchecked input offsets.
use crate::{bad, Error, Result};

#[derive(Default)]
pub struct Encoder(pub Vec<u8>);
impl Encoder {
    pub fn u8(&mut self, v: u8) {
        self.0.push(v);
    }
    pub fn u16(&mut self, v: u16) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }
    pub fn u32(&mut self, v: u32) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }
    pub fn u64(&mut self, v: u64) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }
    pub fn i64(&mut self, v: i64) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }
    pub fn i128(&mut self, v: i128) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }
    pub fn hash(&mut self, v: &[u8; 32]) {
        self.0.extend_from_slice(v);
    }
    pub fn bytes(&mut self, b: &[u8]) -> Result<()> {
        self.u32(u32::try_from(b.len()).map_err(|_| Error::limit("history_blob"))?);
        self.0.extend_from_slice(b);
        Ok(())
    }
    pub fn text(&mut self, v: &str) -> Result<()> {
        self.bytes(v.as_bytes())
    }
    pub fn option_u32(&mut self, v: Option<u32>) {
        self.u8(u8::from(v.is_some()));
        if let Some(n) = v {
            self.u32(n);
        }
    }
    pub fn option_i64(&mut self, v: Option<i64>) {
        self.u8(u8::from(v.is_some()));
        if let Some(n) = v {
            self.i64(n);
        }
    }
    pub fn option_i128(&mut self, v: Option<i128>) {
        self.u8(u8::from(v.is_some()));
        if let Some(n) = v {
            self.i128(n);
        }
    }
}
pub struct Decoder<'a> {
    bytes: &'a [u8],
    at: usize,
}
impl<'a> Decoder<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }
    pub fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .at
            .checked_add(n)
            .ok_or_else(|| Error::limit("history_offset"))?;
        let out = self
            .bytes
            .get(self.at..end)
            .ok_or_else(|| bad("history_record", "truncated field"))?;
        self.at = end;
        Ok(out)
    }
    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    pub fn boolean(&mut self) -> Result<bool> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(bad("history_bool", "noncanonical boolean")),
        }
    }
    pub fn u16(&mut self) -> Result<u16> {
        let mut a = [0; 2];
        a.copy_from_slice(self.take(2)?);
        Ok(u16::from_le_bytes(a))
    }
    pub fn u32(&mut self) -> Result<u32> {
        let mut a = [0; 4];
        a.copy_from_slice(self.take(4)?);
        Ok(u32::from_le_bytes(a))
    }
    pub fn u64(&mut self) -> Result<u64> {
        let mut a = [0; 8];
        a.copy_from_slice(self.take(8)?);
        Ok(u64::from_le_bytes(a))
    }
    pub fn i64(&mut self) -> Result<i64> {
        let mut a = [0; 8];
        a.copy_from_slice(self.take(8)?);
        Ok(i64::from_le_bytes(a))
    }
    pub fn i128(&mut self) -> Result<i128> {
        let mut a = [0; 16];
        a.copy_from_slice(self.take(16)?);
        Ok(i128::from_le_bytes(a))
    }
    pub fn hash(&mut self) -> Result<[u8; 32]> {
        let mut a = [0; 32];
        a.copy_from_slice(self.take(32)?);
        Ok(a)
    }
    pub fn bytes(&mut self, max: usize) -> Result<&'a [u8]> {
        let n = usize::try_from(self.u32()?).map_err(|_| Error::limit("history_blob"))?;
        if n > max {
            return Err(Error::limit("history_blob"));
        }
        self.take(n)
    }
    pub fn text(&mut self, max: usize) -> Result<String> {
        std::str::from_utf8(self.bytes(max)?)
            .map(str::to_owned)
            .map_err(|_| bad("history_text", "invalid UTF-8"))
    }
    pub fn option_u32(&mut self) -> Result<Option<u32>> {
        if self.boolean()? {
            Ok(Some(self.u32()?))
        } else {
            Ok(None)
        }
    }
    pub fn option_i64(&mut self) -> Result<Option<i64>> {
        if self.boolean()? {
            Ok(Some(self.i64()?))
        } else {
            Ok(None)
        }
    }
    pub fn option_i128(&mut self) -> Result<Option<i128>> {
        if self.boolean()? {
            Ok(Some(self.i128()?))
        } else {
            Ok(None)
        }
    }
    pub fn finish(self) -> Result<()> {
        if self.at == self.bytes.len() {
            Ok(())
        } else {
            Err(bad("history_record", "trailing bytes"))
        }
    }
}
