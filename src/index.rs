//! Versioned sidecars are rebuildable projections, never an authority over bytes.
//! Verification intentionally hashes AND re-parses the immutable source once.
use crate::capture::{CaptureIter, Endian, PacketMeta, ParseMode};
use crate::sha256;
use crate::{Error, ErrorCode, Limits, Result};
const MAGIC: &[u8; 8] = b"PCIDX001";
const HEADER: usize = 56;
const ENTRY: usize = 64;
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IndexEntry {
    pub record_offset: u64,
    pub record_length: u32,
    pub packet: PacketMeta,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Index {
    source_len: u64,
    source_sha256: [u8; 32],
    entries: Vec<IndexEntry>,
}
impl Index {
    pub fn build(source: &[u8], limits: Limits) -> Result<Self> {
        let mut entries = Vec::new();
        for record in CaptureIter::new(source, limits, ParseMode::Strict)? {
            let record = record?;
            if let Some((packet, _)) = record.packet() {
                entries.push(IndexEntry {
                    record_offset: record.offset(),
                    record_length: u32::try_from(record.raw().len())
                        .map_err(|_| Error::limit("index_record_length"))?,
                    packet: packet.clone(),
                });
            }
        }
        Ok(Self {
            source_len: source.len() as u64,
            source_sha256: sha256::digest(source),
            entries,
        })
    }
    pub fn entries(&self) -> &[IndexEntry] {
        &self.entries
    }
    pub fn source_sha256(&self) -> [u8; 32] {
        self.source_sha256
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        let capacity = self
            .entries
            .len()
            .checked_mul(ENTRY)
            .and_then(|x| x.checked_add(HEADER + 32))
            .ok_or_else(|| Error::limit("index_bytes"))?;
        let mut out = Vec::with_capacity(capacity);
        let le = Endian::Little;
        out.extend_from_slice(MAGIC);
        le.put_u64(self.source_len, &mut out);
        out.extend_from_slice(&self.source_sha256);
        le.put_u64(self.entries.len() as u64, &mut out);
        for entry in &self.entries {
            let p = &entry.packet;
            le.put_u64(entry.record_offset, &mut out);
            le.put_u32(entry.record_length, &mut out);
            le.put_u32(
                u32::try_from(p.data_offset).map_err(|_| Error::limit("index_data_offset"))?,
                &mut out,
            );
            le.put_u32(p.captured_len, &mut out);
            le.put_u32(p.original_len, &mut out);
            le.put_u64(p.frame, &mut out);
            le.put_u32(p.section, &mut out);
            le.put_u32(p.interface, &mut out);
            le.put_u32(p.link_type, &mut out);
            if let Some(time) = p.timestamp {
                out.push(1);
                out.push(time.resolution.to_pcapng()?);
                le.put_u16(0, &mut out);
                le.put_u64(time.ticks, &mut out);
                le.put_u64(time.offset_seconds as u64, &mut out);
            } else {
                out.extend_from_slice(&[0; 20]);
            }
        }
        let digest = sha256::digest(&out);
        out.extend_from_slice(&digest);
        Ok(out)
    }
}
/// Keeps the exact immutable source borrow used for verification. A filename,
/// mtime or sidecar self-hash alone cannot create this type.
pub struct VerifiedIndex<'a> {
    source: &'a [u8],
    index: Index,
    sorted_times: Vec<(i128, u64)>,
    unknown_times: Vec<u64>,
}
#[derive(Debug, Eq, PartialEq)]
pub struct TimeQuery {
    pub frames: Vec<u64>,
    pub unresolved_frames: Vec<u64>,
}
impl<'a> VerifiedIndex<'a> {
    pub fn build(source: &'a [u8], limits: Limits) -> Result<Self> {
        Ok(Self::from_canonical(source, Index::build(source, limits)?))
    }
    pub fn load(source: &'a [u8], sidecar: &[u8], limits: Limits) -> Result<Self> {
        limits.validate()?;
        if sidecar.len() < HEADER + 32 {
            return Err(invalid("truncated header"));
        }
        if &sidecar[..8] != MAGIC {
            return Err(invalid("unsupported index magic/version"));
        }
        let le = Endian::Little;
        let count = usize::try_from(le.u64(&sidecar[48..56]))
            .map_err(|_| invalid("entry count overflow"))?;
        if count > limits.max_records {
            return Err(Error::limit("index_entries"));
        }
        let expected_len = count
            .checked_mul(ENTRY)
            .and_then(|x| x.checked_add(HEADER + 32))
            .ok_or_else(|| invalid("size overflow"))?;
        if expected_len != sidecar.len() {
            return Err(invalid("size does not equal header + entries + digest"));
        }
        if source.len() > limits.max_input_bytes {
            return Err(Error::limit("input_bytes"));
        }
        if le.u64(&sidecar[8..16]) != source.len() as u64
            || sidecar[16..48] != sha256::digest(source)
        {
            return Err(Error::new(
                ErrorCode::SourceMismatch,
                0,
                "index_source",
                "source bytes do not match the sidecar",
            ));
        }
        let body_end = sidecar.len() - 32;
        if sidecar[body_end..] != sha256::digest(&sidecar[..body_end]) {
            return Err(invalid("index digest mismatch"));
        }
        let index = Index::build(source, limits)?;
        if index.encode()?.as_slice() != sidecar {
            return Err(invalid(
                "reconstructed source metadata disagrees with the sidecar (even if rehashed)",
            ));
        }
        Ok(Self::from_canonical(source, index))
    }
    fn from_canonical(source: &'a [u8], index: Index) -> Self {
        let mut sorted_times = Vec::new();
        let mut unknown_times = Vec::new();
        for entry in &index.entries {
            match entry.packet.timestamp.and_then(|t| t.unix_nanos().ok()) {
                Some(time) => sorted_times.push((time, entry.packet.frame)),
                None => unknown_times.push(entry.packet.frame),
            }
        }
        sorted_times.sort_unstable();
        Self {
            source,
            index,
            sorted_times,
            unknown_times,
        }
    }
    pub fn index(&self) -> &Index {
        &self.index
    }
    /// Frame numbers are 1-based packet ordinals, not block ordinals.
    pub fn packet(&self, frame: u64) -> Result<&'a [u8]> {
        let index = frame
            .checked_sub(1)
            .and_then(|n| usize::try_from(n).ok())
            .ok_or_else(|| invalid("frame must be positive"))?;
        let entry = self
            .index
            .entries
            .get(index)
            .ok_or_else(|| invalid("frame outside capture"))?;
        let start = usize::try_from(entry.record_offset)
            .ok()
            .and_then(|n| n.checked_add(entry.packet.data_offset))
            .ok_or_else(|| invalid("packet offset overflow"))?;
        let end = start
            .checked_add(entry.packet.captured_len as usize)
            .ok_or_else(|| invalid("packet end overflow"))?;
        self.source
            .get(start..end)
            .ok_or_else(|| invalid("packet range outside verified source"))
    }
    /// File order is not assumed to equal timestamp order. Missing/inexact times
    /// are returned separately instead of being interpreted as time zero.
    pub fn time_range(&self, start_ns: i128, end_ns: i128) -> Result<TimeQuery> {
        if start_ns > end_ns {
            return Err(invalid("inverted time range"));
        }
        let first = self
            .sorted_times
            .partition_point(|(time, _)| *time < start_ns);
        let end = self
            .sorted_times
            .partition_point(|(time, _)| *time <= end_ns);
        let mut frames: Vec<_> = self.sorted_times[first..end]
            .iter()
            .map(|(_, frame)| *frame)
            .collect();
        // Preserve the existing public contract: results follow capture order.
        frames.sort_unstable();
        Ok(TimeQuery {
            frames,
            unresolved_frames: self.unknown_times.clone(),
        })
    }
}
fn invalid(detail: &str) -> Error {
    Error::new(ErrorCode::InvalidIndex, 0, "index", detail)
}
