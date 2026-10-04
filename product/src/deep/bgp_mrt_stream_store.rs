//! Additive PCBMRT02 raw-record storage. No whole-source allocation, packet
//! carrier, synthetic PIT, or per-chunk checkpoint is introduced. Failed writes
//! leave an unsealed, consumer-incompatible prefix. The caller owns publication.
use super::bgp_mrt::{self, MrtLimits, MrtSource};
use pcap_evidence::{
    json::Json,
    sha256::{self, Sha256},
    Error, ErrorCode, Result,
};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::Path,
};

pub const MAGIC: &[u8; 8] = b"PCBMRT02";
const FRAME_META: u64 = 85;
const TERMINAL_BYTES: u64 = 113;

#[derive(Clone, Debug)]
pub struct MrtStreamLimits {
    pub source_bytes: u64,
    pub store_bytes: u64,
    pub records: u64,
    /// Complete common header plus body, bounded independently of source size.
    pub record_bytes: usize,
    pub peers: usize,
    pub sessions: usize,
    pub work: u64,
    pub output_bytes: u64,
}
impl Default for MrtStreamLimits {
    fn default() -> Self {
        Self {
            source_bytes: 1024 * 1024 * 1024,
            store_bytes: 2 * 1024 * 1024 * 1024,
            records: 1_000_000,
            record_bytes: 1024 * 1024,
            peers: 4096,
            sessions: 128,
            work: 32 * 1024 * 1024 * 1024,
            output_bytes: 1024 * 1024 * 1024,
        }
    }
}
impl MrtStreamLimits {
    pub fn validate(&self) -> Result<()> {
        if self.source_bytes == 0
            || self.store_bytes == 0
            || self.records == 0
            || !(12..=64 * 1024 * 1024).contains(&self.record_bytes)
            || self.peers == 0
            || self.peers > 65536
            || self.sessions == 0
            || self.sessions > 65536
            || self.work == 0
            || self.output_bytes == 0
        {
            return Err(Error::limit("mrt_stream_configuration"));
        }
        Ok(())
    }
    pub(crate) fn record_limits(&self) -> MrtLimits {
        let n = self.record_bytes;
        MrtLimits {
            input_bytes: n,
            records: 1,
            peers: self.peers,
            rib_entries: n / 8 + 1,
            prefix_bytes: 16,
            path_attributes: n / 3 + 1,
            retained_bytes: n,
            work: n.saturating_mul(64).saturating_add(4096),
            output_bytes: n.saturating_mul(64).saturating_add(8192),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StreamReceipt {
    pub source: MrtSource,
    pub sha256: String,
    pub byte_length: u64,
    pub record_count: u64,
    pub final_chain: String,
    pub seal: String,
    /// Operational counters are not serialized identity or semantic input.
    /// Conservative retained representation accounting, not physical/RSS evidence.
    pub high_water_bytes: usize,
    pub work_used: u64,
    pub output_bytes: u64,
}
impl StreamReceipt {
    pub fn json(&self) -> Json {
        Json::object([
            ("schema", "pcap-evidence.bgp.mrt-stream-receipt.v2".into()),
            ("source_id", self.source.source_id.clone().into()),
            ("checkpoint_id", self.source.checkpoint_id.clone().into()),
            ("source_sha256", self.sha256.clone().into()),
            ("source_bytes", self.byte_length.into()),
            ("record_count", self.record_count.into()),
            ("final_chain", self.final_chain.clone().into()),
            ("seal", self.seal.clone().into()),
            ("high_water_bytes", (self.high_water_bytes as u64).into()),
            ("work_used", self.work_used.into()),
            ("output_bytes", self.output_bytes.into()),
            ("source_authenticated", false.into()),
            ("endpoint_state_claimed", false.into()),
        ])
    }
    pub(crate) fn same_identity(&self, other: &Self) -> bool {
        self.source == other.source
            && self.sha256 == other.sha256
            && self.byte_length == other.byte_length
            && self.record_count == other.record_count
            && self.final_chain == other.final_chain
            && self.seal == other.seal
    }
}
fn invalid(field: &'static str) -> Error {
    Error::new(
        ErrorCode::SourceMismatch,
        0,
        field,
        "invalid, truncated, or inconsistent MRT stream",
    )
}
fn exact<R: Read>(r: &mut R, b: &mut [u8]) -> Result<()> {
    r.read_exact(b).map_err(|e| {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            invalid("mrt_stream_truncated")
        } else {
            Error::io(e)
        }
    })
}
fn no_more<R: Read>(r: &mut R) -> Result<()> {
    let mut probe = [0u8; 1];
    loop {
        match r.read(&mut probe) {
            Ok(0) => return Ok(()),
            Ok(_) => return Err(invalid("mrt_stream_trailing_or_growth")),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(Error::io(e)),
        }
    }
}
fn valid_source(source: &MrtSource) -> Result<()> {
    for s in [&source.source_id, &source.checkpoint_id] {
        if s.trim().is_empty() || s.len() > 1024 || s.chars().any(char::is_control) {
            return Err(invalid("mrt_stream_identity"));
        }
    }
    Ok(())
}
fn header(source: &MrtSource, length: u64) -> Result<Vec<u8>> {
    valid_source(source)?;
    let mut h = Vec::new();
    h.try_reserve_exact(20 + source.source_id.len() + source.checkpoint_id.len())
        .map_err(|_| Error::limit("mrt_stream_header"))?;
    h.extend_from_slice(MAGIC);
    h.extend_from_slice(&length.to_be_bytes());
    for s in [&source.source_id, &source.checkpoint_id] {
        h.extend_from_slice(&(s.len() as u16).to_be_bytes());
        h.extend_from_slice(s.as_bytes());
    }
    Ok(h)
}
fn read_header<R: Read>(r: &mut R) -> Result<(MrtSource, u64, Vec<u8>)> {
    let mut prefix = [0; 16];
    exact(r, &mut prefix)?;
    if &prefix[..8] != MAGIC {
        return Err(invalid("mrt_stream_magic"));
    }
    let length = u64::from_be_bytes(
        prefix[8..]
            .try_into()
            .map_err(|_| invalid("mrt_stream_header"))?,
    );
    let mut labels = Vec::new();
    for _ in 0..2 {
        let mut n = [0; 2];
        exact(r, &mut n)?;
        let n = usize::from(u16::from_be_bytes(n));
        if n == 0 || n > 1024 {
            return Err(invalid("mrt_stream_identity"));
        }
        let mut b = vec![0; n];
        exact(r, &mut b)?;
        labels.push(String::from_utf8(b).map_err(|_| invalid("mrt_stream_identity"))?);
    }
    let source = MrtSource {
        source_id: labels.remove(0),
        checkpoint_id: labels.remove(0),
    };
    let h = header(&source, length)?;
    Ok((source, length, h))
}
fn admit(length: u64, hbytes: u64, l: &MrtStreamLimits) -> Result<()> {
    l.validate()?;
    if length == 0
        || length > l.source_bytes
        || hbytes
            .checked_add(length)
            .and_then(|n| n.checked_add(TERMINAL_BYTES + FRAME_META))
            .filter(|n| *n <= l.store_bytes)
            .is_none()
        || length.checked_mul(4).filter(|n| *n <= l.work).is_none()
    {
        return Err(Error::limit("mrt_stream_preflight"));
    }
    Ok(())
}
pub(crate) fn charge(total: &mut u64, amount: u64, cap: u64, field: &'static str) -> Result<()> {
    *total = total
        .checked_add(amount)
        .filter(|n| *n <= cap)
        .ok_or_else(|| Error::limit(field))?;
    Ok(())
}
fn chain(
    previous: &[u8; 32],
    ordinal: u64,
    offset: u64,
    raw: &[u8],
    digest: &[u8; 32],
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"pcap-evidence.mrt-stream.record.v2\0");
    h.update(previous);
    h.update(&ordinal.to_be_bytes());
    h.update(&offset.to_be_bytes());
    h.update(&(raw.len() as u32).to_be_bytes());
    h.update(digest);
    h.finalize()
}
fn terminal(
    header_digest: &[u8; 32],
    length: u64,
    count: u64,
    digest: &[u8; 32],
    last: &[u8; 32],
) -> Vec<u8> {
    let mut b = Vec::with_capacity(TERMINAL_BYTES as usize);
    b.push(0);
    b.extend_from_slice(&length.to_be_bytes());
    b.extend_from_slice(&count.to_be_bytes());
    b.extend_from_slice(digest);
    b.extend_from_slice(last);
    let mut h = Sha256::new();
    h.update(b"pcap-evidence.mrt-stream.terminal.v2\0");
    h.update(header_digest);
    h.update(&b);
    b.extend_from_slice(&h.finalize());
    b
}
fn raw_record<R: Read>(r: &mut R, remaining: u64, l: &MrtStreamLimits) -> Result<Vec<u8>> {
    if remaining < 12 {
        return Err(invalid("mrt_stream_header"));
    }
    let mut h = [0; 12];
    exact(r, &mut h)?;
    let body = u32::from_be_bytes(
        h[8..12]
            .try_into()
            .map_err(|_| invalid("mrt_stream_length"))?,
    );
    let n = u64::from(body) + 12;
    if n > remaining || n > l.record_bytes as u64 || n > u64::from(u32::MAX) {
        return Err(Error::limit("mrt_stream_record_bytes"));
    }
    let mut raw = Vec::new();
    raw.try_reserve_exact(n as usize)
        .map_err(|_| Error::limit("mrt_stream_record_bytes"))?;
    raw.extend_from_slice(&h);
    raw.resize(n as usize, 0);
    exact(r, &mut raw[12..])?;
    Ok(raw)
}

/// Write exactly the caller-admitted source length and probe for growth before
/// sealing. The source must not be concurrently appended. Output is provisional
/// until this returns; use create-new staging and publish only after success.
pub fn write_stream<R: Read, W: Write>(
    input: &mut R,
    output: &mut W,
    source_length: u64,
    source: MrtSource,
    limits: &MrtStreamLimits,
) -> Result<StreamReceipt> {
    let h = header(&source, source_length)?;
    admit(source_length, h.len() as u64, limits)?;
    let head = sha256::digest(&h);
    let mut previous = head;
    let mut hash = Sha256::new();
    let mut offset = 0;
    let mut count = 0;
    let mut stored = h.len() as u64;
    let mut work = 0;
    charge(
        &mut work,
        (h.len() as u64) * 2 + TERMINAL_BYTES * 2,
        limits.work,
        "mrt_stream_work",
    )?;
    let mut high = h.len();
    let mut table = None;
    output.write_all(&h).map_err(Error::io)?;
    let record_limits = limits.record_limits();
    while offset < source_length {
        if count >= limits.records {
            return Err(Error::limit("mrt_stream_records"));
        }
        let raw = raw_record(input, source_length - offset, limits)?;
        charge(
            &mut stored,
            FRAME_META + raw.len() as u64,
            limits.store_bytes,
            "mrt_stream_store_bytes",
        )?;
        if stored
            .checked_add(TERMINAL_BYTES)
            .filter(|n| *n <= limits.store_bytes)
            .is_none()
        {
            return Err(Error::limit("mrt_stream_store_bytes"));
        }
        let (record, decode_work) =
            bgp_mrt::decode_incremental(&raw, offset, &mut table, &source, &record_limits)?;
        charge(
            &mut work,
            decode_work as u64 + raw.len() as u64 + FRAME_META,
            limits.work,
            "mrt_stream_work",
        )?;
        let digest = sha256::digest(&raw);
        let next = chain(&previous, count, offset, &raw, &digest);
        output.write_all(&[1]).map_err(Error::io)?;
        output.write_all(&count.to_be_bytes()).map_err(Error::io)?;
        output.write_all(&offset.to_be_bytes()).map_err(Error::io)?;
        output
            .write_all(&(raw.len() as u32).to_be_bytes())
            .map_err(Error::io)?;
        output.write_all(&digest).map_err(Error::io)?;
        output.write_all(&next).map_err(Error::io)?;
        output.write_all(&raw).map_err(Error::io)?;
        hash.update(&raw);
        previous = next;
        offset += raw.len() as u64;
        count += 1;
        high = high.max(
            raw.capacity()
                .saturating_add(record_memory(&record))
                .saturating_add(h.len()),
        );
    }
    no_more(input)?;
    let digest = hash.finalize();
    let tail = terminal(&head, offset, count, &digest, &previous);
    output.write_all(&tail).map_err(Error::io)?;
    output.flush().map_err(Error::io)?;
    Ok(StreamReceipt {
        source,
        sha256: sha256::hex(&digest),
        byte_length: offset,
        record_count: count,
        final_chain: sha256::hex(&previous),
        seal: sha256::hex(&tail[81..]),
        high_water_bytes: high,
        work_used: work,
        output_bytes: 0,
    })
}

pub(crate) fn scan<R: Read, F: FnMut(u64, u64, &[u8], bgp_mrt::MrtRecord) -> Result<()>>(
    r: &mut R,
    l: &MrtStreamLimits,
    mut visitor: F,
) -> Result<StreamReceipt> {
    let (source, length, h) = read_header(r)?;
    admit(length, h.len() as u64, l)?;
    let head = sha256::digest(&h);
    let mut previous = head;
    let mut hash = Sha256::new();
    let mut offset = 0;
    let mut count = 0;
    let mut stored = h.len() as u64;
    let mut work = 0;
    charge(
        &mut work,
        (h.len() as u64) * 2 + TERMINAL_BYTES * 2,
        l.work,
        "mrt_stream_work",
    )?;
    let mut high = h.len();
    let mut table = None;
    let record_limits = l.record_limits();
    loop {
        let mut tag = [0; 1];
        exact(r, &mut tag)?;
        if tag[0] == 0 {
            let mut rest = [0; 112];
            exact(r, &mut rest)?;
            charge(
                &mut stored,
                TERMINAL_BYTES,
                l.store_bytes,
                "mrt_stream_store_bytes",
            )?;
            let digest = hash.finalize();
            let expected = terminal(&head, offset, count, &digest, &previous);
            if offset != length || count == 0 || rest != expected[1..] {
                return Err(invalid("mrt_stream_terminal"));
            }
            no_more(r)?;
            return Ok(StreamReceipt {
                source,
                sha256: sha256::hex(&digest),
                byte_length: offset,
                record_count: count,
                final_chain: sha256::hex(&previous),
                seal: sha256::hex(&rest[80..]),
                high_water_bytes: high,
                work_used: work,
                output_bytes: 0,
            });
        }
        if tag[0] != 1 || count >= l.records || offset >= length {
            return Err(invalid("mrt_stream_frame_order"));
        }
        let mut meta = [0; 84];
        exact(r, &mut meta)?;
        let ordinal = u64::from_be_bytes(
            meta[..8]
                .try_into()
                .map_err(|_| invalid("mrt_stream_frame"))?,
        );
        let start = u64::from_be_bytes(
            meta[8..16]
                .try_into()
                .map_err(|_| invalid("mrt_stream_frame"))?,
        );
        let n = u32::from_be_bytes(
            meta[16..20]
                .try_into()
                .map_err(|_| invalid("mrt_stream_frame"))?,
        ) as usize;
        if ordinal != count
            || start != offset
            || n < 12
            || n > l.record_bytes
            || n as u64 > length - offset
        {
            return Err(invalid("mrt_stream_frame_extent"));
        }
        charge(
            &mut stored,
            FRAME_META + n as u64,
            l.store_bytes,
            "mrt_stream_store_bytes",
        )?;
        let mut raw = Vec::new();
        raw.try_reserve_exact(n)
            .map_err(|_| Error::limit("mrt_stream_record_bytes"))?;
        raw.resize(n, 0);
        exact(r, &mut raw)?;
        let digest = sha256::digest(&raw);
        let next = chain(&previous, count, offset, &raw, &digest);
        if meta[20..52] != digest || meta[52..84] != next {
            return Err(invalid("mrt_stream_frame_digest"));
        }
        let (record, decode_work) =
            bgp_mrt::decode_incremental(&raw, offset, &mut table, &source, &record_limits)?;
        charge(
            &mut work,
            decode_work as u64 + n as u64 + FRAME_META,
            l.work,
            "mrt_stream_work",
        )?;
        high = high.max(
            raw.capacity()
                .saturating_add(record_memory(&record))
                .saturating_add(h.len()),
        );
        visitor(count, offset, &raw, record)?;
        hash.update(&raw);
        previous = next;
        offset += n as u64;
        count += 1;
        high = high.max(raw.capacity().saturating_add(h.len()));
    }
}
/// Validate from byte zero to the sealed terminal, including every original
/// header/body and digest. Leaves the reader at EOF; no evidence callbacks run.
pub fn verify_stream<R: Read + Seek>(r: &mut R, l: &MrtStreamLimits) -> Result<StreamReceipt> {
    r.seek(SeekFrom::Start(0)).map_err(Error::io)?;
    scan(r, l, |_, _, _, _| Ok(()))
}
pub fn verify_stream_path(path: &Path, l: &MrtStreamLimits) -> Result<StreamReceipt> {
    verify_stream(&mut File::open(path).map_err(Error::io)?, l)
}
pub fn write_stream_path(
    input: &Path,
    output: &Path,
    source: MrtSource,
    l: &MrtStreamLimits,
) -> Result<StreamReceipt> {
    let mut file = File::open(input).map_err(Error::io)?;
    let metadata = file.metadata().map_err(Error::io)?;
    if !metadata.is_file() {
        return Err(invalid("mrt_stream_source_file"));
    }
    // Preflight before creating the output. Retain partial files on failure;
    // pathname rollback would introduce a same-name replacement race.
    let h = header(&source, metadata.len())?;
    admit(metadata.len(), h.len() as u64, l)?;
    let mut destination = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output)
        .map_err(Error::io)?;
    let receipt = write_stream(&mut file, &mut destination, metadata.len(), source, l)?;
    destination.sync_all().map_err(Error::io)?;
    Ok(receipt)
}

/// Conservative retained representation accounting, separate from source bytes.
pub(crate) fn record_memory(record: &bgp_mrt::MrtRecord) -> usize {
    use bgp_mrt::{Bgp4mpPayload, MrtBody};
    let base = std::mem::size_of::<bgp_mrt::MrtRecord>() + record.sha256.capacity();
    base.saturating_add(match &record.body {
        MrtBody::PeerIndex(p) => {
            p.view_name.capacity() + p.peers.capacity() * std::mem::size_of::<bgp_mrt::Peer>()
        }
        MrtBody::Rib(r) => {
            r.prefix.address.capacity()
                + r.peer_table_sha256.capacity()
                + r.entries.capacity() * std::mem::size_of::<bgp_mrt::RibEntry>()
                + r.entries
                    .iter()
                    .map(|e| e.attributes.capacity())
                    .sum::<usize>()
        }
        MrtBody::Bgp4mp(b) => match &b.payload {
            Bgp4mpPayload::Message(m) => m.capacity(),
            _ => 0,
        },
        MrtBody::Opaque { bytes, .. } => bytes.capacity(),
    })
}

/// Retained JSON representation, including vector capacity and owned strings.
/// This logical accounting is not a process RSS or allocator guarantee.
pub(crate) fn json_memory(value: &Json) -> usize {
    fn heap(value: &Json) -> usize {
        match value {
            Json::String(s) => s.capacity(),
            Json::Array(v) => v
                .capacity()
                .saturating_mul(std::mem::size_of::<Json>())
                .saturating_add(v.iter().map(heap).sum::<usize>()),
            Json::Object(v) => v
                .capacity()
                .saturating_mul(std::mem::size_of::<(&str, Json)>())
                .saturating_add(v.iter().map(|(_, j)| heap(j)).sum::<usize>()),
            _ => 0,
        }
    }
    std::mem::size_of::<Json>().saturating_add(heap(value))
}
