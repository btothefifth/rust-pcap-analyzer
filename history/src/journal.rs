//! Append-only content-bound journal. Hash integrity is not semantic replay.
use crate::{
    bad,
    codec::{Decoder, Encoder},
    model::{Config, SourceIdentity},
    Error, ErrorCode, Result,
};
use pcap_evidence::sha256::{self, Sha256};
use std::{
    cell::RefCell,
    fs::{self, File, OpenOptions},
    io::{BufWriter, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    rc::Rc,
};

pub const MAGIC: &[u8; 8] = b"PCHIST01";
pub const DOMAIN: &[u8] = b"pcap-evidence/history-record/v1\0";
pub const PACKET: u8 = 1;
pub const TCP: u8 = 2;
pub const NOTICE: u8 = 3;
pub const CHECKPOINT: u8 = 4;
pub const ABORT: u8 = 254;
pub const SEAL: u8 = 255;
#[derive(Debug)]
pub struct DiskBudget {
    pub used: u64,
    pub peak: u64,
    pub maximum: u64,
}
impl DiskBudget {
    pub fn charge(&mut self, n: u64) -> Result<()> {
        let next = self
            .used
            .checked_add(n)
            .ok_or_else(|| Error::limit("history_disk"))?;
        if next > self.maximum {
            return Err(Error::limit("history_disk"));
        }
        self.used = next;
        self.peak = self.peak.max(next);
        Ok(())
    }
    pub fn release(&mut self, n: u64) -> Result<()> {
        self.used = self
            .used
            .checked_sub(n)
            .ok_or_else(|| bad("history_disk", "budget accounting underflow"))?;
        Ok(())
    }
}
pub type Quota = Rc<RefCell<DiskBudget>>;
pub fn quota(maximum: u64) -> Quota {
    Rc::new(RefCell::new(DiskBudget {
        used: 0,
        peak: 0,
        maximum,
    }))
}
pub fn regular(path: &Path) -> Result<()> {
    if !fs::symlink_metadata(path)?.file_type().is_file() {
        return Err(bad("history_path", "regular non-symlink file required"));
    }
    Ok(())
}
pub fn write_new(path: &Path, bytes: &[u8], q: &Quota) -> Result<()> {
    q.borrow_mut().charge(bytes.len() as u64)?;
    let mut f = OpenOptions::new().write(true).create_new(true).open(path)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    Ok(())
}
pub fn remove_owned(path: &Path, q: &Quota) -> Result<()> {
    regular(path)?;
    let n = fs::metadata(path)?.len();
    fs::remove_file(path)?;
    q.borrow_mut().release(n)
}
pub fn hash_file(path: &Path, max: u64) -> Result<SourceIdentity> {
    regular(path)?;
    let mut f = File::open(path)?;
    hash_reader(&mut f, max)
}
pub fn hash_reader(r: &mut impl Read, max: u64) -> Result<SourceIdentity> {
    let mut hash = Sha256::new();
    let mut total = 0u64;
    let mut b = [0u8; 65536];
    loop {
        let n = r.read(&mut b)?;
        if n == 0 {
            break;
        }
        total = total
            .checked_add(n as u64)
            .ok_or_else(|| Error::limit("source_bytes"))?;
        if total > max || total > u64::MAX / 8 {
            return Err(Error::limit("source_bytes"));
        }
        hash.update(&b[..n]);
    }
    Ok(SourceIdentity {
        sha256: hash.finalize(),
        bytes: total,
    })
}
#[derive(Clone, Debug)]
pub struct Header {
    pub source: SourceIdentity,
    pub config: Config,
    pub digest: [u8; 32],
    pub bytes: u64,
}
fn header_bytes(source: &SourceIdentity, c: &Config) -> Result<(Vec<u8>, [u8; 32])> {
    let mut body = Encoder::default();
    body.hash(&source.sha256);
    body.u64(source.bytes);
    body.bytes(&c.encode()?)?;
    let mut out = Vec::from(MAGIC.as_slice());
    out.extend_from_slice(&(body.0.len() as u32).to_le_bytes());
    out.extend_from_slice(&body.0);
    let digest = sha256::digest(&out);
    out.extend_from_slice(&digest);
    Ok((out, digest))
}
pub struct Writer {
    file: BufWriter<File>,
    pub header: Header,
    pub count: u64,
    pub position: u64,
    pub previous: [u8; 32],
    pub quota: Quota,
    poisoned: bool,
    terminal: bool,
}
impl Writer {
    pub fn create(
        path: &Path,
        source: SourceIdentity,
        config: Config,
        quota: Quota,
    ) -> Result<Self> {
        config.validate()?;
        let (bytes, digest) = header_bytes(&source, &config)?;
        quota.borrow_mut().charge(bytes.len() as u64)?;
        let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        let size = bytes.len() as u64;
        Ok(Self {
            file: BufWriter::with_capacity(65536, file),
            header: Header {
                source,
                config,
                digest,
                bytes: size,
            },
            count: 0,
            position: size,
            previous: digest,
            quota,
            poisoned: false,
            terminal: false,
        })
    }
    pub fn append(&mut self, kind: u8, body: &[u8]) -> Result<(u64, [u8; 32])> {
        if self.poisoned || self.terminal {
            return Err(bad("history_writer", "writer is failed or terminal"));
        }
        let result = self.write_record(kind, body);
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }
    fn write_record(&mut self, kind: u8, body: &[u8]) -> Result<(u64, [u8; 32])> {
        if ![PACKET, TCP, NOTICE, CHECKPOINT, ABORT, SEAL].contains(&kind) {
            return Err(bad("history_kind", "unknown record type"));
        }
        let len = body
            .len()
            .checked_add(9)
            .ok_or_else(|| Error::limit("history_record"))?;
        if len > self.header.config.max_record_bytes || self.count >= self.header.config.max_records
        {
            return Err(Error::limit("history_record"));
        }
        let seq = self
            .count
            .checked_add(1)
            .ok_or_else(|| Error::limit("history_sequence"))?;
        let length = (len as u32).to_le_bytes();
        let mut payload = Encoder::default();
        payload.u8(kind);
        payload.u64(seq);
        payload.0.extend_from_slice(body);
        let mut hash = Sha256::new();
        hash.update(DOMAIN);
        hash.update(&self.previous);
        hash.update(&length);
        hash.update(&payload.0);
        let digest = hash.finalize();
        let bytes = (len as u64)
            .checked_add(36)
            .ok_or_else(|| Error::limit("history_record"))?;
        self.quota.borrow_mut().charge(bytes)?;
        let offset = self.position;
        self.file.write_all(&length)?;
        self.file.write_all(&payload.0)?;
        self.file.write_all(&digest)?;
        self.position = self
            .position
            .checked_add(bytes)
            .ok_or_else(|| Error::limit("history_position"))?;
        self.count = seq;
        self.previous = digest;
        if [CHECKPOINT, ABORT, SEAL].contains(&kind) {
            self.file.flush()?;
            self.file.get_ref().sync_all()?;
        }
        self.terminal = kind == ABORT || kind == SEAL;
        Ok((offset, digest))
    }
    pub fn sync(&mut self) -> Result<()> {
        if self.poisoned {
            return Err(bad("history_writer", "failed writer"));
        }
        let result = self
            .file
            .flush()
            .and_then(|_| self.file.get_ref().sync_all());
        if result.is_err() {
            self.poisoned = true;
        }
        result.map_err(Error::from)
    }
}
#[derive(Clone, Debug)]
pub struct Record {
    pub kind: u8,
    pub sequence: u64,
    pub body: Vec<u8>,
    pub offset: u64,
    pub digest: [u8; 32],
}
pub struct Reader {
    pub file: File,
    pub header: Header,
    pub count: u64,
    pub position: u64,
    pub previous: [u8; 32],
    pub sealed: bool,
    pub aborted: bool,
    ended: bool,
}
fn exact(f: &mut impl Read, n: usize) -> Result<Vec<u8>> {
    let mut b = vec![0; n];
    match f.read_exact(&mut b) {
        Ok(()) => Ok(b),
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Err(Error::new(
            ErrorCode::Truncated,
            0,
            "history_record",
            "partial journal field",
        )),
        Err(e) => Err(e.into()),
    }
}
impl Reader {
    pub fn open(path: &Path) -> Result<Self> {
        regular(path)?;
        let mut file = File::open(path)?;
        let prefix = exact(&mut file, 12)?;
        if &prefix[..8] != MAGIC {
            return Err(bad("history_magic", "not a history-v1 journal"));
        }
        let len = u32::from_le_bytes([prefix[8], prefix[9], prefix[10], prefix[11]]) as usize;
        if len > 4096 {
            return Err(Error::limit("history_header"));
        }
        let body = exact(&mut file, len)?;
        let digest_bytes = exact(&mut file, 32)?;
        let mut all = prefix;
        all.extend_from_slice(&body);
        let digest = sha256::digest(&all);
        if digest.as_slice() != digest_bytes {
            return Err(bad("history_header", "header digest mismatch"));
        }
        let mut d = Decoder::new(&body);
        let source = SourceIdentity {
            sha256: d.hash()?,
            bytes: d.u64()?,
        };
        let config = Config::decode(d.bytes(2048)?)?;
        d.finish()?;
        if source.bytes > config.max_source_bytes {
            return Err(Error::limit("source_bytes"));
        }
        let bytes = (12 + len + 32) as u64;
        Ok(Self {
            file,
            header: Header {
                source,
                config,
                digest,
                bytes,
            },
            count: 0,
            position: bytes,
            previous: digest,
            sealed: false,
            aborted: false,
            ended: false,
        })
    }
    pub fn next_record(&mut self) -> Result<Option<Record>> {
        let result = self.read_record();
        if result.is_err() {
            self.ended = true;
        }
        result
    }
    fn read_record(&mut self) -> Result<Option<Record>> {
        if self.ended {
            return Ok(None);
        }
        let mut first = [0u8; 1];
        if self.file.read(&mut first)? == 0 {
            self.ended = true;
            return Ok(None);
        }
        if self.sealed || self.aborted {
            return Err(bad("history_terminal", "data after terminal record"));
        }
        let rest = exact(&mut self.file, 3)?;
        let length = [first[0], rest[0], rest[1], rest[2]];
        let len = u32::from_le_bytes(length) as usize;
        if !(9..=self.header.config.max_record_bytes).contains(&len)
            || self.count >= self.header.config.max_records
        {
            return Err(Error::limit("history_record"));
        }
        let payload = exact(&mut self.file, len)?;
        let stored = exact(&mut self.file, 32)?;
        let mut hash = Sha256::new();
        hash.update(DOMAIN);
        hash.update(&self.previous);
        hash.update(&length);
        hash.update(&payload);
        let digest = hash.finalize();
        if digest.as_slice() != stored {
            return Err(bad("history_chain", "record hash mismatch"));
        }
        let mut d = Decoder::new(&payload);
        let kind = d.u8()?;
        let sequence = d.u64()?;
        if sequence != self.count + 1
            || ![PACKET, TCP, NOTICE, CHECKPOINT, ABORT, SEAL].contains(&kind)
        {
            return Err(bad("history_sequence", "noncanonical record sequence/type"));
        }
        let body = d.take(len - 9)?.to_vec();
        d.finish()?;
        let offset = self.position;
        self.position = self
            .position
            .checked_add(len as u64 + 36)
            .ok_or_else(|| Error::limit("history_position"))?;
        self.count = sequence;
        self.previous = digest;
        self.sealed = kind == SEAL;
        self.aborted = kind == ABORT;
        Ok(Some(Record {
            kind,
            sequence,
            body,
            offset,
            digest,
        }))
    }
    /// Read an indexed record with its committed digest. Caller must first verify
    /// the journal chain and index digest; a self-hash does not establish semantics.
    pub fn indexed(&mut self, offset: u64, digest: [u8; 32]) -> Result<Record> {
        if offset < self.header.bytes {
            return Err(bad("history_index", "offset inside header"));
        }
        self.file.seek(SeekFrom::Start(offset - 32))?;
        let previous = exact(&mut self.file, 32)?;
        let length = exact(&mut self.file, 4)?;
        let len = u32::from_le_bytes([length[0], length[1], length[2], length[3]]) as usize;
        if !(9..=self.header.config.max_record_bytes).contains(&len) {
            return Err(Error::limit("history_record"));
        }
        let payload = exact(&mut self.file, len)?;
        let stored = exact(&mut self.file, 32)?;
        if stored != digest {
            return Err(bad(
                "history_index",
                "record digest does not match verified index",
            ));
        }
        let mut hash = Sha256::new();
        hash.update(DOMAIN);
        hash.update(&previous);
        hash.update(&length);
        hash.update(&payload);
        if hash.finalize() != digest {
            return Err(bad("history_index", "indexed payload or predecessor drift"));
        }
        let mut d = Decoder::new(&payload);
        let kind = d.u8()?;
        let sequence = d.u64()?;
        let body = d.take(len - 9)?.to_vec();
        Ok(Record {
            kind,
            sequence,
            body,
            offset,
            digest,
        })
    }
}
pub fn sync_directory(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        File::open(path)?.sync_all()?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}
pub fn new_workspace(path: &Path) -> Result<PathBuf> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    if !fs::symlink_metadata(parent)?.file_type().is_dir() {
        return Err(bad("history_parent", "stable non-symlink parent required"));
    }
    fs::create_dir(path)?;
    Ok(path.to_path_buf())
}
