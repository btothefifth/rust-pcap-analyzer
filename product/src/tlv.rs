//! Output-only binary typed tree. Lengths BE, scalar encodings canonical, bounded.
//! Envelope: magic(8), repeated length:u32 + sequence:u64 + prev:32 + hash:32 + tree.
use pcap_evidence::{
    json::Json,
    sha256::{self, Sha256},
    Error, Result,
};
use pcap_evidence_stream::{Event, EventSink};
use std::io::Write;
pub const MAGIC: &[u8; 8] = b"PCEVTLV1";
pub const DOMAIN: &[u8] = b"pcap-evidence/tlv/v1\0";
fn put(out: &mut Vec<u8>, tag: u8, body: &[u8], max: usize) -> Result<()> {
    if out
        .len()
        .checked_add(5)
        .and_then(|n| n.checked_add(body.len()))
        .is_none_or(|n| n > max)
    {
        return Err(Error::limit("tlv_record"));
    }
    let n = u32::try_from(body.len()).map_err(|_| Error::limit("tlv_length"))?;
    out.push(tag);
    out.extend_from_slice(&n.to_be_bytes());
    out.extend_from_slice(body);
    Ok(())
}
pub fn encode(v: &Json, max: usize) -> Result<Vec<u8>> {
    fn walk(
        v: &Json,
        out: &mut Vec<u8>,
        max: usize,
        depth: usize,
        nodes: &mut usize,
    ) -> Result<()> {
        if depth > 24 || *nodes >= 100000 {
            return Err(Error::limit("tlv_tree"));
        }
        *nodes += 1;
        match v {
            Json::Null => put(out, 0, &[], max),
            Json::Bool(x) => put(out, 1, &[u8::from(*x)], max),
            Json::Number(n) => put(out, 2, &n.to_be_bytes(), max),
            Json::String(s) => put(out, 3, s.as_bytes(), max),
            Json::Array(a) => {
                let mut body = Vec::new();
                for x in a {
                    walk(x, &mut body, max, depth + 1, nodes)?;
                }
                put(out, 4, &body, max)
            }
            Json::Object(a) => {
                let mut body = Vec::new();
                let mut names = std::collections::BTreeSet::new();
                for (k, v) in a {
                    if !names.insert(*k) {
                        return Err(Error::limit("duplicate_tlv_key"));
                    }
                    if *nodes >= 100000 {
                        return Err(Error::limit("tlv_tree"));
                    }
                    *nodes += 1;
                    put(&mut body, 3, k.as_bytes(), max)?;
                    walk(v, &mut body, max, depth + 1, nodes)?;
                }
                put(out, 5, &body, max)
            }
        }
    }
    let mut out = Vec::new();
    let mut nodes = 0;
    walk(v, &mut out, max, 0, &mut nodes)?;
    Ok(out)
}
pub struct TlvSink<W: Write> {
    writer: W,
    run: String,
    seq: u64,
    prev: [u8; 32],
    max: usize,
    failed: bool,
}
impl<W: Write> TlvSink<W> {
    pub fn new(mut writer: W, run: String, max: usize) -> Result<Self> {
        if run.is_empty() || run.len() > 128 || run.chars().any(char::is_control) || max < 1024 {
            return Err(Error::limit("tlv_configuration"));
        }
        writer.write_all(MAGIC)?;
        Ok(Self {
            writer,
            run,
            seq: 0,
            prev: [0; 32],
            max,
            failed: false,
        })
    }
    pub fn finish(mut self) -> Result<W> {
        if self.failed {
            return Err(Error::limit("tlv_writer_failed"));
        }
        self.writer.flush()?;
        Ok(self.writer)
    }
}
impl<W: Write> EventSink for TlvSink<W> {
    fn run_id(&self) -> &str {
        &self.run
    }
    fn emit(&mut self, e: &Event) -> Result<u64> {
        if self.failed {
            return Err(Error::limit("tlv_writer_failed"));
        }
        let seq = self
            .seq
            .checked_add(1)
            .ok_or_else(|| Error::limit("event_sequence"))?;
        let body = encode(&e.json(&self.run, seq), self.max.saturating_sub(76))?;
        let size = u32::try_from(72 + body.len()).map_err(|_| Error::limit("tlv_record"))?;
        let mut h = Sha256::new();
        h.update(DOMAIN);
        h.update(&self.prev);
        h.update(&seq.to_be_bytes());
        h.update(&body);
        let hash = h.finalize();
        let result = (|| -> std::io::Result<()> {
            self.writer.write_all(&size.to_be_bytes())?;
            self.writer.write_all(&seq.to_be_bytes())?;
            self.writer.write_all(&self.prev)?;
            self.writer.write_all(&hash)?;
            self.writer.write_all(&body)
        })();
        if let Err(e) = result {
            self.failed = true;
            return Err(e.into());
        }
        self.prev = hash;
        self.seq = seq;
        Ok(seq)
    }
}
/// Hash helper for cross-language known-answer tests.
pub fn fingerprint(v: &Json, max: usize) -> Result<String> {
    Ok(sha256::hex(&sha256::digest(&encode(v, max)?)))
}
