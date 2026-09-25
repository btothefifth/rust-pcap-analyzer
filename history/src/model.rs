use crate::{
    bad,
    codec::{Decoder, Encoder},
    Error, Result,
};
use pcap_evidence::{sha256, wire::Endpoint};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const ENGINE: &str = "pcap-evidence-history/1;state-policy/1";
pub const MODULUS: i64 = 1i64 << 32;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EpochPolicy {
    StrictAlternatives,
    NearestFrontier,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Config {
    pub max_source_bytes: u64,
    pub max_disk_bytes: u64,
    pub max_records: u64,
    pub max_record_bytes: usize,
    pub hot_tuples: usize,
    pub max_generations: usize,
    pub max_witnesses: usize,
    pub max_epoch_candidates: usize,
    pub sequence_horizon: i64,
    pub epoch_policy: EpochPolicy,
    pub sort_entries: usize,
    pub merge_fan_in: usize,
    pub max_query_bytes: usize,
    pub max_query_intervals: usize,
    pub max_query_work: u64,
    pub checkpoint_records: u64,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            max_source_bytes: 1024u64 * 1024 * 1024 * 1024,
            max_disk_bytes: 1024u64 * 1024 * 1024 * 1024,
            max_records: 20_000_000_000,
            max_record_bytes: 2 * 1024 * 1024,
            hot_tuples: 64,
            max_generations: 128,
            max_witnesses: 2048,
            max_epoch_candidates: 16,
            sequence_horizon: 16 * 1024 * 1024,
            epoch_policy: EpochPolicy::StrictAlternatives,
            sort_entries: 32768,
            merge_fan_in: 16,
            max_query_bytes: 65536,
            max_query_intervals: 4096,
            max_query_work: 128 * 1024 * 1024,
            checkpoint_records: 10000,
        }
    }
}
impl Config {
    pub fn validate(&self) -> Result<()> {
        if usize::BITS < 64
            || self.max_source_bytes == 0
            || self.max_source_bytes > u64::MAX / 8
            || self.max_disk_bytes < 1024
            || self.max_records == 0
            || self.max_records > u64::MAX / 2
            || !(4096..=16 * 1024 * 1024).contains(&self.max_record_bytes)
            || !(1..=4096).contains(&self.hot_tuples)
            || !(1..=4096).contains(&self.max_generations)
            || !(1..=4096).contains(&self.max_witnesses)
            || !(1..=64).contains(&self.max_epoch_candidates)
            || !(1..(1i64 << 31)).contains(&self.sequence_horizon)
            || !(2..=1_000_000).contains(&self.sort_entries)
            || !(2..=64).contains(&self.merge_fan_in)
            || !(1..=1024 * 1024).contains(&self.max_query_bytes)
            || !(1..=65536).contains(&self.max_query_intervals)
            || self.max_query_work == 0
            || self.checkpoint_records == 0
        {
            return Err(bad("history_config", "invalid or excessive resource limit"));
        }
        Ok(())
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut e = Encoder::default();
        e.text(ENGINE)?;
        for n in [
            self.max_source_bytes,
            self.max_disk_bytes,
            self.max_records,
            self.max_record_bytes as u64,
            self.hot_tuples as u64,
            self.max_generations as u64,
            self.max_witnesses as u64,
            self.max_epoch_candidates as u64,
            self.sequence_horizon as u64,
            self.sort_entries as u64,
            self.merge_fan_in as u64,
            self.max_query_bytes as u64,
            self.max_query_intervals as u64,
            self.max_query_work,
            self.checkpoint_records,
        ] {
            e.u64(n);
        }
        e.u8(match self.epoch_policy {
            EpochPolicy::StrictAlternatives => 0,
            EpochPolicy::NearestFrontier => 1,
        });
        Ok(e.0)
    }
    pub fn decode(b: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(b);
        if d.text(128)? != ENGINE {
            return Err(bad("history_engine", "unsupported engine/policy identity"));
        }
        let v: Vec<u64> = (0..15).map(|_| d.u64()).collect::<Result<_>>()?;
        let to_usize = |i: usize| usize::try_from(v[i]).map_err(|_| Error::limit("history_config"));
        let c = Self {
            max_source_bytes: v[0],
            max_disk_bytes: v[1],
            max_records: v[2],
            max_record_bytes: to_usize(3)?,
            hot_tuples: to_usize(4)?,
            max_generations: to_usize(5)?,
            max_witnesses: to_usize(6)?,
            max_epoch_candidates: to_usize(7)?,
            sequence_horizon: i64::try_from(v[8]).map_err(|_| Error::limit("sequence_horizon"))?,
            sort_entries: to_usize(9)?,
            merge_fan_in: to_usize(10)?,
            max_query_bytes: to_usize(11)?,
            max_query_intervals: to_usize(12)?,
            max_query_work: v[13],
            checkpoint_records: v[14],
            epoch_policy: match d.u8()? {
                0 => EpochPolicy::StrictAlternatives,
                1 => EpochPolicy::NearestFrontier,
                _ => return Err(bad("history_policy", "unknown epoch policy")),
            },
        };
        d.finish()?;
        c.validate()?;
        Ok(c)
    }
    pub fn digest(&self) -> Result<[u8; 32]> {
        Ok(sha256::digest(&self.encode()?))
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceIdentity {
    pub sha256: [u8; 32],
    pub bytes: u64,
}
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Key {
    pub section: u32,
    pub interface: u32,
    pub vlans: Vec<u16>,
    pub tunnels: Vec<String>,
    pub a: Endpoint,
    pub b: Endpoint,
}
fn endpoint(e: &mut Encoder, p: Endpoint) {
    match p.address {
        IpAddr::V4(a) => {
            e.u8(4);
            e.0.extend_from_slice(&a.octets());
        }
        IpAddr::V6(a) => {
            e.u8(6);
            e.0.extend_from_slice(&a.octets());
        }
    }
    e.u16(p.port);
}
fn read_endpoint(d: &mut Decoder<'_>) -> Result<Endpoint> {
    let address = match d.u8()? {
        4 => {
            let b = d.take(4)?;
            IpAddr::V4(Ipv4Addr::new(b[0], b[1], b[2], b[3]))
        }
        6 => {
            let mut b = [0; 16];
            b.copy_from_slice(d.take(16)?);
            IpAddr::V6(Ipv6Addr::from(b))
        }
        _ => return Err(bad("history_address", "unknown family")),
    };
    Ok(Endpoint {
        address,
        port: d.u16()?,
    })
}
impl Key {
    pub fn encode(&self) -> Result<Vec<u8>> {
        if self.a > self.b
            || self.vlans.len() > 8
            || self.vlans.iter().any(|v| *v > 4095)
            || self.tunnels.len() > 16
            || self
                .tunnels
                .iter()
                .any(|s| s.len() > 512 || s.chars().any(char::is_control))
        {
            return Err(bad(
                "history_tuple",
                "noncanonical or excessive tuple scope",
            ));
        }
        let mut e = Encoder::default();
        e.u32(self.section);
        e.u32(self.interface);
        e.u8(self.vlans.len() as u8);
        for n in &self.vlans {
            e.u16(*n);
        }
        e.u8(self.tunnels.len() as u8);
        for s in &self.tunnels {
            e.text(s)?;
        }
        endpoint(&mut e, self.a);
        endpoint(&mut e, self.b);
        Ok(e.0)
    }
    pub fn decode(b: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(b);
        let section = d.u32()?;
        let interface = d.u32()?;
        let n = d.u8()? as usize;
        if n > 8 {
            return Err(Error::limit("vlans"));
        }
        let vlans = (0..n).map(|_| d.u16()).collect::<Result<_>>()?;
        let n = d.u8()? as usize;
        if n > 16 {
            return Err(Error::limit("tunnels"));
        }
        let tunnels = (0..n).map(|_| d.text(512)).collect::<Result<_>>()?;
        let a = read_endpoint(&mut d)?;
        let b = read_endpoint(&mut d)?;
        d.finish()?;
        let k = Self {
            section,
            interface,
            vlans,
            tunnels,
            a,
            b,
        };
        k.encode()?;
        Ok(k)
    }
    pub fn digest(&self) -> Result<[u8; 32]> {
        Ok(sha256::digest(&self.encode()?))
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Witness {
    pub start: u32,
    pub end: u32,
    pub frame: u64,
    pub record_offset: u64,
    pub packet_start: u32,
    pub source_offset: u64,
}
impl Witness {
    pub fn encode(&self, e: &mut Encoder) {
        e.u32(self.start);
        e.u32(self.end);
        e.u64(self.frame);
        e.u64(self.record_offset);
        e.u32(self.packet_start);
        e.u64(self.source_offset);
    }
    pub fn decode(d: &mut Decoder<'_>) -> Result<Self> {
        Ok(Self {
            start: d.u32()?,
            end: d.u32()?,
            frame: d.u64()?,
            record_offset: d.u64()?,
            packet_start: d.u32()?,
            source_offset: d.u64()?,
        })
    }
}
/// Header fields are derived from raw bytes, never trusted from a journal index.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TcpInput {
    pub key: Key,
    pub direction: u8,
    pub frame: u64,
    pub when: Option<i128>,
    pub raw: Vec<u8>,
    pub witnesses: Vec<Witness>,
    pub sequence: u32,
    pub acknowledgement: u32,
    pub flags: u16,
    pub window: u16,
    pub timestamp_value: Option<u32>,
    pub header_bytes: usize,
}
impl TcpInput {
    pub fn new(
        key: Key,
        direction: u8,
        frame: u64,
        when: Option<i128>,
        raw: Vec<u8>,
        witnesses: Vec<Witness>,
        c: &Config,
    ) -> Result<Self> {
        c.validate()?;
        key.encode()?;
        if direction > 1
            || frame == 0
            || raw.len() < 20
            || raw.len() > 65535
            || witnesses.len() > c.max_witnesses
        {
            return Err(bad("tcp_input", "invalid input bounds"));
        }
        let header_bytes = usize::from(raw[12] >> 4) * 4;
        if !(20..=60).contains(&header_bytes) || header_bytes > raw.len() {
            return Err(bad("tcp_header", "invalid header length"));
        }
        let u16at = |n: usize| u16::from_be_bytes([raw[n], raw[n + 1]]);
        let u32at = |n: usize| u32::from_be_bytes([raw[n], raw[n + 1], raw[n + 2], raw[n + 3]]);
        let (src, dst) = if direction == 0 {
            (key.a, key.b)
        } else {
            (key.b, key.a)
        };
        if u16at(0) != src.port || u16at(2) != dst.port {
            return Err(bad("tcp_ports", "tuple disagrees with transport header"));
        }
        let mut cursor = 0u32;
        for w in &witnesses {
            if w.start != cursor
                || w.end <= w.start
                || w.end as usize > raw.len()
                || w.frame == 0
                || w.source_offset
                    .checked_add(u64::from(w.end - w.start))
                    .is_none()
                || w.packet_start.checked_add(w.end - w.start).is_none()
            {
                return Err(bad("tcp_witness", "invalid source-span layout"));
            }
            cursor = w.end;
        }
        if cursor as usize != raw.len() {
            return Err(bad("tcp_witness", "raw bytes lack complete witnesses"));
        }
        let mut at = 20;
        let mut timestamp_value = None;
        while at < header_bytes {
            let kind = raw[at];
            if kind == 0 {
                break;
            }
            if kind == 1 {
                at += 1;
                continue;
            }
            let n = usize::from(
                *raw.get(at + 1)
                    .ok_or_else(|| bad("tcp_option", "missing length"))?,
            );
            if n < 2 || at + n > header_bytes {
                return Err(bad("tcp_option", "invalid option extent"));
            }
            if kind == 8 {
                if n != 10 || timestamp_value.is_some() {
                    return Err(bad("tcp_timestamp", "invalid/duplicate timestamp option"));
                }
                timestamp_value = Some(u32at(at + 2));
            }
            at += n;
        }
        let sequence = u32at(4);
        let acknowledgement = u32at(8);
        let flags = u16::from(raw[13]) | (u16::from(raw[12] & 1) << 8);
        let window = u16at(14);
        Ok(Self {
            key,
            direction,
            frame,
            when,
            raw,
            witnesses,
            sequence,
            acknowledgement,
            flags,
            window,
            timestamp_value,
            header_bytes,
        })
    }
    pub fn syn(&self) -> bool {
        self.flags & 2 != 0
    }
    pub fn fin(&self) -> bool {
        self.flags & 1 != 0
    }
    pub fn rst(&self) -> bool {
        self.flags & 4 != 0
    }
    pub fn ack(&self) -> bool {
        self.flags & 16 != 0
    }
    pub fn data_sequence(&self) -> u32 {
        self.sequence.wrapping_add(u32::from(self.syn()))
    }
    pub fn payload(&self) -> &[u8] {
        self.raw.get(self.header_bytes..).unwrap_or(&[])
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut e = Encoder::default();
        e.bytes(&self.key.encode()?)?;
        e.u8(self.direction);
        e.u64(self.frame);
        e.option_i128(self.when);
        e.bytes(&self.raw)?;
        e.u32(u32::try_from(self.witnesses.len()).map_err(|_| Error::limit("witnesses"))?);
        for w in &self.witnesses {
            w.encode(&mut e);
        }
        Ok(e.0)
    }
    pub fn decode(b: &[u8], c: &Config) -> Result<Self> {
        let mut d = Decoder::new(b);
        let key = Key::decode(d.bytes(10000)?)?;
        let direction = d.u8()?;
        let frame = d.u64()?;
        let when = d.option_i128()?;
        let raw = d.bytes(65535)?.to_vec();
        let n = d.u32()? as usize;
        if n > c.max_witnesses {
            return Err(Error::limit("witnesses"));
        }
        let witnesses = (0..n)
            .map(|_| Witness::decode(&mut d))
            .collect::<Result<_>>()?;
        d.finish()?;
        Self::new(key, direction, frame, when, raw, witnesses, c)
    }
}
