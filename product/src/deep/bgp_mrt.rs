//! Bounded MRT container evidence (RFC 6396). Parsing is atomic and makes no
//! claim about collector authenticity, endpoint state, or message negotiation.
//! RIB attributes are kept in their MRT encoding, including abbreviated
//! MP_REACH_NLRI, and must not be passed to an UPDATE decoder as wire bytes.
#[path = "bgp_mrt_ranges.rs"]
mod ranges;

use super::bgp::{AsPathSegment, ImportedRouteObservation, PathAttributes, Prefix, RouteAction};
use super::bgp_import::{
    self, ClockPolicy, ImportContext, ObservationClock, SourceBatch, SourceRange,
};
use super::model::bad;
use pcap_evidence::{json::Json, sha256, Error, Result};
use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const SCHEMA: &str = "pcap-evidence.bgp.mrt-adapter.v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AsnWidthSource {
    PeerIndexType,
    Bgp4mpSubtype,
    TableDumpV2Rib,
}

/// Independent caps for the container and its amplification surfaces.
#[derive(Clone, Debug)]
pub struct MrtLimits {
    pub input_bytes: usize,
    pub records: usize,
    pub peers: usize,
    pub rib_entries: usize,
    pub prefix_bytes: usize,
    pub path_attributes: usize,
    pub retained_bytes: usize,
    pub work: usize,
    pub output_bytes: usize,
}
impl Default for MrtLimits {
    fn default() -> Self {
        Self {
            input_bytes: 1024 * 1024,
            records: 1024,
            peers: 4096,
            rib_entries: 4096,
            prefix_bytes: 16,
            path_attributes: 4096,
            retained_bytes: 1024 * 1024,
            work: 8 * 1024 * 1024,
            output_bytes: 8 * 1024 * 1024,
        }
    }
}
impl MrtLimits {
    pub(crate) fn validate(&self) -> Result<()> {
        if [
            self.input_bytes,
            self.records,
            self.peers,
            self.rib_entries,
            self.prefix_bytes,
            self.path_attributes,
            self.retained_bytes,
            self.work,
            self.output_bytes,
        ]
        .contains(&0)
            || self.input_bytes > 64 * 1024 * 1024
            || self.prefix_bytes > 16
        {
            return Err(Error::limit("mrt_configuration"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MrtSource {
    pub source_id: String,
    pub checkpoint_id: String,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MrtTime {
    pub seconds: u32,
    /// Present only for BGP4MP_ET; the exact wire value is preserved.
    pub microseconds: Option<u32>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MrtRecord {
    pub offset: u64,
    pub length: u32,
    pub record_type: u16,
    pub subtype: u16,
    pub time: MrtTime,
    pub sha256: String,
    pub body: MrtBody,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MrtBody {
    PeerIndex(PeerIndex),
    Rib(Rib),
    Bgp4mp(Bgp4mp),
    /// Includes unknown types, subtypes, and families whose grammar is unknown.
    Opaque {
        reason: &'static str,
        bytes: Vec<u8>,
    },
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerIndex {
    pub collector_bgp_id: [u8; 4],
    pub view_name: Vec<u8>,
    pub peers: Vec<Peer>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Peer {
    pub peer_type: u8,
    pub bgp_id: [u8; 4],
    pub address: IpAddr,
    pub asn: u32,
    /// Width of the peer-index ASN field, not an inferred session capability.
    pub asn_width: u8,
    pub asn_width_source: AsnWidthSource,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Rib {
    pub sequence: u32,
    pub afi: u16,
    pub safi: u8,
    pub prefix: Prefix,
    pub peer_table_offset: u64,
    pub peer_table_sha256: String,
    pub entries: Vec<RibEntry>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RibEntry {
    pub peer_index: u16,
    pub originated_seconds: u32,
    /// Exact MRT attribute bytes. AS_PATH uses four-byte elements here.
    pub attributes: Vec<u8>,
    pub as_path_asn_width: u8,
    pub as_path_asn_width_source: AsnWidthSource,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Bgp4mp {
    pub peer_asn: u32,
    pub local_asn: u32,
    pub asn_width: u8,
    pub asn_width_source: AsnWidthSource,
    pub interface_index: u16,
    pub address_afi: u16,
    pub peer_address: IpAddr,
    pub local_address: IpAddr,
    pub locally_generated: bool,
    pub add_path: bool,
    pub payload: Bgp4mpPayload,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Bgp4mpPayload {
    State {
        old: u16,
        new: u16,
    },
    /// Exactly one framed BGP message, preserved in source order.
    Message(Vec<u8>),
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MrtBatch {
    pub schema: &'static str,
    pub source: MrtSource,
    pub sha256: String,
    pub byte_length: u64,
    pub source_authenticated: bool,
    pub records: Vec<MrtRecord>,
    /// Accounted retained source bytes and estimated serialized upper bound.
    pub retained_bytes: usize,
    pub work_charge: usize,
    pub output_charge: usize,
}

struct Cursor<'a> {
    bytes: &'a [u8],
    at: usize,
    base: usize,
}
impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8], base: usize) -> Self {
        Self { bytes, at: 0, base }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .at
            .checked_add(n)
            .ok_or_else(|| Error::limit("mrt_offset"))?;
        if end > self.bytes.len() {
            return Err(bad(
                "mrt_truncated",
                self.base + self.at,
                "field exceeds record",
            ));
        }
        let part = &self.bytes[self.at..end];
        self.at = end;
        Ok(part)
    }
    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }
    fn u32(&mut self) -> Result<u32> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }
    fn rest(&mut self) -> &'a [u8] {
        let b = &self.bytes[self.at..];
        self.at = self.bytes.len();
        b
    }
    fn finish(&self) -> Result<()> {
        if self.at != self.bytes.len() {
            return Err(bad(
                "mrt_length",
                self.base + self.at,
                "trailing bytes in typed record",
            ));
        }
        Ok(())
    }
}
struct Meter<'a> {
    limits: &'a MrtLimits,
    peers: usize,
    entries: usize,
    attrs: usize,
    retained: usize,
    work: usize,
    output: usize,
}
impl<'a> Meter<'a> {
    fn new(
        limits: &'a MrtLimits,
        input: usize,
        records: usize,
        source: &MrtSource,
    ) -> Result<Self> {
        let output = records
            .checked_mul(256)
            .and_then(|n| n.checked_add(source.source_id.len()))
            .and_then(|n| n.checked_add(source.checkpoint_id.len()))
            .and_then(|n| n.checked_add(256))
            .ok_or_else(|| Error::limit("mrt_output"))?;
        // One bounded pass for header preflight, one for record hashes, one
        // for the batch hash; semantic traversal is charged separately.
        let work = input
            .checked_mul(3)
            .and_then(|n| n.checked_add(records.checked_mul(32)?))
            .ok_or_else(|| Error::limit("mrt_work"))?;
        if output > limits.output_bytes || work > limits.work {
            return Err(Error::limit("mrt_preflight"));
        }
        Ok(Self {
            limits,
            peers: 0,
            entries: 0,
            attrs: 0,
            retained: 0,
            work,
            output,
        })
    }
    fn add(
        &mut self,
        peers: usize,
        entries: usize,
        attrs: usize,
        retained: usize,
        work: usize,
        output: usize,
    ) -> Result<()> {
        fn bounded(old: usize, add: usize, cap: usize) -> Option<usize> {
            old.checked_add(add).filter(|n| *n <= cap)
        }
        let p = bounded(self.peers, peers, self.limits.peers);
        let e = bounded(self.entries, entries, self.limits.rib_entries);
        let a = bounded(self.attrs, attrs, self.limits.path_attributes);
        let r = bounded(self.retained, retained, self.limits.retained_bytes);
        let w = bounded(self.work, work, self.limits.work);
        let o = bounded(self.output, output, self.limits.output_bytes);
        let (Some(p), Some(e), Some(a), Some(r), Some(w), Some(o)) = (p, e, a, r, w, o) else {
            return Err(Error::limit("mrt_budget"));
        };
        (
            self.peers,
            self.entries,
            self.attrs,
            self.retained,
            self.work,
            self.output,
        ) = (p, e, a, r, w, o);
        Ok(())
    }
}
fn address(c: &mut Cursor<'_>, ipv6: bool) -> Result<IpAddr> {
    if ipv6 {
        let mut b = [0; 16];
        b.copy_from_slice(c.take(16)?);
        Ok(IpAddr::V6(Ipv6Addr::from(b)))
    } else {
        let mut b = [0; 4];
        b.copy_from_slice(c.take(4)?);
        Ok(IpAddr::V4(Ipv4Addr::from(b)))
    }
}
fn prefix(c: &mut Cursor<'_>, afi: u16, l: &MrtLimits) -> Result<Prefix> {
    let bits = c.u8()?;
    let width = match afi {
        1 => 4,
        2 => 16,
        _ => return Err(bad("mrt_afi", c.base + c.at - 1, "unsupported prefix AFI")),
    };
    let n = usize::from(bits).div_ceil(8);
    if usize::from(bits) > width * 8 || n > l.prefix_bytes {
        return Err(bad(
            "mrt_prefix",
            c.base + c.at - 1,
            "prefix exceeds family or configured width",
        ));
    }
    let mut padded = vec![0; width];
    padded[..n].copy_from_slice(c.take(n)?);
    // RFC 6396 says padding bits are irrelevant; preserve their source via
    // record digest while exposing a canonical semantic prefix.
    if bits % 8 != 0 && n != 0 {
        padded[n - 1] &= 0xff << (8 - bits % 8);
    }
    Ok(Prefix {
        afi,
        safi: 1,
        length: bits,
        address: padded,
    })
}
fn attr_count(raw: &[u8], base: usize, meter: &mut Meter<'_>) -> Result<()> {
    let mut c = Cursor::new(raw, base);
    while c.at < raw.len() {
        let flags = c.u8()?;
        c.u8()?;
        let len = if flags & 0x10 != 0 {
            usize::from(c.u16()?)
        } else {
            usize::from(c.u8()?)
        };
        c.take(len)?;
        meter.add(0, 0, 1, 0, 4, 16)?;
    }
    Ok(())
}
fn copy_bounded_bytes(raw: &[u8], limit: &'static str) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(raw.len())
        .map_err(|_| Error::limit(limit))?;
    bytes.extend_from_slice(raw);
    Ok(bytes)
}
fn parse_peers(body: &[u8], base: usize, m: &mut Meter<'_>) -> Result<PeerIndex> {
    let mut c = Cursor::new(body, base);
    let mut bgp_id = [0; 4];
    bgp_id.copy_from_slice(c.take(4)?);
    let view_len = usize::from(c.u16()?);
    m.add(0, 0, 0, view_len, view_len, view_len * 2)?;
    let view_name = copy_bounded_bytes(c.take(view_len)?, "mrt_view_name")?;
    if std::str::from_utf8(&view_name).is_err() {
        return Err(bad(
            "mrt_view_name",
            base + 6,
            "peer-index view name is not UTF-8",
        ));
    }
    let count = usize::from(c.u16()?);
    m.add(count, 0, 0, 0, count * 32, count * 128)?;
    if body.len() - c.at < count * 11 {
        return Err(bad(
            "mrt_peer_table",
            base + c.at,
            "peer count exceeds record",
        ));
    }
    let mut peers = Vec::new();
    peers
        .try_reserve_exact(count)
        .map_err(|_| Error::limit("mrt_peer_table"))?;
    for _ in 0..count {
        let peer_type = c.u8()?;
        let mut id = [0; 4];
        id.copy_from_slice(c.take(4)?);
        let addr = address(&mut c, peer_type & 1 != 0)?;
        let asn_width = if peer_type & 2 != 0 { 4 } else { 2 };
        let asn = if asn_width == 4 {
            c.u32()?
        } else {
            u32::from(c.u16()?)
        };
        peers.push(Peer {
            peer_type,
            bgp_id: id,
            address: addr,
            asn,
            asn_width,
            asn_width_source: AsnWidthSource::PeerIndexType,
        });
    }
    c.finish()?;
    Ok(PeerIndex {
        collector_bgp_id: bgp_id,
        view_name,
        peers,
    })
}
fn parse_rib(
    body: &[u8],
    base: usize,
    subtype: u16,
    table: Option<&(u64, String, usize)>,
    m: &mut Meter<'_>,
) -> Result<Option<Rib>> {
    let mut c = Cursor::new(body, base);
    let sequence = c.u32()?;
    let (afi, safi) = match subtype {
        2 => (1, 1),
        4 => (2, 1),
        6 => (c.u16()?, c.u8()?),
        _ => unreachable!(),
    };
    if !matches!((afi, safi), (1, 1) | (2, 1)) {
        return Ok(None);
    }
    let table =
        table.ok_or_else(|| bad("mrt_peer_table", base, "RIB has no preceding peer table"))?;
    let mut p = prefix(&mut c, afi, m.limits)?;
    p.safi = safi;
    let count = usize::from(c.u16()?);
    m.add(0, count, 0, 0, count * 16, count * 112)?;
    if body.len() - c.at < count * 8 {
        return Err(bad(
            "mrt_rib_entries",
            base + c.at,
            "entry count exceeds record",
        ));
    }
    let mut entries = Vec::new();
    entries
        .try_reserve_exact(count)
        .map_err(|_| Error::limit("mrt_rib_entries"))?;
    for _ in 0..count {
        let peer_index = c.u16()?;
        if usize::from(peer_index) >= table.2 {
            return Err(bad(
                "mrt_peer_index",
                c.base + c.at - 2,
                "RIB peer index outside preceding table",
            ));
        }
        let originated_seconds = c.u32()?;
        let len = usize::from(c.u16()?);
        let attr_base = c.base + c.at;
        let raw = c.take(len)?;
        m.add(0, 0, 0, len, len, len * 2)?;
        attr_count(raw, attr_base, m)?;
        entries.push(RibEntry {
            peer_index,
            originated_seconds,
            attributes: copy_bounded_bytes(raw, "mrt_rib_attributes")?,
            as_path_asn_width: 4,
            as_path_asn_width_source: AsnWidthSource::TableDumpV2Rib,
        });
    }
    c.finish()?;
    Ok(Some(Rib {
        sequence,
        afi,
        safi,
        prefix: p,
        peer_table_offset: table.0,
        peer_table_sha256: table.1.clone(),
        entries,
    }))
}
fn parse_bgp4mp(
    body: &[u8],
    base: usize,
    subtype: u16,
    m: &mut Meter<'_>,
) -> Result<Option<Bgp4mp>> {
    let (width, state, local, add_path) = match subtype {
        0 => (2, true, false, false),
        1 => (2, false, false, false),
        4 => (4, false, false, false),
        5 => (4, true, false, false),
        6 => (2, false, true, false),
        7 => (4, false, true, false),
        8 => (2, false, false, true),
        9 => (4, false, false, true),
        10 => (2, false, true, true),
        11 => (4, false, true, true),
        _ => return Ok(None),
    };
    let mut c = Cursor::new(body, base);
    let peer_asn = if width == 4 {
        c.u32()?
    } else {
        u32::from(c.u16()?)
    };
    let local_asn = if width == 4 {
        c.u32()?
    } else {
        u32::from(c.u16()?)
    };
    let interface_index = c.u16()?;
    let afi = c.u16()?;
    if afi != 1 && afi != 2 {
        return Ok(None);
    }
    let peer_address = address(&mut c, afi == 2)?;
    let local_address = address(&mut c, afi == 2)?;
    let payload = if state {
        let old = c.u16()?;
        let new = c.u16()?;
        Bgp4mpPayload::State { old, new }
    } else {
        let msg = c.rest();
        if msg.len() < 19
            || msg[..16] != [0xff; 16]
            || usize::from(u16::from_be_bytes([msg[16], msg[17]])) != msg.len()
        {
            return Err(bad(
                "mrt_bgp_message",
                c.base + c.at - msg.len(),
                "invalid BGP message frame",
            ));
        }
        m.add(0, 0, 0, msg.len(), msg.len(), msg.len() * 2)?;
        Bgp4mpPayload::Message(copy_bounded_bytes(msg, "mrt_bgp_message")?)
    };
    c.finish()?;
    Ok(Some(Bgp4mp {
        peer_asn,
        local_asn,
        asn_width: width,
        asn_width_source: AsnWidthSource::Bgp4mpSubtype,
        interface_index,
        address_afi: afi,
        peer_address,
        local_address,
        locally_generated: local,
        add_path,
        payload,
    }))
}

impl MrtBatch {
    /// Parse all records before publishing any result. Input is an already
    /// available byte slice; no download or collector trust is involved.
    pub fn parse(input: &[u8], source: MrtSource, limits: &MrtLimits) -> Result<Self> {
        limits.validate()?;
        if input.is_empty()
            || input.len() > limits.input_bytes
            || source.source_id.is_empty()
            || source.checkpoint_id.is_empty()
            || source.source_id.len() > 1024
            || source.checkpoint_id.len() > 1024
            || source.source_id.chars().any(char::is_control)
            || source.checkpoint_id.chars().any(char::is_control)
            || source.source_id.trim().is_empty()
            || source.checkpoint_id.trim().is_empty()
        {
            return Err(Error::limit("mrt_input_or_identity"));
        }
        if input
            .len()
            .checked_mul(3)
            .filter(|n| *n <= limits.work)
            .is_none()
        {
            return Err(Error::limit("mrt_work_preflight"));
        }
        // Structural preflight rejects trailing partial records and inflated
        // lengths before semantic allocation begins.
        let mut starts = Vec::new();
        let mut at = 0usize;
        while at < input.len() {
            if input.len() - at < 12 {
                return Err(bad("mrt_header", at, "partial common header"));
            }
            let len = u32::from_be_bytes(
                input[at + 8..at + 12]
                    .try_into()
                    .map_err(|_| Error::limit("mrt_length"))?,
            );
            let end = at
                .checked_add(12)
                .and_then(|n| n.checked_add(len as usize))
                .ok_or_else(|| Error::limit("mrt_length"))?;
            if end > input.len() {
                return Err(bad("mrt_record", at, "record length exceeds input"));
            }
            if starts.len() >= limits.records {
                return Err(Error::limit("mrt_records"));
            }
            starts
                .try_reserve(1)
                .map_err(|_| Error::limit("mrt_records"))?;
            starts.push((at, end, len));
            at = end;
        }
        let mut m = Meter::new(limits, input.len(), starts.len(), &source)?;
        let mut records = Vec::new();
        records
            .try_reserve_exact(starts.len())
            .map_err(|_| Error::limit("mrt_records"))?;
        let mut table: Option<(u64, String, usize)> = None;
        for (at, end, len) in starts {
            let mut h = Cursor::new(&input[at..at + 12], at);
            let seconds = h.u32()?;
            let record_type = h.u16()?;
            let subtype = h.u16()?;
            let declared = h.u32()?;
            if declared != len {
                return Err(bad("mrt_length", at + 8, "preflight mismatch"));
            }
            let digest = sha256::hex(&sha256::digest(&input[at..end]));
            let mut payload = &input[at + 12..end];
            let mut microseconds = None;
            if record_type == 17 {
                let mut et = Cursor::new(payload, at + 12);
                let us = et.u32()?;
                microseconds = Some(us);
                payload = &payload[4..];
            }
            let base = at + 12 + usize::from(microseconds.is_some()) * 4;
            // RFC 6396 binds a peer table only to the immediately following
            // TABLE_DUMP_V2 RIB series. An unrelated record ends that series;
            // a later RIB must not silently reuse stale peer identities.
            if record_type != 13 || !matches!(subtype, 1..=6) {
                table = None;
            }
            let body = match (record_type, subtype) {
                (13, 1) => {
                    let p = parse_peers(payload, base, &mut m)?;
                    table = Some((at as u64, digest.clone(), p.peers.len()));
                    MrtBody::PeerIndex(p)
                }
                (13, 2 | 4 | 6) => {
                    match parse_rib(payload, base, subtype, table.as_ref(), &mut m)? {
                        Some(r) => MrtBody::Rib(r),
                        None => {
                            m.add(0, 0, 0, payload.len(), payload.len(), payload.len() * 2)?;
                            MrtBody::Opaque {
                                reason: "unsupported_afi_safi",
                                bytes: copy_bounded_bytes(payload, "mrt_opaque_record")?,
                            }
                        }
                    }
                }
                (16 | 17, _) => match parse_bgp4mp(payload, base, subtype, &mut m)? {
                    Some(b) => MrtBody::Bgp4mp(b),
                    None => {
                        m.add(0, 0, 0, payload.len(), payload.len(), payload.len() * 2)?;
                        MrtBody::Opaque {
                            reason: "unsupported_bgp4mp_subtype_or_afi",
                            bytes: copy_bounded_bytes(payload, "mrt_opaque_record")?,
                        }
                    }
                },
                _ => {
                    m.add(0, 0, 0, payload.len(), payload.len(), payload.len() * 2)?;
                    MrtBody::Opaque {
                        reason: "unsupported_type_or_subtype",
                        bytes: copy_bounded_bytes(payload, "mrt_opaque_record")?,
                    }
                }
            };
            records.push(MrtRecord {
                offset: at as u64,
                length: len,
                record_type,
                subtype,
                time: MrtTime {
                    seconds,
                    microseconds,
                },
                sha256: digest,
                body,
            });
        }
        Ok(Self {
            schema: SCHEMA,
            source,
            sha256: sha256::hex(&sha256::digest(input)),
            byte_length: input.len() as u64,
            source_authenticated: false,
            records,
            retained_bytes: m.retained,
            work_charge: m.work,
            output_charge: m.output,
        })
    }

    /// Parsed MRT records are retained in strict source-offset order. Resolve a
    /// peer table with a counted lower-bound search rather than rescanning all
    /// prior records for every RIB entry. The probe count is private test evidence
    /// for the logarithmic lookup contract.
    pub(super) fn record_index_by_offset(&self, offset: u64) -> Option<(usize, usize)> {
        let mut low = 0usize;
        let mut high = self.records.len();
        let mut probes = 0usize;
        while low < high {
            probes += 1;
            let middle = low + (high - low) / 2;
            if self.records[middle].offset < offset {
                low = middle + 1;
            } else {
                high = middle;
            }
        }
        let record = self.records.get(low)?;
        probes += 1;
        (record.offset == offset).then_some((low, probes))
    }

    /// Safe subset conversion into the existing contextual import envelope.
    /// Unsupported attribute semantics remain in the versioned MRT record.
    /// A RIB supplies no direction or endpoint generation, so this does not
    /// authorize Adj-RIB-In state or merge it with a captured partition.
    pub fn normalize_rib_entry(
        &self,
        record_index: usize,
        entry_index: usize,
        limits: &super::model::Limits,
    ) -> Result<Option<Json>> {
        let record = self
            .records
            .get(record_index)
            .ok_or_else(|| bad("mrt_record_index", 0, "missing record"))?;
        let MrtBody::Rib(rib) = &record.body else {
            return Err(bad("mrt_rib", 0, "record is not RIB"));
        };
        let entry = rib
            .entries
            .get(entry_index)
            .ok_or_else(|| bad("mrt_entry_index", 0, "missing entry"))?;
        let (table_index, _) = self
            .record_index_by_offset(rib.peer_table_offset)
            .ok_or_else(|| bad("mrt_peer_table", 0, "peer table identity missing"))?;
        let table_record = &self.records[table_index];
        if table_record.sha256.as_str() != rib.peer_table_sha256.as_str() {
            return Err(bad("mrt_peer_table", 0, "peer table identity changed"));
        }
        let MrtBody::PeerIndex(table) = &table_record.body else {
            return Err(bad("mrt_peer_table", 0, "peer table identity changed"));
        };
        let peer = table
            .peers
            .get(usize::from(entry.peer_index))
            .ok_or_else(|| bad("mrt_peer_index", 0, "peer index outside table"))?;
        let Some(parsed_attributes) = semantic_attributes(&entry.attributes, limits)? else {
            return Ok(None);
        };
        let peer_identity = format!(
            "{}:{}:{}:{}",
            rib.peer_table_sha256, entry.peer_index, peer.address, peer.asn
        );
        let session = format!("mrt:{}:{}", rib.peer_table_offset, entry.peer_index);
        let checkpoint = format!(
            "{}:{}:{}",
            self.source.checkpoint_id, rib.peer_table_offset, rib.sequence
        );
        let context = ImportContext {
            source_id: self.source.source_id.clone(),
            source_schema: SCHEMA.into(),
            source_version: Some("1".into()),
            clock: ObservationClock {
                policy: ClockPolicy::SourceLabel,
                clock_id: Some("mrt-originated-seconds".into()),
                reported_uncertainty_ns: None,
            },
            batch: SourceBatch {
                batch_id: None,
                sha256: Some(self.sha256.clone()),
                byte_length: Some(self.byte_length),
            },
            checkpoint_id: checkpoint,
            session: session.clone(),
            generation: 0,
            direction: None,
            peer: Some(peer_identity.clone()),
            local: None,
            provenance: vec![SourceRange {
                start: record.offset,
                end: record.offset + 12 + u64::from(record.length),
                sha256: Some(record.sha256.clone()),
            }],
        };
        let input = ImportedRouteObservation {
            source_id: self.source.source_id.clone(),
            record_id: format!("mrt:{}:{}:{}", record.offset, rib.sequence, entry_index),
            observed_at_ns: Some(i64::from(entry.originated_seconds) * 1_000_000_000),
            session: Some(session),
            peer: Some(peer_identity),
            local: None,
            action: RouteAction::Announce,
            prefix: rib.prefix.clone(),
            attributes: parsed_attributes.attributes.clone(),
        };
        let mut normalized = bgp_import::normalize_with_context(input, context, limits)?;
        let mut reasons = BTreeSet::new();
        if !matches!((rib.afi, rib.safi), (1, 1)) {
            reasons.insert("unsupported_mrt_route_family");
        }
        if [5, 9, 10]
            .into_iter()
            .any(|code| parsed_attributes.seen.contains(&code))
        {
            reasons.insert("peer_relationship_unresolved");
        }
        if parsed_attributes.partial {
            reasons.insert("partial_attribute_value");
        }
        let identity = super::bgp::semantic_route_identity(
            RouteAction::Announce,
            &rib.prefix,
            &parsed_attributes.attributes,
            super::bgp::SemanticIdentityEvidence {
                attributes_present: &parsed_attributes.seen,
                large_communities: &parsed_attributes.large_communities,
                incompleteness_reasons: &reasons,
                opaque_occurrences: &[],
            },
            limits,
        )?;
        let Json::Object(root) = &mut normalized else {
            return Err(bad(
                "mrt_semantic_identity",
                0,
                "route envelope is not an object",
            ));
        };
        let routes = root
            .iter_mut()
            .find_map(|(key, value)| (*key == "routes").then_some(value))
            .and_then(|value| match value {
                Json::Array(routes) => routes.first_mut(),
                _ => None,
            })
            .ok_or_else(|| bad("mrt_semantic_identity", 0, "normalized route missing"))?;
        let Json::Object(route) = routes else {
            return Err(bad(
                "mrt_semantic_identity",
                0,
                "normalized route is not an object",
            ));
        };
        let attributes = route
            .iter_mut()
            .find_map(|(key, value)| (*key == "attributes").then_some(value))
            .ok_or_else(|| bad("mrt_semantic_identity", 0, "route attributes missing"))?;
        let Json::Object(attributes) = attributes else {
            return Err(bad(
                "mrt_semantic_identity",
                0,
                "route attributes are not an object",
            ));
        };
        let mut normalized_large_communities = parsed_attributes.large_communities.clone();
        normalized_large_communities.sort_unstable();
        normalized_large_communities.dedup();
        if attributes
            .iter()
            .any(|(key, _)| *key == "large_communities")
        {
            return Err(bad(
                "mrt_semantic_identity",
                0,
                "unexpected existing Large Communities projection",
            ));
        }
        attributes.push((
            "large_communities",
            Json::array(
                normalized_large_communities
                    .into_iter()
                    .map(|tuple| Json::array(tuple.into_iter().map(Json::from))),
            ),
        ));
        if let Some((_, value)) = route
            .iter_mut()
            .find(|(key, _)| *key == "semantic_identity")
        {
            *value = identity;
        } else {
            route.push(("semantic_identity", identity));
        }
        super::bgp_state::Observation::from_normalized(&normalized, None, limits)?;
        normalized.encode_bounded(limits.input_bytes.min(limits.output_bytes))?;
        Ok(Some(normalized))
    }
}

struct MrtSemanticAttributes {
    attributes: PathAttributes,
    large_communities: Vec<[u32; 3]>,
    seen: BTreeSet<u8>,
    partial: bool,
}

/// Interpret only losslessly representable, unambiguous RIB attributes.
/// MP_REACH uses MRT-specific encoding and remains in the adapter record.
fn semantic_attributes(
    raw: &[u8],
    limits: &super::model::Limits,
) -> Result<Option<MrtSemanticAttributes>> {
    limits.validate()?;
    if raw.len()
        > limits
            .input_bytes
            .min(limits.work)
            .min(limits.retained_bytes)
    {
        return Err(Error::limit("mrt_import_attributes"));
    }
    let mut c = Cursor::new(raw, 0);
    let mut out = PathAttributes::default();
    let mut large_communities = Vec::new();
    let mut seen = [false; 256];
    let mut path_values = 0usize;
    let mut partial = false;
    while c.at < raw.len() {
        let flags = c.u8()?;
        let code = c.u8()?;
        let len = if flags & 0x10 != 0 {
            usize::from(c.u16()?)
        } else {
            usize::from(c.u8()?)
        };
        let value = c.take(len)?;
        if seen[usize::from(code)] {
            if matches!(code, 14 | 15) {
                return Ok(None);
            }
            // RFC 7606 discards later occurrences of ordinary attributes.
            // Preserve every occurrence in the parent MRT record bytes while
            // using the first occurrence as the effective value here.
            continue;
        }
        seen[usize::from(code)] = true;
        let expected_flags = match code {
            1 | 2 | 3 | 5 => 0x40,
            4 | 9 | 10 => 0x80,
            8 | 32 => 0xc0,
            _ => return Ok(None),
        };
        if flags & 0xc0 != expected_flags || (flags & 0x20 != 0 && expected_flags != 0xc0) {
            return Ok(None);
        }
        partial |= flags & 0x20 != 0;
        match code {
            1 if len == 1 && value[0] <= 2 => out.origin = Some(value[0]),
            2 => {
                let mut p = Cursor::new(value, 0);
                while p.at < value.len() {
                    let kind = p.u8()?;
                    let count = usize::from(p.u8()?);
                    if !matches!(kind, 1..=4) {
                        return Ok(None);
                    }
                    if out.as_path.len() >= limits.elements
                        || count > limits.elements.saturating_sub(path_values)
                    {
                        return Err(Error::limit("mrt_import_as_path"));
                    }
                    path_values += count;
                    let mut values = Vec::new();
                    values
                        .try_reserve_exact(count)
                        .map_err(|_| Error::limit("mrt_import_as_path"))?;
                    for _ in 0..count {
                        values.push(p.u32()?);
                    }
                    out.as_path
                        .try_reserve(1)
                        .map_err(|_| Error::limit("mrt_import_as_path"))?;
                    out.as_path.push(AsPathSegment { kind, values });
                }
            }
            3 if len == 4 => {
                out.next_hop =
                    Some(Ipv4Addr::new(value[0], value[1], value[2], value[3]).to_string())
            }
            4 if len == 4 => {
                out.med = Some(u32::from_be_bytes(
                    value
                        .try_into()
                        .map_err(|_| Error::limit("mrt_attribute"))?,
                ))
            }
            5 if len == 4 => {
                out.local_preference = Some(u32::from_be_bytes(
                    value
                        .try_into()
                        .map_err(|_| Error::limit("mrt_attribute"))?,
                ))
            }
            8 if len != 0 && len % 4 == 0 => {
                if len / 4 > limits.elements.saturating_sub(out.communities.len()) {
                    return Err(Error::limit("mrt_import_communities"));
                }
                out.communities
                    .try_reserve(len / 4)
                    .map_err(|_| Error::limit("mrt_import_communities"))?;
                for chunk in value.chunks_exact(4) {
                    out.communities.push(u32::from_be_bytes(
                        chunk
                            .try_into()
                            .map_err(|_| Error::limit("mrt_attribute"))?,
                    ));
                }
            }
            9 if len == 4 => {
                out.originator_id =
                    Some(Ipv4Addr::new(value[0], value[1], value[2], value[3]).to_string())
            }
            10 if len != 0 && len % 4 == 0 => {
                if len / 4 > limits.elements.saturating_sub(out.cluster_list.len()) {
                    return Err(Error::limit("mrt_import_cluster_list"));
                }
                out.cluster_list
                    .try_reserve(len / 4)
                    .map_err(|_| Error::limit("mrt_import_cluster_list"))?;
                for chunk in value.chunks_exact(4) {
                    out.cluster_list
                        .push(Ipv4Addr::new(chunk[0], chunk[1], chunk[2], chunk[3]).to_string());
                }
            }
            32 if len != 0 && len % 12 == 0 => {
                let count = len / 12;
                if count > limits.elements.saturating_sub(large_communities.len()) {
                    return Err(Error::limit("mrt_import_large_communities"));
                }
                large_communities
                    .try_reserve(count)
                    .map_err(|_| Error::limit("mrt_import_large_communities"))?;
                for tuple in value.chunks_exact(12) {
                    large_communities.push([
                        u32::from_be_bytes(
                            tuple[0..4]
                                .try_into()
                                .map_err(|_| Error::limit("mrt_attribute"))?,
                        ),
                        u32::from_be_bytes(
                            tuple[4..8]
                                .try_into()
                                .map_err(|_| Error::limit("mrt_attribute"))?,
                        ),
                        u32::from_be_bytes(
                            tuple[8..12]
                                .try_into()
                                .map_err(|_| Error::limit("mrt_attribute"))?,
                        ),
                    ]);
                }
            }
            _ => return Ok(None),
        }
    }
    Ok(Some(MrtSemanticAttributes {
        attributes: out,
        large_communities,
        seen: seen
            .iter()
            .enumerate()
            .filter_map(|(code, present)| present.then_some(code as u8))
            .collect(),
        partial,
    }))
}
