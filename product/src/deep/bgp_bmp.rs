//! Bounded, source-bound BMP v3 file framing. No network or endpoint authority.
use super::bgp_import::SourceRange;
use super::model::bad;
use pcap_evidence::{json::Json, sha256, Error, ErrorCode, Result};
use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const SCHEMA: &str = "pcap-evidence.bgp.bmp-container.v1";
pub const COMMON_BYTES: usize = 6;
pub const PEER_BYTES: usize = 42;

#[derive(Clone, Debug)]
pub struct BmpLimits {
    pub input_bytes: usize,
    pub record_bytes: usize,
    pub records: usize,
    pub peers: usize,
    pub tlvs: usize,
    pub retained_bytes: usize,
    /// Deterministic byte/element accounting, not elapsed time or RSS.
    pub work: usize,
    /// Typed framing allocation charge, not a future JSON byte count.
    pub output_bytes: usize,
}
impl Default for BmpLimits {
    fn default() -> Self {
        Self {
            input_bytes: 8 * 1024 * 1024,
            record_bytes: 1024 * 1024,
            records: 4096,
            peers: 256,
            tlvs: 4096,
            retained_bytes: 16 * 1024 * 1024,
            work: 32 * 1024 * 1024,
            output_bytes: 32 * 1024 * 1024,
        }
    }
}
impl BmpLimits {
    pub fn validate(&self) -> Result<()> {
        if [
            self.input_bytes,
            self.record_bytes,
            self.records,
            self.peers,
            self.tlvs,
            self.retained_bytes,
            self.work,
            self.output_bytes,
        ]
        .contains(&0)
            || self.input_bytes > 64 * 1024 * 1024
            || self.record_bytes > self.input_bytes
        {
            return Err(Error::limit("bmp_configuration"));
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BmpSource {
    pub source_id: String,
    pub checkpoint_id: String,
}
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct BmpPeerIdentity {
    pub peer_type: u8,
    pub distinguisher: [u8; 8],
    pub address: IpAddr,
    pub asn: u32,
    pub bgp_id: [u8; 4],
}
impl BmpPeerIdentity {
    pub fn label(&self) -> String {
        format!(
            "bmp-peer:{}:{}:{}:{}:{}",
            self.peer_type,
            hex(&self.distinguisher),
            self.address,
            self.asn,
            Ipv4Addr::from(self.bgp_id)
        )
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BmpPeer {
    pub identity: BmpPeerIdentity,
    pub flags: u8,
    pub seconds: u32,
    pub microseconds: u32,
}
impl BmpPeer {
    pub fn post_policy(&self) -> bool {
        self.flags & 0x40 != 0
    }
    pub fn asn_width(&self) -> u8 {
        if self.flags & 0x20 != 0 {
            2
        } else {
            4
        }
    }
    pub fn observed_at_ns(&self) -> Option<i64> {
        if (self.seconds == 0 && self.microseconds == 0) || self.microseconds >= 1_000_000 {
            None
        } else {
            Some(i64::from(self.seconds) * 1_000_000_000 + i64::from(self.microseconds) * 1000)
        }
    }
    pub fn json(&self) -> Json {
        Json::object([
            ("peer_type", self.identity.peer_type.into()),
            ("distinguisher", hex(&self.identity.distinguisher).into()),
            ("address", self.identity.address.to_string().into()),
            ("asn", self.identity.asn.into()),
            (
                "bgp_id",
                Ipv4Addr::from(self.identity.bgp_id).to_string().into(),
            ),
            ("flags", self.flags.into()),
            ("seconds", self.seconds.into()),
            ("microseconds", self.microseconds.into()),
            (
                "observed_at_ns",
                self.observed_at_ns()
                    .map_or(Json::Null, |n| n.to_string().into()),
            ),
            ("clock_accuracy", Json::Null),
        ])
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BmpTlv {
    pub kind: u16,
    pub value: SourceRange,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BmpBody {
    RouteMonitoring {
        message: SourceRange,
    },
    PeerUp {
        local_address: IpAddr,
        local_port: u16,
        remote_port: u16,
        sent_open: SourceRange,
        received_open: SourceRange,
        information: Vec<BmpTlv>,
    },
    PeerDown {
        reason: u8,
        data: Option<SourceRange>,
    },
    Initiation {
        information: Vec<BmpTlv>,
    },
    Termination {
        information: Vec<BmpTlv>,
    },
    Opaque {
        reason: &'static str,
        error_offset: Option<u64>,
    },
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BmpRecord {
    pub offset: u64,
    pub length: u32,
    pub message_type: u8,
    pub sha256: String,
    pub peer: Option<BmpPeer>,
    pub body: BmpBody,
}
#[derive(Clone, Debug)]
pub struct BmpBatch {
    pub source: BmpSource,
    pub sha256: String,
    pub byte_length: u64,
    pub records: Vec<BmpRecord>,
    bytes: Vec<u8>,
    pub retained_charge: usize,
    pub work_charge: usize,
    pub output_charge: usize,
}
impl BmpBatch {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn range_bytes(&self, range: &SourceRange) -> Result<&[u8]> {
        let start = usize::try_from(range.start).map_err(|_| Error::limit("bmp_range"))?;
        let end = usize::try_from(range.end).map_err(|_| Error::limit("bmp_range"))?;
        let bytes = self
            .bytes
            .get(start..end)
            .ok_or_else(|| bad("bmp_range", start, "range outside source"))?;
        if range.sha256.as_deref() != Some(sha256::hex(&sha256::digest(bytes)).as_str()) {
            return Err(bad(
                "bmp_range",
                start,
                "range digest disagrees with source",
            ));
        }
        Ok(bytes)
    }
    pub fn record_range(&self, record: &BmpRecord) -> SourceRange {
        SourceRange {
            start: record.offset,
            end: record.offset + u64::from(record.length),
            sha256: Some(record.sha256.clone()),
        }
    }
    pub fn parse(input: &[u8], source: BmpSource, limits: &BmpLimits) -> Result<Self> {
        limits.validate()?;
        for label in [&source.source_id, &source.checkpoint_id] {
            if label.is_empty()
                || label.len() > 1024
                || label.trim().is_empty()
                || label.chars().any(char::is_control)
            {
                return Err(bad(
                    "bmp_source",
                    0,
                    "nonempty bounded control-free source labels required",
                ));
            }
        }
        if input.is_empty() || input.len() > limits.input_bytes {
            return Err(Error::limit("bmp_input"));
        }
        let mut budget = Budget::new(limits);
        let source_metadata = source
            .source_id
            .len()
            .checked_add(source.checkpoint_id.len())
            .and_then(|n| n.checked_add(64))
            .ok_or_else(|| Error::limit("bmp_retained"))?;
        budget.charge(
            input
                .len()
                .checked_add(source_metadata)
                .ok_or_else(|| Error::limit("bmp_retained"))?,
            input.len(),
            input.len(),
        )?;
        let mut records = Vec::new();
        let mut peers = BTreeSet::new();
        let mut offset = 0usize;
        while offset < input.len() {
            if records.len() >= limits.records {
                return Err(Error::limit("bmp_records"));
            }
            let header = input
                .get(
                    offset
                        ..offset
                            .checked_add(COMMON_BYTES)
                            .ok_or_else(|| Error::limit("bmp_length"))?,
                )
                .ok_or_else(|| truncated(offset, "bmp_common"))?;
            if header[0] != 3 {
                return Err(Error::new(
                    ErrorCode::UnsupportedVersion,
                    offset as u64,
                    "bmp_version",
                    "only BMP v3 supported",
                ));
            }
            let length = u32::from_be_bytes(header[1..5].try_into().unwrap());
            if length < COMMON_BYTES as u32 {
                return Err(bad(
                    "bmp_length",
                    offset + 1,
                    "common length smaller than header",
                ));
            }
            let size = usize::try_from(length).map_err(|_| Error::limit("bmp_length"))?;
            if size > limits.record_bytes {
                return Err(Error::limit("bmp_record_bytes"));
            }
            let end = offset
                .checked_add(size)
                .ok_or_else(|| Error::limit("bmp_length"))?;
            let bytes = input
                .get(offset..end)
                .ok_or_else(|| truncated(offset, "bmp_record"))?;
            budget.charge(
                std::mem::size_of::<BmpRecord>() + 64,
                size,
                std::mem::size_of::<BmpRecord>() + 64,
            )?;
            let message_type = header[5];
            let peer_result = if matches!(message_type, 0..=3 | 6)
                && bytes.len() >= COMMON_BYTES + PEER_BYTES
                && bytes[COMMON_BYTES] <= 2
            {
                parse_peer(&bytes[COMMON_BYTES..COMMON_BYTES + PEER_BYTES]).map(Some)
            } else {
                Ok(None)
            };
            let (peer, peer_error) = match peer_result {
                Ok(peer) => (peer, None),
                Err(error) => (None, Some(error)),
            };
            if let Some(peer) = &peer {
                if !peers.contains(&peer.identity) {
                    if peers.len() >= limits.peers {
                        return Err(Error::limit("bmp_peers"));
                    }
                    budget.charge(
                        std::mem::size_of::<BmpPeerIdentity>(),
                        1,
                        std::mem::size_of::<BmpPeerIdentity>(),
                    )?;
                    peers.insert(peer.identity.clone());
                }
            }
            let parsed = if let Some(error) = peer_error {
                Err(error)
            } else {
                parse_body(
                    input,
                    offset,
                    bytes,
                    message_type,
                    peer.as_ref(),
                    &mut budget,
                )
            };
            let body = match parsed {
                Ok(body) => body,
                Err(error) if error.code == ErrorCode::LimitExceeded => return Err(error),
                Err(error) => BmpBody::Opaque {
                    reason: "malformed_known_record",
                    error_offset: Some(error.offset),
                },
            };
            records
                .try_reserve(1)
                .map_err(|_| Error::limit("bmp_records"))?;
            records.push(BmpRecord {
                offset: offset as u64,
                length,
                message_type,
                sha256: sha256::hex(&sha256::digest(bytes)),
                peer,
                body,
            });
            offset = end;
        }
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(input.len())
            .map_err(|_| Error::limit("bmp_retained"))?;
        bytes.extend_from_slice(input);
        Ok(Self {
            source,
            sha256: sha256::hex(&sha256::digest(input)),
            byte_length: input.len() as u64,
            records,
            bytes,
            retained_charge: budget.retained,
            work_charge: budget.work,
            output_charge: budget.output,
        })
    }
}
struct Budget<'a> {
    limits: &'a BmpLimits,
    retained: usize,
    work: usize,
    output: usize,
    tlvs: usize,
}
impl<'a> Budget<'a> {
    fn new(limits: &'a BmpLimits) -> Self {
        Self {
            limits,
            retained: 0,
            work: 0,
            output: 0,
            tlvs: 0,
        }
    }
    fn charge(&mut self, retained: usize, work: usize, output: usize) -> Result<()> {
        self.retained = self
            .retained
            .checked_add(retained)
            .ok_or_else(|| Error::limit("bmp_retained"))?;
        self.work = self
            .work
            .checked_add(work)
            .ok_or_else(|| Error::limit("bmp_work"))?;
        self.output = self
            .output
            .checked_add(output)
            .ok_or_else(|| Error::limit("bmp_output"))?;
        if self.retained > self.limits.retained_bytes {
            return Err(Error::limit("bmp_retained"));
        }
        if self.work > self.limits.work {
            return Err(Error::limit("bmp_work"));
        }
        if self.output > self.limits.output_bytes {
            return Err(Error::limit("bmp_output"));
        }
        Ok(())
    }
}
fn parse_peer(bytes: &[u8]) -> Result<BmpPeer> {
    let flags = bytes[1];
    let mut distinguisher = [0; 8];
    distinguisher.copy_from_slice(&bytes[2..10]);
    let address = address(&bytes[10..26], flags & 0x80 != 0)?;
    let mut bgp_id = [0; 4];
    bgp_id.copy_from_slice(&bytes[30..34]);
    Ok(BmpPeer {
        identity: BmpPeerIdentity {
            peer_type: bytes[0],
            distinguisher,
            address,
            asn: u32::from_be_bytes(bytes[26..30].try_into().unwrap()),
            bgp_id,
        },
        flags,
        seconds: u32::from_be_bytes(bytes[34..38].try_into().unwrap()),
        microseconds: u32::from_be_bytes(bytes[38..42].try_into().unwrap()),
    })
}
fn address(bytes: &[u8], v6: bool) -> Result<IpAddr> {
    if v6 {
        Ok(IpAddr::V6(Ipv6Addr::from(
            <[u8; 16]>::try_from(bytes).unwrap(),
        )))
    } else {
        // Padding is a reported representation constraint, not a second peer.
        if bytes[..12].iter().any(|v| *v != 0) {
            return Err(bad("bmp_ipv4_padding", 0, "nonzero IPv4 padding"));
        }
        Ok(IpAddr::V4(Ipv4Addr::from(
            <[u8; 4]>::try_from(&bytes[12..]).unwrap(),
        )))
    }
}
fn parse_body(
    input: &[u8],
    offset: usize,
    bytes: &[u8],
    kind: u8,
    peer: Option<&BmpPeer>,
    budget: &mut Budget<'_>,
) -> Result<BmpBody> {
    let start = COMMON_BYTES + PEER_BYTES;
    let opaque = |reason| {
        Ok(BmpBody::Opaque {
            reason,
            error_offset: None,
        })
    };
    if !matches!(kind, 0..=6) {
        return opaque("unknown_message_type");
    }
    if matches!(kind, 1 | 6) {
        return opaque("unsupported_message_type");
    }
    if matches!(kind, 0 | 2 | 3) {
        if bytes
            .get(COMMON_BYTES)
            .is_some_and(|peer_type| *peer_type > 2)
        {
            return opaque("unsupported_peer_type");
        }
        let peer = peer.ok_or_else(|| truncated(offset + COMMON_BYTES, "bmp_per_peer"))?;
        if peer.identity.peer_type == 0 && peer.identity.distinguisher != [0; 8] {
            return Err(bad(
                "bmp_global_distinguisher",
                offset + 8,
                "global peer distinguisher must be zero",
            ));
        }
        if peer.microseconds >= 1_000_000 {
            return Err(bad(
                "bmp_timestamp",
                offset + 44,
                "microseconds out of range",
            ));
        }
        if kind == 0 && peer.flags & 0x10 != 0 {
            return opaque("unsupported_adj_rib_out");
        }
    }
    match kind {
        0 => {
            let message = embedded(input, offset + start, offset + bytes.len(), 2, budget)?;
            if message.end != (offset + bytes.len()) as u64 {
                return Err(bad(
                    "bmp_route_monitoring",
                    offset + start,
                    "UPDATE must fill record",
                ));
            }
            Ok(BmpBody::RouteMonitoring { message })
        }
        3 => {
            let body = bytes
                .get(start..start + 20)
                .ok_or_else(|| truncated(offset + start, "bmp_peer_up"))?;
            let local_address = address(&body[..16], peer.unwrap().flags & 0x80 != 0)?;
            let local_port = u16::from_be_bytes(body[16..18].try_into().unwrap());
            let remote_port = u16::from_be_bytes(body[18..20].try_into().unwrap());
            let sent_open = embedded(input, offset + start + 20, offset + bytes.len(), 1, budget)?;
            let received_open = embedded(
                input,
                sent_open.end as usize,
                offset + bytes.len(),
                1,
                budget,
            )?;
            let information = tlvs(
                input,
                received_open.end as usize,
                offset + bytes.len(),
                3,
                budget,
            )?;
            Ok(BmpBody::PeerUp {
                local_address,
                local_port,
                remote_port,
                sent_open,
                received_open,
                information,
            })
        }
        2 => {
            let reason = *bytes
                .get(start)
                .ok_or_else(|| truncated(offset + start, "bmp_peer_down"))?;
            let data_start = offset + start + 1;
            let end = offset + bytes.len();
            let data = match reason {
                1 | 3 => {
                    let range = embedded(input, data_start, end, 3, budget)?;
                    if range.end != end as u64 || range.end - range.start < 21 {
                        return Err(bad(
                            "bmp_peer_down",
                            data_start,
                            "invalid NOTIFICATION extent",
                        ));
                    }
                    Some(range)
                }
                2 => {
                    if end - data_start != 2 {
                        return Err(bad(
                            "bmp_peer_down",
                            data_start,
                            "FSM event requires two bytes",
                        ));
                    }
                    Some(source_range(input, data_start, end, budget)?)
                }
                4 | 5 => {
                    if end != data_start {
                        return Err(bad("bmp_peer_down", data_start, "unexpected reason data"));
                    }
                    None
                }
                _ => return opaque("unsupported_peer_down_reason"),
            };
            Ok(BmpBody::PeerDown { reason, data })
        }
        4 => {
            let information = tlvs(
                input,
                offset + COMMON_BYTES,
                offset + bytes.len(),
                4,
                budget,
            )?;
            if !information.iter().any(|t| t.kind == 1) || !information.iter().any(|t| t.kind == 2)
            {
                return Err(bad(
                    "bmp_initiation",
                    offset + COMMON_BYTES,
                    "sysDescr and sysName required",
                ));
            }
            Ok(BmpBody::Initiation { information })
        }
        5 => {
            let information = tlvs(
                input,
                offset + COMMON_BYTES,
                offset + bytes.len(),
                5,
                budget,
            )?;
            let mut reason = None;
            for item in information.iter().filter(|item| item.kind == 1) {
                let code = u16::from_be_bytes(
                    input[item.value.start as usize..item.value.end as usize]
                        .try_into()
                        .unwrap(),
                );
                if reason.is_some_and(|prior| prior != code) {
                    return Err(bad(
                        "bmp_termination_reason",
                        item.value.start as usize,
                        "contradictory reason TLVs",
                    ));
                }
                reason = Some(code);
            }
            let reason = reason.ok_or_else(|| {
                bad(
                    "bmp_termination_reason",
                    offset + COMMON_BYTES,
                    "reason TLV required",
                )
            })?;
            if reason > 4 {
                return opaque("unsupported_termination_reason");
            }
            Ok(BmpBody::Termination { information })
        }
        _ => unreachable!(),
    }
}
fn embedded(
    input: &[u8],
    start: usize,
    end: usize,
    kind: u8,
    budget: &mut Budget<'_>,
) -> Result<SourceRange> {
    let header = input
        .get(
            start
                ..start
                    .checked_add(19)
                    .ok_or_else(|| Error::limit("bmp_bgp_length"))?,
        )
        .filter(|_| start + 19 <= end)
        .ok_or_else(|| truncated(start, "bmp_bgp_header"))?;
    if header[..16].iter().any(|v| *v != 255) || header[18] != kind {
        return Err(bad("bmp_bgp_header", start, "invalid BGP marker/type"));
    }
    let length = usize::from(u16::from_be_bytes(header[16..18].try_into().unwrap()));
    let next = start
        .checked_add(length)
        .ok_or_else(|| Error::limit("bmp_bgp_length"))?;
    if length < 19 || next > end {
        return Err(bad("bmp_bgp_length", start + 16, "invalid BGP extent"));
    }
    source_range(input, start, next, budget)
}
fn tlvs(
    input: &[u8],
    mut start: usize,
    end: usize,
    namespace: u8,
    budget: &mut Budget<'_>,
) -> Result<Vec<BmpTlv>> {
    let mut values = Vec::new();
    while start < end {
        let header = input
            .get(start..start + 4)
            .filter(|_| start + 4 <= end)
            .ok_or_else(|| truncated(start, "bmp_tlv_header"))?;
        let kind = u16::from_be_bytes(header[..2].try_into().unwrap());
        let length = usize::from(u16::from_be_bytes(header[2..4].try_into().unwrap()));
        let value_start = start + 4;
        let next = value_start
            .checked_add(length)
            .ok_or_else(|| Error::limit("bmp_tlv_length"))?;
        if next > end {
            return Err(bad("bmp_tlv_length", start + 2, "TLV exceeds record"));
        }
        budget.tlvs = budget
            .tlvs
            .checked_add(1)
            .ok_or_else(|| Error::limit("bmp_tlvs"))?;
        if budget.tlvs > budget.limits.tlvs {
            return Err(Error::limit("bmp_tlvs"));
        }
        let raw = &input[value_start..next];
        let string = match namespace {
            3 => matches!(kind, 0 | 3 | 4),
            4 => kind == 0,
            5 => kind == 0,
            _ => false,
        };
        if string && std::str::from_utf8(raw).is_err() {
            return Err(bad("bmp_tlv_string", value_start, "invalid UTF-8 string"));
        }
        if namespace == 3 && kind == 3 && !(1..=255).contains(&length) {
            return Err(bad(
                "bmp_tlv_vrf",
                value_start,
                "VRF name requires 1..255 bytes",
            ));
        }
        if namespace == 4 && matches!(kind, 1 | 2) && !raw.is_ascii() {
            return Err(bad(
                "bmp_tlv_ascii",
                value_start,
                "sysDescr/sysName requires ASCII",
            ));
        }
        if namespace == 5 && kind == 1 && length != 2 {
            return Err(bad(
                "bmp_termination_reason",
                value_start,
                "reason TLV requires two bytes",
            ));
        }
        budget.charge(
            std::mem::size_of::<BmpTlv>() + 64,
            4,
            std::mem::size_of::<BmpTlv>() + 64,
        )?;
        let value = source_range(input, value_start, next, budget)?;
        values
            .try_reserve(1)
            .map_err(|_| Error::limit("bmp_tlvs"))?;
        values.push(BmpTlv { kind, value });
        start = next;
    }
    Ok(values)
}
fn source_range(
    input: &[u8],
    start: usize,
    end: usize,
    budget: &mut Budget<'_>,
) -> Result<SourceRange> {
    budget.charge(64, end - start, 64)?;
    Ok(SourceRange {
        start: start as u64,
        end: end as u64,
        sha256: Some(sha256::hex(&sha256::digest(&input[start..end]))),
    })
}
fn truncated(offset: usize, context: &'static str) -> Error {
    Error::new(
        ErrorCode::Truncated,
        offset as u64,
        context,
        "truncated BMP field",
    )
}
pub(crate) fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(DIGITS[(b >> 4) as usize] as char);
        s.push(DIGITS[(b & 15) as usize] as char);
    }
    s
}
pub(crate) fn range_json(range: &SourceRange) -> Json {
    Json::object([
        ("start", range.start.into()),
        ("end", range.end.into()),
        (
            "sha256",
            range.sha256.clone().map_or(Json::Null, Json::String),
        ),
    ])
}
