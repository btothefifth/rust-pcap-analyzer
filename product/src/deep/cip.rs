//! EtherNet/IP envelopes, ordered CIP paths and explicit connected-I/O bindings.
use super::model::*;
use pcap_evidence::{json::Json, provenance::EvidenceBytes, sha256, Error, Result};
use std::collections::BTreeMap;

pub fn path(b: &[u8], base: usize, l: &Limits) -> Result<Json> {
    let mut p = 0;
    let mut out = Vec::new();
    while p < b.len() {
        if out.len() >= l.elements {
            return Err(Error::limit("cip_path_segments"));
        }
        let start = p;
        let tag = b[p];
        p += 1;
        let (kind, value) = if tag & 0xe0 == 0x20 {
            let logical = (tag >> 2) & 7;
            let format = tag & 3;
            let width = match format {
                0 => 1,
                1 => 2,
                2 => 4,
                _ => return Err(bad("cip_path", base + start, "reserved logical format")),
            };
            if width > 1 {
                need(b, p + 1, "cip_path_pad")?;
                if b[p] != 0 {
                    return Err(bad("cip_path", base + p, "nonzero logical reserved byte"));
                }
                p += 1;
            }
            need(b, p + width, "cip_logical")?;
            let v = uint(&b[p..p + width], true)?;
            p += width;
            (
                match logical {
                    0 => "class",
                    1 => "instance",
                    2 => "member",
                    3 => "connection_point",
                    4 => "attribute",
                    5 => "special",
                    6 => "service",
                    _ => "extended_logical",
                },
                v.to_string().into(),
            )
        } else if tag == 0x91 {
            need(b, p + 1, "cip_symbol")?;
            let n = usize::from(b[p]);
            p += 1;
            need(b, p + n, "cip_symbol")?;
            let v = hex(&b[p..p + n]);
            p += n;
            if n % 2 == 1 {
                need(b, p + 1, "cip_symbol_padding")?;
                if b[p] != 0 {
                    return Err(bad("cip_path", base + p, "nonzero symbol padding"));
                }
                p += 1;
            }
            ("ansi_symbol_bytes", v)
        } else if tag & 0xe0 == 0 {
            let extended_link = tag & 16 != 0;
            let mut port = u64::from(tag & 15);
            let n = if extended_link {
                need(b, p + 1, "cip_port_link")?;
                let n = usize::from(b[p]);
                p += 1;
                n
            } else {
                1
            };
            if port == 15 {
                port = u64::from(le16(b, p)?);
                p += 2;
            }
            need(b, p + n, "cip_port_link")?;
            let link = hex(&b[p..p + n]);
            p += n;
            if (p - start) % 2 == 1 {
                need(b, p + 1, "cip_port_padding")?;
                p += 1;
            }
            (
                "port",
                Json::object([("port", port.to_string().into()), ("link", link)]),
            )
        } else {
            out.push(Json::object([
                ("kind", "unsupported_path_tail".into()),
                ("start", (base + start).to_string().into()),
                ("end", (base + b.len()).to_string().into()),
                ("raw", hex(&b[start..])),
            ]));
            break;
        };
        out.push(Json::object([
            ("kind", kind.into()),
            ("value", value),
            ("start", (base + start).to_string().into()),
            ("end", (base + p).to_string().into()),
        ]));
    }
    Ok(Json::Array(out))
}
pub fn message(b: &[u8], base: usize, l: &Limits) -> Result<Json> {
    need(b, 2, "cip_message")?;
    let response = b[0] & 128 != 0;
    let service = b[0] & 127;
    let mut fields = vec![("service", service.into()), ("response", response.into())];
    let at = if response {
        need(b, 4, "cip_response")?;
        if b[1] != 0 {
            return Err(bad("cip_response", base + 1, "reserved byte"));
        }
        let count = usize::from(b[3]);
        if count > l.elements {
            return Err(Error::limit("cip_status"));
        }
        need(b, 4 + 2 * count, "cip_additional_status")?;
        fields.push(("general_status", b[2].into()));
        fields.push((
            "additional_status",
            Json::array(
                (0..count)
                    .map(|i| le16(b, 4 + 2 * i).map(Json::from))
                    .collect::<Result<Vec<_>>>()?,
            ),
        ));
        4 + 2 * count
    } else {
        let n = usize::from(b[1]) * 2;
        need(b, 2 + n, "cip_path")?;
        fields.push(("path", path(&b[2..2 + n], base + 2, l)?));
        2 + n
    };
    if service == 0x0a {
        let body = &b[at..];
        let count = usize::from(le16(body, 0)?);
        if count > l.elements {
            return Err(Error::limit("cip_multi_service"));
        }
        need(body, 2 + count * 2, "cip_multi_offsets")?;
        let mut offsets = Vec::new();
        for i in 0..count {
            let p = usize::from(le16(body, 2 + i * 2)?);
            if p < 2 + count * 2 || p >= body.len() || offsets.last().is_some_and(|last| *last >= p)
            {
                return Err(bad(
                    "cip_multi_offsets",
                    base + at,
                    "invalid ordered offset",
                ));
            }
            offsets.push(p);
        }
        let mut items = Vec::new();
        for (i, &p) in offsets.iter().enumerate() {
            let end = offsets.get(i + 1).copied().unwrap_or(body.len());
            let child = &body[p..end];
            // Recursive multiple-service packets consume a reduced explicit depth.
            if l.depth <= 1 {
                return Err(Error::limit("cip_service_depth"));
            }
            let mut next = l.clone();
            next.depth -= 1;
            next.elements = l.elements.saturating_sub(count).max(1);
            items.push(message(child, base + at + p, &next)?);
        }
        fields.push(("services", Json::Array(items)));
    } else if !response && matches!(service, 0x54 | 0x5b) {
        let body = &b[at..];
        let large = service == 0x5b;
        let min = if large { 40 } else { 36 };
        need(body, min, "forward_open")?;
        let params = if large { 4 } else { 2 };
        let ot = 26;
        let to = ot + params + 4;
        let tt = to + params;
        let pathlen = usize::from(body[tt + 1]) * 2;
        need(body, tt + 2 + pathlen, "forward_open_path")?;
        fields.push((
            "forward_open",
            Json::object([
                ("ot_connection_id", le32(body, 2)?.to_string().into()),
                ("to_connection_id", le32(body, 6)?.to_string().into()),
                ("connection_serial", le16(body, 10)?.into()),
                ("originator_vendor", le16(body, 12)?.into()),
                ("originator_serial", le32(body, 14)?.to_string().into()),
                ("timeout_multiplier", body[18].into()),
                ("ot_rpi_us", le32(body, 22)?.to_string().into()),
                (
                    "ot_parameters",
                    uint(&body[ot..ot + params], true)?.to_string().into(),
                ),
                ("to_rpi_us", le32(body, ot + params)?.to_string().into()),
                (
                    "to_parameters",
                    uint(&body[to..to + params], true)?.to_string().into(),
                ),
                ("transport_trigger", body[tt].into()),
                (
                    "connection_path",
                    path(&body[tt + 2..tt + 2 + pathlen], base + at + tt + 2, l)?,
                ),
            ]),
        ));
    } else if response && matches!(service, 0x54 | 0x5b) && b[2] == 0 {
        need(b, at + 26, "forward_open_reply")?;
        fields.push((
            "forward_open_reply",
            Json::object([
                ("ot_connection_id", le32(b, at)?.to_string().into()),
                ("to_connection_id", le32(b, at + 4)?.to_string().into()),
                ("connection_serial", le16(b, at + 8)?.into()),
                ("originator_vendor", le16(b, at + 10)?.into()),
                ("originator_serial", le32(b, at + 12)?.to_string().into()),
                ("ot_api_us", le32(b, at + 16)?.to_string().into()),
                ("to_api_us", le32(b, at + 20)?.to_string().into()),
            ]),
        ));
    } else {
        fields.push((
            "service_body_sha256",
            sha256::hex(&sha256::digest(&b[at..])).into(),
        ));
        fields.push(("service_body_complete_semantics", false.into()));
    }
    fields.push(("start", base.to_string().into()));
    fields.push(("end", (base + b.len()).to_string().into()));
    Ok(Json::Object(fields))
}
pub fn decode(bytes: &EvidenceBytes, l: &Limits) -> Result<Report> {
    let b = bytes.data();
    need(b, 24, "enip")?;
    let n = 24 + usize::from(le16(b, 2)?);
    if n != b.len() {
        return Err(bad("enip", 2, "length does not match framed unit"));
    }
    if le32(b, 20)? != 0 {
        return Err(bad("enip_options", 20, "nonzero reserved options"));
    }
    let cmd = le16(b, 0)?;
    let mut r = Report::new("enip_cip", bytes, l)?;
    r.u("command", u64::from(cmd), 0..2)?;
    r.u("session_handle", u64::from(le32(b, 4)?), 4..8)?;
    r.u("encapsulation_status", u64::from(le32(b, 8)?), 8..12)?;
    r.add(
        "sender_context",
        hex(&b[12..20]),
        12..20,
        "encapsulation_context_not_authentication",
    )?;
    if cmd == 0x65 {
        need(b, 28, "register_session")?;
        r.u("protocol_version", u64::from(le16(b, 24)?), 24..26)?;
        r.u("options", u64::from(le16(b, 26)?), 26..28)?;
        return Ok(r);
    }
    if ![0x6f, 0x70].contains(&cmd) {
        r.note(
            Status::Unsupported,
            "enip_management_command_body",
            24,
            b.len(),
        )?;
        return Ok(r);
    }
    need(b, 32, "enip_cpf")?;
    let count = usize::from(le16(b, 30)?);
    if count > l.elements {
        return Err(Error::limit("cpf_items"));
    }
    let mut at = 32;
    for i in 0..count {
        let ty = le16(b, at)?;
        let n = usize::from(le16(b, at + 2)?);
        at += 4;
        need(b, at + n, "cpf_item")?;
        let v = match ty {
            0xa1 if n == 4 => Json::object([("connection_id", le32(b, at)?.to_string().into())]),
            0x8002 if n == 8 => Json::object([
                ("connection_id", le32(b, at)?.to_string().into()),
                ("sequence", le32(b, at + 4)?.to_string().into()),
            ]),
            0xb2 => message(&b[at..at + n], at, l)?,
            0xb1 => {
                need(&b[..at + n], at + 2, "connected_sequence")?;
                Json::object([
                    ("connected_sequence", le16(b, at)?.into()),
                    ("message", message(&b[at + 2..at + n], at + 2, l)?),
                    ("connection_context_verified", false.into()),
                ])
            }
            _ => Json::object([
                ("opaque", true.into()),
                (
                    "raw_sha256",
                    sha256::hex(&sha256::digest(&b[at..at + n])).into(),
                ),
            ]),
        };
        r.add(
            format!("cpf[{i}]"),
            Json::object([("type", ty.into()), ("data", v)]),
            at - 4..at + n,
            "cpf_item_order_preserved",
        )?;
        at += n;
    }
    if at != b.len() {
        r.note(Status::Rejected, "cpf_trailing_bytes", at, b.len())?;
    }
    Ok(r)
}
/// Explicit negotiated or operator-attributed binding. No connection ID alone is
/// globally unique; callers include the transport/network generation in `scope`.
#[derive(Clone, Debug)]
pub struct Binding {
    pub connection_id: u32,
    pub max_payload: usize,
    pub run_idle_header: bool,
    pub class1_sequence: bool,
    pub producer_evidence_sha256: [u8; 32],
}
pub struct IoSession {
    bindings: BTreeMap<(String, u32), Binding>,
    sequences: BTreeMap<(String, u32), u32>,
    limit: usize,
}
impl IoSession {
    pub fn new(limit: usize) -> Result<Self> {
        if limit == 0 || limit > 65536 {
            return Err(Error::limit("cip_bindings"));
        }
        Ok(Self {
            bindings: BTreeMap::new(),
            sequences: BTreeMap::new(),
            limit,
        })
    }
    pub fn bind(&mut self, scope: &str, binding: Binding) -> Result<()> {
        if scope.is_empty()
            || scope.len() > 512
            || binding.max_payload == 0
            || binding.max_payload > 65535
            || self.bindings.len() >= self.limit
        {
            return Err(Error::limit("cip_binding"));
        }
        let key = (scope.into(), binding.connection_id);
        if self.bindings.contains_key(&key) {
            return Err(bad(
                "cip_binding",
                0,
                "explicit close required before rebinding reused connection ID",
            ));
        }
        self.bindings.insert(key, binding);
        Ok(())
    }
    pub fn close(&mut self, scope: &str, id: u32) {
        let key = (scope.to_owned(), id);
        self.bindings.remove(&key);
        self.sequences.remove(&key);
    }
    pub fn observe(&mut self, scope: &str, bytes: &EvidenceBytes, l: &Limits) -> Result<Report> {
        let b = bytes.data();
        let count = usize::from(le16(b, 0)?);
        if count > 16 {
            return Err(Error::limit("cip_io_cpf"));
        }
        let mut at = 2;
        let mut id = None;
        let mut sequence = None;
        let mut data = None;
        for _ in 0..count {
            let ty = le16(b, at)?;
            let n = usize::from(le16(b, at + 2)?);
            at += 4;
            need(b, at + n, "io_cpf")?;
            match ty {
                0xa1 if n == 4 => {
                    if id.replace(le32(b, at)?).is_some() {
                        return Err(bad("io_cpf", at, "duplicate address"));
                    }
                }
                0x8002 if n == 8 => {
                    if id.replace(le32(b, at)?).is_some() {
                        return Err(bad("io_cpf", at, "duplicate address"));
                    }
                    sequence = Some(le32(b, at + 4)?);
                }
                0xb1 => {
                    if data.replace(at..at + n).is_some() {
                        return Err(bad("io_cpf", at, "duplicate connected data"));
                    }
                }
                _ => {}
            }
            at += n;
        }
        if at != b.len() {
            return Err(bad("io_cpf", at, "trailing bytes"));
        }
        let mut r = Report::new("cip.implicit_io", bytes, l)?;
        let Some(id) = id else {
            return Err(bad("io_cpf", 0, "missing connection identity"));
        };
        let key = (scope.to_owned(), id);
        let Some(binding) = self.bindings.get(&key) else {
            r.note(
                Status::Unsupported,
                "connection_binding_missing",
                0,
                b.len(),
            )?;
            return Ok(r);
        };
        let range = data.ok_or_else(|| bad("io_cpf", 0, "missing connected data"))?;
        if range.len() > binding.max_payload {
            return Err(Error::limit("negotiated_io_size"));
        }
        r.add(
            "binding_evidence_sha256",
            sha256::hex(&binding.producer_evidence_sha256).into(),
            0..0,
            "explicit_binding_dependency",
        )?;
        if let Some(seq) = sequence {
            if let Some(previous) = self.sequences.insert(key, seq) {
                if seq != previous.wrapping_add(1) {
                    r.note(
                        Status::Ambiguous,
                        "io_sequence_duplicate_reorder_or_loss",
                        0,
                        b.len(),
                    )?;
                }
            }
        }
        let mut p = range.start;
        if binding.class1_sequence {
            need(&b[..range.end], p + 2, "class1_sequence")?;
            r.u("class1_sequence", u64::from(le16(b, p)?), p..p + 2)?;
            p += 2;
        }
        if binding.run_idle_header {
            need(&b[..range.end], p + 4, "run_idle_header")?;
            r.u("run_idle_header", u64::from(le32(b, p)?), p..p + 4)?;
            p += 4;
        }
        r.add(
            "process_data",
            hex(&b[p..range.end]),
            p..range.end,
            "bound_io_payload_not_device_state",
        )?;
        Ok(r)
    }
}
