//! RFC 1006 TPKT/COTP and constrained ISO/MMS/S7 field decoding.
//! COTP class-0 DT low sequence bits are not treated as a reorder counter.
use super::{
    ber,
    model::*,
    reassembly::{Outcome, Segment, Segments},
};
use pcap_evidence::{json::Json, provenance::EvidenceBytes, Error, Result};

pub struct Cotp {
    pub kind: u8,
    pub eot: bool,
    pub payload: std::ops::Range<usize>,
    pub consumed: usize,
}
pub fn cotp(b: &[u8]) -> Result<Cotp> {
    need(b, 7, "tpkt")?;
    if b[0] != 3 || b[1] != 0 {
        return Err(bad("tpkt", 0, "unsupported header"));
    }
    let n = usize::from(be16(b, 2)?);
    if n < 7 {
        return Err(bad("tpkt", 2, "length below minimum"));
    }
    need(b, n, "tpkt")?;
    let h = usize::from(b[4]) + 5;
    if h > n || h < 7 {
        return Err(bad("cotp", 4, "invalid length indicator"));
    }
    let kind = b[5] & 0xf0;
    let eot = match kind {
        0xf0 | 0x10 => {
            if b[4] != 2 {
                return Err(bad("cotp_dt", 4, "class zero DT requires two-byte header"));
            }
            b[6] & 128 != 0
        }
        0xe0 | 0xd0 => {
            if b[4] < 6 {
                return Err(bad("cotp_connect", 4, "short connection TPDU"));
            }
            false
        }
        0x80 | 0xc0 => false,
        _ => return Err(bad("cotp", 5, "TPDU outside class-zero subset")),
    };
    Ok(Cotp {
        kind,
        eot,
        payload: h..n,
        consumed: n,
    })
}
pub fn tpkt(bytes: &EvidenceBytes, l: &Limits) -> Result<Report> {
    let b = bytes.data();
    let c = cotp(b)?;
    let mut r = Report::new("iso_cotp", bytes, l)?;
    r.u("tpkt_length", c.consumed as u64, 2..4)?;
    r.u("tpdu_type", u64::from(c.kind), 5..6)?;
    if matches!(c.kind, 0xf0 | 0x10) {
        r.flag("end_of_tsdu", c.eot, 6..7)?;
        r.u(
            "tpdu_number_ignored_class_zero",
            u64::from(b[6] & 127),
            6..7,
        )?;
        if !c.eot {
            r.note(
                Status::Incomplete,
                "cotp_tsdu_continues",
                c.payload.start,
                c.payload.end,
            )?;
        } else if b.get(c.payload.start) == Some(&0x32) {
            let app = bytes.slice(c.payload.clone())?;
            let s = s7(&app, l)?;
            r.add(
                "s7",
                s.json(),
                c.payload.clone(),
                "nested_protocol_evidence",
            )?;
        } else {
            let app = bytes.slice(c.payload.clone())?;
            let s = session_presentation(&app, l)?;
            r.add(
                "iso_upper",
                s.json(),
                c.payload.clone(),
                "nested_protocol_evidence",
            )?;
        }
    } else if matches!(c.kind, 0xe0 | 0xd0) {
        r.u("destination_reference", u64::from(be16(b, 6)?), 6..8)?;
        r.u("source_reference", u64::from(be16(b, 8)?), 8..10)?;
        r.u("class_option", u64::from(b[10]), 10..11)?;
        let mut at = 11;
        let mut count = 0;
        while at < c.payload.start {
            count += 1;
            if count > l.elements {
                return Err(Error::limit("cotp_parameters"));
            }
            need(&b[..c.payload.start], at + 2, "cotp_parameter")?;
            let tag = b[at];
            let n = usize::from(b[at + 1]);
            need(&b[..c.payload.start], at + 2 + n, "cotp_parameter")?;
            r.add(
                format!("parameter[{count}]"),
                Json::object([
                    ("code", tag.into()),
                    ("value_hex", hex(&b[at + 2..at + 2 + n])),
                ]),
                at..at + 2 + n,
                "cotp_parameter",
            )?;
            at += 2 + n;
        }
        if b[10] >> 4 != 0 {
            r.note(Status::Unsupported, "nonzero_transport_class", 10, 11)?;
        }
    }
    Ok(r)
}
/// Reassembles only already-ordered, gap-free class-0 DT payloads, per explicit
/// transport generation/direction. A complete TSDU is not a complete association.
pub struct CotpSession {
    parts: Segments,
    ordinal: u64,
}
impl CotpSession {
    pub fn new(l: Limits) -> Result<Self> {
        Ok(Self {
            parts: Segments::new(l)?,
            ordinal: 0,
        })
    }
    pub fn push(&mut self, scope: &str, bytes: &EvidenceBytes, frame: u64) -> Result<Outcome> {
        let c = cotp(bytes.data())?;
        if c.kind != 0xf0 {
            return Err(bad("cotp_session", 0, "not ordinary DT"));
        }
        let out = self.parts.push(
            scope,
            Segment {
                ordinal: self.ordinal,
                first: self.ordinal == 0,
                final_segment: c.eot,
                bytes: bytes.slice(c.payload)?,
                frame,
            },
        )?;
        self.ordinal = self
            .ordinal
            .checked_add(1)
            .ok_or_else(|| Error::limit("cotp_ordinal"))?;
        if out.completed.is_some() {
            self.parts.cut(scope, "tsdu_complete");
            self.ordinal = 0;
        }
        Ok(out)
    }
    pub fn gap(&mut self, scope: &str) {
        self.parts.cut(scope, "transport_gap");
        self.ordinal = 0;
    }
}
pub fn session_presentation(bytes: &EvidenceBytes, l: &Limits) -> Result<Report> {
    let b = bytes.data();
    let mut r = Report::new("iso_session_presentation", bytes, l)?;
    let mut at = 0;
    // Common session DT: Give-Tokens SPDU followed by Data-Transfer SPDU.
    if b.starts_with(&[1, 0, 1, 0]) {
        r.add(
            "session_data_transfer",
            true.into(),
            0..4,
            "iso_session_dt_subset",
        )?;
        at = 4;
    }
    if at == b.len() {
        r.note(Status::Incomplete, "empty_presentation_payload", at, at)?;
        return Ok(r);
    }
    let tree = match ber::parse(&b[at..], l) {
        Ok(v) => v,
        Err(_) => {
            r.note(
                Status::Unsupported,
                "session_spdu_or_presentation_encoding_outside_subset",
                at,
                b.len(),
            )?;
            return Ok(r);
        }
    };
    r.add(
        "presentation_ber",
        Json::array(tree.iter().map(|x| x.json(&b[at..]))),
        at..b.len(),
        "ber_structure_not_association_truth",
    )?;
    // Locate explicit presentation PDV single-ASN1-type [0]. Context negotiation
    // is not inferred, so nested MMS remains a candidate with retained wrappers.
    fn visit(
        es: &[ber::Element],
        raw: &EvidenceBytes,
        base: usize,
        r: &mut Report,
        l: &Limits,
        depth: usize,
    ) -> Result<()> {
        if es.is_empty() {
            return Ok(());
        }
        if depth >= l.depth {
            return Err(Error::limit("presentation_depth"));
        }
        for e in es {
            if e.class == 1 && matches!(e.tag, 0..=3) {
                r.add(
                    "acse_candidate",
                    e.json(raw.data()),
                    base + e.header.start..base + e.end,
                    "ber_application_tag_requires_context",
                )?;
            }
            if e.is(2, 0) && e.constructed && e.children.len() == 1 {
                let child = &e.children[0];
                if child.class == 2 && (child.tag <= 13) {
                    let view = raw.slice(child.header.start..child.end)?;
                    if let Ok(m) = mms(&view, l) {
                        r.add(
                            "mms_candidate",
                            m.json(),
                            base + child.header.start..base + child.end,
                            "unverified_presentation_context",
                        )?;
                    }
                }
            }
            visit(&e.children, raw, base, r, l, depth + 1)?;
        }
        Ok(())
    }
    let payload = bytes.slice(at..bytes.len())?;
    visit(&tree, &payload, at, &mut r, l, 0)?;
    r.note(
        Status::Unsupported,
        "association_context_negotiation_not_established",
        0,
        b.len(),
    )?;
    Ok(r)
}
pub fn mms(bytes: &EvidenceBytes, l: &Limits) -> Result<Report> {
    let b = bytes.data();
    let tree = ber::parse(b, l)?;
    if tree.len() != 1 {
        return Err(bad("mms", 0, "one PDU required"));
    }
    let root = &tree[0];
    if root.class != 2 || root.tag > 13 {
        return Err(bad("mms", 0, "not a supported MMS PDU tag"));
    }
    let mut r = Report::new("mms", bytes, l)?;
    r.u("pdu_choice", u64::from(root.tag), root.header.clone())?;
    if matches!(root.tag, 0..=2) {
        let Some(invoke) = root.children.first() else {
            return Err(bad("mms", root.content.start, "missing invoke ID"));
        };
        if !invoke.is(0, 2) || invoke.constructed || invoke.content.len() > 5 {
            return Err(bad("mms_invoke", invoke.header.start, "invalid invoke ID"));
        }
        let n = invoke.integer(b)?;
        if !(0..=i64::from(u32::MAX)).contains(&n) {
            return Err(bad("mms_invoke", invoke.content.start, "invoke range"));
        }
        r.u("invoke_id", n as u64, invoke.content.clone())?;
        for service in root.children.iter().skip(1) {
            if service.class != 2 {
                r.note(
                    Status::Unsupported,
                    "unrecognized_mms_service_wrapper",
                    service.header.start,
                    service.end,
                )?;
                continue;
            }
            let name = match service.tag {
                0 => "status",
                1 => "get_name_list",
                2 => "identify",
                4 => "read",
                5 => "write",
                6 => "get_variable_access_attributes",
                11 => "define_named_variable_list",
                12 => "get_named_variable_list_attributes",
                13 => "delete_named_variable_list",
                _ => "unsupported_service",
            };
            r.add(
                "service",
                Json::object([
                    ("id", service.tag.into()),
                    ("name", name.into()),
                    ("tree", service.json(b)),
                ]),
                service.header.start..service.end,
                "mms_confirmed_service_choice",
            )?;
            if name == "unsupported_service" {
                r.note(
                    Status::Unsupported,
                    "mms_service_body_opaque",
                    service.content.start,
                    service.content.end,
                )?;
            }
        }
    } else {
        r.add(
            "pdu_structure",
            root.json(b),
            0..b.len(),
            "mms_ber_structure",
        )?;
        r.note(
            Status::Unsupported,
            "mms_pdu_semantics_outside_confirmed_subset",
            0,
            b.len(),
        )?;
    }
    Ok(r)
}
pub fn s7(bytes: &EvidenceBytes, l: &Limits) -> Result<Report> {
    let b = bytes.data();
    need(b, 10, "s7_header")?;
    if b[0] != 0x32 {
        return Err(bad("s7", 0, "protocol ID"));
    }
    let ros = b[1];
    let header = if matches!(ros, 2 | 3) { 12 } else { 10 };
    need(b, header, "s7_header")?;
    let plen = usize::from(be16(b, 6)?);
    let dlen = usize::from(be16(b, 8)?);
    let end = header + plen + dlen;
    if end != b.len() {
        return Err(bad("s7_length", 6, "lengths do not match TSDU"));
    }
    let mut r = Report::new("s7", bytes, l)?;
    r.u("rosctr", u64::from(ros), 1..2)?;
    r.u("pdu_reference", u64::from(be16(b, 4)?), 4..6)?;
    if header == 12 {
        r.u("error_class", u64::from(b[10]), 10..11)?;
        r.u("error_code", u64::from(b[11]), 11..12)?;
    }
    if plen == 0 {
        r.note(Status::Unsupported, "s7_empty_parameters", header, header)?;
        return Ok(r);
    }
    let f = b[header];
    r.u("function", u64::from(f), header..header + 1)?;
    if f == 0xf0 {
        need(&b[..header + plen], header + 8, "s7_setup")?;
        r.u(
            "max_amq_calling",
            u64::from(be16(b, header + 2)?),
            header + 2..header + 4,
        )?;
        r.u(
            "max_amq_called",
            u64::from(be16(b, header + 4)?),
            header + 4..header + 6,
        )?;
        r.u(
            "negotiated_pdu_length",
            u64::from(be16(b, header + 6)?),
            header + 6..header + 8,
        )?;
        return Ok(r);
    }
    if !matches!(f, 4 | 5) || plen < 2 {
        r.note(
            Status::Unsupported,
            "s7_service_not_read_write_var",
            header,
            end,
        )?;
        return Ok(r);
    }
    let count = usize::from(b[header + 1]);
    if count > l.elements {
        return Err(Error::limit("s7_items"));
    }
    let mut at = header + 2;
    if ros == 1 {
        for i in 0..count {
            need(&b[..header + plen], at + 12, "s7_varspec")?;
            if b[at] != 0x12 || b[at + 1] != 10 || b[at + 2] != 0x10 {
                r.note(
                    Status::Unsupported,
                    "s7_variable_specification_outside_s7any",
                    at,
                    header + plen,
                )?;
                return Ok(r);
            }
            r.add(
                format!("item[{i}].address"),
                Json::object([
                    ("transport_size", b[at + 3].into()),
                    ("elements", be16(b, at + 4)?.into()),
                    ("db_number", be16(b, at + 6)?.into()),
                    ("area", b[at + 8].into()),
                    (
                        "bit_address",
                        uint(&b[at + 9..at + 12], false)?.to_string().into(),
                    ),
                ]),
                at..at + 12,
                "s7any_wire_address_not_device_map",
            )?;
            at += 12;
        }
        if at != header + plen {
            return Err(bad("s7_parameters", at, "unconsumed parameter bytes"));
        }
    }
    at = header + plen;
    if (ros == 3 && f == 4) || (ros == 1 && f == 5) {
        for i in 0..count {
            need(b, at + 4, "s7_data")?;
            let code = b[at];
            let ty = b[at + 1];
            let len = usize::from(be16(b, at + 2)?);
            let size = match ty {
                3..=5 => len.div_ceil(8),
                9 => len,
                0 if len == 0 => 0,
                _ => {
                    r.note(Status::Unsupported, "s7_data_transport_size", at, end)?;
                    return Ok(r);
                }
            };
            need(b, at + 4 + size, "s7_data")?;
            r.add(
                format!("item[{i}].data"),
                Json::object([
                    ("return_code", code.into()),
                    ("transport_size", ty.into()),
                    ("declared_length", len.into()),
                    ("raw", hex(&b[at + 4..at + 4 + size])),
                ]),
                at..at + 4 + size,
                "s7_data_unit",
            )?;
            at += 4 + size;
            if size % 2 == 1 && i + 1 < count {
                need(b, at + 1, "s7_fill")?;
                if b[at] != 0 {
                    r.note(Status::Ambiguous, "nonzero_s7_alignment_byte", at, at + 1)?;
                }
                at += 1;
            }
        }
    } else if ros == 3 && f == 5 {
        need(b, at + count, "s7_write_results")?;
        for i in 0..count {
            r.u(
                format!("item[{i}].return_code"),
                u64::from(b[at + i]),
                at + i..at + i + 1,
            )?;
        }
        at += count;
    }
    if at < end {
        r.note(Status::Unsupported, "s7_uninterpreted_data_tail", at, end)?;
    }
    Ok(r)
}
