//! BACnet/IP NPDU/APDU, service tags and bounded segmentation observations.
//! No serial acquisition, fabricated object catalog or unobserved property values.
use super::{
    model::*,
    reassembly::{Outcome, Segment, Segments},
};
use pcap_evidence::{json::Json, provenance::EvidenceBytes, Error, Result};
use std::ops::Range;
#[derive(Clone, Debug)]
pub struct Tag {
    pub number: u32,
    pub context: bool,
    pub range: Range<usize>,
    pub value: Range<usize>,
    pub children: Vec<Tag>,
    pub boolean: Option<bool>,
}
impl Tag {
    pub fn json(&self, b: &[u8]) -> Json {
        let raw = &b[self.value.clone()];
        let value = if !self.children.is_empty() {
            Json::array(self.children.iter().map(|c| c.json(b)))
        } else if let Some(v) = self.boolean {
            v.into()
        } else if self.context {
            hex(raw)
        } else {
            match self.number {
                0 => Json::Null,
                2 | 9 if raw.len() <= 8 => {
                    uint(raw, false).map_or(Json::Null, |n| n.to_string().into())
                }
                3 if !raw.is_empty() && raw.len() <= 8 => {
                    signed(raw, false).map_or(Json::Null, |n| n.to_string().into())
                }
                12 if raw.len() == 4 => {
                    let n = u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]);
                    Json::object([
                        ("object_type", (n >> 22).into()),
                        ("instance", (n & 0x3fffff).into()),
                    ])
                }
                _ => hex(raw),
            }
        };
        Json::object([
            ("tag", self.number.into()),
            ("context", self.context.into()),
            ("value", value),
            ("start", self.range.start.to_string().into()),
            ("end", self.range.end.to_string().into()),
        ])
    }
}
pub fn tags(b: &[u8], start: usize, l: &Limits) -> Result<Vec<Tag>> {
    let (mut at, mut count) = (start, 0);
    let out = tag_list(b, &mut at, None, 0, &mut count, l)?;
    if at != b.len() {
        return Err(bad("bacnet_tags", at, "trailing tags"));
    }
    Ok(out)
}
fn tag_list(
    b: &[u8],
    at: &mut usize,
    closing: Option<u32>,
    depth: usize,
    count: &mut usize,
    l: &Limits,
) -> Result<Vec<Tag>> {
    if depth >= l.depth {
        return Err(Error::limit("bacnet_tag_depth"));
    }
    let mut out = Vec::new();
    while *at < b.len() {
        if *count >= l.elements {
            return Err(Error::limit("bacnet_tags"));
        }
        *count += 1;
        let begin = *at;
        let ctl = b[*at];
        *at += 1;
        let context = ctl & 8 != 0;
        let mut number = u32::from(ctl >> 4);
        let lvt = ctl & 7;
        if number == 15 {
            need(b, *at + 1, "bacnet_extended_tag")?;
            number = u32::from(b[*at]);
            *at += 1;
            if number == 255 {
                return Err(bad("bacnet_tag", begin, "reserved extended tag"));
            }
        }
        if context && lvt == 7 {
            if closing != Some(number) {
                return Err(bad("bacnet_closing_tag", begin, "mismatched closing tag"));
            }
            return Ok(out);
        }
        if context && lvt == 6 {
            let value_start = *at;
            let children = tag_list(b, at, Some(number), depth + 1, count, l)?;
            out.push(Tag {
                number,
                context,
                range: begin..*at,
                value: value_start..value_start,
                children,
                boolean: None,
            });
            continue;
        }
        if !context && lvt >= 6 {
            return Err(bad("bacnet_tag", begin, "application opening/closing form"));
        }
        let boolean = if !context && number == 1 {
            if lvt > 1 {
                return Err(bad("bacnet_bool", begin, "boolean LVT must be zero or one"));
            }
            Some(lvt != 0)
        } else {
            None
        };
        let length = if boolean.is_some() {
            0
        } else if lvt < 5 {
            usize::from(lvt)
        } else {
            need(b, *at + 1, "bacnet_length")?;
            let n = b[*at];
            *at += 1;
            match n {
                0..=253 => usize::from(n),
                254 => {
                    let n = usize::from(be16(b, *at)?);
                    *at += 2;
                    n
                }
                255 => {
                    let n = usize::try_from(be32(b, *at)?)
                        .map_err(|_| Error::limit("bacnet_length"))?;
                    *at += 4;
                    n
                }
            }
        };
        let end = at
            .checked_add(length)
            .ok_or_else(|| Error::limit("bacnet_length"))?;
        need(b, end, "bacnet_value")?;
        if !context {
            let valid = match number {
                0 => length == 0,
                1 => true,
                2 | 3 | 9 => (1..=4).contains(&length),
                4 => length == 4,
                5 => length == 8,
                8 => length >= 1,
                10..=12 => length == 4,
                _ => true,
            };
            if !valid {
                return Err(bad(
                    "bacnet_application_length",
                    begin,
                    "type length mismatch",
                ));
            }
        }
        out.push(Tag {
            number,
            context,
            range: begin..end,
            value: *at..end,
            children: Vec::new(),
            boolean,
        });
        *at = end;
    }
    if closing.is_some() {
        return Err(bad("bacnet_tags", *at, "missing closing tag"));
    }
    Ok(out)
}
#[derive(Clone, Debug)]
pub struct Apdu {
    pub at: usize,
    pub kind: u8,
    pub invoke: Option<u8>,
    pub service: Option<u8>,
    pub sequence: Option<u8>,
    pub window: Option<u8>,
    pub more: bool,
    pub payload: Range<usize>,
}
pub fn apdu(b: &[u8]) -> Result<Apdu> {
    need(b, 4, "bvlc")?;
    if b[0] != 0x81 {
        return Err(bad("bvlc", 0, "not BACnet IPv4"));
    }
    let end = usize::from(be16(b, 2)?);
    if end != b.len() {
        return Err(bad("bvlc", 2, "datagram length mismatch"));
    }
    let mut at = match b[1] {
        4 => 10,
        9..=11 => 4,
        _ => return Err(bad("bvlc", 1, "management BVLC outside APDU path")),
    };
    need(b, at + 2, "npdu")?;
    if b[at] != 1 {
        return Err(bad("npdu", at, "unsupported version"));
    }
    let control = b[at + 1];
    if control & 0x50 != 0 {
        return Err(bad("npdu", at + 1, "reserved control bits"));
    }
    at += 2;
    if control & 32 != 0 {
        need(b, at + 3, "npdu_destination")?;
        let len = usize::from(b[at + 2]);
        need(b, at + 3 + len, "npdu_destination")?;
        at += 3 + len;
    }
    if control & 8 != 0 {
        need(b, at + 3, "npdu_source")?;
        let len = usize::from(b[at + 2]);
        if len == 0 {
            return Err(bad("npdu_source", at, "empty source address"));
        }
        need(b, at + 3 + len, "npdu_source")?;
        at += 3 + len;
    }
    if control & 32 != 0 {
        need(b, at + 1, "hop_count")?;
        at += 1;
    }
    if control & 128 != 0 {
        return Err(bad("npdu", at, "network management not APDU"));
    }
    need(b, at + 1, "apdu")?;
    let kind = b[at] >> 4;
    let segmented = b[at] & 8 != 0;
    let more = b[at] & 4 != 0;
    let (header, invoke, service, sequence, window) = match kind {
        0 => {
            let n = if segmented { 6 } else { 4 };
            need(b, at + n, "confirmed_request")?;
            (
                n,
                Some(b[at + 2]),
                Some(b[at + n - 1]),
                if segmented { Some(b[at + 3]) } else { None },
                if segmented { Some(b[at + 4]) } else { None },
            )
        }
        1 => {
            need(b, at + 2, "unconfirmed_request")?;
            (2, None, Some(b[at + 1]), None, None)
        }
        2 | 5 => {
            need(b, at + 3, "ack_or_error")?;
            (3, Some(b[at + 1]), Some(b[at + 2]), None, None)
        }
        3 => {
            let n = if segmented { 5 } else { 3 };
            need(b, at + n, "complex_ack")?;
            (
                n,
                Some(b[at + 1]),
                Some(b[at + n - 1]),
                if segmented { Some(b[at + 2]) } else { None },
                if segmented { Some(b[at + 3]) } else { None },
            )
        }
        4 => {
            need(b, at + 4, "segment_ack")?;
            (4, Some(b[at + 1]), None, Some(b[at + 2]), Some(b[at + 3]))
        }
        6 | 7 => {
            need(b, at + 3, "reject_abort")?;
            (3, Some(b[at + 1]), None, None, None)
        }
        _ => return Err(bad("apdu", at, "unknown PDU type")),
    };
    if window.is_some_and(|w| w == 0 || w > 127) {
        return Err(bad("bacnet_segment_window", at, "window outside 1..127"));
    }
    Ok(Apdu {
        at,
        kind,
        invoke,
        service,
        sequence,
        window,
        more,
        payload: at + header..end,
    })
}
pub fn decode(bytes: &EvidenceBytes, l: &Limits) -> Result<Report> {
    let b = bytes.data();
    let a = apdu(b)?;
    let mut r = Report::new("bacnet_ip", bytes, l)?;
    r.u("apdu_type", u64::from(a.kind), a.at..a.at + 1)?;
    if let Some(id) = a.invoke {
        r.u(
            "invoke_id",
            u64::from(id),
            if a.kind == 0 {
                a.at + 2..a.at + 3
            } else {
                a.at + 1..a.at + 2
            },
        )?;
    }
    if let Some(service) = a.service {
        r.u(
            "service_choice",
            u64::from(service),
            a.payload.start - 1..a.payload.start,
        )?;
    }
    if a.sequence.is_some() {
        r.add(
            "segment",
            Json::object([
                ("sequence", a.sequence.map_or(Json::Null, Json::from)),
                ("window", a.window.map_or(Json::Null, Json::from)),
                ("more", a.more.into()),
            ]),
            a.at..a.payload.start,
            "apdu_segmentation_header",
        )?;
        if a.kind != 4 {
            r.note(
                Status::Incomplete,
                "segmented_service_requires_scoped_reassembly",
                a.payload.start,
                a.payload.end,
            )?;
        }
        return Ok(r);
    }
    if a.kind == 6 || a.kind == 7 {
        r.u(
            "reject_or_abort_reason",
            u64::from(b[a.at + 2]),
            a.at + 2..a.at + 3,
        )?;
        return Ok(r);
    }
    if a.kind == 2 {
        return Ok(r);
    }
    let tree = tags(b, a.payload.start, l)?;
    r.add(
        "service_tags",
        Json::array(tree.iter().map(|t| t.json(b))),
        a.payload.clone(),
        "bacnet_service_tag_structure",
    )?;
    let service = a.service.unwrap_or(255);
    if a.kind == 1 && service == 8 {
        if !tree.is_empty() {
            if tree.len() != 2
                || !tree[0].context
                || tree[0].number != 0
                || !tree[1].context
                || tree[1].number != 1
            {
                return Err(bad("who_is", a.payload.start, "invalid limits"));
            }
            let low = uint(&b[tree[0].value.clone()], false)?;
            let high = uint(&b[tree[1].value.clone()], false)?;
            if low > high || high > 0x3fffff {
                return Err(bad("who_is", a.payload.start, "invalid device range"));
            }
            r.u("device_low", low, tree[0].value.clone())?;
            r.u("device_high", high, tree[1].value.clone())?;
        }
    } else if a.kind == 1 && service == 0 {
        if tree.len() != 4
            || tree.iter().any(|t| t.context)
            || tree.iter().map(|t| t.number).collect::<Vec<_>>() != [12, 2, 9, 2]
        {
            return Err(bad("i_am", a.payload.start, "invalid I-Am fields"));
        }
        let id = uint(&b[tree[0].value.clone()], false)?;
        r.u("device_instance", id & 0x3fffff, tree[0].value.clone())?;
        r.u(
            "max_apdu",
            uint(&b[tree[1].value.clone()], false)?,
            tree[1].value.clone(),
        )?;
        r.u(
            "segmentation_supported",
            uint(&b[tree[2].value.clone()], false)?,
            tree[2].value.clone(),
        )?;
        r.u(
            "vendor_id",
            uint(&b[tree[3].value.clone()], false)?,
            tree[3].value.clone(),
        )?;
        if id >> 22 != 8 {
            return Err(bad("i_am", tree[0].value.start, "object is not a device"));
        }
    } else if matches!(service, 12 | 15) && matches!(a.kind, 0 | 3) {
        if tree.len() < 2
            || !tree[0].context
            || tree[0].number != 0
            || tree[0].value.len() != 4
            || !tree[1].context
            || tree[1].number != 1
        {
            return Err(bad(
                "property_service",
                a.payload.start,
                "missing object/property",
            ));
        }
        let id = uint(&b[tree[0].value.clone()], false)?;
        r.u("object_type", id >> 22, tree[0].value.clone())?;
        r.u("object_instance", id & 0x3fffff, tree[0].value.clone())?;
        r.u(
            "property_id",
            uint(&b[tree[1].value.clone()], false)?,
            tree[1].value.clone(),
        )?;
        for t in tree.iter().skip(2) {
            if t.context && t.number == 2 && !t.value.is_empty() {
                r.u(
                    "array_index",
                    uint(&b[t.value.clone()], false)?,
                    t.value.clone(),
                )?;
            } else if t.context && t.number == 4 && !t.value.is_empty() {
                let p = uint(&b[t.value.clone()], false)?;
                if !(1..=16).contains(&p) {
                    return Err(bad(
                        "write_priority",
                        t.value.start,
                        "priority outside 1..16",
                    ));
                }
                r.u("priority", p, t.value.clone())?;
            }
        }
    } else if matches!(service, 14 | 16 | 5 | 1 | 2) {
        r.note(
            Status::Unsupported,
            "service_tags_decoded_schema_not_fully_implemented",
            a.payload.start,
            a.payload.end,
        )?;
    } else {
        r.note(
            Status::Unsupported,
            "service_semantics_opaque",
            a.payload.start,
            a.payload.end,
        )?;
    }
    Ok(r)
}
/// Bound to an explicit transport generation/direction. Does not join invoke IDs
/// from unrelated clients, network numbers, or re-used transactions.
pub struct Session {
    segments: Segments,
}
impl Session {
    pub fn new(l: Limits) -> Result<Self> {
        Ok(Self {
            segments: Segments::new(l)?,
        })
    }
    pub fn push(&mut self, scope: &str, bytes: &EvidenceBytes, frame: u64) -> Result<Outcome> {
        let a = apdu(bytes.data())?;
        let seq = a
            .sequence
            .ok_or_else(|| bad("bacnet_segment", a.at, "unsegmented APDU"))?;
        if !matches!(a.kind, 0 | 3) {
            return Err(bad("bacnet_segment", a.at, "not segmented service data"));
        }
        let key = format!(
            "{scope}:{}:{}:{}",
            a.kind,
            a.invoke.unwrap_or(255),
            a.service.unwrap_or(255)
        );
        self.segments.push(
            &key,
            Segment {
                ordinal: u64::from(seq),
                first: seq == 0,
                final_segment: !a.more,
                bytes: bytes.slice(a.payload)?,
                frame,
            },
        )
    }
    pub fn cut(&mut self, scope: &str, kind: u8, invoke: u8, service: u8) {
        self.segments.cut(
            &format!("{scope}:{kind}:{invoke}:{service}"),
            "explicit_bacnet_scope_boundary",
        );
    }
}
