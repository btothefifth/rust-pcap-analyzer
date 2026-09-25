//! Additional DNP3 value/control/file observations, not endpoint emulation.
//! Object bytes are scoped to ONE application fragment. Application fragments
//! keep their own object headers; their raw object regions are never concatenated.
use super::model::*;
use pcap_evidence::{json::Json, provenance::EvidenceBytes, Error, Result};

#[derive(Clone, Copy)]
struct Shape {
    width: usize,
    flags: bool,
    signed: bool,
    float: bool,
    time: usize,
    packed: usize,
    status_last: bool,
}
fn shape(g: u8, v: u8) -> Option<Shape> {
    let mut s = Shape {
        width: 0,
        flags: false,
        signed: false,
        float: false,
        time: 0,
        packed: 0,
        status_last: false,
    };
    match (g, v) {
        (1 | 10 | 80, 1) => s.packed = 1,
        (3, 1) => s.packed = 2,
        (1 | 3 | 10, 2) | (2 | 4 | 11 | 13, 1) => s.flags = true,
        (2 | 4 | 11 | 13, 2) => {
            s.flags = true;
            s.time = 6
        }
        (2 | 4, 3) => {
            s.flags = true;
            s.time = 2
        }
        (20, 1 | 2) => {
            s.flags = true;
            s.width = if v == 1 { 4 } else { 2 }
        }
        (20, 5 | 6) => s.width = if v == 5 { 4 } else { 2 },
        (21, 1 | 2 | 5 | 6 | 9 | 10) => {
            s.flags = v < 9;
            s.width = if v % 2 == 1 { 4 } else { 2 };
            s.time = if v == 5 || v == 6 { 6 } else { 0 }
        }
        (22 | 23, 1 | 2 | 5 | 6) => {
            s.flags = true;
            s.width = if v % 2 == 1 { 4 } else { 2 };
            s.time = if v >= 5 { 6 } else { 0 }
        }
        (30, 1..=6) => {
            s.flags = ![3, 4].contains(&v);
            s.width = match v {
                1 | 3 | 5 => 4,
                2 | 4 => 2,
                _ => 8,
            };
            s.signed = v < 5;
            s.float = v >= 5
        }
        (31, 1..=8) => {
            s.flags = ![5, 6].contains(&v);
            s.width = if v == 8 {
                8
            } else if [2, 4, 6].contains(&v) {
                2
            } else {
                4
            };
            s.signed = v < 7;
            s.float = v >= 7;
            s.time = if v == 3 || v == 4 { 6 } else { 0 }
        }
        (32 | 33 | 42 | 43, 1..=8) => {
            s.flags = true;
            s.width = match v {
                2 | 4 => 2,
                6 | 8 => 8,
                _ => 4,
            };
            s.signed = v <= 4;
            s.float = v >= 5;
            s.time = if [3, 4, 7, 8].contains(&v) { 6 } else { 0 }
        }
        (40, 1..=4) => {
            s.flags = true;
            s.width = match v {
                1 | 3 => 4,
                2 => 2,
                _ => 8,
            };
            s.signed = v <= 2;
            s.float = v >= 3
        }
        (41, 1..=4) => {
            s.width = match v {
                1 | 3 => 4,
                2 => 2,
                _ => 8,
            };
            s.signed = v <= 2;
            s.float = v >= 3;
            s.status_last = true
        }
        (50, 1 | 3) | (51, 1 | 2) => s.time = 6,
        (52, 1 | 2) => s.width = 2,
        (102, 1) => s.width = 1,
        (110 | 111, 1..=255) => s.width = usize::from(v),
        _ => return None,
    }
    Some(s)
}

pub fn objects(bytes: &EvidenceBytes, function: u8, l: &Limits) -> Result<Report> {
    let b = bytes.data();
    let mut r = Report::new("dnp3.objects", bytes, l)?;
    r.add(
        "application_function",
        function.into(),
        0..0,
        "caller_application_header",
    )?;
    if !matches!(function,1..=6|0x81|0x82|25..=30) {
        r.note(
            Status::Unsupported,
            "application_function_not_in_depth_subset",
            0,
            b.len(),
        )?;
        return Ok(r);
    }
    let mut p = 0;
    let mut total = 0usize;
    let mut header_index = 0;
    while p < b.len() {
        let start = p;
        if b.len() - p < 3 {
            r.note(Status::Incomplete, "object_header_truncated", p, b.len())?;
            break;
        }
        let (g, v, q) = (b[p], b[p + 1], b[p + 2]);
        p += 3;
        header_index += 1;
        r.add(
            format!("header[{header_index}]"),
            Json::object([
                ("group", g.into()),
                ("variation", v.into()),
                ("qualifier", q.into()),
            ]),
            start..p,
            "dnp3_object_header",
        )?;
        if q == 0x5b {
            if g != 70 {
                r.note(
                    Status::Unsupported,
                    "free_format_group_not_supported",
                    start,
                    b.len(),
                )?;
                break;
            }
            need(b, p + 1, "dnp3_freeformat_count")?;
            let count = usize::from(b[p]);
            p += 1;
            if count > l.elements {
                return Err(Error::limit("dnp3_objects"));
            }
            for i in 0..count {
                let at = p;
                let n = usize::from(le16(b, p)?);
                p += 2;
                need(b, p + n, "dnp3_freeformat_object")?;
                file(&mut r, g, v, &b[p..p + n], p, i, l)?;
                p += n;
                r.charge(p - at)?;
            }
            continue;
        }
        let prefix_code = q >> 4;
        let prefix = match prefix_code {
            0 => 0,
            1 => 1,
            2 => 2,
            3 => 4,
            _ => {
                r.note(
                    Status::Unsupported,
                    "object_prefix_format_unknown",
                    start,
                    b.len(),
                )?;
                break;
            }
        };
        let range = q & 15;
        let mut first = 0u64;
        let count = match range {
            0..=2 => {
                if prefix != 0 {
                    r.note(
                        Status::Unsupported,
                        "index_prefix_with_start_stop",
                        start,
                        b.len(),
                    )?;
                    break;
                }
                let n = 1usize << range;
                need(b, p + 2 * n, "dnp3_start_stop")?;
                first = uint(&b[p..p + n], true)?;
                let stop = uint(&b[p + n..p + 2 * n], true)?;
                if stop < first {
                    return Err(bad("dnp3_range", p, "inverted start/stop"));
                }
                p += 2 * n;
                usize::try_from(stop - first + 1).map_err(|_| Error::limit("dnp3_count"))?
            }
            6 => {
                if function == 1 && prefix == 0 {
                    r.add(
                        format!("header[{header_index}].all_objects"),
                        true.into(),
                        start..p,
                        "read_selector_not_value_count",
                    )?;
                    continue;
                }
                r.note(
                    Status::Unsupported,
                    "all_objects_without_value_count",
                    start,
                    b.len(),
                )?;
                break;
            }
            7..=9 => {
                let n = 1usize << (range - 7);
                need(b, p + n, "dnp3_count")?;
                let c = usize::try_from(uint(&b[p..p + n], true)?)
                    .map_err(|_| Error::limit("dnp3_count"))?;
                p += n;
                c
            }
            _ => {
                r.note(
                    Status::Unsupported,
                    "range_qualifier_unknown",
                    start,
                    b.len(),
                )?;
                break;
            }
        };
        total = total
            .checked_add(count)
            .ok_or_else(|| Error::limit("dnp3_objects"))?;
        if total > l.elements {
            return Err(Error::limit("dnp3_objects"));
        }
        if function == 1 {
            if prefix != 0 {
                need(b, p + count * prefix, "dnp3_read_indices")?;
                for i in 0..count {
                    r.u(
                        format!("read_index[{i}]"),
                        uint(&b[p..p + prefix], true)?,
                        p..p + prefix,
                    )?;
                    p += prefix;
                }
            }
            continue;
        }
        if (3..=6).contains(&function) && !matches!(g, 12 | 41) {
            r.note(
                Status::Unsupported,
                "control_function_object_mismatch",
                start,
                b.len(),
            )?;
            break;
        }
        if g == 120 || g == 121 || g == 122 {
            r.note(
                Status::Unsupported,
                "secure_authentication_requires_reviewed_security_context",
                start,
                b.len(),
            )?;
            break;
        }
        if g == 12 && v == 1 {
            for i in 0..count {
                let mut index = first + i as u64;
                if prefix > 0 {
                    need(b, p + prefix, "crob_index")?;
                    index = uint(&b[p..p + prefix], true)?;
                    p += prefix;
                }
                need(b, p + 11, "crob")?;
                r.add(
                    format!("control[{i}]"),
                    Json::object([
                        ("point_index", index.to_string().into()),
                        ("control_code", b[p].into()),
                        ("operation_type", (b[p] & 15).into()),
                        ("queue", (b[p] & 16 != 0).into()),
                        ("clear", (b[p] & 32 != 0).into()),
                        ("trip_close", (b[p] >> 6).into()),
                        ("count", b[p + 1].into()),
                        ("on_time_ms", le32(b, p + 2)?.to_string().into()),
                        ("off_time_ms", le32(b, p + 6)?.to_string().into()),
                        ("status", b[p + 10].into()),
                        ("physical_operation_verified", false.into()),
                    ]),
                    p..p + 11,
                    "control_relay_output_block",
                )?;
                p += 11;
            }
            continue;
        }
        let Some(s) = shape(g, v) else {
            r.note(
                Status::Unsupported,
                "unknown_object_width_no_resynchronization",
                start,
                b.len(),
            )?;
            break;
        };
        if s.packed > 0 {
            if prefix != 0 || range > 2 {
                r.note(
                    Status::Unsupported,
                    "packed_requires_start_stop",
                    start,
                    b.len(),
                )?;
                break;
            }
            let n = (count * s.packed).div_ceil(8);
            need(b, p + n, "packed_points")?;
            for i in 0..count {
                let bit = i * s.packed;
                let at = p + bit / 8;
                let mask = (1u8 << s.packed) - 1;
                r.add(
                    format!("point[{i}]"),
                    Json::object([
                        ("index", (first + i as u64).to_string().into()),
                        ("value", ((b[at] >> (bit % 8)) & mask).into()),
                        ("bit", (bit % 8).into()),
                        ("width", s.packed.into()),
                    ]),
                    at..at + 1,
                    "packed_point",
                )?;
            }
            p += n;
            continue;
        }
        for i in 0..count {
            let mut index = first + i as u64;
            if prefix > 0 {
                need(b, p + prefix, "dnp3_index")?;
                index = uint(&b[p..p + prefix], true)?;
                p += prefix;
            }
            let size = s.width + usize::from(s.flags) + s.time + usize::from(s.status_last);
            need(b, p + size, "dnp3_value")?;
            let mut at = p;
            let mut fields = vec![
                ("point_index", index.to_string().into()),
                ("group", g.into()),
                ("variation", v.into()),
            ];
            if s.flags {
                fields.push(("flags_or_command_status", b[at].into()));
                at += 1;
            }
            if g == 110 || g == 111 {
                fields.push((
                    "octet_string_sha256",
                    pcap_evidence::sha256::hex(&pcap_evidence::sha256::digest(
                        &b[at..at + s.width],
                    ))
                    .into(),
                ));
            } else if s.width > 0 {
                let value = if s.float {
                    Json::object([
                        ("kind", "ieee754_bits".into()),
                        ("bits", hex(&b[at..at + s.width])),
                        ("byte_order", "little".into()),
                    ])
                } else if s.signed {
                    signed(&b[at..at + s.width], true)?.to_string().into()
                } else {
                    uint(&b[at..at + s.width], true)?.to_string().into()
                };
                fields.push(("value", value));
            }
            at += s.width;
            if s.time > 0 {
                fields.push((
                    if s.time == 6 {
                        "raw_time_ms48"
                    } else {
                        "relative_time_ms_unresolved"
                    },
                    uint(&b[at..at + s.time], true)?.to_string().into(),
                ));
                at += s.time;
            }
            if s.status_last {
                fields.push(("command_status", b[at].into()));
            }
            r.add(
                format!("point[{i}]"),
                Json::Object(fields),
                p..p + size,
                "object_group_variation_layout",
            )?;
            p += size;
        }
    }
    Ok(r)
}
fn file(r: &mut Report, _g: u8, v: u8, b: &[u8], base: usize, i: usize, _l: &Limits) -> Result<()> {
    let mut fields = vec![("variation", v.into())];
    match v {
        2 => {
            r.note(
                Status::Unsupported,
                "file_authentication_credentials_not_extracted",
                base,
                base + b.len(),
            )?;
            return Ok(());
        }
        3 => {
            need(b, 26, "file_command")?;
            let at = usize::from(le16(b, 0)?);
            let n = usize::from(le16(b, 2)?);
            let end = at
                .checked_add(n)
                .ok_or_else(|| bad("file_name_range", base, "filename range overflow"))?;
            if at != 26 || end != b.len() {
                return Err(bad("file_name_range", base, "invalid filename range"));
            }
            fields.extend([
                ("file_name_offset", at.to_string().into()),
                ("file_name_length", n.to_string().into()),
                (
                    "creation_time_ms48",
                    uint(&b[4..10], true)?.to_string().into(),
                ),
                ("permissions", le16(b, 10)?.into()),
                ("authentication_key_present_not_extracted", true.into()),
                ("file_size", le32(b, 16)?.to_string().into()),
                ("mode", le16(b, 20)?.into()),
                ("maximum_block", le16(b, 22)?.into()),
                ("request_id", le16(b, 24)?.into()),
                (
                    "filename_sha256",
                    pcap_evidence::sha256::hex(&pcap_evidence::sha256::digest(&b[at..end])).into(),
                ),
            ]);
        }
        4 => {
            need(b, 13, "file_status")?;
            fields.extend([
                ("file_handle", le32(b, 0)?.to_string().into()),
                ("file_size", le32(b, 4)?.to_string().into()),
                ("maximum_block", le16(b, 8)?.into()),
                ("request_id", le16(b, 10)?.into()),
                ("status", b[12].into()),
            ]);
            if b.len() > 13 {
                fields.push((
                    "status_text_sha256",
                    pcap_evidence::sha256::hex(&pcap_evidence::sha256::digest(&b[13..])).into(),
                ));
                fields.push(("status_text_bytes", (b.len() - 13).to_string().into()));
            }
        }
        5 | 6 => {
            need(b, if v == 5 { 8 } else { 9 }, "file_transport")?;
            fields.extend([
                ("file_handle", le32(b, 0)?.to_string().into()),
                ("block_number", le32(b, 4)?.to_string().into()),
            ]);
            if v == 5 {
                fields.push((
                    "content_sha256",
                    pcap_evidence::sha256::hex(&pcap_evidence::sha256::digest(&b[8..])).into(),
                ));
                fields.push(("content_bytes", (b.len() - 8).to_string().into()));
            } else {
                fields.push(("status", b[8].into()));
                if b.len() > 9 {
                    fields.push((
                        "status_text_sha256",
                        pcap_evidence::sha256::hex(&pcap_evidence::sha256::digest(&b[9..])).into(),
                    ));
                    fields.push(("status_text_bytes", (b.len() - 9).to_string().into()));
                }
            }
        }
        7 => {
            need(b, 20, "file_descriptor")?;
            let at = usize::from(le16(b, 0)?);
            let n = usize::from(le16(b, 2)?);
            let end = at
                .checked_add(n)
                .ok_or_else(|| bad("file_name_range", base, "filename range overflow"))?;
            if at != 20 || end != b.len() {
                return Err(bad("file_name_range", base, "invalid filename range"));
            }
            fields.extend([
                ("file_name_offset", at.to_string().into()),
                ("file_name_length", n.to_string().into()),
                ("file_type", le16(b, 4)?.into()),
                ("file_size", le32(b, 6)?.to_string().into()),
                (
                    "creation_time_ms48",
                    uint(&b[10..16], true)?.to_string().into(),
                ),
                ("permissions", le16(b, 16)?.into()),
                ("request_id", le16(b, 18)?.into()),
                (
                    "filename_sha256",
                    pcap_evidence::sha256::hex(&pcap_evidence::sha256::digest(&b[at..end])).into(),
                ),
            ]);
        }
        8 => {
            fields.extend([
                ("file_specification_bytes", b.len().to_string().into()),
                (
                    "file_specification_sha256",
                    pcap_evidence::sha256::hex(&pcap_evidence::sha256::digest(b)).into(),
                ),
            ]);
        }
        _ => {
            r.note(
                Status::Unsupported,
                "file_object_variation_opaque",
                base,
                base + b.len(),
            )?;
            return Ok(());
        }
    }
    r.add(
        format!("file_object[{i}]"),
        Json::Object(fields),
        base..base + b.len(),
        "file_object_metadata_no_file_path_execution",
    )
}

/// Application-message sequence tracking without splicing object-header regions.
/// The caller feeds CRC-validated, transport-reassembled application fragments.
pub struct ApplicationSequence {
    sequence: Option<u8>,
    function: Option<u8>,
    fragments: usize,
    limit: usize,
    tainted: bool,
}
impl ApplicationSequence {
    pub fn new(limit: usize) -> Result<Self> {
        if limit == 0 {
            return Err(Error::limit("dnp_fragment_count"));
        }
        Ok(Self {
            sequence: None,
            function: None,
            fragments: 0,
            limit,
            tainted: false,
        })
    }
    pub fn observe(
        &mut self,
        control: u8,
        function: u8,
        fragment: &EvidenceBytes,
        l: &Limits,
    ) -> Result<Report> {
        let first = control & 128 != 0;
        let final_fragment = control & 64 != 0;
        let seq = control & 15;
        let mut report = if first && final_fragment {
            objects(fragment, function, l)?
        } else {
            let mut incomplete = Report::new("dnp3.objects", fragment, l)?;
            incomplete.note(
                Status::Incomplete,
                "application_fragment_needs_verified_message_assembly",
                0,
                fragment.len(),
            )?;
            incomplete
        };
        if first {
            if self.sequence.is_some() {
                report.note(
                    Status::Incomplete,
                    "new_first_interrupts_application_message",
                    0,
                    fragment.len(),
                )?;
            }
            self.sequence = Some(seq);
            self.function = Some(function);
            self.fragments = 0;
            self.tainted = false;
        } else if self.sequence.is_none() {
            self.tainted = true;
            report.note(
                Status::Incomplete,
                "missing_first_application_fragment",
                0,
                fragment.len(),
            )?;
        } else if self.sequence != Some(seq) || self.function != Some(function) {
            self.tainted = true;
            report.note(
                Status::Ambiguous,
                "application_sequence_or_function_conflict",
                0,
                fragment.len(),
            )?;
        }
        self.fragments += 1;
        if self.fragments > self.limit {
            return Err(Error::limit("dnp_fragment_count"));
        }
        self.sequence = Some((seq + 1) & 15);
        self.function = Some(function);
        report.add(
            "application_sequence",
            Json::object([
                ("fragment_count", self.fragments.to_string().into()),
                ("final", final_fragment.into()),
                ("sequence_consistent", (!self.tainted).into()),
                ("object_regions_spliced", false.into()),
            ]),
            0..0,
            "observed_application_control_sequence",
        )?;
        if final_fragment {
            self.sequence = None;
            self.function = None;
            self.fragments = 0;
        }
        Ok(report)
    }
    pub fn gap(&mut self) {
        self.sequence = None;
        self.function = None;
        self.fragments = 0;
        self.tainted = true;
    }
}
