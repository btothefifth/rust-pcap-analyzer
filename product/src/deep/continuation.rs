//! Stateful application framing across arbitrary source/query page boundaries.
//! A real gap/conflict resets state; a page boundary does not. Use after final
//! history adjudication so a late TCP conflict cannot invalidate earlier output.
use super::{model::*, reassembly::StreamBuffer, Context};
use pcap_evidence::{json::Json, provenance::EvidenceBytes, Error, Result};
use std::collections::BTreeMap;

struct DnpTransport {
    last: u8,
    last_bytes: Vec<u8>,
    pending: EvidenceBytes,
    wire: EvidenceBytes,
    direction: bool,
}
#[derive(Clone, Debug)]
pub struct Completed {
    pub stream_start: i64,
    pub stream_end: i64,
    pub available_at_frame: u64,
    pub report: Report,
}
struct UaAssembly {
    token: u32,
    pending: EvidenceBytes,
}
pub struct Parser {
    protocol: String,
    buffer: StreamBuffer,
    limits: Limits,
    context: Context,
    cotp: EvidenceBytes,
    dnp: BTreeMap<(u16, u16), DnpTransport>,
    ua: BTreeMap<(u32, u32), UaAssembly>,
    ua_last: BTreeMap<u32, u32>,
    last_frame: u64,
    dnp_poisoned: bool,
}
impl Parser {
    pub fn new(protocol: &str, limits: Limits, context: Context) -> Result<Self> {
        if !matches!(
            protocol,
            "modbus" | "dnp3" | "iso_cotp" | "s7" | "iec104" | "enip_cip" | "opcua_tcp"
        ) {
            return Err(bad("continuation_protocol", 0, "unsupported stream framer"));
        }
        limits.validate()?;
        Ok(Self {
            protocol: protocol.into(),
            buffer: StreamBuffer::new(limits.input_bytes, limits.spans)?,
            limits,
            context,
            cotp: EvidenceBytes::default(),
            dnp: BTreeMap::new(),
            ua: BTreeMap::new(),
            ua_last: BTreeMap::new(),
            last_frame: 0,
            dnp_poisoned: false,
        })
    }
    fn length(&self) -> Result<Option<usize>> {
        let b = self.buffer.bytes().data();
        let n = match self.protocol.as_str() {
            "modbus" => {
                if b.len() < 6 {
                    return Ok(None);
                }
                if be16(b, 2)? != 0 {
                    return Err(bad("modbus_framing", 0, "nonzero protocol ID"));
                }
                let n = usize::from(be16(b, 4)?);
                if !(2..=254).contains(&n) {
                    return Err(bad("modbus_framing", 4, "length outside ADU limits"));
                }
                6 + n
            }
            "dnp3" => {
                if b.len() < 10 {
                    return Ok(None);
                }
                if b[..2] != [5, 100]
                    || b[2] < 5
                    || pcap_evidence::dnp3::crc16_dnp(&b[..8]) != le16(b, 8)?
                {
                    return Err(bad("dnp3_link", 0, "invalid link boundary/CRC"));
                }
                let n = usize::from(b[2] - 5);
                10 + n + 2 * n.div_ceil(16)
            }
            "s7" | "iso_cotp" => {
                if b.len() < 4 {
                    return Ok(None);
                }
                if b[0] != 3 || b[1] != 0 {
                    return Err(bad("tpkt", 0, "lost TPKT boundary"));
                }
                let n = usize::from(be16(b, 2)?);
                if n < 7 {
                    return Err(bad("tpkt", 2, "short TPKT"));
                }
                n
            }
            "iec104" => {
                if b.len() < 2 {
                    return Ok(None);
                }
                if b[0] != 0x68 || b[1] < 4 || b[1] > 253 {
                    return Err(bad("iec104", 0, "lost APCI boundary"));
                }
                2 + usize::from(b[1])
            }
            "enip_cip" => {
                if b.len() < 24 {
                    return Ok(None);
                }
                24 + usize::from(le16(b, 2)?)
            }
            "opcua_tcp" => {
                if b.len() < 8 {
                    return Ok(None);
                }
                let n = usize::try_from(le32(b, 4)?).map_err(|_| Error::limit("ua_frame"))?;
                if n < 8 {
                    return Err(bad("ua_size", 4, "message smaller than header"));
                }
                n
            }
            _ => return Err(bad("continuation", 0, "unknown protocol")),
        };
        if n > self.limits.input_bytes {
            return Err(Error::limit("application_message_bytes"));
        }
        Ok(if b.len() >= n { Some(n) } else { None })
    }
    pub fn feed(
        &mut self,
        offset: i64,
        bytes: &EvidenceBytes,
        emit: &mut dyn FnMut(Completed) -> Result<()>,
    ) -> Result<()> {
        let result = self.feed_inner(offset, bytes, emit);
        if self.protocol == "dnp3" && result.is_err() {
            self.dnp_poisoned = true;
        }
        result
    }
    fn feed_inner(
        &mut self,
        offset: i64,
        bytes: &EvidenceBytes,
        emit: &mut dyn FnMut(Completed) -> Result<()>,
    ) -> Result<()> {
        if self.dnp_poisoned {
            return Err(bad(
                "dnp_continuation_requires_cut",
                0,
                "explicit cut required after rejected evidence",
            ));
        }
        if !bytes.validate() {
            return Err(bad("continuation_provenance", 0, "invalid input"));
        }
        let mut p = 0;
        let mut messages = 0;
        while p < bytes.len() {
            let room = self
                .limits
                .input_bytes
                .saturating_sub(self.buffer.bytes().len());
            if room == 0 {
                return Err(Error::limit("application_buffer"));
            }
            let n = room.min(bytes.len() - p);
            let chunk = bytes.slice(p..p + n)?;
            self.buffer.push(
                offset
                    .checked_add(p as i64)
                    .ok_or_else(|| Error::limit("stream_offset"))?,
                &chunk,
            )?;
            p += n;
            while let Some(n) = match self.length() {
                Ok(n) => n,
                Err(e) => {
                    self.dnp_poisoned = self.protocol == "dnp3";
                    return Err(e);
                }
            } {
                messages += 1;
                if messages > self.limits.elements {
                    return Err(Error::limit("messages_per_feed"));
                }
                let at = self.buffer.offset();
                let raw = self.buffer.take(n)?;
                self.last_frame = self
                    .last_frame
                    .max(raw.packets().iter().map(|p| p.frame).max().unwrap_or(0));
                let report = match self.unit(&raw) {
                    Ok(report) => report,
                    Err(e) => {
                        if self.protocol == "dnp3" {
                            self.dnp_poisoned = true;
                            let mut rejected = Report::new("dnp3.rejected", &raw, &self.limits)?;
                            rejected.note(
                                match e.code {
                                    pcap_evidence::ErrorCode::LimitExceeded => Status::Limited,
                                    pcap_evidence::ErrorCode::Truncated => Status::Incomplete,
                                    pcap_evidence::ErrorCode::UnsupportedTransport
                                    | pcap_evidence::ErrorCode::UnsupportedVersion => {
                                        Status::Unsupported
                                    }
                                    _ => Status::Rejected,
                                },
                                e.field,
                                0,
                                raw.len(),
                            )?;
                            emit(Completed {
                                stream_start: at,
                                stream_end: at
                                    .checked_add(n as i64)
                                    .ok_or_else(|| Error::limit("stream_offset"))?,
                                available_at_frame: self.last_frame,
                                report: rejected,
                            })?;
                        }
                        return Err(e);
                    }
                };
                if let Some(report) = report {
                    emit(Completed {
                        stream_start: at,
                        stream_end: at
                            .checked_add(n as i64)
                            .ok_or_else(|| Error::limit("stream_offset"))?,
                        available_at_frame: self.last_frame,
                        report,
                    })?;
                }
            }
        }
        Ok(())
    }
    fn unit(&mut self, raw: &EvidenceBytes) -> Result<Option<Report>> {
        match self.protocol.as_str() {
            "modbus" => {
                let mut r = Report::new("modbus", raw, &self.limits)?;
                let value = pcap_evidence::semantics::modbus::alternatives_json(
                    raw,
                    pcap_evidence::modbus::Role::Unknown,
                    pcap_evidence::semantics::Limits::default(),
                );
                r.add(
                    "wire_semantic_alternatives",
                    value,
                    0..raw.len(),
                    "same_root_decoder_role_not_guessed",
                )?;
                Ok(Some(r))
            }
            "dnp3" => {
                let (frame, _) = pcap_evidence::dnp3::parse_link(raw, 0, 0)?;
                let key = (frame.source, frame.destination);
                if let Some((code, field)) = pcap_evidence::semantics::dnp3_workflow::link_issue(
                    frame.control,
                    frame.source,
                    frame.destination,
                    frame.user_data.len(),
                ) {
                    return Err(pcap_evidence::Error::new(
                        code,
                        0,
                        field,
                        "link metadata cannot authorize application bytes",
                    ));
                }
                if frame.user_data.is_empty() {
                    let mut report = Report::new("dnp3.link", raw, &self.limits)?;
                    report.add(
                        "link_workflow",
                        pcap_evidence::semantics::as_json(
                            pcap_evidence::semantics::dnp3_workflow::link(
                                raw,
                                self.dnp_semantic_limits(),
                            ),
                        ),
                        0..raw.len(),
                        "shared_root_link_decoder",
                    )?;
                    return Ok(Some(report));
                }
                // Account all active DNP state, not merely this address pair.
                let retained = self.dnp.values().try_fold(0usize, |n, s| {
                    n.checked_add(s.pending.len())
                        .and_then(|n| n.checked_add(s.wire.len()))
                        .and_then(|n| n.checked_add(s.last_bytes.len()))
                        .ok_or_else(|| Error::limit("dnp_retained_bytes"))
                })?;
                let additional = raw
                    .len()
                    .checked_add(frame.user_data.len().saturating_mul(2))
                    .ok_or_else(|| Error::limit("dnp_retained_bytes"))?;
                if retained
                    .checked_add(additional)
                    .is_none_or(|n| n > self.limits.retained_bytes)
                {
                    return Err(Error::limit("dnp_retained_bytes"));
                }
                let b = frame.user_data.data();
                let ctl = b[0];
                let seq = ctl & 63;
                if let Some(state) = self.dnp.get_mut(&key) {
                    if state.direction != frame.link_control.direction {
                        return Err(bad(
                            "dnp_link_direction_conflict",
                            0,
                            "direction changed within transport assembly",
                        ));
                    }
                    if seq == state.last && state.last_bytes.as_slice() == b {
                        if state.wire.spans().len().saturating_add(raw.spans().len())
                            > self.limits.spans
                        {
                            return Err(Error::limit("dnp_transport_spans"));
                        }
                        state.wire.append(raw, self.limits.input_bytes)?;
                        let mut duplicate =
                            Report::new("dnp3.transport_duplicate", raw, &self.limits)?;
                        duplicate.note(
                            Status::Observed,
                            "duplicate_transport_segment_not_appended",
                            0,
                            raw.len(),
                        )?;
                        return Ok(Some(duplicate));
                    }
                }
                if ctl & 64 != 0 {
                    if self.dnp.len() >= self.limits.active && !self.dnp.contains_key(&key) {
                        return Err(Error::limit("dnp_transport_sessions"));
                    }
                    if self.dnp.contains_key(&key) {
                        return Err(bad(
                            "dnp_transport",
                            0,
                            "new FIR interrupts unfinished transport fragment",
                        ));
                    }
                    self.dnp.insert(
                        key,
                        DnpTransport {
                            last: seq,
                            last_bytes: b.to_vec(),
                            pending: frame.user_data.slice(1..frame.user_data.len())?,
                            wire: raw.clone(),
                            direction: frame.link_control.direction,
                        },
                    );
                } else {
                    let Some(state) = self.dnp.get_mut(&key) else {
                        return Err(bad("dnp_transport", 0, "missing first transport segment"));
                    };
                    if seq != (state.last + 1) & 63 {
                        // Keep prior source witnesses for cut(), never silently
                        // discard them or use a later segment to fill the hole.
                        return Err(bad(
                            "dnp_transport_sequence_discontinuity",
                            0,
                            "missing/reordered/conflicting segment; cut required",
                        ));
                    }
                    if state.wire.spans().len().saturating_add(raw.spans().len())
                        > self.limits.spans
                    {
                        return Err(Error::limit("dnp_transport_spans"));
                    }
                    state.wire.append(raw, self.limits.input_bytes)?;
                    state.pending.append(
                        &frame.user_data.slice(1..frame.user_data.len())?,
                        self.limits.input_bytes,
                    )?;
                    if state.pending.spans().len() > self.limits.spans {
                        return Err(Error::limit("dnp_transport_spans"));
                    }
                    state.last = seq;
                    state.last_bytes = b.to_vec();
                }
                if ctl & 128 == 0 {
                    return Ok(None);
                }
                let state = self
                    .dnp
                    .get(&key)
                    .ok_or_else(|| bad("dnp_transport", 0, "missing completed state"))?;
                let b = state.pending.data();
                need(b, 2, "dnp_application")?;
                let function = b[1];
                let header = if matches!(function, 0x81 | 0x82) {
                    4
                } else {
                    2
                };
                need(b, header, "dnp_application")?;
                let objects = state.pending.slice(header..state.pending.len())?;
                let single = b[0] & 0xc0 == 0xc0;
                // Keep the separately declared deep file subset; standard objects
                // use the root decoder rather than a second layout table.
                let legacy_file = single
                    && function != 29
                    && (matches!(function, 25..=30) || objects.data().first() == Some(&70));
                let mut report = if legacy_file {
                    super::dnp::objects(&objects, function, &self.limits)?
                } else {
                    Report::new("dnp3.objects", &objects, &self.limits)?
                };
                let root = pcap_evidence::semantics::dnp3_workflow::application(
                    &state.pending,
                    self.dnp_semantic_limits(),
                )?;
                let status = match root.status() {
                    pcap_evidence::semantics::Status::DecodedSubset => Status::Observed,
                    pcap_evidence::semantics::Status::Incomplete => Status::Incomplete,
                    pcap_evidence::semantics::Status::Unsupported => Status::Unsupported,
                    pcap_evidence::semantics::Status::Rejected => Status::Rejected,
                    pcap_evidence::semantics::Status::Limited => Status::Limited,
                };
                if status != Status::Observed {
                    report.note(
                        status,
                        if single {
                            "root_workflow_subset_stopped"
                        } else {
                            "application_fragment_needs_verified_message_assembly"
                        },
                        0,
                        objects.len(),
                    )?;
                }
                report.add(
                    "root_application_workflow",
                    root.json()?,
                    0..0,
                    "shared_root_decoder_on_upstream_application_evidence",
                )?;
                report.add(
                    "application_evidence",
                    pcap_evidence_stream::events::Evidence::bytes(&state.pending).json(),
                    0..0,
                    "exact_transport_reassembled_apdu_including_header",
                )?;
                report.add(
                    "link_frame_evidence",
                    pcap_evidence_stream::events::Evidence::bytes(&state.wire).json(),
                    0..0,
                    "crc_validated_link_frames_including_duplicate_witnesses",
                )?;
                report.add(
                    "upstream_application_fragment",
                    Json::object([
                        ("source", key.0.into()),
                        ("destination", key.1.into()),
                        ("control", b[0].into()),
                        ("function", function.into()),
                        (
                            "header_evidence",
                            pcap_evidence_stream::events::Evidence::bytes(
                                &state.pending.slice(0..header)?,
                            )
                            .json(),
                        ),
                    ]),
                    0..0,
                    "validated_transport_fragment_dependency",
                )?;
                self.dnp.remove(&key);
                Ok(Some(report))
            }
            "s7" | "iso_cotp" => {
                let c = super::iso::cotp(raw.data())?;
                if c.kind != 0xf0 {
                    return Ok(Some(super::iso::tpkt(raw, &self.limits)?));
                }
                let part = raw.slice(c.payload)?;
                if self.cotp.spans().len().saturating_add(part.spans().len()) > self.limits.spans {
                    return Err(Error::limit("cotp_spans"));
                }
                self.cotp.append(&part, self.limits.input_bytes)?;
                if !c.eot {
                    return Ok(None);
                }
                let data = std::mem::take(&mut self.cotp);
                let report = if data.data().first() == Some(&0x32) {
                    super::iso::s7(&data, &self.limits)?
                } else {
                    super::iso::session_presentation(&data, &self.limits)?
                };
                Ok(Some(report))
            }
            "opcua_tcp" if self.context.ua_security_none && raw.data().starts_with(b"MSG") => {
                let b = raw.data();
                need(b, 24, "ua_message")?;
                let key = (le32(b, 8)?, le32(b, 20)?);
                if b[3] == b'A' {
                    self.ua.remove(&key);
                    return Ok(Some(super::opcua::decode(raw, true, &self.limits)?));
                }
                if !matches!(b[3], b'C' | b'F') {
                    return Err(bad("ua_chunk", 3, "unknown chunk flag"));
                }
                let sequence = le32(b, 16)?;
                let token = le32(b, 12)?;
                if self.ua_last.len() >= self.limits.active && !self.ua_last.contains_key(&key.0) {
                    return Err(Error::limit("ua_channels"));
                }
                if self.ua_last.get(&key.0).is_some_and(|previous| {
                    sequence != previous.wrapping_add(1)
                        && !(*previous > u32::MAX - 1024 && sequence < 1024)
                }) {
                    self.ua.remove(&key);
                    return Err(bad(
                        "ua_sequence",
                        16,
                        "gap/reorder/reuse in secure-channel sequence",
                    ));
                }
                self.ua_last.insert(key.0, sequence);
                if !self.ua.contains_key(&key) && self.ua.len() >= self.limits.active {
                    return Err(Error::limit("ua_messages"));
                }
                let assembly = self.ua.entry(key).or_insert_with(|| UaAssembly {
                    token,
                    pending: EvidenceBytes::default(),
                });
                if assembly.token != token {
                    return Err(bad("ua_token", 12, "token changed inside chunked message"));
                }
                let pending = &mut assembly.pending;
                let part = raw.slice(24..raw.len())?;
                if pending.spans().len().saturating_add(part.spans().len()) > self.limits.spans {
                    return Err(Error::limit("ua_spans"));
                }
                pending.append(&part, self.limits.input_bytes)?;
                if b[3] == b'C' {
                    return Ok(None);
                }
                let body = self
                    .ua
                    .remove(&key)
                    .ok_or_else(|| bad("ua_chunks", 0, "missing body"))?;
                Ok(Some(super::opcua::service(&body.pending, &self.limits)?))
            }
            protocol => Ok(Some(super::decode(
                protocol,
                raw,
                &self.context,
                &self.limits,
            )?)),
        }
    }
    fn dnp_semantic_limits(&self) -> pcap_evidence::semantics::Limits {
        let d = pcap_evidence::semantics::Limits::default();
        pcap_evidence::semantics::Limits {
            max_input_bytes: d.max_input_bytes.min(self.limits.input_bytes),
            max_records: d.max_records.min(self.limits.elements),
            max_fields: d.max_fields.min(self.limits.fields),
            max_source_spans: d.max_source_spans.min(self.limits.spans),
            max_work: d.max_work.min(self.limits.work),
            max_json_bytes: d.max_json_bytes.min(self.limits.output_bytes),
        }
    }
    pub fn cut(&mut self, reason: &'static str) -> Result<Report> {
        let pending = self.buffer.gap();
        let mut r = Report::new("application.boundary", &pending, &self.limits)?;
        let mut states = Vec::new();
        if !self.cotp.is_empty() {
            states.push(pcap_evidence_stream::events::Evidence::bytes(&self.cotp).json());
        }
        for s in self.dnp.values() {
            states.push(pcap_evidence_stream::events::Evidence::bytes(&s.pending).json());
            states.push(pcap_evidence_stream::events::Evidence::bytes(&s.wire).json());
        }
        for s in self.ua.values() {
            states.push(pcap_evidence_stream::events::Evidence::bytes(&s.pending).json());
        }
        r.add(
            "discarded_state_evidence",
            Json::Array(states),
            0..0,
            "explicit_application_state_boundary",
        )?;
        self.cotp = EvidenceBytes::default();
        self.dnp.clear();
        self.dnp_poisoned = false;
        self.ua.clear();
        self.ua_last.clear();
        r.note(Status::Incomplete, reason, 0, pending.len())?;
        Ok(r)
    }
    pub fn finish(&mut self) -> Result<Option<Report>> {
        if self.dnp_poisoned
            || !self.buffer.bytes().is_empty()
            || !self.cotp.is_empty()
            || !self.dnp.is_empty()
            || !self.ua.is_empty()
        {
            Ok(Some(
                self.cut("incomplete_application_at_selected_range_end")?,
            ))
        } else {
            Ok(None)
        }
    }
}
