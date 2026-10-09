//! Integration with the existing typed event pipeline. A disk-backed packet map
//! permits late message witnesses without a capture-sized RAM hash map.
use super::{model::*, Context, Limits};
use pcap_evidence::{
    json::Json,
    provenance::{EvidenceBytes, PacketId},
    sha256, Error, ErrorCode, Result,
};
use pcap_evidence_stream::{Event, EventKind, EventSink};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::Path,
};
// Private scratch format: original byte identity plus exact capture time.
const ROW: usize = 65;

pub struct PacketMap {
    source: File,
    index: File,
    rows: u64,
    max_disk: u64,
    namespace: [u8; 32],
}
impl PacketMap {
    pub fn create(mut source: File, path: &Path, max_disk: u64, _run_id: &str) -> Result<Self> {
        if max_disk < ROW as u64 {
            return Err(Error::limit("depth_packet_map_disk"));
        }
        let index = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(path)?;
        let namespace = hash_source(&mut source)?;
        Ok(Self {
            source,
            index,
            rows: 0,
            max_disk,
            namespace,
        })
    }
    pub fn record(&mut self, event: &Event) -> Result<EvidenceBytes> {
        let frame = number(get(&event.data, "frame"))?;
        if frame
            != self
                .rows
                .checked_add(1)
                .ok_or_else(|| Error::limit("depth_frames"))?
        {
            return Err(bad("packet_map", 0, "packet ordinals must be contiguous"));
        }
        let record = number(get(&event.data, "record_offset"))?;
        let offset = number(get(&event.data, "data_offset"))?;
        let cap = usize::try_from(number(get(&event.data, "captured_length"))?)
            .map_err(|_| Error::limit("packet_length"))?;
        if cap > 1024 * 1024 {
            return Err(Error::limit("packet_map_input"));
        }
        let mut raw = vec![0; cap];
        self.source.seek(SeekFrom::Start(offset))?;
        self.source.read_exact(&mut raw)?;
        let hash = sha256::digest(&raw);
        if get(&event.data, "packet_sha256") != Some(&Json::String(sha256::hex(&hash))) {
            return Err(Error::new(
                ErrorCode::SourceMismatch,
                offset,
                "depth_source",
                "packet changed during analysis",
            ));
        }
        let end = frame
            .checked_mul(ROW as u64)
            .filter(|n| *n <= self.max_disk)
            .ok_or_else(|| Error::limit("depth_packet_map_disk"))?;
        let mut row = [0u8; ROW];
        row[..8].copy_from_slice(&record.to_le_bytes());
        row[8..16].copy_from_slice(&offset.to_le_bytes());
        row[16..24].copy_from_slice(&(cap as u64).to_le_bytes());
        row[24..56].copy_from_slice(&hash);
        if let Some(time) = capture_time(get(&event.data, "timestamp_ns")) {
            row[56..64].copy_from_slice(&time.to_le_bytes());
            row[64] = 1;
        }
        self.index.seek(SeekFrom::Start(end - ROW as u64))?;
        self.index.write_all(&row)?;
        self.rows = frame;
        Ok(EvidenceBytes::from_packet(
            &raw,
            PacketId {
                capture: self.namespace,
                frame,
                record_offset: record,
            },
            0,
        ))
    }
    // Select by capture-frame ordinal, never by timestamp or span layout.
    // Call only after materialization verifies every contributing raw span.
    fn observed_at_ns(&mut self, raw: &EvidenceBytes) -> Result<Option<i64>> {
        let Some(span) = raw.spans().iter().max_by_key(|span| span.packet.frame) else {
            return Ok(None);
        };
        let mut row = [0u8; ROW];
        self.index
            .seek(SeekFrom::Start((span.packet.frame - 1) * ROW as u64))?;
        self.index.read_exact(&mut row)?;
        Ok((row[64] == 1).then(|| i64::from_le_bytes(row[56..64].try_into().unwrap())))
    }
    pub fn namespace(&self) -> [u8; 32] {
        self.namespace
    }
    pub fn verify_source(&mut self) -> Result<()> {
        if hash_source(&mut self.source)? != self.namespace {
            return Err(Error::new(
                ErrorCode::SourceMismatch,
                0,
                "depth_source",
                "capture changed during analysis",
            ));
        }
        Ok(())
    }
    fn span(
        &mut self,
        frame: u64,
        record: u64,
        start: usize,
        count: usize,
    ) -> Result<EvidenceBytes> {
        if frame == 0 || frame > self.rows {
            return Err(bad("depth_span", 0, "unknown packet ordinal"));
        }
        let mut row = [0u8; ROW];
        self.index.seek(SeekFrom::Start((frame - 1) * ROW as u64))?;
        self.index.read_exact(&mut row)?;
        if uint(&row[..8], true)? != record {
            return Err(bad("depth_span", 0, "record identity mismatch"));
        }
        let offset = uint(&row[8..16], true)?;
        let cap =
            usize::try_from(uint(&row[16..24], true)?).map_err(|_| Error::limit("packet_cap"))?;
        if cap > 1024 * 1024 || start.checked_add(count).is_none_or(|n| n > cap) {
            return Err(bad("depth_span", start, "span outside original packet"));
        }
        let mut raw = vec![0; cap];
        self.source.seek(SeekFrom::Start(offset))?;
        self.source.read_exact(&mut raw)?;
        if sha256::digest(&raw) != row[24..56] {
            return Err(Error::new(
                ErrorCode::SourceMismatch,
                offset,
                "depth_source",
                "packet no longer matches producer",
            ));
        }
        Ok(EvidenceBytes::from_packet(
            &raw[start..start + count],
            PacketId {
                capture: self.namespace,
                frame,
                record_offset: record,
            },
            start,
        ))
    }
    pub fn materialize(
        &mut self,
        e: &pcap_evidence_stream::events::Evidence,
        l: &Limits,
    ) -> Result<EvidenceBytes> {
        self.materialize_json(&e.json(), l)
    }
    pub fn materialize_json(&mut self, v: &Json, l: &Limits) -> Result<EvidenceBytes> {
        let n = usize::try_from(number(get(v, "byte_length"))?)
            .map_err(|_| Error::limit("depth_materialize"))?;
        let Some(Json::Array(spans)) = get(v, "spans") else {
            return Err(bad("depth_materialize", 0, "missing spans"));
        };
        if n > l.input_bytes || spans.len() > l.spans {
            return Err(Error::limit("depth_materialize"));
        }
        let mut out = EvidenceBytes::default();
        let mut cursor = 0;
        for s in spans {
            let begin = usize::try_from(number(get(s, "start"))?)
                .map_err(|_| Error::limit("span_offset"))?;
            let end =
                usize::try_from(number(get(s, "end"))?).map_err(|_| Error::limit("span_offset"))?;
            if begin != cursor || end <= begin || end > n {
                return Err(bad("depth_materialize", begin, "noncontiguous span layout"));
            }
            let packet_start = usize::try_from(number(get(s, "packet_start"))?)
                .map_err(|_| Error::limit("span_offset"))?;
            let piece = self.span(
                number(get(s, "frame"))?,
                number(get(s, "record_offset"))?,
                packet_start,
                end - begin,
            )?;
            out.append(&piece, l.input_bytes)?;
            cursor = end;
        }
        if cursor != n
            || get(v, "reconstructed_sha256")
                != Some(&Json::String(sha256::hex(&sha256::digest(out.data()))))
        {
            return Err(bad(
                "depth_materialize",
                cursor,
                "reconstructed identity mismatch",
            ));
        }
        Ok(out)
    }
    pub fn finish(&mut self) -> Result<()> {
        self.index.flush()?;
        self.index.sync_all()?;
        Ok(())
    }
}

fn capture_time(value: Option<&Json>) -> Option<i64> {
    let Some(Json::String(text)) = value else {
        return None;
    };
    let time = text.parse::<i64>().ok()?;
    (time.to_string() == *text).then_some(time)
}

// The stream producer names canonical endpoint a as source and b as
// destination in FlowStart.key. These labels do not establish BGP role truth.
fn flow_endpoints(data: &Json) -> Option<(std::net::IpAddr, std::net::IpAddr)> {
    let key = get(data, "key")?;
    if get(key, "transport") != Some(&Json::String("tcp".into())) {
        return None;
    }
    let endpoint = |ip_key, port_key| {
        let Some(Json::String(text)) = get(key, ip_key) else {
            return None;
        };
        let address = text.parse::<std::net::IpAddr>().ok()?;
        if address.to_string() != *text || number(get(key, port_key)).ok()? > u16::MAX as u64 {
            return None;
        }
        Some(address)
    };
    Some((
        endpoint("source_ip", "source_port")?,
        endpoint("destination_ip", "destination_port")?,
    ))
}

fn hash_source(source: &mut File) -> Result<[u8; 32]> {
    let mut capture_hash = sha256::Sha256::new();
    let mut chunk = vec![0u8; 64 * 1024];
    source.seek(SeekFrom::Start(0))?;
    loop {
        let count = source.read(&mut chunk)?;
        if count == 0 {
            break;
        }
        capture_hash.update(&chunk[..count]);
    }
    source.seek(SeekFrom::Start(0))?;
    Ok(capture_hash.finalize())
}
fn set(v: &mut Json, key: &'static str, data: Json) -> Result<()> {
    let Json::Object(fields) = v else {
        return Err(bad("event_data", 0, "expected object"));
    };
    if fields.iter().any(|(k, _)| *k == key) {
        return Err(bad("depth_extension", 0, "duplicate extension field"));
    }
    fields.push((key, data));
    Ok(())
}
fn is_true(v: Option<&Json>) -> bool {
    matches!(v, Some(Json::Bool(true)))
}
fn outcome(result: Result<Report>) -> Json {
    match result {
        Ok(r) => r.json(),
        Err(e) => Json::object([
            ("schema", VERSION.into()),
            (
                "status",
                if e.code == ErrorCode::LimitExceeded {
                    "limited"
                } else if e.code == ErrorCode::Truncated {
                    "incomplete"
                } else {
                    "rejected"
                }
                .into(),
            ),
            ("code", e.code.as_str().into()),
            ("field", e.field.into()),
            ("offset", e.offset.to_string().into()),
            ("device_effect_established", false.into()),
        ]),
    }
}
fn outcome_json(result: Result<Json>) -> Json {
    match result {
        Ok(value) => value,
        Err(e) => Json::object([
            ("schema", super::bgp::SCHEMA.into()),
            (
                "status",
                if e.code == ErrorCode::LimitExceeded {
                    "limited"
                } else if e.code == ErrorCode::Truncated {
                    "incomplete"
                } else {
                    "rejected"
                }
                .into(),
            ),
            ("code", e.code.as_str().into()),
            ("field", e.field.into()),
            ("offset", e.offset.to_string().into()),
            ("endpoint_state_established", false.into()),
            ("causality_established", false.into()),
        ]),
    }
}

fn event_record_id(event: &Event, run_id: &str, limits: &Limits) -> Result<String> {
    let encoded = event.json(run_id, 0).encode_bounded(limits.output_bytes)?;
    Ok(format!(
        "event-sha256:{}",
        sha256::hex(&sha256::digest(encoded.as_bytes()))
    ))
}

fn event_boundary_reason(event: &Event) -> String {
    let detail = ["reason", "policy"]
        .into_iter()
        .find_map(|key| match get(&event.data, key) {
            Some(Json::String(value)) => Some(value.as_str()),
            _ => None,
        })
        .unwrap_or("unspecified");
    format!("{}:{detail}", event.kind.as_str())
}

fn session_apply_status(status: super::bgp_session::ApplyStatus) -> &'static str {
    use super::bgp_session::ApplyStatus;
    match status {
        ApplyStatus::Applied => "applied",
        ApplyStatus::IdenticalReplay => "identical_replay",
        ApplyStatus::Historical => "historical",
        ApplyStatus::Closed => "closed",
        ApplyStatus::IdentityConflict => "identity_conflict",
    }
}

fn rib_apply_status(status: super::bgp_rib::ApplyStatus) -> &'static str {
    use super::bgp_rib::ApplyStatus;
    match status {
        ApplyStatus::Applied => "applied",
        ApplyStatus::IdenticalReplay => "identical_replay",
        ApplyStatus::Historical => "historical",
        ApplyStatus::MissingScope => "missing_scope",
        ApplyStatus::IdentityConflict => "identity_conflict",
    }
}

fn bgp_summary_json(summary: &super::bgp_manager::SessionSummary) -> Json {
    summary.json()
}

fn bgp_apply_json(
    record_id: &str,
    receipt: &super::bgp_pipeline::ApplyReceipt,
    summary: &super::bgp_manager::SessionSummary,
) -> Json {
    Json::object([
        ("schema", "pcap-evidence.bgp.pipeline-receipt.v1".into()),
        ("record_id", record_id.into()),
        (
            "observation_sha256",
            sha256::hex(&receipt.observation_sha256).into(),
        ),
        (
            "session_status",
            session_apply_status(receipt.session_status).into(),
        ),
        (
            "rib_status",
            receipt
                .rib_status
                .map_or(Json::Null, |status| rib_apply_status(status).into()),
        ),
        ("protocol_reset", receipt.protocol_reset.into()),
        ("replayed", receipt.replayed.into()),
        ("state", bgp_summary_json(summary)),
        ("endpoint_state_claimed", false.into()),
    ])
}

fn bgp_boundary_json(
    record_id: &str,
    result: Result<super::bgp_pipeline::BoundaryReceipt>,
) -> Json {
    match result {
        Ok(receipt) => Json::object([
            ("schema", "pcap-evidence.bgp.pipeline-boundary.v1".into()),
            ("record_id", record_id.into()),
            (
                "session_status",
                session_apply_status(receipt.session_status).into(),
            ),
            (
                "rib_status",
                receipt
                    .rib_status
                    .map_or(Json::Null, |status| rib_apply_status(status).into()),
            ),
            ("previous_generation", receipt.previous_generation.into()),
            ("generation", receipt.generation.into()),
            ("replayed", receipt.replayed.into()),
            ("endpoint_state_claimed", false.into()),
        ]),
        Err(error) => Json::object([
            ("schema", "pcap-evidence.bgp.pipeline-boundary.v1".into()),
            ("record_id", record_id.into()),
            ("status", "rejected".into()),
            ("code", error.code.as_str().into()),
            ("field", error.field.into()),
            ("offset", error.offset.to_string().into()),
            ("endpoint_state_claimed", false.into()),
        ]),
    }
}

pub struct DeepSink<'a> {
    pub inner: &'a mut dyn EventSink,
    map: PacketMap,
    limits: Limits,
    context: Context,
    iec: BTreeMap<u64, super::iec104::Session>,
    bacnet: super::bacnet::Session,
    dnp_file: super::dnp_file::FileReconciler,
    bgp: super::bgp_manager::CapturedSessionManager,
    bgp_seen: BTreeSet<u64>,
    flow_endpoints: BTreeMap<u64, (std::net::IpAddr, std::net::IpAddr)>,
    bgp_pending_boundaries: BTreeMap<u64, Vec<(String, String)>>,
    bgp_pending_count: usize,
    bgp_pending_overflow: bool,
    bgp_journal: Option<super::bgp_store::JournalWriter>,
}
impl<'a> DeepSink<'a> {
    pub fn new(
        inner: &'a mut dyn EventSink,
        source: File,
        map_path: &Path,
        disk_budget: u64,
        limits: Limits,
        context: Context,
    ) -> Result<Self> {
        limits.validate()?;
        let map = PacketMap::create(source, map_path, disk_budget, inner.run_id())?;
        let bacnet = super::bacnet::Session::new(limits.clone())?;
        let bgp = super::bgp_manager::CapturedSessionManager::new(
            map.namespace(),
            inner.run_id().to_owned(),
            limits.clone(),
        )?;
        Ok(Self {
            inner,
            map,
            limits,
            context,
            iec: BTreeMap::new(),
            bacnet,
            dnp_file: super::dnp_file::FileReconciler::new(),
            bgp,
            bgp_seen: BTreeSet::new(),
            flow_endpoints: BTreeMap::new(),
            bgp_pending_boundaries: BTreeMap::new(),
            bgp_pending_count: 0,
            bgp_pending_overflow: false,
            bgp_journal: None,
        })
    }

    pub fn enable_bgp_journal(&mut self, path: &Path, disk_budget: u64) -> Result<()> {
        if self.bgp_journal.is_some() {
            return Err(bad(
                "bgp_journal_state",
                0,
                "BGP journal is already enabled",
            ));
        }
        self.bgp_journal = Some(super::bgp_store::JournalWriter::create(
            path,
            self.inner.run_id().to_owned(),
            self.map.namespace(),
            disk_budget,
            self.limits.clone(),
        )?);
        Ok(())
    }

    pub fn finish(mut self) -> Result<Option<super::bgp_store::JournalReceipt>> {
        self.map.verify_source()?;
        self.bgp_journal
            .take()
            .map(super::bgp_store::JournalWriter::seal)
            .transpose()
    }
    fn retain_or_apply_bgp_boundary(
        &mut self,
        session: u64,
        record_id: String,
        reason: String,
    ) -> Option<Result<super::bgp_pipeline::BoundaryReceipt>> {
        if self.bgp_seen.contains(&session) {
            return Some(self.bgp.observe_gap(session, record_id, reason));
        }
        if self.bgp_pending_count >= self.limits.elements
            || (!self.bgp_pending_boundaries.contains_key(&session)
                && self.bgp_pending_boundaries.len() >= self.limits.elements)
        {
            self.bgp_pending_overflow = true;
            return None;
        }
        self.bgp_pending_boundaries
            .entry(session)
            .or_default()
            .push((record_id, reason));
        self.bgp_pending_count += 1;
        None
    }
    fn prepare_bgp_session(&mut self, session: u64, record_id: &str) -> Result<()> {
        if self.bgp_pending_overflow {
            let boundary_id = format!("{record_id}:preclassification-boundary-overflow");
            let reason = "preclassification_boundary_retention_exceeded";
            self.bgp.observe_gap(session, boundary_id, reason.into())?;
        }
        if let Some(boundaries) = self.bgp_pending_boundaries.remove(&session) {
            self.bgp_pending_count = self.bgp_pending_count.saturating_sub(boundaries.len());
            for (boundary_id, reason) in boundaries {
                self.bgp.observe_gap(session, boundary_id, reason)?;
            }
        }
        Ok(())
    }
    fn journal_bgp_preparation(&mut self, session: u64, record_id: &str) -> Result<()> {
        let Some(journal) = self.bgp_journal.as_mut() else {
            return Ok(());
        };
        if self.bgp_pending_overflow {
            journal.gap(
                session,
                &format!("{record_id}:preclassification-boundary-overflow"),
                "preclassification_boundary_retention_exceeded",
            )?;
        }
        if let Some(boundaries) = self.bgp_pending_boundaries.get(&session) {
            for (boundary_id, reason) in boundaries {
                journal.gap(session, boundary_id, reason)?;
            }
        }
        Ok(())
    }
    fn remove_pending_bgp_session(&mut self, session: u64) {
        if let Some(boundaries) = self.bgp_pending_boundaries.remove(&session) {
            self.bgp_pending_count = self.bgp_pending_count.saturating_sub(boundaries.len());
        }
    }
    fn augment(&mut self, e: &Event) -> Result<Event> {
        let mut own = e.clone();
        if e.kind == EventKind::CaptureStart {
            set(
                &mut own.data,
                "depth_engine",
                Json::object([
                    ("schema", VERSION.into()),
                    ("wire_semantics", "bounded_independent_subsets".into()),
                    ("device_maps", "explicit_caller_supplied_only".into()),
                    ("crypto", "not_automatically_enabled".into()),
                ]),
            )?;
        }
        if e.kind == EventKind::Packet {
            let raw = self.map.record(e)?;
            let link = number(get(&e.data, "link_type"))?;
            if link == 195 || link == 230 {
                set(
                    &mut own.data,
                    "depth_observation",
                    outcome(super::zigbee::decode(&raw, link == 195, &self.limits)),
                )?;
            }
        }
        if e.kind == EventKind::FlowStart {
            if let Some(id) = e.session {
                self.flow_endpoints.remove(&id);
                if self.flow_endpoints.len() < self.limits.elements {
                    if let Some(endpoints) = flow_endpoints(&e.data) {
                        self.flow_endpoints.insert(id, endpoints);
                    }
                }
            }
        }
        // A scoped BGP framing issue means the stream decoder omitted source
        // bytes. It carries the same continuity consequence as a transport
        // gap, without manufacturing a withdrawal or successor generation.
        let bgp_issue = e.kind == EventKind::ProtocolIssue && e.protocol.as_deref() == Some("bgp");
        let transport_boundary = matches!(e.kind, EventKind::StreamGap | EventKind::StreamConflict);
        if transport_boundary || bgp_issue {
            if let Some(id) = e.session {
                if transport_boundary {
                    if let Some(s) = self.iec.get_mut(&id) {
                        s.gap();
                    }
                }
                let record_id = event_record_id(e, self.inner.run_id(), &self.limits)?;
                let reason = event_boundary_reason(e);
                if self.bgp_seen.contains(&id) {
                    if let Some(journal) = self.bgp_journal.as_mut() {
                        journal.gap(id, &record_id, &reason)?;
                    }
                }
                let result = self.retain_or_apply_bgp_boundary(id, record_id.clone(), reason);
                if let Some(result) = result {
                    let receipt = result?;
                    set(
                        &mut own.data,
                        "depth_bgp_boundary",
                        bgp_boundary_json(&record_id, Ok(receipt)),
                    )?;
                }
                if transport_boundary {
                    self.dnp_file.reset_session(id);
                }
            }
        }
        if e.kind == EventKind::FlowEnd {
            if let Some(id) = e.session {
                if let Some(mut s) = self.iec.remove(&id) {
                    s.gap();
                }
                self.dnp_file.reset_session(id);
                self.flow_endpoints.remove(&id);
                self.remove_pending_bgp_session(id);
                let was_bgp = self.bgp_seen.remove(&id);
                if was_bgp {
                    if let Some(journal) = self.bgp_journal.as_mut() {
                        journal.end_session(id)?;
                    }
                }
                if let Some(summary) = self.bgp.end_session(id) {
                    if was_bgp {
                        set(
                            &mut own.data,
                            "depth_bgp_session_summary",
                            bgp_summary_json(&summary),
                        )?;
                    }
                }
            }
        }
        if e.kind == EventKind::Boundary {
            self.iec.clear();
            self.flow_endpoints.clear();
            self.bacnet = super::bacnet::Session::new(self.limits.clone())?;
            self.dnp_file.reset();
            self.bgp_pending_boundaries.clear();
            self.bgp_pending_count = 0;
            self.bgp_pending_overflow = false;
            if self.bgp.active_sessions() != 0 {
                if let Some(journal) = self.bgp_journal.as_mut() {
                    journal.clear()?;
                }
            }
            let abandoned: Vec<_> = self
                .bgp
                .clear()
                .into_iter()
                .filter(|summary| self.bgp_seen.contains(&summary.session))
                .map(|summary| bgp_summary_json(&summary))
                .collect();
            self.bgp_seen.clear();
            if !abandoned.is_empty() {
                set(
                    &mut own.data,
                    "depth_bgp_unclosed_sessions",
                    Json::Array(abandoned),
                )?;
            }
        }
        let protocol = e.protocol.as_deref().unwrap_or("");
        if e.kind == EventKind::Message || e.kind == EventKind::Network {
            if protocol == "dnp3" {
                if let Some(Json::Array(fragments)) = get(&e.data, "application_fragment_evidence")
                {
                    if fragments.len() > self.limits.elements {
                        return Err(Error::limit("depth_dnp_fragments"));
                    }
                    let mut results = Vec::new();
                    for fragment in fragments {
                        let raw = self.map.materialize_json(
                            get(fragment, "objects")
                                .ok_or_else(|| bad("dnp_fragment", 0, "object evidence missing"))?,
                            &self.limits,
                        )?;
                        let f = u8::try_from(number(get(fragment, "function"))?)
                            .map_err(|_| Error::limit("dnp_function"))?;
                        results.push(outcome(super::dnp::objects(&raw, f, &self.limits)));
                    }
                    set(&mut own.data, "depth_fragments", Json::Array(results))?;
                }
                if is_true(get(&e.data, "complete")) {
                    if let Some(object_evidence) = get(&e.data, "application_object_evidence") {
                        let raw = self.map.materialize_json(object_evidence, &self.limits)?;
                        let function = u8::try_from(number(get(&e.data, "function"))?)
                            .map_err(|_| Error::limit("dnp_function"))?;
                        set(
                            &mut own.data,
                            "depth_assembled",
                            outcome(super::dnp::objects(&raw, function, &self.limits)),
                        )?;
                        let source = u16::try_from(number(get(&e.data, "source"))?)
                            .map_err(|_| Error::limit("dnp_source"))?;
                        let destination = u16::try_from(number(get(&e.data, "destination"))?)
                            .map_err(|_| Error::limit("dnp_destination"))?;
                        if let Some(reconciliation) = self.dnp_file.observe(
                            super::dnp_file::Observation {
                                session: e.session.unwrap_or(0),
                                direction: e.direction.unwrap_or(0),
                                source,
                                destination,
                                function,
                                objects: &raw,
                                evidence: e.evidence.json(),
                            },
                            &self.limits,
                        )? {
                            set(&mut own.data, "depth_file_transfer", reconciliation)?;
                        }
                    }
                }
            } else if protocol == "bgp" && !e.evidence.spans.is_empty() {
                let raw = self.map.materialize(&e.evidence, &self.limits)?;
                let record_id = event_record_id(e, self.inner.run_id(), &self.limits)?;
                let endpoints = e.session.and_then(|id| self.flow_endpoints.get(&id));
                let (peer, local) = match (e.direction, endpoints) {
                    (Some(0), Some((a, b))) => (Some(a.to_string()), Some(b.to_string())),
                    (Some(1), Some((a, b))) => (Some(b.to_string()), Some(a.to_string())),
                    _ => (None, None),
                };
                let observed_at_ns = self.map.observed_at_ns(&raw)?;
                set(
                    &mut own.data,
                    "depth_bgp_capture_metadata",
                    Json::object([
                        ("time_basis", "latest_contributing_capture_frame".into()),
                        ("time_available", observed_at_ns.is_some().into()),
                        ("clock_calibration", "unknown".into()),
                        ("clock_uncertainty_ns", Json::Null),
                        (
                            "endpoint_basis",
                            "flow_start_canonical_ip_pair_and_direction".into(),
                        ),
                        ("endpoints_available", peer.is_some().into()),
                        (
                            "endpoint_unavailable_reason",
                            if peer.is_some() {
                                Json::Null
                            } else if !matches!(e.direction, Some(0 | 1)) {
                                "direction_missing_or_unknown".into()
                            } else {
                                "flow_start_missing_invalid_or_not_retained".into()
                            },
                        ),
                    ]),
                )?;
                let metadata = super::bgp::PcapMetadata {
                    source_id: self.inner.run_id().to_owned(),
                    record_id: record_id.clone(),
                    observed_at_ns,
                    session: e.session,
                    direction: e.direction,
                    peer,
                    local,
                };
                if let Some(id) = e.session {
                    let first_bgp_message = self.bgp_seen.insert(id);
                    if first_bgp_message {
                        self.journal_bgp_preparation(id, &record_id)?;
                    }
                    if let Some(journal) = self.bgp_journal.as_mut() {
                        journal.message(id, &raw, &metadata)?;
                    }
                    // Preparation is boundary admission, not malformed wire
                    // evidence. Any failure must stop publication.
                    if first_bgp_message {
                        self.prepare_bgp_session(id, &record_id)?;
                    }
                    let result = self.bgp.apply_message(id, &raw, metadata);
                    match result {
                        Ok(receipt) => {
                            let summary = self
                                .bgp
                                .summary(id)
                                .ok_or_else(|| Error::limit("bgp_manager_summary_invariant"))?;
                            set(&mut own.data, "depth_bgp", receipt.normalized.clone())?;
                            set(
                                &mut own.data,
                                "depth_bgp_pipeline",
                                bgp_apply_json(&record_id, &receipt, &summary),
                            )?;
                        }
                        Err(error) if error.code == ErrorCode::LimitExceeded => return Err(error),
                        Err(error) => {
                            // The raw MESSAGE is already the journal carrier.
                            // Replay derives one gap from its rejection; adding
                            // a GAP record here would count the omission twice.
                            let boundary_id = format!("{record_id}:rejected-message");
                            let receipt = self.bgp.observe_gap(
                                id,
                                boundary_id.clone(),
                                "sealed_source_message_rejected".into(),
                            )?;
                            set(
                                &mut own.data,
                                "depth_bgp_boundary",
                                bgp_boundary_json(&boundary_id, Ok(receipt)),
                            )?;
                            set(&mut own.data, "depth_bgp", outcome_json(Err(error.clone())))?;
                            set(
                                &mut own.data,
                                "depth_bgp_pipeline",
                                Json::object([
                                    ("schema", "pcap-evidence.bgp.pipeline-receipt.v1".into()),
                                    ("record_id", record_id.into()),
                                    ("status", "rejected".into()),
                                    ("code", error.code.as_str().into()),
                                    ("field", error.field.into()),
                                    ("offset", error.offset.to_string().into()),
                                    ("endpoint_state_claimed", false.into()),
                                ]),
                            )?;
                        }
                    }
                } else {
                    let mut state = super::bgp::SessionState::default();
                    let result = super::bgp::decode_pcap(&raw, metadata, &mut state, &self.limits);
                    set(&mut own.data, "depth_bgp", outcome_json(result))?;
                    set(
                        &mut own.data,
                        "depth_bgp_pipeline",
                        Json::object([
                            ("schema", "pcap-evidence.bgp.pipeline-receipt.v1".into()),
                            ("record_id", record_id.into()),
                            ("status", "unscoped".into()),
                            ("session", Json::Null),
                            ("endpoint_state_claimed", false.into()),
                        ]),
                    )?;
                }
            } else if matches!(
                protocol,
                "bacnet_ip"
                    | "enip_cip"
                    | "iec104"
                    | "s7"
                    | "mms"
                    | "goose"
                    | "sampled_values"
                    | "opcua_tcp"
                    | "ethercat"
                    | "profinet_rt"
                    | "powerlink"
                    | "stp"
            ) && !e.evidence.spans.is_empty()
            {
                let raw = self.map.materialize(&e.evidence, &self.limits)?;
                let result = if protocol == "iec104" {
                    if let Some(id) = e.session {
                        if !self.iec.contains_key(&id) && self.iec.len() >= self.limits.active {
                            set(
                                &mut own.data,
                                "depth_state_boundary",
                                "active_state_budget".into(),
                            )?;
                            self.iec.clear();
                        }
                        self.iec.entry(id).or_default().observe(
                            e.direction.unwrap_or(0),
                            &raw,
                            &self.limits,
                        )
                    } else {
                        super::decode(protocol, &raw, &self.context, &self.limits)
                    }
                } else {
                    super::decode(protocol, &raw, &self.context, &self.limits)
                };
                set(&mut own.data, "depth_observation", outcome(result))?;
                if protocol == "bacnet_ip" && e.session.is_some() {
                    if let Ok(a) = super::bacnet::apdu(raw.data()) {
                        if a.sequence.is_some() && matches!(a.kind, 0 | 3) {
                            let key =
                                format!("{}:{}", e.session.unwrap_or(0), e.direction.unwrap_or(0));
                            let frame = raw.packets().iter().map(|p| p.frame).max().unwrap_or(0);
                            let s = self.bacnet.push(&key, &raw, frame);
                            let v = match s {
                                Ok(s) => {
                                    let tags = if let Some(ref assembled) = s.completed {
                                        match super::bacnet::tags(assembled.data(), 0, &self.limits)
                                        {
                                            Ok(t) => Json::array(
                                                t.iter().map(|x| x.json(assembled.data())),
                                            ),
                                            Err(err) => outcome(Err(err)),
                                        }
                                    } else {
                                        Json::Null
                                    };
                                    Json::object([("assembly", s.json()), ("service_tags", tags)])
                                }
                                Err(e) => outcome(Err(e)),
                            };
                            set(&mut own.data, "depth_segmentation", v)?;
                        }
                    }
                }
            }
        }
        if e.kind == EventKind::CaptureComplete {
            self.map.finish()?;
            set(
                &mut own.data,
                "depth_complete_protocol_coverage",
                false.into(),
            )?;
        }
        Ok(own)
    }
}
impl EventSink for DeepSink<'_> {
    fn run_id(&self) -> &str {
        self.inner.run_id()
    }
    fn emit(&mut self, event: &Event) -> Result<u64> {
        let own = self.augment(event)?;
        self.inner.emit(&own)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pcap_evidence::provenance::PacketId;
    use pcap_evidence_stream::{events::Evidence, EvidenceStatus};
    use std::time::{SystemTime, UNIX_EPOCH};

    #[derive(Default)]
    struct NullSink {
        emitted: u64,
    }
    impl EventSink for NullSink {
        fn run_id(&self) -> &str {
            "sink-test"
        }
        fn emit(&mut self, _event: &Event) -> Result<u64> {
            self.emitted += 1;
            Ok(self.emitted)
        }
    }

    fn message(frame: u64) -> Event {
        let raw = EvidenceBytes::from_packet(
            &[255; 19],
            PacketId {
                capture: [7; 32],
                frame,
                record_offset: frame * 100,
            },
            54,
        );
        let mut event = Event::new(
            EventKind::Message,
            EvidenceStatus::Candidate,
            Json::object([("complete", true.into())]),
        );
        event.session = Some(9);
        event.direction = Some(0);
        event.protocol = Some("bgp".into());
        event.evidence = Evidence::bytes(&raw);
        event
    }

    fn with_test_sink(limits: Limits, bytes: &[u8], test: impl FnOnce(&mut DeepSink<'_>, &Path)) {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "pcap-depth-sink-omission-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir(&root).unwrap();
        let source = root.join("source.bin");
        std::fs::write(&source, bytes).unwrap();
        let mut inner = NullSink::default();
        let mut sink = DeepSink::new(
            &mut inner,
            File::open(source).unwrap(),
            &root.join("packet.map"),
            4096,
            limits,
            Context::default(),
        )
        .unwrap();
        test(&mut sink, &root);
        drop(sink);
        std::fs::remove_dir_all(root).unwrap();
    }

    fn protocol_issue(session: Option<u64>, protocol: &str) -> Event {
        let mut event = Event::new(
            EventKind::ProtocolIssue,
            EvidenceStatus::Incomplete,
            Json::object([("reason", "synthetic_omission".into())]),
        );
        event.session = session;
        event.protocol = Some(protocol.into());
        event
    }

    fn map_message(sink: &mut DeepSink<'_>, bytes: &[u8]) -> Event {
        let packet = Event::new(
            EventKind::Packet,
            EvidenceStatus::Observed,
            Json::object([
                ("frame", "1".into()),
                ("record_offset", "0".into()),
                ("data_offset", "0".into()),
                ("captured_length", bytes.len().to_string().into()),
                ("packet_sha256", sha256::hex(&sha256::digest(bytes)).into()),
                ("link_type", 228usize.into()),
            ]),
        );
        sink.augment(&packet).unwrap();
        let mut event = message(1);
        event.evidence = Evidence::bytes(&EvidenceBytes::from_packet(
            bytes,
            PacketId {
                capture: sink.map.namespace(),
                frame: 1,
                record_offset: 0,
            },
            0,
        ));
        event
    }

    fn captured_packet(frame: u64, offset: usize, bytes: &[u8], time: Json) -> Event {
        Event::new(
            EventKind::Packet,
            EvidenceStatus::Observed,
            Json::object([
                ("frame", frame.to_string().into()),
                ("record_offset", (frame * 100).to_string().into()),
                ("data_offset", offset.to_string().into()),
                ("captured_length", bytes.len().to_string().into()),
                ("packet_sha256", sha256::hex(&sha256::digest(bytes)).into()),
                ("link_type", 228usize.into()),
                ("timestamp_ns", time),
            ]),
        )
    }

    fn flow_start(session: u64, a: &str, b: &str) -> Event {
        let mut event = Event::new(
            EventKind::FlowStart,
            EvidenceStatus::Candidate,
            Json::object([(
                "key",
                Json::object([
                    ("source_ip", a.into()),
                    ("source_port", 50000usize.into()),
                    ("destination_ip", b.into()),
                    ("destination_port", 179usize.into()),
                    ("transport", "tcp".into()),
                ]),
            )]),
        );
        event.session = Some(session);
        event
    }

    fn normalized(event: &Event) -> &Json {
        get(&event.data, "depth_bgp").unwrap()
    }

    #[test]
    fn captured_metadata_selects_latest_frame_across_reordered_spans_and_sealed_replay() {
        let mut keepalive = vec![255; 16];
        keepalive.extend_from_slice(&[0, 19, 4]);
        let segments = [&keepalive[..5], &keepalive[5..10], &keepalive[10..]];
        // The greatest contributing frame occurs first, middle and last in
        // reconstructed byte order. Neither end of the span list selects time.
        for frame_order in [[3usize, 1, 2], [1, 3, 2], [1, 2, 3]] {
            let mut chunks = [&[][..]; 3];
            for (segment, frame) in segments.iter().zip(frame_order) {
                chunks[frame - 1] = *segment;
            }
            let mut source: Vec<u8> = chunks.iter().flat_map(|c| c.iter().copied()).collect();
            source.push(b'x');
            for latest in [
                Json::from("-50"),
                Json::from("0"),
                Json::from("-9223372036854775808"),
                Json::Null,
                Json::from("9223372036854775808"),
                Json::from("not-a-time"),
            ] {
                with_test_sink(Limits::default(), &source, |sink, root| {
                    let journal = root.join("metadata.journal");
                    sink.enable_bgp_journal(&journal, 8192).unwrap();
                    sink.augment(&flow_start(9, "198.51.100.1", "198.51.100.2"))
                        .unwrap();
                    let times = [Json::from("1000"), Json::from("9000"), latest.clone()];
                    let mut offset = 0;
                    let mut pieces = Vec::new();
                    for (index, chunk) in chunks.iter().enumerate() {
                        let frame = index as u64 + 1;
                        sink.augment(&captured_packet(frame, offset, chunk, times[index].clone()))
                            .unwrap();
                        pieces.push(EvidenceBytes::from_packet(
                            chunk,
                            PacketId {
                                capture: sink.map.namespace(),
                                frame,
                                record_offset: frame * 100,
                            },
                            0,
                        ));
                        offset += chunk.len();
                    }
                    // An unrelated later packet is carried only in packet refs;
                    // it contributes no raw span and must not select message time.
                    sink.augment(&captured_packet(4, offset, b"x", "20000".into()))
                        .unwrap();
                    let mut raw = pieces[frame_order[0] - 1].clone();
                    raw.append(&pieces[frame_order[1] - 1], 4096).unwrap();
                    raw.append(&pieces[frame_order[2] - 1], 4096).unwrap();
                    assert_eq!(raw.data(), keepalive);
                    assert_eq!(
                        raw.spans()
                            .iter()
                            .map(|s| s.packet.frame)
                            .collect::<Vec<_>>(),
                        frame_order.map(|f| f as u64)
                    );
                    let mut event = message(1);
                    event.evidence = Evidence::bytes(&raw);
                    event.evidence.packets.push(PacketId {
                        capture: sink.map.namespace(),
                        frame: 4,
                        record_offset: 400,
                    });
                    let output = sink.augment(&event).unwrap();
                    let expected = match &latest {
                        Json::String(text) if text == "-50" => Some(-50),
                        Json::String(text) if text == "0" => Some(0),
                        Json::String(text) if text == "-9223372036854775808" => Some(i64::MIN),
                        _ => None,
                    };
                    assert_eq!(
                        get(normalized(&output), "observed_at_ns"),
                        Some(&expected.map_or(Json::Null, |t| t.to_string().into()))
                    );
                    assert_eq!(
                        get(normalized(&output), "peer"),
                        Some(&Json::from("198.51.100.1"))
                    );
                    assert_eq!(
                        get(normalized(&output), "local"),
                        Some(&Json::from("198.51.100.2"))
                    );
                    let basis = get(&output.data, "depth_bgp_capture_metadata").unwrap();
                    assert_eq!(
                        get(basis, "time_available"),
                        Some(&Json::Bool(expected.is_some()))
                    );
                    sink.map.verify_source().unwrap();
                    sink.bgp_journal.take().unwrap().seal().unwrap();
                    let archive =
                        super::super::bgp_store::replay(&journal, 8192, Limits::default()).unwrap();
                    assert_eq!(archive.observations.len(), 1);
                    assert_eq!(archive.observations[0].source().observed_at_ns, expected);
                    assert_eq!(
                        archive.observations[0].source().peer.as_deref(),
                        Some("198.51.100.1")
                    );
                    assert_eq!(
                        archive.observations[0].source().local.as_deref(),
                        Some("198.51.100.2")
                    );
                });
            }
        }
    }

    #[test]
    fn captured_endpoint_direction_missing_retention_and_cleanup_controls() {
        let mut keepalive = vec![255; 16];
        keepalive.extend_from_slice(&[0, 19, 4]);
        with_test_sink(Limits::default(), &keepalive, |sink, _| {
            let original = map_message(sink, &keepalive);
            sink.augment(&flow_start(9, "198.51.100.1", "198.51.100.2"))
                .unwrap();
            for (direction, expected) in [
                (Some(0), Some(("198.51.100.1", "198.51.100.2"))),
                (Some(1), Some(("198.51.100.2", "198.51.100.1"))),
                (None, None),
                (Some(2), None),
            ] {
                let mut event = original.clone();
                event.direction = direction;
                let output = sink.augment(&event).unwrap();
                if direction == Some(2) {
                    assert_eq!(
                        get(normalized(&output), "status"),
                        Some(&Json::from("rejected"))
                    );
                } else {
                    assert_eq!(
                        get(normalized(&output), "peer"),
                        Some(&expected.map_or(Json::Null, |e| e.0.into()))
                    );
                    assert_eq!(
                        get(normalized(&output), "local"),
                        Some(&expected.map_or(Json::Null, |e| e.1.into()))
                    );
                }
                assert_eq!(
                    get(
                        get(&output.data, "depth_bgp_capture_metadata").unwrap(),
                        "endpoints_available"
                    ),
                    Some(&Json::Bool(expected.is_some()))
                );
            }
            let mut other_session = original.clone();
            other_session.session = Some(11);
            let output = sink.augment(&other_session).unwrap();
            assert_eq!(get(normalized(&output), "peer"), Some(&Json::Null));
            assert_eq!(get(normalized(&output), "local"), Some(&Json::Null));
            assert_eq!(
                get(normalized(&output), "observed_at_ns"),
                Some(&Json::Null)
            );
            for kind in [EventKind::FlowEnd, EventKind::Boundary] {
                let mut end = protocol_issue(Some(9), "bgp");
                end.kind = kind;
                sink.augment(&end).unwrap();
                let output = sink.augment(&original).unwrap();
                assert_eq!(get(normalized(&output), "peer"), Some(&Json::Null));
                // End the synthetic unavailable occurrence before ID reuse.
                let mut occurrence_end = end.clone();
                occurrence_end.kind = EventKind::FlowEnd;
                sink.augment(&occurrence_end).unwrap();
                sink.augment(&flow_start(9, "2001:db8::1", "2001:db8::2"))
                    .unwrap();
                let output = sink.augment(&original).unwrap();
                assert_eq!(
                    get(normalized(&output), "peer"),
                    Some(&Json::from("2001:db8::1"))
                );
                assert_eq!(
                    get(normalized(&output), "local"),
                    Some(&Json::from("2001:db8::2"))
                );
            }
            let mut end = protocol_issue(Some(9), "bgp");
            end.kind = EventKind::FlowEnd;
            sink.augment(&end).unwrap();
            // Retention pressure on non-BGP flow starts preserves progress and
            // explicitly leaves skipped sessions unavailable, without borrowing.
            sink.flow_endpoints.clear();
            sink.limits.elements = 1;
            sink.augment(&flow_start(10, "192.0.2.1", "192.0.2.2"))
                .unwrap();
            sink.augment(&flow_start(9, "198.51.100.1", "198.51.100.2"))
                .unwrap();
            assert_eq!(sink.flow_endpoints.len(), 1);
            sink.limits.elements = Limits::default().elements;
            let output = sink.augment(&original).unwrap();
            assert_eq!(get(normalized(&output), "peer"), Some(&Json::Null));
            assert_eq!(
                get(
                    get(&output.data, "depth_bgp_capture_metadata").unwrap(),
                    "endpoints_available"
                ),
                Some(&Json::Bool(false))
            );
            sink.augment(&flow_start(9, "invalid", "198.51.100.2"))
                .unwrap();
            assert!(!sink.flow_endpoints.contains_key(&9));
        });
    }

    #[test]
    fn packet_map_exact_disk_budget_and_one_below_include_capture_time() {
        with_test_sink(Limits::default(), b"ab", |_, root| {
            for budget in [ROW as u64 * 2, ROW as u64 * 2 - 1] {
                let path = root.join(format!("bounded-{budget}.map"));
                let mut map = PacketMap::create(
                    File::open(root.join("source.bin")).unwrap(),
                    &path,
                    budget,
                    "run",
                )
                .unwrap();
                map.record(&captured_packet(1, 0, b"a", "0".into()))
                    .unwrap();
                let result = map.record(&captured_packet(2, 1, b"b", "-1".into()));
                if budget == ROW as u64 * 2 {
                    result.unwrap();
                    assert_eq!(std::fs::metadata(&path).unwrap().len(), budget);
                } else {
                    assert_eq!(result.unwrap_err().field, "depth_packet_map_disk");
                    assert_eq!(std::fs::metadata(&path).unwrap().len(), ROW as u64);
                    assert_eq!(map.rows, 1);
                }
            }
        });
    }

    #[test]
    fn bgp_protocol_issue_scope_pending_and_identical_replay() {
        with_test_sink(Limits::default(), &[], |sink, _| {
            let mut iec = super::super::iec104::Session::default();
            iec.active = Some(true);
            sink.iec.insert(9, iec);
            let iec_before = sink.iec[&9].json();
            // Non-BGP and sessionless issues cannot supply managed BGP scope.
            sink.augment(&protocol_issue(Some(9), "dnp3")).unwrap();
            sink.augment(&protocol_issue(None, "bgp")).unwrap();
            assert_eq!(sink.bgp_pending_count, 0);
            assert_eq!(sink.bgp.active_sessions(), 0);

            // A known session needs no invented direction. Before its first
            // BGP message, keep the exact boundary without allocating state.
            let issue = protocol_issue(Some(9), "bgp");
            let record_id = event_record_id(&issue, sink.inner.run_id(), &sink.limits).unwrap();
            sink.augment(&issue).unwrap();
            assert_eq!(sink.iec[&9].json(), iec_before);
            assert_eq!(sink.bgp_pending_count, 1);
            assert_eq!(sink.bgp_pending_boundaries[&9][0].0, record_id);
            assert_eq!(sink.bgp.active_sessions(), 0);
            sink.prepare_bgp_session(9, "first-message").unwrap();
            sink.bgp_seen.insert(9);
            let replay = sink.augment(&issue).unwrap();
            assert_eq!(sink.bgp.summary(9).unwrap().gaps, 1);
            assert_eq!(sink.bgp.summary(9).unwrap().generation, 0);
            assert_eq!(
                get(get(&replay.data, "depth_bgp_boundary").unwrap(), "replayed"),
                Some(&Json::Bool(true))
            );
            assert_eq!(sink.iec[&9].json(), iec_before);
            let mut transport_gap = issue;
            transport_gap.kind = EventKind::StreamGap;
            sink.augment(&transport_gap).unwrap();
            assert!(sink.iec[&9].tainted);
            assert_eq!(sink.iec[&9].active, None);
        });
    }

    #[test]
    fn bgp_boundary_admission_failure_is_fatal_and_atomic() {
        for kind in [
            EventKind::ProtocolIssue,
            EventKind::StreamGap,
            EventKind::StreamConflict,
        ] {
            let limits = Limits {
                elements: 1,
                ..Limits::default()
            };
            with_test_sink(limits, &[], |sink, root| {
                sink.enable_bgp_journal(&root.join("bgp.journal.partial"), 4096)
                    .unwrap();
                sink.bgp
                    .observe_gap(9, "first-gap".into(), "observed_gap".into())
                    .unwrap();
                sink.bgp_seen.insert(9);
                let mut event = protocol_issue(Some(9), "bgp");
                event.kind = kind;
                let error = sink.augment(&event).unwrap_err();
                assert_eq!(error.code, ErrorCode::LimitExceeded);
                assert_eq!(sink.bgp.summary(9).unwrap().gaps, 1);
                assert_eq!(sink.bgp.summary(9).unwrap().generation, 0);
            });
        }
    }

    #[test]
    fn bgp_preparation_failure_is_fatal_before_message_rejection() {
        let mut keepalive = vec![255; 16];
        keepalive.extend_from_slice(&[0, 19, 4]);
        let limits = Limits {
            elements: 1,
            ..Limits::default()
        };
        with_test_sink(limits, &keepalive, |sink, root| {
            sink.enable_bgp_journal(&root.join("bgp.journal.partial"), 4096)
                .unwrap();
            assert!(sink
                .retain_or_apply_bgp_boundary(9, "retained-gap".into(), "observed_gap".into())
                .is_none());
            assert!(sink
                .retain_or_apply_bgp_boundary(9, "overflow-gap".into(), "observed_gap".into())
                .is_none());
            assert!(sink.bgp_pending_overflow);
            let event = map_message(sink, &keepalive);
            let error = sink.augment(&event).unwrap_err();
            assert_eq!(error.code, ErrorCode::LimitExceeded);
            // Admission may retain the first gap, but cannot publish a rejected
            // source message or allow the owning analyze caller to seal.
            let summary = sink.bgp.summary(9).unwrap();
            assert_eq!(summary.gaps, 1);
            assert_eq!(summary.session_events, 1);
            assert_eq!(summary.generation, 0);
        });
    }

    #[test]
    fn bgp_message_capacity_failure_propagates_through_event_sink() {
        let mut keepalive = vec![255; 16];
        keepalive.extend_from_slice(&[0, 19, 4]);
        for active in [1, 2] {
            let limits = Limits {
                active,
                ..Limits::default()
            };
            with_test_sink(limits, &keepalive, |sink, root| {
                let partial = root.join("bgp.journal.partial");
                sink.enable_bgp_journal(&partial, 4096).unwrap();
                let first = map_message(sink, &keepalive);
                // Packet mapping uses augment directly. This public emit must
                // be the first event actually forwarded to the inner sink.
                assert_eq!(EventSink::emit(sink, &first).unwrap(), 1);
                let before = sink.bgp.snapshot(9).unwrap();
                assert_eq!(before.summary.session_events, 1);
                assert_eq!(before.summary.gaps, 0);
                let mut second = first.clone();
                second.session = Some(10);
                if active == 1 {
                    let error = EventSink::emit(sink, &second).unwrap_err();
                    assert_eq!(error.code, ErrorCode::LimitExceeded);
                    assert_eq!(error.field, "bgp_manager_active_sessions");
                    assert_eq!(sink.bgp.snapshot(9).unwrap(), before);
                    assert!(!sink.bgp.contains(10));
                    assert_eq!(sink.bgp.active_sessions(), 1);
                    // The attempted source MESSAGE precedes manager admission
                    // in the journal. It remains unsealed recovery evidence;
                    // no caller here requests finish after the producer error.
                    assert!(partial.is_file());
                    assert!(!root.join("bgp.journal").exists());
                    let raw = std::fs::read(&partial).unwrap();
                    assert!(raw.len() < 4096);
                    assert_eq!(&raw[..8], b"PCBGP001");
                    // v1: fixed header, length-prefixed source label, then
                    // 73-byte record envelopes. The body starts with session.
                    let source_len = u32::from_le_bytes(raw[42..46].try_into().unwrap());
                    let mut offset = 46 + source_len as usize;
                    let mut scopes = Vec::new();
                    while offset < raw.len() {
                        assert_eq!(raw[offset], 1, "only raw MESSAGE carriers are retained");
                        let size =
                            u64::from_le_bytes(raw[offset + 1..offset + 9].try_into().unwrap());
                        scopes.push(u64::from_le_bytes(
                            raw[offset + 73..offset + 81].try_into().unwrap(),
                        ));
                        offset += 73 + size as usize;
                    }
                    assert_eq!(offset, raw.len());
                    assert_eq!(scopes, [9, 10]);
                    let error = super::super::bgp_store::replay(&partial, 4096, Limits::default())
                        .unwrap_err();
                    assert_eq!(error.code, ErrorCode::Truncated);
                    assert_eq!(error.field, "bgp_journal_record");
                    // Identical replay is still accepted. The returned inner
                    // count proves the failed second event was not forwarded.
                    assert_eq!(EventSink::emit(sink, &first).unwrap(), 2);
                    assert_eq!(sink.bgp.snapshot(9).unwrap(), before);
                } else {
                    assert_eq!(EventSink::emit(sink, &second).unwrap(), 2);
                    assert_eq!(sink.bgp.active_sessions(), 2);
                    assert_eq!(sink.bgp.snapshot(9).unwrap(), before);
                    assert_eq!(sink.bgp.summary(10).unwrap().session_events, 1);
                    assert_eq!(sink.bgp.summary(10).unwrap().gaps, 0);
                    sink.map.verify_source().unwrap();
                    sink.bgp_journal.take().unwrap().seal().unwrap();
                    let archive =
                        super::super::bgp_store::replay(&partial, 4096, Limits::default()).unwrap();
                    assert_eq!(archive.sessions.len(), 2);
                    assert_eq!(archive.messages, 2);
                    assert_eq!(archive.boundaries, 0);
                    assert_eq!(archive.rejected_records, 0);
                }
            });
        }
    }

    #[test]
    fn record_identity_is_replay_stable_but_occurrence_specific() {
        let limits = Limits::default();
        let first = message(1);
        let second = message(2);
        let original = event_record_id(&first, "run", &limits).unwrap();

        assert_eq!(
            original,
            event_record_id(&first.clone(), "run", &limits).unwrap()
        );
        assert_ne!(original, event_record_id(&second, "run", &limits).unwrap());
    }

    #[test]
    fn preclassification_boundaries_do_not_consume_bgp_session_capacity() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "pcap-depth-sink-boundary-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir(&root).unwrap();
        let source_path = root.join("source.pcap");
        let map_path = root.join("packet.map");
        std::fs::write(&source_path, []).unwrap();
        let source = File::open(&source_path).unwrap();
        let mut inner = NullSink::default();
        let mut sink = DeepSink::new(
            &mut inner,
            source,
            &map_path,
            4096,
            Limits::default(),
            Context::default(),
        )
        .unwrap();

        assert!(sink
            .retain_or_apply_bgp_boundary(7, "gap-7".into(), "test gap".into())
            .is_none());
        assert_eq!(sink.bgp.active_sessions(), 0);
        assert_eq!(sink.bgp_pending_count, 1);

        sink.prepare_bgp_session(7, "message-7").unwrap();
        assert_eq!(sink.bgp.active_sessions(), 1);
        assert_eq!(sink.bgp.summary(7).unwrap().gaps, 1);
        assert_eq!(sink.bgp_pending_count, 0);

        drop(sink);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn complete_capture_namespace_is_reverified_before_publication() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "pcap-depth-source-identity-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir(&root).unwrap();
        let source_path = root.join("source.pcap");
        let map_path = root.join("packet.map");
        std::fs::write(&source_path, b"original capture").unwrap();
        let source = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&source_path)
            .unwrap();
        let mut map = PacketMap::create(source, &map_path, 4096, "run").unwrap();
        assert_eq!(map.namespace(), sha256::digest(b"original capture"));
        std::fs::write(&source_path, b"changed capture!").unwrap();
        let error = map.verify_source().unwrap_err();
        assert_eq!(error.code, ErrorCode::SourceMismatch);
        drop(map);
        std::fs::remove_dir_all(root).unwrap();
    }
}
