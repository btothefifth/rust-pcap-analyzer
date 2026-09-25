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
const ROW: usize = 64;

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
        if matches!(e.kind, EventKind::StreamGap | EventKind::StreamConflict) {
            if let Some(id) = e.session {
                if let Some(s) = self.iec.get_mut(&id) {
                    s.gap();
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
                    set(
                        &mut own.data,
                        "depth_bgp_boundary",
                        bgp_boundary_json(&record_id, result),
                    )?;
                }
                self.dnp_file.reset_session(id);
            }
        }
        if e.kind == EventKind::FlowEnd {
            if let Some(id) = e.session {
                if let Some(mut s) = self.iec.remove(&id) {
                    s.gap();
                }
                self.dnp_file.reset_session(id);
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
                let metadata = super::bgp::PcapMetadata {
                    source_id: self.inner.run_id().to_owned(),
                    record_id: record_id.clone(),
                    observed_at_ns: None,
                    session: e.session,
                    direction: e.direction,
                    peer: None,
                    local: None,
                };
                if let Some(id) = e.session {
                    let first_bgp_message = self.bgp_seen.insert(id);
                    if first_bgp_message {
                        self.journal_bgp_preparation(id, &record_id)?;
                    }
                    if let Some(journal) = self.bgp_journal.as_mut() {
                        journal.message(id, &raw, &metadata)?;
                    }
                    let result = (if first_bgp_message {
                        self.prepare_bgp_session(id, &record_id)
                    } else {
                        Ok(())
                    })
                    .and_then(|()| self.bgp.apply_message(id, &raw, metadata));
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
                        Err(error) => {
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

    struct NullSink;
    impl EventSink for NullSink {
        fn run_id(&self) -> &str {
            "sink-test"
        }
        fn emit(&mut self, _event: &Event) -> Result<u64> {
            Ok(1)
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
        let mut inner = NullSink;
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
