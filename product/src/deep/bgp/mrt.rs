//! Capability-safe replay of BGP messages embedded in MRT BGP4MP records.
//!
//! MRT records remain the source of truth. This adapter reuses the same BGP
//! OPEN and UPDATE parsers as packet-derived evidence and never manufactures
//! packet IDs or captured-evidence carriers.
use super::super::bgp_import::{
    ClockPolicy, ImportContext, ImportContinuityCut, ImportPartition, ImportedSourceEventKind,
    ObservationClock, SourceBatch, SourceRange,
};
use super::super::bgp_mrt::{Bgp4mp, Bgp4mpPayload, MrtBatch, MrtBody, MrtRecord};
use super::*;
use pcap_evidence::{json::Json, Error, ErrorCode, Result};
use std::collections::BTreeMap;

#[derive(Default)]
pub(crate) struct ReplayState {
    sessions: Vec<ImportedSession>,
    peer_relationship: Option<PeerRelationship>,
    // Exact source scopes observed by the decoder, independent of route admission.
    continuity_contexts: BTreeMap<(String, ImportPartition), (ImportContext, usize)>,
    pending_cuts: BTreeMap<(String, Option<u8>), PendingContinuityCut>,
    continuity_retained: usize,
}

impl ReplayState {
    /// Logical aggregate session retention. Per-session parser caps remain in
    /// force; streaming consumers also enforce one aggregate retained ceiling.
    pub(crate) fn retained_bytes(&self, limits: &Limits) -> Result<usize> {
        let mut bytes = self
            .sessions
            .capacity()
            .checked_mul(std::mem::size_of::<ImportedSession>())
            .ok_or_else(|| Error::limit("bgp_mrt_sessions_retained"))?;
        bytes = bytes
            .checked_add(self.continuity_retained)
            .ok_or_else(|| Error::limit("bgp_mrt_sessions_retained"))?;
        for session in &self.sessions {
            let identity = &session.identity;
            let add = session.id.capacity()
                + identity.source_id.capacity()
                + identity.checkpoint_id.capacity()
                + identity.peer_address.capacity()
                + identity.local_address.capacity();
            bytes = bytes
                .checked_add(add)
                .ok_or_else(|| Error::limit("bgp_mrt_sessions_retained"))?;
            for opens in session.decoder.opens.values() {
                bytes = bytes
                    .checked_add(opens.capacity() * std::mem::size_of::<OpenState>())
                    .ok_or_else(|| Error::limit("bgp_mrt_sessions_retained"))?;
                for open in opens {
                    let add = super::super::bgp_mrt_stream_store::json_memory(&open.witness.value)
                        + open.capabilities.mp.len() * 48
                        + open.capabilities.add_path.len() * 64
                        + open.capability_issues.capacity() * std::mem::size_of::<&str>();
                    bytes = bytes
                        .checked_add(add)
                        .ok_or_else(|| Error::limit("bgp_mrt_sessions_retained"))?;
                }
            }
        }
        if bytes > limits.retained_bytes {
            return Err(Error::limit("bgp_mrt_sessions_retained"));
        }
        Ok(bytes)
    }

    pub(crate) fn with_peer_relationship(peer_relationship: Option<PeerRelationship>) -> Self {
        Self {
            sessions: Vec::new(),
            peer_relationship,
            continuity_contexts: BTreeMap::new(),
            pending_cuts: BTreeMap::new(),
            continuity_retained: 0,
        }
    }

    /// Carry negative continuity across later exact header enrichment, while
    /// retaining the original source witness and the decoder's real generation.
    pub(crate) fn continuity_cuts(
        &mut self,
        batch: &MrtBatch,
        record_index: usize,
        record: &MrtRecord,
        event: &Json,
        opaque_gap: Option<&ImportContinuityCut>,
        limits: &Limits,
    ) -> Result<(Vec<ImportContinuityCut>, usize)> {
        self.retained_bytes(limits)?;
        // Retention walks JSON nodes and reads string/capacity lengths; it does
        // not scan or serialize every retained OPEN byte on every record.
        let mut work = self
            .retention_scan_work()?
            .checked_mul(2)
            .filter(|n| *n <= limits.work)
            .ok_or_else(|| Error::limit("bgp_mrt_gap_work"))?;
        let session = event_text(event, "session");
        let generation = event_number(event, "generation");
        let mut discovered = None;
        if let (Some(session), Some(generation)) = (session, generation) {
            let recovered;
            let outer = match &record.body {
                MrtBody::Bgp4mp(outer) => Some(outer),
                MrtBody::Opaque {
                    reason: "malformed_bgp4mp_record",
                    ..
                } => {
                    recovered = super::super::bgp_mrt::malformed_bgp4mp_scope(record)?;
                    recovered.as_ref()
                }
                _ => None,
            };
            if let (Some(outer), Some(index)) = (
                outer,
                self.sessions.iter().position(|known| known.id == session),
            ) {
                let next = self.sessions[index].decoder.generation();
                let mut context = import_context(
                    RecordContext::new(batch, record_index, record, outer).event(
                        session,
                        Some(u8::from(outer.locally_generated)),
                        generation,
                    ),
                    record_source_range(record)?,
                    limits,
                )?;
                context.generation = next;
                context.direction = None;
                let key = (context.session.clone(), context.partition());
                let old_bytes = self.continuity_contexts.get(&key).map_or(0, |(_, n)| *n);
                if old_bytes == 0 && self.continuity_contexts.len() >= limits.elements {
                    return Err(Error::limit("bgp_mrt_continuity_contexts"));
                }
                let bytes = super::super::bgp_mrt_stream_store::json_memory(&context.json())
                    .checked_add(super::super::bgp_mrt_stream_store::json_memory(
                        &context.partition().json(),
                    ))
                    .and_then(|n| n.checked_add(context.session.len()))
                    .ok_or_else(|| Error::limit("bgp_mrt_continuity_retained"))?;
                self.admit_continuity_retained(old_bytes, bytes, limits, &mut work)?;
                charge_cut_work(&mut work, bytes, limits)?;
                if old_bytes == 0 {
                    discovered = Some(key.clone());
                }
                self.continuity_retained = self.continuity_retained - old_bytes + bytes;
                self.continuity_contexts.insert(key, (context, bytes));
                // Only an actual generation advance retires pending negative
                // evidence. ASN/interface enrichment is not a fresh generation.
                if self.sessions[index]
                    .continuity_generation
                    .is_some_and(|old| old != next)
                {
                    for ((known, _), (context, _)) in &mut self.continuity_contexts {
                        charge_cut_work(&mut work, known.len() + 1, limits)?;
                        if known == session {
                            context.generation = next;
                        }
                    }
                    for direction in [None, Some(0), Some(1)] {
                        if let Some(old) =
                            self.pending_cuts.remove(&(session.to_owned(), direction))
                        {
                            self.continuity_retained -= old.retained_bytes(session);
                        }
                    }
                }
                self.sessions[index].continuity_generation = Some(next);
            }
        }
        let status = event_text(event, "parse_status").unwrap_or("");
        let rejected = status != "quarantined_session_reset"
            && (status == "rejected" || status.starts_with("quarantined"));
        let affected = if rejected
            && matches!(
                status,
                "quarantined_ambiguous_session" | "quarantined_coverage_unknown"
            ) {
            match event_value(event, "detail")
                .and_then(|detail| event_value(detail, "affected_scopes"))
            {
                Some(Json::Array(scopes)) if scopes.len() <= limits.elements => Some(scopes),
                _ => {
                    return Err(bad(
                        "bgp_mrt_gap_scope",
                        record_index,
                        "affected scopes invalid",
                    ))
                }
            }
        } else {
            None
        };
        let original = PendingContinuityCut {
            generation: generation.unwrap_or(0),
            direction: None,
            record_id: format!("mrt-bgp4mp-quarantine:{record_index}:{}", record.sha256),
            reason: format!("source_message_{status}"),
            provenance: record_source_range(record)?,
        };
        let opaque_original = if let Some(gap) = opaque_gap {
            let provenance = gap.context.provenance.first().ok_or_else(|| {
                bad(
                    "bgp_mrt_gap_scope",
                    record_index,
                    "opaque gap witness absent",
                )
            })?;
            let bytes = gap
                .record_id
                .len()
                .checked_add(gap.reason.len())
                .and_then(|n| n.checked_add(provenance.sha256.as_ref().map_or(0, String::len)))
                .and_then(|n| n.checked_add(std::mem::size_of::<PendingContinuityCut>()))
                .ok_or_else(|| Error::limit("bgp_mrt_gap_retained"))?;
            self.admit_continuity_retained(0, bytes, limits, &mut work)?;
            charge_cut_work(&mut work, bytes, limits)?;
            Some(PendingContinuityCut {
                generation: gap.context.generation,
                direction: gap.context.direction,
                record_id: gap.record_id.clone(),
                reason: gap.reason.clone(),
                provenance: provenance.clone(),
            })
        } else {
            None
        };
        let mut cuts = Vec::new();
        let mut cut_bytes = 0usize;
        let mut pending = Vec::new();
        let mut pending_bytes = 0usize;
        for (key @ (known, _), (context, bytes)) in &self.continuity_contexts {
            charge_cut_work(&mut work, known.len() + 1, limits)?;
            let selected = rejected
                && if let Some(scopes) = affected {
                    charge_cut_work(&mut work, scopes.len(), limits)?;
                    scopes.iter().any(|scope| {
                        event_text(scope, "session") == Some(known.as_str())
                            && event_number(scope, "generation") == Some(context.generation)
                    })
                } else {
                    session == Some(known.as_str()) && generation == Some(context.generation)
                };
            let inherit_scope = discovered.as_ref() == Some(key) && !self.pending_cuts.is_empty();
            if inherit_scope {
                // Only three directions can be admitted. Account the temporary
                // lookup key and each probe/copy before cloning session bytes.
                let key_bytes = known
                    .len()
                    .checked_add(std::mem::size_of::<(String, Option<u8>)>())
                    .ok_or_else(|| Error::limit("bgp_mrt_gap_retained"))?;
                self.admit_continuity_retained(
                    0,
                    cut_bytes
                        .checked_add(pending_bytes)
                        .and_then(|n| n.checked_add(key_bytes))
                        .ok_or_else(|| Error::limit("bgp_mrt_gap_retained"))?,
                    limits,
                    &mut work,
                )?;
                let probe_bytes = known
                    .len()
                    .checked_add(1)
                    .and_then(|n| n.checked_mul(3))
                    .ok_or_else(|| Error::limit("bgp_mrt_gap_work"))?;
                charge_cut_work(&mut work, probe_bytes, limits)?;
            }
            let inherited = [None, Some(0), Some(1)]
                .into_iter()
                .filter_map(|direction| {
                    if !inherit_scope {
                        return None;
                    }
                    self.pending_cuts
                        .get(&(known.clone(), direction))
                        .filter(|cut| cut.generation == context.generation)
                });
            // The observation owns the original partition's initial Gap.
            // Every other already known metadata partition must receive the
            // same cut now, including partitions seen only by route-free rows.
            let opaque_selected = opaque_gap.is_some_and(|gap| {
                context.session == gap.context.session
                    && context.generation == gap.context.generation
                    && context.partition() != gap.context.partition()
            });
            for origin in selected
                .then_some(&original)
                .into_iter()
                .chain(inherited)
                .chain(
                    opaque_selected
                        .then_some(opaque_original.as_ref())
                        .flatten(),
                )
            {
                let new_bytes = bytes
                    .checked_add(origin.record_id.len())
                    .and_then(|n| n.checked_add(origin.reason.len()))
                    .ok_or_else(|| Error::limit("bgp_mrt_gap_retained"))?;
                cut_bytes = cut_bytes
                    .checked_add(new_bytes)
                    .filter(|n| *n <= limits.retained_bytes)
                    .ok_or_else(|| Error::limit("bgp_mrt_gap_retained"))?;
                self.admit_continuity_retained(
                    0,
                    cut_bytes
                        .checked_add(pending_bytes)
                        .ok_or_else(|| Error::limit("bgp_mrt_gap_retained"))?,
                    limits,
                    &mut work,
                )?;
                if cuts.len() >= limits.elements {
                    return Err(Error::limit("bgp_mrt_gap_scope"));
                }
                charge_cut_work(&mut work, new_bytes, limits)?;
                let mut cut = context.clone();
                cut.direction = origin.direction;
                cut.provenance = vec![origin.provenance.clone()];
                cuts.try_reserve(1)
                    .map_err(|_| Error::limit("bgp_mrt_gap_scope"))?;
                cuts.push(ImportContinuityCut {
                    context: cut,
                    record_id: origin.record_id.clone(),
                    reason: origin.reason.clone(),
                });
            }
            let pending_key = (known.clone(), None);
            if selected
                && !self.pending_cuts.contains_key(&pending_key)
                && !pending.iter().any(|(key, _)| key == &pending_key)
            {
                let mut origin = original.clone();
                origin.generation = context.generation;
                pending_bytes = pending_bytes
                    .checked_add(origin.retained_bytes(known))
                    .ok_or_else(|| Error::limit("bgp_mrt_gap_retained"))?;
                self.admit_continuity_retained(
                    0,
                    pending_bytes
                        .checked_add(cut_bytes)
                        .ok_or_else(|| Error::limit("bgp_mrt_gap_retained"))?,
                    limits,
                    &mut work,
                )?;
                pending
                    .try_reserve(1)
                    .map_err(|_| Error::limit("bgp_mrt_gap_scope"))?;
                pending.push((pending_key, origin));
            }
        }
        // The checked normalized observation remains the initial Gap owner.
        // Retain its exact directional cut only for later exact partitions.
        if let Some(gap) = opaque_gap {
            let context = &gap.context;
            let key = (context.session.clone(), context.direction);
            if !self.pending_cuts.contains_key(&key) {
                let provenance = context.provenance.first().ok_or_else(|| {
                    bad(
                        "bgp_mrt_gap_scope",
                        record_index,
                        "opaque gap witness absent",
                    )
                })?;
                let bytes = context.session.len()
                    + gap.record_id.len()
                    + gap.reason.len()
                    + provenance.sha256.as_ref().map_or(0, String::len)
                    + std::mem::size_of::<PendingContinuityCut>();
                pending_bytes = pending_bytes
                    .checked_add(bytes)
                    .ok_or_else(|| Error::limit("bgp_mrt_gap_retained"))?;
                self.admit_continuity_retained(
                    0,
                    pending_bytes
                        .checked_add(cut_bytes)
                        .ok_or_else(|| Error::limit("bgp_mrt_gap_retained"))?,
                    limits,
                    &mut work,
                )?;
                pending
                    .try_reserve(1)
                    .map_err(|_| Error::limit("bgp_mrt_gap_scope"))?;
                pending.push((
                    key,
                    PendingContinuityCut {
                        generation: context.generation,
                        direction: context.direction,
                        record_id: gap.record_id.clone(),
                        reason: gap.reason.clone(),
                        provenance: provenance.clone(),
                    },
                ));
            }
        }
        for (session, origin) in pending {
            let bytes = origin.retained_bytes(&session.0);
            if self.pending_cuts.len() >= limits.elements {
                return Err(Error::limit("bgp_mrt_gap_scope"));
            }
            self.admit_continuity_retained(0, bytes + cut_bytes, limits, &mut work)?;
            charge_cut_work(&mut work, bytes, limits)?;
            self.continuity_retained += bytes;
            self.pending_cuts.insert(session, origin);
        }
        Ok((cuts, work))
    }

    /// Project only an event just produced by this decoder, using its admitted
    /// session identity and the parsed outer record. No external event JSON is
    /// accepted by this internal replay seam.
    pub(crate) fn source_context(
        &self,
        batch: &MrtBatch,
        record_index: usize,
        record: &MrtRecord,
        event: &Json,
        limits: &Limits,
    ) -> Result<Option<ImportContext>> {
        let (Some(session), Some(generation)) = (
            event_text(event, "session"),
            event_number(event, "generation"),
        ) else {
            return Ok(None);
        };
        if matches!(
            event_text(event, "parse_status"),
            Some("quarantined_ambiguous_session" | "quarantined_coverage_unknown")
        ) {
            return Ok(None);
        }
        let recovered;
        let outer = match &record.body {
            MrtBody::Bgp4mp(outer) => Some(outer),
            MrtBody::Opaque {
                reason: "malformed_bgp4mp_record",
                ..
            } => {
                recovered = super::super::bgp_mrt::malformed_bgp4mp_scope(record)?;
                recovered.as_ref()
            }
            _ => None,
        };
        let Some(outer) = outer else {
            return Ok(None);
        };
        let direction = event_number(event, "direction").and_then(|n| u8::try_from(n).ok());
        let mut context = import_context(
            RecordContext::new(batch, record_index, record, outer).event(
                session,
                Some(u8::from(outer.locally_generated)),
                generation,
            ),
            record_source_range(record)?,
            limits,
        )?;
        context.direction = direction;
        context.validate(limits)?;
        Ok(Some(context))
    }

    pub(crate) fn source_event_kind(
        &self,
        record: &MrtRecord,
        event: &Json,
        boundary: bool,
        selected: bool,
    ) -> ImportedSourceEventKind {
        use ImportedSourceEventKind as Kind;
        let state_advanced = selected
            && matches!(&record.body, MrtBody::Bgp4mp(outer)
            if matches!(&outer.payload, Bgp4mpPayload::State { old, new }
                if *new == 1 || (*old == 4 && *new == 3)
                    || matches!(event_text(event, "parse_status"), Some("rejected" | "quarantined"))));
        if boundary
            || state_advanced
            || matches!(
                event_text(event, "parse_status"),
                Some("decoded_notification_reset" | "quarantined_session_reset")
            )
        {
            return Kind::GenerationBoundary;
        }
        if event_text(event, "parse_status").is_some_and(|status| {
            status == "rejected"
                || status.starts_with("quarantined")
                || status == "opaque_update_continuity_gap"
        }) {
            return Kind::ContinuityGap;
        }
        match &record.body {
            MrtBody::Bgp4mp(outer) => match &outer.payload {
                Bgp4mpPayload::State { .. } => Kind::SessionMetadata,
                Bgp4mpPayload::Message(bytes) => match bytes.get(18) {
                    Some(1) => Kind::Open,
                    Some(2) => Kind::Update,
                    Some(3) => Kind::Notification,
                    Some(4) => Kind::Keepalive,
                    Some(5) => Kind::RouteRefresh,
                    _ => Kind::Opaque,
                },
            },
            _ => Kind::Opaque,
        }
    }

    fn retention_scan_work(&self) -> Result<usize> {
        fn nodes(value: &Json) -> Result<usize> {
            let mut total = 1usize;
            match value {
                Json::Array(values) => {
                    for value in values {
                        total = total
                            .checked_add(nodes(value)?)
                            .ok_or_else(|| Error::limit("bgp_mrt_gap_work"))?;
                    }
                }
                Json::Object(values) => {
                    for (_, value) in values {
                        total = total
                            .checked_add(nodes(value)?)
                            .ok_or_else(|| Error::limit("bgp_mrt_gap_work"))?;
                    }
                }
                _ => {}
            }
            Ok(total)
        }
        let mut work = self
            .sessions
            .len()
            .checked_mul(16)
            .ok_or_else(|| Error::limit("bgp_mrt_gap_work"))?;
        for session in &self.sessions {
            work = work
                .checked_add(session.decoder.opens.len())
                .ok_or_else(|| Error::limit("bgp_mrt_gap_work"))?;
            for open in session.decoder.opens.values().flatten() {
                work = work
                    .checked_add(nodes(&open.witness.value)?)
                    .and_then(|n| n.checked_add(8))
                    .ok_or_else(|| Error::limit("bgp_mrt_gap_work"))?;
            }
        }
        Ok(work)
    }

    fn admit_continuity_retained(
        &self,
        old: usize,
        new: usize,
        limits: &Limits,
        work: &mut usize,
    ) -> Result<()> {
        *work = work
            .checked_add(
                self.retention_scan_work()?
                    .checked_mul(2)
                    .ok_or_else(|| Error::limit("bgp_mrt_gap_work"))?,
            )
            .filter(|n| *n <= limits.work)
            .ok_or_else(|| Error::limit("bgp_mrt_gap_work"))?;
        self.retained_bytes(limits)?
            .checked_sub(old)
            .and_then(|n| n.checked_add(new))
            .filter(|n| *n <= limits.retained_bytes)
            .ok_or_else(|| Error::limit("bgp_mrt_continuity_retained"))?;
        Ok(())
    }
}

#[derive(Clone)]
struct PendingContinuityCut {
    generation: u64,
    direction: Option<u8>,
    record_id: String,
    reason: String,
    provenance: SourceRange,
}
impl PendingContinuityCut {
    fn retained_bytes(&self, session: &str) -> usize {
        session.len()
            + self.record_id.len()
            + self.reason.len()
            + self.provenance.sha256.as_ref().map_or(0, String::len)
            + std::mem::size_of::<Self>()
    }
}
fn charge_cut_work(work: &mut usize, bytes: usize, limits: &Limits) -> Result<()> {
    *work = work
        .checked_add(
            bytes
                .checked_mul(8)
                .ok_or_else(|| Error::limit("bgp_mrt_gap_work"))?,
        )
        .filter(|n| *n <= limits.work)
        .ok_or_else(|| Error::limit("bgp_mrt_gap_work"))?;
    Ok(())
}
fn event_value<'a>(event: &'a Json, name: &str) -> Option<&'a Json> {
    if let Json::Object(fields) = event {
        fields
            .iter()
            .find(|(key, _)| *key == name)
            .map(|(_, value)| value)
    } else {
        None
    }
}
fn event_text<'a>(event: &'a Json, name: &str) -> Option<&'a str> {
    if let Some(Json::String(value)) = event_value(event, name) {
        Some(value)
    } else {
        None
    }
}
fn event_number(event: &Json, name: &str) -> Option<u64> {
    if let Some(Json::Number(value)) = event_value(event, name) {
        Some(*value)
    } else {
        None
    }
}

#[derive(Default)]
struct ImportedSession {
    id: String,
    identity: SessionIdentity,
    decoder: SessionState,
    fsm: Option<u16>,
    state_conflict: bool,
    continuity_generation: Option<u64>,
}

impl ImportedSession {
    fn clear_grammar(&mut self) {
        self.decoder.opens.clear();
        self.fsm = None;
        self.state_conflict = true;
    }
}

struct AffectedScope {
    session: String,
    generation: u64,
}

enum SessionResolution {
    Selected(usize),
    Ambiguous(Vec<AffectedScope>),
}

fn affected_scopes(
    state: &ReplayState,
    predicate: impl Fn(&ImportedSession) -> bool,
    limits: &Limits,
) -> Result<Vec<AffectedScope>> {
    let mut count = 0usize;
    let mut bytes = 0usize;
    for session in state.sessions.iter().filter(|s| predicate(s)) {
        count = count
            .checked_add(1)
            .filter(|n| *n <= limits.elements)
            .ok_or_else(|| Error::limit("bgp_mrt_affected_scopes"))?;
        bytes = session
            .id
            .len()
            .checked_mul(6)
            .and_then(|escaped| bytes.checked_add(escaped))
            .and_then(|n| n.checked_add(128))
            .filter(|n| {
                *n <= limits.retained_bytes && *n <= limits.output_bytes && *n <= limits.work
            })
            .ok_or_else(|| Error::limit("bgp_mrt_affected_scopes"))?;
    }
    let mut scopes = Vec::new();
    scopes
        .try_reserve_exact(count)
        .map_err(|_| Error::limit("bgp_mrt_affected_scopes"))?;
    for session in state.sessions.iter().filter(|s| predicate(s)) {
        scopes.push(AffectedScope {
            session: session.id.clone(),
            generation: session.decoder.generation(),
        });
    }
    Ok(scopes)
}

fn affected_json(scopes: Vec<AffectedScope>) -> Json {
    Json::array(scopes.into_iter().map(|scope| {
        Json::object([
            ("session", scope.session.into()),
            ("generation", scope.generation.into()),
        ])
    }))
}

fn ambiguous_event(
    source: RecordContext<'_>,
    direction: Option<u8>,
    kind: &str,
    scopes: Vec<AffectedScope>,
    range: Option<SourceRange>,
) -> Json {
    event_json(
        source.event(
            &ambiguous_session_key(source.batch, source.outer),
            direction,
            0,
        ),
        kind,
        "quarantined_ambiguous_session",
        vec!["ambiguous_bgp4mp_session_identity"],
        Some(Json::object([
            ("coverage_scope", "compatible_sessions".into()),
            ("affected_scopes", affected_json(scopes)),
            ("decoder_generation_advanced", false.into()),
        ])),
        range,
    )
}

#[derive(Default)]
struct SessionIdentity {
    source_id: String,
    checkpoint_id: String,
    address_afi: u16,
    peer_address: String,
    local_address: String,
    peer_asn: Option<u32>,
    local_asn: Option<u32>,
    interface_index: Option<u16>,
}

impl SessionIdentity {
    fn from_record(batch: &MrtBatch, outer: &Bgp4mp) -> Self {
        let known_asn = |asn| (asn != 0 && !(outer.asn_width == 2 && asn == 23_456)).then_some(asn);
        Self {
            source_id: batch.source.source_id.clone(),
            checkpoint_id: batch.source.checkpoint_id.clone(),
            address_afi: outer.address_afi,
            peer_address: outer.peer_address.to_string(),
            local_address: outer.local_address.to_string(),
            peer_asn: known_asn(outer.peer_asn),
            local_asn: known_asn(outer.local_asn),
            interface_index: (outer.interface_index != 0).then_some(outer.interface_index),
        }
    }

    fn same_partition_and_addresses(&self, other: &Self) -> bool {
        self.source_id == other.source_id
            && self.checkpoint_id == other.checkpoint_id
            && self.address_afi == other.address_afi
            && self.peer_address == other.peer_address
            && self.local_address == other.local_address
    }

    fn compatible(&self, other: &Self) -> bool {
        self.same_partition_and_addresses(other)
            && compatible_value(self.peer_asn, other.peer_asn)
            && compatible_value(self.local_asn, other.local_asn)
            && compatible_value(self.interface_index, other.interface_index)
    }

    fn enrich(&mut self, other: &Self) {
        self.peer_asn = self.peer_asn.or(other.peer_asn);
        self.local_asn = self.local_asn.or(other.local_asn);
        self.interface_index = self.interface_index.or(other.interface_index);
    }
}

fn compatible_value<T: Copy + Eq>(left: Option<T>, right: Option<T>) -> bool {
    left.is_none() || right.is_none() || left == right
}

pub(crate) struct ReplayRecord {
    pub event: Json,
    pub observation: Option<Json>,
    pub continuity_gap: Option<ImportContinuityCut>,
}

#[derive(Clone, Copy)]
struct RecordContext<'a> {
    batch: &'a MrtBatch,
    record_index: usize,
    record: &'a MrtRecord,
    outer: &'a Bgp4mp,
}

impl<'a> RecordContext<'a> {
    fn new(
        batch: &'a MrtBatch,
        record_index: usize,
        record: &'a MrtRecord,
        outer: &'a Bgp4mp,
    ) -> Self {
        Self {
            batch,
            record_index,
            record,
            outer,
        }
    }

    fn event(self, key: &'a str, direction: Option<u8>, generation: u64) -> EventContext<'a> {
        EventContext {
            source: self,
            key,
            direction,
            generation,
        }
    }
}

#[derive(Clone, Copy)]
struct EventContext<'a> {
    source: RecordContext<'a>,
    key: &'a str,
    direction: Option<u8>,
    generation: u64,
}

/// Apply one source-ordered BGP4MP state-change record. The record is evidence
/// of a reported FSM transition, not endpoint truth.
pub(crate) fn replay_state_record(
    batch: &MrtBatch,
    record_index: usize,
    record: &MrtRecord,
    limits: &Limits,
    state: &mut ReplayState,
) -> Result<Json> {
    let MrtBody::Bgp4mp(outer) = &record.body else {
        return Err(bad("bgp_mrt_state", record_index, "record is not BGP4MP"));
    };
    let source = RecordContext::new(batch, record_index, record, outer);
    let Bgp4mpPayload::State { old, new } = &outer.payload else {
        return Err(bad(
            "bgp_mrt_state",
            record_index,
            "record is not a state change",
        ));
    };
    let (old, new) = (*old, *new);
    let source_range = record_source_range(record)?;
    let session_index = match resolve_session(batch, outer, limits, state)? {
        SessionResolution::Selected(index) => index,
        SessionResolution::Ambiguous(scopes) => {
            return Ok(ambiguous_event(source, None, "state_change", scopes, None))
        }
    };
    let key = state.sessions[session_index].id.clone();
    let session = &mut state.sessions[session_index];
    let mut issues = Vec::new();
    let mut parse_status = "reported_transition";

    if !(1..=6).contains(&old) || !(1..=6).contains(&new) {
        issues.push("invalid_fsm_state_value");
        parse_status = "rejected";
        session.decoder.reset()?;
        session.fsm = None;
        session.state_conflict = true;
    } else if !valid_fsm_transition(old, new) {
        issues.push("illegal_reported_fsm_transition");
        parse_status = "quarantined";
        session.decoder.reset()?;
        session.fsm = None;
        session.state_conflict = true;
    } else if session.fsm.is_some_and(|prior| prior != old) {
        issues.push("reported_old_state_conflicts_with_prior_new_state");
        parse_status = "quarantined";
        session.decoder.reset()?;
        session.fsm = None;
        session.state_conflict = true;
    } else {
        // Idle begins a fresh session generation. OpenSent -> Active reports
        // a failed TCP attempt (RFC 4271, Section 8.2.2); OPEN evidence from
        // that attempt must not negotiate capabilities for the retry.
        if new == 1 || (old == 4 && new == 3) {
            session.decoder.reset()?;
        }
        session.fsm = Some(new);
        session.state_conflict = false;
        if new == 6 {
            let (_, basis) = producer::layout_evidence(&session.decoder, true);
            if basis != "both_four_octet_advertisements"
                && basis != "two_octet_bilateral_advertisements"
            {
                issues.push("established_state_without_unambiguous_bilateral_open");
            }
        }
    }

    let generation = session.decoder.generation();
    Ok(event_json(
        source.event(&key, None, generation),
        "state_change",
        parse_status,
        issues,
        Some(Json::object([
            ("old_state", old.into()),
            ("new_state", new.into()),
            ("session_state_known", session.fsm.is_some().into()),
            ("source_range", range_json(&source_range)),
        ])),
        None,
    ))
}

/// Replay one BGP4MP message from its checked absolute source range. The caller
/// has already reparsed the original source, verified its seal/hash, and
/// compared this range with the embedded message bytes.
pub(crate) fn replay_message_record(
    batch: &MrtBatch,
    record_index: usize,
    record: &MrtRecord,
    message_range: SourceRange,
    limits: &Limits,
    state: &mut ReplayState,
) -> Result<ReplayRecord> {
    let MrtBody::Bgp4mp(outer) = &record.body else {
        return Err(bad("bgp_mrt_message", record_index, "record is not BGP4MP"));
    };
    let source = RecordContext::new(batch, record_index, record, outer);
    let Bgp4mpPayload::Message(bytes) = &outer.payload else {
        return Err(bad(
            "bgp_mrt_message",
            record_index,
            "record is not a message",
        ));
    };
    let direction = u8::from(outer.locally_generated);
    let session_index = match resolve_session(batch, outer, limits, state)? {
        SessionResolution::Selected(index) => index,
        SessionResolution::Ambiguous(scopes) => {
            return Ok(ReplayRecord {
                event: ambiguous_event(
                    source,
                    Some(direction),
                    "message",
                    scopes,
                    Some(message_range),
                ),
                observation: None,
                continuity_gap: None,
            })
        }
    };
    let key = state.sessions[session_index].id.clone();
    let session = &mut state.sessions[session_index];
    let (negotiated, capability_basis) = producer::layout_evidence(
        &session.decoder,
        session.fsm == Some(6) && !session.state_conflict,
    );
    let extended_message = negotiated.extended_message_senders.contains(&direction);

    let message_type = match producer::validate_message_frame(bytes, extended_message) {
        Ok(message_type) => message_type,
        Err(error) if error.code == ErrorCode::LimitExceeded => return Err(error),
        Err(error) => {
            session.clear_grammar();
            return Ok(ReplayRecord {
                event: rejected_message_event(
                    source.event(&key, Some(direction), session.decoder.generation()),
                    &message_range,
                    "rejected",
                    "bgp4mp_message_frame_rejected",
                    &error,
                ),
                observation: None,
                continuity_gap: None,
            });
        }
    };
    let generation = session.decoder.generation();
    let mut issues = Vec::new();

    match message_type {
        1 => {
            let source_metadata = source_json(batch, record_index, record, outer, &key, direction);
            let evidence = message_evidence(record, outer, &message_range);
            let mut open =
                match producer::parse_open_imported(bytes, source_metadata, evidence, limits) {
                    Ok(open) => open,
                    Err(error) if error.code == ErrorCode::LimitExceeded => return Err(error),
                    Err(error) => {
                        return Ok(ReplayRecord {
                            event: rejected_message_event(
                                source.event(&key, Some(direction), generation),
                                &message_range,
                                "rejected",
                                "bgp4mp_open_rejected",
                                &error,
                            ),
                            observation: None,
                            continuity_gap: None,
                        });
                    }
                };
            let expected_asn = if outer.locally_generated {
                outer.local_asn
            } else {
                outer.peer_asn
            };
            // The 2-octet MRT subtypes carry the legacy ASN field. In an
            // AS_TRANS session, the OPEN's four-octet capability is not
            // comparable to that container field; 4-octet MRT subtypes are.
            let advertised_asn = if outer.asn_width == 4 {
                open.four_octet_asn
                    .unwrap_or(u32::from(open.autonomous_system))
            } else {
                u32::from(open.autonomous_system)
            };
            if advertised_asn != expected_asn {
                open.ambiguous = true;
                open.capabilities.valid = false;
                open.capability_issues
                    .push("open_asn_disagrees_with_mrt_peer_metadata");
                issues.push("open_asn_disagrees_with_mrt_peer_metadata");
            }
            let opening_state_known = !session.state_conflict && matches!(session.fsm, Some(2..=4));
            if opening_state_known {
                let open_count: usize = session.decoder.opens.values().map(Vec::len).sum();
                if open_count >= limits.elements {
                    return Err(Error::limit("bgp_mrt_open_records"));
                }
                session
                    .decoder
                    .opens
                    .entry(direction)
                    .or_default()
                    .push(open.clone());
            } else {
                issues.push("open_outside_opening_fsm_state_not_used_for_layout");
            }
            let (_, basis) = producer::layout_evidence(&session.decoder, true);
            let event = event_json(
                source.event(&key, Some(direction), generation),
                "message",
                if opening_state_known {
                    "decoded_open"
                } else {
                    "quarantined_open_fsm_state"
                },
                issues,
                Some(Json::object([
                    ("open_witness", open.witness.value),
                    ("capability_context_basis", basis.into()),
                    ("negotiation_established", false.into()),
                ])),
                Some(message_range),
            );
            Ok(ReplayRecord {
                event,
                observation: None,
                continuity_gap: None,
            })
        }
        2 => {
            if session.fsm != Some(6) || session.state_conflict {
                issues.push("update_without_known_established_state");
                return Ok(ReplayRecord {
                    event: event_json(
                        source.event(&key, Some(direction), generation),
                        "message",
                        "quarantined",
                        issues,
                        Some(Json::object([
                            ("capability_context_basis", capability_basis.into()),
                            ("container_add_path", outer.add_path.into()),
                        ])),
                        Some(message_range),
                    ),
                    observation: None,
                    continuity_gap: None,
                });
            }
            if !matches!(
                capability_basis,
                "both_four_octet_advertisements" | "two_octet_bilateral_advertisements"
            ) {
                issues.push("capability_context_unresolved");
                return Ok(ReplayRecord {
                    event: event_json(
                        source.event(&key, Some(direction), generation),
                        "message",
                        "quarantined",
                        issues,
                        Some(Json::object([
                            ("capability_context_basis", capability_basis.into()),
                            ("container_add_path", outer.add_path.into()),
                        ])),
                        Some(message_range),
                    ),
                    observation: None,
                    continuity_gap: None,
                });
            }
            if negotiated
                .unresolved_add_path
                .iter()
                .any(|(sender, _, _)| *sender == direction)
            {
                issues.push("add_path_capability_context_unresolved");
                return Ok(ReplayRecord {
                    event: event_json(
                        source.event(&key, Some(direction), generation),
                        "message",
                        "quarantined",
                        issues,
                        Some(Json::object([
                            ("capability_context_basis", capability_basis.into()),
                            ("container_add_path", outer.add_path.into()),
                        ])),
                        Some(message_range),
                    ),
                    observation: None,
                    continuity_gap: None,
                });
            }

            let mut wire_layout = negotiated.clone();
            let asn_width_conflict = usize::from(outer.asn_width) != negotiated.asn_width;
            // RFC 6396's AS4 subtype defines the embedded AS_PATH width;
            // RFC 8050's ADD-PATH subtype defines this record's NLRI layout.
            // OPEN capabilities remain the independent negotiation evidence.
            wire_layout.asn_width = usize::from(outer.asn_width);
            for (afi, safi) in [(1u16, 1u8), (1, 2), (2, 1), (2, 2)]
                .into_iter()
                .chain(negotiated.mp.iter().copied())
            {
                wire_layout.add_path.remove(&(direction, afi, safi));
                if outer.add_path {
                    wire_layout.add_path.insert((direction, afi, safi));
                }
            }
            let mut budget = producer::Budget::new(limits);
            let mut parsed =
                match parse_update(bytes, &wire_layout, Some(direction), limits, &mut budget) {
                    Ok(parsed) => parsed,
                    Err(error) if error.code == ErrorCode::LimitExceeded => return Err(error),
                    Err(error) => {
                        return Ok(ReplayRecord {
                            event: rejected_message_event(
                                source.event(&key, Some(direction), generation),
                                &message_range,
                                "rejected",
                                "bgp4mp_update_rejected",
                                &error,
                            ),
                            observation: None,
                            continuity_gap: None,
                        });
                    }
                };

            if session.decoder.opens.values().flatten().any(|open| {
                open.capability_issues.iter().any(|issue| {
                    matches!(
                        *issue,
                        "unsupported_capability_retained_by_hash"
                            | "unsupported_open_parameter_retained_by_hash"
                    )
                })
            }) {
                parsed
                    .issues
                    .push("unsupported_session_capabilities_not_interpreted");
            }

            let add_path_conflict = parsed.records.iter().any(|route| {
                let family = (direction, route.prefix.afi, route.prefix.safi);
                negotiated.unresolved_add_path.contains(&family)
                    || negotiated.add_path.contains(&family) != route.path_id.is_some()
            });
            if asn_width_conflict || add_path_conflict {
                issues.push(if asn_width_conflict {
                    "container_asn_width_conflicts_with_bilateral_open"
                } else {
                    "container_add_path_layout_conflicts_with_bilateral_open"
                });
                return Ok(ReplayRecord {
                    event: event_json(
                        source.event(&key, Some(direction), generation),
                        "message",
                        "quarantined",
                        issues,
                        Some(update_detail(
                            &parsed,
                            outer,
                            capability_basis,
                            &message_range,
                        )),
                        Some(message_range),
                    ),
                    observation: None,
                    continuity_gap: None,
                });
            }
            if parsed.known_disposition == "session_reset" {
                issues.push("malformed_update_requires_session_reset");
                session.decoder.reset()?;
                session.fsm = None;
                return Ok(ReplayRecord {
                    event: event_json(
                        source.event(&key, Some(direction), generation),
                        "message",
                        "quarantined_session_reset",
                        issues,
                        Some(update_detail(
                            &parsed,
                            outer,
                            capability_basis,
                            &message_range,
                        )),
                        Some(message_range),
                    ),
                    observation: None,
                    continuity_gap: None,
                });
            }

            if parsed.peer_relationship_unresolved {
                issues.push("peer_relationship_context_unresolved_update_not_admitted");
            }

            issues.extend(parsed.issues.iter().copied());
            if observation_time_ns(record).is_none() {
                issues.push("invalid_mrt_record_timestamp");
            }
            let context = import_context(
                source.event(&key, Some(direction), generation),
                message_range.clone(),
                limits,
            )?;
            let details = update_detail(&parsed, outer, capability_basis, &message_range);
            let event_issues = issues.clone();
            // Imported observations bind the complete BGP message through
            // ImportContext. Packet-relative route spans belong only to the
            // captured evidence carrier and must not be asserted here.
            let mut imported_records = std::mem::take(&mut parsed.records);
            let occurrence_inventory = imported_attribute_inventory(
                &parsed.attribute_ranges,
                bytes,
                &message_range,
                imported_records.len(),
                limits,
            )?;
            let identities = imported_route_identities(&mut imported_records, limits)?;
            let mut normalized = envelope(
                Source {
                    kind: SourceKind::Imported,
                    source_id: batch.source.source_id.clone(),
                    record_id: record_id(record_index, record, &message_range),
                    observed_at_ns: observation_time_ns(record),
                    session: Some(key.clone()),
                    direction: Some(direction),
                    peer: Some(peer_identity(outer)),
                    local: Some(local_identity(outer)),
                },
                generation,
                0,
                imported_records,
                issues,
                EnvelopeDetails {
                    message_detail: Some(details),
                    evidence: None,
                    import_context: Some(context.json()),
                },
                limits,
            )?;
            let atomic_aggregate = parsed
                .attribute_ranges
                .iter()
                .any(|occurrence| occurrence.code == 6 && occurrence.disposition != "discard");
            finish_imported_update(
                &mut normalized,
                identities,
                occurrence_inventory,
                atomic_aggregate,
                limits,
            )?;
            Ok(ReplayRecord {
                event: event_json(
                    source.event(&key, Some(direction), generation),
                    "message",
                    if route_projection_incomplete(&parsed) {
                        "opaque_update_continuity_gap"
                    } else {
                        "decoded_update_candidate"
                    },
                    event_issues,
                    Some(Json::object([
                        ("capability_context_basis", capability_basis.into()),
                        (
                            "observation_record_id",
                            record_id(record_index, record, &message_range).into(),
                        ),
                        ("route_count", parsed_route_count(&normalized).into()),
                    ])),
                    Some(message_range.clone()),
                ),
                observation: Some(normalized),
                continuity_gap: route_projection_incomplete(&parsed).then(|| ImportContinuityCut {
                    context,
                    record_id: record_id(record_index, record, &message_range),
                    reason: "decoded_update_opaque_route_evidence".to_owned(),
                }),
            })
        }
        3 => {
            if bytes.len() < 21 {
                let error = bad(
                    "bgp_notification",
                    19,
                    "NOTIFICATION is shorter than its header",
                );
                return Ok(ReplayRecord {
                    event: rejected_message_event(
                        source.event(&key, Some(direction), generation),
                        &message_range,
                        "rejected",
                        "bgp4mp_notification_rejected",
                        &error,
                    ),
                    observation: None,
                    continuity_gap: None,
                });
            }
            session.decoder.reset()?;
            session.fsm = None;
            Ok(ReplayRecord {
                event: event_json(
                    source.event(&key, Some(direction), generation),
                    "message",
                    "decoded_notification_reset",
                    Vec::new(),
                    Some(Json::object([
                        ("error_code", bytes[19].into()),
                        ("error_subcode", bytes[20].into()),
                        (
                            "data_sha256",
                            sha256::hex(&sha256::digest(&bytes[21..])).into(),
                        ),
                        ("next_generation", session.decoder.generation().into()),
                    ])),
                    Some(message_range),
                ),
                observation: None,
                continuity_gap: None,
            })
        }
        4 => {
            if bytes.len() != 19 {
                let error = bad("bgp_keepalive", 16, "KEEPALIVE must be 19 bytes");
                return Ok(ReplayRecord {
                    event: rejected_message_event(
                        source.event(&key, Some(direction), generation),
                        &message_range,
                        "rejected",
                        "bgp4mp_keepalive_rejected",
                        &error,
                    ),
                    observation: None,
                    continuity_gap: None,
                });
            }
            let accepted_state = !session.state_conflict && matches!(session.fsm, Some(5 | 6));
            Ok(ReplayRecord {
                event: event_json(
                    source.event(&key, Some(direction), generation),
                    "message",
                    if accepted_state {
                        "decoded_keepalive"
                    } else {
                        "quarantined_keepalive_fsm_state"
                    },
                    if accepted_state {
                        Vec::new()
                    } else {
                        vec!["keepalive_outside_open_confirm_or_established"]
                    },
                    None,
                    Some(message_range),
                ),
                observation: None,
                continuity_gap: None,
            })
        }
        5 => {
            if bytes.len() != 23 {
                let error = bad("bgp_route_refresh", 16, "invalid ROUTE-REFRESH length");
                return Ok(ReplayRecord {
                    event: rejected_message_event(
                        source.event(&key, Some(direction), generation),
                        &message_range,
                        "rejected",
                        "bgp4mp_route_refresh_rejected",
                        &error,
                    ),
                    observation: None,
                    continuity_gap: None,
                });
            }
            let accepted_state = !session.state_conflict && session.fsm == Some(6);
            // RFC 7313 section 4 describes the sender's procedure: the
            // opposite-side receiver advertised support to that sender.
            // This is observed wire layout evidence, not proof that either
            // endpoint negotiated or processed the refresh. The separate
            // receiver error-handling condition in section 5 is not inferred.
            let (receiver_capability70, refresh_basis) =
                refresh_sender_layout(&session.decoder, direction);
            let subtype = bytes[21];
            let parse_status = if subtype > 2 {
                issues.push("unknown_route_refresh_subtype_ignored");
                "ignored_unknown_route_refresh_subtype"
            } else if !accepted_state {
                "quarantined_route_refresh_fsm_state"
            } else if matches!(subtype, 1 | 2) && !receiver_capability70 {
                issues.push("enhanced_route_refresh_unresolved_context");
                "quarantined_route_refresh_capability_context"
            } else {
                "decoded_route_refresh"
            };
            if !accepted_state {
                issues.push("route_refresh_outside_established");
            }
            Ok(ReplayRecord {
                event: event_json(
                    source.event(&key, Some(direction), generation),
                    "message",
                    parse_status,
                    issues,
                    Some(Json::object([
                        ("afi", be16(bytes, 19)?.into()),
                        ("subtype", subtype.into()),
                        ("safi", bytes[22].into()),
                        ("receiver_open_direction", (1 - direction).into()),
                        (
                            "receiver_capability70_advertised",
                            receiver_capability70.into(),
                        ),
                        ("sender_layout_basis", refresh_basis.into()),
                        ("negotiation_established", false.into()),
                        ("endpoint_processing_claimed", false.into()),
                    ])),
                    Some(message_range),
                ),
                observation: None,
                continuity_gap: None,
            })
        }
        _ => Ok(ReplayRecord {
            event: event_json(
                source.event(&key, Some(direction), generation),
                "message",
                "rejected",
                vec!["unsupported_bgp_message_type"],
                Some(Json::object([("message_type", message_type.into())])),
                Some(message_range),
            ),
            observation: None,
            continuity_gap: None,
        }),
    }
}

/// Qualify only the RFC 7313 sender layout from same-generation wire OPENs.
/// Session/FSM admission is checked separately; no reported BMP OPEN is used.
fn refresh_sender_layout(state: &SessionState, direction: u8) -> (bool, &'static str) {
    let Some(opens) = state.opens.get(&(1 - direction)) else {
        return (false, "missing_receiver_open");
    };
    if opens.is_empty() {
        return (false, "missing_receiver_open");
    }
    let Some(open) = state.unambiguous_open(1 - direction) else {
        return (false, "ambiguous_receiver_open");
    };
    if open.ambiguous || !open.capabilities.valid {
        return (false, "invalid_receiver_open");
    }
    if !open.capabilities.enhanced_refresh {
        return (false, "receiver_did_not_advertise_capability70");
    }
    (true, "observed_peer_capability70_for_sender_layout")
}

fn resolve_session(
    batch: &MrtBatch,
    outer: &Bgp4mp,
    limits: &Limits,
    state: &mut ReplayState,
) -> Result<SessionResolution> {
    let incoming = SessionIdentity::from_record(batch, outer);
    let mut selected = None;
    let mut ambiguous = false;
    for (index, session) in state.sessions.iter().enumerate() {
        if session.identity.compatible(&incoming) && selected.replace(index).is_some() {
            ambiguous = true;
            break;
        }
    }
    if ambiguous {
        let affected = affected_scopes(
            state,
            |session| session.identity.compatible(&incoming),
            limits,
        )?;
        for session in &mut state.sessions {
            if session.identity.compatible(&incoming) {
                session.clear_grammar();
            }
        }
        return Ok(SessionResolution::Ambiguous(affected));
    }
    if let Some(index) = selected {
        state.sessions[index].identity.enrich(&incoming);
        return Ok(SessionResolution::Selected(index));
    }
    if state.sessions.len() >= limits.active {
        return Err(Error::limit("bgp_mrt_active_sessions"));
    }
    let slot = state
        .sessions
        .iter()
        .filter(|session| session.identity.same_partition_and_addresses(&incoming))
        .count();
    let id = session_key(batch, outer, slot);
    let mut decoder = SessionState::default();
    if let Some(relationship) = state.peer_relationship {
        decoder.set_peer_relationship(relationship);
    }
    state
        .sessions
        .try_reserve(1)
        .map_err(|_| Error::limit("bgp_mrt_active_sessions"))?;
    state.sessions.push(ImportedSession {
        id,
        identity: incoming,
        decoder,
        ..ImportedSession::default()
    });
    Ok(SessionResolution::Selected(state.sessions.len() - 1))
}

/// An opaque malformed record has a full-record witness, not an embedded
/// message range. Recover only independently validated header scope; otherwise
/// conservatively report unknown coverage of this source/checkpoint.
pub(crate) fn replay_malformed_record(
    batch: &MrtBatch,
    record_index: usize,
    record: &MrtRecord,
    limits: &Limits,
    state: &mut ReplayState,
) -> Result<Json> {
    if let Some(outer) = super::super::bgp_mrt::malformed_bgp4mp_scope(record)? {
        let source = RecordContext::new(batch, record_index, record, &outer);
        let index = match resolve_session(batch, &outer, limits, state)? {
            SessionResolution::Selected(index) => index,
            SessionResolution::Ambiguous(scopes) => {
                return Ok(ambiguous_event(
                    source,
                    None,
                    "malformed_record",
                    scopes,
                    None,
                ))
            }
        };
        let session = &mut state.sessions[index];
        session.clear_grammar();
        return Ok(event_json(
            source.event(&session.id, None, session.decoder.generation()),
            "malformed_record",
            "rejected",
            vec!["malformed_bgp4mp_record"],
            Some(Json::object([
                ("coverage_scope", "validated_header_session".into()),
                ("decoder_generation_advanced", false.into()),
            ])),
            None,
        ));
    }
    let affected = affected_scopes(state, |_| true, limits)?;
    for session in &mut state.sessions {
        session.clear_grammar();
    }
    Ok(Json::object([
        ("schema", "pcap-evidence.bgp.mrt-session-event.v1".into()),
        ("source_id", batch.source.source_id.clone().into()),
        ("checkpoint_id", batch.source.checkpoint_id.clone().into()),
        ("record_index", record_index.into()),
        ("record_offset", record.offset.into()),
        ("record_sha256", record.sha256.clone().into()),
        ("record_range", range_json(&record_source_range(record)?)),
        ("event_kind", "malformed_record".into()),
        ("parse_status", "quarantined_coverage_unknown".into()),
        ("session", Json::Null),
        ("generation", Json::Null),
        ("direction", Json::Null),
        ("peer_asn", Json::Null),
        ("local_asn", Json::Null),
        ("peer_address", Json::Null),
        ("local_address", Json::Null),
        ("interface_index", Json::Null),
        ("address_afi", Json::Null),
        ("locally_generated", Json::Null),
        ("container_add_path", Json::Null),
        ("asn_width", Json::Null),
        ("timestamp_seconds", record.time.seconds.into()),
        (
            "timestamp_microseconds",
            record.time.microseconds.map_or(Json::Null, Json::from),
        ),
        ("message_range", Json::Null),
        (
            "issues",
            Json::array(["malformed_bgp4mp_scope_unrecoverable".into()]),
        ),
        (
            "detail",
            Json::object([
                ("coverage_scope", "source_checkpoint".into()),
                ("affected_scopes", affected_json(affected)),
                ("decoder_generation_advanced", false.into()),
            ]),
        ),
        ("source_authenticated", false.into()),
        ("endpoint_state_claimed", false.into()),
    ]))
}

fn valid_fsm_transition(old: u16, new: u16) -> bool {
    match old {
        1 => matches!(new, 2 | 3),
        2 => matches!(new, 1 | 3 | 4),
        3 => matches!(new, 1 | 2 | 4),
        4 => matches!(new, 1 | 3 | 5),
        5 => matches!(new, 1 | 6),
        6 => new == 1,
        _ => false,
    }
}

fn session_key(batch: &MrtBatch, outer: &Bgp4mp, slot: usize) -> String {
    format!(
        "mrt-bgp4mp:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}",
        batch.source.source_id.len(),
        batch.source.source_id,
        batch.source.checkpoint_id.len(),
        batch.source.checkpoint_id,
        outer.address_afi,
        outer.peer_address.to_string().len(),
        outer.peer_address,
        outer.local_address.to_string().len(),
        outer.local_address,
        outer.peer_asn,
        outer.local_asn,
        outer.interface_index,
        slot,
    )
}

fn ambiguous_session_key(batch: &MrtBatch, outer: &Bgp4mp) -> String {
    format!(
        "mrt-bgp4mp-ambiguous:{}",
        session_key(batch, outer, usize::MAX)
    )
}

fn peer_identity(outer: &Bgp4mp) -> String {
    format!("{}@{}", outer.peer_asn, outer.peer_address)
}

fn local_identity(outer: &Bgp4mp) -> String {
    format!("{}@{}", outer.local_asn, outer.local_address)
}

pub(crate) fn record_id(
    record_index: usize,
    record: &MrtRecord,
    message_range: &SourceRange,
) -> String {
    format!(
        "mrt-bgp4mp:{}:{}:{}:{}",
        record.offset,
        record.subtype,
        record_index,
        message_range.sha256.as_deref().unwrap_or(&record.sha256),
    )
}

fn observation_time_ns(record: &MrtRecord) -> Option<i64> {
    let micros = if record.record_type == 17 {
        // RFC 6396 ET is an explicit microsecond field, not an optional zero.
        // Preserve malformed raw values in record/event evidence, but expose
        // no usable numeric observation time when the field is absent/invalid.
        record.time.microseconds.filter(|us| *us < 1_000_000)?
    } else {
        0
    };
    let seconds = i64::from(record.time.seconds).checked_mul(1_000_000_000)?;
    seconds.checked_add(i64::from(micros).checked_mul(1_000)?)
}

/// Exact imported value bytes and message-relative coordinates, with no packet
/// carrier. The sealed store independently binds this inventory to source.
/// Shared imported semantic donor. A sizing pass holds one identity at a time;
/// aggregate admission precedes the retained vector and span clearing.
pub(super) fn imported_route_identities(
    records: &mut [RouteRecord],
    limits: &Limits,
) -> Result<Vec<Json>> {
    let cap = limits
        .input_bytes
        .min(limits.retained_bytes)
        .min(limits.output_bytes);
    let mut size = 0usize;
    for record in records.iter() {
        let identity = capture_semantic_identity(record, limits)?;
        size = size
            .checked_add(identity.encoded_len_bounded(cap.saturating_sub(size))?)
            .filter(|size| *size <= cap)
            .ok_or_else(|| Error::limit("bgp_mrt_semantic_identity_fanout"))?;
    }
    if size
        .checked_mul(2)
        .filter(|size| *size <= limits.work)
        .is_none()
    {
        return Err(Error::limit("bgp_mrt_semantic_identity_work"));
    }
    let mut identities = Vec::new();
    identities
        .try_reserve_exact(records.len())
        .map_err(|_| Error::limit("bgp_mrt_semantic_identity"))?;
    for route in records {
        identities.push(capture_semantic_identity(route, limits)?);
        route.start = 0;
        route.end = 0;
        route.attribute_ranges.clear();
    }
    Ok(identities)
}

/// Attach the preflighted source proof to an imported envelope. BMP and MRT
/// share this join rather than maintaining separate semantic carrier rules.
pub(super) fn finish_imported_update(
    normalized: &mut Json,
    identities: Vec<Json>,
    inventory: Json,
    atomic_aggregate: bool,
    limits: &Limits,
) -> Result<()> {
    let cap = limits
        .input_bytes
        .min(limits.output_bytes)
        .min(limits.retained_bytes);
    let mut size = normalized.encoded_len_bounded(cap)?;
    let Json::Object(fields) = normalized else {
        return Err(bad("bgp_mrt_import", 0, "route envelope absent"));
    };
    let routes = fields
        .iter_mut()
        .find_map(|(key, value)| (*key == "routes").then_some(value))
        .ok_or_else(|| bad("bgp_mrt_import", 0, "routes absent"))?;
    let Json::Array(routes) = routes else {
        return Err(bad("bgp_mrt_import", 0, "routes not array"));
    };
    if routes.len() != identities.len() {
        return Err(bad(
            "bgp_mrt_import",
            0,
            "identity fanout does not match routes",
        ));
    }
    let inventory_size = inventory.encoded_len_bounded(cap)?;
    let identity_key = Json::from("semantic_identity").encoded_len_bounded(cap)? + 2;
    let inventory_key = Json::from("imported_attribute_occurrences").encoded_len_bounded(cap)? + 2;
    let atomic_key = Json::from("atomic_aggregate").encoded_len_bounded(cap)? + 1;
    for (route, identity) in routes.iter().zip(&identities) {
        let Json::Object(route) = route else {
            return Err(bad("bgp_mrt_import", 0, "route not object"));
        };
        let atom = route
            .iter()
            .find_map(|(key, value)| (*key == "attributes").then_some(value))
            .and_then(|value| match value {
                Json::Object(attrs) => Some(attrs),
                _ => None,
            });
        let growth = identity_key
            .checked_add(identity.encoded_len_bounded(cap)?)
            .and_then(|size| size.checked_add(inventory_key))
            .and_then(|size| size.checked_add(inventory_size))
            .and_then(|size| {
                size.checked_add(atom.map_or(0, |attrs| {
                    atomic_key
                        + usize::from(!attrs.is_empty())
                        + if atomic_aggregate { 4 } else { 5 }
                }))
            })
            .ok_or_else(|| Error::limit("bgp_mrt_imported_occurrence_fanout"))?;
        size = size
            .checked_add(growth)
            .filter(|size| *size <= cap.min(limits.work))
            .ok_or_else(|| Error::limit("bgp_mrt_imported_occurrence_fanout"))?;
    }
    for (route, identity) in routes.iter_mut().zip(identities) {
        let Json::Object(route) = route else {
            unreachable!("preflighted route")
        };
        route.push(("semantic_identity", identity));
        route.push(("imported_attribute_occurrences", inventory.clone()));
        if let Some(Json::Object(attributes)) = route
            .iter_mut()
            .find_map(|(key, value)| (*key == "attributes").then_some(value))
        {
            attributes.push(("atomic_aggregate", atomic_aggregate.into()));
        }
    }
    let actual = normalized.encoded_len_bounded(cap)?;
    if actual != size {
        return Err(bad(
            "bgp_mrt_import",
            0,
            "imported proof size changed after preflight",
        ));
    }
    Ok(())
}

pub(super) fn imported_attribute_inventory(
    ranges: &[AttributeRange],
    message: &[u8],
    message_range: &SourceRange,
    route_count: usize,
    limits: &Limits,
) -> Result<Json> {
    let withdrawn_length = message.get(19..21).ok_or_else(|| {
        bad(
            "bgp_mrt_imported_occurrences",
            19,
            "UPDATE withdrawn length absent",
        )
    })?;
    let attribute_length_start = 21usize
        .checked_add(usize::from(u16::from_be_bytes([
            withdrawn_length[0],
            withdrawn_length[1],
        ])))
        .ok_or_else(|| Error::limit("bgp_mrt_imported_occurrences"))?;
    let attribute_length_end = attribute_length_start
        .checked_add(2)
        .ok_or_else(|| Error::limit("bgp_mrt_imported_occurrences"))?;
    let attribute_length = message
        .get(attribute_length_start..attribute_length_end)
        .ok_or_else(|| {
            bad(
                "bgp_mrt_imported_occurrences",
                attribute_length_start,
                "UPDATE attribute length absent",
            )
        })?;
    let attributes_end = attribute_length_end
        .checked_add(usize::from(u16::from_be_bytes([
            attribute_length[0],
            attribute_length[1],
        ])))
        .filter(|end| *end <= message.len())
        .ok_or_else(|| Error::limit("bgp_mrt_imported_occurrences"))?;
    let prefix = &message[..attribute_length_end];
    let suffix = &message[attributes_end..];

    // Admit every raw hex byte, including endpoints and route fanout, before
    // allocating any occurrence or hex String. Endpoint bytes close membership:
    // the consumer can reconstruct all declared TLVs and the full message hash.
    let mut raw_bytes = prefix
        .len()
        .checked_add(suffix.len())
        .ok_or_else(|| Error::limit("bgp_mrt_imported_occurrences"))?;
    for range in ranges {
        let value = message.get(range.value_start..range.end).ok_or_else(|| {
            bad(
                "bgp_mrt_imported_occurrences",
                range.value_start,
                "attribute outside message",
            )
        })?;
        raw_bytes = raw_bytes
            .checked_add(value.len())
            .ok_or_else(|| Error::limit("bgp_mrt_imported_occurrences"))?;
    }
    let hex_bytes = raw_bytes
        .checked_mul(2)
        .and_then(|size| size.checked_mul(route_count.max(1)))
        .filter(|size| {
            *size
                <= limits
                    .input_bytes
                    .min(limits.retained_bytes)
                    .min(limits.output_bytes)
        })
        .ok_or_else(|| Error::limit("bgp_mrt_imported_occurrence_hex_fanout"))?;
    if hex_bytes
        .checked_mul(2)
        .filter(|size| *size <= limits.work)
        .is_none()
    {
        return Err(Error::limit("bgp_mrt_imported_occurrence_hex_work"));
    }
    let mut occurrences = Vec::new();
    occurrences
        .try_reserve_exact(ranges.len())
        .map_err(|_| Error::limit("bgp_mrt_imported_occurrences"))?;
    for range in ranges {
        let value = message.get(range.value_start..range.end).ok_or_else(|| {
            bad(
                "bgp_mrt_imported_occurrences",
                range.value_start,
                "attribute outside message",
            )
        })?;
        let value_hex = imported_hex(value)?;
        let mut occurrence = attribute_range_json(range);
        let Json::Object(fields) = &mut occurrence else {
            unreachable!()
        };
        // The captured type-16 carrier already includes raw bytes. This owner
        // reconstructs imported values for every code; retain exactly one key.
        fields.retain(|(key, _)| *key != "value_hex");
        fields.push(("value_hex", value_hex.into()));
        occurrences.push(occurrence);
    }
    let inventory = Json::object([
        (
            "schema",
            "pcap-evidence.bgp.imported-attribute-occurrences.v1".into(),
        ),
        ("coordinate_system", "bgp-message-relative".into()),
        ("message_length", message.len().into()),
        (
            "message_sha256",
            message_range
                .sha256
                .clone()
                .ok_or_else(|| bad("bgp_mrt_imported_occurrences", 0, "message digest absent"))?
                .into(),
        ),
        ("occurrences", Json::Array(occurrences)),
        ("message_prefix_hex", imported_hex(prefix)?.into()),
        ("message_suffix_hex", imported_hex(suffix)?.into()),
    ]);
    let length = inventory.encoded_len_bounded(limits.input_bytes)?;
    if length
        .checked_mul(route_count)
        .filter(|size| {
            *size
                <= limits
                    .retained_bytes
                    .min(limits.output_bytes)
                    .min(limits.work)
        })
        .is_none()
    {
        return Err(Error::limit("bgp_mrt_imported_occurrence_fanout"));
    }
    Ok(inventory)
}

fn imported_hex(bytes: &[u8]) -> Result<String> {
    let size = bytes
        .len()
        .checked_mul(2)
        .ok_or_else(|| Error::limit("bgp_mrt_imported_occurrences"))?;
    let mut hex = String::new();
    hex.try_reserve_exact(size)
        .map_err(|_| Error::limit("bgp_mrt_imported_occurrences"))?;
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut hex, "{byte:02x}").map_err(|_| Error::limit("bgp_mrt_imported_occurrences"))?;
    }
    Ok(hex)
}

fn import_context(
    event: EventContext<'_>,
    message_range: SourceRange,
    limits: &Limits,
) -> Result<ImportContext> {
    let direction = event.direction.ok_or_else(|| {
        bad(
            "bgp_mrt_import_context",
            event.source.record_index,
            "imported BGP4MP message is missing its direction label",
        )
    })?;
    let context = ImportContext {
        source_id: event.source.batch.source.source_id.clone(),
        source_schema: super::super::bgp_mrt::SCHEMA.into(),
        source_version: Some("1".into()),
        clock: ObservationClock {
            policy: ClockPolicy::SourceLabel,
            clock_id: Some("mrt-bgp4mp-record-timestamp".into()),
            reported_uncertainty_ns: None,
        },
        batch: SourceBatch {
            batch_id: None,
            sha256: Some(event.source.batch.sha256.clone()),
            byte_length: Some(event.source.batch.byte_length),
        },
        checkpoint_id: event.source.batch.source.checkpoint_id.clone(),
        session: event.key.to_owned(),
        generation: event.generation,
        direction: Some(direction),
        peer: Some(peer_identity(event.source.outer)),
        local: Some(local_identity(event.source.outer)),
        provenance: vec![message_range],
    };
    context.validate(limits)?;
    // A source label may have unknown numeric time. Exact byte provenance and
    // checkpoint/session identity remain available independently of that clock.
    Ok(context)
}

fn parsed_route_count(value: &Json) -> usize {
    match value {
        Json::Object(fields) => fields
            .iter()
            .find(|(key, _)| *key == "routes")
            .and_then(|(_, routes)| match routes {
                Json::Array(items) => Some(items.len()),
                _ => None,
            })
            .unwrap_or(0),
        _ => 0,
    }
}

fn source_json(
    batch: &MrtBatch,
    record_index: usize,
    record: &MrtRecord,
    outer: &Bgp4mp,
    key: &str,
    direction: u8,
) -> Json {
    Json::object([
        ("source_kind", "imported".into()),
        ("source_id", batch.source.source_id.clone().into()),
        ("checkpoint_id", batch.source.checkpoint_id.clone().into()),
        (
            "record_id",
            format!("mrt-bgp4mp:{}:{}", record.offset, record_index).into(),
        ),
        ("session", key.into()),
        ("direction", direction.into()),
        ("peer", peer_identity(outer).into()),
        ("local", local_identity(outer).into()),
    ])
}

fn message_evidence(record: &MrtRecord, outer: &Bgp4mp, range: &SourceRange) -> Json {
    Json::object([
        ("kind", "mrt_bgp4mp_message_range".into()),
        ("record_offset", record.offset.into()),
        ("record_sha256", record.sha256.clone().into()),
        ("record_type", record.record_type.into()),
        ("record_subtype", record.subtype.into()),
        ("asn_width", outer.asn_width.into()),
        ("add_path_layout", outer.add_path.into()),
        ("locally_generated", outer.locally_generated.into()),
        ("source_range", range_json(range)),
        ("source_authenticated", false.into()),
        ("endpoint_state_claimed", false.into()),
    ])
}

fn record_source_range(record: &MrtRecord) -> Result<SourceRange> {
    let end = record
        .offset
        .checked_add(12)
        .and_then(|value| value.checked_add(u64::from(record.length)))
        .ok_or_else(|| Error::limit("bgp_mrt_source_range"))?;
    Ok(SourceRange {
        start: record.offset,
        end,
        sha256: Some(record.sha256.clone()),
    })
}

fn range_json(range: &SourceRange) -> Json {
    Json::object([
        ("start", range.start.into()),
        ("end", range.end.into()),
        (
            "sha256",
            range.sha256.clone().map_or(Json::Null, Json::String),
        ),
    ])
}

fn event_json(
    context: EventContext<'_>,
    event_kind: &str,
    parse_status: &str,
    issues: Vec<&'static str>,
    detail: Option<Json>,
    message_range: Option<SourceRange>,
) -> Json {
    let EventContext {
        source:
            RecordContext {
                batch,
                record_index,
                record,
                outer,
            },
        key,
        direction,
        generation,
    } = context;
    Json::object([
        ("schema", "pcap-evidence.bgp.mrt-session-event.v1".into()),
        ("source_id", batch.source.source_id.clone().into()),
        ("checkpoint_id", batch.source.checkpoint_id.clone().into()),
        ("record_index", record_index.into()),
        ("record_offset", record.offset.into()),
        ("record_sha256", record.sha256.clone().into()),
        (
            "record_range",
            record_source_range(record).map_or(Json::Null, |r| range_json(&r)),
        ),
        ("event_kind", event_kind.into()),
        ("parse_status", parse_status.into()),
        ("session", key.into()),
        ("generation", generation.into()),
        ("direction", direction.map_or(Json::Null, Json::from)),
        ("peer_asn", outer.peer_asn.into()),
        ("local_asn", outer.local_asn.into()),
        ("peer_address", outer.peer_address.to_string().into()),
        ("local_address", outer.local_address.to_string().into()),
        ("interface_index", outer.interface_index.into()),
        ("address_afi", outer.address_afi.into()),
        ("locally_generated", outer.locally_generated.into()),
        ("container_add_path", outer.add_path.into()),
        ("asn_width", outer.asn_width.into()),
        ("timestamp_seconds", record.time.seconds.into()),
        (
            "timestamp_microseconds",
            record.time.microseconds.map_or(Json::Null, Json::from),
        ),
        (
            "message_range",
            message_range.map_or(Json::Null, |range| range_json(&range)),
        ),
        ("issues", Json::array(issues.into_iter().map(Json::from))),
        ("detail", detail.unwrap_or(Json::Null)),
        ("source_authenticated", false.into()),
        ("endpoint_state_claimed", false.into()),
    ])
}

fn rejected_message_event(
    context: EventContext<'_>,
    range: &SourceRange,
    status: &str,
    issue: &'static str,
    error: &Error,
) -> Json {
    event_json(
        context,
        "message",
        status,
        vec![issue],
        Some(Json::object([
            ("code", format!("{:?}", error.code).into()),
            ("offset", error.offset.into()),
            (
                "message_sha256",
                range.sha256.clone().map_or(Json::Null, Json::String),
            ),
        ])),
        Some(range.clone()),
    )
}

/// Opaque route payloads cannot establish continuity of native candidates.
/// A family-header-only MP_UNREACH contains no NLRI, even when the family is
/// unsupported; retain that journal boundary without poisoning native routes.
/// The shared parser emits exactly one multiprotocol opaque item per unresolved
/// attribute, so the range census also distinguishes mixed/partial updates.
pub(super) fn route_projection_incomplete(parsed: &super::ParsedUpdate) -> bool {
    if parsed.opaque_nlri.is_empty() {
        return false;
    }
    let only_multiprotocol = parsed.opaque_nlri.iter().all(|item| {
        matches!(item, Json::Object(fields) if fields.iter().any(|(name, value)|
            *name == "kind" && matches!(value, Json::String(kind) if kind == "multiprotocol_layout_unresolved")))
    });
    let only_empty_unreach = parsed
        .attribute_ranges
        .iter()
        .filter(|range| {
            matches!(range.code, 14 | 15)
                && range.interpretation == "opaque_family_capability_or_add_path_layout"
        })
        .all(|range| range.code == 15 && range.end - range.value_start == 3);
    !(only_multiprotocol && only_empty_unreach)
}

fn update_detail(
    parsed: &super::ParsedUpdate,
    outer: &Bgp4mp,
    capability_basis: &str,
    message_range: &SourceRange,
) -> Json {
    Json::object([
        (
            "attribute_ranges",
            Json::array(parsed.attribute_ranges.iter().map(attribute_range_json)),
        ),
        ("disposition", parsed.disposition.into()),
        ("known_disposition", parsed.known_disposition.into()),
        (
            "route_projection_incomplete",
            route_projection_incomplete(parsed).into(),
        ),
        (
            "internal_local_pref_missing",
            parsed.internal_local_pref_missing.into(),
        ),
        (
            "malformed_attribute_envelope",
            parsed
                .malformed_attribute_envelope
                .clone()
                .unwrap_or(Json::Null),
        ),
        (
            "peer_relationship",
            parsed.peer_relationship.as_str().into(),
        ),
        (
            "peer_relationship_basis",
            parsed.peer_relationship_basis.into(),
        ),
        (
            "peer_relationship_unresolved",
            parsed.peer_relationship_unresolved.into(),
        ),
        (
            "end_of_rib",
            Json::array(parsed.end_of_rib.iter().map(|(afi, safi)| {
                Json::object([("afi", (*afi).into()), ("safi", (*safi).into())])
            })),
        ),
        ("as4_reconstruction", parsed.as4_reconstruction.clone()),
        ("opaque_nlri", Json::Array(parsed.opaque_nlri.clone())),
        (
            "missing_mandatory_attributes",
            Json::array(parsed.missing_mandatory.iter().map(|code| (*code).into())),
        ),
        ("capability_context_basis", capability_basis.into()),
        (
            "container_layout",
            Json::object([
                ("asn_width", outer.asn_width.into()),
                ("add_path", outer.add_path.into()),
                ("layout_source", "mrt_subtype".into()),
            ]),
        ),
        ("message_range", range_json(message_range)),
        (
            "message_sha256",
            message_range
                .sha256
                .clone()
                .map_or(Json::Null, Json::String),
        ),
    ])
}

#[cfg(test)]
mod imported_occurrence_tests {
    use super::*;

    fn message() -> Vec<u8> {
        let mut bytes = vec![0xff; 16];
        bytes.extend([0, 31, 2, 0, 4, 24, 192, 0, 2, 0, 0, 24, 198, 51, 100]);
        bytes
    }

    #[test]
    fn imported_occurrence_endpoints_cover_withdrawals_lengths_and_announcements() {
        let message = message();
        let range = SourceRange {
            start: 100,
            end: 131,
            sha256: Some(sha256::hex(&sha256::digest(&message))),
        };
        let inventory =
            imported_attribute_inventory(&[], &message, &range, 1, &Limits::default()).unwrap();
        let Json::Object(fields) = &inventory else {
            panic!("inventory")
        };
        let get = |name| &fields.iter().find(|(key, _)| *key == name).unwrap().1;
        assert_eq!(
            get("message_prefix_hex"),
            &Json::from(sha256::hex(&message[..27]))
        );
        assert_eq!(
            get("message_suffix_hex"),
            &Json::from(sha256::hex(&message[27..]))
        );
        assert_eq!(fields.len(), 7);
        let exact = inventory.encoded_len_bounded(usize::MAX).unwrap();
        for limit in [exact, exact - 1] {
            let result = imported_attribute_inventory(
                &[],
                &message,
                &range,
                1,
                &Limits {
                    input_bytes: limit,
                    retained_bytes: limit,
                    output_bytes: limit,
                    ..Limits::default()
                },
            );
            assert_eq!(result.is_ok(), limit == exact);
        }
    }

    #[test]
    fn imported_occurrence_endpoint_hex_fanout_is_admitted_before_materialization() {
        let message = message();
        let range = SourceRange {
            start: 100,
            end: 131,
            sha256: Some(sha256::hex(&sha256::digest(&message))),
        };
        let hex = message.len() * 2;
        for limits in [
            Limits {
                input_bytes: hex - 1,
                ..Limits::default()
            },
            Limits {
                retained_bytes: hex * 2 - 1,
                ..Limits::default()
            },
            Limits {
                output_bytes: hex * 2 - 1,
                ..Limits::default()
            },
        ] {
            let routes = if limits.input_bytes == hex - 1 { 1 } else { 2 };
            assert_eq!(
                imported_attribute_inventory(&[], &message, &range, routes, &limits)
                    .unwrap_err()
                    .field,
                "bgp_mrt_imported_occurrence_hex_fanout"
            );
        }
        assert_eq!(
            imported_attribute_inventory(
                &[],
                &message,
                &range,
                2,
                &Limits {
                    work: hex * 4 - 1,
                    ..Limits::default()
                }
            )
            .unwrap_err()
            .field,
            "bgp_mrt_imported_occurrence_hex_work"
        );
    }
}

#[cfg(test)]
mod transition_tests {
    use super::valid_fsm_transition;

    #[test]
    fn reported_state_edges_follow_the_base_fsm() {
        for (old, new) in [
            (1, 2),
            (1, 3),
            (2, 1),
            (2, 3),
            (2, 4),
            (3, 1),
            (3, 2),
            (3, 4),
            (4, 1),
            (4, 3),
            (4, 5),
            (5, 1),
            (5, 6),
            (6, 1),
        ] {
            assert!(valid_fsm_transition(old, new), "{old} -> {new}");
        }
        for (old, new) in [
            (2, 5),
            (3, 5),
            (2, 6),
            (3, 6),
            (4, 6),
            (5, 4),
            (6, 5),
            (1, 1),
            (4, 4),
            (6, 6),
        ] {
            assert!(!valid_fsm_transition(old, new), "{old} -> {new}");
        }
    }
}

#[cfg(test)]
mod observation_time_tests {
    use super::super::super::bgp_mrt::MrtTime;
    use super::*;

    #[test]
    fn ordinary_and_extended_raw_time_have_distinct_numeric_admission() {
        let mut record = MrtRecord {
            offset: 0,
            length: 0,
            record_type: 16,
            subtype: 99,
            time: MrtTime {
                seconds: 30,
                microseconds: None,
            },
            sha256: String::new(),
            body: MrtBody::Opaque {
                reason: "test",
                bytes: Vec::new(),
            },
        };
        assert_eq!(observation_time_ns(&record), Some(30_000_000_000));
        record.time.microseconds = Some(999_999);
        assert_eq!(observation_time_ns(&record), Some(30_000_000_000));
        record.record_type = 17;
        for (raw, expected) in [
            (None, None),
            (Some(0), Some(30_000_000_000)),
            (Some(999_999), Some(30_999_999_000)),
            (Some(1_000_000), None),
            (Some(u32::MAX), None),
        ] {
            record.time.microseconds = raw;
            assert_eq!(observation_time_ns(&record), expected);
            assert_eq!(
                record.time.microseconds, raw,
                "classification must preserve raw evidence"
            );
        }
    }
}

#[cfg(test)]
mod continuity_budget_tests {
    use super::super::super::bgp_mrt::{MrtLimits, MrtSource};
    use super::*;

    fn fixture() -> (MrtBatch, ReplayState, Json) {
        let mut body = vec![0; 8];
        body.extend(7u16.to_be_bytes());
        body.extend(1u16.to_be_bytes());
        body.extend([198, 51, 100, 1, 198, 51, 100, 2]);
        body.extend([0xff; 16]);
        body.extend(20u16.to_be_bytes());
        body.extend([4, 0]);
        let mut raw = 1u32.to_be_bytes().to_vec();
        raw.extend(16u16.to_be_bytes());
        raw.extend(4u16.to_be_bytes());
        raw.extend((body.len() as u32).to_be_bytes());
        raw.extend(body);
        let limits = Limits::default();
        let batch = MrtBatch::parse(
            &raw,
            MrtSource {
                source_id: "budget-source".into(),
                checkpoint_id: "budget-checkpoint".into(),
            },
            &MrtLimits::default(),
        )
        .unwrap();
        let mut state = ReplayState::default();
        let range = batch.bgp4mp_message_source_range(0).unwrap().unwrap();
        let replay =
            replay_message_record(&batch, 0, &batch.records[0], range, &limits, &mut state)
                .unwrap();
        assert_eq!(event_text(&replay.event, "parse_status"), Some("rejected"));
        (batch, state, replay.event)
    }

    #[test]
    fn exact_continuity_inventory_peak_and_work_reject_one_below() {
        let (batch, mut state, event) = fixture();
        let (cuts, work) = state
            .continuity_cuts(
                &batch,
                0,
                &batch.records[0],
                &event,
                None,
                &Limits::default(),
            )
            .unwrap();
        assert_eq!(cuts.len(), 1);
        let cut_bytes = state.continuity_contexts.values().next().unwrap().1
            + cuts[0].record_id.len()
            + cuts[0].reason.len();
        let peak = state.retained_bytes(&Limits::default()).unwrap() + cut_bytes;
        for cap in [peak, peak - 1] {
            let (batch, mut state, event) = fixture();
            let result = state.continuity_cuts(
                &batch,
                0,
                &batch.records[0],
                &event,
                None,
                &Limits {
                    retained_bytes: cap,
                    ..Limits::default()
                },
            );
            assert_eq!(result.is_ok(), cap == peak, "cap={cap} peak={peak}");
            if let Err(error) = result {
                assert_eq!(error.field, "bgp_mrt_continuity_retained");
                assert!(
                    state.pending_cuts.is_empty(),
                    "pending negative preflight precedes insertion"
                );
                assert!(state.retained_bytes(&Limits::default()).unwrap() <= cap);
            }
        }
        for cap in [work, work - 1] {
            let (batch, mut state, event) = fixture();
            let result = state.continuity_cuts(
                &batch,
                0,
                &batch.records[0],
                &event,
                None,
                &Limits {
                    work: cap,
                    ..Limits::default()
                },
            );
            assert_eq!(result.is_ok(), cap == work, "cap={cap} work={work}");
            if let Err(error) = result {
                assert_eq!(error.field, "bgp_mrt_gap_work");
            }
        }
    }
}
