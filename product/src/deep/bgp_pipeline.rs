//! Atomic join from captured BGP messages to the offline session observer and
//! Adj-RIB-In candidate model. This is evidence reduction, not an active speaker.
use super::bgp::{self, PcapMetadata, RouteAction, SessionState, SourceKind};
use super::bgp_rib::{
    AdjRibIn, ApplyStatus as RibApplyStatus, PathId, RibAction, RibEvent, RibEventKind, RibScope,
};
use super::bgp_session::{
    ApplyStatus as SessionApplyStatus, Capability, Event, EventKind, Family, OpenAdvertisement,
    PartitionKind, ProtocolResetKind, SessionKey, SessionObserver, SourcePartition,
};
use super::bgp_state::{self, Observation, ObservationKind, RoutePathId};
use super::model::{bad, Limits};
use pcap_evidence::{json::Json, provenance::EvidenceBytes, sha256, Error, Result};
use std::collections::BTreeMap;

/// Result of one message applied atomically to all three owned projections.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApplyReceipt {
    pub normalized: Json,
    pub observation_sha256: [u8; 32],
    pub session_status: SessionApplyStatus,
    pub rib_status: Option<RibApplyStatus>,
    pub protocol_reset: bool,
    pub replayed: bool,
}

#[derive(Clone)]
struct AppliedRecord {
    input_sha256: [u8; 32],
    metadata: PcapMetadata,
    receipt: ApplyReceipt,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BoundaryKind {
    Gap,
    Reset,
}

#[derive(Clone)]
struct AppliedBoundary {
    kind: BoundaryKind,
    reason: String,
    receipt: BoundaryReceipt,
}

/// Result of a caller-observed transport gap or generation boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BoundaryReceipt {
    pub session_status: SessionApplyStatus,
    pub rib_status: Option<RibApplyStatus>,
    pub previous_generation: u64,
    pub generation: u64,
    pub replayed: bool,
}

/// One immutable capture, source label, and caller-assigned TCP session.
///
/// `apply_message`, `observe_gap`, and `reset_generation` stage a complete clone.
/// No wire/session/RIB state is published unless every downstream operation
/// succeeds. A changed immutable record identity taints the pipeline and blocks
/// later application; the retained conflict remains available for inspection.
#[derive(Clone)]
pub struct CapturedSessionPipeline {
    capture_namespace: [u8; 32],
    source_id: String,
    session: u64,
    limits: Limits,
    wire: SessionState,
    observer: SessionObserver,
    rib: AdjRibIn,
    applied: BTreeMap<String, AppliedRecord>,
    boundaries: BTreeMap<String, AppliedBoundary>,
    applied_bytes: usize,
    tainted: bool,
}

impl CapturedSessionPipeline {
    pub fn new(
        capture_namespace: [u8; 32],
        source_id: String,
        session: u64,
        limits: Limits,
    ) -> Result<Self> {
        limits.validate()?;
        let key = SessionKey {
            source: SourcePartition {
                kind: PartitionKind::Captured,
                source_id: source_id.clone(),
                partition_id: format!(
                    "capture-namespace-sha256:{}",
                    sha256::hex(&capture_namespace)
                ),
            },
            session: session.to_string(),
        };
        Ok(Self {
            capture_namespace,
            source_id,
            session,
            observer: SessionObserver::new(key, limits.clone())?,
            rib: AdjRibIn::new(limits.clone())?,
            wire: SessionState::default(),
            limits,
            applied: BTreeMap::new(),
            boundaries: BTreeMap::new(),
            applied_bytes: 0,
            tainted: false,
        })
    }

    pub fn wire_state(&self) -> &SessionState {
        &self.wire
    }
    pub fn observer(&self) -> &SessionObserver {
        &self.observer
    }
    pub fn rib(&self) -> &AdjRibIn {
        &self.rib
    }
    pub fn tainted(&self) -> bool {
        self.tainted
    }

    pub fn apply_message(
        &mut self,
        bytes: &EvidenceBytes,
        metadata: PcapMetadata,
    ) -> Result<ApplyReceipt> {
        if metadata.source_id != self.source_id || metadata.session != Some(self.session) {
            return Err(bad(
                "bgp_pipeline_scope",
                0,
                "message source or session differs from the bound pipeline",
            ));
        }
        if bytes.spans().is_empty()
            || bytes
                .spans()
                .iter()
                .any(|span| span.packet.capture != self.capture_namespace)
        {
            return Err(bad(
                "bgp_pipeline_capture",
                0,
                "message provenance differs from the bound capture",
            ));
        }
        let input_sha256 = input_identity(bytes)?;
        if let Some(previous) = self.applied.get(&metadata.record_id) {
            if previous.input_sha256 == input_sha256 && previous.metadata == metadata {
                let mut receipt = previous.receipt.clone();
                receipt.session_status = SessionApplyStatus::IdenticalReplay;
                receipt.rib_status = receipt.rib_status.map(|_| RibApplyStatus::IdenticalReplay);
                receipt.protocol_reset = false;
                receipt.replayed = true;
                return Ok(receipt);
            }
        }
        self.require_usable()?;

        let mut next = self.clone();
        let normalized = bgp::decode_pcap(bytes, metadata.clone(), &mut next.wire, &next.limits)?;
        let observation = Observation::from_normalized(&normalized, None, &next.limits)?;
        let event = session_event(
            &observation,
            next.observer.key().source.clone(),
            next.wire.generation(),
        )?;
        let session_status = next.observer.apply(event.clone())?;
        if matches!(session_status, SessionApplyStatus::IdentityConflict) {
            next.wire = self.wire.clone();
        }
        let protocol_reset = matches!(event.kind, EventKind::ProtocolReset { .. })
            && !matches!(session_status, SessionApplyStatus::IdentityConflict);
        let mut rib_event = if matches!(session_status, SessionApplyStatus::IdentityConflict) {
            Some(RibEvent {
                scope: rib_scope(
                    observation.source(),
                    &event.session.source,
                    event.generation,
                    None,
                )?,
                record_id: observation.source().record_id.clone(),
                kind: RibEventKind::Gap {
                    reason: "session_record_identity_conflict".into(),
                },
            })
        } else {
            rib_event(&observation, &event, &next.limits)?
        };
        if rib_event
            .as_ref()
            .is_some_and(|candidate| matches!(candidate.kind, RibEventKind::Reset { .. }))
            && !next.has_rib_generation(event.generation)
        {
            rib_event = None;
        }
        let rib_status = rib_event.map(|event| next.rib.apply(event)).transpose()?;
        next.tainted = matches!(session_status, SessionApplyStatus::IdentityConflict)
            || matches!(rib_status, Some(RibApplyStatus::IdentityConflict));
        let receipt = ApplyReceipt {
            observation_sha256: observation.sha256(),
            normalized,
            session_status,
            rib_status,
            protocol_reset,
            replayed: false,
        };
        if !next.applied.contains_key(&metadata.record_id)
            && !next.boundaries.contains_key(&metadata.record_id)
        {
            if next
                .applied
                .len()
                .checked_add(next.boundaries.len())
                .is_none_or(|count| count >= next.limits.elements)
            {
                return Err(Error::limit("bgp_pipeline_records"));
            }
            let retained_bytes = retained_record_bytes(&metadata, &receipt, &next.limits)?;
            next.applied_bytes = next
                .applied_bytes
                .checked_add(retained_bytes)
                .ok_or_else(|| Error::limit("bgp_pipeline_retained"))?;
            if next.applied_bytes > next.limits.retained_bytes {
                return Err(Error::limit("bgp_pipeline_retained"));
            }
            next.applied.insert(
                metadata.record_id.clone(),
                AppliedRecord {
                    input_sha256,
                    metadata,
                    receipt: receipt.clone(),
                },
            );
        }
        *self = next;
        Ok(receipt)
    }

    /// Record a continuity loss without inventing a successor generation.
    pub fn observe_gap(&mut self, record_id: String, reason: String) -> Result<BoundaryReceipt> {
        if let Some(previous) = self.boundaries.get(&record_id) {
            if previous.kind == BoundaryKind::Gap && previous.reason == reason {
                return Ok(replayed_boundary(previous));
            }
        }
        self.require_usable()?;
        let mut next = self.clone();
        let generation = next.wire.generation();
        let session_event = Event {
            session: next.observer.key().clone(),
            generation,
            direction: None,
            record_id: record_id.clone(),
            kind: EventKind::Gap {
                reason: reason.clone(),
            },
        };
        let session_status = next.observer.apply(session_event)?;
        let rib_status = Some(next.rib.apply(RibEvent {
            scope: RibScope {
                source: next.observer.key().source.clone(),
                session: next.observer.key().session.clone(),
                generation,
                direction: None,
                peer: None,
            },
            record_id: record_id.clone(),
            kind: RibEventKind::Gap {
                reason: reason.clone(),
            },
        })?);
        next.tainted = matches!(session_status, SessionApplyStatus::IdentityConflict)
            || matches!(rib_status, Some(RibApplyStatus::IdentityConflict));
        let receipt = BoundaryReceipt {
            session_status,
            rib_status,
            previous_generation: generation,
            generation,
            replayed: false,
        };
        next.retain_boundary(record_id, BoundaryKind::Gap, reason, receipt)?;
        *self = next;
        Ok(receipt)
    }

    /// Advance after an explicit caller-observed transport boundary. This is
    /// separate from `observe_gap`: loss of continuity alone does not prove a
    /// new TCP/BGP generation.
    pub fn reset_generation(
        &mut self,
        record_id: String,
        reason: String,
    ) -> Result<BoundaryReceipt> {
        if let Some(previous) = self.boundaries.get(&record_id) {
            if previous.kind == BoundaryKind::Reset && previous.reason == reason {
                return Ok(replayed_boundary(previous));
            }
        }
        self.require_usable()?;
        let mut next = self.clone();
        let previous_generation = next.wire.generation();
        next.wire.reset()?;
        let generation = next.wire.generation();
        let session_status = next.observer.apply(Event {
            session: next.observer.key().clone(),
            generation,
            direction: None,
            record_id: record_id.clone(),
            kind: EventKind::Reset {
                previous_generation,
                reason: reason.clone(),
            },
        })?;
        if matches!(session_status, SessionApplyStatus::IdentityConflict) {
            next.wire = self.wire.clone();
        }
        let committed_generation = if matches!(session_status, SessionApplyStatus::IdentityConflict)
        {
            previous_generation
        } else {
            generation
        };
        let rib_status = if matches!(session_status, SessionApplyStatus::IdentityConflict) {
            Some(next.rib.apply(RibEvent {
                scope: RibScope {
                    source: next.observer.key().source.clone(),
                    session: next.observer.key().session.clone(),
                    generation: previous_generation,
                    direction: None,
                    peer: None,
                },
                record_id: record_id.clone(),
                kind: RibEventKind::Gap {
                    reason: "session_record_identity_conflict".into(),
                },
            })?)
        } else if next.has_rib_generation(previous_generation) {
            Some(next.rib.apply(RibEvent {
                scope: RibScope {
                    source: next.observer.key().source.clone(),
                    session: next.observer.key().session.clone(),
                    generation,
                    direction: None,
                    peer: None,
                },
                record_id: record_id.clone(),
                kind: RibEventKind::Reset {
                    previous_generation,
                    reason: reason.clone(),
                },
            })?)
        } else {
            None
        };
        next.tainted = matches!(session_status, SessionApplyStatus::IdentityConflict)
            || matches!(rib_status, Some(RibApplyStatus::IdentityConflict));
        let receipt = BoundaryReceipt {
            session_status,
            rib_status,
            previous_generation,
            generation: committed_generation,
            replayed: false,
        };
        next.retain_boundary(record_id, BoundaryKind::Reset, reason, receipt)?;
        *self = next;
        Ok(receipt)
    }

    fn require_usable(&self) -> Result<()> {
        if self.tainted {
            Err(bad(
                "bgp_pipeline_tainted",
                0,
                "record identity conflict requires a new pipeline partition",
            ))
        } else {
            Ok(())
        }
    }

    fn has_rib_generation(&self, generation: u64) -> bool {
        self.rib.events().iter().any(|event| {
            event.scope.source == self.observer.key().source
                && event.scope.session == self.observer.key().session
                && event.scope.generation == generation
        })
    }

    fn retain_boundary(
        &mut self,
        record_id: String,
        kind: BoundaryKind,
        reason: String,
        receipt: BoundaryReceipt,
    ) -> Result<()> {
        if self.boundaries.contains_key(&record_id) || self.applied.contains_key(&record_id) {
            return Ok(());
        }
        if self
            .applied
            .len()
            .checked_add(self.boundaries.len())
            .is_none_or(|count| count >= self.limits.elements)
        {
            return Err(Error::limit("bgp_pipeline_records"));
        }
        let retained_bytes = record_id
            .len()
            .checked_add(reason.len())
            .and_then(|size| size.checked_add(128))
            .ok_or_else(|| Error::limit("bgp_pipeline_retained"))?;
        self.applied_bytes = self
            .applied_bytes
            .checked_add(retained_bytes)
            .ok_or_else(|| Error::limit("bgp_pipeline_retained"))?;
        if self.applied_bytes > self.limits.retained_bytes {
            return Err(Error::limit("bgp_pipeline_retained"));
        }
        self.boundaries.insert(
            record_id,
            AppliedBoundary {
                kind,
                reason,
                receipt,
            },
        );
        Ok(())
    }
}

fn replayed_boundary(previous: &AppliedBoundary) -> BoundaryReceipt {
    let mut receipt = previous.receipt;
    receipt.session_status = SessionApplyStatus::IdenticalReplay;
    receipt.rib_status = receipt.rib_status.map(|_| RibApplyStatus::IdenticalReplay);
    receipt.replayed = true;
    receipt
}

fn input_identity(bytes: &EvidenceBytes) -> Result<[u8; 32]> {
    let mut hash = sha256::Sha256::new();
    hash.update(b"pcap-evidence.bgp.pipeline-input.v1\0");
    hash_u64(&mut hash, bytes.len())?;
    hash.update(bytes.data());
    hash_u64(&mut hash, bytes.spans().len())?;
    for span in bytes.spans() {
        hash_u64(&mut hash, span.start)?;
        hash_u64(&mut hash, span.end)?;
        hash.update(&span.packet.capture);
        hash.update(&span.packet.frame.to_be_bytes());
        hash.update(&span.packet.record_offset.to_be_bytes());
        hash_u64(&mut hash, span.packet_start)?;
    }
    Ok(hash.finalize())
}

fn hash_u64(hash: &mut sha256::Sha256, value: usize) -> Result<()> {
    let value = u64::try_from(value).map_err(|_| Error::limit("bgp_pipeline_identity"))?;
    hash.update(&value.to_be_bytes());
    Ok(())
}

fn retained_record_bytes(
    metadata: &PcapMetadata,
    receipt: &ApplyReceipt,
    limits: &Limits,
) -> Result<usize> {
    let normalized = receipt.normalized.encode_bounded(limits.output_bytes)?;
    [
        normalized.len(),
        metadata.source_id.len(),
        metadata.record_id.len(),
        metadata.peer.as_ref().map_or(0, String::len),
        metadata.local.as_ref().map_or(0, String::len),
        128,
    ]
    .into_iter()
    .try_fold(0usize, |total, size| {
        total
            .checked_add(size)
            .ok_or_else(|| Error::limit("bgp_pipeline_retained"))
    })
}

fn session_event(
    observation: &Observation,
    source: SourcePartition,
    decoder_generation: u64,
) -> Result<Event> {
    let observed = observation.source();
    if observed.kind != SourceKind::Captured || observed.source_id != source.source_id {
        return Err(bad(
            "bgp_pipeline_source",
            0,
            "captured observation source does not match partition",
        ));
    }
    let session = observed
        .session
        .clone()
        .ok_or_else(|| bad("bgp_pipeline_session", 0, "captured session is required"))?;
    let generation = observed.generation.ok_or_else(|| {
        bad(
            "bgp_pipeline_generation",
            0,
            "captured generation is required",
        )
    })?;
    let normalized = observation.normalized();
    let kind = match observation.kind() {
        ObservationKind::Open => EventKind::Open(open_advertisement(normalized)?),
        ObservationKind::Keepalive => EventKind::Keepalive,
        ObservationKind::Notification => EventKind::ProtocolReset {
            next_generation: decoder_generation,
            kind: ProtocolResetKind::Notification,
        },
        ObservationKind::RouteRefresh => {
            let detail = bgp_state::member(normalized, "message_detail")?;
            EventKind::RouteRefresh {
                family: Family {
                    afi: u16::try_from(bgp_state::number(bgp_state::member(detail, "afi")?)?)
                        .map_err(|_| bad("bgp_pipeline_family", 0, "AFI out of range"))?,
                    safi: u8::try_from(bgp_state::number(bgp_state::member(detail, "safi")?)?)
                        .map_err(|_| bad("bgp_pipeline_family", 0, "SAFI out of range"))?,
                },
                subtype: Some(
                    u8::try_from(bgp_state::number(bgp_state::member(detail, "reserved")?)?)
                        .map_err(|_| bad("bgp_pipeline_refresh", 0, "subtype out of range"))?,
                ),
            }
        }
        ObservationKind::Routes => {
            let detail = bgp_state::member(normalized, "message_detail")?;
            if bgp_state::text(bgp_state::member(detail, "update_disposition")?)? == "session_reset"
            {
                EventKind::ProtocolReset {
                    next_generation: decoder_generation,
                    kind: ProtocolResetKind::UpdateError,
                }
            } else if let Some(family) = end_of_rib(detail)? {
                EventKind::EndOfRib(family)
            } else {
                EventKind::Update
            }
        }
        ObservationKind::Reset => {
            return Err(bad(
                "bgp_pipeline_observation",
                0,
                "captured decoder cannot emit caller reset observations",
            ))
        }
    };
    if matches!(kind, EventKind::ProtocolReset { .. }) {
        if generation.checked_add(1) != Some(decoder_generation) {
            return Err(bad(
                "bgp_pipeline_generation",
                0,
                "decoder did not advance exactly once after protocol reset",
            ));
        }
    } else if generation != decoder_generation {
        return Err(bad(
            "bgp_pipeline_generation",
            0,
            "observation and decoder generations disagree",
        ));
    }
    Ok(Event {
        session: SessionKey { source, session },
        generation,
        direction: observed.direction,
        record_id: observed.record_id.clone(),
        kind,
    })
}

fn open_advertisement(normalized: &Json) -> Result<OpenAdvertisement> {
    let detail = bgp_state::member(normalized, "message_detail")?;
    let ambiguous = match bgp_state::member(detail, "ambiguous")? {
        Json::Bool(value) => *value,
        _ => return Err(bad("bgp_pipeline_open", 0, "ambiguous must be boolean")),
    };
    let capabilities = bgp_state::array(bgp_state::member(detail, "capability_occurrences")?)?
        .iter()
        .map(|occurrence| {
            Ok(Capability {
                code: u8::try_from(bgp_state::number(bgp_state::member(occurrence, "code")?)?)
                    .map_err(|_| bad("bgp_pipeline_capability", 0, "code out of range"))?,
                value_sha256: bgp_state::text(bgp_state::member(occurrence, "sha256")?)?.to_owned(),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(OpenAdvertisement {
        capabilities,
        ambiguous,
    })
}

fn end_of_rib(detail: &Json) -> Result<Option<Family>> {
    let families = bgp_state::array(bgp_state::member(detail, "end_of_rib")?)?;
    if families.len() > 1 {
        return Err(bad(
            "bgp_pipeline_eor",
            0,
            "one UPDATE cannot establish multiple EOR markers",
        ));
    }
    families
        .first()
        .map(|family| {
            Ok(Family {
                afi: u16::try_from(bgp_state::number(bgp_state::member(family, "afi")?)?)
                    .map_err(|_| bad("bgp_pipeline_family", 0, "AFI out of range"))?,
                safi: u8::try_from(bgp_state::number(bgp_state::member(family, "safi")?)?)
                    .map_err(|_| bad("bgp_pipeline_family", 0, "SAFI out of range"))?,
            })
        })
        .transpose()
}

fn rib_event(
    observation: &Observation,
    session: &Event,
    limits: &Limits,
) -> Result<Option<RibEvent>> {
    let source = observation.source();
    let kind = match &session.kind {
        EventKind::ProtocolReset { .. } => RibEventKind::Reset {
            previous_generation: session.generation,
            reason: "decoded_protocol_session_reset".into(),
        },
        EventKind::EndOfRib(family) => RibEventKind::EndOfRib(*family),
        EventKind::Update => {
            let mut actions = Vec::with_capacity(observation.routes().len());
            for route in observation.routes() {
                let path_id = match route.path_id() {
                    RoutePathId::Absent => PathId::Absent,
                    RoutePathId::Present(value) => PathId::Present(value),
                };
                let action = match route.action() {
                    RouteAction::Withdraw => RibAction::Withdraw {
                        prefix: route.prefix().clone(),
                        path_id,
                    },
                    RouteAction::Announce if route.ambiguous_attributes() => RibAction::Reject {
                        prefix: route.prefix().clone(),
                        path_id,
                        reason: "ambiguous_attribute_context".into(),
                    },
                    RouteAction::Announce => RibAction::Announce {
                        prefix: route.prefix().clone(),
                        path_id,
                        attributes: route.attributes().clone(),
                        attribute_identity: {
                            let encoded = route
                                .attribute_identity()
                                .encode_bounded(limits.input_bytes)?;
                            format!(
                                "sha256:{}",
                                sha256::hex(&sha256::digest(encoded.as_bytes()))
                            )
                        },
                    },
                };
                actions.push(action);
            }
            if actions.is_empty() {
                return Ok(None);
            }
            RibEventKind::Update(actions)
        }
        EventKind::Open(_)
        | EventKind::Keepalive
        | EventKind::Notification
        | EventKind::RouteRefresh { .. }
        | EventKind::Stale { .. }
        | EventKind::Gap { .. }
        | EventKind::Reset { .. } => return Ok(None),
    };
    let generation = match &session.kind {
        EventKind::ProtocolReset {
            next_generation, ..
        } => *next_generation,
        _ => session.generation,
    };
    Ok(Some(RibEvent {
        scope: rib_scope(
            source,
            &session.session.source,
            generation,
            if matches!(session.kind, EventKind::ProtocolReset { .. }) {
                None
            } else {
                source.direction
            },
        )?,
        record_id: source.record_id.clone(),
        kind,
    }))
}

fn rib_scope(
    source: &bgp_state::Source,
    partition: &SourcePartition,
    generation: u64,
    direction: Option<u8>,
) -> Result<RibScope> {
    let session = source
        .session
        .clone()
        .ok_or_else(|| bad("bgp_pipeline_session", 0, "session is required"))?;
    Ok(RibScope {
        source: partition.clone(),
        session,
        generation,
        direction,
        peer: if direction.is_some() {
            source.peer.clone()
        } else {
            None
        },
    })
}
