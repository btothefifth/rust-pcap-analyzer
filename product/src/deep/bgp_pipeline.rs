//! Atomic join from captured BGP messages to the offline session observer and
//! Adj-RIB-In candidate model. This is evidence reduction, not an active speaker.
use super::bgp::{self, PcapMetadata, RouteAction, SessionState, SourceKind};
use super::bgp_rib::{
    AdjRibIn, ApplyStatus as RibApplyStatus, PathId, RibAction, RibEvent, RibEventKind, RibScope,
};
use super::bgp_session::{
    ApplyStatus as SessionApplyStatus, Capability, Event, EventKind, Family, OpenAdvertisement,
    OpenContinuityVerdict, PartitionKind, ProtocolResetKind, SessionKey, SessionObserver,
    SourcePartition,
};
use super::bgp_state::{self, Observation, ObservationKind, RoutePathId};
use super::model::{bad, Limits};
use pcap_evidence::{json::Json, provenance::EvidenceBytes, sha256, Error, Result};
use std::collections::{BTreeMap, HashMap};

/// Result of one message applied atomically to all three owned projections.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApplyReceipt {
    pub normalized: Json,
    pub observation_sha256: [u8; 32],
    pub session_status: SessionApplyStatus,
    pub rib_status: Option<RibApplyStatus>,
    pub protocol_reset: bool,
    pub replayed: bool,
    pub continuity: Option<DecodedContinuity>,
}

/// An admitted native continuity effect. It carries no route actions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecodedContinuity {
    pub scope: RibScope,
    pub reason: String,
    pub native_status: Option<RibApplyStatus>,
    pub session_status: SessionApplyStatus,
    pub newly_applied: bool,
    pub(crate) kind: super::bgp_rib::NativeContinuityKind,
    pub(crate) effect: super::bgp_rib::NativeContinuityEffect,
}
impl DecodedContinuity {
    pub fn is_reset(&self) -> bool {
        matches!(
            self.kind,
            super::bgp_rib::NativeContinuityKind::Reset { .. }
        )
    }
    pub fn generations(&self) -> (u64, u64) {
        match self.kind {
            super::bgp_rib::NativeContinuityKind::Gap => {
                (self.scope.generation, self.scope.generation)
            }
            super::bgp_rib::NativeContinuityKind::Reset {
                previous_generation,
                next_generation,
            } => (previous_generation, next_generation),
        }
    }
    pub fn affects_scope(&self, scope: &RibScope) -> bool {
        self.newly_applied
            && super::bgp_rib::continuity_affects_scope(self.kind, self.effect, &self.scope, scope)
    }
    pub fn retained_charge(&self) -> usize {
        continuity_charge(
            &self.scope.source,
            &self.scope.session,
            self.scope.peer.as_deref(),
            &self.reason,
        )
    }
    pub fn json(&self) -> Json {
        let (previous, next) = self.generations();
        let effect = match self.effect {
            super::bgp_rib::NativeContinuityEffect::SessionGeneration => "session_generation",
            super::bgp_rib::NativeContinuityEffect::SessionAllGenerations => {
                "session_all_generations"
            }
            super::bgp_rib::NativeContinuityEffect::BaseDirectionalGeneration => {
                "base_directional_generation"
            }
        };
        Json::object([
            ("kind", if self.is_reset() { "reset" } else { "gap" }.into()),
            ("affected_scope", effect.into()),
            ("source_id", self.scope.source.source_id.clone().into()),
            (
                "partition_id",
                self.scope.source.partition_id.clone().into(),
            ),
            ("session", self.scope.session.clone().into()),
            ("generation", self.scope.generation.into()),
            (
                "direction",
                self.scope.direction.map_or(Json::Null, Json::from),
            ),
            (
                "peer",
                self.scope.peer.clone().map_or(Json::Null, Json::from),
            ),
            ("previous_generation", previous.into()),
            ("next_generation", next.into()),
            ("reason", self.reason.clone().into()),
            (
                "native_status",
                self.native_status
                    .map_or(Json::Null, |v| format!("{:?}", v).into()),
            ),
            (
                "session_status",
                format!("{:?}", self.session_status).into(),
            ),
            ("newly_applied", self.newly_applied.into()),
        ])
    }
}
fn continuity_charge(
    source: &SourcePartition,
    session: &str,
    peer: Option<&str>,
    reason: &str,
) -> usize {
    1024usize
        .saturating_add(source.source_id.len())
        .saturating_add(source.partition_id.len())
        .saturating_add(session.len())
        .saturating_add(peer.map_or(0, str::len))
        .saturating_add(reason.len())
}
fn admit_continuity(charge: usize, retained: usize, limits: &Limits) -> Result<()> {
    let total = charge
        .checked_mul(4)
        .and_then(|v| v.checked_add(retained))
        .ok_or_else(|| Error::limit("bgp_pipeline_continuity"))?;
    if total > limits.retained_bytes || total > limits.work || limits.elements < 1 {
        return Err(Error::limit("bgp_pipeline_continuity"));
    }
    Ok(())
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

/// Supplemental admitted-operation counters at the receipt-cache copy owner.
/// A failed transaction does not publish counters. These do not measure RSS,
/// allocation capacity or throughput.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PipelineReductionWork {
    pub complete_pipeline_clones: usize,
    pub copied_receipt_records: usize,
    pub copied_boundary_records: usize,
}

/// One immutable capture, source label, and caller-assigned TCP session.
///
/// Messages stage the bounded wire decoder and owned reducer plans. Explicit
/// caller boundaries retain a bounded complete-clone transaction.
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
    applied: HashMap<String, AppliedRecord>,
    boundaries: BTreeMap<String, AppliedBoundary>,
    applied_bytes: usize,
    tainted: bool,
    reduction_work: PipelineReductionWork,
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
            rib: AdjRibIn::for_embedded_projection(limits.clone())?,
            wire: SessionState::default(),
            limits,
            applied: HashMap::new(),
            boundaries: BTreeMap::new(),
            applied_bytes: 0,
            tainted: false,
            reduction_work: PipelineReductionWork::default(),
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
    pub fn reduction_work(&self) -> PipelineReductionWork {
        self.reduction_work
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
                if let Some(c) = &previous.receipt.continuity {
                    admit_continuity(c.retained_charge(), self.applied_bytes, &self.limits)?;
                }
                let mut receipt = previous.receipt.clone();
                if let Some(c) = &mut receipt.continuity {
                    c.newly_applied = false;
                }
                receipt.session_status = SessionApplyStatus::IdenticalReplay;
                receipt.rib_status = receipt.rib_status.map(|_| RibApplyStatus::IdenticalReplay);
                receipt.protocol_reset = false;
                receipt.replayed = true;
                return Ok(receipt);
            }
        }
        self.require_usable()?;

        let mut wire = self.wire.clone();
        let normalized = bgp::decode_pcap(bytes, metadata.clone(), &mut wire, &self.limits)?;
        let observation = Observation::from_normalized(&normalized, None, &self.limits)?;
        let mut event = session_event(
            &observation,
            self.observer.key().source.clone(),
            wire.generation(),
        )?;
        if let EventKind::Open(advertisement) = &event.kind {
            event.kind = EventKind::CapturedOpen {
                advertisement: advertisement.clone(),
                message_sha256: sha256::digest(bytes.data()),
            };
        }
        let open_continuity = self.observer.open_continuity(&event);
        let session_plan = self.observer.prepare(event.clone())?;
        let session_status = session_plan.status();
        if matches!(session_status, SessionApplyStatus::IdentityConflict) {
            wire = self.wire.clone();
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
        } else if session_status == SessionApplyStatus::Applied {
            if let OpenContinuityVerdict::Contradiction {
                session,
                generation,
            } = open_continuity
            {
                if self.has_rib_generation(generation) {
                    Some(RibEvent {
                        scope: RibScope {
                            source: session.source,
                            session: session.session,
                            generation,
                            // Layout uses both OPEN directions. Contradiction
                            // invalidates this bilateral session generation.
                            direction: None,
                            peer: None,
                        },
                        record_id: event.record_id.clone(),
                        kind: RibEventKind::Gap {
                            reason: "captured_open_content_contradiction".into(),
                        },
                    })
                } else {
                    None
                }
            } else {
                rib_event(&observation, &event, &self.limits)?
            }
        } else {
            rib_event(&observation, &event, &self.limits)?
        };
        if rib_event
            .as_ref()
            .is_some_and(|candidate| matches!(candidate.kind, RibEventKind::Reset { .. }))
            && !self.has_rib_generation(event.generation)
        {
            rib_event = None;
        }
        let rib_plan = rib_event
            .map(|event| self.rib.prepare_with_origin(event, observation.sha256()))
            .transpose()?;
        let rib_status = rib_plan.as_ref().map(|plan| plan.status());
        let continuity = if let Some(effect) = rib_plan.as_ref().and_then(|p| p.continuity_effect())
        {
            let charge = continuity_charge(
                &effect.scope.source,
                &effect.scope.session,
                effect.scope.peer.as_deref(),
                effect.reason,
            );
            admit_continuity(charge, self.applied_bytes, &self.limits)?;
            Some(DecodedContinuity {
                scope: effect.scope.clone(),
                reason: effect.reason.to_owned(),
                native_status: Some(effect.status),
                session_status,
                newly_applied: true,
                kind: effect.kind,
                effect: effect.effect,
            })
        } else if session_status == SessionApplyStatus::Applied && protocol_reset {
            if let EventKind::ProtocolReset {
                next_generation, ..
            } = event.kind
            {
                let reason = "decoded_protocol_session_reset";
                admit_continuity(
                    continuity_charge(&event.session.source, &event.session.session, None, reason),
                    self.applied_bytes,
                    &self.limits,
                )?;
                Some(DecodedContinuity {
                    scope: RibScope {
                        source: event.session.source.clone(),
                        session: event.session.session.clone(),
                        generation: next_generation,
                        direction: None,
                        peer: None,
                    },
                    reason: reason.into(),
                    native_status: None,
                    session_status,
                    newly_applied: true,
                    kind: super::bgp_rib::NativeContinuityKind::Reset {
                        previous_generation: event.generation,
                        next_generation,
                    },
                    effect: super::bgp_rib::NativeContinuityEffect::SessionGeneration,
                })
            } else {
                None
            }
        } else {
            None
        };
        let receipt = ApplyReceipt {
            observation_sha256: observation.sha256(),
            normalized,
            session_status,
            rib_status,
            protocol_reset,
            replayed: false,
            continuity,
        };
        let new_record = !self.applied.contains_key(&metadata.record_id)
            && !self.boundaries.contains_key(&metadata.record_id);
        let mut applied_bytes = self.applied_bytes;
        let staged_record = if new_record {
            if self
                .applied
                .len()
                .checked_add(self.boundaries.len())
                .is_none_or(|count| count >= self.limits.elements)
            {
                return Err(Error::limit("bgp_pipeline_records"));
            }
            let retained_bytes = retained_record_bytes(&metadata, &receipt, &self.limits)?;
            applied_bytes = applied_bytes
                .checked_add(retained_bytes)
                .ok_or_else(|| Error::limit("bgp_pipeline_retained"))?;
            if applied_bytes > self.limits.retained_bytes {
                return Err(Error::limit("bgp_pipeline_retained"));
            }
            Some((
                metadata.record_id.clone(),
                AppliedRecord {
                    input_sha256,
                    metadata,
                    receipt: receipt.clone(),
                },
            ))
        } else {
            None
        };
        // All fallible admission, including append capacity, precedes the first
        // semantic publication. Tokens bind each exact receiver and revision.
        if !self.observer.prepared_current(&session_plan)
            || rib_plan
                .as_ref()
                .is_some_and(|plan| !self.rib.prepared_current(plan))
        {
            return Err(bad(
                "bgp_pipeline_revision",
                0,
                "prepared reducer revision changed",
            ));
        }
        self.observer.admit_prepared(&session_plan)?;
        if staged_record.is_some() {
            self.applied
                .try_reserve(1)
                .map_err(|_| Error::limit("bgp_pipeline_capacity"))?;
        }
        self.observer.commit(session_plan);
        if let Some(plan) = rib_plan {
            self.rib.commit(plan);
        }
        self.wire = wire;
        self.tainted = matches!(session_status, SessionApplyStatus::IdentityConflict)
            || matches!(rib_status, Some(RibApplyStatus::IdentityConflict));
        if let Some((record_id, record)) = staged_record {
            self.applied.insert(record_id, record);
        }
        self.applied_bytes = applied_bytes;
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
        self.admit_continuity_snapshot()?;
        let mut next = self.clone();
        next.reduction_work.complete_pipeline_clones = next
            .reduction_work
            .complete_pipeline_clones
            .saturating_add(1);
        next.reduction_work.copied_receipt_records = next
            .reduction_work
            .copied_receipt_records
            .saturating_add(self.applied.len());
        next.reduction_work.copied_boundary_records = next
            .reduction_work
            .copied_boundary_records
            .saturating_add(self.boundaries.len());
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
        self.admit_continuity_snapshot()?;
        let mut next = self.clone();
        next.reduction_work.complete_pipeline_clones = next
            .reduction_work
            .complete_pipeline_clones
            .saturating_add(1);
        next.reduction_work.copied_receipt_records = next
            .reduction_work
            .copied_receipt_records
            .saturating_add(self.applied.len());
        next.reduction_work.copied_boundary_records = next
            .reduction_work
            .copied_boundary_records
            .saturating_add(self.boundaries.len());
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

    fn admit_continuity_snapshot(&self) -> Result<()> {
        let extra = self.applied.values().try_fold(0usize, |n, record| {
            n.checked_add(
                record
                    .receipt
                    .continuity
                    .as_ref()
                    .map_or(0, DecodedContinuity::retained_charge),
            )
            .ok_or_else(|| Error::limit("bgp_pipeline_continuity"))
        })?;
        // The original carrier is included in applied_bytes. Admit its new
        // complete-pipeline snapshot copy before invoking Clone.
        let total = self
            .applied_bytes
            .checked_add(extra)
            .ok_or_else(|| Error::limit("bgp_pipeline_continuity"))?;
        if total > self.limits.retained_bytes || total > self.limits.work {
            return Err(Error::limit("bgp_pipeline_continuity"));
        }
        Ok(())
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
        receipt
            .continuity
            .as_ref()
            .map_or(0, DecodedContinuity::retained_charge),
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
            } else if !bgp_state::array(bgp_state::member(detail, "opaque_nlri")?)?.is_empty() {
                EventKind::Gap {
                    reason: "decoded_update_opaque_route_evidence".into(),
                }
            } else if let Some(family) = end_of_rib(observation)? {
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

fn end_of_rib(observation: &Observation) -> Result<Option<Family>> {
    let families = observation.end_of_rib_families()?.ok_or_else(|| {
        bad(
            "bgp_pipeline_eor",
            0,
            "captured UPDATE EOR metadata missing",
        )
    })?;
    Ok(families.first().copied())
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
        EventKind::Gap { reason } => RibEventKind::Gap {
            reason: reason.clone(),
        },
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
        | EventKind::CapturedOpen { .. }
        | EventKind::Keepalive
        | EventKind::Notification
        | EventKind::RouteRefresh { .. }
        | EventKind::Stale { .. }
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

#[cfg(test)]
mod decoded_continuity_admission_tests {
    use super::*;
    #[test]
    fn continuity_copy_charge_exact_and_one_below() {
        let charge = 1024;
        let retained = 17;
        let exact = retained + charge * 4;
        let limits = Limits {
            retained_bytes: exact,
            work: exact,
            ..Limits::default()
        };
        admit_continuity(charge, retained, &limits).unwrap();
        for l in [
            Limits {
                retained_bytes: exact - 1,
                ..limits.clone()
            },
            Limits {
                work: exact - 1,
                ..limits.clone()
            },
        ] {
            assert_eq!(
                admit_continuity(charge, retained, &l).unwrap_err().code,
                pcap_evidence::ErrorCode::LimitExceeded
            );
        }
    }
}
