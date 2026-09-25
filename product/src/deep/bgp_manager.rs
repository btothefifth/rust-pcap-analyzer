//! Bounded owner for captured BGP session pipelines.
//!
//! The caller owns TCP reconstruction and supplies stable analysis-session IDs.
//! This manager prevents cross-session state sharing and makes lifecycle removal
//! explicit; it does not infer endpoint identity or physical connection truth.
use super::bgp::{PcapMetadata, SessionState};
use super::bgp_pipeline::{ApplyReceipt, BoundaryReceipt, CapturedSessionPipeline};
use super::bgp_rib::{PathId, RouteStatus, VersionDisposition};
use super::bgp_session::{CapabilityContext, PartitionKind, StaleKind};
use super::model::Limits;
use pcap_evidence::{json::Json, provenance::EvidenceBytes, Error, Result};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionSummary {
    pub session: u64,
    pub generation: u64,
    pub session_events: usize,
    pub rib_events: usize,
    pub route_entries: usize,
    pub active_routes: usize,
    pub unresolved_routes: usize,
    pub withdrawn_routes: usize,
    pub superseded_routes: usize,
    pub stale_routes: usize,
    pub rejected_routes: usize,
    pub eor_markers: usize,
    pub gaps: usize,
    pub tainted: bool,
}

impl SessionSummary {
    pub fn json(&self) -> Json {
        Json::object([
            ("schema", "pcap-evidence.bgp.session-summary.v1".into()),
            ("session", self.session.to_string().into()),
            ("generation", self.generation.into()),
            ("session_events", self.session_events.into()),
            ("rib_events", self.rib_events.into()),
            ("route_entries", self.route_entries.into()),
            ("active_routes", self.active_routes.into()),
            ("unresolved_routes", self.unresolved_routes.into()),
            ("withdrawn_routes", self.withdrawn_routes.into()),
            ("superseded_routes", self.superseded_routes.into()),
            ("stale_routes", self.stale_routes.into()),
            ("rejected_routes", self.rejected_routes.into()),
            ("eor_markers", self.eor_markers.into()),
            ("gaps", self.gaps.into()),
            ("tainted", self.tainted.into()),
            ("endpoint_rib_claimed", false.into()),
        ])
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionSnapshot {
    pub session: u64,
    pub summary: SessionSummary,
    pub state: Json,
}

impl SessionSnapshot {
    pub fn json(&self) -> Json {
        Json::object([
            ("schema", "pcap-evidence.bgp.session-snapshot.v1".into()),
            ("summary", self.summary.json()),
            ("state", self.state.clone()),
            ("endpoint_state_claimed", false.into()),
        ])
    }
}

#[derive(Clone)]
pub struct CapturedSessionManager {
    capture_namespace: [u8; 32],
    source_id: String,
    limits: Limits,
    sessions: BTreeMap<u64, CapturedSessionPipeline>,
}

impl CapturedSessionManager {
    pub fn new(capture_namespace: [u8; 32], source_id: String, limits: Limits) -> Result<Self> {
        limits.validate()?;
        // Construct one temporary observer to apply the same source-identity
        // validation even when no session is ever observed.
        CapturedSessionPipeline::new(capture_namespace, source_id.clone(), 0, limits.clone())?;
        Ok(Self {
            capture_namespace,
            source_id,
            limits,
            sessions: BTreeMap::new(),
        })
    }

    pub fn active_sessions(&self) -> usize {
        self.sessions.len()
    }

    pub fn contains(&self, session: u64) -> bool {
        self.sessions.contains_key(&session)
    }

    pub fn session_ids(&self) -> Vec<u64> {
        self.sessions.keys().copied().collect()
    }

    pub fn apply_message(
        &mut self,
        session: u64,
        bytes: &EvidenceBytes,
        metadata: PcapMetadata,
    ) -> Result<ApplyReceipt> {
        if metadata.session != Some(session) {
            return Err(super::model::bad(
                "bgp_manager_session",
                0,
                "metadata session differs from manager key",
            ));
        }
        if let Some(pipeline) = self.sessions.get_mut(&session) {
            return pipeline.apply_message(bytes, metadata);
        }
        if self.sessions.len() >= self.limits.active {
            return Err(Error::limit("bgp_manager_active_sessions"));
        }
        let mut pipeline = CapturedSessionPipeline::new(
            self.capture_namespace,
            self.source_id.clone(),
            session,
            self.limits.clone(),
        )?;
        let receipt = pipeline.apply_message(bytes, metadata)?;
        self.sessions.insert(session, pipeline);
        Ok(receipt)
    }

    pub fn observe_gap(
        &mut self,
        session: u64,
        record_id: String,
        reason: String,
    ) -> Result<BoundaryReceipt> {
        self.pipeline(session)?.observe_gap(record_id, reason)
    }

    pub fn reset_generation(
        &mut self,
        session: u64,
        record_id: String,
        reason: String,
    ) -> Result<BoundaryReceipt> {
        self.pipeline(session)?.reset_generation(record_id, reason)
    }

    pub fn wire_state(&self, session: u64) -> Option<&SessionState> {
        self.sessions
            .get(&session)
            .map(|pipeline| pipeline.wire_state())
    }

    pub fn summary(&self, session: u64) -> Option<SessionSummary> {
        self.sessions
            .get(&session)
            .map(|pipeline| summarize(session, pipeline))
    }

    pub fn snapshot(&self, session: u64) -> Option<SessionSnapshot> {
        self.sessions
            .get(&session)
            .map(|pipeline| snapshot(session, pipeline))
    }

    pub fn end_session(&mut self, session: u64) -> Option<SessionSummary> {
        self.sessions
            .remove(&session)
            .map(|pipeline| summarize(session, &pipeline))
    }

    pub fn end_session_snapshot(&mut self, session: u64) -> Option<SessionSnapshot> {
        self.sessions
            .remove(&session)
            .map(|pipeline| snapshot(session, &pipeline))
    }

    pub fn clear(&mut self) -> Vec<SessionSummary> {
        std::mem::take(&mut self.sessions)
            .into_iter()
            .map(|(session, pipeline)| summarize(session, &pipeline))
            .collect()
    }

    pub fn clear_snapshots(&mut self) -> Vec<SessionSnapshot> {
        std::mem::take(&mut self.sessions)
            .into_iter()
            .map(|(session, pipeline)| snapshot(session, &pipeline))
            .collect()
    }

    fn pipeline(&mut self, session: u64) -> Result<&mut CapturedSessionPipeline> {
        if !self.sessions.contains_key(&session) {
            if self.sessions.len() >= self.limits.active {
                return Err(Error::limit("bgp_manager_active_sessions"));
            }
            let pipeline = CapturedSessionPipeline::new(
                self.capture_namespace,
                self.source_id.clone(),
                session,
                self.limits.clone(),
            )?;
            self.sessions.insert(session, pipeline);
        }
        self.sessions
            .get_mut(&session)
            .ok_or_else(|| Error::limit("bgp_manager_session"))
    }
}

fn snapshot(session: u64, pipeline: &CapturedSessionPipeline) -> SessionSnapshot {
    let summary = summarize(session, pipeline);
    let observer = pipeline.observer();
    let view = observer.view();
    let capability_context = match view.map(|view| &view.context) {
        None => Json::Null,
        Some(CapabilityContext::Unresolved(reason)) => Json::object([
            ("status", "unresolved".into()),
            ("reason", (*reason).into()),
        ]),
        Some(CapabilityContext::BilateralCandidate { common_codes }) => Json::object([
            ("status", "bilateral_candidate".into()),
            (
                "common_codes",
                Json::array(common_codes.iter().copied().map(Json::from)),
            ),
        ]),
    };
    let directions = view.map_or_else(
        || Json::Array(Vec::new()),
        |view| {
            Json::array(view.directions.iter().enumerate().map(|(direction, item)| {
                Json::object([
                    ("direction", direction.into()),
                    ("open_alternatives", item.opens.len().into()),
                    ("keepalives", item.keepalives.len().into()),
                    ("updates", item.updates.len().into()),
                    ("notifications", item.notifications.len().into()),
                    ("route_refreshes", item.refreshes.len().into()),
                    ("end_of_rib", item.eors.len().into()),
                    ("stale_markers", item.stale.len().into()),
                ])
            }))
        },
    );
    let key = observer.key();
    let source_kind = match key.source.kind {
        PartitionKind::Captured => "captured",
        PartitionKind::Imported => "imported",
    };
    let routes = Json::array(pipeline.rib().entries().values().map(|entry| {
        let path_id = match entry.key.path_id {
            PathId::Absent => Json::Null,
            PathId::Present(value) => value.into(),
            PathId::Unknown => "unknown".into(),
        };
        let status = match entry.status {
            RouteStatus::Active => "active",
            RouteStatus::Stale(StaleKind::Graceful) => "stale_graceful",
            RouteStatus::Stale(StaleKind::LongLivedGraceful) => "stale_long_lived_graceful",
            RouteStatus::StaleAtEor => "stale_at_eor",
            RouteStatus::Withdrawn => "withdrawn",
            RouteStatus::Superseded => "superseded",
            RouteStatus::Unresolved => "unresolved",
            RouteStatus::Rejected => "rejected",
        };
        Json::object([
            (
                "scope",
                Json::object([
                    ("source_kind", source_kind.into()),
                    ("source_id", entry.key.scope.source.source_id.clone().into()),
                    (
                        "partition_id",
                        entry.key.scope.source.partition_id.clone().into(),
                    ),
                    ("session", entry.key.scope.session.clone().into()),
                    ("generation", entry.key.scope.generation.into()),
                    (
                        "direction",
                        entry.key.scope.direction.map_or(Json::Null, Json::from),
                    ),
                    (
                        "peer",
                        entry.key.scope.peer.clone().map_or(Json::Null, Json::from),
                    ),
                ]),
            ),
            (
                "family",
                Json::object([
                    ("afi", entry.key.family.afi.into()),
                    ("safi", entry.key.family.safi.into()),
                ]),
            ),
            (
                "prefix",
                Json::object([
                    ("afi", entry.key.prefix.afi.into()),
                    ("safi", entry.key.prefix.safi.into()),
                    ("length", entry.key.prefix.length.into()),
                    ("address", entry.key.prefix.address.clone().into()),
                ]),
            ),
            ("path_id", path_id),
            ("status", status.into()),
            ("last_witness", entry.last_witness.clone().into()),
            (
                "versions",
                Json::array(entry.versions.iter().map(|version| {
                    let disposition = match version.disposition {
                        VersionDisposition::Current => "current",
                        VersionDisposition::Replaced => "replaced",
                        VersionDisposition::Withdrawn => "withdrawn",
                        VersionDisposition::Superseded => "superseded",
                        VersionDisposition::Conflicting => "conflicting",
                    };
                    Json::object([
                        (
                            "attribute_identity",
                            version.attribute_identity.clone().into(),
                        ),
                        ("attributes", version.attributes.clone()),
                        (
                            "witnesses",
                            Json::array(version.witnesses.iter().cloned().map(Json::from)),
                        ),
                        ("disposition", disposition.into()),
                    ])
                })),
            ),
        ])
    }));
    let state = Json::object([
        ("source_kind", source_kind.into()),
        ("source_id", key.source.source_id.clone().into()),
        ("partition_id", key.source.partition_id.clone().into()),
        ("session", key.session.clone().into()),
        ("generation", summary.generation.into()),
        ("capability_context", capability_context),
        ("directions", directions),
        (
            "gap_reasons",
            view.map_or_else(
                || Json::Array(Vec::new()),
                |view| Json::array(view.gaps.iter().cloned().map(Json::from)),
            ),
        ),
        (
            "reset_records",
            view.map_or_else(
                || Json::Array(Vec::new()),
                |view| Json::array(view.resets.iter().cloned().map(Json::from)),
            ),
        ),
        (
            "closed_by_notification",
            view.is_some_and(|view| view.closed_by_notification).into(),
        ),
        (
            "identity_conflict",
            view.is_some_and(|view| view.identity_conflict).into(),
        ),
        ("routes", routes),
        ("endpoint_rib_claimed", false.into()),
    ]);
    SessionSnapshot {
        session,
        summary,
        state,
    }
}

fn summarize(session: u64, pipeline: &CapturedSessionPipeline) -> SessionSummary {
    let mut active_routes = 0;
    let mut unresolved_routes = 0;
    let mut withdrawn_routes = 0;
    let mut superseded_routes = 0;
    let mut stale_routes = 0;
    let mut rejected_routes = 0;
    for entry in pipeline.rib().entries().values() {
        match entry.status {
            RouteStatus::Active => active_routes += 1,
            RouteStatus::Unresolved => unresolved_routes += 1,
            RouteStatus::Withdrawn => withdrawn_routes += 1,
            RouteStatus::Superseded => superseded_routes += 1,
            RouteStatus::Stale(_) | RouteStatus::StaleAtEor => stale_routes += 1,
            RouteStatus::Rejected => rejected_routes += 1,
        }
    }
    SessionSummary {
        session,
        generation: pipeline.wire_state().generation(),
        session_events: pipeline.observer().events().len(),
        rib_events: pipeline.rib().events().len(),
        route_entries: pipeline.rib().entries().len(),
        active_routes,
        unresolved_routes,
        withdrawn_routes,
        superseded_routes,
        stale_routes,
        rejected_routes: rejected_routes + pipeline.rib().rejections().len(),
        eor_markers: pipeline.rib().eors().len(),
        gaps: pipeline.rib().gaps().len(),
        tainted: pipeline.tainted(),
    }
}
