//! BMP-specific reported context; all embedded syntax and route semantics are shared.
use super::super::bgp_bmp::{self, BmpBatch, BmpBody, BmpPeer, BmpPeerIdentity, BmpRecord};
use super::super::bgp_import::{
    ClockPolicy, GenerationBoundary, ImportContext, ObservationClock, SourceBatch, SourceRange,
};
use super::*;
use pcap_evidence::ErrorCode;

pub(crate) struct ReplayState {
    sessions: BTreeMap<BmpPeerIdentity, PeerState>,
    relationship: Option<PeerRelationship>,
    monitor_closed: bool,
    monitor_coverage_uncertain: bool,
}
struct PeerState {
    index: usize,
    decoder: SessionState,
    reported_up: bool,
    // Tracks normalized journal publication, including route-free observations;
    // native RIB admission is a separate fact owned by the store/reducer seam.
    used_streams: [bool; 2],
    context_unresolved: bool,
}
pub(crate) struct ReplayRecord {
    pub event: Json,
    pub observations: Vec<Json>,
    pub gaps: Vec<ImportContext>,
}
impl ReplayState {
    pub(crate) fn new(relationship: Option<PeerRelationship>) -> Self {
        Self {
            sessions: BTreeMap::new(),
            relationship,
            monitor_closed: false,
            monitor_coverage_uncertain: false,
        }
    }
}
pub(crate) fn replay_record(
    batch: &BmpBatch,
    index: usize,
    limits: &Limits,
    peer_limit: usize,
    state: &mut ReplayState,
) -> Result<ReplayRecord> {
    let record = &batch.records[index];
    let mut observations = Vec::new();
    let mut gaps = Vec::new();
    let mut details = Json::Null;
    let status;
    let mut issues = Vec::new();
    let mut session_label = None;
    let mut generation = 0;
    match &record.body {
        BmpBody::Initiation { .. } => {
            state.monitor_closed = false;
            status = "reported_initiation";
        }
        BmpBody::Termination { .. } => {
            for (identity, session) in &mut state.sessions {
                let peer = BmpPeer {
                    identity: identity.clone(),
                    flags: 0,
                    seconds: 0,
                    microseconds: 0,
                };
                observations.extend(reset(
                    batch,
                    record,
                    &peer,
                    session,
                    "bmp_monitor_termination",
                    limits,
                )?);
            }
            state.monitor_closed = true;
            status = "reported_monitor_termination";
        }
        BmpBody::Opaque { reason, .. } => {
            status = "opaque_quarantine";
            issues.push(*reason);
            if (*reason == "malformed_known_record" && matches!(record.message_type, 0 | 2 | 3 | 5))
                || (record.message_type == 5 && *reason == "unsupported_termination_reason")
            {
                if let Some(peer) = &record.peer {
                    if let Some(session) = state.sessions.get_mut(&peer.identity) {
                        session.context_unresolved = true;
                        for stream in 0..2 {
                            if session.used_streams[stream] {
                                gaps.push(context(
                                    batch,
                                    record,
                                    peer,
                                    session,
                                    (stream, None),
                                    batch.record_range(record),
                                    limits,
                                )?);
                            }
                        }
                    }
                } else {
                    state.monitor_coverage_uncertain = true;
                    for (identity, session) in &mut state.sessions {
                        session.context_unresolved = true;
                        let peer = BmpPeer {
                            identity: identity.clone(),
                            flags: 0,
                            seconds: 0,
                            microseconds: 0,
                        };
                        for stream in 0..2 {
                            if session.used_streams[stream] {
                                gaps.push(context(
                                    batch,
                                    record,
                                    &peer,
                                    session,
                                    (stream, None),
                                    batch.record_range(record),
                                    limits,
                                )?);
                            }
                        }
                    }
                }
            }
        }
        body => {
            let peer = record
                .peer
                .as_ref()
                .ok_or_else(|| bad("bmp_peer", index, "supported peer record has no peer"))?;
            if !state.sessions.contains_key(&peer.identity) {
                if state.sessions.len() >= peer_limit || state.sessions.len() >= limits.active {
                    return Err(Error::limit("bmp_peers"));
                }
                let mut decoder = SessionState::default();
                if let Some(relationship) = state.relationship {
                    decoder.set_peer_relationship(relationship);
                }
                let session = PeerState {
                    index: state.sessions.len(),
                    decoder,
                    reported_up: false,
                    used_streams: [false; 2],
                    context_unresolved: false,
                };
                state.sessions.insert(peer.identity.clone(), session);
            }
            let session = state.sessions.get_mut(&peer.identity).unwrap();
            session_label = Some(format!("bmp:{}", session.index));
            generation = session.decoder.generation();
            match body {
                BmpBody::PeerUp {
                    local_address,
                    local_port,
                    remote_port,
                    sent_open,
                    received_open,
                    ..
                } => {
                    let sent = batch.range_bytes(sent_open)?;
                    let received = batch.range_bytes(received_open)?;
                    let metadata = Json::object([
                        ("source_id", batch.source.source_id.clone().into()),
                        ("container_schema", bgp_bmp::SCHEMA.into()),
                        ("peer", peer.json()),
                    ]);
                    let parsed = (|| {
                        producer::validate_message_frame(sent, false)?;
                        producer::validate_message_frame(received, false)?;
                        let sent = producer::parse_open_imported(
                            sent,
                            metadata.clone(),
                            bgp_bmp::range_json(sent_open),
                            limits,
                        )?;
                        let received = producer::parse_open_imported(
                            received,
                            metadata,
                            bgp_bmp::range_json(received_open),
                            limits,
                        )?;
                        Ok::<_, Error>((sent, received))
                    })();
                    match parsed {
                        Err(error) if error.code == ErrorCode::LimitExceeded => return Err(error),
                        Err(_) => {
                            status = "quarantined_peer_up";
                            issues.push("malformed_reported_open");
                            session.context_unresolved = true;
                            gaps.extend(gap_contexts(batch, record, peer, session, limits)?);
                        }
                        Ok((sent, mut received)) => {
                            let advertised = received
                                .four_octet_asn
                                .unwrap_or(u32::from(received.autonomous_system));
                            if advertised != peer.identity.asn {
                                received.ambiguous = true;
                                received.capabilities.valid = false;
                                received
                                    .capability_issues
                                    .push("open_asn_disagrees_with_bmp_peer_metadata");
                                issues.push("open_asn_disagrees_with_bmp_peer_metadata");
                            }
                            let received_bytes = batch.range_bytes(received_open)?;
                            if received_bytes[24..28] != peer.identity.bgp_id {
                                received.ambiguous = true;
                                received.capabilities.valid = false;
                                received
                                    .capability_issues
                                    .push("open_bgp_id_disagrees_with_bmp_peer_metadata");
                                issues.push("open_bgp_id_disagrees_with_bmp_peer_metadata");
                            }
                            if session.reported_up || session.used_streams.iter().any(|v| *v) {
                                observations.extend(reset(
                                    batch,
                                    record,
                                    peer,
                                    session,
                                    "bmp_reported_peer_up",
                                    limits,
                                )?);
                            }
                            details = Json::object([
                                ("sent_open", sent.witness.value.clone()),
                                ("received_open", received.witness.value.clone()),
                                ("local_address", local_address.to_string().into()),
                                ("local_port", (*local_port).into()),
                                ("remote_port", (*remote_port).into()),
                                ("negotiation_established", false.into()),
                                ("context_basis", "bmp_reported_peer_up_opens".into()),
                            ]);
                            session.decoder.opens.insert(1, vec![sent]);
                            session.decoder.opens.insert(0, vec![received]);
                            session.reported_up = true;
                            session.context_unresolved = false;
                            status = "reported_peer_up";
                            generation = session.decoder.generation();
                        }
                    }
                }
                BmpBody::PeerDown { reason, .. } => {
                    observations.extend(reset(
                        batch,
                        record,
                        peer,
                        session,
                        if *reason == 5 {
                            "bmp_monitoring_coverage_closed"
                        } else {
                            "bmp_reported_peer_down"
                        },
                        limits,
                    )?);
                    generation = session.decoder.generation();
                    status = if *reason == 5 {
                        "reported_coverage_close"
                    } else {
                        "reported_peer_down"
                    };
                    details = Json::object([
                        ("reason", (*reason).into()),
                        ("endpoint_down_established", false.into()),
                        ("coverage_closed", true.into()),
                        ("reported_bgp_down", (*reason != 5).into()),
                    ]);
                }
                BmpBody::RouteMonitoring { message } => {
                    let stream = usize::from(peer.post_policy());
                    session_label = Some(stream_id(session, stream));
                    if state.monitor_closed || !session.reported_up || session.context_unresolved {
                        status = "quarantined_route_monitoring";
                        issues.push("missing_unambiguous_reported_peer_up");
                    } else {
                        let (mut layout, basis) = producer::layout_evidence(&session.decoder, true);
                        if !matches!(
                            basis,
                            "both_four_octet_advertisements" | "two_octet_bilateral_advertisements"
                        ) || layout
                            .unresolved_add_path
                            .iter()
                            .any(|(direction, _, _)| *direction == 0)
                        {
                            status = "quarantined_route_monitoring";
                            issues.push("reported_open_capabilities_unresolved");
                        } else {
                            // BMP may rewrite AS_PATH into four-octet form independently of OPENs.
                            layout.asn_width = usize::from(peer.asn_width());
                            let bytes = batch.range_bytes(message)?;
                            let parsed = (|| {
                                producer::validate_message_frame(
                                    bytes,
                                    layout.extended_message_senders.contains(&0),
                                )?;
                                let mut budget = producer::Budget::new(limits);
                                parse_update(bytes, &layout, Some(0), limits, &mut budget)
                            })();
                            match parsed {
                                Err(error) if error.code == ErrorCode::LimitExceeded => {
                                    return Err(error)
                                }
                                Err(_) => {
                                    status = "quarantined_malformed_update";
                                    issues.push("bmp_embedded_update_rejected");
                                    session.context_unresolved = true;
                                    gaps.extend(gap_contexts(
                                        batch, record, peer, session, limits,
                                    )?);
                                }
                                Ok(mut parsed) => {
                                    if session.decoder.opens.values().flatten().any(|open| {
                                        open.capability_issues.iter().any(|issue| {
                                            matches!(
                                                *issue,
                                                "unsupported_capability_retained_by_hash"
                                                    | "unsupported_open_parameter_retained_by_hash"
                                            )
                                        })
                                    }) {
                                        parsed.issues.push(
                                            "unsupported_session_capabilities_not_interpreted",
                                        );
                                    }
                                    details = update_details(&parsed, peer, basis, message);
                                    if parsed.known_disposition == "session_reset" {
                                        observations.extend(reset(
                                            batch,
                                            record,
                                            peer,
                                            session,
                                            "bmp_embedded_update_error_context_cut",
                                            limits,
                                        )?);
                                        status = "quarantined_session_reset";
                                        issues.push("embedded_update_requires_context_reset");
                                    } else if parsed.peer_relationship_unresolved {
                                        status = "quarantined_peer_relationship";
                                        issues.push("peer_relationship_context_unresolved");
                                        gaps.extend(gap_contexts(
                                            batch, record, peer, session, limits,
                                        )?);
                                    } else {
                                        let mut routes = std::mem::take(&mut parsed.records);
                                        let inventory = mrt::imported_attribute_inventory(
                                            &parsed.attribute_ranges,
                                            bytes,
                                            message,
                                            routes.len(),
                                            limits,
                                        )?;
                                        let identities =
                                            mrt::imported_route_identities(&mut routes, limits)?;
                                        let atomic_aggregate =
                                            parsed.attribute_ranges.iter().any(|occurrence| {
                                                occurrence.code == 6
                                                    && occurrence.disposition != "discard"
                                            });
                                        let context = context(
                                            batch,
                                            record,
                                            peer,
                                            session,
                                            (stream, Some(0)),
                                            message.clone(),
                                            limits,
                                        )?;
                                        let mut normalized = envelope(
                                            Source {
                                                kind: SourceKind::Imported,
                                                source_id: batch.source.source_id.clone(),
                                                record_id: record_id(record, stream),
                                                observed_at_ns: peer.observed_at_ns(),
                                                session: Some(context.session.clone()),
                                                direction: Some(0),
                                                peer: context.peer.clone(),
                                                local: context.local.clone(),
                                            },
                                            session.decoder.generation(),
                                            // Source-neutral imported route carrier; embedded UPDATE
                                            // type 2 remains bound by the exact original message range.
                                            0,
                                            routes,
                                            parsed.issues,
                                            EnvelopeDetails {
                                                message_detail: Some(details.clone()),
                                                evidence: None,
                                                import_context: Some(context.json()),
                                            },
                                            limits,
                                        )?;
                                        mrt::finish_imported_update(
                                            &mut normalized,
                                            identities,
                                            inventory,
                                            atomic_aggregate,
                                            limits,
                                        )?;
                                        observations.push(normalized);
                                        session.used_streams[stream] = true;
                                        status = "decoded_route_monitoring_candidate";
                                    }
                                }
                            }
                        }
                    }
                }
                _ => unreachable!(),
            }
        }
    }
    let event = Json::object([
        ("schema", "pcap-evidence.bgp.bmp-event.v1".into()),
        ("source_id", batch.source.source_id.clone().into()),
        ("checkpoint_id", batch.source.checkpoint_id.clone().into()),
        ("batch_sha256", batch.sha256.clone().into()),
        ("record_index", index.into()),
        (
            "record_range",
            bgp_bmp::range_json(&batch.record_range(record)),
        ),
        ("message_type", record.message_type.into()),
        ("session", session_label.map_or(Json::Null, Json::String)),
        ("generation", generation.into()),
        (
            "peer",
            record.peer.as_ref().map_or(Json::Null, BmpPeer::json),
        ),
        ("status", status.into()),
        ("issues", Json::array(issues.into_iter().map(Json::from))),
        (
            "monitor_coverage_uncertain",
            state.monitor_coverage_uncertain.into(),
        ),
        ("detail", details),
        ("endpoint_state_established", false.into()),
    ]);
    Ok(ReplayRecord {
        event,
        observations,
        gaps,
    })
}
fn stream_id(session: &PeerState, stream: usize) -> String {
    format!(
        "bmp:{}:{}",
        session.index,
        if stream == 0 { "pre" } else { "post" }
    )
}
fn gap_contexts(
    batch: &BmpBatch,
    record: &BmpRecord,
    peer: &BmpPeer,
    session: &PeerState,
    limits: &Limits,
) -> Result<Vec<ImportContext>> {
    let mut contexts = Vec::new();
    for stream in 0..2 {
        if session.used_streams[stream] {
            contexts.push(context(
                batch,
                record,
                peer,
                session,
                (stream, None),
                batch.record_range(record),
                limits,
            )?);
        }
    }
    Ok(contexts)
}
fn record_id(record: &BmpRecord, stream: usize) -> String {
    format!(
        "bmp:{}:{}:{}:{}",
        record.offset, record.message_type, stream, record.sha256
    )
}
fn context(
    batch: &BmpBatch,
    record: &BmpRecord,
    peer: &BmpPeer,
    session: &PeerState,
    stream_direction: (usize, Option<u8>),
    range: SourceRange,
    limits: &Limits,
) -> Result<ImportContext> {
    let (stream, direction) = stream_direction;
    let context = ImportContext {
        source_id: batch.source.source_id.clone(),
        source_schema: bgp_bmp::SCHEMA.into(),
        source_version: Some("1".into()),
        clock: ObservationClock {
            policy: if peer.observed_at_ns().is_some() {
                ClockPolicy::SourceLabel
            } else {
                ClockPolicy::Unknown
            },
            clock_id: peer
                .observed_at_ns()
                .map(|_| "bmp-reported-per-peer-timestamp".into()),
            reported_uncertainty_ns: None,
        },
        batch: SourceBatch {
            batch_id: None,
            sha256: Some(batch.sha256.clone()),
            byte_length: Some(batch.byte_length),
        },
        checkpoint_id: batch.source.checkpoint_id.clone(),
        session: stream_id(session, stream),
        generation: session.decoder.generation(),
        direction,
        peer: Some(peer.identity.label()),
        local: Some("bmp-monitored-instance".into()),
        provenance: vec![range],
    };
    let _ = record;
    context.validate(limits)?;
    Ok(context)
}
fn reset(
    batch: &BmpBatch,
    record: &BmpRecord,
    peer: &BmpPeer,
    session: &mut PeerState,
    reason: &str,
    limits: &Limits,
) -> Result<Vec<Json>> {
    let previous = session.decoder.generation();
    session.decoder.reset()?;
    let mut observations = Vec::new();
    for stream in 0..2 {
        if session.used_streams[stream] {
            let context = context(
                batch,
                record,
                peer,
                session,
                (stream, None),
                batch.record_range(record),
                limits,
            )?;
            observations.push(super::super::bgp_import::normalize_boundary(
                context,
                GenerationBoundary {
                    previous_generation: previous,
                    reason: reason.into(),
                },
                record_id(record, stream),
                peer.observed_at_ns(),
                limits,
            )?);
        }
    }
    session.reported_up = false;
    session.context_unresolved = false;
    Ok(observations)
}
fn update_details(parsed: &ParsedUpdate, peer: &BmpPeer, basis: &str, range: &SourceRange) -> Json {
    Json::object([
        (
            "attribute_ranges",
            Json::array(parsed.attribute_ranges.iter().map(attribute_range_json)),
        ),
        ("disposition", parsed.disposition.into()),
        ("known_disposition", parsed.known_disposition.into()),
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
        ("capability_context_basis", basis.into()),
        ("negotiation_established", false.into()),
        (
            "container_layout",
            Json::object([
                ("asn_width", peer.asn_width().into()),
                ("layout_source", "bmp_a_flag".into()),
            ]),
        ),
        (
            "bmp_policy_view",
            if peer.post_policy() {
                "post_policy"
            } else {
                "pre_policy"
            }
            .into(),
        ),
        ("message_range", bgp_bmp::range_json(range)),
    ])
}
