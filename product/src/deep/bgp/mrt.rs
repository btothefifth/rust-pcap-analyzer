//! Capability-safe replay of BGP messages embedded in MRT BGP4MP records.
//!
//! MRT records remain the source of truth. This adapter reuses the same BGP
//! OPEN and UPDATE parsers as packet-derived evidence and never manufactures
//! packet IDs or captured-evidence carriers.
use super::super::bgp_import::{
    ClockPolicy, ImportContext, ObservationClock, SourceBatch, SourceRange,
};
use super::super::bgp_mrt::{Bgp4mp, Bgp4mpPayload, MrtBatch, MrtBody, MrtRecord};
use super::*;
use pcap_evidence::{json::Json, Error, ErrorCode, Result};

#[derive(Default)]
pub(crate) struct ReplayState {
    sessions: Vec<ImportedSession>,
    peer_relationship: Option<PeerRelationship>,
}

impl ReplayState {
    pub(crate) fn with_peer_relationship(peer_relationship: Option<PeerRelationship>) -> Self {
        Self {
            sessions: Vec::new(),
            peer_relationship,
        }
    }
}

#[derive(Default)]
struct ImportedSession {
    id: String,
    identity: SessionIdentity,
    decoder: SessionState,
    fsm: Option<u16>,
    state_conflict: bool,
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
    let Some(session_index) = resolve_session(batch, outer, limits, state)? else {
        return Ok(event_json(
            source.event(&ambiguous_session_key(batch, outer), None, 0),
            "state_change",
            "quarantined_ambiguous_session",
            vec!["ambiguous_bgp4mp_session_identity"],
            Some(Json::object([("source_range", range_json(&source_range))])),
            None,
        ));
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
    let Some(session_index) = resolve_session(batch, outer, limits, state)? else {
        return Ok(ReplayRecord {
            event: event_json(
                source.event(&ambiguous_session_key(batch, outer), Some(direction), 0),
                "message",
                "quarantined_ambiguous_session",
                vec!["ambiguous_bgp4mp_session_identity"],
                None,
                Some(message_range),
            ),
            observation: None,
        });
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
            return Ok(ReplayRecord {
                event: rejected_message_event(
                    source.event(&key, Some(direction), session.decoder.generation()),
                    &message_range,
                    "rejected",
                    "bgp4mp_message_frame_rejected",
                    &error,
                ),
                observation: None,
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
                });
            }

            if parsed.peer_relationship_unresolved {
                issues.extend(parsed.issues.iter().copied());
                issues.push("peer_relationship_context_unresolved_update_not_admitted");
                return Ok(ReplayRecord {
                    event: event_json(
                        source.event(&key, Some(direction), generation),
                        "message",
                        "quarantined_peer_relationship_unresolved",
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
                });
            }

            issues.extend(parsed.issues.iter().copied());
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
            for route in &mut imported_records {
                route.start = 0;
                route.end = 0;
                route.attribute_ranges.clear();
            }
            let normalized = envelope(
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
            Ok(ReplayRecord {
                event: event_json(
                    source.event(&key, Some(direction), generation),
                    "message",
                    "decoded_update_candidate",
                    event_issues,
                    Some(Json::object([
                        ("capability_context_basis", capability_basis.into()),
                        (
                            "observation_record_id",
                            record_id(record_index, record, &message_range).into(),
                        ),
                        ("route_count", parsed_route_count(&normalized).into()),
                    ])),
                    Some(message_range),
                ),
                observation: Some(normalized),
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
                });
            }
            let accepted_state = !session.state_conflict && session.fsm == Some(6);
            Ok(ReplayRecord {
                event: event_json(
                    source.event(&key, Some(direction), generation),
                    "message",
                    if accepted_state {
                        "decoded_route_refresh"
                    } else {
                        "quarantined_route_refresh_fsm_state"
                    },
                    if accepted_state {
                        Vec::new()
                    } else {
                        vec!["route_refresh_outside_established"]
                    },
                    Some(Json::object([
                        ("afi", be16(bytes, 19)?.into()),
                        ("subtype", bytes[21].into()),
                        ("safi", bytes[22].into()),
                    ])),
                    Some(message_range),
                ),
                observation: None,
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
        }),
    }
}

fn resolve_session(
    batch: &MrtBatch,
    outer: &Bgp4mp,
    limits: &Limits,
    state: &mut ReplayState,
) -> Result<Option<usize>> {
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
        for session in &mut state.sessions {
            if session.identity.compatible(&incoming) {
                session.decoder.reset()?;
                session.fsm = None;
                session.state_conflict = true;
            }
        }
        return Ok(None);
    }
    if let Some(index) = selected {
        state.sessions[index].identity.enrich(&incoming);
        return Ok(Some(index));
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
    Ok(Some(state.sessions.len() - 1))
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
    let seconds = i64::from(record.time.seconds).checked_mul(1_000_000_000)?;
    let micros = i64::from(record.time.microseconds.unwrap_or(0)).checked_mul(1_000)?;
    seconds.checked_add(micros)
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
    if observation_time_ns(event.source.record).is_none() {
        return Err(Error::limit("bgp_mrt_timestamp"));
    }
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
