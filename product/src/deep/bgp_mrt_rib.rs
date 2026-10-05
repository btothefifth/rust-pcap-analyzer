//! The imported observation-to-RIB join. The RIB owner defines replacement,
//! withdrawal, reset, and history semantics; this seam supplies checked scope.
use super::*;
use crate::deep::{
    bgp_rib::{
        PathId, RibAction, RibEvent, RibEventKind, RibScope, RouteStatus, VersionDisposition,
    },
    bgp_session::SourcePartition,
};

pub(crate) fn observation_event(
    observation: &Observation,
    limits: &Limits,
) -> Result<Option<RibEvent>> {
    let context = observation.import_context().ok_or_else(|| {
        bad(
            "bgp_mrt_rib_context",
            0,
            "imported RIB observation requires exact context",
        )
    })?;
    let scope = RibScope {
        source: SourcePartition::from_import_context(context, limits)?,
        session: context.session.clone(),
        generation: context.generation,
        direction: context.direction,
        peer: context.peer.clone(),
    };
    let kind = if let Some(boundary) = observation.import_boundary() {
        RibEventKind::Reset {
            previous_generation: boundary.previous_generation,
            reason: boundary.reason.clone(),
        }
    } else if route_projection_incomplete(observation) {
        // Retain the complete imported observation, including any decoded
        // sibling routes, but publish no native actions from an incomplete
        // UPDATE. Gap admission also establishes uncertainty before the first
        // supported route and survives later messages in the same generation.
        RibEventKind::Gap {
            reason: "decoded_update_opaque_route_evidence".into(),
        }
    } else {
        let mut actions = Vec::new();
        actions
            .try_reserve_exact(observation.routes().len())
            .map_err(|_| Error::limit("bgp_mrt_rib_actions"))?;
        for route in observation.routes() {
            let path_id = match route.path_id() {
                RoutePathId::Absent => PathId::Absent,
                RoutePathId::Present(value) => PathId::Present(value),
            };
            actions.push(match route.action() {
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
            });
        }
        if actions.is_empty() {
            let Some(family) = end_of_rib_family(observation)? else {
                return Ok(None);
            };
            RibEventKind::EndOfRib(family)
        } else {
            RibEventKind::Update(actions)
        }
    };
    Ok(Some(RibEvent {
        scope,
        record_id: observation.source().record_id.clone(),
        kind,
    }))
}

pub(crate) fn route_projection_incomplete(observation: &Observation) -> bool {
    event_value(observation.normalized(), "message_detail")
        .and_then(|detail| event_value(detail, "route_projection_incomplete"))
        == Some(&Json::Bool(true))
}

pub(crate) fn end_of_rib_family(
    observation: &Observation,
) -> Result<Option<crate::deep::bgp_session::Family>> {
    let Some(detail) = event_value(observation.normalized(), "message_detail") else {
        return Ok(None);
    };
    let Some(Json::Array(families)) = event_value(detail, "end_of_rib") else {
        return Ok(None);
    };
    if families.len() > 1 {
        return Err(bad(
            "bgp_mrt_end_of_rib",
            0,
            "one immutable UPDATE cannot carry multiple EOR markers",
        ));
    }
    let Some(family) = families.first() else {
        return Ok(None);
    };
    let afi = event_number(family, "afi")
        .and_then(|value| u16::try_from(value).ok())
        .ok_or_else(|| bad("bgp_mrt_end_of_rib", 0, "EOR AFI absent"))?;
    let safi = event_number(family, "safi")
        .and_then(|value| u8::try_from(value).ok())
        .ok_or_else(|| bad("bgp_mrt_end_of_rib", 0, "EOR SAFI absent"))?;
    // Unsupported family evidence remains in the exact source event; it
    // cannot acquire a supported route-family marker by proximity.
    Ok((matches!(afi, 1 | 2) && matches!(safi, 1 | 2))
        .then_some(crate::deep::bgp_session::Family { afi, safi }))
}

/// A rejected source message cannot prove continuity of older route candidates.
/// This is an explicit gap, not a decoder reset or a manufactured withdrawal.
pub(super) fn quarantine_event(
    rib: &mut AdjRibIn,
    event: &Json,
    contexts: &BTreeMap<(String, ImportPartition), ImportContext>,
    native_continuity: &mut Vec<bgp_import::ImportedNativeContinuity>,
    admission: (usize, usize),
    limits: &Limits,
) -> Result<usize> {
    let mut work = 0usize;
    let Some(status) = event_text(event, "parse_status") else {
        return Ok(0);
    };
    if status != "rejected" && !status.starts_with("quarantined") {
        return Ok(0);
    }
    // Reset dispositions already have an exact checked boundary. Ambiguous
    // and unknown-coverage events instead carry every affected real scope.
    if status == "quarantined_session_reset" {
        return Ok(0);
    }
    let affected = if matches!(
        status,
        "quarantined_ambiguous_session" | "quarantined_coverage_unknown"
    ) {
        let scopes =
            event_value(event, "detail").and_then(|detail| event_value(detail, "affected_scopes"));
        let Some(Json::Array(scopes)) = scopes else {
            return Err(bad(
                "bgp_mrt_gap_scope",
                0,
                "affected session scopes absent",
            ));
        };
        if scopes.len() > limits.elements {
            return Err(Error::limit("bgp_mrt_gap_scope"));
        }
        for scope in scopes {
            if event_text(scope, "session").is_none() || event_number(scope, "generation").is_none()
            {
                return Err(bad(
                    "bgp_mrt_gap_scope",
                    0,
                    "affected session identity or generation absent",
                ));
            }
        }
        Some(scopes)
    } else {
        None
    };
    let session = event_text(event, "session");
    if session.is_none() && affected.is_none() {
        return Ok(0);
    }
    let Some(record_id) = event_text(event, "record_sha256") else {
        return Ok(0);
    };
    for ((known_session, _), context) in contexts {
        let generation = if let Some(scopes) = affected {
            work = work
                .checked_add(scopes.len())
                .filter(|work| *work <= limits.work)
                .ok_or_else(|| Error::limit("bgp_mrt_rib_work"))?;
            scopes
                .iter()
                .find(|scope| event_text(scope, "session") == Some(known_session.as_str()))
                .and_then(|scope| event_number(scope, "generation"))
        } else if session == Some(known_session.as_str()) {
            event_number(event, "generation")
        } else {
            None
        };
        let Some(generation) = generation else {
            continue;
        };
        if generation != context.generation
            || event_text(event, "source_id") != Some(context.source_id.as_str())
            || event_text(event, "checkpoint_id") != Some(context.checkpoint_id.as_str())
        {
            return Err(bad(
                "bgp_mrt_gap_scope",
                0,
                "gap differs from exact tracked source scope",
            ));
        }
        let before = rib.accounted_work();
        bgp_import::apply_native_event(
            rib,
            RibEvent {
                scope: RibScope {
                    source: SourcePartition::from_import_context(context, limits)?,
                    session: context.session.clone(),
                    generation: context.generation,
                    direction: None,
                    peer: context.peer.clone(),
                },
                record_id: format!(
                    "mrt-bgp4mp-quarantine:{}:{}",
                    event_number(event, "record_index").unwrap_or(0),
                    record_id
                ),
                kind: RibEventKind::Gap {
                    reason: format!("source_message_{status}"),
                },
            },
            None,
            native_continuity,
            (
                admission.0,
                admission
                    .1
                    .checked_add(work)
                    .ok_or_else(|| Error::limit("bgp_mrt_rib_work"))?,
                1,
                8,
            ),
            limits,
        )?;
        work = work
            .checked_add(
                rib.accounted_work()
                    .checked_sub(before)
                    .ok_or_else(|| Error::limit("bgp_mrt_rib_work"))?,
            )
            .filter(|work| *work <= limits.work)
            .ok_or_else(|| Error::limit("bgp_mrt_rib_work"))?;
    }
    Ok(work)
}

pub(super) fn apply_continuity_cuts(
    rib: &mut AdjRibIn,
    cuts: &[super::super::bgp_import::ImportContinuityCut],
    native_continuity: &mut Vec<bgp_import::ImportedNativeContinuity>,
    admission: (usize, usize),
    limits: &Limits,
) -> Result<usize> {
    let mut work = 0usize;
    for cut in cuts {
        let context = &cut.context;
        let before = rib.accounted_work();
        bgp_import::apply_native_event(
            rib,
            RibEvent {
                scope: RibScope {
                    source: SourcePartition::from_import_context(context, limits)?,
                    session: context.session.clone(),
                    generation: context.generation,
                    direction: context.direction,
                    peer: context.peer.clone(),
                },
                record_id: cut.record_id.clone(),
                kind: RibEventKind::Gap {
                    reason: cut.reason.clone(),
                },
            },
            None,
            native_continuity,
            (
                admission.0,
                admission
                    .1
                    .checked_add(work)
                    .ok_or_else(|| Error::limit("bgp_mrt_rib_work"))?,
                1,
                8,
            ),
            limits,
        )?;
        work = work
            .checked_add(
                rib.accounted_work()
                    .checked_sub(before)
                    .ok_or_else(|| Error::limit("bgp_mrt_rib_work"))?,
            )
            .filter(|n| *n <= limits.work)
            .ok_or_else(|| Error::limit("bgp_mrt_rib_work"))?;
    }
    Ok(work)
}

/// Native gaps can initialize a scope without a shared-journal observation.
/// Forward reset only for an actual admitted native predecessor; the shared
/// journal retains its own stricter predecessor inventory.
pub(super) fn reset_native_scopes(
    rib: &mut AdjRibIn,
    event: &Json,
    record_index: usize,
    record: &MrtRecord,
    native_continuity: &mut Vec<bgp_import::ImportedNativeContinuity>,
    admission: (usize, usize),
    limits: &Limits,
) -> Result<usize> {
    let Some((generation, reason)) = bgp4mp_reset_generation(event, record_index)? else {
        return Ok(0);
    };
    let Some(session) = event_text(event, "session") else {
        return Ok(0);
    };
    let mut seen = std::collections::BTreeSet::new();
    let mut resets = Vec::new();
    let mut work = 0usize;
    for prior in rib.events().iter().rev() {
        work = work
            .checked_add(prior.scope.session.len() + 1)
            .filter(|n| *n <= limits.work)
            .ok_or_else(|| Error::limit("bgp_mrt_rib_work"))?;
        if prior.scope.session != session
            || event_text(event, "source_id") != Some(prior.scope.source.source_id.as_str())
            || !seen.insert(prior.scope.source.clone())
            || prior.scope.generation == generation
        {
            continue;
        }
        if prior.scope.generation.checked_add(1) != Some(generation) {
            return Err(bad(
                "bgp_mrt_generation_boundary",
                record_index,
                "native reset does not advance the admitted generation exactly once",
            ));
        }
        let mut scope = prior.scope.clone();
        let previous_generation = scope.generation;
        scope.generation = generation;
        scope.direction = None;
        resets
            .try_reserve(1)
            .map_err(|_| Error::limit("bgp_mrt_generation_contexts"))?;
        resets.push(RibEvent {
            scope,
            record_id: format!(
                "mrt-bgp4mp-reset:{}:{}:{}:{}",
                record.offset, record.subtype, record_index, record.sha256
            ),
            kind: RibEventKind::Reset {
                previous_generation,
                reason: reason.to_owned(),
            },
        });
    }
    for reset in resets {
        let before = rib.accounted_work();
        bgp_import::apply_native_event(
            rib,
            reset,
            None,
            native_continuity,
            (
                admission.0,
                admission
                    .1
                    .checked_add(work)
                    .ok_or_else(|| Error::limit("bgp_mrt_rib_work"))?,
                1,
                8,
            ),
            limits,
        )?;
        work = work
            .checked_add(
                rib.accounted_work()
                    .checked_sub(before)
                    .ok_or_else(|| Error::limit("bgp_mrt_rib_work"))?,
            )
            .filter(|n| *n <= limits.work)
            .ok_or_else(|| Error::limit("bgp_mrt_rib_work"))?;
    }
    Ok(work)
}

pub(super) fn route_status(status: RouteStatus) -> &'static str {
    match status {
        RouteStatus::Active => "active",
        RouteStatus::Stale(_) => "stale",
        RouteStatus::StaleAtEor => "stale_at_eor",
        RouteStatus::Withdrawn => "withdrawn",
        RouteStatus::Superseded => "superseded",
        RouteStatus::Unresolved => "unresolved",
        RouteStatus::Rejected => "rejected",
    }
}
pub(super) fn version_status(status: VersionDisposition) -> &'static str {
    match status {
        VersionDisposition::Current => "current",
        VersionDisposition::Replaced => "replaced",
        VersionDisposition::Withdrawn => "withdrawn",
        VersionDisposition::Superseded => "superseded",
        VersionDisposition::Conflicting => "conflicting",
    }
}

impl MrtReplayArchive {
    /// Offline session candidates rebuilt from exact source records. Context,
    /// source clock, trust labels and full witnesses remain in candidate_state.
    pub fn bgp4mp_rib_json(&self, session: Option<&str>) -> Json {
        rib_json(&self.bgp4mp_rib, session)
    }
}

pub(crate) fn rib_json(rib: &AdjRibIn, session: Option<&str>) -> Json {
    Json::object([
        ("schema", crate::deep::bgp_rib::SCHEMA.into()),
        ("source_authenticated", false.into()),
        ("endpoint_state_claimed", false.into()),
        ("installed_routes_established", false.into()),
        ("reachability_established", false.into()),
        (
            "end_of_rib",
            Json::array(
                rib.eors()
                    .iter()
                    .filter(|marker| session.is_none_or(|session| marker.scope.session == session))
                    .map(|marker| {
                        Json::object([
                            (
                                "partition_id",
                                marker.scope.source.partition_id.clone().into(),
                            ),
                            ("session", marker.scope.session.clone().into()),
                            ("generation", marker.scope.generation.to_string().into()),
                            (
                                "direction",
                                marker.scope.direction.map_or(Json::Null, Json::from),
                            ),
                            ("afi", marker.family.afi.into()),
                            ("safi", marker.family.safi.into()),
                            ("record_id", marker.record_id.clone().into()),
                        ])
                    }),
            ),
        ),
        (
            "entries",
            Json::array(
                rib.entries()
                    .values()
                    .filter(|entry| {
                        session.is_none_or(|session| entry.key.scope.session == session)
                    })
                    .map(|entry| {
                        Json::object([
                            ("source_id", entry.key.scope.source.source_id.clone().into()),
                            (
                                "partition_id",
                                entry.key.scope.source.partition_id.clone().into(),
                            ),
                            ("session", entry.key.scope.session.clone().into()),
                            ("generation", entry.key.scope.generation.to_string().into()),
                            (
                                "direction",
                                entry.key.scope.direction.map_or(Json::Null, Json::from),
                            ),
                            (
                                "peer",
                                entry.key.scope.peer.clone().map_or(Json::Null, Json::from),
                            ),
                            ("prefix", prefix_json(&entry.key.prefix)),
                            (
                                "path_id",
                                match entry.key.path_id {
                                    PathId::Absent => Json::Null,
                                    PathId::Present(value) => value.into(),
                                    PathId::Unknown => "unknown".into(),
                                },
                            ),
                            ("status", route_status(entry.status).into()),
                            ("last_witness", entry.last_witness.clone().into()),
                            (
                                "versions",
                                Json::array(entry.versions.iter().map(|version| {
                                    Json::object([
                                        ("attributes", version.attributes.clone()),
                                        (
                                            "attribute_identity",
                                            version.attribute_identity.clone().into(),
                                        ),
                                        ("disposition", version_status(version.disposition).into()),
                                        (
                                            "witnesses",
                                            Json::array(
                                                version.witnesses.iter().cloned().map(Json::from),
                                            ),
                                        ),
                                    ])
                                })),
                            ),
                        ])
                    }),
            ),
        ),
        (
            "gaps",
            Json::array(
                rib.gaps()
                    .iter()
                    .filter(|(scope, _)| session.is_none_or(|session| scope.session == session))
                    .map(|(scope, record)| {
                        Json::object([
                            ("partition_id", scope.source.partition_id.clone().into()),
                            ("session", scope.session.clone().into()),
                            ("generation", scope.generation.to_string().into()),
                            ("record_id", record.clone().into()),
                        ])
                    }),
            ),
        ),
        (
            "rejected_records",
            Json::array(
                rib.rejections()
                    .iter()
                    .filter(|item| session.is_none_or(|session| item.key.scope.session == session))
                    .map(|item| {
                        Json::object([
                            (
                                "partition_id",
                                item.key.scope.source.partition_id.clone().into(),
                            ),
                            ("session", item.key.scope.session.clone().into()),
                            ("generation", item.key.scope.generation.to_string().into()),
                            ("prefix", prefix_json(&item.key.prefix)),
                            ("record_id", item.record_id.clone().into()),
                            ("reason", item.reason.clone().into()),
                        ])
                    }),
            ),
        ),
    ])
}
