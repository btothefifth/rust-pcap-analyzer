//! Replay admission owns raw-store dispatch and exact archive/source bindings.
//! Row consumers receive these inputs only after the source owner completes
//! sealed replay; collector snapshots remain separate from native RIB entries.
use super::*;

pub(super) struct ReplayInputs {
    pub receipt: Json,
    pub digest: String,
    pub namespace: String,
    pub entries: Vec<super::super::bgp_rib::RouteEntry>,
    pub rejections: Vec<super::super::bgp_rib::RejectedRecord>,
    pub observations: Vec<Observation>,
    pub collector: Vec<RouteRow>,
    pub source_events: Vec<Json>,
    pub captured_source_events: Vec<bgp_store::CapturedSourceEvent>,
    pub imported_source_events: Vec<super::super::bgp_import::ImportedSourceEvent>,
    pub captured_rejections: Vec<bgp_store::CapturedRejection>,
    pub captured_entry_evidence: Vec<bgp_store::CapturedEntryEvidence>,
    pub captured_observation_evidence: Vec<bgp_store::CapturedObservationEvidence>,
}
impl ReplayInputs {
    pub fn read(
        path: &Path,
        maximum: u64,
        mrt_limits: MrtLimits,
        limits: &Limits,
        options: bgp_mrt_store::MrtReplayOptions,
    ) -> Result<Self> {
        limits.validate()?;
        let mut f = File::open(path)?;
        if !f.metadata()?.is_file() || f.metadata()?.len() > maximum {
            return Err(Error::limit("bgp_store_disk"));
        }
        let mut magic = [0u8; 8];
        f.read_exact(&mut magic)?;
        drop(f);
        let mut source_events = Vec::new();
        let mut captured_source_events = Vec::new();
        let mut imported_source_events = Vec::new();
        let mut captured_rejections = Vec::new();
        let mut captured_entry_evidence = Vec::new();
        let mut captured_observation_evidence = Vec::new();
        let inputs = if &magic == bgp_store::MAGIC {
            if options.peer_relationship.is_some() {
                return Err(bad(
                    "bgp_persisted_options",
                    0,
                    "capture replay does not accept imported relationship override",
                ));
            }
            let a = bgp_store::replay(path, maximum, limits.clone())?;
            let mut event_bytes = 0usize;
            let mut event_nodes = 0usize;
            for event in &a.source_events {
                if let Some(c) = &event.continuity {
                    let o = a.observations.get(c.observation_index).ok_or_else(|| {
                        bad("bgp_persisted_continuity", 0, "bound observation missing")
                    })?;
                    let evidence =
                        a.observation_evidence
                            .get(c.observation_index)
                            .ok_or_else(|| {
                                bad(
                                    "bgp_persisted_continuity",
                                    0,
                                    "bound journal evidence missing",
                                )
                            })?;
                    if o.sha256() != c.observation_sha256
                        || evidence.source_record_index != event.source_record_index
                        || evidence.journal_record_sha256 != event.journal_record_sha256
                        || evidence.source_start != event.source_start
                        || evidence.source_end != event.source_end
                        || event.scopes.len() != 1
                        || event.scopes[0].lifecycle != evidence.lifecycle
                        || o.source().session.as_deref() != Some(c.decision.scope.session.as_str())
                        || c.decision.scope.session != event.scopes[0].session.to_string()
                        || c.decision.scope.source.source_id != o.source().source_id
                        || c.decision.scope.source.partition_id
                            != format!(
                                "capture-namespace-sha256:{}",
                                sha256::hex(&a.receipt.capture_namespace)
                            )
                    {
                        return Err(bad(
                            "bgp_persisted_continuity",
                            0,
                            "decoded boundary occurrence binding mismatch",
                        ));
                    }
                }
                // Typed archive bounds its own shape; admit consumer copy before serialization.
                let size = event.retained_charge();
                event_bytes = event_bytes
                    .checked_add(size.saturating_mul(6))
                    .ok_or_else(|| Error::limit("bgp_persisted_source_events"))?;
                if event_bytes > limits.retained_bytes
                    || event_bytes > limits.work
                    || source_events.len() >= limits.elements
                {
                    return Err(Error::limit("bgp_persisted_source_events"));
                }
                event_nodes = event_nodes
                    .checked_add(event.projection_nodes())
                    .ok_or_else(|| Error::limit("bgp_persisted_source_events"))?;
                if event_nodes > limits.fields || event.projection_depth() > limits.depth {
                    return Err(Error::limit("bgp_persisted_source_events"));
                }
                source_events.push(event.json());
            }
            captured_source_events = a.source_events;
            captured_rejections = a.route_rejections;
            captured_entry_evidence = a.route_entry_evidence;
            captured_observation_evidence = a.observation_evidence;
            let digest = sha256::hex(&a.receipt.terminal_sha256);
            let namespace = format!(
                "capture-namespace-sha256:{}",
                sha256::hex(&a.receipt.capture_namespace)
            );
            Self {
                receipt: a.receipt.json(),
                digest,
                namespace,
                entries: a.route_entries,
                rejections: Vec::new(),
                observations: a.observations,
                collector: Vec::new(),
                source_events,
                captured_source_events,
                imported_source_events,
                captured_rejections,
                captured_entry_evidence,
                captured_observation_evidence,
            }
        } else if &magic == bgp_mrt_store::MAGIC {
            let a = bgp_mrt_store::replay_with_options(
                path,
                maximum,
                mrt_limits,
                limits.clone(),
                options,
            )?;
            preflight_native_clone(&a.bgp4mp_rib, a.state.observations(), limits)?;
            let namespace = format!(
                "mrt-source-sha256:{}:checkpoint:{}",
                sha256::hex(&a.receipt.source_sha256),
                a.receipt.checkpoint_id
            );
            let collector = collector_rows(&a, &namespace, limits)?;
            // Finish archive-owned candidate validation before moving its vectors.
            imported_source_events = a.source_events;
            source_events = a.bgp4mp_events;
            let digest = sha256::hex(&a.receipt.terminal_sha256);
            Self {
                receipt: a.receipt.json(),
                digest,
                namespace,
                entries: a.bgp4mp_rib.entries().values().cloned().collect(),
                rejections: a.bgp4mp_rib.rejections().to_vec(),
                observations: a.state.observations().to_vec(),
                collector,
                source_events,
                captured_source_events,
                imported_source_events,
                captured_rejections,
                captured_entry_evidence,
                captured_observation_evidence,
            }
        } else if &magic == bgp_bmp_store::MAGIC {
            let bmp_limits = bmp_profile(&mrt_limits);
            let a = bgp_bmp_store::replay_with_options(
                path,
                maximum,
                bmp_limits,
                limits.clone(),
                bgp_bmp_store::BmpReplayOptions {
                    peer_relationship: options.peer_relationship,
                },
            )?;
            preflight_native_clone(&a.bmp_rib, a.state.observations(), limits)?;
            imported_source_events = a.source_events;
            source_events = a.bmp_events;
            let digest = sha256::hex(&a.receipt.terminal_sha256);
            let namespace = format!(
                "bmp-source-sha256:{}:checkpoint:{}",
                sha256::hex(&a.receipt.source_sha256),
                a.receipt.checkpoint_id
            );
            Self {
                receipt: a.receipt.json(),
                digest,
                namespace,
                entries: a.bmp_rib.entries().values().cloned().collect(),
                rejections: a.bmp_rib.rejections().to_vec(),
                observations: a.state.observations().to_vec(),
                collector: Vec::new(),
                source_events,
                captured_source_events,
                imported_source_events,
                captured_rejections,
                captured_entry_evidence,
                captured_observation_evidence,
            }
        } else {
            return Err(Error::new(
                ErrorCode::BadMagic,
                0,
                "bgp_store_magic",
                "sealed captured/MRT/BMP source store required",
            ));
        };
        Ok(inputs)
    }
}

// Candidate validation requires the still-intact MRT archive. This owner
// admits a collector occurrence before copying it and never turns a snapshot
// candidate into an active native reducer version.
fn collector_rows(
    a: &bgp_mrt_store::MrtReplayArchive,
    namespace: &str,
    limits: &Limits,
) -> Result<Vec<RouteRow>> {
    let mut collector = Vec::new();
    let mut collector_bytes = 0usize;
    for c in &a.candidates {
        let o = a.candidate_observation(c)?;
        let r = &o.routes()[c.route_index];
        collector_bytes = collector_bytes
            .checked_add(
                r.attributes()
                    .encoded_len_bounded(limits.retained_bytes)?
                    .saturating_mul(3)
                    .saturating_add(4096),
            )
            .ok_or_else(|| Error::limit("bgp_persisted_collector"))?;
        if collector.len() >= limits.elements
            || collector_bytes > limits.retained_bytes
            || collector_bytes > limits.work
        {
            return Err(Error::limit("bgp_persisted_collector"));
        }
        let context = o
            .import_context()
            .ok_or_else(|| bad("bgp_persisted_import", 0, "context missing"))?;
        let p = super::super::bgp_session::SourcePartition::from_import_context(context, limits)?;
        let key = RouteKey {
            scope: super::super::bgp_rib::RibScope {
                source: p,
                session: c.session.clone(),
                generation: o.source().generation.unwrap_or(0),
                direction: None,
                peer: c.peer.clone(),
            },
            family: Family {
                afi: c.prefix.afi,
                safi: c.prefix.safi,
            },
            path_id: match c.path_id {
                super::super::bgp_state::RoutePathId::Absent => PathId::Absent,
                super::super::bgp_state::RoutePathId::Present(v) => PathId::Present(v),
            },
            prefix: c.prefix.clone(),
        };
        let occurrence_charge = o
            .normalized()
            .encoded_len_bounded(limits.retained_bytes)?
            .saturating_add(4096)
            .saturating_mul(8);
        collector_bytes = collector_bytes
            .checked_add(occurrence_charge)
            .ok_or_else(|| Error::limit("bgp_persisted_collector"))?;
        if collector_bytes > limits.retained_bytes || collector_bytes > limits.work {
            return Err(Error::limit("bgp_persisted_collector"));
        }
        let clock = context.clock.clone();
        let occurrence_ref = occurrence_reference(o, c.route_index, &key, None, namespace, &clock);
        let encoded_identity = r.attribute_identity().encode_bounded(limits.input_bytes)?;
        let attribute_identity = format!(
            "sha256:{}",
            sha256::hex(&sha256::digest(encoded_identity.as_bytes()))
        );
        let version_occurrences = Json::array([Json::object([
            ("attribute_identity", attribute_identity.clone().into()),
            ("disposition", "collector_candidate".into()),
            ("native_version_index", Json::Null),
            ("origin_binding", "unavailable_collector_candidate".into()),
            ("occurrences", Json::array([occurrence_ref.clone()])),
        ])]);
        let selector_versions = vec![SelectorVersion {
            native_version_index: None,
            attribute_identity,
            disposition: VersionDisposition::Conflicting,
            occurrences: vec![SelectorOccurrence {
                native_event_index: None,
                observation_index: c.observation_index,
                route_index: c.route_index,
                occurrence_ref,
                clock,
                observed_at_ns: c.observed_at_ns,
            }],
        }];
        collector.push(RouteRow {
            id: format!("collector:{}:{}", c.record_index, c.entry_index),
            key,
            status: RouteStatus::Unresolved,
            collector: true,
            current: false,
            lifecycle: None,
            original_partition: None,
            alternatives: Json::array([Json::object([
                ("attributes", r.attributes().clone()),
                ("observation_sha256", sha256::hex(&o.sha256()).into()),
                ("record_id", c.record_id.clone().into()),
            ])]),
            version_occurrences,
            selector_versions,
            attributes: None,
            witnesses: vec![c.record_id.clone()],
            checkpoint: Some(c.checkpoint_id.clone()),
            clock: context.clock.clone(),
            observed_at_ns: c.observed_at_ns,
            rejection: None,
        });
    }
    Ok(collector)
}
