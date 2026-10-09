//! One archive-preparation owner: decode source records, apply native replay,
//! retain source occurrences, then bind candidate ordinals to reduced state.
use super::*;

pub(super) fn build_archive(
    batch: MrtBatch,
    terminal: [u8; 32],
    source_bytes: &[u8],
    limits: Limits,
    options: MrtReplayOptions,
) -> Result<MrtReplayArchive> {
    let mut builder = MrtArchiveBuilder::new(batch, source_bytes, limits, options)?;
    for record_index in 0..builder.batch.records.len() {
        let replay = builder.decode_record(record_index)?;
        let (cuts, native_continuity) = builder.apply_native_record(record_index, &replay)?;
        builder.publish_source_record(record_index, &replay, cuts, &native_continuity)?;
    }
    builder.finish(terminal, options)
}

/// All mutable preparation state stays with the archive transaction. The
/// record phases borrow this owner; they do not maintain alternate reducers.
struct MrtArchiveBuilder<'source> {
    batch: MrtBatch,
    source_bytes: &'source [u8],
    limits: Limits,
    state: CandidateState,
    bgp4mp_rib: AdjRibIn,
    bgp4mp_rib_work: usize,
    candidates: Vec<CollectorCandidate>,
    bgp4mp_candidates: Vec<Bgp4mpCandidate>,
    bgp4mp_events: Vec<Json>,
    bgp4mp_event_bytes: usize,
    source_events: Vec<ImportedSourceEvent>,
    source_event_bytes: usize,
    source_event_work: usize,
    source_observation_bytes: usize,
    imported_sessions: bgp::mrt::ReplayState,
    observations: Vec<Observation>,
    observations_work: usize,
    bgp4mp_contexts: BTreeMap<(String, ImportPartition), ImportContext>,
    opaque_records: u64,
    unsupported_rib_entries: u64,
    bgp4mp_messages: u64,
    bgp4mp_state_changes: u64,
}

/// A source record's exact inventory cuts, before interpretation. These
/// offsets bind new observations, JSON witnesses, and admitted native events.
struct RecordReplay {
    observations_before: usize,
    events_before: usize,
    native_before: usize,
    opaque_gap: Option<ImportContinuityCut>,
}

/// Fixed held bytes/work for this record, excluding the decoder and cut
/// collectors whose actual current retention is refreshed at every admission.
struct NativeRecordAdmission {
    retained_base: usize,
    work_base: usize,
}
impl NativeRecordAdmission {
    fn footprint(
        &self,
        sessions: &bgp::mrt::ReplayState,
        cuts: &[ImportContinuityCut],
        native_work: usize,
        limits: &Limits,
    ) -> Result<(usize, usize)> {
        let retained = native_external_retained(self.retained_base, sessions, cuts, limits)?;
        let work = self
            .work_base
            .checked_add(native_work)
            .ok_or_else(|| Error::limit("bgp_mrt_source_event_work"))?;
        Ok((retained, work))
    }
}

fn observation_retained_charge(observation: &Observation) -> Result<usize> {
    let bytes = super::super::bgp_mrt_stream_store::json_memory(observation.normalized())
        .checked_add(std::mem::size_of::<Observation>())
        .ok_or_else(|| Error::limit("bgp_mrt_source_events"))?;
    bytes
        .checked_add(
            observation
                .import_context()
                .map_or(Ok(0), |c| c.retained_charge())?,
        )
        .ok_or_else(|| Error::limit("bgp_mrt_source_events"))
}

impl<'source> MrtArchiveBuilder<'source> {
    fn new(
        batch: MrtBatch,
        source_bytes: &'source [u8],
        limits: Limits,
        options: MrtReplayOptions,
    ) -> Result<Self> {
        if u64::try_from(source_bytes.len()).ok() != Some(batch.byte_length) {
            return Err(Error::limit("bgp_mrt_source_bytes"));
        }
        let state = CandidateState::new(limits.clone())?;
        // The archive projection owns the actual output cap; native typed
        // retention and work remain independently bounded.
        let bgp4mp_rib = AdjRibIn::for_embedded_projection(limits.clone())?;
        Ok(Self {
            batch,
            source_bytes,
            limits,
            state,
            bgp4mp_rib,
            bgp4mp_rib_work: 0,
            candidates: Vec::new(),
            bgp4mp_candidates: Vec::new(),
            bgp4mp_events: Vec::new(),
            bgp4mp_event_bytes: 0,
            source_events: Vec::new(),
            source_event_bytes: 0,
            source_event_work: 0,
            source_observation_bytes: 0,
            imported_sessions: bgp::mrt::ReplayState::with_peer_relationship(
                options.peer_relationship,
            ),
            observations: Vec::new(),
            observations_work: 0,
            bgp4mp_contexts: BTreeMap::new(),
            opaque_records: 0,
            unsupported_rib_entries: 0,
            bgp4mp_messages: 0,
            bgp4mp_state_changes: 0,
        })
    }

    fn decode_record(&mut self, record_index: usize) -> Result<RecordReplay> {
        let record = &self.batch.records[record_index];
        let observations_before = self.observations.len();
        let events_before = self.bgp4mp_events.len();
        let native_before = self.bgp4mp_rib.events().len();
        let mut opaque_gap = None;
        match &record.body {
            MrtBody::Rib(rib) => {
                for entry_index in 0..rib.entries.len() {
                    let Some(normalized) =
                        self.batch
                            .normalize_rib_entry(record_index, entry_index, &self.limits)?
                    else {
                        self.unsupported_rib_entries = increment(
                            self.unsupported_rib_entries,
                            "bgp_mrt_unsupported_rib_entries",
                        )?;
                        if self.unsupported_rib_entries > self.limits.elements as u64 {
                            return Err(Error::limit("bgp_mrt_unsupported_rib_entries"));
                        }
                        continue;
                    };
                    let candidate_count_before = self.candidates.len();
                    let observation =
                        Observation::from_normalized(&normalized, None, &self.limits)?;
                    self.observations_work = self
                        .observations_work
                        .checked_add(observation.batch_work()?)
                        .ok_or_else(|| Error::limit("bgp_state_work"))?;
                    if self.observations_work > self.limits.work {
                        return Err(Error::limit("bgp_state_work"));
                    }
                    if self.observations.len() >= self.limits.elements {
                        return Err(Error::limit("bgp_mrt_observations"));
                    }
                    self.observations
                        .try_reserve(1)
                        .map_err(|_| Error::limit("bgp_mrt_observations"))?;
                    let observation_index = self.observations.len();
                    for (route_index, route) in observation.routes().iter().enumerate() {
                        if self.candidates.len() >= self.limits.elements {
                            return Err(Error::limit("bgp_mrt_collector_candidates"));
                        }
                        self.candidates
                            .try_reserve(1)
                            .map_err(|_| Error::limit("bgp_mrt_collector_candidates"))?;
                        let source = observation.source();
                        if source.kind != SourceKind::Imported {
                            return Err(bad(
                                "bgp_mrt_source_kind",
                                0,
                                "MRT normalization produced non-imported evidence",
                            ));
                        }
                        self.candidates.push(CollectorCandidate {
                            record_index,
                            entry_index,
                            observation_sha256: observation.sha256(),
                            source_id: source.source_id.clone(),
                            checkpoint_id: self.batch.source.checkpoint_id.clone(),
                            record_id: source.record_id.clone(),
                            session: source.session.clone().ok_or_else(|| {
                                bad("bgp_mrt_session", 0, "normalized MRT session is absent")
                            })?,
                            peer: source.peer.clone(),
                            observed_at_ns: source.observed_at_ns,
                            prefix: route.prefix().clone(),
                            path_id: route.path_id(),
                            action: route.action(),
                            ambiguous_attributes: route.ambiguous_attributes(),
                            observation_index,
                            route_index,
                        });
                    }
                    if self.candidates.len() == candidate_count_before {
                        return Err(bad(
                            "bgp_mrt_collector_candidate",
                            entry_index,
                            "normalized RIB entry produced no route candidate",
                        ));
                    }
                    self.observations.push(observation);
                }
            }
            MrtBody::Bgp4mp(message) => match &message.payload {
                Bgp4mpPayload::Message(embedded) => {
                    self.bgp4mp_messages =
                        increment(self.bgp4mp_messages, "bgp_mrt_bgp4mp_messages")?;
                    let range = self
                        .batch
                        .bgp4mp_message_source_range(record_index)?
                        .ok_or_else(|| {
                            bad("bgp_mrt_message_range", record_index, "range absent")
                        })?;
                    let start = usize::try_from(range.start)
                        .map_err(|_| Error::limit("bgp_mrt_message_range"))?;
                    let end = usize::try_from(range.end)
                        .map_err(|_| Error::limit("bgp_mrt_message_range"))?;
                    let original = self.source_bytes.get(start..end).ok_or_else(|| {
                        bad(
                            "bgp_mrt_message_source",
                            start,
                            "message range outside source",
                        )
                    })?;
                    let source_message_sha256 = sha256::hex(&sha256::digest(original));
                    if original != embedded.as_slice()
                        || range.sha256.as_deref() != Some(source_message_sha256.as_str())
                    {
                        return Err(bad(
                            "bgp_mrt_message_source",
                            start,
                            "embedded message differs from original source range",
                        ));
                    }
                    let replay = bgp::mrt::replay_message_record(
                        &self.batch,
                        record_index,
                        record,
                        super::bgp_import::SourceRange {
                            start: range.start,
                            end: range.end,
                            sha256: range.sha256.clone(),
                        },
                        &self.limits,
                        &mut self.imported_sessions,
                    )?;
                    opaque_gap = replay.continuity_gap;
                    append_bgp4mp_generation_boundaries(Bgp4mpGenerationBoundaryInput {
                        observations: &mut self.observations,
                        observations_work: &mut self.observations_work,
                        contexts: &mut self.bgp4mp_contexts,
                        batch: &self.batch,
                        record_index,
                        record,
                        event: &replay.event,
                        limits: &self.limits,
                    })?;
                    retain_bgp4mp_event(
                        &mut self.bgp4mp_events,
                        &mut self.bgp4mp_event_bytes,
                        replay.event,
                        &self.limits,
                    )?;
                    if let Some(normalized) = replay.observation {
                        let observation =
                            Observation::from_normalized(&normalized, None, &self.limits)?;
                        // Route-free opaque UPDATEs must reach the native
                        // reducer as gaps and remain in the immutable journal.
                        if !observation.routes().is_empty()
                            || rib_support::route_projection_incomplete(&observation)
                            || rib_support::end_of_rib_family(&observation)?.is_some()
                        {
                            self.observations_work = self
                                .observations_work
                                .checked_add(observation.batch_work()?)
                                .ok_or_else(|| Error::limit("bgp_state_work"))?;
                            if self.observations_work > self.limits.work {
                                return Err(Error::limit("bgp_state_work"));
                            }
                            if self.observations.len() >= self.limits.elements {
                                return Err(Error::limit("bgp_mrt_observations"));
                            }
                            self.observations
                                .try_reserve(1)
                                .map_err(|_| Error::limit("bgp_mrt_observations"))?;
                            let observation_index = self.observations.len();
                            let source = observation.source();
                            for (route_index, route) in observation.routes().iter().enumerate() {
                                if self.bgp4mp_candidates.len() >= self.limits.elements {
                                    return Err(Error::limit("bgp_mrt_bgp4mp_candidates"));
                                }
                                self.bgp4mp_candidates
                                    .try_reserve(1)
                                    .map_err(|_| Error::limit("bgp_mrt_bgp4mp_candidates"))?;
                                self.bgp4mp_candidates.push(Bgp4mpCandidate {
                                    record_index,
                                    observation_sha256: observation.sha256(),
                                    source_id: source.source_id.clone(),
                                    checkpoint_id: self.batch.source.checkpoint_id.clone(),
                                    record_id: source.record_id.clone(),
                                    session: source.session.clone().ok_or_else(|| {
                                        bad("bgp_mrt_session", record_index, "session absent")
                                    })?,
                                    peer: source.peer.clone(),
                                    observed_at_ns: source.observed_at_ns,
                                    direction: source.direction.ok_or_else(|| {
                                        bad("bgp_mrt_direction", record_index, "direction absent")
                                    })?,
                                    source_range_start: range.start,
                                    source_range_end: range.end,
                                    message_sha256: range.sha256.clone().ok_or_else(|| {
                                        bad(
                                            "bgp_mrt_message_hash",
                                            record_index,
                                            "message digest absent",
                                        )
                                    })?,
                                    prefix: route.prefix().clone(),
                                    path_id: route.path_id(),
                                    action: route.action(),
                                    observation_index,
                                    route_index,
                                });
                            }
                            let context =
                                observation.import_context().cloned().ok_or_else(|| {
                                    bad(
                                        "bgp_mrt_import_context",
                                        record_index,
                                        "BGP4MP route observation has no import context",
                                    )
                                })?;
                            let context_key = (context.session.clone(), context.partition());
                            if !self.bgp4mp_contexts.contains_key(&context_key)
                                && self.bgp4mp_contexts.len() >= self.limits.elements
                            {
                                return Err(Error::limit("bgp_mrt_generation_contexts"));
                            }
                            self.bgp4mp_contexts.insert(context_key, context);
                            self.observations.push(observation);
                        }
                    }
                }
                Bgp4mpPayload::State { .. } => {
                    self.bgp4mp_state_changes =
                        increment(self.bgp4mp_state_changes, "bgp_mrt_bgp4mp_states")?;
                    let event = bgp::mrt::replay_state_record(
                        &self.batch,
                        record_index,
                        record,
                        &self.limits,
                        &mut self.imported_sessions,
                    )?;
                    append_bgp4mp_generation_boundaries(Bgp4mpGenerationBoundaryInput {
                        observations: &mut self.observations,
                        observations_work: &mut self.observations_work,
                        contexts: &mut self.bgp4mp_contexts,
                        batch: &self.batch,
                        record_index,
                        record,
                        event: &event,
                        limits: &self.limits,
                    })?;
                    retain_bgp4mp_event(
                        &mut self.bgp4mp_events,
                        &mut self.bgp4mp_event_bytes,
                        event,
                        &self.limits,
                    )?;
                }
            },
            MrtBody::Opaque { reason, .. } => {
                self.opaque_records = increment(self.opaque_records, "bgp_mrt_opaque_records")?;
                if *reason == "malformed_bgp4mp_record" {
                    let event = bgp::mrt::replay_malformed_record(
                        &self.batch,
                        record_index,
                        record,
                        &self.limits,
                        &mut self.imported_sessions,
                    )?;
                    retain_bgp4mp_event(
                        &mut self.bgp4mp_events,
                        &mut self.bgp4mp_event_bytes,
                        event,
                        &self.limits,
                    )?;
                }
            }
            MrtBody::PeerIndex(_) => {}
        }
        Ok(RecordReplay {
            observations_before,
            events_before,
            native_before,
            opaque_gap,
        })
    }

    fn apply_native_record(
        &mut self,
        record_index: usize,
        replay: &RecordReplay,
    ) -> Result<(
        Vec<ImportContinuityCut>,
        Vec<bgp_import::ImportedNativeContinuity>,
    )> {
        let record = &self.batch.records[record_index];
        let observations_before = replay.observations_before;
        let events_before = replay.events_before;
        let opaque_gap = &replay.opaque_gap;
        let mut native_continuity = Vec::new();
        if matches!(
            record.body,
            MrtBody::Bgp4mp(_)
                | MrtBody::Opaque {
                    reason: "malformed_bgp4mp_record",
                    ..
                }
        ) {
            // Include pending observations and source-event metadata before a
            // native effect can be copied into the per-record collector.
            let pending_bytes = self.observations[observations_before..].iter().try_fold(
                0usize,
                |n, observation| {
                    let bytes = observation_retained_charge(observation)
                        .map_err(|_| Error::limit("bgp_mrt_source_events"))?;
                    n.checked_add(bytes)
                        .ok_or_else(|| Error::limit("bgp_mrt_source_events"))
                },
            )?;
            let native_base = self
                .batch
                .retained_bytes
                .checked_add(self.source_event_bytes)
                .and_then(|n| n.checked_add(self.source_observation_bytes))
                .and_then(|n| n.checked_add(pending_bytes))
                .and_then(|n| n.checked_add(self.bgp4mp_event_bytes))
                .ok_or_else(|| Error::limit("bgp_mrt_source_events"))?;
            let admission = NativeRecordAdmission {
                retained_base: native_base,
                work_base: self
                    .observations_work
                    .checked_add(pending_bytes)
                    .and_then(|n| n.checked_add(self.source_event_work))
                    .ok_or_else(|| Error::limit("bgp_mrt_source_event_work"))?,
            };
            let mut cuts = Vec::new();
            for event in &self.bgp4mp_events[events_before..] {
                let (record_cuts, work) = self.imported_sessions.continuity_cuts(
                    &self.batch,
                    record_index,
                    record,
                    event,
                    opaque_gap.as_ref(),
                    &self.limits,
                )?;
                self.bgp4mp_rib_work = self
                    .bgp4mp_rib_work
                    .checked_add(work)
                    .filter(|n| *n <= self.limits.work)
                    .ok_or_else(|| Error::limit("bgp_mrt_rib_work"))?;
                cuts.extend(record_cuts);
                self.bgp4mp_rib_work = self
                    .bgp4mp_rib_work
                    .checked_add(rib_support::reset_native_scopes(
                        &mut self.bgp4mp_rib,
                        event,
                        record_index,
                        record,
                        &mut native_continuity,
                        admission.footprint(
                            &self.imported_sessions,
                            &cuts,
                            self.bgp4mp_rib_work,
                            &self.limits,
                        )?,
                        &self.limits,
                    )?)
                    .filter(|work| *work <= self.limits.work)
                    .ok_or_else(|| Error::limit("bgp_mrt_rib_work"))?;
            }
            self.bgp4mp_rib_work = self
                .bgp4mp_rib_work
                .checked_add(rib_support::apply_continuity_cuts(
                    &mut self.bgp4mp_rib,
                    &cuts,
                    &mut native_continuity,
                    admission.footprint(
                        &self.imported_sessions,
                        &cuts,
                        self.bgp4mp_rib_work,
                        &self.limits,
                    )?,
                    &self.limits,
                )?)
                .filter(|n| *n <= self.limits.work)
                .ok_or_else(|| Error::limit("bgp_mrt_rib_work"))?;
            for observation in &self.observations[observations_before..] {
                if let Some(event) = rib_support::observation_event(observation, &self.limits)? {
                    let before = self.bgp4mp_rib.accounted_work();
                    let origin =
                        if let super::super::bgp_rib::RibEventKind::Update(actions) = &event.kind {
                            if actions.len() != observation.routes().len() {
                                return Err(bad(
                                    "bgp_mrt_native_origin",
                                    record_index,
                                    "native actions differ from checked observation route ordinals",
                                ));
                            }
                            // The checked envelope's immutable digest and exact
                            // route/action order are the producer's version origin.
                            self.bgp4mp_rib_work = self
                                .bgp4mp_rib_work
                                .checked_add(observation.batch_work()?)
                                .filter(|n| *n <= self.limits.work)
                                .ok_or_else(|| Error::limit("bgp_mrt_rib_work"))?;
                            Some(observation.sha256())
                        } else {
                            None
                        };
                    bgp_import::apply_native_event(
                        &mut self.bgp4mp_rib,
                        event,
                        origin,
                        &mut native_continuity,
                        {
                            let (retained, work) = admission.footprint(
                                &self.imported_sessions,
                                &cuts,
                                self.bgp4mp_rib_work,
                                &self.limits,
                            )?;
                            (retained, work, 1, 8)
                        },
                        &self.limits,
                    )?;
                    self.bgp4mp_rib_work = self
                        .bgp4mp_rib_work
                        .checked_add(
                            self.bgp4mp_rib
                                .accounted_work()
                                .checked_sub(before)
                                .ok_or_else(|| Error::limit("bgp_mrt_rib_work"))?,
                        )
                        .filter(|work| *work <= self.limits.work)
                        .ok_or_else(|| Error::limit("bgp_mrt_rib_work"))?;
                }
            }
            for event in &self.bgp4mp_events[events_before..] {
                self.bgp4mp_rib_work = self
                    .bgp4mp_rib_work
                    .checked_add(rib_support::quarantine_event(
                        &mut self.bgp4mp_rib,
                        event,
                        &self.bgp4mp_contexts,
                        &mut native_continuity,
                        admission.footprint(
                            &self.imported_sessions,
                            &cuts,
                            self.bgp4mp_rib_work,
                            &self.limits,
                        )?,
                        &self.limits,
                    )?)
                    .filter(|work| *work <= self.limits.work)
                    .ok_or_else(|| Error::limit("bgp_mrt_rib_work"))?;
            }
            return Ok((cuts, native_continuity));
        }
        Ok((Vec::new(), native_continuity))
    }

    fn publish_source_record(
        &mut self,
        record_index: usize,
        replay: &RecordReplay,
        mut record_cuts: Vec<ImportContinuityCut>,
        native_continuity: &[bgp_import::ImportedNativeContinuity],
    ) -> Result<()> {
        let record = &self.batch.records[record_index];
        let observations_before = replay.observations_before;
        let events_before = replay.events_before;
        let native_before = replay.native_before;
        let opaque_gap = &replay.opaque_gap;
        for observation in &self.observations[observations_before..] {
            let bytes = observation_retained_charge(observation)?;
            self.source_observation_bytes = self
                .source_observation_bytes
                .checked_add(bytes)
                .ok_or_else(|| Error::limit("bgp_mrt_source_events"))?;
            self.source_event_work = self
                .source_event_work
                .checked_add(bytes)
                .filter(|n| *n <= self.limits.work)
                .ok_or_else(|| Error::limit("bgp_mrt_source_event_work"))?;
        }
        let native_bytes =
            bgp_import::native_continuity_charge(native_continuity, "bgp_mrt_source_events")?;
        self.bgp4mp_rib_work = self
            .bgp4mp_rib_work
            .checked_add(
                native_bytes
                    .checked_mul(8)
                    .ok_or_else(|| Error::limit("bgp_mrt_source_event_work"))?,
            )
            .filter(|n| *n <= self.limits.work)
            .ok_or_else(|| Error::limit("bgp_mrt_source_event_work"))?;
        let source_event_base = self
            .batch
            .retained_bytes
            .checked_add(native_bytes)
            .ok_or_else(|| Error::limit("bgp_mrt_source_events"))?
            .checked_add(self.bgp4mp_rib.retained_bytes())
            .and_then(|n| n.checked_add(self.bgp4mp_event_bytes))
            .and_then(|n| n.checked_add(self.source_observation_bytes))
            .and_then(|n| n.checked_add(self.imported_sessions.retained_bytes(&self.limits).ok()?))
            .ok_or_else(|| Error::limit("bgp_mrt_source_events"))?;
        // Checked source metadata is retained before copying opaque references.
        // Container rows and observation rows remain distinct source occurrences.
        if let Some(gap) = opaque_gap.as_ref() {
            append_opaque_source_cut(
                &mut record_cuts,
                gap,
                source_event_base,
                self.source_event_bytes,
                &self.limits,
            )?;
        }
        let boundary = self.bgp4mp_rib.events()[native_before..]
            .iter()
            .any(|event| {
                matches!(
                    event.kind,
                    super::super::bgp_rib::RibEventKind::Reset { .. }
                )
            });
        let fallback = (events_before == self.bgp4mp_events.len()).then(|| record_json(record));
        let references: &[Json] = fallback
            .as_ref()
            .map_or(&self.bgp4mp_events[events_before..], std::slice::from_ref);
        for (reference_index, reference) in references.iter().enumerate() {
            let context = if fallback.is_none() {
                self.imported_sessions.source_context(
                    &self.batch,
                    record_index,
                    record,
                    reference,
                    &self.limits,
                )?
            } else {
                None
            };
            let kind = if fallback.is_none() {
                self.imported_sessions.source_event_kind(
                    record,
                    reference,
                    boundary,
                    context.is_some(),
                )
            } else {
                match &record.body {
                    MrtBody::PeerIndex(_) => ImportedSourceEventKind::SessionMetadata,
                    MrtBody::Rib(_) => ImportedSourceEventKind::Update,
                    _ => ImportedSourceEventKind::Opaque,
                }
            };
            retain_source_event(
                &mut self.source_events,
                &mut self.source_event_bytes,
                &mut self.source_event_work,
                source_event_held_base(source_event_base, &record_cuts)?,
                self.observations_work
                    .checked_add(self.bgp4mp_rib_work)
                    .ok_or_else(|| Error::limit("bgp_mrt_source_event_work"))?,
                record_index,
                None,
                kind,
                context.as_ref(),
                &record_cuts,
                &self.batch.source.source_id,
                &self.batch.source.checkpoint_id,
                if reference_index == 0 {
                    native_continuity
                } else {
                    &[]
                },
                reference,
                &self.limits,
            )?;
            for (offset, observation) in self.observations[observations_before..].iter().enumerate()
            {
                let kind = match observation.kind() {
                    ObservationKind::Reset => ImportedSourceEventKind::GenerationBoundary,
                    ObservationKind::Routes => {
                        if rib_support::route_projection_incomplete(observation) {
                            ImportedSourceEventKind::ContinuityGap
                        } else {
                            ImportedSourceEventKind::Update
                        }
                    }
                    ObservationKind::Open => ImportedSourceEventKind::Open,
                    ObservationKind::Notification => ImportedSourceEventKind::Notification,
                    ObservationKind::Keepalive => ImportedSourceEventKind::Keepalive,
                    ObservationKind::RouteRefresh => ImportedSourceEventKind::RouteRefresh,
                };
                retain_source_event(
                    &mut self.source_events,
                    &mut self.source_event_bytes,
                    &mut self.source_event_work,
                    source_event_held_base(source_event_base, &record_cuts)?,
                    self.observations_work
                        .checked_add(self.bgp4mp_rib_work)
                        .ok_or_else(|| Error::limit("bgp_mrt_source_event_work"))?,
                    record_index,
                    Some(observations_before + offset),
                    kind,
                    observation.import_context(),
                    &[],
                    &self.batch.source.source_id,
                    &self.batch.source.checkpoint_id,
                    &[],
                    reference,
                    &self.limits,
                )?;
            }
        }
        Ok(())
    }

    fn finish(self, terminal: [u8; 32], options: MrtReplayOptions) -> Result<MrtReplayArchive> {
        let Self {
            batch,
            limits,
            mut state,
            bgp4mp_rib,
            bgp4mp_rib_work,
            mut candidates,
            mut bgp4mp_candidates,
            bgp4mp_events,
            bgp4mp_event_bytes,
            mut source_events,
            source_event_bytes,
            source_event_work,
            imported_sessions: _,
            observations,
            mut observations_work,
            opaque_records,
            unsupported_rib_entries,
            bgp4mp_messages,
            bgp4mp_state_changes,
            source_bytes: _,
            source_observation_bytes: _,
            bgp4mp_contexts: _,
        } = self;
        observations_work = observations_work
            .checked_add(bgp4mp_rib_work)
            .and_then(|n| n.checked_add(source_event_work))
            .filter(|work| *work <= limits.work)
            .ok_or_else(|| Error::limit("bgp_mrt_rib_work"))?;
        let outcomes = state.apply_batch(observations)?;
        for event in &mut source_events {
            if let Some(index) = event.observation_index {
                event.observation_index = Some(
                    outcomes
                        .get(index)
                        .ok_or_else(|| {
                            bad("bgp_mrt_source_event_ref", index, "missing batch receipt")
                        })?
                        .observation,
                );
                let observation = state
                    .observations()
                    .get(event.observation_index.unwrap())
                    .ok_or_else(|| {
                        bad(
                            "bgp_mrt_source_event_ref",
                            index,
                            "missing retained observation",
                        )
                    })?;
                if event.context.as_ref() != observation.import_context() {
                    return Err(bad(
                        "bgp_mrt_source_event_ref",
                        index,
                        "context changed during reduction",
                    ));
                }
            }
        }
        for candidate in &mut candidates {
            let outcome = outcomes.get(candidate.observation_index).ok_or_else(|| {
                bad(
                    "bgp_mrt_observation_ref",
                    candidate.observation_index,
                    "missing batch receipt",
                )
            })?;
            candidate.observation_index = outcome.observation;
            let routes = state
                .observations()
                .get(candidate.observation_index)
                .ok_or_else(|| {
                    bad(
                        "bgp_mrt_observation_ref",
                        candidate.observation_index,
                        "missing retained observation",
                    )
                })?
                .routes();
            if candidate.route_index >= routes.len() {
                return Err(bad(
                    "bgp_mrt_route_ref",
                    candidate.route_index,
                    "candidate route reference is outside the observation",
                ));
            }
        }
        for candidate in &mut bgp4mp_candidates {
            let outcome = outcomes.get(candidate.observation_index).ok_or_else(|| {
                bad(
                    "bgp_mrt_observation_ref",
                    candidate.observation_index,
                    "missing BGP4MP batch receipt",
                )
            })?;
            candidate.observation_index = outcome.observation;
            let observation = state
                .observations()
                .get(candidate.observation_index)
                .ok_or_else(|| {
                    bad(
                        "bgp_mrt_observation_ref",
                        candidate.observation_index,
                        "missing retained BGP4MP observation",
                    )
                })?;
            let route = observation
                .routes()
                .get(candidate.route_index)
                .ok_or_else(|| {
                    bad(
                        "bgp_mrt_route_ref",
                        candidate.route_index,
                        "BGP4MP candidate route is outside observation",
                    )
                })?;
            if route.prefix() != &candidate.prefix
                || route.path_id() != candidate.path_id
                || route.action() != candidate.action
            {
                return Err(bad(
                    "bgp_mrt_candidate_route",
                    candidate.route_index,
                    "BGP4MP route changed during state reduction",
                ));
            }
        }
        let records = as_u64(batch.records.len(), "bgp_mrt_records")?;
        let mut source_sha256 = [0u8; 32];
        let decoded = decode_hex_32(&batch.sha256)?;
        source_sha256.copy_from_slice(&decoded);
        let receipt = MrtStoreReceipt {
            source_id: batch.source.source_id.clone(),
            checkpoint_id: batch.source.checkpoint_id.clone(),
            source_sha256,
            source_bytes: batch.byte_length,
            terminal_sha256: terminal,
            records,
        };
        let mut archive = MrtReplayArchive {
            receipt,
            batch,
            state,
            bgp4mp_rib,
            peer_relationship: options.peer_relationship,
            candidates,
            bgp4mp_candidates,
            bgp4mp_events,
            source_events,
            opaque_records,
            unsupported_rib_entries,
            unsupported_rib_entry_evidence: Vec::new(),
            bgp4mp_messages,
            bgp4mp_state_changes,
        };
        // Logical retained-byte accounting, not allocator capacity or process RSS.
        // Keep the parsed batch, shared state, and compact projection inside one cap.
        let mut retained = archive
            .state
            .retained_bytes()
            .checked_add(archive.bgp4mp_rib.retained_bytes())
            .ok_or_else(|| Error::limit("bgp_mrt_retained"))?
            .checked_add(archive.batch.retained_bytes)
            .ok_or_else(|| Error::limit("bgp_mrt_retained"))?;
        for candidate in &archive.candidates {
            retained = retained
                .checked_add(
                    candidate
                        .json()
                        .encoded_len_bounded(limits.retained_bytes)?,
                )
                .ok_or_else(|| Error::limit("bgp_mrt_retained"))?;
            if retained > limits.retained_bytes {
                return Err(Error::limit("bgp_mrt_retained"));
            }
        }
        for candidate in &archive.bgp4mp_candidates {
            retained = retained
                .checked_add(
                    candidate
                        .json()
                        .encoded_len_bounded(limits.retained_bytes)?,
                )
                .ok_or_else(|| Error::limit("bgp_mrt_retained"))?;
            if retained > limits.retained_bytes {
                return Err(Error::limit("bgp_mrt_retained"));
            }
        }
        retained = retained
            .checked_add(bgp4mp_event_bytes)
            .and_then(|n| n.checked_add(source_event_bytes))
            .ok_or_else(|| Error::limit("bgp_mrt_retained"))?;
        if retained > limits.retained_bytes {
            return Err(Error::limit("bgp_mrt_retained"));
        }
        let base_output_bytes = archive.encoded_len_bounded(limits.output_bytes)?;
        let unsupported_count = usize::try_from(unsupported_rib_entries)
            .map_err(|_| Error::limit("bgp_mrt_unsupported_rib_entries"))?;
        let plan = preflight_unsupported_rib_evidence(
            &archive.batch,
            &archive.candidates,
            unsupported_count,
            limits.output_bytes - base_output_bytes,
            limits.retained_bytes - retained,
            limits
                .work
                .checked_sub(observations_work)
                .ok_or_else(|| Error::limit("bgp_state_work"))?,
        )?;
        if observations_work
            .checked_add(plan.work_units)
            .filter(|work| *work <= limits.work)
            .is_none()
        {
            return Err(Error::limit("bgp_state_work"));
        }
        let planned_output_bytes = base_output_bytes
            .checked_add(plan.output_growth)
            .ok_or_else(|| Error::limit("bgp_mrt_output"))?;
        if planned_output_bytes > limits.output_bytes {
            return Err(Error::limit("report_bytes"));
        }
        archive.unsupported_rib_entry_evidence = materialize_unsupported_rib_evidence(
            &archive.batch,
            &archive.candidates,
            plan.count,
            plan.rib_entry_count,
        )?;
        retained = retained
            .checked_add(plan.retained_bytes)
            .ok_or_else(|| Error::limit("bgp_mrt_retained"))?;
        if retained > limits.retained_bytes {
            return Err(Error::limit("bgp_mrt_retained"));
        }
        Ok(archive)
    }
}
