//! Bounded, byte-compatible projections without an archive-sized JSON tree.
use super::*;

fn event_session(event: &Json) -> Option<&str> {
    match event {
        Json::Object(fields) => {
            fields
                .iter()
                .find(|(key, _)| *key == "session")
                .and_then(|(_, value)| match value {
                    Json::String(session) => Some(session.as_str()),
                    _ => None,
                })
        }
        _ => None,
    }
}

struct Projection<'a> {
    writer: Option<&'a mut dyn Write>,
    used: usize,
    limit: usize,
}

impl Projection<'_> {
    fn account(&mut self, length: usize) -> Result<()> {
        self.used = self
            .used
            .checked_add(length)
            .filter(|size| *size <= self.limit)
            .ok_or_else(|| Error::limit("report_bytes"))?;
        Ok(())
    }

    // Only punctuation and the already-validated, cached state encoding use
    // this private method. All labels/capture-derived strings use Json escaping.
    fn raw(&mut self, value: &str) -> Result<()> {
        self.account(value.len())?;
        if let Some(writer) = &mut self.writer {
            writer.write_all(value.as_bytes())?;
        }
        Ok(())
    }

    fn value(&mut self, value: Json) -> Result<()> {
        self.value_ref(&value)
    }

    fn value_ref(&mut self, value: &Json) -> Result<()> {
        let size = value.encoded_len_bounded(self.limit.saturating_sub(self.used))?;
        self.account(size)?;
        if let Some(writer) = &mut self.writer {
            let encoded = value.encode_bounded(size)?;
            writer.write_all(encoded.as_bytes())?;
        }
        Ok(())
    }

    fn field(&mut self, key: &'static str, first: bool) -> Result<()> {
        if !first {
            self.raw(",")?;
        }
        self.value(key.into())?;
        self.raw(":")
    }
}

impl MrtReplayArchive {
    fn project(&self, out: &mut Projection<'_>) -> Result<()> {
        out.raw("{")?;
        out.field("schema", true)?;
        out.value(REPLAY_SCHEMA.into())?;
        out.field("receipt", false)?;
        out.value(self.receipt.json())?;
        out.field("adapter_schema", false)?;
        out.value(self.batch.schema.into())?;
        out.field("fresh_process_reduction", false)?;
        out.value(true.into())?;
        out.field("source_authenticated", false)?;
        out.value(false.into())?;
        out.field("endpoint_state_claimed", false)?;
        out.value(false.into())?;
        out.field("bgp4mp_peer_relationship", false)?;
        out.value(
            self.peer_relationship
                .map_or("unknown", peer_relationship_name)
                .into(),
        )?;
        out.field("bgp4mp_peer_relationship_basis", false)?;
        out.value(
            if self.peer_relationship.is_some() {
                "explicit_configuration"
            } else {
                "default_unknown"
            }
            .into(),
        )?;
        out.field("bgp4mp_peer_relationship_scope", false)?;
        out.value("all_sessions_in_this_replay".into())?;
        out.field("collector_candidates", false)?;
        out.raw("[")?;
        for (index, candidate) in self.candidates.iter().enumerate() {
            if index != 0 {
                out.raw(",")?;
            }
            self.candidate_observation(candidate)?;
            out.value(candidate.json())?;
        }
        out.raw("]")?;
        out.field("bgp4mp_candidates", false)?;
        out.raw("[")?;
        for (index, candidate) in self.bgp4mp_candidates.iter().enumerate() {
            if index != 0 {
                out.raw(",")?;
            }
            self.bgp4mp_candidate_observation(candidate)?;
            out.value(candidate.json())?;
        }
        out.raw("]")?;
        out.field("bgp4mp_events", false)?;
        out.raw("[")?;
        for (index, event) in self.bgp4mp_events.iter().enumerate() {
            if index != 0 {
                out.raw(",")?;
            }
            out.value_ref(event)?;
        }
        out.raw("]")?;
        out.field("candidate_state", false)?;
        out.raw(self.state.encode())?;
        out.field("record_summaries", false)?;
        out.raw("[")?;
        for (index, record) in self.batch.records.iter().enumerate() {
            if index != 0 {
                out.raw(",")?;
            }
            out.value(record_json(record))?;
        }
        out.raw("]")?;
        out.field("opaque_records", false)?;
        out.value(self.opaque_records.to_string().into())?;
        out.field("unsupported_rib_entries", false)?;
        out.value(self.unsupported_rib_entries.to_string().into())?;
        out.field("unsupported_rib_entry_evidence", false)?;
        out.raw("[")?;
        for (index, evidence) in self.unsupported_rib_entry_evidence.iter().enumerate() {
            if index != 0 {
                out.raw(",")?;
            }
            out.value_ref(evidence)?;
        }
        out.raw("]")?;
        out.field("bgp4mp_messages", false)?;
        out.value(self.bgp4mp_messages.to_string().into())?;
        out.field("bgp4mp_state_changes", false)?;
        out.value(self.bgp4mp_state_changes.to_string().into())?;
        out.raw("}")
    }

    fn project_session(&self, session: &str, out: &mut Projection<'_>) -> Result<()> {
        if !self
            .candidates
            .iter()
            .any(|candidate| candidate.session == session)
            && !self
                .bgp4mp_candidates
                .iter()
                .any(|candidate| candidate.session == session)
            && !self
                .bgp4mp_events
                .iter()
                .any(|event| event_session(event) == Some(session))
        {
            return Err(Error::new(
                ErrorCode::InvalidIndex,
                0,
                "bgp_session",
                "session is not present in the sealed MRT store",
            ));
        }
        out.raw("{")?;
        out.field("schema", true)?;
        out.value("pcap-evidence.bgp.imported-session-query.v3".into())?;
        out.field("session", false)?;
        out.value(session.into())?;
        out.field("observations", false)?;
        out.raw("[")?;
        let mut seen = HashSet::new();
        let mut first_observation = true;
        for candidate in self
            .candidates
            .iter()
            .filter(|item| item.session == session)
        {
            // Validate before deduplication, including repeated indices.
            let observation = self.candidate_observation(candidate)?;
            seen.try_reserve(1)
                .map_err(|_| Error::limit("bgp_mrt_observations"))?;
            if seen.insert(candidate.observation_index) {
                if !first_observation {
                    out.raw(",")?;
                }
                first_observation = false;
                out.value(Json::object([
                    (
                        "observation_index",
                        candidate.observation_index.to_string().into(),
                    ),
                    ("normalized_observation", observation.normalized().clone()),
                ]))?;
            }
        }
        for candidate in self
            .bgp4mp_candidates
            .iter()
            .filter(|item| item.session == session)
        {
            // Validate before deduplication, including repeated indices.
            let observation = self.bgp4mp_candidate_observation(candidate)?;
            seen.try_reserve(1)
                .map_err(|_| Error::limit("bgp_mrt_observations"))?;
            if seen.insert(candidate.observation_index) {
                if !first_observation {
                    out.raw(",")?;
                }
                first_observation = false;
                out.value(Json::object([
                    (
                        "observation_index",
                        candidate.observation_index.to_string().into(),
                    ),
                    ("normalized_observation", observation.normalized().clone()),
                ]))?;
            }
        }
        out.raw("]")?;
        out.field("candidates", false)?;
        out.raw("[")?;
        let mut first = true;
        for candidate in self
            .candidates
            .iter()
            .filter(|item| item.session == session)
        {
            if !first {
                out.raw(",")?;
            }
            first = false;
            self.candidate_observation(candidate)?;
            out.value(candidate.json())?;
        }
        out.raw("]")?;
        out.field("bgp4mp_candidates", false)?;
        out.raw("[")?;
        let mut first = true;
        for candidate in self
            .bgp4mp_candidates
            .iter()
            .filter(|item| item.session == session)
        {
            if !first {
                out.raw(",")?;
            }
            first = false;
            self.bgp4mp_candidate_observation(candidate)?;
            out.value(candidate.json())?;
        }
        out.raw("]")?;
        out.field("bgp4mp_events", false)?;
        out.raw("[")?;
        let mut first = true;
        for event in self
            .bgp4mp_events
            .iter()
            .filter(|event| event_session(event) == Some(session))
        {
            if !first {
                out.raw(",")?;
            }
            first = false;
            out.value_ref(event)?;
        }
        out.raw("]")?;
        out.field("endpoint_state_claimed", false)?;
        out.value(false.into())?;
        out.raw("}")
    }

    /// Exact current v3 JSON size. No whole-archive Json/String is constructed;
    /// each projected value is temporary, but session queries also retain a
    /// fallibly grown observation-index set for deduplication.
    pub fn encoded_len_bounded(&self, limit: usize) -> Result<usize> {
        let mut out = Projection {
            writer: None,
            used: 0,
            limit,
        };
        self.project(&mut out)?;
        Ok(out.used)
    }

    /// Preserve the current v3 JSON bytes for callers that need a String.
    /// Prefer `write_bounded_line` for files to avoid an aggregate output buffer.
    pub fn encode_bounded(&self, limit: usize) -> Result<String> {
        let size = self.encoded_len_bounded(limit)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(size)
            .map_err(|_| Error::limit("bgp_mrt_output_allocation"))?;
        let mut out = Projection {
            writer: Some(&mut bytes),
            used: 0,
            limit: size,
        };
        self.project(&mut out)?;
        if out.used != size {
            return Err(bad("bgp_mrt_output", 0, "projection size changed"));
        }
        String::from_utf8(bytes)
            .map_err(|_| bad("bgp_mrt_output", 0, "JSON projection is not UTF-8"))
    }

    /// Validate the entire output budget, including newline, before writing.
    /// I/O failures can leave partial bytes; the caller still owns staging,
    /// syncing, exclusive publication, and receipt-last commit semantics.
    pub fn write_bounded_line(&self, writer: &mut dyn Write, limit: usize) -> Result<usize> {
        let body_limit = limit
            .checked_sub(1)
            .ok_or_else(|| Error::limit("report_bytes"))?;
        let body = self.encoded_len_bounded(body_limit)?;
        let expected = body
            .checked_add(1)
            .ok_or_else(|| Error::limit("report_bytes"))?;
        let mut out = Projection {
            writer: Some(writer),
            used: 0,
            limit: expected,
        };
        self.project(&mut out)?;
        out.raw("\n")?;
        if out.used != expected {
            return Err(bad("bgp_mrt_output", 0, "projection size changed"));
        }
        Ok(out.used)
    }

    /// Same schema and field order as the existing imported-session query.
    /// A missing session or insufficient output budget writes no bytes.
    pub fn write_session_query_bounded_line(
        &self,
        session: &str,
        writer: &mut dyn Write,
        limit: usize,
    ) -> Result<usize> {
        let mut measure = Projection {
            writer: None,
            used: 0,
            limit,
        };
        self.project_session(session, &mut measure)?;
        measure.raw("\n")?;
        let expected = measure.used;
        let mut out = Projection {
            writer: Some(writer),
            used: 0,
            limit: expected,
        };
        self.project_session(session, &mut out)?;
        out.raw("\n")?;
        if out.used != expected {
            return Err(bad("bgp_mrt_output", 0, "session projection size changed"));
        }
        Ok(out.used)
    }
}
