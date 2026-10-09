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

/// Include the original source event without selecting a winner or rewriting
/// its label when the queried real session belongs to its affected inventory.
fn event_affects_session(event: &Json, session: &str) -> bool {
    if event_session(event) == Some(session) {
        return true;
    }
    if !matches!(
        event_text(event, "parse_status"),
        Some("quarantined_ambiguous_session" | "quarantined_coverage_unknown")
    ) {
        return false;
    }
    let Some(Json::Array(scopes)) =
        event_value(event, "detail").and_then(|detail| event_value(detail, "affected_scopes"))
    else {
        return false;
    };
    scopes
        .iter()
        .any(|scope| event_text(scope, "session") == Some(session))
}

pub(crate) struct Projection<'a> {
    writer: Option<&'a mut dyn Write>,
    used: usize,
    limit: usize,
}

impl<'a> Projection<'a> {
    pub(crate) fn new(writer: Option<&'a mut dyn Write>, limit: usize) -> Self {
        Self {
            writer,
            used: 0,
            limit,
        }
    }

    pub(crate) fn used(&self) -> usize {
        self.used
    }
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
    pub(crate) fn raw(&mut self, value: &str) -> Result<()> {
        self.account(value.len())?;
        if let Some(writer) = &mut self.writer {
            writer.write_all(value.as_bytes())?;
        }
        Ok(())
    }

    pub(crate) fn value(&mut self, value: Json) -> Result<()> {
        self.value_ref(&value)
    }

    pub(crate) fn value_ref(&mut self, value: &Json) -> Result<()> {
        value.encoded_len_bounded(self.limit.saturating_sub(self.used))?;
        self.borrowed_value(value)
    }

    // Walk admitted JSON by reference, without a second tree or encoded buffer.
    fn borrowed_value(&mut self, value: &Json) -> Result<()> {
        match value {
            Json::Null => self.raw("null"),
            Json::Bool(value) => self.raw(if *value { "true" } else { "false" }),
            Json::Number(value) => self.raw(&value.to_string()),
            Json::String(value) => self.text(value),
            Json::Array(values) => {
                self.raw("[")?;
                for (index, value) in values.iter().enumerate() {
                    if index != 0 {
                        self.raw(",")?;
                    }
                    self.borrowed_value(value)?;
                }
                self.raw("]")
            }
            Json::Object(values) => {
                self.raw("{")?;
                for (index, (key, value)) in values.iter().enumerate() {
                    self.field(key, index == 0)?;
                    self.borrowed_value(value)?;
                }
                self.raw("}")
            }
        }
    }

    pub(crate) fn text(&mut self, value: &str) -> Result<()> {
        let size = value
            .chars()
            .try_fold(2usize, |size, c| {
                size.checked_add(match c {
                    '"' | '\\' | '\n' | '\r' | '\t' | '\x08' | '\x0c' => 2,
                    c if (c as u32) < 32 => 6,
                    c => c.len_utf8(),
                })
            })
            .filter(|size| *size <= self.limit.saturating_sub(self.used))
            .ok_or_else(|| Error::limit("report_bytes"))?;
        if self.writer.is_none() {
            return self.account(size);
        }
        self.raw("\"")?;
        let mut start = 0;
        for (index, c) in value.char_indices() {
            if c != '"' && c != '\\' && (c as u32) >= 32 {
                continue;
            }
            self.raw(&value[start..index])?;
            match c {
                '"' => self.raw("\\\"")?,
                '\\' => self.raw("\\\\")?,
                '\n' => self.raw("\\n")?,
                '\r' => self.raw("\\r")?,
                '\t' => self.raw("\\t")?,
                '\x08' => self.raw("\\b")?,
                '\x0c' => self.raw("\\f")?,
                c if (c as u32) < 32 => self.raw(&format!("\\u{:04x}", c as u32))?,
                _ => unreachable!("only escape characters enter this branch"),
            }
            start = index + c.len_utf8();
        }
        self.raw(&value[start..])?;
        self.raw("\"")
    }

    pub(crate) fn field(&mut self, key: &'static str, first: bool) -> Result<()> {
        if !first {
            self.raw(",")?;
        }
        self.text(key)?;
        self.raw(":")
    }
}

// Stream the typed RIB directly. In particular, versions/attributes/witnesses
// are borrowed rather than collected into a potentially amplified JSON tree.
pub(crate) fn project_rib(
    rib: &AdjRibIn,
    session: Option<&str>,
    out: &mut Projection<'_>,
) -> Result<()> {
    use crate::deep::bgp_rib::PathId;
    macro_rules! text {
        ($key:literal, $value:expr, $first:expr) => {{
            out.field($key, $first)?;
            out.text($value)?;
        }};
    }
    macro_rules! value {
        ($key:literal, $value:expr, $first:expr) => {{
            out.field($key, $first)?;
            out.value($value)?;
        }};
    }
    let own = |scope: &crate::deep::bgp_rib::RibScope| {
        session.is_none_or(|session| scope.session == session)
    };
    out.raw("{")?;
    text!("schema", crate::deep::bgp_rib::SCHEMA, true);
    value!("source_authenticated", false.into(), false);
    value!("endpoint_state_claimed", false.into(), false);
    value!("installed_routes_established", false.into(), false);
    value!("reachability_established", false.into(), false);
    out.field("end_of_rib", false)?;
    out.raw("[")?;
    for (index, marker) in rib
        .eors()
        .iter()
        .filter(|marker| own(&marker.scope))
        .enumerate()
    {
        if index != 0 {
            out.raw(",")?;
        }
        out.raw("{")?;
        text!("partition_id", &marker.scope.source.partition_id, true);
        text!("session", &marker.scope.session, false);
        text!("generation", &marker.scope.generation.to_string(), false);
        value!(
            "direction",
            marker.scope.direction.map_or(Json::Null, Json::from),
            false
        );
        value!("afi", marker.family.afi.into(), false);
        value!("safi", marker.family.safi.into(), false);
        text!("record_id", &marker.record_id, false);
        out.raw("}")?;
    }
    out.raw("]")?;
    out.field("entries", false)?;
    out.raw("[")?;
    for (index, entry) in rib
        .entries()
        .values()
        .filter(|entry| own(&entry.key.scope))
        .enumerate()
    {
        if index != 0 {
            out.raw(",")?;
        }
        out.raw("{")?;
        text!("source_id", &entry.key.scope.source.source_id, true);
        text!("partition_id", &entry.key.scope.source.partition_id, false);
        text!("session", &entry.key.scope.session, false);
        text!("generation", &entry.key.scope.generation.to_string(), false);
        value!(
            "direction",
            entry.key.scope.direction.map_or(Json::Null, Json::from),
            false
        );
        out.field("peer", false)?;
        if let Some(peer) = &entry.key.scope.peer {
            out.text(peer)?;
        } else {
            out.raw("null")?;
        }
        out.field("prefix", false)?;
        project_prefix(&entry.key.prefix, out)?;
        value!(
            "path_id",
            match entry.key.path_id {
                PathId::Absent => Json::Null,
                PathId::Present(value) => value.into(),
                PathId::Unknown => "unknown".into(),
            },
            false
        );
        text!("status", rib_support::route_status(entry.status), false);
        text!("last_witness", &entry.last_witness, false);
        out.field("versions", false)?;
        out.raw("[")?;
        for (index, version) in entry.versions.iter().enumerate() {
            if index != 0 {
                out.raw(",")?;
            }
            out.raw("{")?;
            out.field("attributes", true)?;
            out.value_ref(&version.attributes)?;
            text!("attribute_identity", &version.attribute_identity, false);
            text!(
                "disposition",
                rib_support::version_status(version.disposition),
                false
            );
            out.field("witnesses", false)?;
            out.raw("[")?;
            for (index, witness) in version.witnesses.iter().enumerate() {
                if index != 0 {
                    out.raw(",")?;
                }
                out.text(witness)?;
            }
            out.raw("]}")?;
        }
        out.raw("]}")?;
    }
    out.raw("]")?;
    out.field("gaps", false)?;
    out.raw("[")?;
    for (index, (scope, record)) in rib
        .gaps()
        .iter()
        .filter(|(scope, _)| own(scope))
        .enumerate()
    {
        if index != 0 {
            out.raw(",")?;
        }
        out.raw("{")?;
        text!("partition_id", &scope.source.partition_id, true);
        text!("session", &scope.session, false);
        text!("generation", &scope.generation.to_string(), false);
        text!("record_id", record, false);
        out.raw("}")?;
    }
    out.raw("]")?;
    out.field("rejected_records", false)?;
    out.raw("[")?;
    for (index, item) in rib
        .rejections()
        .iter()
        .filter(|item| own(&item.key.scope))
        .enumerate()
    {
        if index != 0 {
            out.raw(",")?;
        }
        out.raw("{")?;
        text!("partition_id", &item.key.scope.source.partition_id, true);
        text!("session", &item.key.scope.session, false);
        text!("generation", &item.key.scope.generation.to_string(), false);
        out.field("prefix", false)?;
        project_prefix(&item.key.prefix, out)?;
        text!("record_id", &item.record_id, false);
        text!("reason", &item.reason, false);
        out.raw("}")?;
    }
    out.raw("]}")
}

fn project_prefix(prefix: &PrefixIdentity, out: &mut Projection<'_>) -> Result<()> {
    out.raw("{")?;
    out.field("afi", true)?;
    out.value(prefix.afi.into())?;
    out.field("safi", false)?;
    out.value(prefix.safi.into())?;
    out.field("length", false)?;
    out.value(prefix.length.into())?;
    out.field("address", false)?;
    out.text(&prefix.address)?;
    out.raw("}")
}

impl MrtReplayArchive {
    /// Exact typed RIB preflight followed by borrowed streaming. A size failure
    /// writes no bytes and never constructs an aggregate RIB JSON tree.
    pub fn write_bgp4mp_rib_bounded_line(
        &self,
        session: Option<&str>,
        writer: &mut dyn Write,
        limit: usize,
    ) -> Result<usize> {
        let mut measure = Projection {
            writer: None,
            used: 0,
            limit,
        };
        project_rib(&self.bgp4mp_rib, session, &mut measure)?;
        measure.raw("\n")?;
        let expected = measure.used;
        let mut out = Projection {
            writer: Some(writer),
            used: 0,
            limit: expected,
        };
        project_rib(&self.bgp4mp_rib, session, &mut out)?;
        out.raw("\n")?;
        if out.used != expected {
            return Err(bad("bgp_mrt_output", 0, "RIB projection size changed"));
        }
        Ok(out.used)
    }
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
        out.field("bgp4mp_adj_rib_in", false)?;
        project_rib(&self.bgp4mp_rib, None, out)?;
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
                .any(|event| event_affects_session(event, session))
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
        out.value("pcap-evidence.bgp.imported-session-query.v4".into())?;
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
        // Route-free imported boundaries and EOR records are source evidence
        // for native RIB history even though no candidate can reference them.
        for (index, observation) in self.state.observations().iter().enumerate() {
            if observation.source().session.as_deref() != Some(session)
                || !observation.routes().is_empty()
                || observation.import_context().is_none()
            {
                continue;
            }
            seen.try_reserve(1)
                .map_err(|_| Error::limit("bgp_mrt_observations"))?;
            if seen.insert(index) {
                if !first_observation {
                    out.raw(",")?;
                }
                first_observation = false;
                out.value(Json::object([
                    ("observation_index", index.to_string().into()),
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
            .filter(|event| event_affects_session(event, session))
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
        out.field("bgp4mp_adj_rib_in", false)?;
        project_rib(&self.bgp4mp_rib, Some(session), out)?;
        out.raw("}")
    }

    /// Exact current v4 JSON size. No whole-archive Json/String is constructed;
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

    /// Preserve the current v4 JSON bytes for callers that need a String.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deep::{
        bgp_rib::{PathId, RibAction, RibEvent, RibEventKind, RibScope},
        bgp_session::{PartitionKind, SourcePartition},
    };

    #[test]
    fn large_native_rib_payload_rejects_small_remaining_budget_during_preflight() {
        let mut rib = AdjRibIn::new(Limits::default()).unwrap();
        rib.apply(RibEvent {
            scope: RibScope {
                source: SourcePartition {
                    kind: PartitionKind::Imported,
                    source_id: "large-source".into(),
                    partition_id: "large-partition".into(),
                },
                session: "large-session".into(),
                generation: 0,
                direction: Some(0),
                peer: Some("large-peer".into()),
            },
            record_id: "large-record".into(),
            kind: RibEventKind::Update(vec![RibAction::Announce {
                prefix: PrefixIdentity {
                    afi: 1,
                    safi: 1,
                    length: 24,
                    address: "203.0.113.0".into(),
                },
                path_id: PathId::Absent,
                attributes: Json::object([("source_payload", "a".repeat(128 * 1024).into())]),
                attribute_identity: "large-attributes".into(),
            }]),
        })
        .unwrap();
        let mut measure = Projection::new(None, 768);
        let error = project_rib(&rib, None, &mut measure).unwrap_err();
        assert_eq!(error.field, "report_bytes");
        assert!(
            measure.used() < 768,
            "borrowed attribute extent is checked before traversal/output"
        );
        let expected = rib_support::rib_json(&rib, None)
            .encode_bounded_line(1024 * 1024)
            .unwrap();
        let mut bytes = Vec::new();
        let mut out = Projection::new(Some(&mut bytes), expected.len());
        project_rib(&rib, None, &mut out).unwrap();
        out.raw("\n").unwrap();
        assert_eq!(bytes, expected.as_bytes());
    }

    #[test]
    fn borrowed_string_stream_matches_json_escaping_without_aggregate_buffer() {
        let text = "quote\" slash\\ newline\n return\r tab\t back\x08 form\x0c nul\0 unicodeé中";
        let expected = Json::from(text).encode();
        let mut bytes = Vec::new();
        let mut out = Projection::new(Some(&mut bytes), expected.len());
        out.text(text).unwrap();
        assert_eq!(out.used(), expected.len());
        assert_eq!(bytes, expected.as_bytes());
    }
}
