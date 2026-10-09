//! Exact output preflight and borrowed streaming; convenience JSON trees are separate.
use super::*;
use crate::deep::bgp_mrt_store::output::{project_rib, Projection};
#[derive(Clone, Copy)]
enum OutputKind<'a> {
    Archive,
    Session(&'a str),
    Export,
    Rib(Option<&'a str>),
}

impl BmpReplayArchive {
    fn project(&self, out: &mut Projection<'_>) -> Result<()> {
        out.raw("{")?;
        out.field("schema", true)?;
        out.text(REPLAY_SCHEMA)?;
        out.field("receipt", false)?;
        out.value(self.receipt.json())?;
        out.field("adapter_schema", false)?;
        out.text(bgp_bmp::SCHEMA)?;
        out.field("fresh_process_reduction", false)?;
        out.raw("true")?;
        out.field("source_authenticated", false)?;
        out.raw("false")?;
        out.field("endpoint_state_claimed", false)?;
        out.raw("false")?;
        out.field("bmp_peer_relationship", false)?;
        out.text(
            self.peer_relationship
                .map_or("unknown", PeerRelationship::as_str),
        )?;
        out.field("bmp_peer_relationship_basis", false)?;
        out.text(if self.peer_relationship.is_some() {
            "explicit_configuration"
        } else {
            "default_unknown"
        })?;
        out.field("bmp_peer_relationship_scope", false)?;
        out.text("all_sessions_in_this_replay")?;
        out.field("candidate_state", false)?;
        out.raw(self.state.encode())?;
        out.field("bmp_rib", false)?;
        project_rib(&self.bmp_rib, None, out)?;
        out.field("bmp_events", false)?;
        self.project_events(None, out)?;
        out.raw("}")
    }
    fn project_events(&self, session: Option<&str>, out: &mut Projection<'_>) -> Result<()> {
        out.raw("[")?;
        for (index, event) in self
            .bmp_events
            .iter()
            .filter(|event| session.is_none_or(|s| event_matches(event, s)))
            .enumerate()
        {
            if index != 0 {
                out.raw(",")?;
            }
            out.value_ref(event)?;
        }
        out.raw("]")
    }
    fn project_observation(
        &self,
        index: usize,
        observation: &Observation,
        export: bool,
        out: &mut Projection<'_>,
    ) -> Result<()> {
        out.raw("{")?;
        if export {
            out.field("schema", true)?;
            out.text("pcap-evidence.bgp.bmp-observation.v1")?;
        }
        out.field("observation_index", !export)?;
        out.value(index.into())?;
        out.field("observation_sha256", false)?;
        out.text(&sha256::hex(&observation.sha256()))?;
        out.field("normalized_observation", false)?;
        out.value_ref(observation.normalized())?;
        out.raw("}")
    }
    fn project_session(&self, session: &str, out: &mut Projection<'_>) -> Result<()> {
        out.raw("{")?;
        out.field("schema", true)?;
        out.text("pcap-evidence.bgp.bmp-candidate-query.v1")?;
        out.field("receipt", false)?;
        out.value(self.receipt.json())?;
        out.field("session", false)?;
        out.text(session)?;
        out.field("bmp_rib", false)?;
        project_rib(&self.bmp_rib, Some(session), out)?;
        out.field("bmp_events", false)?;
        self.project_events(Some(session), out)?;
        out.field("observations", false)?;
        out.raw("[")?;
        let mut first = true;
        for (index, observation) in self
            .state
            .observations()
            .iter()
            .enumerate()
            .filter(|(_, o)| o.source().session.as_deref() == Some(session))
        {
            if !first {
                out.raw(",")?;
            }
            first = false;
            self.project_observation(index, observation, false, out)?;
        }
        out.raw("]")?;
        out.field("source_authenticated", false)?;
        out.raw("false")?;
        out.field("endpoint_state_claimed", false)?;
        out.raw("false}")
    }
    fn project_export(&self, out: &mut Projection<'_>) -> Result<()> {
        out.value(Json::object([
            ("schema", "pcap-evidence.bgp.bmp-export.v1".into()),
            ("receipt", self.receipt.json()),
        ]))?;
        out.raw("\n")?;
        for record in &self.batch.records {
            let (status, reason) = match &record.body {
                bgp_bmp::BmpBody::Opaque { reason, .. } => ("opaque", *reason),
                _ => ("framed", ""),
            };
            out.raw("{")?;
            out.field("schema", true)?;
            out.text(bgp_bmp::SCHEMA)?;
            out.field("message_type", false)?;
            out.value(record.message_type.into())?;
            out.field("range", false)?;
            out.value(bgp_bmp::range_json(&self.batch.record_range(record)))?;
            out.field("peer", false)?;
            out.value(
                record
                    .peer
                    .as_ref()
                    .map_or(Json::Null, bgp_bmp::BmpPeer::json),
            )?;
            out.field("status", false)?;
            out.text(status)?;
            out.field("reason", false)?;
            out.text(reason)?;
            out.field("original_hex", false)?;
            out.raw("\"")?;
            const DIGITS: &[u8; 16] = b"0123456789abcdef";
            for byte in &self.batch.bytes()
                [record.offset as usize..record.offset as usize + record.length as usize]
            {
                let encoded = [DIGITS[(byte >> 4) as usize], DIGITS[(byte & 15) as usize]];
                out.raw(std::str::from_utf8(&encoded).unwrap())?;
            }
            out.raw("\"}\n")?;
        }
        for event in &self.bmp_events {
            out.value_ref(event)?;
            out.raw("\n")?;
        }
        for (index, observation) in self.state.observations().iter().enumerate() {
            self.project_observation(index, observation, true, out)?;
            out.raw("\n")?;
        }
        out.raw("{")?;
        out.field("schema", true)?;
        out.text("pcap-evidence.bgp.bmp-rib-export.v1")?;
        out.field("bmp_rib", false)?;
        project_rib(&self.bmp_rib, None, out)?;
        out.raw("}\n")
    }
    pub fn encoded_len_bounded(&self, maximum: usize) -> Result<usize> {
        let mut out = Projection::new(None, maximum);
        self.project(&mut out)?;
        Ok(out.used())
    }
    fn encode_projection(
        &self,
        maximum: usize,
        session: Option<&str>,
        export: bool,
    ) -> Result<String> {
        let project = |out: &mut Projection<'_>| match (session, export) {
            (Some(session), _) => self.project_session(session, out),
            (_, true) => self.project_export(out),
            _ => self.project(out),
        };
        let mut measure = Projection::new(None, maximum);
        project(&mut measure)?;
        let expected = measure.used();
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(expected)
            .map_err(|_| Error::limit("bmp_output_allocation"))?;
        let mut out = Projection::new(Some(&mut bytes), expected);
        project(&mut out)?;
        if out.used() != expected {
            return Err(bad("bmp_output", 0, "projection size changed"));
        }
        String::from_utf8(bytes).map_err(|_| bad("bmp_output", 0, "JSON projection is not UTF-8"))
    }
    pub fn encode_json(&self, maximum: usize) -> Result<String> {
        self.encode_projection(maximum, None, false)
    }
    pub fn encode_session_query_bounded(&self, session: &str, maximum: usize) -> Result<String> {
        self.encode_projection(maximum, Some(session), false)
    }
    pub fn export_ndjson(&self, maximum: usize) -> Result<String> {
        self.encode_projection(maximum, None, true)
    }
    fn write_projection(
        &self,
        writer: &mut dyn Write,
        maximum: usize,
        kind: OutputKind<'_>,
        newline: bool,
    ) -> Result<usize> {
        let project = |out: &mut Projection<'_>| -> Result<()> {
            match kind {
                OutputKind::Rib(session) => project_rib(&self.bmp_rib, session, out)?,
                OutputKind::Session(session) => self.project_session(session, out)?,
                OutputKind::Export => self.project_export(out)?,
                OutputKind::Archive => self.project(out)?,
            }
            if newline {
                out.raw("\n")?;
            }
            Ok(())
        };
        let mut measure = Projection::new(None, maximum);
        project(&mut measure)?;
        let expected = measure.used();
        let mut out = Projection::new(Some(writer), expected);
        project(&mut out)?;
        if out.used() != expected {
            return Err(bad("bmp_output", 0, "projection size changed"));
        }
        Ok(out.used())
    }
    pub fn write_json(&self, writer: &mut impl Write, maximum: usize) -> Result<()> {
        self.write_projection(writer, maximum, OutputKind::Archive, false)
            .map(|_| ())
    }
    pub fn write_bounded_line(&self, writer: &mut dyn Write, maximum: usize) -> Result<usize> {
        self.write_projection(writer, maximum, OutputKind::Archive, true)
    }
    pub fn write_session_query_bounded_line(
        &self,
        session: &str,
        writer: &mut dyn Write,
        maximum: usize,
    ) -> Result<usize> {
        self.write_projection(writer, maximum, OutputKind::Session(session), true)
    }
    pub fn write_bmp_rib_bounded_line(
        &self,
        session: Option<&str>,
        writer: &mut dyn Write,
        maximum: usize,
    ) -> Result<usize> {
        self.write_projection(writer, maximum, OutputKind::Rib(session), true)
    }
    pub fn write_export_ndjson(&self, writer: &mut dyn Write, maximum: usize) -> Result<()> {
        self.write_projection(writer, maximum, OutputKind::Export, false)
            .map(|_| ())
    }
}
