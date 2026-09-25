//! In-process, trusted-code extension API. Limits constrain built-ins and outputs;
//! they are not a CPU/memory sandbox for arbitrary third-party Rust code.
use crate::{
    config::StreamConfig,
    events::{Event, EventKind, EventSink, Evidence, EvidenceStatus},
    malformed, protocols, Error, Result,
};
use pcap_evidence::{
    dnp3,
    json::Json,
    modbus,
    protocol::{
        Dnp3Probe, ModbusProbe, ProbeInput, ProbeResult, ProbeStrength, ProbeTransport,
        ProtocolProbe,
    },
    provenance::EvidenceBytes,
    tcp::{StreamChunk, StreamResult},
    wire::Endpoint,
    Limits,
};
use std::collections::BTreeMap;

mod dnp_workflow;

#[derive(Clone, Debug)]
pub struct AnalyzerLimits {
    pub max_buffer_bytes: usize,
    pub max_messages: usize,
    pub max_work_bytes: usize,
}
impl AnalyzerLimits {
    pub fn from_config(c: &StreamConfig) -> Self {
        Self {
            max_buffer_bytes: c.max_plugin_bytes,
            max_messages: c.max_plugin_events,
            max_work_bytes: c.max_plugin_bytes.saturating_mul(16),
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Role {
    Request,
    Response,
    Unknown,
}
#[derive(Clone, Debug)]
pub struct CorrelationHint {
    pub key: String,
    pub role: Role,
    pub compatibility: String,
}
#[derive(Clone, Debug)]
pub struct MessageRecord {
    pub event: u64,
    pub session: u64,
    pub direction: u8,
    pub protocol: &'static str,
    pub hint: CorrelationHint,
    pub complete: bool,
    pub ambiguous: bool,
    pub boundary_verified: bool,
}

/// A verified DNP3 application fragment retained for the streaming-only
/// confirmation projection. This is intentionally separate from
/// `MessageRecord`: generic `transaction.candidate` correlation must not gain
/// DNP3-specific semantics as the protocol grows.
#[derive(Clone, Debug)]
pub struct Dnp3StreamingConfirmationRecord {
    pub event: u64,
    pub session: u64,
    pub window: u64,
    pub generation: Option<usize>,
    pub direction: u8,
    pub source: u16,
    pub destination: u16,
    pub witness: pcap_evidence::semantics::dnp3_workflow::FragmentWitness,
    pub raw: EvidenceBytes,
    pub ambiguous: bool,
    pub boundary_verified: bool,
}
#[derive(Clone, Debug)]
pub struct Context {
    pub session: u64,
    pub window: u64,
    pub generation: Option<usize>,
    pub direction: u8,
    pub source: Endpoint,
    pub destination: Endpoint,
    pub transport: ProbeTransport,
    pub ambiguous: bool,
    pub boundary_verified: bool,
    pub modbus_ports: Vec<u16>,
}
pub struct StreamInput<'a> {
    pub offset: i64,
    pub bytes: &'a EvidenceBytes,
    pub boundary_verified: bool,
}
pub struct DatagramInput<'a> {
    pub bytes: &'a EvidenceBytes,
}
pub struct Output<'a> {
    pub context: &'a Context,
    pub sink: &'a mut dyn EventSink,
    pub records: &'a mut Vec<MessageRecord>,
    pub dnp3_confirmations: &'a mut Vec<Dnp3StreamingConfirmationRecord>,
    pub remaining: &'a mut usize,
    pub max_message_bytes: usize,
    sink_failed: bool,
}

/// Mutable sinks shared by one registry invocation. Keeping these together
/// prevents the registry entry points from accumulating unrelated arguments as
/// additional protocol-specific projections are added.
pub struct RegistryOutput<'a> {
    pub sink: &'a mut dyn EventSink,
    pub records: &'a mut Vec<MessageRecord>,
    pub dnp3_confirmations: &'a mut Vec<Dnp3StreamingConfirmationRecord>,
    pub remaining: &'a mut usize,
}

struct BufferedSink {
    run_id: String,
    events: Vec<Event>,
    retained_bytes: usize,
    byte_limit: usize,
    per_event_limit: usize,
}
impl EventSink for BufferedSink {
    fn run_id(&self) -> &str {
        &self.run_id
    }
    fn emit(&mut self, event: &Event) -> Result<u64> {
        let sequence = u64::try_from(self.events.len() + 1)
            .map_err(|_| Error::limit("buffered_plugin_events"))?;
        let encoded = event
            .json(&self.run_id, sequence)
            .encode_bounded(self.per_event_limit)?;
        self.retained_bytes = self
            .retained_bytes
            .checked_add(encoded.len())
            .filter(|bytes| *bytes <= self.byte_limit)
            .ok_or_else(|| Error::limit("bidirectional_event_buffer"))?;
        self.events.push(event.clone());
        u64::try_from(self.events.len()).map_err(|_| Error::limit("buffered_plugin_events"))
    }
}
fn remap_buffered_event(local_id: u64, actual_ids: &[Option<u64>]) -> Result<u64> {
    let index = usize::try_from(
        local_id
            .checked_sub(1)
            .ok_or_else(|| Error::limit("buffered_plugin_event_id"))?,
    )
    .map_err(|_| Error::limit("buffered_plugin_event_id"))?;
    actual_ids
        .get(index)
        .and_then(|id| *id)
        .ok_or_else(|| Error::limit("buffered_plugin_event_id"))
}
impl Output<'_> {
    pub fn dnp3_confirmation_fragment(
        &mut self,
        raw: &EvidenceBytes,
        witness: pcap_evidence::semantics::dnp3_workflow::FragmentWitness,
        function_name: &'static str,
    ) -> Result<u64> {
        if self.context.transport != ProbeTransport::Tcp {
            return Ok(0);
        }
        if *self.remaining == 0 {
            return Err(Error::limit("plugin_events"));
        }
        if raw.len() > self.max_message_bytes || !raw.validate() {
            return Err(Error::limit("plugin_message"));
        }
        *self.remaining -= 1;
        let status = if self.context.ambiguous {
            EvidenceStatus::Ambiguous
        } else {
            EvidenceStatus::Observed
        };
        let mut event = Event::new(
            EventKind::Message,
            status,
            Json::object([
                ("projection", "dnp3_confirmation_fragment".into()),
                ("function_name", function_name.into()),
                ("function", witness.header.function.into()),
                ("sequence", witness.header.sequence().into()),
                ("unsolicited_namespace", witness.header.unsolicited().into()),
                ("source", witness.source.into()),
                ("destination", witness.destination.into()),
                ("link_direction", witness.link_direction.into()),
                ("scope", "one_stream_session_generation".into()),
            ]),
        );
        event.session = Some(self.context.session);
        event.direction = Some(self.context.direction);
        event.protocol = Some("dnp3".into());
        event.evidence = Evidence::bytes(raw);
        let id = match self.sink.emit(&event) {
            Ok(id) => id,
            Err(error) => {
                self.sink_failed = true;
                return Err(error);
            }
        };
        self.dnp3_confirmations
            .push(Dnp3StreamingConfirmationRecord {
                event: id,
                session: self.context.session,
                window: self.context.window,
                generation: self.context.generation,
                direction: self.context.direction,
                source: witness.source,
                destination: witness.destination,
                witness,
                raw: raw.clone(),
                ambiguous: self.context.ambiguous,
                boundary_verified: self.context.boundary_verified,
            });
        Ok(id)
    }

    pub fn message(
        &mut self,
        protocol: &'static str,
        bytes: &EvidenceBytes,
        range: Option<(i64, i64)>,
        data: Json,
        hint: Option<CorrelationHint>,
        complete: bool,
    ) -> Result<u64> {
        if *self.remaining == 0 {
            return Err(Error::limit("plugin_events"));
        }
        if bytes.len() > self.max_message_bytes || !bytes.validate() {
            return Err(Error::limit("plugin_message"));
        }
        *self.remaining -= 1;
        let status = if self.context.ambiguous {
            EvidenceStatus::Ambiguous
        } else if !complete {
            EvidenceStatus::Incomplete
        } else {
            EvidenceStatus::Candidate
        };
        let mut e = Event::new(EventKind::Message, status, data);
        e.session = Some(self.context.session);
        e.direction = Some(self.context.direction);
        e.protocol = Some(protocol.into());
        e.evidence = Evidence::bytes(bytes);
        e.stream_range = range;
        let id = match self.sink.emit(&e) {
            Ok(id) => id,
            Err(error) => {
                self.sink_failed = true;
                return Err(error);
            }
        };
        if let Some(hint) = hint {
            if hint.key.len() > 2048 || hint.compatibility.len() > 2048 {
                return Err(Error::limit("correlation_hint"));
            }
            self.records.push(MessageRecord {
                event: id,
                session: self.context.session,
                direction: self.context.direction,
                protocol,
                hint,
                complete,
                ambiguous: self.context.ambiguous,
                boundary_verified: self.context.boundary_verified,
            });
        }
        Ok(id)
    }
    pub fn issue(
        &mut self,
        protocol: &'static str,
        code: impl Into<String>,
        bytes: &EvidenceBytes,
    ) -> Result<()> {
        if *self.remaining == 0 {
            return Err(Error::limit("plugin_events"));
        }
        *self.remaining -= 1;
        let code: String = code.into();
        let mut e = Event::new(
            EventKind::ProtocolIssue,
            EvidenceStatus::Incomplete,
            Json::object([("reason", code.into())]),
        );
        e.session = Some(self.context.session);
        e.direction = Some(self.context.direction);
        e.protocol = Some(protocol.into());
        e.evidence = Evidence::bytes(bytes);
        match self.sink.emit(&e) {
            Ok(_) => Ok(()),
            Err(error) => {
                self.sink_failed = true;
                Err(error)
            }
        }
    }
}
pub trait ProtocolDetector: Send + Sync {
    fn protocol(&self) -> &'static str;
    fn detect(&self, input: &ProbeInput<'_>) -> ProbeResult;
}
pub trait StreamAnalyzer: Send {
    fn push(&mut self, input: &StreamInput<'_>, out: &mut Output<'_>) -> Result<()>;
    /// A gap is a hard protocol-state boundary; implementations cannot bridge it.
    fn gap(&mut self, reason: &str, out: &mut Output<'_>) -> Result<()>;
    fn finish(&mut self, out: &mut Output<'_>) -> Result<()>;
    fn retained_bytes(&self) -> usize;
}
pub trait DatagramAnalyzer: Send {
    /// Each call is exactly one reconstructed datagram, never a synthetic stream.
    fn analyze(&mut self, input: &DatagramInput<'_>, out: &mut Output<'_>) -> Result<()>;
    fn retained_bytes(&self) -> usize;
}
pub trait AnalyzerPlugin: ProtocolDetector {
    fn stream(&self, limits: AnalyzerLimits) -> Option<Box<dyn StreamAnalyzer>>;
    fn datagram(&self, limits: AnalyzerLimits) -> Option<Box<dyn DatagramAnalyzer>>;
}
pub trait TransactionCorrelator: Send + Sync {
    fn correlate(
        &self,
        records: &[MessageRecord],
        sink: &mut dyn EventSink,
        max_checks: usize,
    ) -> Result<()>;
}
/// Conservative grouping within ONE retained analysis window. Reused identifiers
/// are reported as ambiguous, not greedily paired using an invented time rule.
pub struct IdentifierCorrelator;
impl TransactionCorrelator for IdentifierCorrelator {
    fn correlate(
        &self,
        records: &[MessageRecord],
        sink: &mut dyn EventSink,
        max_checks: usize,
    ) -> Result<()> {
        if records.len() > max_checks {
            return Err(Error::limit("correlation_checks"));
        }
        let mut groups: BTreeMap<(u64, &'static str, String), Vec<&MessageRecord>> =
            BTreeMap::new();
        for r in records {
            if r.complete && !r.ambiguous && r.hint.role != Role::Unknown {
                groups
                    .entry((r.session, r.protocol, r.hint.key.clone()))
                    .or_default()
                    .push(r);
            }
        }
        for ((session, protocol, key), group) in groups {
            let req: Vec<_> = group
                .iter()
                .filter(|r| r.hint.role == Role::Request)
                .collect();
            let rsp: Vec<_> = group
                .iter()
                .filter(|r| r.hint.role == Role::Response)
                .collect();
            let unique = req.len() == 1 && rsp.len() == 1;
            let compatible = unique
                && if protocol == "modbus" {
                    pcap_evidence::semantics::modbus::compatibility_matches(
                        &req[0].hint.compatibility,
                        &rsp[0].hint.compatibility,
                    )
                } else {
                    req[0].hint.compatibility.is_empty()
                        || rsp[0].hint.compatibility.is_empty()
                        || req[0].hint.compatibility == rsp[0].hint.compatibility
                };
            let (status, reason) = if req.is_empty() {
                (EvidenceStatus::Incomplete, "orphan_response")
            } else if rsp.is_empty() {
                (EvidenceStatus::Incomplete, "unanswered_in_window")
            } else if !unique || req[0].direction == rsp[0].direction {
                (
                    EvidenceStatus::Ambiguous,
                    "identifier_reuse_or_direction_conflict",
                )
            } else if !compatible {
                (EvidenceStatus::Rejected, "inconsistent_response")
            } else if !req[0].boundary_verified || !rsp[0].boundary_verified {
                (EvidenceStatus::Candidate, "candidate_unverified_boundary")
            } else {
                (
                    EvidenceStatus::Candidate,
                    "matching_identifiers_not_causality",
                )
            };
            let mut e = Event::new(
                EventKind::Transaction,
                status,
                Json::object([
                    ("reason", reason.into()),
                    ("correlation_key", key.into()),
                    (
                        "requests",
                        Json::array(req.iter().map(|r| r.event.to_string().into())),
                    ),
                    (
                        "responses",
                        Json::array(rsp.iter().map(|r| r.event.to_string().into())),
                    ),
                    ("scope", "bounded_analysis_window".into()),
                ]),
            );
            e.session = Some(session);
            e.protocol = Some(protocol.into());
            e.related_events = group.iter().map(|r| r.event).collect();
            sink.emit(&e)?;
        }
        Ok(())
    }
}

#[derive(Default)]
struct Dnp3ConfirmationGroup {
    confirms: Vec<Dnp3StreamingConfirmationRecord>,
    responses: Vec<Dnp3StreamingConfirmationRecord>,
}

type Dnp3ConfirmationKey = ([u8; 32], u64, u64, Option<usize>, u16, u16, u8, bool);

fn dnp3_confirmation_key(r: &Dnp3StreamingConfirmationRecord) -> Dnp3ConfirmationKey {
    let (source, destination) = if r.witness.header.function == 0 {
        (r.source, r.destination)
    } else {
        (r.destination, r.source)
    };
    let capture = r
        .witness
        .packets
        .first()
        .map_or([0; 32], |packet| packet.capture);
    (
        capture,
        r.session,
        r.window,
        r.generation,
        source,
        destination,
        r.witness.header.sequence(),
        r.witness.header.unsolicited(),
    )
}

fn dnp3_participant_json(r: &Dnp3StreamingConfirmationRecord) -> Json {
    Json::object([
        ("event", r.event.to_string().into()),
        ("session", r.session.to_string().into()),
        ("window", r.window.to_string().into()),
        (
            "generation",
            r.generation
                .map_or(Json::Null, |generation| generation.to_string().into()),
        ),
        ("direction", r.direction.into()),
        ("source", r.source.into()),
        ("destination", r.destination.into()),
        ("function", r.witness.header.function.into()),
        ("sequence", r.witness.header.sequence().into()),
        (
            "unsolicited_namespace",
            r.witness.header.unsolicited().into(),
        ),
        (
            "confirmation_requested",
            r.witness.header.confirm_requested().into(),
        ),
        ("link_direction", r.witness.link_direction.into()),
        ("ambiguous_context", r.ambiguous.into()),
        ("boundary_verified", r.boundary_verified.into()),
        ("evidence", Evidence::bytes(&r.raw).json()),
    ])
}

/// Emit a DNP3-specific projection without changing generic transaction
/// semantics. Pairing is limited to one active window, one session and one
/// TCP generation; no timestamp, port, order or endpoint-state heuristic is
/// used. The work estimate is charged before any candidate event is emitted,
/// so budget exhaustion cannot return a partial projection.
pub fn correlate_dnp3_confirmations(
    records: &[Dnp3StreamingConfirmationRecord],
    sink: &mut dyn EventSink,
    max_checks: usize,
) -> Result<()> {
    let mut required = records.len();
    let mut groups: BTreeMap<Dnp3ConfirmationKey, Dnp3ConfirmationGroup> = BTreeMap::new();
    for record in records {
        if !matches!(record.witness.header.function, 0 | 0x81 | 0x82) {
            continue;
        }
        required = required
            .checked_add(1)
            .ok_or_else(|| Error::limit("dnp3_confirmation_checks"))?;
        let group = groups.entry(dnp3_confirmation_key(record)).or_default();
        if record.witness.header.function == 0 {
            group.confirms.push(record.clone());
        } else {
            group.responses.push(record.clone());
        }
    }
    for group in groups.values() {
        required = required
            .checked_add(
                group
                    .confirms
                    .len()
                    .checked_mul(group.responses.len())
                    .ok_or_else(|| Error::limit("dnp3_confirmation_checks"))?,
            )
            .and_then(|n| n.checked_add(group.responses.len()))
            .ok_or_else(|| Error::limit("dnp3_confirmation_checks"))?;
    }
    if required > max_checks {
        return Err(Error::limit("dnp3_confirmation_checks"));
    }

    for (_, group) in groups {
        if group.confirms.is_empty() {
            continue;
        }
        let mut eligible = Vec::new();
        let mut excluded = Vec::new();
        for response in &group.responses {
            let reason = if !response.witness.header.confirm_requested() {
                "target_does_not_request_confirmation"
            } else if response.ambiguous {
                "ambiguous_stream_context"
            } else if !response.boundary_verified {
                "unverified_stream_boundary"
            } else if !group.confirms.iter().any(|confirm| {
                confirm.direction != response.direction
                    && confirm.witness.link_direction != response.witness.link_direction
            }) {
                "direction_evidence_not_jointly_compatible"
            } else {
                ""
            };
            if reason.is_empty() {
                eligible.push(response.clone());
            } else {
                excluded.push((response.clone(), reason));
            }
        }
        let ambiguous_context = group.confirms.iter().any(|r| r.ambiguous)
            || group.responses.iter().any(|r| r.ambiguous);
        let boundary_ok = group.confirms.iter().all(|r| r.boundary_verified)
            && eligible.iter().all(|r| r.boundary_verified);
        let (status, reason) = if ambiguous_context {
            (EvidenceStatus::Ambiguous, "ambiguous_stream_context")
        } else if group.confirms.len() > 1 {
            (
                EvidenceStatus::Ambiguous,
                "duplicate_or_reused_confirmation_identifier",
            )
        } else if eligible.is_empty() {
            (
                EvidenceStatus::Incomplete,
                "no_verified_response_fragment_matches_all_confirmation_fields",
            )
        } else if !boundary_ok {
            (EvidenceStatus::Ambiguous, "unverified_stream_boundary")
        } else if eligible.len() > 1 || !excluded.is_empty() {
            (
                EvidenceStatus::Ambiguous,
                "duplicate_or_reused_response_identifier",
            )
        } else {
            (
                EvidenceStatus::Candidate,
                "unique_verified_stream_fragment_identifiers_not_receipt_or_causality",
            )
        };
        let mut related = group.confirms.iter().map(|r| r.event).collect::<Vec<_>>();
        related.extend(group.responses.iter().map(|r| r.event));
        let mut packets = Vec::new();
        for r in group.confirms.iter().chain(group.responses.iter()) {
            packets.extend(r.witness.packets.iter().copied());
        }
        packets.sort();
        packets.dedup();
        let mut e = Event::new(
            EventKind::Dnp3Confirmation,
            status,
            Json::object([
                ("projection", "dnp3_confirmation_candidate".into()),
                ("reason", reason.into()),
                (
                    "scope",
                    "one_analysis_window_one_stream_session_one_tcp_generation".into(),
                ),
                (
                    "confirms",
                    Json::array(group.confirms.iter().map(dnp3_participant_json)),
                ),
                (
                    "targets",
                    Json::array(eligible.iter().map(dnp3_participant_json)),
                ),
                (
                    "excluded_targets",
                    Json::array(excluded.iter().map(|(r, reason)| {
                        Json::object([
                            ("reason", (*reason).into()),
                            ("participant", dnp3_participant_json(r)),
                        ])
                    })),
                ),
                ("generic_transaction_untouched", true.into()),
                ("source_binding", "capture_complete_required".into()),
            ]),
        );
        e.session = group.confirms.first().map(|r| r.session);
        e.protocol = Some("dnp3".into());
        e.related_events = related;
        e.evidence = Evidence::packets(packets);
        sink.emit(&e)?;
    }
    Ok(())
}

pub struct Registry {
    plugins: Vec<Box<dyn AnalyzerPlugin>>,
    max: usize,
    correlator: Box<dyn TransactionCorrelator>,
}
impl Registry {
    pub fn new(max: usize) -> Result<Self> {
        if max == 0 || max > 64 {
            return Err(Error::limit("detectors"));
        }
        Ok(Self {
            plugins: Vec::new(),
            max,
            correlator: Box::new(IdentifierCorrelator),
        })
    }
    pub fn builtins(config: &StreamConfig) -> Result<Self> {
        let mut r = Self::new(config.max_detectors)?;
        for k in [
            Kind::Dnp3,
            Kind::Modbus,
            Kind::Dns,
            Kind::Http,
            Kind::Tls,
            Kind::Quic,
            Kind::Dhcp,
            Kind::Dhcpv6,
            Kind::Smb,
        ] {
            r.register(Box::new(Builtin(k)))?;
        }
        Ok(r)
    }
    pub fn register(&mut self, p: Box<dyn AnalyzerPlugin>) -> Result<()> {
        if self.plugins.len() >= self.max
            || p.protocol().is_empty()
            || self
                .plugins
                .iter()
                .any(|old| old.protocol() == p.protocol())
        {
            return Err(malformed(
                "registry",
                "duplicate/empty protocol name or registry full",
            ));
        }
        self.plugins.push(p);
        Ok(())
    }
    pub fn set_correlator(&mut self, c: Box<dyn TransactionCorrelator>) {
        self.correlator = c;
    }
    pub fn correlate(
        &self,
        records: &[MessageRecord],
        sink: &mut dyn EventSink,
        max: usize,
    ) -> Result<()> {
        self.correlator.correlate(records, sink, max)
    }
    pub fn names(&self) -> Vec<&'static str> {
        self.plugins.iter().map(|p| p.protocol()).collect()
    }
    fn selection(
        &self,
        ctx: &Context,
        bytes: &EvidenceBytes,
        c: &StreamConfig,
        sink: &mut dyn EventSink,
    ) -> Result<Vec<usize>> {
        let prefix = &bytes.data()[..bytes.len().min(c.max_probe_bytes)];
        let input = ProbeInput {
            transport: ctx.transport,
            source_port: ctx.source.port,
            destination_port: ctx.destination.port,
            prefix,
        };
        let mut selected = Vec::new();
        let mut observations = Vec::new();
        for (i, p) in self.plugins.iter().enumerate() {
            let result = p.detect(&input);
            let data = match result {
                ProbeResult::NoMatch => Json::object([
                    ("detector", p.protocol().into()),
                    ("result", "no_match".into()),
                ]),
                ProbeResult::NeedMore { minimum_total } => {
                    if minimum_total <= prefix.len() {
                        return Err(malformed("detector", "invalid NeedMore contract"));
                    }
                    Json::object([
                        ("detector", p.protocol().into()),
                        ("result", "need_more".into()),
                        ("minimum_total", minimum_total.into()),
                        (
                            "probe_budget_exceeded",
                            (minimum_total > c.max_probe_bytes).into(),
                        ),
                    ])
                }
                ProbeResult::Match {
                    protocol,
                    strength,
                    examined_bytes,
                    reason,
                } => {
                    if protocol != p.protocol()
                        || examined_bytes == 0
                        || examined_bytes > prefix.len()
                    {
                        return Err(malformed(
                            "detector",
                            "invalid successful extent or protocol identity",
                        ));
                    }
                    selected.push(i);
                    Json::object([
                        ("detector", protocol.into()),
                        ("result", "match".into()),
                        ("strength", format!("{strength:?}").into()),
                        ("examined_bytes", examined_bytes.into()),
                        ("reason", reason.into()),
                    ])
                }
            };
            observations.push(data);
        }
        let mut hinted = false;
        if selected.is_empty() && c.allow_port_hints {
            for (i, p) in self.plugins.iter().enumerate() {
                let ports = match p.protocol() {
                    "dnp3" => &c.base.dnp3_ports,
                    "modbus" => &c.base.modbus_ports,
                    _ => continue,
                };
                if ports.contains(&ctx.source.port) || ports.contains(&ctx.destination.port) {
                    selected.push(i);
                    hinted = true;
                }
            }
        }
        let status = if selected.len() > 1 {
            EvidenceStatus::Ambiguous
        } else if selected.is_empty() {
            EvidenceStatus::Unsupported
        } else {
            EvidenceStatus::Candidate
        };
        let mut e = Event::new(
            EventKind::Detection,
            status,
            Json::object([
                ("results", Json::Array(observations)),
                (
                    "selected",
                    Json::array(selected.iter().map(|i| self.plugins[*i].protocol().into())),
                ),
                ("configured_port_fallback", hinted.into()),
                ("every_match_retained", true.into()),
            ]),
        );
        e.session = Some(ctx.session);
        e.direction = Some(ctx.direction);
        e.evidence = Evidence::bytes(&bytes.slice(0..prefix.len())?);
        sink.emit(&e)?;
        Ok(selected)
    }
    pub fn stream(
        &self,
        ctx: &Context,
        stream: &StreamResult,
        c: &StreamConfig,
        output: &mut RegistryOutput<'_>,
    ) -> Result<()> {
        self.streams(&[(ctx.clone(), stream)], c, output)
    }

    /// Analyze reconstructed directions in original capture-record order.
    ///
    /// TCP reconstruction necessarily stores each direction independently, but
    /// stateful application protocols can depend on the observed ordering across
    /// both directions. Each contiguous reconstructed chunk remains an isolated
    /// analyzer unit (the pre-existing gap boundary), while source-span pieces
    /// are fed to those analyzers in packet-record order. This does not claim
    /// endpoint execution order; it preserves only the capture's observed order.
    pub fn streams(
        &self,
        inputs: &[(Context, &StreamResult)],
        c: &StreamConfig,
        output: &mut RegistryOutput<'_>,
    ) -> Result<()> {
        struct BufferedAnalysis {
            sink: BufferedSink,
            records: Vec<MessageRecord>,
            confirmations: Vec<Dnp3StreamingConfirmationRecord>,
            fallback_frame: u64,
            fallback_record_offset: u64,
        }
        struct ScheduledEvent {
            frame: u64,
            record_offset: u64,
            stream_offset: i64,
            direction: u8,
            analysis: usize,
            local_id: u64,
        }

        let run_id = output.sink.run_id().to_owned();
        let mut analyses = Vec::new();
        let mut buffered_bytes = 0usize;
        for (ctx, stream) in inputs {
            for chunk in &stream.chunks {
                let indices = self.selection(ctx, &chunk.bytes, c, output.sink)?;
                let mut context = ctx.clone();
                context.ambiguous = ctx.ambiguous || indices.len() > 1;
                // The runner has already evaluated the complete flow's gaps,
                // conflicts and SYN anchor. Preserve that verdict for every
                // event produced from this contiguous chunk.
                context.boundary_verified = ctx.boundary_verified;
                let fallback = chunk
                    .bytes
                    .packets()
                    .into_iter()
                    .max_by_key(|packet| (packet.frame, packet.record_offset));
                let mut analysis = BufferedAnalysis {
                    sink: BufferedSink {
                        run_id: run_id.clone(),
                        events: Vec::new(),
                        retained_bytes: 0,
                        byte_limit: c
                            .max_event_bytes
                            .checked_sub(buffered_bytes)
                            .ok_or_else(|| Error::limit("bidirectional_event_buffer"))?,
                        per_event_limit: c.max_event_bytes,
                    },
                    records: Vec::new(),
                    confirmations: Vec::new(),
                    fallback_frame: fallback.map_or(u64::MAX, |packet| packet.frame),
                    fallback_record_offset: fallback
                        .map_or(u64::MAX, |packet| packet.record_offset),
                };
                for index in indices {
                    let factory = &self.plugins[index];
                    let Some(mut analyzer) = factory.stream(AnalyzerLimits::from_config(c)) else {
                        continue;
                    };
                    let mut out = Output {
                        context: &context,
                        sink: &mut analysis.sink,
                        records: &mut analysis.records,
                        dnp3_confirmations: &mut analysis.confirmations,
                        remaining: output.remaining,
                        max_message_bytes: c.max_plugin_bytes,
                        sink_failed: false,
                    };
                    let result = analyzer
                        .push(
                            &StreamInput {
                                offset: chunk.offset,
                                bytes: &chunk.bytes,
                                boundary_verified: context.boundary_verified,
                            },
                            &mut out,
                        )
                        .and_then(|_| analyzer.finish(&mut out));
                    if let Err(error) = result {
                        if out.sink_failed {
                            return Err(error);
                        }
                        out.issue(factory.protocol(), error.to_string(), &chunk.bytes)?;
                    }
                    if analyzer.retained_bytes() > c.max_plugin_bytes {
                        return Err(Error::limit("plugin_retained_bytes"));
                    }
                }
                if !analysis.sink.events.is_empty() {
                    buffered_bytes = buffered_bytes
                        .checked_add(analysis.sink.retained_bytes)
                        .filter(|bytes| *bytes <= c.max_event_bytes)
                        .ok_or_else(|| Error::limit("bidirectional_event_buffer"))?;
                    analyses.push(analysis);
                }
            }
        }

        let mut scheduled = Vec::new();
        for (analysis_index, analysis) in analyses.iter().enumerate() {
            for (event_index, event) in analysis.sink.events.iter().enumerate() {
                let completion = event
                    .evidence
                    .packets
                    .iter()
                    .max_by_key(|packet| (packet.frame, packet.record_offset));
                scheduled.push(ScheduledEvent {
                    frame: completion.map_or(analysis.fallback_frame, |packet| packet.frame),
                    record_offset: completion.map_or(analysis.fallback_record_offset, |packet| {
                        packet.record_offset
                    }),
                    stream_offset: event.stream_range.map_or(i64::MAX, |range| range.0),
                    direction: event.direction.unwrap_or(u8::MAX),
                    analysis: analysis_index,
                    local_id: u64::try_from(event_index + 1)
                        .map_err(|_| Error::limit("buffered_plugin_events"))?,
                });
            }
        }
        scheduled.sort_by_key(|event| {
            (
                event.frame,
                event.record_offset,
                event.stream_offset,
                event.direction,
                event.analysis,
                event.local_id,
            )
        });
        let mut actual_ids = analyses
            .iter()
            .map(|analysis| vec![None; analysis.sink.events.len()])
            .collect::<Vec<_>>();
        for scheduled_event in scheduled {
            let index = usize::try_from(scheduled_event.local_id - 1)
                .map_err(|_| Error::limit("buffered_plugin_events"))?;
            let mut event = analyses[scheduled_event.analysis].sink.events[index].clone();
            for related in &mut event.related_events {
                let related_index = usize::try_from(
                    related
                        .checked_sub(1)
                        .ok_or_else(|| Error::limit("buffered_related_event"))?,
                )
                .map_err(|_| Error::limit("buffered_related_event"))?;
                *related = actual_ids[scheduled_event.analysis]
                    .get(related_index)
                    .and_then(|id| *id)
                    .ok_or_else(|| Error::limit("buffered_related_event_order"))?;
            }
            let actual = output.sink.emit(&event)?;
            actual_ids[scheduled_event.analysis][index] = Some(actual);
        }
        for (analysis_index, analysis) in analyses.into_iter().enumerate() {
            for mut record in analysis.records {
                record.event = remap_buffered_event(record.event, &actual_ids[analysis_index])?;
                output.records.push(record);
            }
            for mut confirmation in analysis.confirmations {
                confirmation.event =
                    remap_buffered_event(confirmation.event, &actual_ids[analysis_index])?;
                output.dnp3_confirmations.push(confirmation);
            }
        }
        Ok(())
    }
    pub fn datagram(
        &self,
        ctx: &Context,
        bytes: &EvidenceBytes,
        c: &StreamConfig,
        output: &mut RegistryOutput<'_>,
    ) -> Result<()> {
        let indices = self.selection(ctx, bytes, c, output.sink)?;
        let mut context = ctx.clone();
        context.ambiguous = ctx.ambiguous || indices.len() > 1;
        context.boundary_verified = true;
        for index in indices {
            let factory = &self.plugins[index];
            let Some(mut analyzer) = factory.datagram(AnalyzerLimits::from_config(c)) else {
                continue;
            };
            let mut out = Output {
                context: &context,
                sink: output.sink,
                records: output.records,
                dnp3_confirmations: output.dnp3_confirmations,
                remaining: output.remaining,
                max_message_bytes: c.max_plugin_bytes,
                sink_failed: false,
            };
            if let Err(e) = analyzer.analyze(&DatagramInput { bytes }, &mut out) {
                if out.sink_failed {
                    return Err(e);
                }
                out.issue(factory.protocol(), e.to_string(), bytes)?;
            }
            if analyzer.retained_bytes() > c.max_plugin_bytes {
                return Err(Error::limit("plugin_retained_bytes"));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum Kind {
    Dnp3,
    Modbus,
    Dns,
    Http,
    Tls,
    Quic,
    Dhcp,
    Dhcpv6,
    Smb,
}
struct Builtin(Kind);
impl Builtin {
    fn name(&self) -> &'static str {
        match self.0 {
            Kind::Dnp3 => "dnp3",
            Kind::Modbus => "modbus",
            Kind::Dns => "dns",
            Kind::Http => "http1",
            Kind::Tls => "tls",
            Kind::Quic => "quic",
            Kind::Dhcp => "dhcp",
            Kind::Dhcpv6 => "dhcpv6",
            Kind::Smb => "smb2",
        }
    }
}
fn matched(protocol: &'static str, examined_bytes: usize) -> ProbeResult {
    ProbeResult::Match {
        protocol,
        strength: ProbeStrength::HeaderStructure,
        examined_bytes,
        reason: "bounded_structural_candidate_not_authenticated_identity",
    }
}
impl ProtocolDetector for Builtin {
    fn protocol(&self) -> &'static str {
        self.name()
    }
    fn detect(&self, i: &ProbeInput<'_>) -> ProbeResult {
        let b = i.prefix;
        let tcp = i.transport == ProbeTransport::Tcp;
        match self.0 {
            Kind::Dnp3 => Dnp3Probe.probe(i),
            Kind::Modbus => ModbusProbe.probe(i),
            Kind::Dns => {
                let (body, n) = if tcp {
                    if b.len() < 2 {
                        return ProbeResult::NeedMore { minimum_total: 2 };
                    }
                    let n = usize::from(protocols::be16(b, 0));
                    if n < 12 {
                        return ProbeResult::NoMatch;
                    }
                    if b.len() < n + 2 {
                        return ProbeResult::NeedMore {
                            minimum_total: n + 2,
                        };
                    }
                    (&b[2..2 + n], n + 2)
                } else {
                    (b, b.len())
                };
                if body.len() < 12 {
                    return ProbeResult::NeedMore {
                        minimum_total: if tcp { 14 } else { 12 },
                    };
                }
                if body[3] & 0x40 != 0 || (body[2] & 0x78) > 0x30 {
                    return ProbeResult::NoMatch;
                }
                if protocols::dns(body).is_ok() {
                    matched("dns", n)
                } else {
                    ProbeResult::NoMatch
                }
            }
            Kind::Http => {
                if !tcp {
                    return ProbeResult::NoMatch;
                }
                if b.len() < 8 {
                    return ProbeResult::NeedMore { minimum_total: 8 };
                }
                if b.starts_with(b"HTTP/1.0 ")
                    || b.starts_with(b"HTTP/1.1 ")
                    || [
                        b"GET ".as_slice(),
                        b"POST ",
                        b"HEAD ",
                        b"PUT ",
                        b"DELETE ",
                        b"OPTIONS ",
                        b"CONNECT ",
                        b"TRACE ",
                        b"PATCH ",
                    ]
                    .iter()
                    .any(|p| b.starts_with(p))
                {
                    matched("http1", b.len().min(16))
                } else {
                    ProbeResult::NoMatch
                }
            }
            Kind::Tls => {
                if !tcp {
                    return ProbeResult::NoMatch;
                }
                if b.len() < 5 {
                    return ProbeResult::NeedMore { minimum_total: 5 };
                }
                let n = protocols::be16(b, 3);
                if (20..=24).contains(&b[0]) && b[1] == 3 && b[2] <= 4 && n <= 18432 {
                    matched("tls", 5)
                } else {
                    ProbeResult::NoMatch
                }
            }
            Kind::Quic => {
                if !tcp && protocols::quic(b).is_ok() {
                    matched("quic", b.len().min(47))
                } else {
                    ProbeResult::NoMatch
                }
            }
            Kind::Dhcp => {
                if !tcp && b.len() >= 240 && protocols::dhcp(b).is_ok() {
                    matched("dhcp", b.len())
                } else {
                    ProbeResult::NoMatch
                }
            }
            Kind::Dhcpv6 => {
                // Require at least one option. Small type/transaction fields alone
                // are far too weak a discriminator for arbitrary UDP payloads.
                if !tcp && b.len() >= 8 && protocols::dhcpv6(b).is_ok() {
                    matched("dhcpv6", b.len())
                } else {
                    ProbeResult::NoMatch
                }
            }
            Kind::Smb => {
                if !tcp || b.len() < 8 || b[0] != 0 {
                    return ProbeResult::NoMatch;
                }
                if [0xfe, 0xfd, 0xfc].contains(&b[4]) && b[5..8] == *b"SMB" {
                    matched("smb2", 8)
                } else {
                    ProbeResult::NoMatch
                }
            }
        }
    }
}
impl AnalyzerPlugin for Builtin {
    fn stream(&self, limits: AnalyzerLimits) -> Option<Box<dyn StreamAnalyzer>> {
        match self.0 {
            Kind::Dnp3 | Kind::Modbus | Kind::Dns | Kind::Http | Kind::Tls | Kind::Smb => {
                Some(Box::new(Framer {
                    kind: self.0,
                    buffer: EvidenceBytes::default(),
                    offset: 0,
                    boundary: false,
                    limits,
                    work: 0,
                    http_done: false,
                    handshake: EvidenceBytes::default(),
                }))
            }
            _ => None,
        }
    }
    fn datagram(&self, limits: AnalyzerLimits) -> Option<Box<dyn DatagramAnalyzer>> {
        match self.0 {
            Kind::Dnp3 | Kind::Dns | Kind::Quic | Kind::Dhcp | Kind::Dhcpv6 => {
                Some(Box::new(UdpBuiltin {
                    kind: self.0,
                    limits,
                }))
            }
            _ => None,
        }
    }
}
struct UdpBuiltin {
    kind: Kind,
    limits: AnalyzerLimits,
}
impl DatagramAnalyzer for UdpBuiltin {
    fn analyze(&mut self, input: &DatagramInput<'_>, out: &mut Output<'_>) -> Result<()> {
        let b = input.bytes;
        if b.len() > self.limits.max_buffer_bytes {
            return Err(Error::limit("datagram_analyzer"));
        }
        match self.kind {
            Kind::Dnp3 => decode_dnp(b, 0, false, out, &self.limits),
            Kind::Dns => emit_dns(b, None, out),
            Kind::Quic => {
                out.message("quic", b, None, protocols::quic(b.data())?, None, true)?;
                Ok(())
            }
            Kind::Dhcp => {
                out.message("dhcp", b, None, protocols::dhcp(b.data())?, None, true)?;
                Ok(())
            }
            Kind::Dhcpv6 => {
                out.message("dhcpv6", b, None, protocols::dhcpv6(b.data())?, None, true)?;
                Ok(())
            }
            _ => Err(malformed("datagram_analyzer", "unsupported transport")),
        }
    }
    fn retained_bytes(&self) -> usize {
        0
    }
}
fn emit_dns(raw: &EvidenceBytes, range: Option<(i64, i64)>, out: &mut Output<'_>) -> Result<()> {
    let d = protocols::dns(raw.data())?;
    let hint = if d.truncated || d.questions.is_empty() {
        None
    } else {
        Some(CorrelationHint {
            key: protocols::dns_key(&d),
            role: if d.response {
                Role::Response
            } else {
                Role::Request
            },
            compatibility: String::new(),
        })
    };
    out.message("dns", raw, range, d.metadata, hint, !d.truncated)?;
    Ok(())
}
struct Framer {
    kind: Kind,
    buffer: EvidenceBytes,
    offset: i64,
    boundary: bool,
    limits: AnalyzerLimits,
    work: usize,
    http_done: bool,
    handshake: EvidenceBytes,
}
impl Framer {
    fn charge(&mut self, n: usize) -> Result<()> {
        self.work = self
            .work
            .checked_add(n)
            .ok_or_else(|| Error::limit("analyzer_work"))?;
        if self.work > self.limits.max_work_bytes {
            return Err(Error::limit("analyzer_work"));
        }
        Ok(())
    }
    fn parse(&mut self, out: &mut Output<'_>) -> Result<()> {
        if matches!(self.kind, Kind::Dnp3) {
            return Ok(());
        }
        if matches!(self.kind, Kind::Http) {
            if self.http_done {
                self.buffer = EvidenceBytes::default();
                return Ok(());
            }
            if !self.buffer.data().windows(4).any(|w| w == b"\r\n\r\n") {
                return Ok(());
            }
            let (metadata, n) = protocols::http_header(self.buffer.data())?;
            let raw = self.buffer.slice(0..n)?;
            let ambiguous = match &metadata {
                Json::Object(fields) => fields
                    .iter()
                    .any(|(key, value)| *key == "framing_ambiguous" && *value == Json::Bool(true)),
                _ => false,
            };
            if ambiguous {
                out.issue("http1", "ambiguous_http_message_framing", &raw)?;
            }
            out.message(
                "http1",
                &raw,
                Some((self.offset, self.offset + n as i64)),
                metadata,
                None,
                !ambiguous,
            )?;
            // Deliberately do not mistake opaque/chunked body bytes for requests.
            self.http_done = true;
            self.buffer = EvidenceBytes::default();
            return Ok(());
        }
        let mut p = 0usize;
        while p < self.buffer.len() {
            let b = &self.buffer.data()[p..];
            let (header, n): (usize, usize) = match self.kind {
                Kind::Dns => {
                    if b.len() < 2 {
                        break;
                    }
                    let n = usize::from(protocols::be16(b, 0));
                    if n < 12 {
                        return Err(malformed("dns_tcp", "short message length"));
                    }
                    (2, n)
                }
                Kind::Modbus => {
                    if b.len() < 6 {
                        break;
                    }
                    let n = usize::from(protocols::be16(b, 4));
                    if protocols::be16(b, 2) != 0 || !(2..=254).contains(&n) {
                        return Err(malformed("modbus", "invalid MBAP framing"));
                    }
                    (0, 6 + n)
                }
                Kind::Tls => {
                    if b.len() < 5 {
                        break;
                    }
                    let n = usize::from(protocols::be16(b, 3));
                    if !(20..=24).contains(&b[0]) || b[1] != 3 || b[2] > 4 || n > 18432 {
                        return Err(malformed("tls", "invalid record header"));
                    }
                    (0, 5 + n)
                }
                Kind::Smb => {
                    if b.len() < 4 {
                        break;
                    }
                    if b[0] != 0 {
                        return Err(malformed("smb", "non-session-message NBSS type"));
                    }
                    let n =
                        (usize::from(b[1]) << 16) | (usize::from(b[2]) << 8) | usize::from(b[3]);
                    (4, n)
                }
                _ => return Err(malformed("framer", "invalid kind")),
            };
            let total = header
                .checked_add(n)
                .ok_or_else(|| Error::limit("frame_length"))?;
            if total > self.limits.max_buffer_bytes {
                return Err(Error::limit("application_frame"));
            }
            if b.len() < total {
                break;
            }
            let raw = self.buffer.slice(p + header..p + total)?;
            let at = self
                .offset
                .checked_add((p + header) as i64)
                .ok_or_else(|| Error::limit("stream_offset"))?;
            let range = Some((at, at + raw.len() as i64));
            match self.kind {
                Kind::Dns => emit_dns(&raw, range, out)?,
                Kind::Modbus => emit_modbus(&raw, at, self.boundary, out, &self.limits)?,
                Kind::Smb => {
                    out.message(
                        "smb2",
                        &raw,
                        range,
                        protocols::smb2(raw.data())?,
                        None,
                        true,
                    )?;
                }
                Kind::Tls => {
                    let bytes = raw.data();
                    out.message(
                        "tls",
                        &raw,
                        range,
                        Json::object([
                            ("record_type", bytes[0].into()),
                            ("legacy_record_version", protocols::be16(bytes, 1).into()),
                            ("record_length", protocols::be16(bytes, 3).into()),
                            ("decrypted", false.into()),
                        ]),
                        None,
                        true,
                    )?;
                    if bytes[0] == 22 {
                        self.handshake
                            .append(&raw.slice(5..raw.len())?, self.limits.max_buffer_bytes)?;
                        let mut used = 0;
                        while self.handshake.len() - used >= 4 {
                            let h = &self.handshake.data()[used..];
                            let length = (usize::from(h[1]) << 16)
                                | (usize::from(h[2]) << 8)
                                | usize::from(h[3]);
                            if length + 4 > self.limits.max_buffer_bytes {
                                return Err(Error::limit("tls_handshake"));
                            }
                            if h.len() < length + 4 {
                                break;
                            }
                            if h[0] == 1 {
                                let hello = self.handshake.slice(used..used + length + 4)?;
                                out.message(
                                    "tls",
                                    &hello,
                                    None,
                                    protocols::tls_client_hello(&hello.data()[4..])?,
                                    None,
                                    true,
                                )?;
                            }
                            used += length + 4;
                        }
                        if used > 0 {
                            self.handshake = self.handshake.slice(used..self.handshake.len())?;
                        }
                    } else if !self.handshake.is_empty() {
                        out.issue(
                            "tls",
                            "non_handshake_record_interrupts_incomplete_handshake",
                            &self.handshake,
                        )?;
                        self.handshake = EvidenceBytes::default();
                    }
                }
                _ => {}
            }
            p += total;
        }
        if p > 0 {
            self.buffer = self.buffer.slice(p..self.buffer.len())?;
            self.offset = self
                .offset
                .checked_add(p as i64)
                .ok_or_else(|| Error::limit("stream_offset"))?;
        }
        Ok(())
    }
}
impl StreamAnalyzer for Framer {
    fn push(&mut self, input: &StreamInput<'_>, out: &mut Output<'_>) -> Result<()> {
        let extent =
            i64::try_from(input.bytes.len()).map_err(|_| Error::limit("plugin_stream_offset"))?;
        if input.offset.checked_add(extent).is_none() {
            return Err(Error::limit("plugin_stream_offset"));
        }
        self.charge(input.bytes.len())?;
        if self.http_done {
            return Ok(());
        }
        if self.buffer.is_empty() {
            self.offset = input.offset;
            self.boundary = input.boundary_verified;
        } else if self.offset.checked_add(self.buffer.len() as i64) != Some(input.offset) {
            self.gap("noncontiguous_plugin_input", out)?;
            self.offset = input.offset;
            self.boundary = false;
        }
        self.buffer
            .append(input.bytes, self.limits.max_buffer_bytes)?;
        self.charge(self.buffer.len())?;
        self.parse(out)
    }
    fn gap(&mut self, reason: &str, out: &mut Output<'_>) -> Result<()> {
        self.finish(out)?;
        self.http_done = false;
        self.boundary = false;
        out.issue(Builtin(self.kind).name(), reason, &EvidenceBytes::default())
    }
    fn finish(&mut self, out: &mut Output<'_>) -> Result<()> {
        if matches!(self.kind, Kind::Dnp3) && !self.buffer.is_empty() {
            decode_dnp(&self.buffer, self.offset, self.boundary, out, &self.limits)?;
            self.buffer = EvidenceBytes::default();
        } else if !self.buffer.is_empty() {
            out.issue(
                Builtin(self.kind).name(),
                "incomplete_application_at_gap_or_window_end",
                &self.buffer,
            )?;
            self.buffer = EvidenceBytes::default();
        }
        if !self.handshake.is_empty() {
            out.issue(
                "tls",
                "incomplete_handshake_at_gap_or_window_end",
                &self.handshake,
            )?;
            self.handshake = EvidenceBytes::default();
        }
        Ok(())
    }
    fn retained_bytes(&self) -> usize {
        self.buffer.len() + self.handshake.len()
    }
}
fn native_limits(l: &AnalyzerLimits) -> Limits {
    Limits {
        max_application_bytes: l.max_buffer_bytes,
        max_protocol_messages: l.max_messages,
        ..Limits::default()
    }
}
fn one_stream(raw: &EvidenceBytes, at: i64, boundary: bool) -> StreamResult {
    StreamResult {
        base_sequence: None,
        anchored_by_syn: boundary,
        chunks: vec![StreamChunk {
            offset: at,
            bytes: raw.clone(),
        }],
        gaps: vec![],
        conflicts: vec![],
        duplicate_observed_bytes: 0,
    }
}
fn decode_dnp(
    raw: &EvidenceBytes,
    at: i64,
    boundary: bool,
    out: &mut Output<'_>,
    l: &AnalyzerLimits,
) -> Result<()> {
    dnp_workflow::decode(raw, at, boundary, out, l)
}
fn emit_modbus(
    raw: &EvidenceBytes,
    at: i64,
    boundary: bool,
    out: &mut Output<'_>,
    l: &AnalyzerLimits,
) -> Result<()> {
    let stream = one_stream(raw, at, boundary);
    let limits = native_limits(l);
    let request = modbus::decode(&stream, modbus::Role::Request, &limits)?;
    let response = modbus::decode(&stream, modbus::Role::Response, &limits)?;
    let a = request
        .messages
        .first()
        .ok_or_else(|| malformed("modbus", "no framed request interpretation"))?;
    let b = response
        .messages
        .first()
        .ok_or_else(|| malformed("modbus", "no framed response interpretation"))?;
    let source_server = out.context.modbus_ports.contains(&out.context.source.port);
    let destination_server = out
        .context
        .modbus_ports
        .contains(&out.context.destination.port);
    let configured = source_server != destination_server;
    let role = if configured {
        if source_server {
            Role::Response
        } else {
            Role::Request
        }
    } else {
        match (a.shape_valid, b.shape_valid) {
            (true, false) => Role::Request,
            (false, true) => Role::Response,
            _ => Role::Unknown,
        }
    };
    let chosen = if role == Role::Response { b } else { a };
    let valid = match role {
        Role::Request => a.shape_valid,
        Role::Response => b.shape_valid,
        Role::Unknown => a.shape_valid || b.shape_valid,
    };
    let bytes = raw.data();
    let compatibility = match (chosen.function & 0x7f, role) {
        (1 | 2, Role::Request) if bytes.len() == 12 => {
            format!("modbus-bits-v1:quantity:{}", protocols::be16(bytes, 10))
        }
        (3 | 4, Role::Request) if bytes.len() == 12 => {
            format!("count:{}", 2 * usize::from(protocols::be16(bytes, 10)))
        }
        (1 | 2, Role::Response) if bytes.len() >= 10 && chosen.function & 0x80 == 0 => {
            format!(
                "modbus-bits-v1:response:{}:{}",
                bytes[8],
                bytes[bytes.len() - 1]
            )
        }
        (3 | 4, Role::Response) if bytes.len() >= 9 && chosen.function & 0x80 == 0 => {
            format!("count:{}", bytes[8])
        }
        (5 | 6 | 15 | 16, _) if bytes.len() >= 12 && chosen.function & 0x80 == 0 => {
            format!("echo:{}", pcap_evidence::sha256::hex(&bytes[8..12]))
        }
        _ => String::new(),
    };
    let hint = if valid && chosen.semantics_supported && role != Role::Unknown {
        Some(CorrelationHint {
            key: format!(
                "{}:{}:{}",
                chosen.transaction,
                chosen.unit,
                chosen.function & 0x7f
            ),
            role,
            compatibility,
        })
    } else {
        None
    };
    out.message(
        "modbus",
        raw,
        Some((at, at + raw.len() as i64)),
        Json::object([
            ("transaction_id", chosen.transaction.into()),
            ("unit", chosen.unit.into()),
            ("function", chosen.function.into()),
            ("role", format!("{role:?}").to_ascii_lowercase().into()),
            ("role_from_configuration", configured.into()),
            ("request_shape_valid", a.shape_valid.into()),
            ("response_shape_valid", b.shape_valid.into()),
            ("semantics_supported", chosen.semantics_supported.into()),
            ("boundary_verified", boundary.into()),
            (
                "semantic_subset",
                pcap_evidence::semantics::modbus::alternatives_json(
                    raw,
                    match role {
                        Role::Request => modbus::Role::Request,
                        Role::Response => modbus::Role::Response,
                        Role::Unknown => modbus::Role::Unknown,
                    },
                    pcap_evidence::semantics::Limits::from_capture(&native_limits(l)),
                ),
            ),
        ]),
        hint,
        valid,
    )?;
    Ok(())
}
