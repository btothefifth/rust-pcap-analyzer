//! Streaming input with bounded active tuple windows. A window is NOT a new TCP
//! connection claim. Eviction, budget rollover, ambiguity and incomplete state
//! are emitted; the engine never silently stitches across discarded history.
use crate::{
    config::StreamConfig,
    events::{Event, EventKind, EventSink, Evidence, EvidenceStatus},
    network::{self, Decoded},
    plugin::{Context, Dnp3StreamingConfirmationRecord, MessageRecord, Registry, RegistryOutput},
    Error, Result,
};
use pcap_evidence::{
    capture::{CaptureReader, PacketMeta, RecordKind},
    fragment::{FragmentNotice, FragmentOutcome, FragmentReassembler},
    json::Json,
    protocol::ProbeTransport,
    provenance::{EvidenceBytes, PacketId},
    sha256::{self, Sha256},
    tcp::{Assignment, FlowResult, TcpTracker},
    wire::{self, Checksum, ChecksumPolicy, Endpoint, Scope, Transport},
};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;

#[derive(Clone, Debug, Default)]
pub struct Summary {
    pub source_bytes: u64,
    pub source_sha256: [u8; 32],
    pub records: u64,
    pub packets: u64,
    pub events: u64,
    pub degraded_events: u64,
    pub windows: u64,
    pub peak_active_keys: usize,
    pub peak_retained_tcp_payload: usize,
}
struct HashReader<R> {
    inner: R,
    hash: Sha256,
    bytes: u64,
    max: u64,
}
impl<R: Read> Read for HashReader<R> {
    fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(b)?;
        self.bytes = self
            .bytes
            .checked_add(n as u64)
            .ok_or_else(|| std::io::Error::other("source byte counter overflow"))?;
        self.hash.update(&b[..n]);
        if self.bytes > self.max {
            return Err(std::io::Error::other("source byte limit exceeded"));
        }
        Ok(n)
    }
}
struct Meter<'a> {
    inner: &'a mut dyn EventSink,
    events: u64,
    degraded: u64,
}
impl EventSink for Meter<'_> {
    fn run_id(&self) -> &str {
        self.inner.run_id()
    }
    fn emit(&mut self, e: &Event) -> Result<u64> {
        let id = self.inner.emit(e)?;
        self.events = self
            .events
            .checked_add(1)
            .ok_or_else(|| Error::limit("events"))?;
        if matches!(
            e.status,
            EvidenceStatus::Ambiguous
                | EvidenceStatus::Incomplete
                | EvidenceStatus::Rejected
                | EvidenceStatus::Unsupported
        ) {
            self.degraded = self
                .degraded
                .checked_add(1)
                .ok_or_else(|| Error::limit("diagnostics"))?;
        }
        Ok(id)
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct Key {
    scope: Scope,
    path: Vec<String>,
    transport: u8,
    a: Endpoint,
    b: Endpoint,
}
impl Key {
    fn new(
        scope: Scope,
        path: Vec<String>,
        transport: u8,
        src: Endpoint,
        dst: Endpoint,
    ) -> (Self, u8) {
        let (a, b, d) = if src <= dst {
            (src, dst, 0)
        } else {
            (dst, src, 1)
        };
        (
            Self {
                scope,
                path,
                transport,
                a,
                b,
            },
            d,
        )
    }
    fn json(&self) -> Json {
        Json::object([
            ("source_ip", self.a.address.to_string().into()),
            ("source_port", self.a.port.into()),
            ("destination_ip", self.b.address.to_string().into()),
            ("destination_port", self.b.port.into()),
            (
                "transport",
                if self.transport == 6 { "tcp" } else { "udp" }.into(),
            ),
            ("section", self.scope.section.into()),
            ("interface", self.scope.interface.into()),
            (
                "vlans",
                Json::array(self.scope.vlans.iter().copied().map(Json::from)),
            ),
            (
                "tunnel_path",
                Json::array(self.path.iter().cloned().map(Json::from)),
            ),
        ])
    }
}
struct Active {
    key: Key,
    window: u64,
    tracker: Option<TcpTracker>,
    flow_ids: BTreeMap<usize, u64>,
    udp_id: Option<u64>,
    payload: usize,
    packet_refs: usize,
    last_frame: u64,
    last_ns: Option<i128>,
    messages: Vec<MessageRecord>,
    dnp3_confirmations: Vec<Dnp3StreamingConfirmationRecord>,
    remaining: usize,
}
struct FragSlot {
    reassembler: FragmentReassembler,
    last_frame: u64,
}
struct LayerContext<'a> {
    path: Vec<String>,
    depth: usize,
    frame: u64,
    time: Option<i128>,
    raw: &'a EvidenceBytes,
    id: PacketId,
}
struct State<'a> {
    c: &'a StreamConfig,
    registry: &'a Registry,
    sink: &'a mut dyn EventSink,
    namespace: [u8; 32],
    active: BTreeMap<Key, Active>,
    order: BTreeSet<(u64, Key)>,
    fragments: BTreeMap<Vec<String>, FragSlot>,
    retained: usize,
    next_session: u64,
    next_window: u64,
    summary: Summary,
}
impl State<'_> {
    fn session(&mut self) -> Result<u64> {
        self.next_session = self
            .next_session
            .checked_add(1)
            .ok_or_else(|| Error::limit("session_id"))?;
        Ok(self.next_session)
    }
    fn create(&mut self, key: Key, frame: u64, time: Option<i128>) -> Result<Active> {
        self.next_window = self
            .next_window
            .checked_add(1)
            .ok_or_else(|| Error::limit("window_id"))?;
        self.summary.windows += 1;
        let tracker = if key.transport == 6 {
            Some(TcpTracker::new(
                self.c.tracker_limits(),
                self.c.base.idle_timeout_ns,
            )?)
        } else {
            None
        };
        let udp_id = if key.transport == 17 {
            Some(self.session()?)
        } else {
            None
        };
        let active = Active {
            key,
            window: self.next_window,
            tracker,
            flow_ids: BTreeMap::new(),
            udp_id,
            payload: 0,
            packet_refs: 0,
            last_frame: frame,
            last_ns: time,
            messages: Vec::new(),
            dnp3_confirmations: Vec::new(),
            remaining: self.c.max_plugin_events,
        };
        if let Some(id) = udp_id {
            self.start_flow(&active, id, "udp_analysis_window")?;
        }
        Ok(active)
    }
    fn start_flow(&mut self, a: &Active, id: u64, basis: &'static str) -> Result<()> {
        let mut e = Event::new(
            EventKind::FlowStart,
            EvidenceStatus::Candidate,
            Json::object([
                ("key", a.key.json()),
                ("window_id", a.window.to_string().into()),
                ("identity_basis", basis.into()),
                ("new_physical_connection_claimed", false.into()),
                ("cross_window_history_retained", false.into()),
            ]),
        );
        e.session = Some(id);
        self.sink.emit(&e)?;
        Ok(())
    }
    fn take(&mut self, key: &Key) -> Option<Active> {
        let a = self.active.remove(key)?;
        self.order.remove(&(a.last_frame, key.clone()));
        self.retained -= a.payload;
        Some(a)
    }
    fn put(&mut self, a: Active) -> Result<()> {
        self.retained = self
            .retained
            .checked_add(a.payload)
            .ok_or_else(|| Error::limit("active_payload"))?;
        if self.retained > self.c.max_active_payload || self.active.len() >= self.c.max_active_keys
        {
            return Err(Error::limit("active_state"));
        }
        self.order.insert((a.last_frame, a.key.clone()));
        self.active.insert(a.key.clone(), a);
        self.summary.peak_active_keys = self.summary.peak_active_keys.max(self.active.len());
        self.summary.peak_retained_tcp_payload =
            self.summary.peak_retained_tcp_payload.max(self.retained);
        Ok(())
    }
    fn evict_oldest(&mut self, reason: &'static str) -> Result<bool> {
        let Some((_, key)) = self.order.first().cloned() else {
            return Ok(false);
        };
        let a = self
            .take(&key)
            .ok_or_else(|| Error::limit("active_order_invariant"))?;
        self.flush(a, reason)?;
        Ok(true)
    }
    fn room(&mut self, bytes: usize) -> Result<()> {
        while self.active.len() >= self.c.max_active_keys
            || self
                .retained
                .checked_add(bytes)
                .is_none_or(|n| n > self.c.max_active_payload)
        {
            if !self.evict_oldest("active_state_budget")? {
                return Err(Error::limit("active_payload"));
            }
        }
        Ok(())
    }
    fn expire(&mut self, frame: u64) -> Result<()> {
        loop {
            let expired = self
                .order
                .first()
                .is_some_and(|(last, _)| frame.saturating_sub(*last) > self.c.idle_frames);
            if !expired {
                break;
            }
            self.evict_oldest("idle_frame_boundary")?;
        }
        let keys: Vec<_> = self.fragments.keys().cloned().collect();
        for key in keys {
            let notices = self
                .fragments
                .get_mut(&key)
                .ok_or_else(|| Error::limit("fragment_context"))?
                .reassembler
                .expire(frame);
            for n in notices {
                self.fragment_notice(n)?;
            }
        }
        Ok(())
    }
    fn fragment_notice(&mut self, n: FragmentNotice) -> Result<()> {
        let mut e = Event::new(
            EventKind::Diagnostic,
            EvidenceStatus::Incomplete,
            Json::object([("reason", n.code.into()), ("layer", "ip_fragments".into())]),
        );
        e.evidence = Evidence::packets(n.packets);
        self.sink.emit(&e)?;
        Ok(())
    }
    fn diagnostic(
        &mut self,
        reason: impl Into<String>,
        packets: Vec<PacketId>,
        status: EvidenceStatus,
    ) -> Result<()> {
        let reason: String = reason.into();
        let mut e = Event::new(
            EventKind::Diagnostic,
            status,
            Json::object([("reason", reason.into())]),
        );
        e.evidence = Evidence::packets(packets);
        self.sink.emit(&e)?;
        Ok(())
    }
    fn reassemble(
        &mut self,
        d: wire::Datagram,
        path: &[String],
        frame: u64,
    ) -> Result<Option<(wire::Datagram, Vec<PacketId>)>> {
        if !self.fragments.contains_key(path) {
            if self.fragments.len() >= self.c.max_tunnel_contexts {
                let oldest = self
                    .fragments
                    .iter()
                    .min_by_key(|(_, s)| s.last_frame)
                    .map(|(k, _)| k.clone())
                    .ok_or_else(|| Error::limit("fragment_context"))?;
                let slot = self
                    .fragments
                    .remove(&oldest)
                    .ok_or_else(|| Error::limit("fragment_context"))?;
                for n in slot.reassembler.finish() {
                    self.fragment_notice(n)?;
                }
                self.diagnostic(
                    "fragment_context_evicted",
                    vec![],
                    EvidenceStatus::Incomplete,
                )?;
            }
            self.fragments.insert(
                path.to_vec(),
                FragSlot {
                    reassembler: FragmentReassembler::new(self.c.fragment_limits()),
                    last_frame: frame,
                },
            );
        }
        let contributors = d.payload.packets();
        let result = {
            let slot = self
                .fragments
                .get_mut(path)
                .ok_or_else(|| Error::limit("fragment_context"))?;
            slot.last_frame = frame;
            slot.reassembler.push(d, frame)
        };
        match result {
            Ok(FragmentOutcome::Pending) => Ok(None),
            Ok(FragmentOutcome::Complete(d, ids)) => Ok(Some((d, ids))),
            Ok(FragmentOutcome::Rejected(n)) => {
                self.fragment_notice(n)?;
                Ok(None)
            }
            Err(error) => {
                // Never silently discard a contradictory fragment and continue
                // the same reconstruction as though it had never been observed.
                let slot = self
                    .fragments
                    .remove(path)
                    .ok_or_else(|| Error::limit("fragment_context"))?;
                for n in slot.reassembler.finish() {
                    self.fragment_notice(n)?;
                }
                self.diagnostic(
                    format!("fragment_context_reset:{error}"),
                    contributors,
                    EvidenceStatus::Incomplete,
                )?;
                Ok(None)
            }
        }
    }
    fn packet(
        &mut self,
        meta: &PacketMeta,
        data: &[u8],
        record_offset: u64,
        warnings: Vec<String>,
    ) -> Result<()> {
        self.expire(meta.frame)?;
        let id = PacketId {
            capture: self.namespace,
            frame: meta.frame,
            record_offset,
        };
        let timestamp = meta.timestamp;
        let exact = timestamp.and_then(|t| t.unix_nanos().ok());
        let raw_time = timestamp.map_or(Json::Null, |t| {
            Json::object([
                ("ticks", t.ticks.to_string().into()),
                (
                    "resolution_code",
                    t.resolution.to_pcapng().map_or(Json::Null, Json::from),
                ),
                ("offset_seconds", t.offset_seconds.to_string().into()),
            ])
        });
        let data_offset = record_offset
            .checked_add(meta.data_offset as u64)
            .ok_or_else(|| Error::limit("packet_offset"))?;
        let mut p = Event::new(
            EventKind::Packet,
            EvidenceStatus::Observed,
            Json::object([
                ("frame", meta.frame.to_string().into()),
                ("record_offset", record_offset.to_string().into()),
                ("data_offset", data_offset.to_string().into()),
                ("captured_length", meta.captured_len.into()),
                ("original_length", meta.original_len.into()),
                ("link_type", meta.link_type.into()),
                ("section", meta.section.into()),
                ("interface", meta.interface.into()),
                (
                    "timestamp_ns",
                    exact.map_or(Json::Null, |n| n.to_string().into()),
                ),
                ("raw_timestamp", raw_time),
                ("packet_sha256", sha256::hex(&sha256::digest(data)).into()),
                (
                    "warnings",
                    Json::array(warnings.into_iter().map(Json::from)),
                ),
                (
                    "snaplen_truncated",
                    (meta.captured_len < meta.original_len).into(),
                ),
            ]),
        );
        p.evidence = Evidence::packets(vec![id]);
        self.sink.emit(&p)?;
        if timestamp.is_none() || exact.is_none() {
            self.diagnostic(
                "timestamp_absent_or_not_exact_nanoseconds",
                vec![id],
                EvidenceStatus::Incomplete,
            )?;
        }
        if meta.captured_len < meta.original_len {
            self.diagnostic(
                "snaplen_truncated_packet",
                vec![id],
                EvidenceStatus::Incomplete,
            )?;
        }
        let raw = EvidenceBytes::from_packet(data, id, 0);
        let scope = Scope {
            section: meta.section,
            interface: meta.interface,
            vlans: vec![],
        };
        let decoded = match network::decode(meta.link_type, &raw, scope) {
            Ok(d) => d,
            Err(e) => {
                self.diagnostic(e.to_string(), vec![id], EvidenceStatus::Unsupported)?;
                return Ok(());
            }
        };
        self.layers(
            decoded,
            LayerContext {
                path: vec![],
                depth: 0,
                frame: meta.frame,
                time: exact,
                raw: &raw,
                id,
            },
        )
    }
    fn layers(&mut self, decoded: Decoded, context: LayerContext<'_>) -> Result<()> {
        let LayerContext {
            mut path,
            depth,
            frame,
            time,
            raw,
            id,
        } = context;
        let (d, extra) = match decoded {
            Decoded::Metadata {
                protocol,
                data,
                supported,
            } => {
                let mut e = Event::new(
                    EventKind::Network,
                    if supported {
                        EvidenceStatus::Observed
                    } else {
                        EvidenceStatus::Unsupported
                    },
                    data,
                );
                e.protocol = Some(protocol.into());
                e.evidence = Evidence::bytes(raw);
                self.sink.emit(&e)?;
                return Ok(());
            }
            Decoded::Ip(d, p) => (d, p),
        };
        path.extend(extra);
        if d.ip_checksum == Checksum::Invalid {
            self.diagnostic(
                "invalid_ipv4_checksum_observed",
                vec![id],
                EvidenceStatus::Incomplete,
            )?;
            if self.c.base.checksum_policy == ChecksumPolicy::RequireValid {
                return Ok(());
            }
        }
        let fragmented = d.fragment.is_some();
        let Some((datagram, mut contributors)) = self.reassemble(d, &path, frame)? else {
            return Ok(());
        };
        if contributors.is_empty() {
            contributors.push(id);
        }
        let datagram = match network::normalize(datagram) {
            Ok(d) => d,
            Err(e) => {
                self.diagnostic(e.to_string(), contributors, EvidenceStatus::Unsupported)?;
                return Ok(());
            }
        };
        if fragmented {
            let mut e = Event::new(
                EventKind::Reassembled,
                EvidenceStatus::Candidate,
                Json::object([
                    ("ip_protocol", datagram.protocol.into()),
                    (
                        "tunnel_path",
                        Json::array(path.iter().cloned().map(Json::from)),
                    ),
                ]),
            );
            e.evidence = Evidence::bytes(&datagram.payload);
            e.evidence.packets = contributors.clone();
            self.sink.emit(&e)?;
        }
        // Outer UDP checksums must be evaluated before tunnel decapsulation.
        if datagram.protocol == 17 {
            match wire::decode_transport(&datagram, self.c.base.checksum_policy) {
                Ok(Transport::Udp(u)) if u.checksum == Checksum::Invalid => self.diagnostic(
                    "invalid_outer_udp_checksum_observed",
                    contributors.clone(),
                    EvidenceStatus::Incomplete,
                )?,
                Err(e) => {
                    self.diagnostic(e.to_string(), contributors, EvidenceStatus::Rejected)?;
                    return Ok(());
                }
                _ => {}
            }
        }
        match network::peel(&datagram) {
            Ok(Some((inner, hop))) => {
                if depth >= self.c.max_tunnel_depth {
                    self.diagnostic(
                        "tunnel_depth_limit",
                        contributors,
                        EvidenceStatus::Unsupported,
                    )?;
                    return Ok(());
                }
                let mut e = Event::new(
                    EventKind::Network,
                    EvidenceStatus::Candidate,
                    Json::object([
                        ("encapsulation", hop.clone().into()),
                        ("source_ip", datagram.source.to_string().into()),
                        ("destination_ip", datagram.destination.to_string().into()),
                    ]),
                );
                e.evidence = Evidence::bytes(&datagram.payload);
                self.sink.emit(&e)?;
                path.push(hop);
                return self.layers(
                    inner,
                    LayerContext {
                        path,
                        depth: depth + 1,
                        frame,
                        time,
                        raw: &datagram.payload,
                        id,
                    },
                );
            }
            Err(e) => {
                self.diagnostic(
                    format!("tunnel_candidate_rejected:{e}"),
                    contributors.clone(),
                    EvidenceStatus::Unsupported,
                )?;
                // A standard UDP tunnel port is a hint, not proof. Still offer
                // the original UDP datagram to content-based application probes.
                if datagram.protocol != 17 {
                    return Ok(());
                }
            }
            Ok(None) => {}
        }
        match network::transport_metadata(&datagram) {
            Ok(Some((protocol, data))) => {
                let invalid = match &data {
                    Json::Object(fields) => fields.iter().any(|(key, value)| {
                        ["checksum_valid", "crc32c_valid"].contains(key)
                            && *value == Json::Bool(false)
                    }),
                    _ => false,
                };
                let status =
                    if invalid && self.c.base.checksum_policy == ChecksumPolicy::RequireValid {
                        EvidenceStatus::Rejected
                    } else if invalid {
                        EvidenceStatus::Incomplete
                    } else {
                        EvidenceStatus::Observed
                    };
                let mut e = Event::new(
                    EventKind::Network,
                    status,
                    Json::object([
                        ("source_ip", datagram.source.to_string().into()),
                        ("destination_ip", datagram.destination.to_string().into()),
                        ("metadata", data),
                    ]),
                );
                e.protocol = Some(protocol.into());
                e.evidence = Evidence::bytes(&datagram.payload);
                self.sink.emit(&e)?;
                return Ok(());
            }
            Err(e) => {
                self.diagnostic(e.to_string(), contributors, EvidenceStatus::Rejected)?;
                return Ok(());
            }
            Ok(None) => {}
        }
        let transport = match wire::decode_transport(&datagram, self.c.base.checksum_policy) {
            Ok(t) => t,
            Err(e) => {
                self.diagnostic(e.to_string(), contributors, EvidenceStatus::Unsupported)?;
                return Ok(());
            }
        };
        self.transport(datagram.scope, path, transport, contributors, frame, time)
    }
    fn transport(
        &mut self,
        scope: Scope,
        path: Vec<String>,
        transport: Transport,
        packets: Vec<PacketId>,
        frame: u64,
        time: Option<i128>,
    ) -> Result<()> {
        let (source, destination, protocol, bytes, checksum) = match &transport {
            Transport::Tcp(s) => (s.source, s.destination, 6, s.payload.len(), s.checksum),
            Transport::Udp(d) => (d.source, d.destination, 17, 0, d.checksum),
        };
        if checksum == Checksum::Invalid {
            self.diagnostic(
                "invalid_transport_checksum_observed",
                packets.clone(),
                EvidenceStatus::Incomplete,
            )?;
        }
        if bytes > self.c.window_payload || packets.len() > self.c.window_packets {
            self.diagnostic(
                "segment_or_fragment_provenance_exceeds_window_budget",
                packets,
                EvidenceStatus::Incomplete,
            )?;
            return Ok(());
        }
        let (key, direction) = Key::new(scope.clone(), path, protocol, source, destination);
        let mut a = match self.take(&key) {
            Some(a) => a,
            None => {
                self.room(bytes)?;
                self.create(key.clone(), frame, time)?
            }
        };
        let idle = match (time, a.last_ns) {
            (Some(now), Some(last)) => now.saturating_sub(last) > self.c.base.idle_timeout_ns,
            _ => false,
        };
        if idle
            || a.packet_refs
                .checked_add(packets.len())
                .is_none_or(|n| n > self.c.window_packets)
            || a.payload
                .checked_add(bytes)
                .is_none_or(|n| n > self.c.window_payload)
        {
            self.flush(
                a,
                if idle {
                    "idle_time_boundary"
                } else {
                    "reconstruction_window_budget"
                },
            )?;
            a = self.create(key.clone(), frame, time)?;
        }
        self.room(a.payload + bytes)?;
        if matches!((time,a.last_ns),(Some(now),Some(last)) if now<last) {
            self.diagnostic(
                "capture_clock_reversal",
                packets.clone(),
                EvidenceStatus::Ambiguous,
            )?;
        }
        a.last_frame = frame;
        a.last_ns = match (time, a.last_ns) {
            (Some(x), Some(y)) => Some(x.max(y)),
            (x, None) => x,
            (None, y) => y,
        };
        a.packet_refs += packets.len();
        match transport {
            Transport::Tcp(segment) => {
                let syn = segment.syn();
                let retry = segment.clone();
                let result = a
                    .tracker
                    .as_mut()
                    .ok_or_else(|| Error::limit("tcp_tracker"))?
                    .ingest_with_packets(scope.clone(), &packets, time, segment);
                let assignment = match result {
                    Ok(x) => x,
                    Err(error) => {
                        self.diagnostic(
                            format!("tcp_window_reset:{error}"),
                            packets.clone(),
                            EvidenceStatus::Incomplete,
                        )?;
                        self.flush(a, "tracker_admission_boundary")?;
                        a = self.create(key.clone(), frame, time)?;
                        a.packet_refs = packets.len();
                        a.tracker
                            .as_mut()
                            .ok_or_else(|| Error::limit("tcp_tracker"))?
                            .ingest_with_packets(scope, &packets, time, retry)?
                    }
                };
                let (session, disposition, candidates) = match assignment {
                    Assignment::Assigned { flow_id, .. } => {
                        let id = if let Some(id) = a.flow_ids.get(&flow_id) {
                            *id
                        } else {
                            let id = self.session()?;
                            a.flow_ids.insert(flow_id, id);
                            self.start_flow(
                                &a,
                                id,
                                if syn {
                                    "observed_syn_candidate"
                                } else {
                                    "midstream_candidate"
                                },
                            )?;
                            id
                        };
                        a.payload += bytes;
                        (Some(id), "assigned", vec![])
                    }
                    Assignment::Ambiguous { candidate_flow_ids } => {
                        let candidates = candidate_flow_ids
                            .iter()
                            .filter_map(|id| a.flow_ids.get(id))
                            .copied()
                            .collect();
                        (None, "ambiguous_generation", candidates)
                    }
                    Assignment::Unassigned { reason } => {
                        self.diagnostic(reason, packets.clone(), EvidenceStatus::Ambiguous)?;
                        (None, "unassigned", vec![])
                    }
                };
                let mut e = Event::new(
                    EventKind::Network,
                    if session.is_some() {
                        EvidenceStatus::Candidate
                    } else {
                        EvidenceStatus::Ambiguous
                    },
                    Json::object([
                        ("transport", "tcp".into()),
                        ("source_ip", source.address.to_string().into()),
                        ("source_port", source.port.into()),
                        ("destination_ip", destination.address.to_string().into()),
                        ("destination_port", destination.port.into()),
                        ("disposition", disposition.into()),
                        (
                            "candidate_sessions",
                            Json::array(candidates.iter().map(|id: &u64| id.to_string().into())),
                        ),
                        ("window_id", a.window.to_string().into()),
                    ]),
                );
                e.session = session;
                e.direction = Some(direction);
                e.evidence = Evidence::packets(packets);
                self.sink.emit(&e)?;
            }
            Transport::Udp(d) => {
                let id = a.udp_id.ok_or_else(|| Error::limit("udp_session"))?;
                let mut e = Event::new(
                    EventKind::Network,
                    EvidenceStatus::Observed,
                    Json::object([
                        ("transport", "udp".into()),
                        ("source_ip", source.address.to_string().into()),
                        ("source_port", source.port.into()),
                        ("destination_ip", destination.address.to_string().into()),
                        ("destination_port", destination.port.into()),
                        ("window_id", a.window.to_string().into()),
                        ("datagram_local", true.into()),
                    ]),
                );
                e.session = Some(id);
                e.direction = Some(direction);
                e.evidence = Evidence::bytes(&d.payload);
                e.evidence.packets = packets;
                self.sink.emit(&e)?;
                if !d.payload.is_empty() {
                    let ctx = Context {
                        session: id,
                        window: a.window,
                        generation: None,
                        direction,
                        source,
                        destination,
                        transport: ProbeTransport::Udp,
                        ambiguous: false,
                        boundary_verified: true,
                        modbus_ports: self.c.base.modbus_ports.clone(),
                    };
                    let mut output = RegistryOutput {
                        sink: self.sink,
                        records: &mut a.messages,
                        dnp3_confirmations: &mut a.dnp3_confirmations,
                        remaining: &mut a.remaining,
                    };
                    self.registry
                        .datagram(&ctx, &d.payload, self.c, &mut output)?;
                }
            }
        }
        self.put(a)
    }
    fn flow_streams(
        &mut self,
        id: u64,
        window: u64,
        flow: &FlowResult,
        messages: &mut Vec<MessageRecord>,
        dnp3_confirmations: &mut Vec<Dnp3StreamingConfirmationRecord>,
        remaining: &mut usize,
    ) -> Result<()> {
        let flow_ambiguous = !flow.reconstruction_errors.is_empty()
            || !flow.anomalies.is_empty()
            || flow
                .streams
                .iter()
                .flatten()
                .any(|stream| !stream.gaps.is_empty() || !stream.conflicts.is_empty());
        let mut protocol_inputs = Vec::new();
        for error in &flow.reconstruction_errors {
            self.diagnostic(
                format!("stream_reconstruction:{error}"),
                flow.packets.clone(),
                EvidenceStatus::Incomplete,
            )?;
        }
        for anomaly in &flow.anomalies {
            self.diagnostic(*anomaly, flow.packets.clone(), EvidenceStatus::Ambiguous)?;
        }
        for direction in 0..2 {
            let Some(stream) = &flow.streams[direction] else {
                continue;
            };
            for gap in &stream.gaps {
                let mut e = Event::new(
                    EventKind::StreamGap,
                    EvidenceStatus::Incomplete,
                    Json::object([("reason", gap.reason.into())]),
                );
                e.session = Some(id);
                e.direction = Some(direction as u8);
                e.stream_range = Some((gap.start, gap.end));
                self.sink.emit(&e)?;
            }
            for conflict in &stream.conflicts {
                let mut e = Event::new(
                    EventKind::StreamConflict,
                    EvidenceStatus::Ambiguous,
                    Json::object([("policy", self.c.base.overlap_policy.as_str().into())]),
                );
                e.session = Some(id);
                e.direction = Some(direction as u8);
                e.stream_range = Some((conflict.start, conflict.end));
                e.evidence = Evidence::packets(conflict.packets.clone());
                self.sink.emit(&e)?;
            }
            for chunk in &stream.chunks {
                let mut e = Event::new(
                    EventKind::StreamChunk,
                    EvidenceStatus::Candidate,
                    Json::object([
                        (
                            "base_sequence",
                            stream.base_sequence.map_or(Json::Null, Json::from),
                        ),
                        ("anchored_by_observed_syn", stream.anchored_by_syn.into()),
                        (
                            "payload_hex",
                            if self.c.include_payload {
                                sha256::hex(chunk.bytes.data()).into()
                            } else {
                                Json::Null
                            },
                        ),
                    ]),
                );
                e.session = Some(id);
                e.direction = Some(direction as u8);
                e.evidence = Evidence::bytes(&chunk.bytes);
                e.stream_range = Some((chunk.offset, chunk.offset + chunk.bytes.len() as i64));
                self.sink.emit(&e)?;
            }
            let (source, destination) = if direction == 0 {
                (flow.key.a, flow.key.b)
            } else {
                (flow.key.b, flow.key.a)
            };
            let ctx = Context {
                session: id,
                window,
                generation: Some(flow.generation),
                direction: direction as u8,
                source,
                destination,
                transport: ProbeTransport::Tcp,
                ambiguous: flow_ambiguous,
                boundary_verified: stream.anchored_by_syn
                    && stream.gaps.is_empty()
                    && stream.conflicts.is_empty()
                    && flow.reconstruction_errors.is_empty(),
                modbus_ports: self.c.base.modbus_ports.clone(),
            };
            protocol_inputs.push((ctx, stream));
        }
        let mut output = RegistryOutput {
            sink: self.sink,
            records: messages,
            dnp3_confirmations,
            remaining,
        };
        self.registry
            .streams(&protocol_inputs, self.c, &mut output)?;
        Ok(())
    }
    fn flush(&mut self, mut a: Active, reason: &'static str) -> Result<()> {
        if let Some(tracker) = a.tracker.take() {
            for flow in tracker.finish(self.c.base.overlap_policy)? {
                let id = if let Some(id) = a.flow_ids.get(&flow.id) {
                    *id
                } else {
                    let id = self.session()?;
                    self.start_flow(&a, id, "unassigned_reconstruction_state")?;
                    id
                };
                self.flow_streams(
                    id,
                    a.window,
                    &flow,
                    &mut a.messages,
                    &mut a.dnp3_confirmations,
                    &mut a.remaining,
                )?;
                let mut e = Event::new(
                    EventKind::FlowEnd,
                    if flow.closed && flow.reconstruction_errors.is_empty() {
                        EvidenceStatus::Candidate
                    } else {
                        EvidenceStatus::Incomplete
                    },
                    Json::object([
                        ("reason", reason.into()),
                        ("closed_observed", flow.closed.into()),
                        ("midstream", flow.midstream.into()),
                        ("window_id", a.window.to_string().into()),
                        ("local_generation", flow.generation.to_string().into()),
                        (
                            "first_timestamp_ns",
                            flow.first_ns.map_or(Json::Null, |n| n.to_string().into()),
                        ),
                        (
                            "last_timestamp_ns",
                            flow.last_ns.map_or(Json::Null, |n| n.to_string().into()),
                        ),
                    ]),
                );
                e.session = Some(id);
                e.evidence = Evidence::packets(flow.packets);
                self.sink.emit(&e)?;
            }
        }
        if let Some(id) = a.udp_id {
            let mut e = Event::new(
                EventKind::FlowEnd,
                EvidenceStatus::Candidate,
                Json::object([
                    ("reason", reason.into()),
                    ("window_id", a.window.to_string().into()),
                    ("transport", "udp".into()),
                ]),
            );
            e.session = Some(id);
            self.sink.emit(&e)?;
        }
        self.registry.correlate(
            &a.messages,
            self.sink,
            self.c.base.limits.max_correlation_checks,
        )?;
        crate::plugin::correlate_dnp3_confirmations(
            &a.dnp3_confirmations,
            self.sink,
            self.c.base.limits.max_correlation_checks,
        )?;
        let status = if reason == "eof" {
            EvidenceStatus::Observed
        } else {
            EvidenceStatus::Incomplete
        };
        self.sink.emit(&Event::new(
            EventKind::Boundary,
            status,
            Json::object([
                ("reason", reason.into()),
                ("window_id", a.window.to_string().into()),
                ("last_frame", a.last_frame.to_string().into()),
                ("cross_window_protocol_state_retained", false.into()),
                ("cross_window_retransmission_history_retained", false.into()),
                ("physical_connection_may_continue", true.into()),
            ]),
        ))?;
        Ok(())
    }
    fn finish(&mut self) -> Result<()> {
        while self.evict_oldest("eof")? {}
        let fragments = std::mem::take(&mut self.fragments);
        for (_, slot) in fragments {
            for n in slot.reassembler.finish() {
                self.fragment_notice(n)?;
            }
        }
        Ok(())
    }
}

/// Consumes Read incrementally, with bounded active state and synchronous event
/// backpressure. No source-size-dependent Vec, whole-file report or final JSON tree.
/// A complete source digest binds the provisional run only after successful EOF.
pub fn analyze_reader<R: Read>(
    input: R,
    config: StreamConfig,
    registry: &Registry,
    sink: &mut dyn EventSink,
) -> Result<Summary> {
    config.validate()?;
    let namespace =
        sha256::digest(format!("pcap-evidence/unbound-run/v1:{}", sink.run_id()).as_bytes());
    let mut meter = Meter {
        inner: sink,
        events: 0,
        degraded: 0,
    };
    meter.emit(&Event::new(
        EventKind::CaptureStart,
        EvidenceStatus::Observed,
        Json::object([
            ("implementation", "pcap-evidence-stream/0.1.0".into()),
            ("config", config.json()),
            (
                "plugins",
                Json::array(registry.names().into_iter().map(Json::from)),
            ),
            ("source_sha256", Json::Null),
            ("provenance_binding", "run_id_until_successful_EOF".into()),
            (
                "reconstruction_scope",
                "bounded_active_windows_not_full_history".into(),
            ),
        ]),
    ))?;
    let hash_reader = HashReader {
        inner: input,
        hash: Sha256::new(),
        bytes: 0,
        max: config.max_source_bytes,
    };
    let mut reader =
        CaptureReader::new(hash_reader, config.reader_limits(), config.base.parse_mode)?;
    let mut state = State {
        c: &config,
        registry,
        sink: &mut meter,
        namespace,
        active: BTreeMap::new(),
        order: BTreeSet::new(),
        fragments: BTreeMap::new(),
        retained: 0,
        next_session: 0,
        next_window: 0,
        summary: Summary::default(),
    };
    let result = (|| -> Result<()> {
        while let Some(record) = reader.next_record()? {
            state.summary.records = state
                .summary
                .records
                .checked_add(1)
                .ok_or_else(|| Error::limit("records"))?;
            if let Some((meta, data)) = record.packet() {
                state.summary.packets = state
                    .summary
                    .packets
                    .checked_add(1)
                    .ok_or_else(|| Error::limit("packets"))?;
                state.packet(
                    meta,
                    data,
                    record.offset(),
                    record
                        .warnings()
                        .iter()
                        .map(|w| w.code.to_owned())
                        .collect(),
                )?;
            } else {
                let secrets = matches!(record.kind(), RecordKind::Secrets { .. });
                state.sink.emit(&Event::new(
                    EventKind::Metadata,
                    EvidenceStatus::Observed,
                    Json::object([
                        ("record_offset", record.offset().to_string().into()),
                        ("record_length", record.raw().len().to_string().into()),
                        ("kind", format!("{:?}", record.kind()).into()),
                        (
                            "record_sha256",
                            sha256::hex(&sha256::digest(record.raw())).into(),
                        ),
                        ("secrets_redacted", secrets.into()),
                    ]),
                ))?;
            }
        }
        state.finish()
    })();
    let mut summary = state.summary.clone();
    drop(state);
    let read = reader.into_inner();
    summary.source_bytes = read.bytes;
    summary.source_sha256 = read.hash.finalize();
    if let Err(error) = result {
        let _ = meter.emit(&Event::new(
            EventKind::CaptureAborted,
            EvidenceStatus::Rejected,
            Json::object([
                ("reason", error.to_string().into()),
                ("consumed_bytes", summary.source_bytes.to_string().into()),
                (
                    "consumed_prefix_sha256",
                    sha256::hex(&summary.source_sha256).into(),
                ),
                ("complete_source_binding", false.into()),
            ]),
        ));
        return Err(error);
    }
    summary.events = meter
        .events
        .checked_add(1)
        .ok_or_else(|| Error::limit("events"))?;
    summary.degraded_events = meter.degraded;
    meter.emit(&Event::new(
        EventKind::CaptureComplete,
        EvidenceStatus::Observed,
        Json::object([
            ("source_bytes", summary.source_bytes.to_string().into()),
            ("source_sha256", sha256::hex(&summary.source_sha256).into()),
            ("records", summary.records.to_string().into()),
            ("packets", summary.packets.to_string().into()),
            ("events", summary.events.to_string().into()),
            (
                "degraded_events",
                summary.degraded_events.to_string().into(),
            ),
            ("windows", summary.windows.to_string().into()),
            ("peak_active_keys", summary.peak_active_keys.into()),
            (
                "peak_retained_tcp_payload",
                summary.peak_retained_tcp_payload.into(),
            ),
            ("complete_container_read", true.into()),
            ("complete_protocol_history", false.into()),
        ]),
    ))?;
    Ok(summary)
}
