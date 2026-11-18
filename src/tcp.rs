//! Offline TCP generations and sequence-space reconstruction. These policies are
//! explicit interpretations; none claims to emulate every endpoint OS TCP stack.
use crate::provenance::{EvidenceBytes, PacketId};
use crate::wire::{Endpoint, Scope, TcpHeader, TcpSegment};
use crate::{Error, ErrorCode, Limits, Result};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OverlapPolicy {
    RejectConflict,
    FirstObserved,
    LastObserved,
}
impl OverlapPolicy {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RejectConflict => "reject_conflict",
            Self::FirstObserved => "first_observed",
            Self::LastObserved => "last_observed",
        }
    }
}
#[derive(Clone, Debug)]
pub struct StreamChunk {
    pub offset: i64,
    pub bytes: EvidenceBytes,
}
#[derive(Clone, Debug)]
pub struct StreamGap {
    pub start: i64,
    pub end: i64,
    pub reason: &'static str,
}
#[derive(Clone, Debug)]
pub struct Conflict {
    pub start: i64,
    pub end: i64,
    pub packets: Vec<PacketId>,
}
#[derive(Clone, Debug)]
pub struct StreamResult {
    pub base_sequence: Option<u32>,
    pub anchored_by_syn: bool,
    pub chunks: Vec<StreamChunk>,
    pub gaps: Vec<StreamGap>,
    pub conflicts: Vec<Conflict>,
    pub duplicate_observed_bytes: usize,
}
struct Segment {
    start: i64,
    bytes: EvidenceBytes,
}
pub struct StreamAssembler {
    base: Option<u32>,
    anchored_by_syn: bool,
    segments: Vec<Segment>,
    min: i64,
    max: i64,
    fin: Option<i64>,
    retained: usize,
    limits: Limits,
}

/// Map a wrapping u32 sequence into a bounded signed interval around an anchor.
pub fn sequence_delta(sequence: u32, anchor: u32) -> Result<i64> {
    let delta = sequence.wrapping_sub(anchor);
    if delta == 0x8000_0000 {
        return Err(Error::new(
            ErrorCode::SequenceAmbiguous,
            0,
            "sequence",
            "exact half-space difference has no unique ordering",
        ));
    }
    Ok(i64::from(delta as i32))
}
impl StreamAssembler {
    pub fn new(syn: Option<u32>, limits: Limits) -> Self {
        Self {
            base: syn.map(|n| n.wrapping_add(1)),
            anchored_by_syn: syn.is_some(),
            segments: Vec::new(),
            min: 0,
            max: 0,
            fin: None,
            retained: 0,
            limits,
        }
    }
    pub fn push(&mut self, sequence: u32, bytes: EvidenceBytes) -> Result<()> {
        self.limits.validate()?;
        if bytes.is_empty() {
            return Ok(());
        }
        if !bytes.validate() {
            return Err(Error::new(
                ErrorCode::Invariant,
                0,
                "provenance",
                "invalid source-span layout",
            ));
        }
        let retained = self
            .retained
            .checked_add(bytes.len())
            .ok_or_else(|| Error::limit("stream_retained_payload"))?;
        if retained > self.limits.max_retained_payload {
            return Err(Error::limit("stream_retained_payload"));
        }
        if self.segments.len() >= self.limits.max_segments_per_flow {
            return Err(Error::limit("stream_segments"));
        }
        let base = self.base.unwrap_or(sequence);
        let start = sequence_delta(sequence, base)?;
        let end = start
            .checked_add(bytes.len() as i64)
            .ok_or_else(|| Error::limit("stream_span"))?;
        let min = self.min.min(start);
        let max = self.max.max(end);
        if max - min > self.limits.max_stream_span as i64 {
            return Err(Error::limit("stream_span"));
        }
        if self.anchored_by_syn && start < 0 {
            return Err(Error::new(
                ErrorCode::SequenceAmbiguous,
                0,
                "sequence",
                "payload precedes observed SYN",
            ));
        }
        self.base.get_or_insert(sequence);
        self.retained = retained;
        self.min = min;
        self.max = max;
        self.segments.push(Segment { start, bytes });
        Ok(())
    }
    pub fn end_at(&mut self, sequence_after_payload: u32) -> Result<()> {
        self.limits.validate()?;
        // Even a FIN observed before any payload is evidence of an end position.
        // A subsequent earlier segment can have a negative unanchored offset.
        let base = self.base.unwrap_or(sequence_after_payload);
        let end = sequence_delta(sequence_after_payload, base)?;
        if end < self.min || end - self.min > self.limits.max_stream_span as i64 {
            return Err(Error::limit("fin_sequence"));
        }
        if self.fin.is_some_and(|old| old != end) {
            return Err(Error::new(
                ErrorCode::SequenceAmbiguous,
                0,
                "fin_sequence",
                "conflicting FIN positions",
            ));
        }
        self.base.get_or_insert(sequence_after_payload);
        self.fin = Some(end);
        Ok(())
    }
    pub fn finish(self, policy: OverlapPolicy) -> Result<StreamResult> {
        self.limits.validate()?;
        let mut result = StreamResult {
            base_sequence: self.base,
            anchored_by_syn: self.anchored_by_syn,
            chunks: Vec::new(),
            gaps: Vec::new(),
            conflicts: Vec::new(),
            duplicate_observed_bytes: 0,
        };
        if self.segments.is_empty() {
            if self.anchored_by_syn {
                if let Some(end) = self.fin {
                    if end > 0 {
                        result.gaps.push(StreamGap {
                            start: 0,
                            end,
                            reason: "missing_capture_bytes",
                        });
                    }
                }
            }
            return Ok(result);
        }
        if self.fin.is_some_and(|fin| self.max > fin) {
            return Err(Error::new(
                ErrorCode::SequenceAmbiguous,
                0,
                "fin_sequence",
                "observed payload extends beyond FIN",
            ));
        }
        // Sweep segment boundary events. Comparisons cover only captured overlaps,
        // so total byte comparison work is bounded by retained segment bytes.
        let mut events: BTreeMap<i64, (Vec<usize>, Vec<usize>)> = BTreeMap::new();
        for (i, segment) in self.segments.iter().enumerate() {
            events.entry(segment.start).or_default().0.push(i);
            events
                .entry(segment.start + segment.bytes.len() as i64)
                .or_default()
                .1
                .push(i);
        }
        if self.anchored_by_syn {
            events.entry(0).or_default();
        }
        if let Some(fin) = self.fin {
            events.entry(fin).or_default();
        }
        let boundaries: Vec<_> = events.keys().copied().collect();
        let mut active = BTreeSet::new();
        for pair in boundaries.windows(2) {
            let a = pair[0];
            let b = pair[1];
            let (starts, ends) = &events[&a];
            for index in ends {
                active.remove(index);
            }
            for index in starts {
                active.insert(*index);
            }
            if active.is_empty() {
                result.gaps.push(StreamGap {
                    start: a,
                    end: b,
                    reason: "missing_capture_bytes",
                });
                continue;
            }
            let chosen = if policy == OverlapPolicy::LastObserved {
                *active
                    .iter()
                    .next_back()
                    .ok_or_else(|| Error::limit("sweep"))?
            } else {
                *active.iter().next().ok_or_else(|| Error::limit("sweep"))?
            };
            let segment = &self.segments[chosen];
            let start = (a - segment.start) as usize;
            let end = (b - segment.start) as usize;
            let selected = &segment.bytes.data()[start..end];
            let mut conflict = false;
            let mut packets = Vec::new();
            for i in &active {
                let other = &self.segments[*i];
                let x = (a - other.start) as usize;
                let y = (b - other.start) as usize;
                let raw = &other.bytes.data()[x..y];
                if raw != selected {
                    conflict = true;
                }
                if *i != chosen && raw == selected {
                    result.duplicate_observed_bytes += raw.len();
                }
                let spans = other.bytes.spans();
                let first = spans.partition_point(|span| span.end <= x);
                packets.extend(
                    spans[first..]
                        .iter()
                        .take_while(|span| span.start < y)
                        .map(|span| span.packet),
                );
            }
            if conflict {
                packets.sort();
                packets.dedup();
                result.conflicts.push(Conflict {
                    start: a,
                    end: b,
                    packets,
                });
                if policy == OverlapPolicy::RejectConflict {
                    result.gaps.push(StreamGap {
                        start: a,
                        end: b,
                        reason: "conflicting_capture_bytes",
                    });
                    continue;
                }
            }
            let bytes = segment.bytes.slice(start..end)?;
            if let Some(previous) = result.chunks.last_mut() {
                if previous.offset + previous.bytes.len() as i64 == a {
                    previous.bytes.append(&bytes, self.limits.max_stream_span)?;
                    continue;
                }
            }
            result.chunks.push(StreamChunk { offset: a, bytes });
        }
        Ok(result)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct FlowKey {
    pub scope: Scope,
    pub a: Endpoint,
    pub b: Endpoint,
}
impl FlowKey {
    pub fn new(scope: Scope, source: Endpoint, destination: Endpoint) -> (Self, usize) {
        if source <= destination {
            (
                Self {
                    scope,
                    a: source,
                    b: destination,
                },
                0,
            )
        } else {
            (
                Self {
                    scope,
                    a: destination,
                    b: source,
                },
                1,
            )
        }
    }
}
struct Input {
    direction: usize,
    segment: TcpSegment,
}
struct Flow {
    id: usize,
    generation: usize,
    key: FlowKey,
    syn: [Option<u32>; 2],
    anchors: [Option<u32>; 2],
    fin: [bool; 2],
    fin_next: [Option<u32>; 2],
    closed: bool,
    rst_seen: bool,
    has_payload: bool,
    midstream: bool,
    first_ns: Option<i128>,
    last_ns: Option<i128>,
    packets: Vec<PacketId>,
    inputs: Vec<Input>,
    anomalies: Vec<&'static str>,
    uncertain_payload: Option<PacketId>,
}
#[derive(Clone, Debug)]
pub struct FlowResult {
    pub id: usize,
    pub generation: usize,
    pub key: FlowKey,
    pub syn: [Option<u32>; 2],
    pub closed: bool,
    pub midstream: bool,
    pub first_ns: Option<i128>,
    pub last_ns: Option<i128>,
    pub packets: Vec<PacketId>,
    pub streams: [Option<StreamResult>; 2],
    pub reconstruction_errors: Vec<Error>,
    pub anomalies: Vec<&'static str>,
    /// Earliest observed packet that could carry unretained data for this generation.
    pub uncertain_payload: Option<PacketId>,
}
impl FlowResult {
    pub(crate) fn has_transport_loss(&self) -> bool {
        self.uncertain_payload.is_some()
            || !self.reconstruction_errors.is_empty()
            || self
                .streams
                .iter()
                .flatten()
                .any(|s| !s.gaps.is_empty() || !s.conflicts.is_empty())
    }
}
#[derive(Clone, Debug)]
pub enum Assignment {
    Assigned { flow_id: usize, direction: usize },
    Ambiguous { candidate_flow_ids: Vec<usize> },
    Unassigned { reason: &'static str },
}
impl Flow {
    fn admits_payload_start(&self, direction: usize, sequence: u32) -> bool {
        self.syn[direction].is_none_or(|isn| {
            sequence_delta(sequence, isn.wrapping_add(1)).is_ok_and(|delta| delta >= 0)
        })
    }

    fn sequence_plausible(
        &self,
        direction: usize,
        seq: u32,
        ack: Option<u32>,
        max_span: i64,
    ) -> bool {
        let pair = self.anchors[direction]
            .map(|base| (seq, base))
            .or_else(|| ack.zip(self.anchors[1 - direction]));
        pair.is_none_or(|(seq, base)| sequence_delta(seq, base).is_ok_and(|d| d.abs() <= max_span))
    }
    fn note_uncertain(&mut self, packet: PacketId) {
        self.uncertain_payload = Some(self.uncertain_payload.map_or(packet, |p| p.min(packet)));
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum HeaderDisposition {
    AwaitingReassembly,
    Omitted,
}

struct UnretainedHeader {
    disposition: HeaderDisposition,
    existing: Vec<usize>,
    packet: PacketId,
    time: Option<i128>,
    direction: usize,
    sequence: u32,
    ack: Option<u32>,
    syn_isn: Option<u32>,
    // Generations below this ID were already considered at packet admission.
    first_future_id: usize,
}
impl UnretainedHeader {
    fn handshake_allows(&self, flow: &Flow) -> bool {
        self.syn_isn
            .zip(flow.syn[self.direction])
            .is_none_or(|(seen, assigned)| seen == assigned)
            && flow.admits_payload_start(self.direction, self.sequence)
    }

    fn matches(&self, flow: &Flow, max_span: i64) -> bool {
        flow.packets
            .first()
            .is_some_and(|p| p.capture == self.packet.capture)
            && self.handshake_allows(flow)
            && flow.sequence_plausible(self.direction, self.sequence, self.ack, max_span)
    }
}
pub struct TcpTracker {
    unretained: BTreeMap<FlowKey, BTreeMap<PacketId, UnretainedHeader>>,
    loss_count: usize,
    remaining_loss_checks: usize,
    keys: BTreeMap<FlowKey, Vec<usize>>,
    flows: Vec<Flow>,
    retained: usize,
    limits: Limits,
    idle_ns: i128,
}
impl TcpTracker {
    pub fn new(limits: Limits, idle_ns: i128) -> Result<Self> {
        limits.validate()?;
        if idle_ns <= 0 {
            return Err(Error::new(
                ErrorCode::Usage,
                0,
                "idle_timeout",
                "must be positive",
            ));
        }
        Ok(Self {
            keys: BTreeMap::new(),
            flows: Vec::new(),
            unretained: BTreeMap::new(),
            loss_count: 0,
            remaining_loss_checks: limits.max_correlation_checks,
            retained: 0,
            limits,
            idle_ns,
        })
    }
    fn create(&mut self, key: FlowKey, midstream: bool) -> Result<usize> {
        if self.flows.len() >= self.limits.max_flows {
            return Err(Error::limit("flows"));
        }
        let id = self.flows.len();
        let generation = self.keys.get(&key).map_or(1, |ids| ids.len() + 1);
        self.keys.entry(key.clone()).or_default().push(id);
        self.flows.push(Flow {
            id,
            generation,
            key,
            syn: [None, None],
            anchors: [None, None],
            fin: [false, false],
            fin_next: [None, None],
            closed: false,
            rst_seen: false,
            has_payload: false,
            midstream,
            first_ns: None,
            last_ns: None,
            packets: Vec::new(),
            inputs: Vec::new(),
            anomalies: Vec::new(),
            uncertain_payload: None,
        });
        Ok(id)
    }

    fn active_at(&self, flow: &Flow, when: Option<i128>) -> bool {
        match (when, flow.last_ns) {
            (Some(now), Some(last)) => now.saturating_sub(last) <= self.idle_ns,
            _ => true, // unavailable time never becomes an invented expiry
        }
    }
    fn plausible(&self, flow: &Flow, direction: usize, segment: &TcpSegment) -> bool {
        (segment.payload.is_empty()
            || flow.admits_payload_start(direction, segment.data_sequence()))
            && flow.sequence_plausible(
                direction,
                segment.data_sequence(),
                segment.ack().then_some(segment.acknowledgement),
                self.limits.max_stream_span as i64,
            )
    }
    fn is_final_ack(flow: &Flow, direction: usize, segment: &TcpSegment) -> bool {
        if flow.rst_seen
            || !flow.fin[0]
            || !flow.fin[1]
            || segment.syn()
            || segment.fin()
            || segment.rst()
            || !segment.ack()
            || !segment.payload.is_empty()
        {
            return false;
        }
        match (flow.fin_next[direction], flow.fin_next[1 - direction]) {
            (Some(own_next), Some(peer_next)) => {
                segment.data_sequence() == own_next && segment.acknowledgement == peer_next
            }
            _ => false,
        }
    }
    /// Keep header evidence until the owning generation is known. Reassembled
    /// segments release their provisional headers only after successful admission.
    pub fn observe_header(
        &mut self,
        scope: Scope,
        packet: PacketId,
        when: Option<i128>,
        segment: TcpHeader,
        disposition: HeaderDisposition,
    ) -> Result<()> {
        let (key, direction) = FlowKey::new(scope, segment.source, segment.destination);
        if let Some(previous) = self
            .unretained
            .get_mut(&key)
            .and_then(|set| set.get_mut(&packet))
        {
            if disposition == HeaderDisposition::Omitted {
                previous.disposition = disposition;
            }
            return Ok(());
        }
        if self.loss_count >= self.limits.max_records {
            return Err(Error::limit("unretained_tcp_headers"));
        }
        if !self.unretained.contains_key(&key) && self.unretained.len() >= self.limits.max_flows {
            return Err(Error::limit("unretained_tcp_keys"));
        }
        let header = self.match_header(&key, direction, packet, when, segment, disposition)?;
        let headers = self.unretained.entry(key).or_default();
        if headers.len() >= self.limits.max_segments_per_flow {
            return Err(Error::limit("unretained_tcp_headers"));
        }
        headers.insert(packet, header);
        self.loss_count += 1;
        Ok(())
    }

    fn opening_syn_owner(
        &self,
        history: &[usize],
        direction: usize,
        sequence: u32,
        when: Option<i128>,
    ) -> Option<usize> {
        let same_syn = history.iter().rev().copied().find(|id| {
            let f = &self.flows[*id];
            !f.closed && self.active_at(f, when) && f.syn[direction] == Some(sequence)
        });
        let simultaneous = history.last().copied().filter(|id| {
            let f = &self.flows[*id];
            !f.closed
                && self.active_at(f, when)
                && !f.midstream
                && !f.has_payload
                && f.syn[direction].is_none()
                && f.syn[1 - direction].is_some()
        });
        same_syn.or(simultaneous)
    }

    fn match_header(
        &mut self,
        key: &FlowKey,
        direction: usize,
        packet: PacketId,
        when: Option<i128>,
        segment: TcpHeader,
        disposition: HeaderDisposition,
    ) -> Result<UnretainedHeader> {
        let mut header = UnretainedHeader {
            packet,
            time: when,
            direction,
            sequence: segment
                .sequence
                .wrapping_add(u32::from(segment.flags & 2 != 0)),
            ack: (segment.flags & 0x10 != 0).then_some(segment.acknowledgement),
            syn_isn: (segment.flags & 2 != 0).then_some(segment.sequence),
            first_future_id: self.flows.len(),
            existing: Vec::new(),
            disposition,
        };
        let max_span = self.limits.max_stream_span as i64;
        let ids = self.keys.get(key).map_or(&[][..], Vec::as_slice);
        self.remaining_loss_checks = self
            .remaining_loss_checks
            .checked_sub(ids.len())
            .ok_or_else(|| Error::limit("unretained_tcp_generation_checks"))?;
        if let Some(isn) = header.syn_isn.filter(|_| header.ack.is_none()) {
            if let Some(id) = self.opening_syn_owner(ids, direction, isn, when) {
                if self.flows[id]
                    .packets
                    .first()
                    .is_some_and(|p| p.capture == packet.capture)
                {
                    header.existing.push(id);
                }
            }
            return Ok(header);
        }
        let mut open = false;
        for &id in ids {
            let flow = &self.flows[id];
            if self.active_at(flow, when) && header.matches(flow, max_span) {
                header.existing.push(id);
                open |= !flow.closed;
            }
        }
        // A late data packet with only closed candidates is unassigned.
        if !open {
            header.existing.clear();
        }
        Ok(header)
    }

    /// Apply an arriving loss to matching generations before closing a window.
    /// No header is retained here: the new window owns any future generations.
    pub fn observe_at_cut(
        &mut self,
        scope: Scope,
        packet: PacketId,
        when: Option<i128>,
        segment: TcpHeader,
    ) -> Result<()> {
        let (key, direction) = FlowKey::new(scope, segment.source, segment.destination);
        let header = self.match_header(
            &key,
            direction,
            packet,
            when,
            segment,
            HeaderDisposition::Omitted,
        )?;
        for id in header.existing {
            self.flows[id].note_uncertain(packet);
        }
        Ok(())
    }

    /// Count contributor references already charged while waiting for reassembly.
    pub fn provisional_count(
        &self,
        scope: Scope,
        header: TcpHeader,
        packets: &[PacketId],
    ) -> usize {
        let (key, _) = FlowKey::new(scope, header.source, header.destination);
        self.unretained.get(&key).map_or(0, |set| {
            packets
                .iter()
                .filter(|id| {
                    set.get(id)
                        .is_some_and(|h| h.disposition == HeaderDisposition::AwaitingReassembly)
                })
                .count()
        })
    }

    /// A completed reassembly with a definitive transport disposition resolves
    /// its provisional observations. Omitted data remains a loss witness.
    pub fn resolve_reassembly(
        &mut self,
        scope: Scope,
        header: TcpHeader,
        packets: &[PacketId],
    ) -> usize {
        let (key, _) = FlowKey::new(scope, header.source, header.destination);
        self.resolve_packets(&key, packets)
    }

    pub fn ingest(
        &mut self,
        scope: Scope,
        packet: PacketId,
        when: Option<i128>,
        segment: TcpSegment,
    ) -> Result<Assignment> {
        self.ingest_with_packets(scope, &[packet], when, segment)
    }
    pub fn ingest_with_packets(
        &mut self,
        scope: Scope,
        packets: &[PacketId],
        when: Option<i128>,
        segment: TcpSegment,
    ) -> Result<Assignment> {
        if packets.is_empty() {
            return Err(Error::new(
                ErrorCode::Invariant,
                0,
                "tcp_evidence",
                "TCP segment requires source packets",
            ));
        }
        let header = segment.header();
        let has_payload = !segment.payload.is_empty();
        let (key, direction) = FlowKey::new(scope, header.source, header.destination);
        let assignment = self.assign(&key, direction, packets, when, segment)?;
        if matches!(assignment, Assignment::Assigned { .. }) {
            self.resolve_packets(&key, packets);
        } else if has_payload {
            self.observe_header(
                key.scope,
                packets[0],
                when,
                header,
                HeaderDisposition::Omitted,
            )?;
        }
        Ok(assignment)
    }

    fn resolve_packets(&mut self, key: &FlowKey, packets: &[PacketId]) -> usize {
        let before = self.loss_count;
        if let Some(headers) = self.unretained.get_mut(key) {
            for id in packets {
                if headers
                    .get(id)
                    .is_some_and(|h| h.disposition == HeaderDisposition::AwaitingReassembly)
                {
                    headers.remove(id);
                    self.loss_count -= 1;
                }
            }
            if headers.is_empty() {
                self.unretained.remove(key);
            }
        }
        before - self.loss_count
    }

    fn assign(
        &mut self,
        key: &FlowKey,
        direction: usize,
        packets: &[PacketId],
        when: Option<i128>,
        segment: TcpSegment,
    ) -> Result<Assignment> {
        let retained = self
            .retained
            .checked_add(segment.payload.len())
            .ok_or_else(|| Error::limit("tcp_retained_payload"))?;
        if retained > self.limits.max_retained_payload {
            return Err(Error::limit("tcp_retained_payload"));
        }
        let history = self.keys.get(key).cloned().unwrap_or_default();
        let selected;
        if segment.syn() && !segment.ack() {
            selected = if let Some(id) =
                self.opening_syn_owner(&history, direction, segment.sequence, when)
            {
                id
            } else {
                self.create(key.clone(), false)?
            };
        } else if history.is_empty() {
            selected = self.create(key.clone(), true)?;
        } else {
            let mut candidates = Vec::new();
            let mut closed_candidates = Vec::new();
            let mut closed_final_ack_candidates = Vec::new();
            let mut conflicting_syn = false;
            for id in &history {
                let f = &self.flows[*id];
                let expired = match (when, f.last_ns) {
                    (Some(now), Some(last)) => now.saturating_sub(last) > self.idle_ns,
                    _ => false,
                };
                if !expired && self.plausible(f, direction, &segment) {
                    if segment.syn() && f.syn[direction].is_some_and(|isn| isn != segment.sequence)
                    {
                        conflicting_syn |= !f.closed;
                        continue;
                    }
                    if f.closed {
                        closed_candidates.push(*id);
                        if Self::is_final_ack(f, direction, &segment) {
                            closed_final_ack_candidates.push(*id);
                        }
                    } else {
                        candidates.push(*id);
                    }
                }
            }
            if !closed_final_ack_candidates.is_empty()
                && closed_final_ack_candidates.len() == 1
                && closed_candidates.len() == 1
                && candidates.is_empty()
            {
                selected = closed_final_ack_candidates[0];
            } else if !closed_candidates.is_empty() {
                if segment.syn() && candidates.is_empty() {
                    // A SYN establishes a new generation even when the initial
                    // SYN was not captured (for example, an observed SYN-ACK).
                    selected = self.create(key.clone(), true)?;
                } else if candidates.is_empty() {
                    return Ok(Assignment::Unassigned {
                        reason: "closed_generation_requires_syn",
                    });
                } else {
                    let mut possible = closed_candidates;
                    possible.extend(candidates);
                    possible.sort_unstable();
                    return Ok(Assignment::Ambiguous {
                        candidate_flow_ids: possible,
                    });
                }
            } else if candidates.len() > 1 {
                return Ok(Assignment::Ambiguous {
                    candidate_flow_ids: candidates,
                });
            } else if let Some(id) = candidates.first() {
                selected = *id;
            } else if conflicting_syn {
                return Ok(Assignment::Unassigned {
                    reason: "conflicting_syn_for_generation",
                });
            } else {
                let all_expired = history
                    .iter()
                    .all(|id| match (when, self.flows[*id].last_ns) {
                        (Some(now), Some(last)) => now.saturating_sub(last) > self.idle_ns,
                        _ => false,
                    });
                if all_expired || segment.syn() {
                    selected = self.create(key.clone(), true)?;
                } else {
                    return Ok(Assignment::Unassigned {
                        reason: "sequence_outside_known_generations",
                    });
                }
            }
        }

        let flow = &mut self.flows[selected];
        if flow.inputs.len() >= self.limits.max_segments_per_flow {
            return Err(Error::limit("segments_per_flow"));
        }
        if segment.syn() {
            flow.syn[direction] = Some(segment.sequence);
        }
        flow.anchors[direction].get_or_insert(segment.data_sequence());
        if let Some(now) = when {
            if flow.last_ns.is_some_and(|last| now < last) {
                flow.anomalies.push("capture_clock_reversal");
            }
            flow.first_ns = Some(flow.first_ns.map_or(now, |first| first.min(now)));
            flow.last_ns = Some(flow.last_ns.map_or(now, |last| last.max(now)));
        } else {
            flow.anomalies.push("packet_time_unavailable");
        }
        flow.has_payload |= !segment.payload.is_empty();
        if segment.fin() {
            flow.fin[direction] = true;
            flow.fin_next[direction].get_or_insert(
                segment
                    .data_sequence()
                    .wrapping_add(segment.payload.len() as u32)
                    .wrapping_add(1),
            );
        }
        flow.rst_seen |= segment.rst();
        flow.closed |= flow.rst_seen || (flow.fin[0] && flow.fin[1]);
        flow.packets.extend_from_slice(packets);
        // Include every IP fragment contributing to this TCP segment, not just
        // the last arriving fragment that completed the network datagram.
        flow.packets.extend(segment.payload.packets());
        flow.inputs.push(Input { direction, segment });
        self.retained = retained;
        Ok(Assignment::Assigned {
            flow_id: selected,
            direction,
        })
    }
    pub fn finish(mut self, policy: OverlapPolicy) -> Result<Vec<FlowResult>> {
        let max_span = self.limits.max_stream_span as i64;
        for (key, headers) in self.unretained {
            let Some(ids) = self.keys.get(&key) else {
                continue;
            };
            for header in headers.into_values() {
                for &id in &header.existing {
                    let flow = &mut self.flows[id];
                    // The opposite half of the handshake may have arrived since admission.
                    if header.handshake_allows(flow) {
                        flow.note_uncertain(header.packet);
                    }
                }
                if header.syn_isn.is_some() && header.ack.is_none() && !header.existing.is_empty() {
                    continue; // An observed opening SYN already owned this retransmission.
                }
                let first = ids.partition_point(|&id| id < header.first_future_id);
                for &id in &ids[first..] {
                    self.remaining_loss_checks = self
                        .remaining_loss_checks
                        .checked_sub(1)
                        .ok_or_else(|| Error::limit("unretained_tcp_generation_checks"))?;
                    let flow = &mut self.flows[id];
                    let expired = header
                        .time
                        .zip(flow.first_ns)
                        .is_some_and(|(seen, start)| start.saturating_sub(seen) > self.idle_ns);
                    if !expired && header.matches(flow, max_span) {
                        flow.note_uncertain(header.packet);
                    }
                }
            }
        }
        let mut output = Vec::with_capacity(self.flows.len());
        for mut flow in self.flows {
            let mut a = StreamAssembler::new(flow.syn[0], self.limits.clone());
            let mut b = StreamAssembler::new(flow.syn[1], self.limits.clone());
            let mut reconstruction_errors = Vec::new();
            let mut invalid = [false, false];
            for input in flow.inputs {
                if invalid[input.direction] {
                    continue;
                }
                let stream = if input.direction == 0 { &mut a } else { &mut b };
                let data_sequence = input.segment.data_sequence();
                let len = input.segment.payload.len();
                let fin = input.segment.fin();
                let step = stream
                    .push(data_sequence, input.segment.payload)
                    .and_then(|_| {
                        if fin {
                            stream.end_at(data_sequence.wrapping_add(len as u32))
                        } else {
                            Ok(())
                        }
                    });
                if let Err(e) = step {
                    invalid[input.direction] = true;
                    reconstruction_errors.push(e);
                }
            }
            let first = if invalid[0] {
                None
            } else {
                match a.finish(policy) {
                    Ok(x) => Some(x),
                    Err(e) => {
                        reconstruction_errors.push(e);
                        None
                    }
                }
            };
            let second = if invalid[1] {
                None
            } else {
                match b.finish(policy) {
                    Ok(x) => Some(x),
                    Err(e) => {
                        reconstruction_errors.push(e);
                        None
                    }
                }
            };
            flow.packets.sort();
            flow.packets.dedup();
            flow.anomalies.sort();
            flow.anomalies.dedup();
            output.push(FlowResult {
                id: flow.id,
                generation: flow.generation,
                key: flow.key,
                syn: flow.syn,
                closed: flow.closed,
                midstream: flow.midstream,
                first_ns: flow.first_ns,
                last_ns: flow.last_ns,
                packets: flow.packets,
                streams: [first, second],
                reconstruction_errors,
                anomalies: flow.anomalies,
                uncertain_payload: flow.uncertain_payload,
            });
        }
        Ok(output)
    }
}
