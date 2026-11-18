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
// Capture order within this tracker. A later handshake can displace an input
// after another generation has opened or closed.
#[derive(Clone, Copy)]
struct Arrival {
    ordinal: usize,
    first_future_id: usize,
}
struct Input {
    arrival: Arrival,
    packets: Vec<PacketId>,
    when: Option<i128>,
    direction: usize,
    segment: TcpSegment,
}
impl Input {
    fn outside_span(&self, direction: usize, first: u32, max_span: usize) -> bool {
        self.direction == direction
            && self.segment.contributes_stream_extent()
            && !within_syn_span(self.segment.data_sequence(), first, max_span as i64)
    }
}
struct Flow {
    id: usize,
    generation: usize,
    key: FlowKey,
    syn: [Option<u32>; 2],
    syn_sequence_len: [usize; 2],
    anchors: [Option<u32>; 2],
    // FIN data positions in directions whose SYN has not yet supplied an origin.
    provisional_fin_starts: [BTreeSet<u32>; 2],
    fin_next: [Option<u32>; 2],
    // Furthest retained payload end per direction, in TCP sequence space.
    payload_end: [Option<u32>; 2],
    closed_at: Option<usize>,
    rst_seen: bool,
    first_payload_at: Option<usize>,
    midstream: bool,
    first_ns: Option<i128>,
    last_ns: Option<i128>,
    inputs: Vec<Input>,
    outside_syn_span: Vec<PacketId>,
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
    /// Earliest observed packet indicating possible missing data or a conflicting stream end.
    pub uncertain_payload: Option<PacketId>,
    /// Previously assigned segments excluded when a later SYN established the sequence range.
    pub outside_syn_span: Vec<PacketId>,
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
enum Owner {
    Existing(usize),
    New { midstream: bool },
    Unresolved(Assignment),
}

fn within_syn_span(sequence: u32, first: u32, max_span: i64) -> bool {
    sequence_delta(sequence, first).is_ok_and(|delta| (0..=max_span).contains(&delta))
}

impl Flow {
    fn open_at(&self, ordinal: usize) -> bool {
        self.closed_at.is_none_or(|at| at >= ordinal)
    }

    fn can_accept_opposite_syn(&self, direction: usize) -> bool {
        !self.midstream && self.syn[direction].is_none() && self.syn[1 - direction].is_some()
    }

    fn reset_observations(&mut self) {
        self.syn = [None; 2];
        self.syn_sequence_len = [0; 2];
        self.anchors = [None; 2];
        self.provisional_fin_starts = Default::default();
        self.fin_next = [None; 2];
        self.payload_end = [None; 2];
        self.closed_at = None;
        self.rst_seen = false;
        self.first_payload_at = None;
        self.first_ns = None;
        self.last_ns = None;
        self.anomalies.clear();
    }
    fn record(&mut self, input: &Input) {
        let direction = input.direction;
        let segment = &input.segment;
        let when = input.when;
        if segment.syn() {
            self.syn[direction] = Some(segment.sequence);
            self.provisional_fin_starts[direction].clear();
            self.syn_sequence_len[direction] = self.syn_sequence_len[direction]
                .max(1 + segment.payload.len() + usize::from(segment.fin()));
            self.anchors[direction] = Some(segment.data_sequence());
        } else {
            self.anchors[direction].get_or_insert(segment.data_sequence());
        }
        if let Some(now) = when {
            if self.last_ns.is_some_and(|last| now < last) {
                self.anomalies.push("capture_clock_reversal");
            }
            self.first_ns = Some(self.first_ns.map_or(now, |first| first.min(now)));
            self.last_ns = Some(self.last_ns.map_or(now, |last| last.max(now)));
        } else {
            self.anomalies.push("packet_time_unavailable");
        }
        if !segment.payload.is_empty() {
            self.first_payload_at.get_or_insert(input.arrival.ordinal);
            let end = segment
                .data_sequence()
                .wrapping_add(segment.payload.len() as u32);
            if self.payload_end[direction]
                .is_none_or(|last| sequence_delta(end, last).is_ok_and(|n| n > 0))
            {
                self.payload_end[direction] = Some(end);
            }
        }
        if segment.fin() {
            if self.syn[direction].is_none() {
                self.provisional_fin_starts[direction].insert(segment.data_sequence());
            }
            self.fin_next[direction].get_or_insert(
                segment
                    .data_sequence()
                    .wrapping_add(segment.payload.len() as u32)
                    .wrapping_add(1),
            );
        }
        self.rst_seen |= segment.rst();
        if self.rst_seen || self.fin_next.iter().all(Option::is_some) {
            self.closed_at.get_or_insert(input.arrival.ordinal);
        }
    }

    // A SYN consumes one sequence number. The ACK may cover any prefix of
    // the data on it, including none (RFC 9293, section 3.10.7.3).
    fn acknowledges_syn(&self, peer: usize, ack: u32) -> Option<bool> {
        let acknowledged = ack.wrapping_sub(self.syn[peer]?) as usize;
        Some((1..=self.syn_sequence_len[peer]).contains(&acknowledged))
    }

    /// A SYN-ACK that identifies the peer SYN can establish the missing sequence
    /// origin. A reset or a FIN consistent with that origin still closes the flow.
    fn completes_handshake(
        &self,
        direction: usize,
        isn: u32,
        ack: u32,
        ordinal: usize,
        max_span: i64,
    ) -> bool {
        if self.syn[direction].is_some() || self.acknowledges_syn(1 - direction, ack) != Some(true)
        {
            return false;
        }
        if self.open_at(ordinal) {
            return true;
        }
        if self.rst_seen {
            return false;
        }
        // The first FIN at or after the proposed origin in sequence space
        // decides whether any FIN survives, including across u32 wraparound.
        let first = isn.wrapping_add(1);
        let starts = &self.provisional_fin_starts[direction];
        let nearest = starts.range(first..).next().or_else(|| starts.first());
        nearest.is_none_or(|&fin| !within_syn_span(fin, first, max_span))
    }

    fn admits_stream_start(&self, direction: usize, sequence: u32) -> bool {
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
    fn note_uncertain(&mut self, header: &UnretainedHeader) {
        if header.extent == MissingExtent::EmptyFin {
            let direction = header.direction;
            let end = self.payload_end[direction]
                .or_else(|| self.syn[direction].map(|s| s.wrapping_add(1)));
            let fin = self.fin_next[direction].map(|n| n.wrapping_sub(1));
            if end.is_none_or(|n| n == header.sequence) && fin.is_none_or(|n| n == header.sequence)
            {
                return;
            }
        }
        let packet = header.packet;
        self.uncertain_payload = Some(self.uncertain_payload.map_or(packet, |p| p.min(packet)));
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum HeaderDisposition {
    AwaitingReassembly,
    Omitted,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum HeaderCandidate {
    Open,
    Closed,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum MissingExtent {
    PossiblePayload,
    FinWithUnknownLength,
    EmptyFin,
}

struct UnretainedHeader {
    disposition: HeaderDisposition,
    existing: Vec<usize>,
    simultaneous_open: Option<usize>,
    packet: PacketId,
    time: Option<i128>,
    direction: usize,
    sequence: u32,
    extent: MissingExtent,
    ack: Option<u32>,
    syn_isn: Option<u32>,
    arrival: Arrival,
}
impl UnretainedHeader {
    fn new(
        direction: usize,
        packet: PacketId,
        when: Option<i128>,
        segment: TcpHeader,
        disposition: HeaderDisposition,
        arrival: Arrival,
    ) -> Self {
        Self {
            packet,
            time: when,
            direction,
            extent: match (segment.flags & 1 != 0, segment.payload_len) {
                (true, None) => MissingExtent::FinWithUnknownLength,
                (true, Some(0)) => MissingExtent::EmptyFin,
                _ => MissingExtent::PossiblePayload,
            },
            sequence: segment
                .sequence
                .wrapping_add(u32::from(segment.flags & 2 != 0)),
            ack: (segment.flags & 0x10 != 0).then_some(segment.acknowledgement),
            syn_isn: (segment.flags & 2 != 0).then_some(segment.sequence),
            arrival,
            existing: Vec::new(),
            simultaneous_open: None,
            disposition,
        }
    }

    fn refine_empty_fin(&mut self, direction: usize, header: TcpHeader) {
        let sequence = header
            .sequence
            .wrapping_add(u32::from(header.flags & 2 != 0));
        if self.disposition == HeaderDisposition::AwaitingReassembly
            && self.extent == MissingExtent::FinWithUnknownLength
            && self.direction == direction
            && self.sequence == sequence
            && header.is_empty_fin()
            && self.syn_isn == (header.flags & 2 != 0).then_some(header.sequence)
            && self.ack == (header.flags & 0x10 != 0).then_some(header.acknowledgement)
        {
            self.extent = MissingExtent::EmptyFin;
        }
    }

    fn apply_existing(&mut self, flows: &mut [Flow], max_span: i64, idle_ns: i128) -> bool {
        if self.syn_isn.is_some() && self.ack.is_none() {
            // Prefer the newest matching retransmission. A simultaneous open is
            // possible only if no payload had been admitted by its arrival.
            let simultaneous = self.simultaneous_open.filter(|&id| {
                flows[id]
                    .first_payload_at
                    .is_none_or(|at| at >= self.arrival.ordinal)
            });
            let owner = self
                .existing
                .iter()
                .rev()
                .copied()
                .chain(simultaneous)
                .find(|&id| {
                    let flow = &flows[id];
                    self.within_final_idle(flow, idle_ns)
                        && self.candidate(flow, max_span) == Some(HeaderCandidate::Open)
                });
            if let Some(id) = owner {
                flows[id].note_uncertain(self);
            }
            return owner.is_some();
        }
        let mut candidates = std::mem::take(&mut self.existing);
        let mut open = false;
        candidates.retain(|candidate| {
            let flow = &flows[*candidate];
            if !self.within_final_idle(flow, idle_ns) {
                return false;
            }
            let candidate = self.candidate(flow, max_span);
            open |= candidate == Some(HeaderCandidate::Open);
            candidate.is_some()
        });
        if open {
            for candidate in &candidates {
                flows[*candidate].note_uncertain(self);
            }
        }
        open
    }

    fn within_final_idle(&self, flow: &Flow, idle_ns: i128) -> bool {
        self.disposition != HeaderDisposition::AwaitingReassembly
            || self
                .time
                .zip(flow.last_ns)
                .is_none_or(|(seen, last)| seen.saturating_sub(last) <= idle_ns)
    }

    fn handshake_allows(&self, flow: &Flow) -> bool {
        self.syn_isn
            .zip(flow.syn[self.direction])
            .is_none_or(|(seen, assigned)| seen == assigned)
            && self.syn_isn.zip(self.ack).is_none_or(|(_, ack)| {
                flow.acknowledges_syn(1 - self.direction, ack) != Some(false)
            })
            && flow.admits_stream_start(self.direction, self.sequence)
    }

    fn candidate(&self, flow: &Flow, max_span: i64) -> Option<HeaderCandidate> {
        let packet = flow.inputs.first()?.packets.first()?;
        if packet.capture != self.packet.capture || !self.handshake_allows(flow) {
            return None;
        }
        if self.syn_isn.zip(self.ack).is_some_and(|(isn, ack)| {
            flow.completes_handshake(self.direction, isn, ack, self.arrival.ordinal, max_span)
        }) {
            // The observed header could invalidate the provisional close just
            // as a retained SYN-ACK would. Its missing bytes remain uncertain.
            return Some(HeaderCandidate::Open);
        }
        if !flow.sequence_plausible(self.direction, self.sequence, self.ack, max_span) {
            return None;
        }
        Some(if flow.open_at(self.arrival.ordinal) {
            HeaderCandidate::Open
        } else {
            HeaderCandidate::Closed
        })
    }
}
pub struct TcpTracker {
    next_input: usize,
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
            next_input: 0,
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
            syn_sequence_len: [0; 2],
            anchors: [None, None],
            provisional_fin_starts: Default::default(),
            fin_next: [None, None],
            payload_end: [None; 2],
            closed_at: None,
            rst_seen: false,
            first_payload_at: None,
            midstream,
            first_ns: None,
            last_ns: None,
            outside_syn_span: Vec::new(),
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
        (!segment.contributes_stream_extent()
            || flow.admits_stream_start(direction, segment.data_sequence()))
            && flow.sequence_plausible(
                direction,
                segment.data_sequence(),
                segment.ack().then_some(segment.acknowledgement),
                self.limits.max_stream_span as i64,
            )
    }
    fn is_final_ack(flow: &Flow, direction: usize, segment: &TcpSegment) -> bool {
        if flow.rst_seen
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
    /// segments replace provisional payload evidence with their known extent.
    pub fn observe_header(
        &mut self,
        scope: Scope,
        packet: PacketId,
        when: Option<i128>,
        segment: TcpHeader,
        disposition: HeaderDisposition,
    ) -> Result<()> {
        let (key, direction) = FlowKey::new(scope, segment.source, segment.destination);
        let previous = self
            .unretained
            .get_mut(&key)
            .and_then(|set| set.get_mut(&packet));
        let replacing = previous.is_some();
        if let Some(seen) = previous {
            if seen.disposition == HeaderDisposition::Omitted {
                return Ok(());
            }
            if disposition == HeaderDisposition::AwaitingReassembly {
                seen.refine_empty_fin(direction, segment);
                return Ok(());
            }
        }
        self.check_header_capacity(&key, usize::from(!replacing))?;
        let header = self.match_header(
            &key,
            UnretainedHeader::new(
                direction,
                packet,
                when,
                segment,
                disposition,
                self.arrival(),
            ),
        )?;
        let headers = self.unretained.entry(key).or_default();
        headers.insert(packet, header);
        self.loss_count += usize::from(!replacing);
        Ok(())
    }

    fn check_header_capacity(&self, key: &FlowKey, additional: usize) -> Result<()> {
        if additional > self.limits.max_records - self.loss_count {
            return Err(Error::limit("unretained_tcp_headers"));
        }
        let existing = self.unretained.get(key);
        if additional > 0 && existing.is_none() && self.unretained.len() >= self.limits.max_flows {
            return Err(Error::limit("unretained_tcp_keys"));
        }
        if additional > self.limits.max_segments_per_flow - existing.map_or(0, BTreeMap::len) {
            return Err(Error::limit("unretained_tcp_headers"));
        }
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
            f.closed_at.is_none() && self.active_at(f, when) && f.syn[direction] == Some(sequence)
        });
        let simultaneous = history.last().copied().filter(|id| {
            let f = &self.flows[*id];
            f.closed_at.is_none()
                && self.active_at(f, when)
                && f.first_payload_at.is_none()
                && f.can_accept_opposite_syn(direction)
        });
        same_syn.or(simultaneous)
    }

    fn arrival(&self) -> Arrival {
        Arrival {
            ordinal: self.next_input,
            first_future_id: self.flows.len(),
        }
    }

    fn match_header(
        &mut self,
        key: &FlowKey,
        mut header: UnretainedHeader,
    ) -> Result<UnretainedHeader> {
        let direction = header.direction;
        let ids = self.keys.get(key).map_or(&[][..], Vec::as_slice);
        let ids = &ids[..ids.partition_point(|&id| id < header.arrival.first_future_id)];
        self.remaining_loss_checks = self
            .remaining_loss_checks
            .checked_sub(ids.len())
            .ok_or_else(|| Error::limit("unretained_tcp_generation_checks"))?;
        // Fragment timestamps remain provisional until completion. Compare them
        // with admitted activity at finalization, including any later response.
        let admission_time = match header.disposition {
            HeaderDisposition::AwaitingReassembly => None,
            HeaderDisposition::Omitted => header.time,
        };
        if let Some(isn) = header.syn_isn.filter(|_| header.ack.is_none()) {
            // A missing handshake can later disprove a FIN and change the
            // close ordinal. Retain the structural candidates until then.
            for &id in ids {
                let flow = &self.flows[id];
                if !self.active_at(flow, admission_time) {
                    continue;
                }
                if flow.syn[direction] == Some(isn) {
                    header.existing.push(id);
                } else if Some(&id) == ids.last() && flow.can_accept_opposite_syn(direction) {
                    header.simultaneous_open = Some(id);
                }
            }
            return Ok(header);
        }
        for &id in ids {
            let flow = &self.flows[id];
            // Both the sequence origin and the peer SYN's observed data extent
            // can change. Apply the sequence tests once, at finalization.
            if self.active_at(flow, admission_time) {
                header.existing.push(id);
            }
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
        let mut header = self.match_header(
            &key,
            UnretainedHeader::new(
                direction,
                packet,
                when,
                segment,
                HeaderDisposition::Omitted,
                self.arrival(),
            ),
        )?;
        header.apply_existing(
            &mut self.flows,
            self.limits.max_stream_span as i64,
            self.idle_ns,
        );
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

    /// A terminal fragment can fix a FIN's position while TCP options are
    /// still missing. Preserve each contributor's arrival and candidate flows.
    pub fn refine_reassembly_extent(
        &mut self,
        scope: &Scope,
        header: TcpHeader,
        packets: &[PacketId],
    ) {
        if !header.is_empty_fin() {
            return;
        }
        let (key, direction) = FlowKey::new(scope.clone(), header.source, header.destination);
        if let Some(headers) = self.unretained.get_mut(&key) {
            for packet in packets {
                if let Some(seen) = headers.get_mut(packet) {
                    seen.refine_empty_fin(direction, header);
                }
            }
        }
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
        // The complete segment replaces all partial observations of its bytes,
        // including when a payload-free control has several possible owners.
        if has_payload && !matches!(assignment, Assignment::Assigned { .. }) {
            self.observe_header(
                key.scope.clone(),
                packets[0],
                when,
                header,
                HeaderDisposition::Omitted,
            )?;
        }
        self.resolve_packets(&key, packets);
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

    fn owner(
        &self,
        key: &FlowKey,
        direction: usize,
        when: Option<i128>,
        segment: &TcpSegment,
    ) -> Owner {
        let history = self.keys.get(key).map_or(&[][..], Vec::as_slice);
        if segment.syn() && !segment.ack() {
            return self
                .opening_syn_owner(history, direction, segment.sequence, when)
                .map_or(Owner::New { midstream: false }, Owner::Existing);
        }
        if history.is_empty() {
            return Owner::New { midstream: true };
        }
        let mut candidates = Vec::new();
        let mut closed_candidates = Vec::new();
        let mut closed_final_ack_candidates = Vec::new();
        let mut conflicting_syn = false;
        for id in history {
            let f = &self.flows[*id];
            if !self.active_at(f, when) {
                continue;
            }
            if segment.syn()
                && segment.ack()
                && f.acknowledges_syn(1 - direction, segment.acknowledgement) == Some(false)
            {
                conflicting_syn |= f.closed_at.is_none() && self.plausible(f, direction, segment);
                continue;
            }
            if segment.syn()
                && segment.ack()
                && f.completes_handshake(
                    direction,
                    segment.sequence,
                    segment.acknowledgement,
                    self.next_input,
                    self.limits.max_stream_span as i64,
                )
            {
                candidates.push(*id);
                continue;
            }
            if self.plausible(f, direction, segment) {
                if segment.syn() && f.syn[direction].is_some_and(|isn| isn != segment.sequence) {
                    conflicting_syn |= f.closed_at.is_none();
                    continue;
                }
                if f.closed_at.is_some() {
                    closed_candidates.push(*id);
                    if Self::is_final_ack(f, direction, segment) {
                        closed_final_ack_candidates.push(*id);
                    }
                } else {
                    candidates.push(*id);
                }
            }
        }
        if closed_final_ack_candidates.len() == 1
            && closed_candidates.len() == 1
            && candidates.is_empty()
        {
            Owner::Existing(closed_final_ack_candidates[0])
        } else if !closed_candidates.is_empty() {
            if segment.syn() && candidates.is_empty() {
                // A SYN establishes a new generation even when the initial
                // SYN was not captured (for example, an observed SYN-ACK).
                Owner::New { midstream: true }
            } else if candidates.is_empty() {
                Owner::Unresolved(Assignment::Unassigned {
                    reason: "closed_generation_requires_syn",
                })
            } else {
                let mut possible = closed_candidates;
                possible.extend(candidates);
                possible.sort_unstable();
                Owner::Unresolved(Assignment::Ambiguous {
                    candidate_flow_ids: possible,
                })
            }
        } else if candidates.len() > 1 {
            Owner::Unresolved(Assignment::Ambiguous {
                candidate_flow_ids: candidates,
            })
        } else if let Some(id) = candidates.first() {
            Owner::Existing(*id)
        } else if conflicting_syn {
            Owner::Unresolved(Assignment::Unassigned {
                reason: "conflicting_syn_for_generation",
            })
        } else {
            let all_expired = history
                .iter()
                .all(|id| !self.active_at(&self.flows[*id], when));
            if all_expired || segment.syn() {
                Owner::New { midstream: true }
            } else {
                Owner::Unresolved(Assignment::Unassigned {
                    reason: "sequence_outside_known_generations",
                })
            }
        }
    }

    /// TCP payload bytes currently held across all generations in this tracker.
    pub fn retained_payload_bytes(&self) -> usize {
        self.retained
    }

    fn retained_after(
        &self,
        owner: &Owner,
        direction: usize,
        segment: &TcpSegment,
    ) -> Result<usize> {
        let excluded = match owner {
            Owner::Unresolved(_) => return Ok(self.retained),
            Owner::Existing(id) if segment.syn() && self.flows[*id].syn[direction].is_none() => {
                let first = segment.data_sequence();
                self.flows[*id]
                    .inputs
                    .iter()
                    .filter(|input| {
                        input.outside_span(direction, first, self.limits.max_stream_span)
                    })
                    .map(|input| input.segment.payload.len())
                    .sum()
            }
            _ => 0,
        };
        (self.retained - excluded)
            .checked_add(segment.payload.len())
            .ok_or_else(|| Error::limit("tcp_retained_payload"))
    }

    /// Retained bytes if this segment is admitted now, including the effect
    /// of a late handshake on previously assigned payload.
    pub fn projected_payload_bytes(
        &self,
        scope: Scope,
        when: Option<i128>,
        segment: &TcpSegment,
    ) -> Result<usize> {
        let (key, direction) = FlowKey::new(scope, segment.source, segment.destination);
        self.retained_after(
            &self.owner(&key, direction, when, segment),
            direction,
            segment,
        )
    }

    /// Prepare the loss observations before changing the generation that held
    /// these bytes. A work or retention limit leaves its inputs intact.
    fn displaced_headers(
        &mut self,
        key: &FlowKey,
        selected: usize,
        direction: usize,
        first: u32,
    ) -> Result<Vec<UnretainedHeader>> {
        let existing = self.unretained.get(key);
        let mut displaced = BTreeMap::new();
        for input in &self.flows[selected].inputs {
            if !input.segment.payload.is_empty()
                && input.outside_span(direction, first, self.limits.max_stream_span)
            {
                let packet = input.packets[0];
                if !existing
                    .and_then(|set| set.get(&packet))
                    .is_some_and(|h| h.disposition == HeaderDisposition::Omitted)
                {
                    displaced.entry(packet).or_insert((
                        input.when,
                        input.segment.header(),
                        input.arrival,
                    ));
                }
            }
        }
        let additional = displaced
            .keys()
            .filter(|packet| existing.is_none_or(|set| !set.contains_key(*packet)))
            .count();
        self.check_header_capacity(key, additional)?;
        displaced
            .into_iter()
            .map(|(packet, (when, header, arrival))| {
                self.match_header(
                    key,
                    UnretainedHeader::new(
                        direction,
                        packet,
                        when,
                        header,
                        HeaderDisposition::Omitted,
                        arrival,
                    ),
                )
            })
            .collect()
    }

    fn assign(
        &mut self,
        key: &FlowKey,
        direction: usize,
        packets: &[PacketId],
        when: Option<i128>,
        segment: TcpSegment,
    ) -> Result<Assignment> {
        let owner = self.owner(key, direction, when, &segment);
        let retained = self.retained_after(&owner, direction, &segment)?;
        if retained > self.limits.max_retained_payload {
            return Err(Error::limit("tcp_retained_payload"));
        }
        let selected = match owner {
            Owner::Existing(id) => id,
            Owner::New { midstream } => self.create(key.clone(), midstream)?,
            Owner::Unresolved(assignment) => return Ok(assignment),
        };

        let flow = &self.flows[selected];
        if flow.inputs.len() >= self.limits.max_segments_per_flow {
            return Err(Error::limit("segments_per_flow"));
        }
        let reconcile = segment.syn() && flow.syn[direction].is_none();
        let displaced = if reconcile {
            self.displaced_headers(key, selected, direction, segment.data_sequence())?
        } else {
            Vec::new()
        };
        let arrival = self.arrival();
        let flow = &mut self.flows[selected];
        if reconcile {
            // Before the handshake arrives, this direction has only a relative
            // sequence origin. Reconcile data and control state against the ISN.
            let first = segment.data_sequence();
            let outside =
                |input: &Input| input.outside_span(direction, first, self.limits.max_stream_span);
            if flow.inputs.iter().any(outside) {
                flow.reset_observations();
                for input in std::mem::take(&mut flow.inputs) {
                    if outside(&input) {
                        flow.outside_syn_span.extend_from_slice(&input.packets);
                    } else {
                        flow.record(&input);
                        flow.inputs.push(input);
                    }
                }
            }
        }
        let mut sources = packets.to_vec();
        sources.extend(segment.payload.packets());
        sources.sort_unstable();
        sources.dedup();
        let input = Input {
            arrival,
            direction,
            segment,
            when,
            packets: sources,
        };
        self.next_input += 1;
        flow.record(&input);
        flow.inputs.push(input);
        self.retained = retained;
        if !displaced.is_empty() {
            let set = self.unretained.entry(key.clone()).or_default();
            for header in displaced {
                self.loss_count += usize::from(set.insert(header.packet, header).is_none());
            }
        }
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
            for mut header in headers.into_values() {
                let owned = header.apply_existing(&mut self.flows, max_span, self.idle_ns);
                if owned && header.syn_isn.is_some() && header.ack.is_none() {
                    continue; // An observed opening SYN already owned this retransmission.
                }
                let first = ids.partition_point(|&id| id < header.arrival.first_future_id);
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
                    if !expired
                        && header.within_final_idle(flow, self.idle_ns)
                        && header.candidate(flow, max_span).is_some()
                    {
                        flow.note_uncertain(&header);
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
            let mut packets = Vec::new();
            for input in flow.inputs {
                packets.extend(input.packets);
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
            packets.sort_unstable();
            packets.dedup();
            flow.outside_syn_span.sort_unstable();
            flow.outside_syn_span.dedup();
            flow.anomalies.sort();
            flow.anomalies.dedup();
            output.push(FlowResult {
                id: flow.id,
                generation: flow.generation,
                key: flow.key,
                syn: flow.syn,
                closed: flow.closed_at.is_some(),
                midstream: flow.midstream,
                first_ns: flow.first_ns,
                last_ns: flow.last_ns,
                packets,
                outside_syn_span: flow.outside_syn_span,
                streams: [first, second],
                reconstruction_errors,
                anomalies: flow.anomalies,
                uncertain_payload: flow.uncertain_payload,
            });
        }
        Ok(output)
    }
}
