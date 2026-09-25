//! Bounded application segmentation. Scope is a caller-justified transport
//! generation + direction + service identity, never a bare reused transaction ID.
use super::model::*;
use pcap_evidence::{json::Json, provenance::EvidenceBytes, sha256, Error, Result};
use std::collections::BTreeMap;

#[derive(Clone, Debug)]
pub struct Segment {
    pub ordinal: u64,
    pub first: bool,
    pub final_segment: bool,
    pub bytes: EvidenceBytes,
    pub frame: u64,
}
#[derive(Clone, Debug)]
pub struct Outcome {
    pub status: Status,
    pub reason: &'static str,
    pub completed: Option<EvidenceBytes>,
    pub before: [u8; 32],
    pub after: [u8; 32],
}
impl Outcome {
    pub fn json(&self) -> Json {
        Json::object([
            ("status", self.status.name().into()),
            ("reason", self.reason.into()),
            ("state_before_sha256", sha256::hex(&self.before).into()),
            ("state_after_sha256", sha256::hex(&self.after).into()),
            (
                "scope",
                "caller_justified_generation_not_global_transaction_id".into(),
            ),
            (
                "evidence",
                self.completed.as_ref().map_or(Json::Null, |b| {
                    pcap_evidence_stream::events::Evidence::bytes(b).json()
                }),
            ),
        ])
    }
}
#[derive(Clone, Default)]
struct Chain {
    parts: BTreeMap<u64, Segment>,
    conflicts: Vec<(u64, EvidenceBytes)>,
    last: Option<u64>,
    first: bool,
    poisoned: bool,
    last_frame: u64,
}
impl Chain {
    fn identity(&self) -> [u8; 32] {
        let v = Json::object([
            (
                "last",
                self.last.map_or(Json::Null, |x| x.to_string().into()),
            ),
            ("first", self.first.into()),
            ("poisoned", self.poisoned.into()),
            ("last_frame", self.last_frame.to_string().into()),
            (
                "conflicts",
                Json::array(self.conflicts.iter().map(|(n, b)| {
                    Json::object([
                        ("ordinal", n.to_string().into()),
                        (
                            "evidence",
                            pcap_evidence_stream::events::Evidence::bytes(b).json(),
                        ),
                    ])
                })),
            ),
            (
                "parts",
                Json::array(self.parts.iter().map(|(k, v)| {
                    Json::object([
                        ("ordinal", k.to_string().into()),
                        ("hash", sha256::hex(&sha256::digest(v.bytes.data())).into()),
                        ("first", v.first.into()),
                        ("final", v.final_segment.into()),
                        (
                            "evidence",
                            pcap_evidence_stream::events::Evidence::bytes(&v.bytes).json(),
                        ),
                    ])
                })),
            ),
        ]);
        sha256::digest(v.encode().as_bytes())
    }
    fn bytes(&self) -> usize {
        self.parts.values().map(|s| s.bytes.len()).sum::<usize>()
            + self.conflicts.iter().map(|(_, b)| b.len()).sum::<usize>()
    }
}
pub struct Segments {
    limits: Limits,
    chains: BTreeMap<String, Chain>,
    retained: usize,
}
impl Segments {
    pub fn new(limits: Limits) -> Result<Self> {
        limits.validate()?;
        Ok(Self {
            limits,
            chains: BTreeMap::new(),
            retained: 0,
        })
    }
    pub fn retained_bytes(&self) -> usize {
        self.retained
    }
    pub fn push(&mut self, scope: &str, s: Segment) -> Result<Outcome> {
        if scope.is_empty()
            || scope.len() > 512
            || !s.bytes.validate()
            || s.bytes.spans().len() > self.limits.spans
            || s.bytes.len() > self.limits.input_bytes
            || s.ordinal >= self.limits.elements as u64
        {
            return Err(Error::limit("segmentation_input"));
        }
        if s.first && s.ordinal != 0 {
            return Err(bad(
                "segmentation",
                0,
                "first must have logical ordinal zero",
            ));
        }
        if !self.chains.contains_key(scope) && self.chains.len() >= self.limits.active {
            return Err(Error::limit("active_segmented_messages"));
        }
        let previous = self.chains.get(scope).cloned().unwrap_or_default();
        let before = previous.identity();
        let mut next = previous.clone();
        if next.poisoned {
            return Ok(Outcome {
                status: Status::Ambiguous,
                reason: "conflicted_scope_requires_explicit_reset",
                completed: None,
                before,
                after: before,
            });
        }
        if let Some(old) = next.parts.get(&s.ordinal) {
            if old.bytes.data() == s.bytes.data()
                && old.first == s.first
                && old.final_segment == s.final_segment
            {
                return Ok(Outcome {
                    status: Status::Observed,
                    reason: "duplicate_segment_not_appended",
                    completed: None,
                    before,
                    after: before,
                });
            }
            let total = self
                .retained
                .checked_add(s.bytes.len())
                .filter(|n| *n <= self.limits.retained_bytes)
                .ok_or_else(|| Error::limit("conflict_bytes"))?;
            if next.conflicts.len() >= self.limits.elements {
                return Err(Error::limit("conflict_count"));
            }
            next.conflicts.push((s.ordinal, s.bytes.clone()));
            next.poisoned = true;
            let after = next.identity();
            self.retained = total;
            self.chains.insert(scope.into(), next);
            return Ok(Outcome {
                status: Status::Ambiguous,
                reason: "conflicting_segment_retained_as_boundary",
                completed: None,
                before,
                after,
            });
        }
        let total = self
            .retained
            .checked_add(s.bytes.len())
            .ok_or_else(|| Error::limit("segmentation_bytes"))?;
        if total > self.limits.retained_bytes
            || next.bytes().saturating_add(s.bytes.len()) > self.limits.input_bytes
        {
            return Err(Error::limit("segmentation_bytes"));
        }
        if next.parts.len() >= self.limits.elements {
            return Err(Error::limit("segmentation_parts"));
        }
        if s.final_segment {
            if next.last.is_some_and(|last| last != s.ordinal) {
                next.poisoned = true;
            }
            next.last = Some(s.ordinal);
        }
        if next.last.is_some_and(|last| s.ordinal > last)
            || next
                .parts
                .keys()
                .any(|x| next.last.is_some_and(|last| *x > last))
        {
            next.poisoned = true;
        }
        next.first |= s.first;
        next.last_frame = next.last_frame.max(s.frame);
        next.parts.insert(s.ordinal, s);
        // Commit only after all size checks. Failed pushes do not silently lose state.
        let mut complete = None;
        let (mut status, mut reason) = (Status::Incomplete, "awaiting_segments");
        if next.poisoned {
            status = Status::Ambiguous;
            reason = "contradictory_last_segment";
        } else if next.first
            && next
                .last
                .is_some_and(|last| last + 1 == next.parts.len() as u64)
        {
            let mut assembled = EvidenceBytes::default();
            for (expected, (ordinal, part)) in next.parts.iter().enumerate() {
                if *ordinal != expected as u64 {
                    return Err(bad("segmentation", 0, "noncontiguous completed set"));
                }
                if assembled
                    .spans()
                    .len()
                    .saturating_add(part.bytes.spans().len())
                    > self.limits.spans
                {
                    return Err(Error::limit("segmentation_spans"));
                }
                assembled.append(&part.bytes, self.limits.input_bytes)?;
            }
            complete = Some(assembled);
            status = Status::Candidate;
            reason = "complete_in_observed_scope";
        }
        let after = next.identity();
        self.retained = total;
        self.chains.insert(scope.into(), next);
        // Keep the completed scope until explicit release: a late conflict must not
        // be mistaken for a new transfer. Caller controls finite scope lifetime.
        Ok(Outcome {
            status,
            reason,
            completed: complete,
            before,
            after,
        })
    }
    pub fn cut(&mut self, scope: &str, reason: &'static str) -> Option<Outcome> {
        let old = self.chains.remove(scope)?;
        self.retained -= old.bytes();
        Some(Outcome {
            status: Status::Incomplete,
            reason,
            completed: None,
            before: old.identity(),
            after: Chain::default().identity(),
        })
    }
    pub fn expire(&mut self, frame: u64, max_idle_frames: u64) -> Vec<(String, Outcome)> {
        let expired: Vec<_> = self
            .chains
            .iter()
            .filter(|(_, v)| frame.saturating_sub(v.last_frame) > max_idle_frames)
            .map(|(k, _)| k.clone())
            .collect();
        expired
            .into_iter()
            .filter_map(|k| self.cut(&k, "capture_frame_expiration").map(|o| (k, o)))
            .collect()
    }
}

/// Stream framer used by disk-history consumers. No application bytes cross gaps.
pub struct StreamBuffer {
    pending: EvidenceBytes,
    next: Option<i64>,
    base: i64,
    limit: usize,
    spans: usize,
    poisoned: bool,
}
impl StreamBuffer {
    pub fn new(limit: usize, spans: usize) -> Result<Self> {
        if limit == 0 || spans == 0 {
            return Err(Error::limit("stream_buffer"));
        }
        Ok(Self {
            pending: EvidenceBytes::default(),
            next: None,
            base: 0,
            limit,
            spans,
            poisoned: false,
        })
    }
    pub fn push(&mut self, offset: i64, bytes: &EvidenceBytes) -> Result<()> {
        if self.poisoned {
            return Err(bad("stream_buffer", 0, "explicit gap/reset required"));
        }
        if !bytes.validate() || self.next.is_some_and(|n| n != offset) {
            self.poisoned = true;
            return Err(bad("stream_buffer", 0, "noncontiguous evidence"));
        }
        let end = offset
            .checked_add(i64::try_from(bytes.len()).map_err(|_| Error::limit("stream_offset"))?)
            .ok_or_else(|| Error::limit("stream_offset"))?;
        if self
            .pending
            .spans()
            .len()
            .saturating_add(bytes.spans().len())
            > self.spans
        {
            return Err(Error::limit("stream_buffer_spans"));
        }
        if self.pending.is_empty() {
            self.base = offset;
        }
        self.pending.append(bytes, self.limit)?;
        self.next = Some(end);
        Ok(())
    }
    pub fn bytes(&self) -> &EvidenceBytes {
        &self.pending
    }
    pub fn offset(&self) -> i64 {
        self.base
    }
    pub fn take(&mut self, count: usize) -> Result<EvidenceBytes> {
        if count == 0 || count > self.pending.len() {
            return Err(bad("stream_buffer", 0, "invalid consumed extent"));
        }
        let out = self.pending.slice(0..count)?;
        let rest = self.pending.slice(count..self.pending.len())?;
        self.base = self
            .base
            .checked_add(count as i64)
            .ok_or_else(|| Error::limit("stream_offset"))?;
        self.pending = rest;
        Ok(out)
    }
    pub fn gap(&mut self) -> EvidenceBytes {
        self.next = None;
        self.poisoned = false;
        std::mem::take(&mut self.pending)
    }
}
