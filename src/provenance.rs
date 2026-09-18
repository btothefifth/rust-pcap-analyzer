use crate::{Error, ErrorCode, Result};
use std::ops::Range;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct PacketId {
    pub capture: [u8; 32],
    pub frame: u64,
    pub record_offset: u64,
}

/// Maps a half-open reconstructed range to bytes in a captured packet.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceSpan {
    pub start: usize,
    pub end: usize,
    pub packet: PacketId,
    pub packet_start: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvidenceBytes {
    data: Vec<u8>,
    spans: Vec<SourceSpan>,
    // All fields are private; no API exposes mutable data/spans. Constructors
    // establish this invariant and append/slice preserve it. Caching it avoids
    // rescanning the entire growing prefix on every append (quadratic work).
    layout_valid: bool,
}
impl Default for EvidenceBytes {
    fn default() -> Self {
        Self {
            data: Vec::new(),
            spans: Vec::new(),
            layout_valid: true,
        }
    }
}
impl EvidenceBytes {
    /// Compatibility constructor. Invalid source-offset arithmetic remains
    /// explicitly invalid, rather than wrapping or being laundered by slicing.
    /// This cannot verify the real packet length: that requires source bytes.
    pub fn from_packet(data: &[u8], packet: PacketId, packet_start: usize) -> Self {
        let spans = if data.is_empty() {
            Vec::new()
        } else {
            vec![SourceSpan {
                start: 0,
                end: data.len(),
                packet,
                packet_start,
            }]
        };
        Self {
            data: data.to_vec(),
            spans,
            layout_valid: data.is_empty() || packet_start.checked_add(data.len()).is_some(),
        }
    }
    pub fn data(&self) -> &[u8] {
        &self.data
    }
    pub fn spans(&self) -> &[SourceSpan] {
        &self.spans
    }
    pub fn len(&self) -> usize {
        self.data.len()
    }
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    pub fn slice(&self, range: Range<usize>) -> Result<Self> {
        if !self.layout_valid {
            return Err(invalid("invalid source-span layout"));
        }
        if range.start > range.end || range.end > self.data.len() {
            return Err(Error::new(
                ErrorCode::Invariant,
                0,
                "evidence_slice",
                "slice outside retained evidence",
            ));
        }
        // Spans are contiguous and sorted by construction. Do not walk unrelated
        // prefix spans for every small protocol field extracted from a stream.
        let first = self.spans.partition_point(|span| span.end <= range.start);
        let mut spans = Vec::new();
        for s in self.spans[first..]
            .iter()
            .take_while(|s| s.start < range.end)
        {
            let a = s.start.max(range.start);
            let b = s.end.min(range.end);
            if a < b {
                spans.push(SourceSpan {
                    start: a - range.start,
                    end: b - range.start,
                    packet: s.packet,
                    packet_start: s
                        .packet_start
                        .checked_add(a - s.start)
                        .ok_or_else(|| invalid("source offset overflow"))?,
                });
            }
        }
        Ok(Self {
            data: self.data[range].to_vec(),
            spans,
            layout_valid: true,
        })
    }

    pub fn append(&mut self, other: &Self, limit: usize) -> Result<()> {
        if !self.layout_valid || !other.layout_valid {
            return Err(invalid("invalid source-span layout"));
        }
        let base = self.data.len();
        let end = base
            .checked_add(other.data.len())
            .ok_or_else(|| Error::limit("evidence_bytes"))?;
        if end > limit {
            return Err(Error::limit("evidence_bytes"));
        }
        // Reserve before changing semantic state. A failed reserve can change
        // capacity but never the evidence bytes or span interpretation.
        self.data
            .try_reserve(other.data.len())
            .map_err(|_| Error::limit("evidence_bytes_allocation"))?;
        self.spans
            .try_reserve(other.spans.len())
            .map_err(|_| Error::limit("evidence_spans_allocation"))?;
        self.data.extend_from_slice(&other.data);
        for s in &other.spans {
            let next = SourceSpan {
                start: base + s.start,
                end: base + s.end,
                packet: s.packet,
                packet_start: s.packet_start,
            };
            if let Some(last) = self.spans.last_mut() {
                if last.packet == next.packet
                    && last.end == next.start
                    && last.packet_start.checked_add(last.end - last.start)
                        == Some(next.packet_start)
                {
                    last.end = next.end;
                    continue;
                }
            }
            self.spans.push(next);
        }
        Ok(())
    }
    pub fn packets(&self) -> Vec<PacketId> {
        let mut ids: Vec<_> = self.spans.iter().map(|s| s.packet).collect();
        ids.sort();
        ids.dedup();
        ids
    }
    /// Full independent layout scan, retained for audit/fuzz assertions. This
    /// checks arithmetic and continuity, not packet identity authenticity.
    pub fn validate(&self) -> bool {
        if !self.layout_valid {
            return false;
        }
        let mut cursor = 0;
        for span in &self.spans {
            if span.start != cursor
                || span.end <= span.start
                || span.end > self.data.len()
                || span
                    .packet_start
                    .checked_add(span.end - span.start)
                    .is_none()
            {
                return false;
            }
            cursor = span.end;
        }
        cursor == self.data.len()
    }
}
fn invalid(detail: &str) -> Error {
    Error::new(ErrorCode::Invariant, 0, "provenance", detail)
}
