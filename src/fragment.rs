//! Bounded IP fragment reconstruction. Missing bytes are never synthesized.
use crate::provenance::{EvidenceBytes, PacketId, SourceSpan};
use crate::wire::{Checksum, ChecksumContext, Datagram, FragmentInfo, Scope};
use crate::{Error, Limits, Result};
use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct Key {
    scope: Scope,
    source: IpAddr,
    destination: IpAddr,
    protocol: u8,
    id: u32,
    ipv6: bool,
}
impl Key {
    fn new(d: &Datagram, info: &FragmentInfo) -> Self {
        Self {
            scope: d.scope.clone(),
            source: d.source,
            destination: d.destination,
            protocol: if d.ipv6 { 0 } else { d.protocol },
            id: info.id,
            ipv6: d.ipv6,
        }
    }
}
struct Part {
    start: usize,
    end: usize,
    more: bool,
    // Dropped once the contiguous prefix owns these bytes.
    pending: Option<EvidenceBytes>,
    // A lower-offset fragment can arrive after a higher-offset one has
    // supplied identical bytes. Its source spans win at final reconstruction.
    preferred_spans: Vec<SourceSpan>,
}
impl Part {
    fn data<'a>(&'a self, prefix: &'a EvidenceBytes) -> &'a [u8] {
        match &self.pending {
            Some(bytes) => bytes.data(),
            None => &prefix.data()[self.start..self.end],
        }
    }
}
struct Assembly<V> {
    verdict: Option<V>,
    prefix: Datagram,
    parts: Vec<Part>,
    end: Option<usize>,
    first_frame: u64,
    packets: Vec<PacketId>,
    // Earliest disputed byte or terminal boundary. Quarantined sets only expose
    // evidence before this offset and never complete.
    disputed_at: Option<usize>,
    // None once additional bytes cannot change the classification.
    next_inspection_len: Option<usize>,
}
#[derive(Clone, Debug)]
pub struct FragmentNotice {
    pub code: &'static str,
    pub packets: Vec<PacketId>,
}
pub enum FragmentOutcome {
    Pending,
    Complete(Datagram, Vec<PacketId>),
    Rejected(FragmentNotice),
}
/// The observed datagram prefix and all packets contributing to its fragment set.
pub type PrefixObserver<'a> = dyn FnMut(&Datagram, &[PacketId]) -> bool + 'a;

/// Returns the next contiguous length worth inspecting and an optional verdict
/// to reuse for identical offset-zero fragments.
pub type CachedPrefixObserver<'a, V> =
    dyn FnMut(&Datagram, &[PacketId]) -> (Option<usize>, Option<V>) + 'a;

pub struct FragmentReassembler<V = ()> {
    sets: BTreeMap<Key, Assembly<V>>,
    deadlines: BTreeSet<(u64, Key)>,
    retained: usize,
    limits: Limits,
}
impl FragmentReassembler {
    pub fn new(limits: Limits) -> Self {
        Self::with_prefix_cache(limits)
    }
    pub fn push(&mut self, datagram: Datagram, frame: u64) -> Result<FragmentOutcome> {
        self.push_with_contributors(datagram, frame, &[])
    }
    /// Retain enclosing datagram contributors, including exact retransmissions
    /// that supplied no unique bytes to an inner fragment.
    pub fn push_with_contributors(
        &mut self,
        datagram: Datagram,
        frame: u64,
        ancestors: &[PacketId],
    ) -> Result<FragmentOutcome> {
        self.push_observing_prefix(datagram, frame, ancestors, None)
    }
    /// Inspect a contiguous prefix for loss attribution. Return true when
    /// additional bytes cannot change its classification. A fragment refused
    /// at the capacity limit may supply header evidence to the observer. Only
    /// a successful Complete outcome delivers a datagram to the caller.
    pub fn push_observing_prefix(
        &mut self,
        datagram: Datagram,
        frame: u64,
        ancestors: &[PacketId],
        observer: Option<&mut PrefixObserver<'_>>,
    ) -> Result<FragmentOutcome> {
        match observer {
            Some(inspect) => self.push_caching_prefix(
                datagram,
                frame,
                ancestors,
                Some(&mut |p, ids| ((!inspect(p, ids)).then(|| p.payload.len() + 1), None)),
            ),
            None => self.push_caching_prefix(datagram, frame, ancestors, None),
        }
    }
}
impl<V> FragmentReassembler<V> {
    pub fn with_prefix_cache(limits: Limits) -> Self {
        Self {
            sets: BTreeMap::new(),
            deadlines: BTreeSet::new(),
            retained: 0,
            limits,
        }
    }
    pub fn expire(&mut self, frame: u64) -> Vec<FragmentNotice> {
        self.expire_with(frame, |notice, _| notice)
    }
    /// Return the last prefix decision along with each expired set's contributors.
    pub fn expire_with<T>(
        &mut self,
        frame: u64,
        mut retire: impl FnMut(FragmentNotice, Option<V>) -> T,
    ) -> Vec<T> {
        let mut notices = Vec::new();
        while self
            .deadlines
            .first()
            .is_some_and(|(deadline, _)| *deadline <= frame)
        {
            let Some((_, key)) = self.deadlines.pop_first() else {
                break;
            };
            if let Some(assembly) = self.remove(&key) {
                notices.push(retire(
                    FragmentNotice {
                        code: "fragment_expired",
                        packets: assembly.packets,
                    },
                    assembly.verdict,
                ));
            }
        }
        notices
    }
    fn remove(&mut self, key: &Key) -> Option<Assembly<V>> {
        let a = self.sets.remove(key)?;
        if let Some(deadline) = a
            .first_frame
            .checked_add(self.limits.fragment_frame_lifetime)
            .and_then(|n| n.checked_add(1))
        {
            self.deadlines.remove(&(deadline, key.clone()));
        }

        let size: usize = a.parts.iter().map(|p| p.end - p.start).sum();
        self.retained -= size;
        Some(a)
    }
    /// Last classification for this set. It describes previously inspected bytes.
    pub fn last_prefix_verdict(&self, datagram: &Datagram) -> Option<&V> {
        let info = datagram.fragment.as_ref()?;
        self.sets.get(&Key::new(datagram, info))?.verdict.as_ref()
    }
    /// Return the verdict for an identical offset-zero prefix in this set.
    /// The caller still submits the fragment for admission and accounting.
    pub fn cached_prefix(&self, datagram: &Datagram) -> Option<&V> {
        let info = datagram.fragment.as_ref()?;
        if info.offset != 0 || !info.more || datagram.ipv6 {
            return None;
        }
        self.sets
            .get(&Key::new(datagram, info))?
            .reusable_verdict(datagram, info)
    }

    /// Inspect at the scheduled prefix length or when header metadata changes.
    /// An unchanged duplicate reuses the cached classifier result. The caller
    /// must use the same classifier and policy throughout a fragment set.
    pub fn push_caching_prefix(
        &mut self,
        datagram: Datagram,
        frame: u64,
        ancestors: &[PacketId],
        observer: Option<&mut CachedPrefixObserver<'_, V>>,
    ) -> Result<FragmentOutcome> {
        self.push_with_invalidation(datagram, frame, ancestors, observer, |_, _, _| None)
    }

    /// Notify the consumer whenever the arriving fragment belongs to a quarantined
    /// set. The first notification returns any cached verdict to retract. When
    /// the agreed prefix grows, it is available for loss attribution only.
    /// Return the next useful prefix length, or None when identity is settled.
    pub fn push_with_invalidation(
        &mut self,
        mut datagram: Datagram,
        frame: u64,
        ancestors: &[PacketId],
        observer: Option<&mut CachedPrefixObserver<'_, V>>,
        mut invalidate: impl FnMut(Option<&Datagram>, Option<V>, &[PacketId]) -> Option<usize>,
    ) -> Result<FragmentOutcome> {
        self.limits.validate()?;
        datagram.require_complete()?;
        if ancestors.len() > self.limits.max_fragments_per_set {
            return Err(Error::limit("fragment_contributors"));
        }
        let mut ids = datagram.payload.packets();
        if !ancestors.is_empty() {
            ids.extend_from_slice(ancestors);
            ids.sort_unstable();
            ids.dedup();
        }
        let info = match datagram.fragment.clone() {
            Some(x) => x,
            None => {
                if ids.len() > self.limits.max_fragments_per_set {
                    return Err(Error::limit("fragment_contributors"));
                }
                return Ok(FragmentOutcome::Complete(datagram, ids));
            }
        };
        let key = Key::new(&datagram, &info);
        let end = info
            .offset
            .checked_add(datagram.payload.len())
            .ok_or_else(|| Error::limit("fragment_range"))?;
        if end > 65_535 || datagram.payload.is_empty() {
            return Ok(FragmentOutcome::Rejected(FragmentNotice {
                code: "invalid_fragment_range",
                packets: datagram.payload.packets(),
            }));
        }

        if !datagram.payload.validate() {
            return Err(crate::Error::new(
                crate::ErrorCode::Invariant,
                0,
                "provenance",
                "invalid fragment source spans",
            ));
        }
        let existing = self.sets.get(&key);
        let mut admitted_packets = existing.map_or_else(Vec::new, |set| set.packets.clone());
        admitted_packets.extend(ids);
        admitted_packets.sort();
        admitted_packets.dedup();
        let too_many = admitted_packets.len() > self.limits.max_fragments_per_set
            || existing.is_some_and(|set| set.parts.len() >= self.limits.max_fragments_per_set);
        let retained_arrival =
            match existing.and_then(|set| set.disputed_at.map(|bound| (set, bound))) {
                Some((set, bound)) => {
                    let stop = bound.min(end);
                    if observer.is_some()
                        && set.next_inspection_len.is_some()
                        && stop > set.prefix.payload.len()
                    {
                        stop.saturating_sub(info.offset)
                    } else {
                        0
                    }
                }
                _ => datagram.payload.len(),
            };
        let new_size = self
            .retained
            .checked_add(retained_arrival)
            .ok_or_else(|| Error::limit("fragment_payload"))?;
        if too_many || new_size > self.limits.max_retained_payload {
            if let Some(set) = self.sets.get_mut(&key) {
                let inspect_new = (observer.is_some() || set.verdict.is_some())
                    && set.reusable_verdict(&datagram, &info).is_none();
                let conflict = inspect_new
                    .then(|| set.conflict(&datagram, &info, end))
                    .flatten();
                if let Some((_, bound)) = set.dispute(conflict) {
                    if observer.is_none() {
                        set.next_inspection_len = None;
                    }
                    set.inspect_quarantine(datagram, &info, bound, false, &mut invalidate)?;
                } else if inspect_new {
                    if let Some(inspect) = observer {
                        set.inspect_refused(datagram, &info, end, &admitted_packets, inspect)?;
                    }
                }
            }
            return Err(Error::limit(if too_many {
                "fragments_per_set"
            } else {
                "fragment_payload"
            }));
        }
        if !self.sets.contains_key(&key) {
            if self.sets.len() >= self.limits.max_fragment_sets {
                return Err(Error::limit("fragment_sets"));
            }

            // Copy fixed metadata, not a full payload that is immediately discarded.
            let prefix = with_payload(&datagram, EvidenceBytes::default());
            if let Some(deadline) = frame
                .checked_add(self.limits.fragment_frame_lifetime)
                .and_then(|n| n.checked_add(1))
            {
                self.deadlines.insert((deadline, key.clone()));
            }

            self.sets.insert(
                key.clone(),
                Assembly {
                    prefix,
                    parts: Vec::new(),
                    end: None,
                    first_frame: frame,
                    packets: Vec::new(),
                    disputed_at: None,
                    next_inspection_len: Some(1),
                    verdict: None,
                },
            );
        }
        let mut ready = false;
        {
            let set = self
                .sets
                .get_mut(&key)
                .ok_or_else(|| Error::limit("fragment_state"))?;
            set.packets = admitted_packets;
            let learned_end = !info.more && set.end.is_none();
            let conflict = set.conflict(&datagram, &info, end);
            if let Some((code, bound)) = set.dispute(conflict) {
                if observer.is_none() {
                    set.next_inspection_len = None;
                }
                self.retained += set.inspect_quarantine(
                    datagram,
                    &info,
                    bound,
                    observer.is_some(),
                    &mut invalidate,
                )?;
                return Ok(FragmentOutcome::Rejected(FragmentNotice {
                    code,
                    packets: set.packets.clone(),
                }));
            }

            // Conflict checks above established equality on every overlap.
            let repeat = set.reusable_metadata(&datagram, &info);
            let previous_checksum = (set.prefix.ip_checksum, set.prefix.checksum_context);
            update_metadata(&mut set.prefix, &datagram, &info);
            let checksum_changed =
                previous_checksum != (set.prefix.ip_checksum, set.prefix.checksum_context);
            if !info.more {
                set.end = Some(end);
            }
            self.retained = new_size;
            let index = set.parts.partition_point(|part| part.start <= info.offset);
            let preferred_spans = if set
                .parts
                .get(index)
                .is_some_and(|next| next.start < end && next.start < set.prefix.payload.len())
            {
                datagram.payload.spans().to_vec()
            } else {
                Vec::new()
            };
            set.parts.insert(
                index,
                Part {
                    preferred_spans,
                    start: info.offset,
                    end,
                    more: info.more,
                    pending: Some(std::mem::take(&mut datagram.payload)),
                },
            );
            if let Err(error) = set.extend_prefix(index) {
                set.disputed_at = Some(0);
                invalidate(None, set.verdict.take(), &set.packets);
                return Err(error);
            }
            let contiguous = set.prefix.payload.len();
            if let Some(total) = set.end {
                ready = contiguous == total;
                if ready {
                    let overhead = if key.ipv6 {
                        set.prefix.network_header_len.saturating_sub(48)
                    } else {
                        set.prefix.network_header_len
                    };
                    if total + overhead > 65_535 {
                        set.disputed_at = Some(0);
                        invalidate(None, set.verdict.take(), &set.packets);
                        return Ok(FragmentOutcome::Rejected(FragmentNotice {
                            code: "reassembled_ip_length_overflow",
                            packets: set.packets.clone(),
                        }));
                    }
                }
            }
            // The terminal fragment can establish a decisive length while a hole
            // remains. A new offset-zero witness can reuse a classification
            // only after the overlapping bytes and header metadata agree.
            let new_prefix = set
                .next_inspection_len
                .is_some_and(|next| contiguous >= next);
            if !ready
                && contiguous > 0
                && (new_prefix || learned_end || checksum_changed || (info.offset == 0 && !repeat))
            {
                if let Some(inspect) = observer {
                    let prefix = &mut set.prefix;
                    set_prefix_extent(prefix, set.end);
                    let (next, verdict) = inspect(prefix, &set.packets);
                    set.next_inspection_len = next.map(|n| n.max(contiguous + 1));
                    set.verdict = verdict;
                } else {
                    set.next_inspection_len = Some(1);
                    set.verdict = None;
                }
            }
        }
        if !ready {
            return Ok(FragmentOutcome::Pending);
        }
        let mut set = self
            .remove(&key)
            .ok_or_else(|| Error::limit("fragment_state"))?;
        set.restore_overlap_sources()?;
        set.prefix.declared_payload_len = set.prefix.payload.len();
        set.prefix.fragment = None;
        Ok(FragmentOutcome::Complete(set.prefix, set.packets))
    }
    pub fn finish(self) -> Vec<FragmentNotice> {
        self.finish_with(|notice, _| notice)
    }
    /// Retire every remaining set and its prefix decision together.
    pub fn finish_with<T>(self, mut retire: impl FnMut(FragmentNotice, Option<V>) -> T) -> Vec<T> {
        self.sets
            .into_values()
            .map(|set| {
                retire(
                    FragmentNotice {
                        code: if set.disputed_at.is_some() {
                            "fragment_quarantine_at_eof"
                        } else {
                            "incomplete_fragment_set_at_eof"
                        },
                        packets: set.packets,
                    },
                    set.verdict,
                )
            })
            .collect()
    }
}

impl<V> Assembly<V> {
    fn dispute(&self, conflict: Option<(&'static str, usize)>) -> Option<(&'static str, usize)> {
        match self.disputed_at {
            Some(bound) => Some((
                "fragment_set_quarantined",
                conflict.map_or(bound, |(_, new)| bound.min(new)),
            )),
            None => conflict,
        }
    }

    fn inspect_quarantine(
        &mut self,
        arrival: Datagram,
        info: &FragmentInfo,
        bound: usize,
        retain: bool,
        invalidate: &mut impl FnMut(Option<&Datagram>, Option<V>, &[PacketId]) -> Option<usize>,
    ) -> Result<usize> {
        self.disputed_at = Some(bound);
        let previous = self.verdict.take();
        let start = self.prefix.payload.len();
        let end = bound.min(info.offset + arrival.payload.len());
        let Some(next) = self.next_inspection_len.filter(|next| *next <= bound) else {
            invalidate(None, previous, &self.packets);
            return Ok(0);
        };
        if end <= start.max(info.offset) {
            invalidate(None, previous, &self.packets);
            return Ok(0);
        }
        // Keep a refused arrival transient. Admitted, out-of-order pieces can
        // supply the agreed prefix when a later arrival closes a hole.
        let index = self.parts.partition_point(|part| part.start <= info.offset);
        let part = Part {
            start: info.offset,
            end,
            more: info.more,
            pending: Some(arrival.payload.slice(0..end - info.offset)?),
            preferred_spans: Vec::new(),
        };
        let charged = if retain { end - info.offset } else { 0 };
        let mut transient;
        let prefix = if retain {
            self.parts.insert(index, part);
            update_metadata(&mut self.prefix, &arrival, info);
            self.extend_prefix(index)?;
            &mut self.prefix
        } else {
            if info.offset > start {
                invalidate(None, previous, &self.packets);
                return Ok(0);
            }
            transient = self.prefix.clone();
            update_metadata(&mut transient, &arrival, info);
            let pieces = self.parts[..index]
                .iter()
                .chain([&part])
                .chain(&self.parts[index..]);
            append_pending(&mut transient.payload, pieces, bound)?;
            &mut transient
        };
        let length = bound.min(prefix.payload.len());
        if length <= start || length < next {
            invalidate(None, previous, &self.packets);
            return Ok(charged);
        }
        // The bytes after the agreed prefix, including its terminal extent,
        // cannot influence the classifier. Never expose the result as complete.
        prefix.fragment = Some(FragmentInfo {
            id: info.id,
            offset: 0,
            more: true,
        });
        prefix.declared_payload_len = length + 1;
        let limited;
        let view = if length < prefix.payload.len() {
            limited = with_payload(prefix, prefix.payload.slice(0..length)?);
            &limited
        } else {
            &*prefix
        };
        self.next_inspection_len =
            invalidate(Some(view), previous, &self.packets).map(|n| n.max(length + 1));
        Ok(charged)
    }

    fn reusable_metadata(&self, d: &Datagram, info: &FragmentInfo) -> bool {
        self.verdict.is_some()
            && self.disputed_at.is_none()
            && !d.ipv6
            && info.offset == 0
            && info.more
            && d.protocol == self.prefix.protocol
            && d.network_header_len == self.prefix.network_header_len
            && d.ip_checksum == self.prefix.ip_checksum
            && d.checksum_context == self.prefix.checksum_context
            && self.end.is_none_or(|total| d.payload.len() < total)
            && d.payload.len() <= self.prefix.payload.len()
    }

    fn reusable_verdict(&self, d: &Datagram, info: &FragmentInfo) -> Option<&V> {
        if self.reusable_metadata(d, info)
            && self.prefix.payload.data().starts_with(d.payload.data())
        {
            self.verdict.as_ref()
        } else {
            None
        }
    }

    fn conflict(
        &self,
        datagram: &Datagram,
        info: &FragmentInfo,
        end: usize,
    ) -> Option<(&'static str, usize)> {
        if self
            .disputed_at
            .is_some_and(|bound| self.next_inspection_len.is_none_or(|next| next > bound))
        {
            return None;
        }
        // A fragment can violate more than one rule. V1 history records the
        // overlap verdict first, then a range violation, then a disputed end.
        let boundary = self
            .end
            .unwrap_or(65_535)
            .min(if info.more { 65_535 } else { end });
        let mut disagreement = None;
        for part in &self.parts {
            let start = info.offset.max(part.start);
            let stop = end.min(part.end).min(disagreement.unwrap_or(end));
            if start < stop {
                if datagram.ipv6 {
                    return Some(("ipv6_overlapping_fragments", start.min(boundary)));
                }
                let incoming = &datagram.payload.data()[start - info.offset..stop - info.offset];
                let retained =
                    &part.data(&self.prefix.payload)[start - part.start..stop - part.start];
                if incoming != retained {
                    let first = incoming
                        .iter()
                        .zip(retained)
                        .position(|(a, b)| a != b)
                        .unwrap();
                    disagreement = Some(start + first);
                }
            }
        }
        if let Some(first) = disagreement {
            return Some(("conflicting_fragment_bytes", first.min(boundary)));
        }
        let terminal = if info.more { self.end } else { Some(end) };
        if let Some(total) = terminal {
            if end > total
                || (info.more && end == total)
                || self
                    .parts
                    .iter()
                    .any(|p| p.end > total || (p.more && p.end == total))
            {
                return Some(("fragment_outside_terminal_length", boundary));
            }
        }
        if !info.more && self.end.is_some_and(|total| total != end) {
            return Some(("conflicting_fragment_terminal_length", boundary));
        }
        None
    }

    fn restore_overlap_sources(&mut self) -> Result<()> {
        if !self.parts.iter().any(|p| !p.preferred_spans.is_empty()) {
            return Ok(());
        }
        let prefix = &self.prefix.payload;
        let mut joined = EvidenceBytes::default();
        for part in &self.parts {
            let start = joined.len();
            if start >= part.end {
                continue;
            }
            if part.preferred_spans.is_empty() {
                joined.append(&prefix.slice(start..part.end)?, 65_535)?;
                continue;
            }
            for span in &part.preferred_spans {
                let a = start.max(part.start + span.start);
                let b = part.start + span.end;
                if a < b {
                    let bytes = EvidenceBytes::from_packet(
                        &prefix.data()[a..b],
                        span.packet,
                        span.packet_start + (a - part.start - span.start),
                    );
                    joined.append(&bytes, 65_535)?;
                }
            }
        }
        self.prefix.payload = joined;
        Ok(())
    }

    fn extend_prefix(&mut self, index: usize) -> Result<()> {
        let prefix = &mut self.prefix.payload;
        for part in &mut self.parts[index..] {
            if part.start > prefix.len() {
                break;
            }
            if let Some(bytes) = part.pending.take() {
                append_contiguous(prefix, part.start, bytes)?;
            }
        }
        Ok(())
    }

    /// A rejected arrival may close the gap inside a transport header. Inspect
    /// the available prefix once without retaining the arrival or delivering it.
    fn inspect_refused(
        &self,
        mut arrival: Datagram,
        info: &FragmentInfo,
        end: usize,
        packets: &[PacketId],
        inspect: &mut CachedPrefixObserver<'_, V>,
    ) -> Result<()> {
        let contiguous = self.prefix.payload.len();
        let extends = info.offset <= contiguous && end > contiguous;
        if !extends && info.more && info.offset != 0 {
            return Ok(());
        }
        let mut prefix = self.prefix.clone();
        update_metadata(&mut prefix, &arrival, info);
        if extends {
            append_contiguous(
                &mut prefix.payload,
                info.offset,
                std::mem::take(&mut arrival.payload),
            )?;
        }
        append_pending(&mut prefix.payload, &self.parts, 65_535)?;
        if prefix.payload.is_empty() {
            return Ok(());
        }
        set_prefix_extent(&mut prefix, self.end.or((!info.more).then_some(end)));
        inspect(&prefix, packets);
        Ok(())
    }
}

fn with_payload(template: &Datagram, payload: EvidenceBytes) -> Datagram {
    Datagram {
        scope: template.scope.clone(),
        fragment: template.fragment.clone(),
        payload,
        ..*template
    }
}

fn append_pending<'a>(
    prefix: &mut EvidenceBytes,
    parts: impl IntoIterator<Item = &'a Part>,
    bound: usize,
) -> Result<()> {
    for part in parts {
        if part.start > prefix.len() || prefix.len() >= bound {
            break;
        }
        let stop = part.end.min(bound);
        if stop > prefix.len() {
            if let Some(bytes) = &part.pending {
                prefix.append(
                    &bytes.slice(prefix.len() - part.start..stop - part.start)?,
                    65_535,
                )?;
            }
        }
    }
    Ok(())
}

fn append_contiguous(prefix: &mut EvidenceBytes, start: usize, bytes: EvidenceBytes) -> Result<()> {
    if prefix.is_empty() {
        *prefix = bytes;
    } else if start == prefix.len() {
        prefix.append(&bytes, 65_535)?;
    } else if start + bytes.len() > prefix.len() {
        prefix.append(&bytes.slice(prefix.len() - start..bytes.len())?, 65_535)?;
    }
    Ok(())
}

fn update_metadata(prefix: &mut Datagram, arrival: &Datagram, info: &FragmentInfo) {
    if info.offset == 0 {
        // RFC 8200 §4.5 gives the offset-zero fragment authority over Next Header.
        prefix.fragment = Some(info.clone());
        prefix.protocol = arrival.protocol;
        prefix.network_header_len = arrival.network_header_len;
    }
    if arrival.ip_checksum == Checksum::Invalid {
        prefix.ip_checksum = Checksum::Invalid;
    }
    if arrival.checksum_context == ChecksumContext::Unsupported {
        prefix.checksum_context = ChecksumContext::Unsupported;
    }
}

fn set_prefix_extent(prefix: &mut Datagram, end: Option<usize>) {
    if let Some(total) = end {
        prefix.fragment = None;
        prefix.declared_payload_len = total;
    } else {
        // At least one byte follows the contiguous part of an unfinished datagram.
        prefix.declared_payload_len = prefix.payload.len() + 1;
    }
}
