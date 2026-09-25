//! Bounded IP fragment reconstruction. Missing bytes are never synthesized.
use crate::provenance::{EvidenceBytes, PacketId};
use crate::wire::{Checksum, Datagram, Scope};
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
struct Part {
    start: usize,
    more: bool,
    bytes: EvidenceBytes,
}
struct Assembly {
    template: Datagram,
    parts: Vec<Part>,
    end: Option<usize>,
    first_frame: u64,
    packets: Vec<PacketId>,
    poisoned: bool,
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
pub struct FragmentReassembler {
    sets: BTreeMap<Key, Assembly>,
    deadlines: BTreeSet<(u64, Key)>,
    retained: usize,
    limits: Limits,
}
impl FragmentReassembler {
    pub fn new(limits: Limits) -> Self {
        Self {
            sets: BTreeMap::new(),
            deadlines: BTreeSet::new(),
            retained: 0,
            limits,
        }
    }
    pub fn expire(&mut self, frame: u64) -> Vec<FragmentNotice> {
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
                notices.push(FragmentNotice {
                    code: "fragment_expired",
                    packets: assembly.packets,
                });
            }
        }
        notices
    }
    fn remove(&mut self, key: &Key) -> Option<Assembly> {
        let a = self.sets.remove(key)?;
        if let Some(deadline) = a
            .first_frame
            .checked_add(self.limits.fragment_frame_lifetime)
            .and_then(|n| n.checked_add(1))
        {
            self.deadlines.remove(&(deadline, key.clone()));
        }

        let size: usize = a.parts.iter().map(|p| p.bytes.len()).sum();
        self.retained -= size;
        Some(a)
    }
    pub fn push(&mut self, mut datagram: Datagram, frame: u64) -> Result<FragmentOutcome> {
        self.limits.validate()?;
        let info = match datagram.fragment.clone() {
            Some(x) => x,
            None => {
                let ids = datagram.payload.packets();
                return Ok(FragmentOutcome::Complete(datagram, ids));
            }
        };
        let key = Key {
            scope: datagram.scope.clone(),
            source: datagram.source,
            destination: datagram.destination,
            protocol: if datagram.ipv6 { 0 } else { datagram.protocol },
            id: info.id,
            ipv6: datagram.ipv6,
        };
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
        admitted_packets.extend(datagram.payload.packets());
        admitted_packets.sort();
        admitted_packets.dedup();
        if admitted_packets.len() > self.limits.max_fragments_per_set
            || existing.is_some_and(|set| set.parts.len() >= self.limits.max_fragments_per_set)
        {
            return Err(Error::limit("fragments_per_set"));
        }
        let new_size = if existing.is_some_and(|set| set.poisoned) {
            self.retained
        } else {
            self.retained
                .checked_add(datagram.payload.len())
                .ok_or_else(|| Error::limit("fragment_payload"))?
        };
        if new_size > self.limits.max_retained_payload {
            return Err(Error::limit("fragment_payload"));
        }
        if !self.sets.contains_key(&key) {
            if self.sets.len() >= self.limits.max_fragment_sets {
                return Err(Error::limit("fragment_sets"));
            }

            // Copy fixed metadata, not a full payload that is immediately discarded.
            let template = Datagram {
                scope: datagram.scope.clone(),
                source: datagram.source,
                destination: datagram.destination,
                protocol: datagram.protocol,
                ipv6: datagram.ipv6,
                network_header_len: datagram.network_header_len,
                fragment: datagram.fragment.clone(),
                payload: EvidenceBytes::default(),
                ip_checksum: datagram.ip_checksum,
            };
            if let Some(deadline) = frame
                .checked_add(self.limits.fragment_frame_lifetime)
                .and_then(|n| n.checked_add(1))
            {
                self.deadlines.insert((deadline, key.clone()));
            }

            self.sets.insert(
                key.clone(),
                Assembly {
                    template,
                    parts: Vec::new(),
                    end: None,
                    first_frame: frame,
                    packets: Vec::new(),
                    poisoned: false,
                },
            );
        }
        let mut rejection = None;
        let mut ready = false;
        {
            let set = self
                .sets
                .get_mut(&key)
                .ok_or_else(|| Error::limit("fragment_state"))?;
            set.packets = admitted_packets;
            if set.poisoned {
                return Ok(FragmentOutcome::Rejected(FragmentNotice {
                    code: "fragment_set_quarantined",
                    packets: set.packets.clone(),
                }));
            }
            if datagram.ip_checksum == Checksum::Invalid {
                set.template.ip_checksum = Checksum::Invalid;
            }
            if info.offset == 0 {
                // RFC 8200 4.5: IPv6 nonzero fragments may advertise different
                // Next Header values. Offset zero owns the reassembled value.
                set.template.protocol = datagram.protocol;

                set.template.network_header_len = datagram.network_header_len;
            }
            if !info.more {
                if set.end.is_some_and(|old| old != end) {
                    rejection = Some("conflicting_fragment_terminal_length");
                }
                set.end = Some(end);
            }
            if let Some(total) = set.end {
                if end > total
                    || (info.more && end >= total)
                    || set.parts.iter().any(|p| {
                        p.start + p.bytes.len() > total
                            || (p.more && p.start + p.bytes.len() >= total)
                    })
                {
                    rejection = Some("fragment_outside_terminal_length");
                }
            }
            for previous in &set.parts {
                let a = previous.start.max(info.offset);
                let b = (previous.start + previous.bytes.len()).min(end);
                if a < b {
                    if key.ipv6 {
                        rejection = Some("ipv6_overlapping_fragments");
                    } else if previous.bytes.data()[a - previous.start..b - previous.start]
                        != datagram.payload.data()[a - info.offset..b - info.offset]
                    {
                        rejection = Some("conflicting_fragment_bytes");
                    }
                }
            }
            if let Some(code) = rejection {
                set.poisoned = true;
                return Ok(FragmentOutcome::Rejected(FragmentNotice {
                    code,
                    packets: set.packets.clone(),
                }));
            }

            self.retained = new_size;
            set.parts.push(Part {
                start: info.offset,
                more: info.more,
                bytes: std::mem::take(&mut datagram.payload),
            });
            set.parts.sort_by_key(|p| p.start);
            if let Some(total) = set.end {
                let mut cursor = 0;
                for part in &set.parts {
                    if part.start > cursor {
                        break;
                    }
                    cursor = cursor.max(part.start + part.bytes.len());
                }
                ready = cursor == total;
                if ready {
                    let overhead = if key.ipv6 {
                        set.template.network_header_len.saturating_sub(48)
                    } else {
                        set.template.network_header_len
                    };
                    if total + overhead > 65_535 {
                        set.poisoned = true;
                        return Ok(FragmentOutcome::Rejected(FragmentNotice {
                            code: "reassembled_ip_length_overflow",
                            packets: set.packets.clone(),
                        }));
                    }
                }
            }
        }
        if !ready {
            return Ok(FragmentOutcome::Pending);
        }
        let mut set = self
            .remove(&key)
            .ok_or_else(|| Error::limit("fragment_state"))?;
        let mut joined = EvidenceBytes::default();
        for part in &set.parts {
            let skip = joined
                .len()
                .saturating_sub(part.start)
                .min(part.bytes.len());
            if skip < part.bytes.len() {
                joined.append(&part.bytes.slice(skip..part.bytes.len())?, 65_535)?;
            }
        }
        set.template.payload = joined;
        set.template.fragment = None;
        Ok(FragmentOutcome::Complete(set.template, set.packets))
    }
    pub fn finish(mut self) -> Vec<FragmentNotice> {
        let sets = std::mem::take(&mut self.sets);
        sets.into_values()
            .map(|set| FragmentNotice {
                code: if set.poisoned {
                    "fragment_quarantine_at_eof"
                } else {
                    "incomplete_fragment_set_at_eof"
                },
                packets: set.packets,
            })
            .collect()
    }
}
