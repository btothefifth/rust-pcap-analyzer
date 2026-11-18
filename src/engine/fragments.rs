//! TCP observations that may change while snapshot IP reassembly is pending.
use crate::fragment::{FragmentNotice, FragmentOutcome, FragmentReassembler};
use crate::provenance::PacketId;
use crate::tcp::{HeaderDisposition, TcpTracker};
use crate::wire::{self, ChecksumPolicy, Datagram, Scope, TcpHeader};
use crate::{ErrorCode, Limits, Result};

#[derive(Clone)]
struct Prefix {
    scope: Scope,
    header: TcpHeader,
    disposition: HeaderDisposition,
}

impl Prefix {
    fn inspect(datagram: &Datagram, policy: ChecksumPolicy) -> Result<Option<(PacketId, Self)>> {
        Ok(wire::inspect_tcp_header(datagram)?.map(|observation| {
            let disposition = if observation.pending_extent(policy).is_some() {
                HeaderDisposition::AwaitingReassembly
            } else {
                HeaderDisposition::RejectedPrefix
            };
            (
                observation.packet,
                Self {
                    scope: datagram.scope.clone(),
                    header: observation.header,
                    disposition,
                },
            )
        }))
    }

    fn reversible(&self) -> bool {
        self.header.payload_len == Some(0) || self.disposition == HeaderDisposition::RejectedPrefix
    }

    fn invalidate(&self, tracker: &mut TcpTracker, packets: &[PacketId]) {
        tracker.invalidate_reassembly_extent(&self.scope, self.header, packets);
    }

    fn retire(self, tracker: &mut TcpTracker, packets: &[PacketId]) {
        if self.disposition == HeaderDisposition::RejectedPrefix {
            tracker.resolve_reassembly(self.scope, self.header, packets);
        }
    }
}

pub(super) struct SnapshotFragments {
    sets: FragmentReassembler<Prefix>,
    policy: ChecksumPolicy,
}

impl SnapshotFragments {
    pub(super) fn new(limits: Limits, policy: ChecksumPolicy) -> Self {
        Self {
            sets: FragmentReassembler::with_prefix_cache(limits),
            policy,
        }
    }

    pub(super) fn expire(&mut self, frame: u64, tracker: &mut TcpTracker) -> Vec<FragmentNotice> {
        self.sets.expire_with(frame, |notice, prefix| {
            if let Some(prefix) = prefix {
                prefix.retire(tracker, &notice.packets);
            }
            notice
        })
    }

    pub(super) fn finish(self) -> Vec<FragmentNotice> {
        // The tracker finishes immediately afterwards and ignores rejected prefixes.
        self.sets.finish()
    }

    pub(super) fn push(
        &mut self,
        datagram: Datagram,
        frame: u64,
        time: Option<i128>,
        tracker: &mut TcpTracker,
    ) -> Result<FragmentOutcome> {
        if datagram.fragment.is_none() {
            return self.sets.push_caching_prefix(datagram, frame, &[], None);
        }
        // The arriving packet keeps its own identity even when identical bytes
        // inherit the set's earlier checksum or length decision.
        let mut arriving = Prefix::inspect(&datagram, self.policy).ok().flatten();
        if let (Some((_, current)), Some(cached)) =
            (&mut arriving, self.sets.cached_prefix(&datagram))
        {
            *current = cached.clone();
        }
        let previously_rejected = self
            .sets
            .last_prefix_verdict(&datagram)
            .filter(|v| v.disposition == HeaderDisposition::RejectedPrefix)
            .cloned();
        let mut inspect = |prefix: &Datagram, contributors: &[PacketId]| match Prefix::inspect(
            prefix,
            self.policy,
        ) {
            Ok(Some((packet, verdict))) => {
                if previously_rejected.is_some() || verdict.reversible() {
                    tracker.set_reassembly_prefix_rejected(
                        &verdict.scope,
                        verdict.header,
                        contributors,
                        verdict.disposition == HeaderDisposition::RejectedPrefix,
                    );
                }
                let witness = arriving.as_ref().map_or(packet, |(id, _)| *id);
                let cached = verdict.reversible().then(|| verdict.clone());
                arriving = Some((witness, verdict));
                (None, cached)
            }
            Ok(None) => (None, None),
            Err(e) => (
                (e.code == ErrorCode::Truncated).then(|| prefix.payload.len() + 1),
                None,
            ),
        };
        let mut quarantined = false;
        let mut disputed = None;
        let outcome = self.sets.push_with_invalidation(
            datagram,
            frame,
            &[],
            Some(&mut inspect),
            |_, previous, _| {
                quarantined = true;
                disputed = previous;
            },
        )?;
        if let FragmentOutcome::Complete(_, packets) = &outcome {
            if let Some(prefix) = previously_rejected {
                prefix.retire(tracker, packets);
            }
        } else {
            if let (FragmentOutcome::Rejected(notice), Some(prefix)) = (&outcome, disputed) {
                prefix.invalidate(tracker, &notice.packets);
            }
            if let Some((packet, mut prefix)) = arriving {
                if quarantined {
                    prefix.disposition = HeaderDisposition::AwaitingReassembly;
                    prefix.header.payload_len = None;
                }
                tracker.observe_header(
                    prefix.scope,
                    packet,
                    time,
                    prefix.header,
                    prefix.disposition,
                )?;
            }
        }
        Ok(outcome)
    }
}

#[cfg(test)]
mod tests;
