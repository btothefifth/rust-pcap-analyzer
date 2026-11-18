use super::*;
use crate::capture::CaptureIter;
use crate::correlate::transactions_with_flows;
use crate::engine::{analyze, Config};
use crate::provenance::EvidenceBytes;
use crate::wire::{ChecksumContext, FragmentInfo, Transport};

#[test]
fn pending_checksum_verdict_keeps_its_capture_witness_until_retirement() {
    let input = include_bytes!("../../../fixtures/semantics/modbus_fc23_split.pcap");
    let config = Config {
        checksum_policy: ChecksumPolicy::RequireValid,
        ..Config::default()
    };
    let clean = analyze(input, config.clone()).unwrap();
    let mut apps = clean.applications().to_vec();
    // The two logical interfaces carry the same intact request and response.
    apps.extend(clean.applications().iter().cloned().map(|mut a| {
        a.flow = 1;
        a
    }));
    for (disputed, expire) in [(false, false), (true, false), (false, true)] {
        let mut tracker = TcpTracker::new(config.limits.clone(), config.idle_timeout_ns).unwrap();
        let mut fragments = SnapshotFragments::new(config.limits.clone(), config.checksum_policy);
        let mut request = None;
        for record in CaptureIter::new(input, config.limits.clone(), config.parse_mode).unwrap() {
            let record = record.unwrap();
            let Some((meta, bytes)) = record.packet() else {
                continue;
            };
            let id = PacketId {
                capture: clean.capture_sha256,
                frame: meta.frame,
                record_offset: record.offset(),
            };
            for interface in 0..2 {
                let scope = Scope {
                    section: meta.section,
                    interface,
                    link_interface: None,
                    vlans: vec![],
                };
                let datagram =
                    wire::decode_packet(meta.link_type, bytes, id, scope.clone()).unwrap();
                let Transport::Tcp(segment) =
                    wire::decode_transport(&datagram, config.checksum_policy).unwrap()
                else {
                    panic!("fixture must contain a TCP exchange");
                };
                tracker.ingest(scope, id, None, segment).unwrap();
                if meta.frame == 4 && interface == 0 {
                    request = Some(datagram);
                }
            }
        }

        // Model two observations with identical TCP bytes and different
        // checksum metadata, then supply the reassembler's terminal decision.
        let witness = PacketId {
            capture: clean.capture_sha256,
            frame: 8,
            record_offset: input.len() as u64,
        };
        let repeat = PacketId {
            frame: 9,
            record_offset: witness.record_offset + 128,
            ..witness
        };
        let mut d = request.unwrap();
        d.fragment = Some(FragmentInfo {
            id: 1,
            offset: 0,
            more: true,
        });
        let mut packets = Vec::new();
        for (id, context) in [
            (witness, ChecksumContext::BaseAddresses),
            (repeat, ChecksumContext::Unsupported),
        ] {
            d.checksum_context = context;
            d.payload = EvidenceBytes::from_packet(d.payload.data(), id, 0);
            assert!(matches!(
                fragments
                    .push(d.clone(), id.frame, None, &mut tracker)
                    .unwrap(),
                FragmentOutcome::Pending
            ));
            packets.push(id);
        }
        let retained = fragments
            .sets
            .last_prefix_verdict(&d)
            .expect("pending rejection must remain reversible");
        assert!(retained.disposition == HeaderDisposition::RejectedPrefix);
        if disputed {
            retained.invalidate(&mut tracker, &packets);
        } else if expire {
            let header = retained.header;
            assert_eq!(fragments.expire(u64::MAX, &mut tracker).len(), 1);
            assert_eq!(tracker.provisional_count(d.scope, header, &packets), 0);
        }
        let flows = tracker.finish(config.overlap_policy).unwrap();
        assert_eq!(flows[0].uncertain_payload, disputed.then_some(witness));
        assert_eq!(flows[1].uncertain_payload, None);
        let mut snapshot = clean.clone();
        snapshot.transactions = transactions_with_flows(&apps, &config.limits, &flows).unwrap();
        snapshot.flows = flows;
        snapshot.applications.clone_from(&apps);
        let pairs: Vec<_> = snapshot
            .transactions
            .iter()
            .filter(|t| t.status == "candidate_pair")
            .map(|t| t.flow)
            .collect();
        let rendered = crate::report::analysis(&snapshot, false).encode();
        assert_eq!(rendered.matches("\"read_mapping\":").count(), pairs.len());
        assert_eq!(pairs, if disputed { vec![1] } else { vec![0, 1] });
    }
}
