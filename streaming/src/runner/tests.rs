use super::*;

#[derive(Default)]
struct Events(Vec<Event>);
impl EventSink for Events {
    fn run_id(&self) -> &str {
        "fragment-verdict-test"
    }
    fn emit(&mut self, e: &Event) -> Result<u64> {
        self.0.push(e.clone());
        Ok(self.0.len() as u64)
    }
}

#[test]
fn provisional_rejection_and_quarantine_keep_the_original_transaction_witness() {
    let input = include_bytes!("../../../fixtures/semantics/modbus_fc23_split.pcap");
    let mut config = StreamConfig::default();
    config.base.checksum_policy = ChecksumPolicy::RequireValid;
    let registry = Registry::builtins(&config).unwrap();
    let namespace = sha256::digest(input);
    // Replay the same valid exchange on two interfaces. Apply the prefix
    // decisions directly so this test isolates the lifetime of the verdict.
    for (rejected, quarantined) in [(true, false), (false, true), (true, true)] {
        let mut reader =
            CaptureReader::new(&input[..], config.reader_limits(), config.base.parse_mode).unwrap();
        let mut events = Events::default();
        let mut state = State::new(&config, &registry, &mut events, namespace);
        let mut observed = None;
        let mut original_session = None;
        while let Some(record) = reader.next_record().unwrap() {
            let Some((meta, bytes)) = record.packet() else {
                continue;
            };
            state
                .packet(meta, bytes, record.offset(), Vec::new())
                .unwrap();
            let mut sibling = meta.clone();
            sibling.interface += 1;
            state
                .packet(&sibling, bytes, record.offset(), Vec::new())
                .unwrap();
            if meta.frame == 4 {
                let id = PacketId {
                    capture: namespace,
                    frame: 8,
                    record_offset: input.len() as u64,
                };
                let scope = Scope {
                    section: meta.section,
                    interface: meta.interface,
                    link_interface: None,
                    vlans: Vec::new(),
                };
                let raw = EvidenceBytes::from_packet(bytes, id, 0);
                let Decoded::Ip(datagram, path) =
                    network::decode(meta.link_type, &raw, scope).unwrap()
                else {
                    panic!("expected IP")
                };
                let (_, verdict) = PrefixVerdict::inspect(
                    &datagram,
                    &path,
                    0,
                    network::HeaderUse::Pending(ChecksumPolicy::Observe),
                );
                let PrefixVerdict::Pending(header) = verdict else {
                    panic!("expected a TCP header")
                };
                let (scope, path, segment, _) = &header.path;
                let (key, _) = Key::new(
                    scope.clone(),
                    path.clone(),
                    6,
                    segment.source,
                    segment.destination,
                );
                original_session = state.active[&key].flow_ids.get(&0).copied();
                observed = Some(header);
            }
        }
        let header = observed.unwrap();
        let id = header.path.3;
        let packets = [id];
        state
            .observe_tcp_header(
                header.path.clone(),
                id.frame,
                None,
                HeaderDisposition::AwaitingReassembly,
            )
            .unwrap();
        let verdict = if rejected {
            state
                .apply_pending_header(
                    header.path.clone(),
                    HeaderDisposition::RejectedPrefix,
                    &packets,
                    9,
                    None,
                )
                .unwrap();
            PrefixVerdict::Rejected(header)
        } else {
            PrefixVerdict::Pending(header)
        };
        if quarantined {
            verdict.invalidate(&mut state.active, &packets);
        }
        state.finish().unwrap();
        let session = original_session.unwrap();
        let mappings: Vec<_> = events
            .0
            .iter()
            .filter(|e| {
                e.kind == EventKind::Transaction && e.data.encode().contains("read_mapping")
            })
            .map(|e| e.session.unwrap())
            .collect();
        assert_eq!(mappings.contains(&session), !quarantined);
        assert_eq!(mappings.iter().filter(|s| **s != session).count(), 1);
        let uncertain: Vec<_> = events
            .0
            .iter()
            .filter(|e| e.data.encode().contains("tcp_generation_payload_uncertain"))
            .collect();
        assert_eq!(uncertain.len(), usize::from(quarantined));
        if let Some(e) = uncertain.first() {
            assert_eq!(e.session, Some(session));
            assert_eq!(e.evidence.packets, packets);
        }
    }
}
