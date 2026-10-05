mod support {
    pub mod tiny_capture;
}
use pcap_evidence_history::{
    analyze_file,
    journal::{self, Reader, Writer},
    query::History,
    recover_file, verify_file, Cancellation, Config, ErrorCode,
};
use std::fs;
use support::tiny_capture::{capture, routed_ipv4, sll2, tcp, tunneled, Temp};

#[test]
fn unsupported_checksum_operands_survive_history_journal_and_query_projection() {
    for outer_udp in [false, true] {
        let temp = Temp::new();
        let packets = [tcp(false, 100, 0, 2, &[]), tcp(false, 101, 0, 0x18, b"abc")];
        let mut routed: Vec<_> = packets
            .iter()
            .map(|packet| {
                if outer_udp {
                    let mut outer = tunneled("vxlan", 7, false, packet);
                    outer[40..42].copy_from_slice(&1u16.to_be_bytes());
                    routed_ipv4(&outer)
                } else {
                    routed_ipv4(packet)
                }
            })
            .collect();
        let ordinary = tcp(false, 104, 0, 0x18, b"def");
        routed.push(if outer_udp {
            tunneled("vxlan", 7, false, &ordinary)
        } else {
            ordinary
        });
        let source = temp.source(&routed);
        let workspace = temp.0.join("history");
        analyze_file(
            &source,
            &workspace,
            Config::default(),
            &Cancellation::default(),
        )
        .unwrap();
        let wanted = if outer_udp {
            "unsupported_outer_udp_checksum_operands"
        } else {
            "unsupported_transport_checksum_operands"
        };
        let mut reader = Reader::open(&workspace.join("journal.bin")).unwrap();
        let mut notices = Vec::new();
        while let Some(record) = reader.next_record().unwrap() {
            if record.kind == journal::NOTICE {
                notices.push(
                    pcap_evidence_history::codec::Decoder::new(&record.body)
                        .text(2048)
                        .unwrap(),
                );
            }
        }
        assert_eq!(
            notices
                .iter()
                .filter(|notice| notice.as_str() == wanted)
                .count(),
            2
        );
        let mut history = History::open(&source, &workspace).unwrap();
        let generation = history.generations(None, 10).unwrap()[0];
        let range = history.range(generation, 0, 0, 3).unwrap().encode();
        assert!(range.contains("616263"));
        if !outer_udp {
            assert!(range.contains(wanted));
        }
        let ordinary_range = history.range(generation, 0, 3, 6).unwrap().encode();
        assert!(ordinary_range.contains("646566"));
        assert!(!ordinary_range.contains(wanted));
        assert!(!ordinary_range.contains("invalid_tcp_checksum"));
        verify_file(
            &source,
            &workspace,
            &temp.0.join("replay"),
            &Cancellation::default(),
        )
        .unwrap();
    }
}

#[test]
fn sll2_link_interfaces_remain_separate_through_spill_journal_and_replay() {
    let temp = Temp::new();
    let mut bytes = capture(&[
        sll2(7, &tcp(false, 100, 0, 2, &[])),
        sll2(8, &tcp(false, 100, 0, 2, &[])),
        sll2(7, &tcp(false, 101, 0, 0x18, b"one")),
        sll2(8, &tcp(false, 101, 0, 0x18, b"two")),
    ]);
    bytes[20..24].copy_from_slice(&276u32.to_le_bytes());
    let source = temp.0.join("source.pcap");
    fs::write(&source, bytes).unwrap();
    let workspace = temp.0.join("history");
    let config = Config {
        hot_tuples: 1,
        ..Config::default()
    };
    analyze_file(&source, &workspace, config, &Cancellation::default()).unwrap();
    let mut history = History::open(&source, &workspace).unwrap();
    let generations = history.generations(None, 10).unwrap();
    assert_eq!(generations.len(), 2);
    let mut payloads = Vec::new();
    for generation in generations {
        let range = history.range(generation, 0, 0, 3).unwrap().encode();
        assert!(!range.contains("conflicting_bytes"));
        assert!(range.contains("6f6e65") ^ range.contains("74776f"));
        payloads.push(range);
    }
    assert!(payloads.iter().any(|range| range.contains("6f6e65")));
    assert!(payloads.iter().any(|range| range.contains("74776f")));
    verify_file(
        &source,
        &workspace,
        &temp.0.join("replay"),
        &Cancellation::default(),
    )
    .unwrap();
}

#[test]
fn reverse_tunnel_directions_share_generation_and_distinct_tunnels_do_not() {
    for kind in ["gre", "vxlan", "geneve"] {
        let temp = Temp::new();
        let source = temp.source(&[
            tunneled(kind, 1, false, &tcp(false, 100, 0, 2, &[])),
            tunneled(kind, 1, true, &tcp(true, 200, 101, 0x12, &[])),
            tunneled(kind, 1, false, &tcp(false, 101, 201, 0x18, b"abc")),
            tunneled(kind, 1, true, &tcp(true, 201, 104, 0x18, b"xyz")),
            tunneled(kind, 2, false, &tcp(false, 100, 0, 2, &[])),
            tunneled(kind, 2, false, &tcp(false, 101, 0, 0x18, b"new")),
        ]);
        let workspace = temp.0.join("history");
        analyze_file(
            &source,
            &workspace,
            Config::default(),
            &Cancellation::default(),
        )
        .unwrap();
        let mut history = History::open(&source, &workspace).unwrap();
        let generations = history.generations(None, 10).unwrap();
        assert_eq!(generations.len(), 2, "{kind}: one generation per tunnel");
        let mut matched = 0;
        for generation in generations {
            let forward = history.range(generation, 0, 0, 3).unwrap().encode();
            let reverse = history.range(generation, 1, 0, 3).unwrap().encode();
            if forward.contains("616263") {
                assert!(
                    reverse.contains("78797a"),
                    "{kind}: reverse bytes in same generation"
                );
                matched += 1;
            } else {
                assert!(forward.contains("6e6577"));
                assert!(!reverse.contains("78797a"));
            }
        }
        assert_eq!(matched, 1);
        verify_file(
            &source,
            &workspace,
            &temp.0.join("replay"),
            &Cancellation::default(),
        )
        .unwrap();
    }
}

#[test]
fn recovery_requires_eof_after_seal_even_when_torn_tail_is_authorized() {
    for allow_torn in [false, true] {
        let temp = Temp::new();
        let source = temp.source(&[tcp(false, 100, 0, 2, &[]), tcp(false, 101, 0, 0x18, b"abc")]);
        let old = temp.0.join("old");
        analyze_file(&source, &old, Config::default(), &Cancellation::default()).unwrap();
        let journal_path = old.join("journal.bin");
        let mut bytes = fs::read(&journal_path).unwrap();
        bytes.extend_from_slice(&[0; 4]);
        fs::write(journal_path, bytes).unwrap();
        let new = temp.0.join("new");
        let error =
            recover_file(&source, &old, &new, allow_torn, &Cancellation::default()).unwrap_err();
        assert_eq!(error.field, "history_terminal");
        assert!(!new.exists());
    }
}

#[test]
fn recovery_requires_eof_after_abort_and_replays_a_clean_abort_prefix() {
    let temp = Temp::new();
    let source = temp.source(&[tcp(false, 100, 0, 2, &[])]);
    let sealed = temp.0.join("sealed");
    analyze_file(
        &source,
        &sealed,
        Config::default(),
        &Cancellation::default(),
    )
    .unwrap();
    let header = Reader::open(&sealed.join("journal.bin")).unwrap().header;
    let old = temp.0.join("old");
    fs::create_dir(&old).unwrap();
    let mut writer = Writer::create(
        &old.join("journal.bin"),
        header.source,
        header.config,
        journal::quota(65536),
    )
    .unwrap();
    writer.append(journal::ABORT, &[]).unwrap();
    drop(writer);
    recover_file(
        &source,
        &old,
        &temp.0.join("clean"),
        false,
        &Cancellation::default(),
    )
    .unwrap();
    let path = old.join("journal.bin");
    let mut bytes = fs::read(&path).unwrap();
    bytes.push(0);
    fs::write(path, bytes).unwrap();
    let error = recover_file(
        &source,
        &old,
        &temp.0.join("bad"),
        true,
        &Cancellation::default(),
    )
    .unwrap_err();
    assert_eq!(error.field, "history_terminal");
}

#[test]
fn skipped_intervals_charge_scan_and_work_budgets() {
    let temp = Temp::new();
    let source = temp.source(&[
        tcp(false, 100, 0, 2, &[]),
        tcp(false, 101, 0, 0x18, b"x"),
        tcp(false, 101, 0, 0x18, b"x"),
        tcp(false, 101, 0, 0x18, b"x"),
    ]);
    let workspace = temp.0.join("history");
    analyze_file(
        &source,
        &workspace,
        Config::default(),
        &Cancellation::default(),
    )
    .unwrap();
    let mut history = History::open(&source, &workspace).unwrap();
    let generation = history.generations(None, 10).unwrap()[0];
    history.config.max_query_intervals = 2;
    let error = history.range(generation, 0, 1, 2).unwrap_err();
    assert_eq!(error.code, ErrorCode::LimitExceeded);
    assert_eq!(error.field, "query_scan");
    history.config.max_query_intervals = 3;
    history.config.max_query_work = (2 * pcap_evidence_history::index::WIDTH) as u64;
    let error = history.range(generation, 0, 1, 2).unwrap_err();
    assert_eq!(error.field, "query_work");
    history.config.max_query_work = (3 * pcap_evidence_history::index::WIDTH) as u64;
    let result = history.range(generation, 0, 1, 2).unwrap().encode();
    assert!(result.contains("gap"));
    assert!(!result.contains("\"packet\""));
}
