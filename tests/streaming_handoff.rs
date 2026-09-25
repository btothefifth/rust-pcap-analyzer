//! Root-crate compatibility regressions for the guarded handoff patch.
use pcap_evidence::{
    cli_ports::extend_ports,
    detection,
    engine::{analyze, Config},
    index::VerifiedIndex,
    Limits,
};
#[test]
fn repeated_and_csv_ports_share_transactional_semantics() {
    let mut p = vec![20000];
    extend_ports(&mut p, "20001,20002", true).unwrap();
    extend_ports(&mut p, "20002,20003", false).unwrap();
    assert_eq!(p, vec![20001, 20002, 20003]);
}
#[test]
fn invalid_port_does_not_partially_update() {
    let mut p = vec![502];
    assert!(extend_ports(&mut p, "503,65536", true).is_err());
    assert_eq!(p, vec![502]);
}
#[test]
fn empty_port_list_is_usage_error() {
    let mut p = vec![502];
    assert!(extend_ports(&mut p, "", true).is_err());
    assert_eq!(p, vec![502]);
}
#[test]
fn root_engine_recognizes_modbus_without_configured_fixture_port() {
    let config = Config {
        modbus_ports: vec![65001],
        dnp3_ports: vec![65002],
        ..Config::default()
    };
    let analysis = analyze(include_bytes!("fixtures/modbus_tcp.pcap"), config).unwrap();
    assert!(analysis.applications.iter().any(|a| a.protocol == "modbus"));
    assert!(analysis
        .flows
        .iter()
        .any(|f| detection::classify_flow(f, &analysis.config).unwrap().basis == "content"));
}
#[test]
fn timestamp_secondary_index_preserves_file_order_and_unknowns() {
    let source = include_bytes!("fixtures/mixed_sections.pcapng");
    let index = VerifiedIndex::build(source, Limits::default()).unwrap();
    for (start, end) in [(i128::MIN, i128::MAX), (0, 1_000_000_000), (0, 0)] {
        let q = index.time_range(start, end).unwrap();
        let mut frames = vec![];
        let mut unresolved = vec![];
        for e in index.index().entries() {
            match e.packet.timestamp.and_then(|t| t.unix_nanos().ok()) {
                Some(t) if start <= t && t <= end => frames.push(e.packet.frame),
                None => unresolved.push(e.packet.frame),
                _ => {}
            }
        }
        assert_eq!(q.frames, frames);
        assert_eq!(q.unresolved_frames, unresolved);
    }
}
