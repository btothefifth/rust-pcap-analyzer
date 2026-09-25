use pcap_evidence::{
    engine::{self, Config},
    report,
};
fn capture(name: &str) -> Vec<u8> {
    std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("fixtures/semantics")
            .join(name),
    )
    .unwrap()
}
#[test]
fn snapshot_modbus_semantic_fields_reach_actual_report() {
    let a = engine::analyze(&capture("modbus_bits_valid.pcap"), Config::default()).unwrap();
    assert!(a.transactions.iter().any(|t| t.status == "candidate_pair"));
    let j = report::analysis(&a, false).encode();
    assert!(j.contains("pcap-evidence.modbus-alternatives.v1"));
    assert!(j.contains("starting_address_zero_based"));
    assert!(j.contains("packed_lsb_first"));
}
#[test]
fn snapshot_padding_bad_response_does_not_pair_as_consistent() {
    let a = engine::analyze(&capture("modbus_bits_bad_padding.pcap"), Config::default()).unwrap();
    assert!(a
        .transactions
        .iter()
        .any(|t| t.status == "inconsistent_response"));
    assert!(!a.transactions.iter().any(|t| t.status == "candidate_pair"));
}
#[test]
fn snapshot_dnp_split_reordered_duplicate_retains_semantic_objects() {
    let a = engine::analyze(&capture("dnp3_split_valid.pcap"), Config::default()).unwrap();
    let j = report::analysis(&a, false).encode();
    assert!(j.contains("object_semantic_subset"));
    assert!(j.contains("function_name"));
    assert!(j.contains("control_semantics"));
    assert!(j.contains("confirmed_user_data") || j.contains("unconfirmed_user_data"));
    assert!(j.contains("\"broadcast\":false"));
    assert!(j.contains("message_object_semantic_subset"));
    assert!(j.contains("lsb_zero_bit_position"));
    assert!(j.contains("\"value\":\"9\""));
}
#[test]
fn snapshot_dnp_gap_or_conflict_cannot_create_response_values() {
    for name in ["dnp3_split_gap.pcap", "dnp3_split_conflict.pcap"] {
        let a = engine::analyze(&capture(name), Config::default()).unwrap();
        let j = report::analysis(&a, false).encode();
        assert!(!j.contains("lsb_zero_bit_position"));
        assert!(a.has_diagnostics());
    }
}
#[test]
fn snapshot_semantic_extension_output_is_deterministic() {
    let b = capture("dnp3_split_valid.pcap");
    let a = engine::analyze(&b, Config::default()).unwrap();
    let c = engine::analyze(&b, Config::default()).unwrap();
    assert_eq!(report::analysis(&a, false), report::analysis(&c, false));
}
