#[path = "support/bgp_profile_campaign.rs"]
mod campaign;

#[test]
fn bounded_wire_scope_and_truncation_preserve_valid_state() {
    for value in [0, 1, 255, 0x4271, u64::MAX] {
        campaign::wire_property(value, 32768, 1024 * 1024);
    }
}
#[test]
fn bounded_rib_source_path_generation_and_failure_are_isolated() {
    for value in [0, 1, u32::MAX as u64, u64::MAX] {
        campaign::rib_property(value, 32768, 1024 * 1024);
    }
}
#[test]
fn bounded_policy_preserves_early_winner_unknown_and_atomic_output() {
    for value in [0, 1, 999, u64::MAX] {
        campaign::policy_property(value, 32768, 1024 * 1024);
    }
}
#[test]
fn bounded_sealed_source_replays_and_tamper_is_rejected() {
    let scratch = campaign::Scratch::create(&std::env::temp_dir(), 12345);
    campaign::store_property(scratch.path(), 42, 32768, 1024 * 1024);
}
#[test]
fn deterministic_campaign_has_positive_and_negative_controls() {
    let r = campaign::run(
        campaign::DEFAULT_SEED,
        4,
        32768,
        1024 * 1024,
        60,
        &std::env::temp_dir(),
    );
    assert_eq!(r.iterations, 4);
    assert_eq!(r.negative_wire_cases, 192);
    assert!(r.disk_peak < campaign::DISK_CAP && r.elapsed_ms < 60_000);
}

#[test]
#[should_panic(expected = "offline policy invented endpoint authority")]
fn controlled_authority_mutant_reaches_the_terminal_oracle() {
    let mut result = campaign::policy_property(42, 32768, 1024 * 1024);
    result.endpoint_rib_established = true;
    campaign::assert_no_authority(&result);
}
