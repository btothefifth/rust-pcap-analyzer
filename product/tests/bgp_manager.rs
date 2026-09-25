use pcap_evidence::{
    provenance::{EvidenceBytes, PacketId},
    sha256, ErrorCode,
};
use pcap_evidence_product::deep::{
    bgp::PcapMetadata, bgp_manager::CapturedSessionManager,
    bgp_session::ApplyStatus as SessionApplyStatus, Limits,
};

fn capture() -> [u8; 32] {
    sha256::digest(b"bgp-manager-capture-namespace")
}

fn keepalive(frame: u64) -> EvidenceBytes {
    let mut bytes = vec![255; 16];
    bytes.extend_from_slice(&19u16.to_be_bytes());
    bytes.push(4);
    EvidenceBytes::from_packet(
        &bytes,
        PacketId {
            capture: capture(),
            frame,
            record_offset: frame * 100,
        },
        54,
    )
}

fn metadata(session: u64, frame: u64) -> PcapMetadata {
    PcapMetadata {
        source_id: "capture-a".into(),
        record_id: format!("event-{frame}"),
        observed_at_ns: None,
        session: Some(session),
        direction: Some(0),
        peer: None,
        local: None,
    }
}

#[test]
fn sessions_gaps_and_lifecycle_are_isolated() {
    let mut manager =
        CapturedSessionManager::new(capture(), "capture-a".into(), Limits::default()).unwrap();
    manager
        .observe_gap(7, "gap-1".into(), "missing TCP bytes".into())
        .unwrap();
    manager
        .apply_message(8, &keepalive(2), metadata(8, 2))
        .unwrap();

    let first = manager.summary(7).unwrap();
    let second = manager.summary(8).unwrap();
    assert_eq!((first.gaps, first.session_events), (1, 1));
    assert_eq!((second.gaps, second.session_events), (0, 1));
    assert_eq!(manager.active_sessions(), 2);

    assert_eq!(manager.end_session(7).unwrap(), first);
    assert!(!manager.contains(7));
    assert!(manager.contains(8));
    assert_eq!(manager.clear(), [second]);
    assert_eq!(manager.active_sessions(), 0);
}

#[test]
fn explicit_reset_and_exact_replay_are_owned_per_session() {
    let mut manager =
        CapturedSessionManager::new(capture(), "capture-a".into(), Limits::default()).unwrap();
    manager
        .apply_message(3, &keepalive(1), metadata(3, 1))
        .unwrap();
    let reset = manager
        .reset_generation(3, "reset-2".into(), "observed successor SYN".into())
        .unwrap();
    let replay = manager
        .reset_generation(3, "reset-2".into(), "observed successor SYN".into())
        .unwrap();

    assert_eq!((reset.previous_generation, reset.generation), (0, 1));
    assert_eq!(replay.session_status, SessionApplyStatus::IdenticalReplay);
    assert!(replay.replayed);
    assert_eq!(manager.wire_state(3).unwrap().generation(), 1);
}

#[test]
fn active_session_limit_fails_without_evicting_existing_state() {
    let limits = Limits {
        active: 1,
        ..Limits::default()
    };
    let mut manager = CapturedSessionManager::new(capture(), "capture-a".into(), limits).unwrap();
    manager
        .apply_message(1, &keepalive(1), metadata(1, 1))
        .unwrap();
    let error = manager
        .apply_message(2, &keepalive(2), metadata(2, 2))
        .unwrap_err();

    assert_eq!(error.code, ErrorCode::LimitExceeded);
    assert!(manager.contains(1));
    assert!(!manager.contains(2));
    assert_eq!(manager.active_sessions(), 1);
}

#[test]
fn metadata_cannot_be_applied_under_another_manager_key() {
    let mut manager =
        CapturedSessionManager::new(capture(), "capture-a".into(), Limits::default()).unwrap();
    let error = manager
        .apply_message(9, &keepalive(1), metadata(10, 1))
        .unwrap_err();

    assert_eq!(error.field, "bgp_manager_session");
    assert_eq!(manager.active_sessions(), 0);
}

#[test]
fn malformed_first_message_does_not_retain_an_empty_session() {
    let mut manager =
        CapturedSessionManager::new(capture(), "capture-a".into(), Limits::default()).unwrap();
    let malformed = EvidenceBytes::from_packet(
        &[0],
        PacketId {
            capture: capture(),
            frame: 1,
            record_offset: 100,
        },
        54,
    );

    manager
        .apply_message(4, &malformed, metadata(4, 1))
        .unwrap_err();
    assert_eq!(manager.active_sessions(), 0);
    assert!(!manager.contains(4));
}
