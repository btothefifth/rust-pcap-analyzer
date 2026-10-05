//! Independent wire-to-session-to-RIB joins through the public atomic pipeline.
use pcap_evidence::{
    provenance::{EvidenceBytes, PacketId},
    sha256, ErrorCode,
};
use pcap_evidence_product::deep::{
    bgp::PcapMetadata,
    bgp_manager::CapturedSessionManager,
    bgp_mrt::MrtLimits,
    bgp_mrt_store::MrtReplayOptions,
    bgp_persisted::{PolicyProfile, Query, VerifiedStore},
    bgp_pipeline::CapturedSessionPipeline,
    bgp_rib::{ApplyStatus as RibApplyStatus, RouteStatus},
    bgp_session::{ApplyStatus as SessionApplyStatus, CapabilityContext},
    bgp_store::{self, JournalWriter},
    Limits,
};

const SESSION: u64 = 17;

fn capture() -> [u8; 32] {
    sha256::digest(b"bgp-pipeline-capture")
}

fn evidence(bytes: &[u8], frame: u64) -> EvidenceBytes {
    EvidenceBytes::from_packet(
        bytes,
        PacketId {
            capture: capture(),
            frame,
            record_offset: frame * 100,
        },
        54,
    )
}

fn metadata(direction: Option<u8>, frame: u64) -> PcapMetadata {
    PcapMetadata {
        source_id: "capture-a".into(),
        record_id: format!("record-{frame}"),
        observed_at_ns: Some(i64::try_from(frame).unwrap()),
        session: Some(SESSION),
        direction,
        peer: direction.map(|side| format!("peer-{side}")),
        local: Some("local".into()),
    }
}

fn message(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![255; 16];
    out.extend_from_slice(&u16::try_from(19 + body.len()).unwrap().to_be_bytes());
    out.push(kind);
    out.extend_from_slice(body);
    out
}

fn capability(code: u8, value: &[u8]) -> Vec<u8> {
    let mut out = vec![code, u8::try_from(value.len()).unwrap()];
    out.extend_from_slice(value);
    out
}

fn opened(asn: u16, capabilities: &[Vec<u8>]) -> Vec<u8> {
    let caps: Vec<u8> = capabilities.iter().flatten().copied().collect();
    let mut body = vec![4];
    body.extend_from_slice(&asn.to_be_bytes());
    body.extend_from_slice(&90u16.to_be_bytes());
    body.extend_from_slice(&[192, 0, 2, 1]);
    body.push(u8::try_from(caps.len() + 2).unwrap());
    body.extend_from_slice(&[2, u8::try_from(caps.len()).unwrap()]);
    body.extend(caps);
    message(1, &body)
}

fn attribute(flags: u8, code: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![flags, code, u8::try_from(payload.len()).unwrap()];
    out.extend_from_slice(payload);
    out
}

fn update(attributes: &[u8], nlri: &[u8]) -> Vec<u8> {
    let mut body = vec![0, 0];
    body.extend_from_slice(&u16::try_from(attributes.len()).unwrap().to_be_bytes());
    body.extend_from_slice(attributes);
    body.extend_from_slice(nlri);
    message(2, &body)
}

fn announcement() -> Vec<u8> {
    let mut attributes = attribute(0x40, 1, &[0]);
    attributes.extend(attribute(0x40, 2, &[2, 1, 0, 0, 0xfd, 0xe8]));
    attributes.extend(attribute(0x40, 3, &[192, 0, 2, 9]));
    update(&attributes, &[24, 203, 0, 113])
}

fn pipeline() -> CapturedSessionPipeline {
    CapturedSessionPipeline::new(capture(), "capture-a".into(), SESSION, Limits::default()).unwrap()
}

fn establish(pipeline: &mut CapturedSessionPipeline) {
    for (frame, direction, asn) in [(1, 0, 65000), (2, 1, 65001)] {
        let open = opened(asn, &[capability(65, &u32::from(asn).to_be_bytes())]);
        pipeline
            .apply_message(&evidence(&open, frame), metadata(Some(direction), frame))
            .unwrap();
    }
}

#[test]
fn decoded_open_and_update_reach_session_and_adj_rib_in_atomically() {
    let mut pipeline = pipeline();
    establish(&mut pipeline);
    assert_eq!(
        pipeline.observer().view().unwrap().context,
        CapabilityContext::BilateralCandidate {
            common_codes: vec![65]
        }
    );

    let receipt = pipeline
        .apply_message(&evidence(&announcement(), 3), metadata(Some(0), 3))
        .unwrap();
    assert_eq!(receipt.session_status, SessionApplyStatus::Applied);
    assert_eq!(receipt.rib_status, Some(RibApplyStatus::Applied));
    assert!(!receipt.protocol_reset);
    assert_eq!(
        pipeline.observer().view().unwrap().directions[0].updates,
        ["record-3"]
    );
    assert_eq!(pipeline.rib().entries().len(), 1);
    assert_eq!(
        pipeline.rib().entries().values().next().unwrap().status,
        RouteStatus::Active
    );
}

#[test]
fn multiple_nlri_from_one_update_are_one_atomic_rib_event() {
    let mut pipeline = pipeline();
    establish(&mut pipeline);
    let mut attributes = attribute(0x40, 1, &[0]);
    attributes.extend(attribute(0x40, 2, &[2, 1, 0, 0, 0xfd, 0xe8]));
    attributes.extend(attribute(0x40, 3, &[192, 0, 2, 9]));
    let raw = update(&attributes, &[24, 203, 0, 113, 24, 198, 51, 100]);
    pipeline
        .apply_message(&evidence(&raw, 3), metadata(Some(0), 3))
        .unwrap();
    assert_eq!(pipeline.rib().events().len(), 1);
    assert_eq!(pipeline.rib().entries().len(), 2);
    assert!(pipeline
        .rib()
        .entries()
        .values()
        .all(|entry| entry.status == RouteStatus::Active));
}

#[test]
fn conventional_and_multiprotocol_end_of_rib_are_explicit_events() {
    let mut conventional = pipeline();
    establish(&mut conventional);
    conventional
        .apply_message(&evidence(&update(&[], &[]), 3), metadata(Some(0), 3))
        .unwrap();
    assert_eq!(conventional.rib().eors().len(), 1);
    assert_eq!(conventional.rib().eors()[0].family.afi, 1);
    assert_eq!(conventional.rib().eors()[0].family.safi, 1);

    let mp_capability = capability(1, &[0, 2, 0, 1]);
    let mut multiprotocol = pipeline();
    for (frame, direction, asn) in [(1, 0, 65000), (2, 1, 65001)] {
        let open = opened(
            asn,
            &[
                capability(65, &u32::from(asn).to_be_bytes()),
                mp_capability.clone(),
            ],
        );
        multiprotocol
            .apply_message(&evidence(&open, frame), metadata(Some(direction), frame))
            .unwrap();
    }
    let mp_eor = update(&attribute(0x80, 15, &[0, 2, 1]), &[]);
    multiprotocol
        .apply_message(&evidence(&mp_eor, 3), metadata(Some(0), 3))
        .unwrap();
    assert_eq!(multiprotocol.rib().eors().len(), 1);
    assert_eq!(multiprotocol.rib().eors()[0].family.afi, 2);
    assert_eq!(multiprotocol.rib().eors()[0].family.safi, 1);
}

#[test]
fn notification_advances_all_owned_state_and_supersedes_old_routes() {
    let mut pipeline = pipeline();
    establish(&mut pipeline);
    pipeline
        .apply_message(&evidence(&announcement(), 3), metadata(Some(0), 3))
        .unwrap();
    let notification = message(3, &[6, 0]);
    let receipt = pipeline
        .apply_message(&evidence(&notification, 4), metadata(Some(1), 4))
        .unwrap();
    assert!(receipt.protocol_reset);
    assert_eq!(receipt.rib_status, Some(RibApplyStatus::Applied));
    assert_eq!(pipeline.wire_state().generation(), 1);
    assert_eq!(pipeline.observer().view().unwrap().generation, 1);
    assert_eq!(pipeline.observer().view().unwrap().resets, ["record-4"]);
    assert!(pipeline
        .rib()
        .entries()
        .values()
        .all(|entry| entry.status == RouteStatus::Superseded));
}

#[test]
fn malformed_update_session_reset_cannot_leave_an_old_active_route() {
    let mut pipeline = pipeline();
    establish(&mut pipeline);
    pipeline
        .apply_message(&evidence(&announcement(), 3), metadata(Some(0), 3))
        .unwrap();
    let malformed = update(&attribute(0x80, 14, &[]), &[24, 198, 51, 100]);
    let receipt = pipeline
        .apply_message(&evidence(&malformed, 4), metadata(Some(0), 4))
        .unwrap();
    assert!(receipt.protocol_reset);
    assert_eq!(pipeline.wire_state().generation(), 1);
    assert!(pipeline
        .rib()
        .entries()
        .values()
        .all(|entry| entry.status == RouteStatus::Superseded));
}

#[test]
fn treat_as_withdraw_reaches_rib_as_withdrawal_not_rejection() {
    let mut pipeline = pipeline();
    establish(&mut pipeline);
    pipeline
        .apply_message(&evidence(&announcement(), 3), metadata(Some(0), 3))
        .unwrap();
    let mut attributes = attribute(0x40, 1, &[0]);
    attributes.extend(attribute(0x40, 2, &[2, 1, 0, 0, 0xfd, 0xe8]));
    attributes.extend(attribute(0x40, 3, &[192, 0, 2, 9]));
    attributes.extend(attribute(0xc0, 8, &[]));
    let malformed = update(&attributes, &[24, 203, 0, 113]);
    let receipt = pipeline
        .apply_message(&evidence(&malformed, 4), metadata(Some(0), 4))
        .unwrap();
    assert!(!receipt.protocol_reset);
    assert_eq!(pipeline.rib().rejections().len(), 0);
    assert_eq!(
        pipeline.rib().entries().values().next().unwrap().status,
        RouteStatus::Withdrawn
    );
}

#[test]
fn recoverable_final_attribute_envelopes_withdraw_only_identified_routes() {
    for fragment in [&[0x40][..], &[0x50, 1, 0][..], &[0xc0, 8, 4, 0][..]] {
        let mut pipeline = pipeline();
        establish(&mut pipeline);
        let mut attrs = attribute(0x40, 1, &[0]);
        attrs.extend(attribute(0x40, 2, &[2, 1, 0, 0, 0xfd, 0xe8]));
        attrs.extend(attribute(0x40, 3, &[192, 0, 2, 9]));
        let initial = update(&attrs, &[24, 203, 0, 113, 24, 198, 51, 100]);
        pipeline
            .apply_message(&evidence(&initial, 3), metadata(Some(0), 3))
            .unwrap();
        attrs.extend_from_slice(fragment);
        let malformed = update(&attrs, &[24, 203, 0, 113]);
        let receipt = pipeline
            .apply_message(&evidence(&malformed, 4), metadata(Some(0), 4))
            .unwrap();
        assert!(!receipt.protocol_reset);
        assert_eq!(pipeline.wire_state().generation(), 0);
        let entries: Vec<_> = pipeline.rib().entries().values().collect();
        assert_eq!(
            entries
                .iter()
                .filter(|entry| entry.status == RouteStatus::Withdrawn)
                .count(),
            1
        );
        assert_eq!(
            entries
                .iter()
                .filter(|entry| entry.status == RouteStatus::Active)
                .count(),
            1
        );
        assert!(pipeline.rib().gaps().is_empty());
        assert!(
            pipeline
                .apply_message(&evidence(&malformed, 4), metadata(Some(0), 4))
                .unwrap()
                .replayed
        );
    }
}

#[test]
fn opaque_withdrawal_after_conflicting_open_breaks_rib_continuity_and_replays_inertly() {
    let mut pipeline = pipeline();
    establish(&mut pipeline);
    pipeline
        .apply_message(&evidence(&announcement(), 3), metadata(Some(0), 3))
        .unwrap();
    let conflicting = opened(
        65000,
        &[
            capability(65, &65000u32.to_be_bytes()),
            capability(69, &[0, 1, 1, 2]),
        ],
    );
    pipeline
        .apply_message(&evidence(&conflicting, 4), metadata(Some(0), 4))
        .unwrap();
    let withdrawal = message(2, &[0, 4, 24, 203, 0, 113, 0, 0]);
    let receipt = pipeline
        .apply_message(&evidence(&withdrawal, 5), metadata(Some(0), 5))
        .unwrap();
    assert!(!receipt.protocol_reset);
    assert_eq!(pipeline.wire_state().generation(), 0);
    assert_eq!(pipeline.rib().gaps().len(), 2);
    assert_eq!(pipeline.observer().view().unwrap().gaps, ["record-5"]);
    assert!(pipeline
        .rib()
        .entries()
        .values()
        .all(|entry| entry.status == RouteStatus::Unresolved));
    let event_count = pipeline.rib().events().len();
    assert!(
        pipeline
            .apply_message(&evidence(&withdrawal, 5), metadata(Some(0), 5))
            .unwrap()
            .replayed
    );
    assert_eq!(pipeline.rib().events().len(), event_count);
}

#[test]
fn ordinary_layout_survives_unilateral_add_path_with_two_complete_opens() {
    for advertising_sender in [false, true] {
        let mut pipeline = pipeline();
        for (frame, direction, asn) in [(1, 0, 65000), (2, 1, 65001)] {
            let mut caps = vec![capability(65, &u32::from(asn).to_be_bytes())];
            if (direction == 0) == advertising_sender {
                caps.push(capability(69, &[0, 1, 1, 3]));
            }
            let open = opened(asn, &caps);
            pipeline
                .apply_message(&evidence(&open, frame), metadata(Some(direction), frame))
                .unwrap();
        }
        pipeline
            .apply_message(&evidence(&announcement(), 3), metadata(Some(0), 3))
            .unwrap();
        assert_eq!(pipeline.rib().entries().len(), 1);
        assert_eq!(
            pipeline.rib().entries().values().next().unwrap().status,
            RouteStatus::Active
        );
        let withdrawal = message(2, &[0, 4, 24, 203, 0, 113, 0, 0]);
        pipeline
            .apply_message(&evidence(&withdrawal, 4), metadata(Some(0), 4))
            .unwrap();
        assert_eq!(
            pipeline.rib().entries().values().next().unwrap().status,
            RouteStatus::Withdrawn
        );
        assert!(pipeline.rib().gaps().is_empty());
    }
}

#[test]
fn multiprotocol_wrong_flags_reset_even_with_identified_conventional_nlri() {
    for (code, value) in [
        (14, vec![0, 1, 1, 4, 192, 0, 2, 1, 0, 24, 203, 0, 113]),
        (15, vec![0, 1, 1, 24, 203, 0, 113]),
    ] {
        let mut pipeline = pipeline();
        establish(&mut pipeline);
        pipeline
            .apply_message(&evidence(&announcement(), 3), metadata(Some(0), 3))
            .unwrap();
        let mut attrs = attribute(0x40, 1, &[0]);
        attrs.extend(attribute(0x40, 2, &[2, 1, 0, 0, 0xfd, 0xe8]));
        attrs.extend(attribute(0x40, 3, &[192, 0, 2, 9]));
        attrs.extend(attribute(0x40, code, &value));
        let malformed = update(&attrs, &[24, 198, 51, 100]);
        assert!(
            pipeline
                .apply_message(&evidence(&malformed, 4), metadata(Some(0), 4))
                .unwrap()
                .protocol_reset
        );
        assert!(pipeline
            .rib()
            .entries()
            .values()
            .all(|entry| entry.status == RouteStatus::Superseded));
    }
}

#[test]
fn unparsed_final_mp_attribute_cannot_borrow_conventional_nlri_recovery() {
    for code in [14, 15] {
        let mut pipeline = pipeline();
        establish(&mut pipeline);
        pipeline
            .apply_message(&evidence(&announcement(), 3), metadata(Some(0), 3))
            .unwrap();
        let malformed = update(&[0x80, code, 20, 0, 1, 1], &[24, 203, 0, 113]);
        let receipt = pipeline
            .apply_message(&evidence(&malformed, 4), metadata(Some(0), 4))
            .unwrap();
        assert!(receipt.protocol_reset);
        assert!(pipeline
            .rib()
            .entries()
            .values()
            .all(|entry| entry.status == RouteStatus::Superseded));
    }
}

#[test]
fn opaque_mp_withdrawal_breaks_continuity_without_inventing_withdrawals() {
    let mut pipeline = pipeline();
    establish(&mut pipeline);
    pipeline
        .apply_message(&evidence(&announcement(), 3), metadata(Some(0), 3))
        .unwrap();
    let unsupported = update(&attribute(0x80, 15, &[0, 1, 1, 24, 203, 0, 113]), &[]);
    let receipt = pipeline
        .apply_message(&evidence(&unsupported, 4), metadata(Some(0), 4))
        .unwrap();
    assert!(!receipt.protocol_reset);
    assert_eq!(pipeline.rib().gaps().len(), 1);
    assert_eq!(
        pipeline.rib().entries().values().next().unwrap().status,
        RouteStatus::Unresolved
    );
}

#[test]
fn unresolved_attribute_layout_is_rejected_not_promoted_to_active_state() {
    fn hex(value: &str) -> Vec<u8> {
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }
    let dual_width = hex(
        "ffffffffffffffffffffffffffffffff003302000000184001010040020a02020001020102010002400304c000020118cb0071",
    );
    let mut pipeline = pipeline();
    let receipt = pipeline
        .apply_message(&evidence(&dual_width, 1), metadata(Some(0), 1))
        .unwrap();
    assert_eq!(receipt.rib_status, Some(RibApplyStatus::Applied));
    assert!(pipeline.rib().entries().is_empty());
    assert_eq!(pipeline.rib().rejections().len(), 1);
    assert_eq!(
        pipeline.rib().rejections()[0].reason,
        "ambiguous_attribute_context"
    );
}

#[test]
fn gap_and_explicit_transport_reset_are_separate_and_ordered() {
    let mut pipeline = pipeline();
    establish(&mut pipeline);
    pipeline
        .apply_message(&evidence(&announcement(), 3), metadata(Some(0), 3))
        .unwrap();
    let gap = pipeline
        .observe_gap("gap-4".into(), "missing TCP sequence range".into())
        .unwrap();
    assert_eq!(gap.generation, 0);
    assert!(pipeline
        .rib()
        .entries()
        .values()
        .all(|entry| entry.status == RouteStatus::Unresolved));
    let reset = pipeline
        .reset_generation("reset-5".into(), "observed successor SYN".into())
        .unwrap();
    assert_eq!((reset.previous_generation, reset.generation), (0, 1));
    assert_eq!(pipeline.wire_state().generation(), 1);
    assert_eq!(pipeline.observer().view().unwrap().generation, 1);
}

#[test]
fn exact_transport_reset_replay_does_not_skip_a_generation() {
    let mut pipeline = pipeline();
    establish(&mut pipeline);
    let original = pipeline
        .reset_generation("reset-3".into(), "observed successor SYN".into())
        .unwrap();
    let event_count = pipeline.observer().events().len();

    let replay = pipeline
        .reset_generation("reset-3".into(), "observed successor SYN".into())
        .unwrap();

    assert!(!original.replayed);
    assert!(replay.replayed);
    assert_eq!(replay.session_status, SessionApplyStatus::IdenticalReplay);
    assert_eq!(pipeline.wire_state().generation(), 1);
    assert_eq!(pipeline.observer().view().unwrap().generation, 1);
    assert_eq!(pipeline.observer().events().len(), event_count);
    assert!(!pipeline.tainted());
}

#[test]
fn changed_reset_identity_cannot_advance_wire_state() {
    let mut pipeline = pipeline();
    establish(&mut pipeline);
    pipeline
        .observe_gap("boundary-3".into(), "missing TCP sequence range".into())
        .unwrap();

    let receipt = pipeline
        .reset_generation("boundary-3".into(), "observed successor SYN".into())
        .unwrap();

    assert_eq!(receipt.session_status, SessionApplyStatus::IdentityConflict);
    assert_eq!((receipt.previous_generation, receipt.generation), (0, 0));
    assert_eq!(pipeline.wire_state().generation(), 0);
    assert_eq!(pipeline.observer().view().unwrap().generation, 0);
    assert!(pipeline.tainted());
}

#[test]
fn gap_before_first_route_keeps_later_candidates_unresolved() {
    let mut pipeline = pipeline();
    establish(&mut pipeline);
    let gap = pipeline
        .observe_gap("gap-3".into(), "missing TCP sequence range".into())
        .unwrap();
    assert_eq!(gap.rib_status, Some(RibApplyStatus::Applied));

    pipeline
        .apply_message(&evidence(&announcement(), 4), metadata(Some(0), 4))
        .unwrap();

    assert_eq!(pipeline.rib().entries().len(), 1);
    assert!(pipeline
        .rib()
        .entries()
        .values()
        .all(|entry| entry.status == RouteStatus::Unresolved));
}

#[test]
fn scope_or_capture_mismatch_is_atomic() {
    let mut pipeline = pipeline();
    establish(&mut pipeline);
    let before_generation = pipeline.wire_state().generation();
    let before_session_events = pipeline.observer().events().len();
    let before_rib_events = pipeline.rib().events().len();
    let mut wrong_source = metadata(Some(0), 3);
    wrong_source.source_id = "other".into();
    assert!(pipeline
        .apply_message(&evidence(&announcement(), 3), wrong_source)
        .is_err());

    let wrong_capture = EvidenceBytes::from_packet(
        &announcement(),
        PacketId {
            capture: sha256::digest(b"other"),
            frame: 3,
            record_offset: 300,
        },
        54,
    );
    assert!(pipeline
        .apply_message(&wrong_capture, metadata(Some(0), 3))
        .is_err());
    assert_eq!(pipeline.wire_state().generation(), before_generation);
    assert_eq!(pipeline.observer().events().len(), before_session_events);
    assert_eq!(pipeline.rib().events().len(), before_rib_events);
}

#[test]
fn changed_record_identity_is_retained_then_blocks_later_application() {
    let mut pipeline = pipeline();
    let first = opened(65000, &[capability(65, &65000u32.to_be_bytes())]);
    pipeline
        .apply_message(&evidence(&first, 1), metadata(Some(0), 1))
        .unwrap();
    let changed = opened(65000, &[capability(2, &[])]);
    let mut same_identity = metadata(Some(0), 2);
    same_identity.record_id = "record-1".into();
    let receipt = pipeline
        .apply_message(&evidence(&changed, 2), same_identity)
        .unwrap();
    assert_eq!(receipt.session_status, SessionApplyStatus::IdentityConflict);
    assert!(pipeline.tainted());
    assert!(pipeline
        .apply_message(&evidence(&message(4, &[]), 3), metadata(Some(0), 3))
        .is_err());
}

#[test]
fn changed_non_route_record_cannot_install_a_route_before_quarantine() {
    let mut pipeline = pipeline();
    let first = opened(65000, &[capability(65, &65000u32.to_be_bytes())]);
    pipeline
        .apply_message(&evidence(&first, 1), metadata(Some(0), 1))
        .unwrap();

    let mut same_identity = metadata(Some(0), 2);
    same_identity.record_id = "record-1".into();
    let receipt = pipeline
        .apply_message(&evidence(&announcement(), 2), same_identity)
        .unwrap();

    assert_eq!(receipt.session_status, SessionApplyStatus::IdentityConflict);
    assert_eq!(receipt.rib_status, Some(RibApplyStatus::Applied));
    assert!(pipeline.rib().entries().is_empty());
    assert_eq!(pipeline.rib().gaps().len(), 1);
    assert!(pipeline.tainted());
}

#[test]
fn changed_record_cannot_invent_a_protocol_generation() {
    let mut pipeline = pipeline();
    let first = opened(65000, &[capability(65, &65000u32.to_be_bytes())]);
    pipeline
        .apply_message(&evidence(&first, 1), metadata(Some(0), 1))
        .unwrap();
    let notification = message(3, &[6, 0]);
    let mut same_identity = metadata(Some(1), 2);
    same_identity.record_id = "record-1".into();

    let receipt = pipeline
        .apply_message(&evidence(&notification, 2), same_identity)
        .unwrap();

    assert_eq!(receipt.session_status, SessionApplyStatus::IdentityConflict);
    assert!(!receipt.protocol_reset);
    assert_eq!(pipeline.wire_state().generation(), 0);
    assert_eq!(pipeline.observer().view().unwrap().generation, 0);
    assert!(pipeline.tainted());
}

#[test]
fn exact_notification_replay_is_inert_across_the_generation_boundary() {
    let mut pipeline = pipeline();
    establish(&mut pipeline);
    pipeline
        .apply_message(&evidence(&announcement(), 3), metadata(Some(0), 3))
        .unwrap();
    let notification = message(3, &[6, 0]);
    let original = pipeline
        .apply_message(&evidence(&notification, 4), metadata(Some(1), 4))
        .unwrap();
    let session_events = pipeline.observer().events().len();
    let rib_events = pipeline.rib().events().len();

    let replay = pipeline
        .apply_message(&evidence(&notification, 4), metadata(Some(1), 4))
        .unwrap();

    assert!(!original.replayed);
    assert!(replay.replayed);
    assert!(!replay.protocol_reset);
    assert_eq!(replay.session_status, SessionApplyStatus::IdenticalReplay);
    assert_eq!(replay.rib_status, Some(RibApplyStatus::IdenticalReplay));
    assert_eq!(pipeline.wire_state().generation(), 1);
    assert_eq!(pipeline.observer().events().len(), session_events);
    assert_eq!(pipeline.rib().events().len(), rib_events);
    assert!(!pipeline.tainted());
}

#[test]
fn mixed_next_hop_diagnostic_cannot_erase_unresolved_mp_reach_continuity() {
    use pcap_evidence::json::Json;
    use pcap_evidence_product::deep::bgp;
    for reverse in [false, true] {
        for conventional in [false, true] {
            let mut pipeline = pipeline();
            establish(&mut pipeline);
            pipeline
                .apply_message(&evidence(&announcement(), 3), metadata(Some(0), 3))
                .unwrap();
            let mut attributes = attribute(0x40, 1, &[0]);
            attributes.extend(attribute(0x40, 2, &[2, 1, 0, 0, 0xfd, 0xe8]));
            let next_hop = attribute(0x40, 3, &[192, 0, 2, 9]);
            let mp = attribute(0x80, 14, &[0, 1, 1, 4, 192, 0, 2, 9, 0, 24, 198, 51, 100]);
            if reverse {
                attributes.extend(mp);
                attributes.extend(next_hop);
            } else {
                attributes.extend(next_hop);
                attributes.extend(mp);
            }
            let wire = update(
                &attributes,
                if conventional {
                    &[24, 203, 0, 113]
                } else {
                    &[]
                },
            );
            let mut wire_state = pipeline.wire_state().clone();
            let decoded = bgp::decode_pcap(
                &evidence(&wire, 4),
                metadata(Some(0), 4),
                &mut wire_state,
                &Limits::default(),
            )
            .unwrap();
            pipeline
                .apply_message(&evidence(&wire, 4), metadata(Some(0), 4))
                .unwrap();
            assert_eq!(
                pipeline.rib().gaps().len(),
                1,
                "reverse={reverse} conventional={conventional}"
            );
            assert!(pipeline
                .rib()
                .entries()
                .values()
                .all(|entry| entry.status == RouteStatus::Unresolved));
            assert!(!pipeline
                .rib()
                .entries()
                .values()
                .any(|entry| entry.status == RouteStatus::Withdrawn));
            let Json::Object(top) = &decoded else {
                panic!("decoded object")
            };
            let Json::Object(detail) = &top
                .iter()
                .find(|(key, _)| *key == "message_detail")
                .unwrap()
                .1
            else {
                panic!("message detail")
            };
            let Json::Array(opaque) = &detail
                .iter()
                .find(|(key, _)| *key == "opaque_nlri")
                .unwrap()
                .1
            else {
                panic!("opaque array")
            };
            assert_eq!(opaque.len(), 1);
            assert!(decoded
                .encode()
                .contains("next_hop_family_context_unresolved"));
            let events = pipeline.rib().events().len();
            pipeline
                .apply_message(&evidence(&wire, 4), metadata(Some(0), 4))
                .unwrap();
            assert_eq!(
                pipeline.rib().events().len(),
                events,
                "exact replay remains inert"
            );
            assert_eq!(pipeline.rib().gaps().len(), 1);
            pipeline
                .apply_message(&evidence(&announcement(), 5), metadata(Some(0), 5))
                .unwrap();
            assert!(pipeline
                .rib()
                .entries()
                .values()
                .all(|entry| entry.status == RouteStatus::Unresolved));
        }
    }
    // Ordinary routes and bilateral MP layout remain decoded. Mixed next-hop
    // ambiguity is retained, but known MP bytes do not become a source gap.
    let mut known = pipeline();
    for (frame, direction, asn) in [(1, 0, 65000), (2, 1, 65001)] {
        let open = opened(
            asn,
            &[
                capability(65, &u32::from(asn).to_be_bytes()),
                capability(1, &[0, 1, 0, 1]),
            ],
        );
        known
            .apply_message(&evidence(&open, frame), metadata(Some(direction), frame))
            .unwrap();
    }
    known
        .apply_message(&evidence(&announcement(), 3), metadata(Some(0), 3))
        .unwrap();
    assert_eq!(
        known.rib().entries().values().next().unwrap().status,
        RouteStatus::Active
    );
    let mut attrs = attribute(0x40, 1, &[0]);
    attrs.extend(attribute(0x40, 2, &[2, 1, 0, 0, 0xfd, 0xe8]));
    attrs.extend(attribute(0x40, 3, &[192, 0, 2, 9]));
    attrs.extend(attribute(
        0x80,
        14,
        &[0, 1, 1, 4, 192, 0, 2, 9, 0, 24, 198, 51, 100],
    ));
    let wire = update(&attrs, &[24, 203, 0, 113]);
    let mut state = known.wire_state().clone();
    let decoded = bgp::decode_pcap(
        &evidence(&wire, 4),
        metadata(Some(0), 4),
        &mut state,
        &Limits::default(),
    )
    .unwrap();
    assert!(decoded.encode().contains("\"opaque_nlri\":[]"));
    known
        .apply_message(&evidence(&wire, 4), metadata(Some(0), 4))
        .unwrap();
    assert!(known.rib().gaps().is_empty());
}

fn contradictory_open() -> Vec<u8> {
    opened(
        65000,
        &[capability(65, &65000u32.to_be_bytes()), capability(2, &[])],
    )
}

#[test]
fn contradictory_open_immediately_gaps_existing_bilateral_routes_and_keeps_history() {
    // The layout context is bilateral: contradiction on either direction
    // invalidates both directions of this generation, not another session.
    for contradicted_direction in [0, 1] {
        let mut pipeline = pipeline();
        establish(&mut pipeline);
        for (frame, direction) in [(3, 0), (4, 1)] {
            pipeline
                .apply_message(
                    &evidence(&announcement(), frame),
                    metadata(Some(direction), frame),
                )
                .unwrap();
        }
        let before = pipeline.rib().entries().clone();
        let changed = opened(
            65000 + u16::from(contradicted_direction),
            &[
                capability(
                    65,
                    &(65000u32 + u32::from(contradicted_direction)).to_be_bytes(),
                ),
                capability(2, &[]),
            ],
        );
        let receipt = pipeline
            .apply_message(
                &evidence(&changed, 5),
                metadata(Some(contradicted_direction), 5),
            )
            .unwrap();
        assert_eq!(receipt.rib_status, Some(RibApplyStatus::Applied));
        assert!(!receipt.protocol_reset);
        assert_eq!(pipeline.wire_state().generation(), 0);
        assert_eq!(pipeline.rib().gaps().len(), 1);
        let gap = &pipeline.rib().events().last().unwrap();
        assert_eq!(gap.record_id, "record-5");
        assert_eq!(gap.scope.direction, None);
        assert_eq!(gap.scope.peer, None);
        assert!(matches!(
            gap.kind,
            pcap_evidence_product::deep::bgp_rib::RibEventKind::Gap { .. }
        ));
        for (key, entry) in pipeline.rib().entries() {
            assert_eq!(entry.status, RouteStatus::Unresolved);
            assert_eq!(entry.versions, before[key].versions);
        }
        // Ambiguous replacement is still rejected and cannot resurrect an
        // older accepted route. Reject is not itself a new continuity gap.
        pipeline
            .apply_message(&evidence(&announcement(), 6), metadata(Some(0), 6))
            .unwrap();
        assert_eq!(pipeline.rib().gaps().len(), 1);
        assert_eq!(pipeline.rib().rejections().len(), 1);
        assert!(pipeline
            .rib()
            .entries()
            .values()
            .all(|e| e.status == RouteStatus::Unresolved));
    }
}

#[test]
fn contradictory_open_identity_covers_non_capability_fields() {
    for offset in [23, 27] {
        // Hold time and BGP identifier, same capabilities.
        let mut pipeline = pipeline();
        establish(&mut pipeline);
        pipeline
            .apply_message(&evidence(&announcement(), 3), metadata(Some(0), 3))
            .unwrap();
        let mut changed = opened(65000, &[capability(65, &65000u32.to_be_bytes())]);
        changed[offset] ^= 1;
        pipeline
            .apply_message(&evidence(&changed, 4), metadata(Some(0), 4))
            .unwrap();
        assert_eq!(pipeline.rib().gaps().len(), 1);
        assert_eq!(
            pipeline.rib().entries().values().next().unwrap().status,
            RouteStatus::Unresolved
        );
    }
}

#[test]
fn initial_opens_and_exact_immutable_replays_do_not_fabricate_gaps() {
    let mut pipeline = pipeline();
    let original = opened(65000, &[capability(65, &65000u32.to_be_bytes())]);
    let initial = pipeline
        .apply_message(&evidence(&original, 1), metadata(Some(0), 1))
        .unwrap();
    assert_eq!(initial.rib_status, None);
    let changed = contradictory_open();
    // A changed unilateral OPEN before any RIB event does not fabricate RIB
    // history, a reset, or a successor generation.
    let second = pipeline
        .apply_message(&evidence(&changed, 2), metadata(Some(0), 2))
        .unwrap();
    assert_eq!(second.rib_status, None);
    assert!(pipeline.rib().events().is_empty());
    assert_eq!(pipeline.wire_state().generation(), 0);

    let mut established = self::pipeline();
    establish(&mut established);
    established
        .apply_message(&evidence(&announcement(), 3), metadata(Some(0), 3))
        .unwrap();
    for frame in [1, 2] {
        let direction = u8::try_from(frame - 1).unwrap();
        let asn = 65000 + u16::from(direction);
        let original = opened(asn, &[capability(65, &u32::from(asn).to_be_bytes())]);
        assert!(
            established
                .apply_message(
                    &evidence(&original, frame),
                    metadata(Some(direction), frame)
                )
                .unwrap()
                .replayed
        );
    }
    assert!(established.rib().gaps().is_empty());
    assert_eq!(
        established.rib().entries().values().next().unwrap().status,
        RouteStatus::Active
    );
    established
        .apply_message(&evidence(&changed, 4), metadata(Some(0), 4))
        .unwrap();
    let before = established.rib().events().to_vec();
    let replay = established
        .apply_message(&evidence(&changed, 4), metadata(Some(0), 4))
        .unwrap();
    assert!(replay.replayed);
    assert_eq!(established.rib().events(), before);
}

#[test]
fn same_open_bytes_at_a_new_source_occurrence_do_not_create_a_contradiction_gap() {
    let mut pipeline = pipeline();
    establish(&mut pipeline);
    pipeline
        .apply_message(&evidence(&announcement(), 3), metadata(Some(0), 3))
        .unwrap();
    let original = opened(65000, &[capability(65, &65000u32.to_be_bytes())]);
    let receipt = pipeline
        .apply_message(&evidence(&original, 4), metadata(Some(0), 4))
        .unwrap();
    assert!(!receipt.replayed);
    assert_eq!(receipt.session_status, SessionApplyStatus::Applied);
    assert_eq!(receipt.rib_status, None);
    assert!(pipeline.rib().gaps().is_empty());
    assert_eq!(
        pipeline.rib().entries().values().next().unwrap().status,
        RouteStatus::Active
    );
}

#[test]
fn new_open_gap_rib_budget_failure_rolls_back_wire_observer_and_pipeline_receipt() {
    fn populated(limits: Limits) -> CapturedSessionPipeline {
        let mut pipeline =
            CapturedSessionPipeline::new(capture(), "capture-a".into(), SESSION, limits).unwrap();
        establish(&mut pipeline);
        for frame in 3..19 {
            pipeline
                .apply_message(&evidence(&announcement(), frame), metadata(Some(0), frame))
                .unwrap();
        }
        pipeline
    }
    let probe = populated(Limits::default());
    // Admit the existing RIB exactly at its owning reported work boundary.
    // Sixteen repeated route witnesses make that bound larger than an OPEN decode so
    // the incoming OPEN reaches the RIB budget, rather than an earlier limit.
    let mut pipeline = populated(Limits {
        work: probe.rib().accounted_work(),
        ..Limits::default()
    });
    let before_wire = pipeline.wire_state().clone();
    let before_events = pipeline.observer().events().to_vec();
    let before_rib = pipeline.rib().events().to_vec();
    let before_entries = pipeline.rib().entries().clone();
    let error = pipeline
        .apply_message(&evidence(&contradictory_open(), 19), metadata(Some(0), 19))
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::LimitExceeded);
    assert_eq!(error.field, "bgp_rib_budget");
    assert_eq!(pipeline.wire_state(), &before_wire);
    assert_eq!(pipeline.observer().events(), before_events);
    assert_eq!(pipeline.rib().events(), before_rib);
    assert_eq!(pipeline.rib().entries(), &before_entries);
    assert!(pipeline.rib().gaps().is_empty());
    assert!(!pipeline.tainted());
    // The failed attempt must not cache an Applied receipt: retry also reaches
    // the same failing budget and leaves the original state unchanged.
    assert_eq!(
        pipeline
            .apply_message(&evidence(&contradictory_open(), 19), metadata(Some(0), 19))
            .unwrap_err()
            .field,
        "bgp_rib_budget"
    );
}

#[test]
fn explicit_successor_reset_restores_routes_after_open_contradiction() {
    let mut pipeline = pipeline();
    establish(&mut pipeline);
    pipeline
        .apply_message(&evidence(&announcement(), 3), metadata(Some(0), 3))
        .unwrap();
    pipeline
        .apply_message(&evidence(&contradictory_open(), 4), metadata(Some(0), 4))
        .unwrap();
    pipeline
        .reset_generation("reset-5".into(), "observed successor SYN".into())
        .unwrap();
    for (frame, direction, asn) in [(6, 0, 65002), (7, 1, 65003)] {
        let open = opened(asn, &[capability(65, &u32::from(asn).to_be_bytes())]);
        assert_eq!(
            pipeline
                .apply_message(&evidence(&open, frame), metadata(Some(direction), frame))
                .unwrap()
                .rib_status,
            None
        );
    }
    pipeline
        .apply_message(&evidence(&announcement(), 8), metadata(Some(0), 8))
        .unwrap();
    assert_eq!(pipeline.wire_state().generation(), 1);
    assert_eq!(pipeline.rib().gaps().len(), 1);
    assert_eq!(
        pipeline
            .rib()
            .entries()
            .values()
            .filter(|e| e.status == RouteStatus::Superseded)
            .count(),
        1
    );
    assert_eq!(
        pipeline
            .rib()
            .entries()
            .values()
            .filter(|e| e.status == RouteStatus::Active && e.key.scope.generation == 1)
            .count(),
        1
    );
}

#[test]
fn open_contradiction_budget_failure_is_atomic() {
    let mut pipeline = CapturedSessionPipeline::new(
        capture(),
        "capture-a".into(),
        SESSION,
        Limits {
            elements: 8,
            ..Limits::default()
        },
    )
    .unwrap();
    establish(&mut pipeline);
    pipeline
        .apply_message(&evidence(&announcement(), 3), metadata(Some(0), 3))
        .unwrap();
    for frame in 4..=8 {
        pipeline
            .apply_message(&evidence(&message(4, &[]), frame), metadata(Some(0), frame))
            .unwrap();
    }
    let before_wire = pipeline.wire_state().clone();
    let before_events = pipeline.observer().events().to_vec();
    let before_rib = pipeline.rib().events().to_vec();
    let before_entries = pipeline.rib().entries().clone();
    let error = pipeline
        .apply_message(&evidence(&contradictory_open(), 9), metadata(Some(0), 9))
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::LimitExceeded);
    assert_eq!(error.field, "bgp_session_events");
    assert_eq!(pipeline.wire_state(), &before_wire);
    assert_eq!(pipeline.observer().events(), before_events);
    assert_eq!(pipeline.rib().events(), before_rib);
    assert_eq!(pipeline.rib().entries(), &before_entries);
    assert!(pipeline.rib().gaps().is_empty());
    assert!(!pipeline.tainted());
}

struct OpenGapJournal(std::path::PathBuf);
impl Drop for OpenGapJournal {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

#[test]
fn sealed_replay_preserves_open_gap_session_scope_and_policy_exclusion() {
    let path = std::env::temp_dir().join(format!("bgp-open-gap-{}.journal", std::process::id()));
    let cleanup = OpenGapJournal(path.clone());
    let limits = Limits::default();
    let mut writer = JournalWriter::create(
        &path,
        "capture-a".into(),
        capture(),
        1024 * 1024,
        limits.clone(),
    )
    .unwrap();
    let mut manager =
        CapturedSessionManager::new(capture(), "capture-a".into(), limits.clone()).unwrap();
    for session in [SESSION, SESSION + 1] {
        for (frame, direction, raw) in [
            (
                1,
                0,
                opened(65000, &[capability(65, &65000u32.to_be_bytes())]),
            ),
            (
                2,
                1,
                opened(65001, &[capability(65, &65001u32.to_be_bytes())]),
            ),
            (3, 0, announcement()),
        ] {
            let evidence = evidence(&raw, frame + session * 10);
            let mut metadata = metadata(Some(direction), frame + session * 10);
            metadata.session = Some(session);
            writer.message(session, &evidence, &metadata).unwrap();
            manager.apply_message(session, &evidence, metadata).unwrap();
        }
    }
    let changed = evidence(&contradictory_open(), 400);
    let metadata = metadata(Some(0), 400);
    writer.message(SESSION, &changed, &metadata).unwrap();
    manager.apply_message(SESSION, &changed, metadata).unwrap();
    assert_eq!(manager.summary(SESSION).unwrap().active_routes, 0);
    assert_eq!(manager.summary(SESSION).unwrap().unresolved_routes, 1);
    assert_eq!(manager.summary(SESSION + 1).unwrap().active_routes, 1);
    writer.seal().unwrap();
    let archive = bgp_store::replay(&path, 1024 * 1024, limits.clone()).unwrap();
    for session in [SESSION, SESSION + 1] {
        assert_eq!(
            archive.session_history(session)[0].summary,
            manager.summary(session).unwrap()
        );
    }
    let store = VerifiedStore::load(
        &path,
        1024 * 1024,
        MrtLimits::default(),
        limits.clone(),
        MrtReplayOptions::default(),
    )
    .unwrap();
    let query = Query {
        session: Some(SESSION.to_string()),
        ..Query::default()
    };
    let query_output = store.query(&query, &limits).unwrap();
    let profile = PolicyProfile::parse(b"schema=pcap-evidence.bgp.persisted-policy.v1\nprovenance=open-gap-test\ncomparison_context=same-prefix\nmissing_local_preference=100\nmed_rule=skip\nage_rule=skip\n", &limits).unwrap();
    let policy_output = store.policy(&query, &profile, &limits).unwrap();
    // Parse the actual persisted JSON at an independent consumer, as the
    // ordinary persisted CLI regressions do, rather than matching substrings.
    let script = r#"import json, sys
query = json.loads(sys.stdin.readline())
policy = json.loads(sys.stdin.readline())
assert len(query['routes']) == 1
assert query['routes'][0]['status'] == 'unresolved'
assert query['routes'][0]['native_current'] is False
assert len(policy['policy_results']) == 1
result = policy['policy_results'][0]
assert result['selected'] is None
assert len(result['excluded']) == 1
assert result['excluded'][0]['status'] == 'unresolved'
"#;
    let mut child = std::process::Command::new("python3")
        .args(["-B", "-c", script])
        .stdin(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    {
        use std::io::Write;
        let mut input = child.stdin.take().unwrap();
        writeln!(input, "{query_output}").unwrap();
        writeln!(input, "{policy_output}").unwrap();
    }
    assert!(child.wait().unwrap().success());
    drop(cleanup);
}

#[test]
fn captured_same_open_content_new_witness_preserves_bilateral_context() {
    let mut pipeline = pipeline();
    establish(&mut pipeline);
    let original = opened(65000, &[capability(65, &65000u32.to_be_bytes())]);
    let receipt = pipeline
        .apply_message(&evidence(&original, 3), metadata(Some(0), 3))
        .unwrap();
    assert!(!receipt.replayed);
    assert_eq!(
        pipeline.observer().view().unwrap().directions[0].opens[0].witnesses,
        ["record-1", "record-3"]
    );
    assert_eq!(
        pipeline.observer().view().unwrap().context,
        CapabilityContext::BilateralCandidate {
            common_codes: vec![65]
        }
    );
    assert!(pipeline.rib().gaps().is_empty());
}

#[test]
fn captured_same_open_content_new_witness_preserves_following_update_layout() {
    let mut pipeline = pipeline();
    establish(&mut pipeline);
    pipeline
        .apply_message(&evidence(&announcement(), 3), metadata(Some(0), 3))
        .unwrap();
    let original = opened(65000, &[capability(65, &65000u32.to_be_bytes())]);
    assert!(
        !pipeline
            .apply_message(&evidence(&original, 4), metadata(Some(0), 4))
            .unwrap()
            .replayed
    );
    pipeline
        .apply_message(&evidence(&announcement(), 5), metadata(Some(0), 5))
        .unwrap();
    assert!(pipeline.rib().rejections().is_empty());
    let entry = pipeline.rib().entries().values().next().unwrap();
    assert_eq!(entry.status, RouteStatus::Active);
    assert_eq!(entry.versions[0].witnesses, ["record-3", "record-5"]);
    assert!(pipeline.rib().gaps().is_empty());
}

#[test]
fn hundred_and_two_hundred_ordinary_messages_do_not_copy_prior_receipts_or_session_history() {
    fn input(frame: u64, route_count: u64) -> Vec<u8> {
        let mut wire = announcement();
        if frame - 3 < route_count {
            // Sixteen actual /24 prefixes bound each native key's origin history.
            *wire.last_mut().unwrap() = 113 + u8::try_from((frame - 3) % 16).unwrap();
            wire
        } else {
            // Valid attributes without NLRI are an ordinary UPDATE with an
            // explicit empty EOR projection, rather than an EOR or KEEPALIVE.
            update(&wire[23..wire.len() - 4], &[])
        }
    }
    for count in [100u64, 200] {
        let route_count = count / 4;
        let mut pipe = pipeline();
        establish(&mut pipe);
        let session_work = pipe.observer().reduction_work();
        let pipeline_work = pipe.reduction_work();
        let mut route_origins = Vec::new();
        for frame in 3..3 + count {
            let receipt = pipe
                .apply_message(
                    &evidence(&input(frame, route_count), frame),
                    metadata(Some(0), frame),
                )
                .unwrap();
            assert_eq!(receipt.session_status, SessionApplyStatus::Applied);
            assert_eq!(
                receipt.rib_status,
                if frame - 3 < route_count {
                    Some(RibApplyStatus::Applied)
                } else {
                    None
                }
            );
            if frame - 3 < route_count {
                route_origins.push(receipt.observation_sha256);
            }
            assert_eq!(
                pipe.observer().events().last().unwrap().kind,
                pcap_evidence_product::deep::bgp_session::EventKind::Update
            );
        }
        assert_eq!(
            pipe.observer().events().len(),
            usize::try_from(count).unwrap() + 2
        );
        assert_eq!(
            pipe.observer().view().unwrap().directions[0].updates.len(),
            usize::try_from(count).unwrap()
        );
        assert_eq!(
            pipe.rib().events().len(),
            usize::try_from(route_count).unwrap()
        );
        assert_eq!(pipe.rib().entries().len(), 16);
        let mut witnesses = 0;
        let mut occurrences = 0;
        for entry in pipe.rib().entries().values() {
            assert_eq!(entry.status, RouteStatus::Active);
            assert_eq!(entry.versions.len(), 1);
            let version = &entry.versions[0];
            assert_eq!(version.occurrences.len(), version.witnesses.len());
            for (witness, occurrence) in version.witnesses.iter().zip(&version.occurrences) {
                assert_eq!(
                    &pipe.rib().events()[occurrence.event_index].record_id,
                    witness
                );
                assert_eq!(witness, &format!("record-{}", occurrence.event_index + 3));
                assert_eq!(occurrence.route_index, 0);
                assert_eq!(
                    occurrence.observation_sha256,
                    route_origins[occurrence.event_index]
                );
                let subnet = 113 + occurrence.event_index % 16;
                assert_eq!(entry.key.prefix.address, format!("203.0.{subnet}.0"));
            }
            witnesses += version.witnesses.len();
            occurrences += version.occurrences.len();
        }
        assert_eq!(witnesses, usize::try_from(route_count).unwrap());
        assert_eq!(occurrences, usize::try_from(route_count).unwrap());
        // These actual copy/accounting owners stay fixed across every ordinary
        // observer append and receipt admission. Native RIB origins remain
        // costed; this fixture does not claim 200 rich announcements fit defaults.
        assert_eq!(pipe.observer().reduction_work(), session_work);
        assert_eq!(pipe.reduction_work(), pipeline_work);
        for replay_frame in [3 + route_count / 2, 3 + count / 2] {
            let replay = pipe
                .apply_message(
                    &evidence(&input(replay_frame, route_count), replay_frame),
                    metadata(Some(0), replay_frame),
                )
                .unwrap();
            assert!(replay.replayed);
            assert_eq!(pipe.observer().reduction_work(), session_work);
            assert_eq!(pipe.reduction_work(), pipeline_work);
        }
    }
}

#[test]
fn keepalive_history_append_preserves_context_without_measuring_prior_journal() {
    let mut pipe = pipeline();
    establish(&mut pipe);
    let context = pipe.observer().view().unwrap().context.clone();
    let session_work = pipe.observer().reduction_work();
    let pipeline_work = pipe.reduction_work();
    for frame in 3..203 {
        let receipt = pipe
            .apply_message(&evidence(&message(4, &[]), frame), metadata(Some(1), frame))
            .unwrap();
        assert_eq!(receipt.session_status, SessionApplyStatus::Applied);
        assert_eq!(receipt.rib_status, None);
    }
    assert_eq!(pipe.observer().events().len(), 202);
    assert_eq!(
        pipe.observer().view().unwrap().directions[1]
            .keepalives
            .len(),
        200
    );
    assert_eq!(pipe.observer().view().unwrap().context, context);
    assert!(pipe.rib().entries().is_empty());
    assert_eq!(pipe.observer().reduction_work(), session_work);
    assert_eq!(pipe.reduction_work(), pipeline_work);
}

#[test]
fn ordinary_append_budget_rejection_preserves_admitted_state_and_diagnostics() {
    let mut pipe = CapturedSessionPipeline::new(
        capture(),
        "capture-a".into(),
        SESSION,
        Limits {
            elements: 8,
            ..Limits::default()
        },
    )
    .unwrap();
    establish(&mut pipe);
    let keepalive = message(4, &[]);
    for frame in 3..=8 {
        pipe.apply_message(&evidence(&keepalive, frame), metadata(Some(0), frame))
            .unwrap();
    }
    let before_events = pipe.observer().events().to_vec();
    let before_view = pipe.observer().view().cloned();
    let before_session_work = pipe.observer().reduction_work();
    let before_pipeline_work = pipe.reduction_work();
    let before_generation = pipe.wire_state().generation();
    let error = pipe
        .apply_message(&evidence(&keepalive, 9), metadata(Some(0), 9))
        .unwrap_err();
    assert_eq!(error.field, "bgp_session_events");
    assert_eq!(pipe.observer().events(), before_events);
    assert_eq!(pipe.observer().view(), before_view.as_ref());
    assert_eq!(pipe.observer().reduction_work(), before_session_work);
    assert_eq!(pipe.reduction_work(), before_pipeline_work);
    assert_eq!(pipe.wire_state().generation(), before_generation);
    assert!(pipe.rib().events().is_empty());
    assert!(!pipe.tainted());
    let replay = pipe
        .apply_message(&evidence(&keepalive, 8), metadata(Some(0), 8))
        .unwrap();
    assert!(replay.replayed);
    assert_eq!(pipe.observer().reduction_work(), before_session_work);
    assert_eq!(pipe.reduction_work(), before_pipeline_work);
    assert_eq!(pipe.observer().events(), before_events);
}

#[test]
fn repeated_same_prefix_origin_history_hits_default_work_budget_atomically() {
    let mut pipe = pipeline();
    establish(&mut pipe);
    let mut failed_frame = None;
    let wire = announcement();
    // The adversely executed predecessor fixture hit this unchanged default
    // work cap within 64 same-prefix updates. Preserve that refusal as evidence.
    for frame in 3..67 {
        let before_wire = pipe.wire_state().clone();
        let before_events = pipe.observer().events().to_vec();
        let before_view = pipe.observer().view().cloned();
        let before_rib = pipe.rib().events().to_vec();
        let before_entries = pipe.rib().entries().clone();
        let before_session_diagnostics = pipe.observer().reduction_work();
        let before_pipeline_diagnostics = pipe.reduction_work();
        let before_rib_diagnostics = pipe.rib().transaction_diagnostics();
        let before_session_charge = (
            pipe.observer().retained_bytes(),
            pipe.observer().accounted_work(),
        );
        let before_rib_charge = (pipe.rib().retained_bytes(), pipe.rib().accounted_work());
        match pipe.apply_message(&evidence(&wire, frame), metadata(Some(0), frame)) {
            Ok(receipt) => {
                assert_eq!(receipt.session_status, SessionApplyStatus::Applied);
                assert_eq!(receipt.rib_status, Some(RibApplyStatus::Applied));
                assert_eq!(pipe.rib().entries().len(), 1);
                let entry = pipe.rib().entries().values().next().unwrap();
                assert_eq!(entry.status, RouteStatus::Active);
                assert_eq!(
                    entry.versions[0].witnesses.len(),
                    usize::try_from(frame - 2).unwrap()
                );
                assert_eq!(
                    entry.versions[0].occurrences.len(),
                    usize::try_from(frame - 2).unwrap()
                );
            }
            Err(error) => {
                assert_eq!(error.code, ErrorCode::LimitExceeded);
                assert_eq!(error.field, "bgp_rib_budget");
                assert!(frame > 3);
                assert_eq!(pipe.wire_state(), &before_wire);
                assert_eq!(pipe.observer().events(), before_events);
                assert_eq!(pipe.observer().view(), before_view.as_ref());
                assert_eq!(pipe.rib().events(), before_rib);
                assert_eq!(pipe.rib().entries(), &before_entries);
                assert_eq!(pipe.observer().reduction_work(), before_session_diagnostics);
                assert_eq!(pipe.reduction_work(), before_pipeline_diagnostics);
                assert_eq!(pipe.rib().transaction_diagnostics(), before_rib_diagnostics);
                assert_eq!(
                    (
                        pipe.observer().retained_bytes(),
                        pipe.observer().accounted_work()
                    ),
                    before_session_charge
                );
                assert_eq!(
                    (pipe.rib().retained_bytes(), pipe.rib().accounted_work()),
                    before_rib_charge
                );
                assert!(pipe.rib().gaps().is_empty());
                assert!(!pipe.tainted());
                assert_eq!(
                    pipe.apply_message(&evidence(&wire, frame), metadata(Some(0), frame))
                        .unwrap_err()
                        .field,
                    "bgp_rib_budget"
                );
                assert_eq!(pipe.observer().events(), before_events);
                assert_eq!(pipe.rib().events(), before_rib);
                assert_eq!(pipe.rib().entries(), &before_entries);
                assert_eq!(pipe.rib().transaction_diagnostics(), before_rib_diagnostics);
                failed_frame = Some(frame);
                break;
            }
        }
    }
    assert!(
        failed_frame.is_some(),
        "same-key origin history must retain its default-budget refusal"
    );
}
