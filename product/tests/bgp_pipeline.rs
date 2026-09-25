//! Independent wire-to-session-to-RIB joins through the public atomic pipeline.
use pcap_evidence::{
    provenance::{EvidenceBytes, PacketId},
    sha256,
};
use pcap_evidence_product::deep::{
    bgp::PcapMetadata,
    bgp_pipeline::CapturedSessionPipeline,
    bgp_rib::{ApplyStatus as RibApplyStatus, RouteStatus},
    bgp_session::{ApplyStatus as SessionApplyStatus, CapabilityContext},
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
