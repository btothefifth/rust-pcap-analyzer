//! Tiny independent RFC 7313 wire fixtures through sealed imported replay.
//! These establish offline parsing/layout evidence, never endpoint processing.
use pcap_evidence::{json::Json, sha256};
use pcap_evidence_product::deep::{
    bgp_bmp::{BmpLimits, BmpSource},
    bgp_bmp_store,
    bgp_mrt::{MrtLimits, MrtSource},
    bgp_mrt_store,
    bgp_rib::{AdjRibIn, RibEventKind, RouteStatus, VersionDisposition},
    Limits,
};
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

static SERIAL: AtomicU64 = AtomicU64::new(0);
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "pcap-imported-refresh-{}-{}",
            std::process::id(),
            SERIAL.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn member<'a>(json: &'a Json, key: &str) -> &'a Json {
    let Json::Object(fields) = json else {
        panic!("object expected: {json:?}")
    };
    &fields
        .iter()
        .find(|(name, _)| *name == key)
        .unwrap_or_else(|| panic!("missing {key}: {json:?}"))
        .1
}
fn bgp(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut bytes = vec![255; 16];
    bytes.extend_from_slice(&((19 + body.len()) as u16).to_be_bytes());
    bytes.push(kind);
    bytes.extend_from_slice(body);
    bytes
}
fn open(local: bool, capabilities: &[u8]) -> Vec<u8> {
    let mut body = vec![4];
    body.extend_from_slice(&(if local { 65002u16 } else { 65001u16 }).to_be_bytes());
    body.extend_from_slice(&90u16.to_be_bytes());
    body.extend_from_slice(&[192, 0, 2, if local { 2 } else { 1 }]);
    if capabilities.is_empty() {
        body.push(0);
    } else {
        body.push((2 + capabilities.len()) as u8);
        body.extend_from_slice(&[2, capabilities.len() as u8]);
        body.extend_from_slice(capabilities);
    }
    bgp(1, &body)
}
fn mrt(subtype: u16, payload: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&65001u16.to_be_bytes());
    body.extend_from_slice(&65002u16.to_be_bytes());
    body.extend_from_slice(&7u16.to_be_bytes());
    body.extend_from_slice(&1u16.to_be_bytes());
    body.extend_from_slice(&[192, 0, 2, 1, 192, 0, 2, 2]);
    body.extend_from_slice(payload);
    let mut bytes = 10u32.to_be_bytes().to_vec();
    bytes.extend_from_slice(&16u16.to_be_bytes());
    bytes.extend_from_slice(&subtype.to_be_bytes());
    bytes.extend_from_slice(&(body.len() as u32).to_be_bytes());
    bytes.extend_from_slice(&body);
    bytes
}
fn state(old: u16, new: u16) -> Vec<u8> {
    let mut payload = old.to_be_bytes().to_vec();
    payload.extend_from_slice(&new.to_be_bytes());
    mrt(0, &payload)
}
fn message(local: bool, bytes: &[u8]) -> Vec<u8> {
    mrt(if local { 6 } else { 1 }, bytes)
}
fn established(peer_caps: &[u8], local_caps: &[u8]) -> Vec<u8> {
    [
        state(3, 4),
        message(false, &open(false, peer_caps)),
        message(true, &open(true, local_caps)),
        state(4, 5),
        state(5, 6),
    ]
    .concat()
}
fn refresh(subtype: u8) -> Vec<u8> {
    bgp(5, &[0, 1, subtype, 1])
}
fn replay(input: &[u8]) -> bgp_mrt_store::MrtReplayArchive {
    let fresh = replay_source(input);
    assert!(fresh.bgp4mp_candidates.is_empty());
    fresh
}
fn replay_source(input: &[u8]) -> bgp_mrt_store::MrtReplayArchive {
    let scratch = Scratch::new();
    let path = scratch.0.join("source.mrt");
    let created = bgp_mrt_store::create(
        &path,
        input,
        MrtSource {
            source_id: "refresh-fixture".into(),
            checkpoint_id: "one".into(),
        },
        1 << 20,
        MrtLimits::default(),
        Limits::default(),
    )
    .unwrap();
    let fresh =
        bgp_mrt_store::replay(&path, 1 << 20, MrtLimits::default(), Limits::default()).unwrap();
    assert_eq!(created.bgp4mp_events, fresh.bgp4mp_events);
    assert_eq!(created.bgp4mp_rib.events(), fresh.bgp4mp_rib.events());
    assert_eq!(created.bgp4mp_rib.entries(), fresh.bgp4mp_rib.entries());
    assert_eq!(created.bgp4mp_rib.gaps(), fresh.bgp4mp_rib.gaps());
    assert_eq!(created.bgp4mp_rib.eors(), fresh.bgp4mp_rib.eors());
    fresh
}
fn last(archive: &bgp_mrt_store::MrtReplayArchive) -> &Json {
    archive.bgp4mp_events.last().unwrap()
}
fn assert_event(archive: &bgp_mrt_store::MrtReplayArchive, expected: &str, wire: &[u8]) {
    let event = last(archive);
    assert_eq!(
        member(event, "parse_status"),
        &Json::from(expected),
        "{event:?}"
    );
    assert_eq!(member(event, "source_authenticated"), &Json::from(false));
    assert_eq!(member(event, "endpoint_state_claimed"), &Json::from(false));
    let range = member(event, "message_range");
    assert_eq!(
        member(range, "sha256"),
        &Json::from(sha256::hex(&sha256::digest(wire)))
    );
    if wire.len() == 23 && expected == "decoded_route_refresh" && matches!(wire[21], 1 | 2) {
        let detail = member(event, "detail");
        assert_eq!(
            member(detail, "receiver_capability70_advertised"),
            &Json::from(true)
        );
        assert_eq!(
            member(detail, "sender_layout_basis"),
            &Json::from("observed_peer_capability70_for_sender_layout")
        );
        assert_eq!(
            member(detail, "negotiation_established"),
            &Json::from(false)
        );
        assert_eq!(
            member(detail, "endpoint_processing_claimed"),
            &Json::from(false)
        );
    }
}

#[test]
fn ordinary_refresh_without_enhanced_capability_remains_decoded() {
    for local in [false, true] {
        let wire = refresh(0);
        let mut input = established(&[], &[]);
        input.extend(message(local, &wire));
        assert_event(&replay(&input), "decoded_route_refresh", &wire);
    }
}
#[test]
fn reserved_and_unassigned_refresh_subtypes_are_ignored() {
    for subtype in [3, 255] {
        let wire = refresh(subtype);
        let mut input = established(&[70, 0], &[70, 0]);
        input.extend(message(false, &wire));
        assert_event(
            &replay(&input),
            "ignored_unknown_route_refresh_subtype",
            &wire,
        );
    }
}
#[test]
fn enhanced_refresh_without_receiver_capability_is_quarantined() {
    for subtype in [1, 2] {
        for local in [false, true] {
            let wire = refresh(subtype);
            let mut input = established(&[], &[]);
            input.extend(message(local, &wire));
            assert_event(
                &replay(&input),
                "quarantined_route_refresh_capability_context",
                &wire,
            );
        }
        // Reported Established alone supplies no opposite OPEN advertisement.
        let wire = refresh(subtype);
        let input = [state(5, 6), message(false, &wire)].concat();
        let archive = replay(&input);
        assert_event(
            &archive,
            "quarantined_route_refresh_capability_context",
            &wire,
        );
        assert_eq!(
            member(member(last(&archive), "detail"), "sender_layout_basis"),
            &Json::from("missing_receiver_open")
        );
    }
}
#[test]
fn enhanced_refresh_unilateral_receiver_advertisement_is_directional() {
    // RFC 7313 section 4: sender must have received the receiver's cap 70.
    for subtype in [1, 2] {
        for advertising_local in [false, true] {
            let mut input = if advertising_local {
                established(&[], &[70, 0])
            } else {
                established(&[70, 0], &[])
            };
            let wire = refresh(subtype);
            input.extend(message(!advertising_local, &wire));
            let permitted = replay(&input);
            assert_event(&permitted, "decoded_route_refresh", &wire);
            assert_eq!(
                member(
                    member(last(&permitted), "detail"),
                    "receiver_open_direction"
                ),
                &Json::from(u8::from(advertising_local))
            );
            input.extend(message(advertising_local, &wire));
            assert_event(
                &replay(&input),
                "quarantined_route_refresh_capability_context",
                &wire,
            );
        }
    }
}
#[test]
fn enhanced_refresh_bilateral_advertisements_preserve_both_marker_types() {
    for subtype in [1, 2] {
        for local in [false, true] {
            let wire = refresh(subtype);
            let mut input = established(&[70, 0], &[70, 0]);
            input.extend(message(local, &wire));
            assert_event(&replay(&input), "decoded_route_refresh", &wire);
        }
    }
}
#[test]
fn malformed_or_duplicate_receiver_open_cannot_supply_capability_authority() {
    for malformed in [false, true] {
        let mut input = established(&[], if malformed { &[70, 1, 0] } else { &[70, 0] });
        if !malformed {
            // Duplicate OPEN in the opening state; preserve valid source FSM edges.
            input = [
                state(3, 4),
                message(false, &open(false, &[])),
                message(true, &open(true, &[70, 0])),
                message(true, &open(true, &[70, 0])),
                state(4, 5),
                state(5, 6),
            ]
            .concat();
        }
        let wire = refresh(1);
        input.extend(message(false, &wire));
        assert_event(
            &replay(&input),
            "quarantined_route_refresh_capability_context",
            &wire,
        );
    }
}
#[test]
fn reset_clears_enhanced_refresh_capability_before_the_next_generation() {
    let mut input = established(&[70, 0], &[70, 0]);
    let wire = refresh(1);
    input.extend(message(false, &wire));
    assert_event(&replay(&input), "decoded_route_refresh", &wire);
    input.extend(state(6, 1));
    input.extend(state(1, 2));
    input.extend(state(2, 4));
    input.extend(message(false, &open(false, &[])));
    input.extend(message(true, &open(true, &[])));
    input.extend(state(4, 5));
    input.extend(state(5, 6));
    input.extend(message(false, &wire));
    let archive = replay(&input);
    assert_event(
        &archive,
        "quarantined_route_refresh_capability_context",
        &wire,
    );
    assert_eq!(member(last(&archive), "generation"), &Json::from(1u64));
}
#[test]
fn enhanced_refresh_wrong_length_remains_rejected_with_exact_wire_identity() {
    for subtype in [1, 2] {
        for body in [vec![0, 1, subtype], vec![0, 1, subtype, 1, 0]] {
            let wire = bgp(5, &body);
            let mut input = established(&[70, 0], &[70, 0]);
            input.extend(message(false, &wire));
            assert_event(&replay(&input), "rejected", &wire);
        }
    }
}

#[test]
fn tracked_route_refresh_dispositions_preserve_history_and_qualify_continuity() {
    // Independently encoded 2-octet AS_SEQUENCE [65001], ORIGIN IGP,
    // NEXT_HOP 192.0.2.9, and ordinary 198.51.100.0/24 announcement.
    // No LOCAL_PREF or peer-relationship-dependent optional attribute.
    let mut attributes = vec![0x40, 1, 1, 0, 0x40, 2, 4, 2, 1];
    attributes.extend_from_slice(&65001u16.to_be_bytes());
    attributes.extend_from_slice(&[0x40, 3, 4, 192, 0, 2, 9]);
    let mut body = vec![0, 0];
    body.extend_from_slice(&(attributes.len() as u16).to_be_bytes());
    body.extend_from_slice(&attributes);
    body.extend_from_slice(&[24, 198, 51, 100]);
    let update = bgp(2, &body);
    for (local_caps, subtype, expected_status, expect_gap) in [
        (&[70, 0][..], 1, "decoded_route_refresh", false),
        (&[70, 0][..], 2, "decoded_route_refresh", false),
        (&[][..], 3, "ignored_unknown_route_refresh_subtype", false),
        (&[][..], 255, "ignored_unknown_route_refresh_subtype", false),
        (
            &[][..],
            1,
            "quarantined_route_refresh_capability_context",
            true,
        ),
        (
            &[][..],
            2,
            "quarantined_route_refresh_capability_context",
            true,
        ),
    ] {
        let mut input = established(&[], local_caps);
        input.extend(message(false, &update));
        let wire = refresh(subtype);
        input.extend(message(false, &wire));
        let after = replay_source(&input);
        // Use the real admitted UPDATE event from the same sealed batch to
        // establish its pre-refresh native state. Sealing a shorter prefix
        // would create a different import batch/partition identity.
        assert_eq!(after.bgp4mp_candidates.len(), 1);
        assert_eq!(after.state.observations().len(), 1);
        assert_eq!(
            after.bgp4mp_candidates[0].message_sha256,
            sha256::hex(&sha256::digest(&update))
        );
        assert_eq!(
            member(&after.bgp4mp_events[5], "parse_status"),
            &Json::from("decoded_update_candidate")
        );
        assert!(matches!(
            after.bgp4mp_rib.events()[0].kind,
            RibEventKind::Update(_)
        ));
        let mut before = AdjRibIn::new(Limits::default()).unwrap();
        before.apply(after.bgp4mp_rib.events()[0].clone()).unwrap();
        assert_eq!(before.entries().len(), 1);
        assert!(before.gaps().is_empty());
        assert!(before.eors().is_empty());
        assert_eq!(before.events().len(), 1);
        let original = before.entries().values().next().unwrap();
        assert_eq!(original.status, RouteStatus::Active);
        assert_eq!(original.key.scope.generation, 0);
        assert_eq!(original.key.scope.direction, Some(0));
        assert_eq!(original.key.family.afi, 1);
        assert_eq!(original.key.family.safi, 1);
        assert_eq!(original.key.prefix.afi, 1);
        assert_eq!(original.key.prefix.safi, 1);
        assert_eq!(original.key.prefix.length, 24);
        assert_eq!(original.key.prefix.address, "198.51.100.0");
        assert_eq!(original.versions.len(), 1);
        assert_eq!(
            original.versions[0].disposition,
            VersionDisposition::Current
        );

        assert_event(&after, expected_status, &wire);
        assert_eq!(after.bgp4mp_rib.entries().len(), 1);
        assert!(after.bgp4mp_rib.eors().is_empty());
        assert!(after.bgp4mp_rib.rejections().is_empty());
        let retained = after.bgp4mp_rib.entries().values().next().unwrap();
        assert_eq!(retained.key, original.key);
        assert_eq!(retained.versions, original.versions);
        assert_eq!(retained.last_witness, original.last_witness);
        // The existing version remains Current: a gap does not invent a
        // withdrawal, reset, refreshed version, or stale-route cleanup.
        assert_eq!(
            retained.status,
            if expect_gap {
                RouteStatus::Unresolved
            } else {
                RouteStatus::Active
            }
        );
        assert_eq!(after.bgp4mp_rib.events().len(), 1 + usize::from(expect_gap));
        assert_eq!(&after.bgp4mp_rib.events()[..1], before.events());
        assert_eq!(after.bgp4mp_rib.gaps().len(), usize::from(expect_gap));
        if expect_gap {
            let event = &after.bgp4mp_rib.events()[1];
            assert_eq!(
                event.kind,
                RibEventKind::Gap {
                    reason: "source_message_quarantined_route_refresh_capability_context".into()
                }
            );
            let (scope, witness) = &after.bgp4mp_rib.gaps()[0];
            assert_eq!(scope, &event.scope);
            assert_eq!(witness, &event.record_id);
            assert_eq!(scope.source, original.key.scope.source);
            assert_eq!(scope.session, original.key.scope.session);
            assert_eq!(scope.generation, original.key.scope.generation);
            assert_eq!(scope.peer, original.key.scope.peer);
            assert_eq!(scope.direction, None);
        } else {
            assert_eq!(after.bgp4mp_rib.entries(), before.entries());
        }
    }
}
#[test]
fn reported_bmp_opens_cannot_qualify_route_refresh_as_route_monitoring() {
    fn bmp(kind: u8, body: &[u8]) -> Vec<u8> {
        let mut bytes = vec![3];
        bytes.extend_from_slice(&((6 + body.len()) as u32).to_be_bytes());
        bytes.push(kind);
        bytes.extend_from_slice(body);
        bytes
    }
    let mut peer = vec![0, 0];
    peer.extend_from_slice(&[0; 8]);
    peer.extend_from_slice(&[0; 12]);
    peer.extend_from_slice(&[192, 0, 2, 1]);
    peer.extend_from_slice(&65001u32.to_be_bytes());
    peer.extend_from_slice(&[192, 0, 2, 1]);
    peer.extend_from_slice(&10u32.to_be_bytes());
    peer.extend_from_slice(&0u32.to_be_bytes());
    let mut up = peer.clone();
    up.extend_from_slice(&[0; 12]);
    up.extend_from_slice(&[192, 0, 2, 2]);
    up.extend_from_slice(&179u16.to_be_bytes());
    up.extend_from_slice(&40000u16.to_be_bytes());
    up.extend(open(true, &[70, 0]));
    up.extend(open(false, &[70, 0]));
    let mut input = bmp(3, &up);
    for subtype in [0, 1, 2, 3, 255] {
        let mut monitoring = peer.clone();
        monitoring.extend(refresh(subtype));
        input.extend(bmp(0, &monitoring));
    }
    let scratch = Scratch::new();
    let path = scratch.0.join("source.bmp");
    let archive = bgp_bmp_store::create(
        &path,
        &input,
        BmpSource {
            source_id: "refresh-bmp".into(),
            checkpoint_id: "one".into(),
        },
        1 << 20,
        BmpLimits::default(),
        Limits::default(),
    )
    .unwrap();
    let fresh =
        bgp_bmp_store::replay(&path, 1 << 20, BmpLimits::default(), Limits::default()).unwrap();
    assert_eq!(archive.bmp_events, fresh.bmp_events);
    assert_eq!(
        member(&fresh.bmp_events[0], "status"),
        &Json::from("reported_peer_up")
    );
    for event in &fresh.bmp_events[1..] {
        assert_eq!(member(event, "status"), &Json::from("opaque_quarantine"));
    }
    assert!(fresh.state.observations().is_empty());
}
