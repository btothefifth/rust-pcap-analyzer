//! Fixed wire layouts and independent contract assertions; no device/RIB oracle.
use pcap_evidence::{
    json::Json,
    provenance::{EvidenceBytes, PacketId},
    sha256, ErrorCode,
};
use pcap_evidence_product::deep::{
    bgp::{
        self, ImportedRouteObservation, PathAttributes, PcapMetadata, PeerRelationship, Prefix,
        RouteAction, SessionState,
    },
    bgp_association::{
        self as association, AssociationStatus, Coverage, DimensionRule, Dimensions, DirectionRule,
        EndpointIdentity, InternalEvidence, InternalInput, InternalKind, Policy, Provenance,
        RouteBatch, RouteContext, RouteEvidence, Scope, SourceIdentity, SpatialRule, TimeLabel,
        TimePolicy,
    },
    bgp_import::{self, ClockPolicy, ImportContext, ObservationClock, SourceBatch, SourceRange},
    bgp_replay::{Completion, FeedEnvelope, FeedRecord, FeedReplay, ReplayStatus},
    bgp_state::{ApplyStatus, CandidateState, EffectKind, Observation},
    Limits,
};

const VECTORS: &str = include_str!("fixtures/bgp_producer.hex");
fn wire(name: &str) -> Vec<u8> {
    let row = VECTORS
        .lines()
        .find(|row| row.split_whitespace().next() == Some(name))
        .unwrap();
    let hex = row.split_whitespace().nth(1).unwrap();
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}
fn packet(frame: u64) -> PacketId {
    PacketId {
        capture: sha256::digest(b"producer-capture"),
        frame,
        record_offset: frame * 100,
    }
}
fn evidence(raw: &[u8], frame: u64) -> EvidenceBytes {
    EvidenceBytes::from_packet(raw, packet(frame), 54)
}
fn metadata(direction: Option<u8>, frame: u64) -> PcapMetadata {
    PcapMetadata {
        source_id: "capture-source".into(),
        record_id: format!("record-{frame}"),
        observed_at_ns: Some(-7),
        session: Some(7),
        direction,
        peer: None,
        local: None,
    }
}
fn get<'a>(value: &'a Json, key: &str) -> &'a Json {
    let Json::Object(items) = value else {
        panic!("expected object")
    };
    &items
        .iter()
        .find(|(k, _)| *k == key)
        .unwrap_or_else(|| panic!("missing {key}"))
        .1
}
fn array(value: &Json) -> &[Json] {
    let Json::Array(items) = value else {
        panic!("expected array")
    };
    items
}
fn set(value: &mut Json, key: &'static str, data: Json) {
    let Json::Object(items) = value else {
        panic!("expected object")
    };
    if let Some((_, old)) = items.iter_mut().find(|(k, _)| *k == key) {
        *old = data;
    } else {
        items.push((key, data));
    }
}
fn decode(name: &str, state: &mut SessionState, direction: Option<u8>, frame: u64) -> Json {
    bgp::decode_pcap(
        &evidence(&wire(name), frame),
        metadata(direction, frame),
        state,
        &Limits::default(),
    )
    .unwrap()
}
fn route(value: &Json) -> &Json {
    &array(get(value, "routes"))[0]
}
fn attrs(value: &Json) -> &Json {
    get(route(value), "attributes")
}
fn ranges(value: &Json) -> &[Json] {
    array(get(get(value, "message_detail"), "attribute_ranges"))
}
fn context(value: &Json) -> &Json {
    get(value, "producer_context")
}
fn opens(value: &Json) -> &[Json] {
    array(get(context(value), "open_sides"))
}
fn paired() -> SessionState {
    let mut state = SessionState::default();
    decode("open_four_a", &mut state, Some(0), 1);
    decode("open_four_b", &mut state, Some(1), 2);
    state
}
fn changed_update(attributes: &[u8], prefixes: &[u8]) -> Vec<u8> {
    let length = 23 + attributes.len() + prefixes.len();
    let mut raw = vec![255; 16];
    raw.extend_from_slice(&(length as u16).to_be_bytes());
    raw.extend_from_slice(&[2, 0, 0]);
    raw.extend_from_slice(&(attributes.len() as u16).to_be_bytes());
    raw.extend_from_slice(attributes);
    raw.extend_from_slice(prefixes);
    raw
}
fn wire_attribute(flags: u8, code: u8, payload: &[u8]) -> Vec<u8> {
    let mut value = vec![flags, code, payload.len() as u8];
    value.extend_from_slice(payload);
    value
}
fn required_attributes_except(code: u8) -> Vec<u8> {
    let mut values = Vec::new();
    for (required_code, flags, payload) in [
        (1, 0x40, &[0][..]),
        (2, 0x40, &[2, 1, 0, 1][..]),
        (3, 0x40, &[192, 0, 2, 1][..]),
    ] {
        if required_code != code {
            values.extend(wire_attribute(flags, required_code, payload));
        }
    }
    values
}
fn atomic_error(
    raw: &[u8],
    meta: PcapMetadata,
    state: &mut SessionState,
    limits: &Limits,
) -> pcap_evidence::Error {
    let before = state.clone();
    let error = bgp::decode_pcap(
        &evidence(
            raw,
            meta.record_id
                .strip_prefix("record-")
                .unwrap_or("3")
                .parse()
                .unwrap_or(3),
        ),
        meta,
        state,
        limits,
    )
    .unwrap_err();
    assert_eq!(*state, before);
    error
}

#[test]
fn direct_byte_field_depth_span_work_and_output_budgets_fail_atomically() {
    for which in 0..7 {
        let mut l = Limits::default();
        match which {
            0 => l.input_bytes = 36,
            1 => l.fields = 10,
            2 => l.depth = 2,
            3 => l.spans = 1,
            4 => l.work = 10,
            5 => l.output_bytes = 1,
            _ => l.retained_bytes = 1,
        }
        let mut state = SessionState::default();
        let error = atomic_error(&wire("open_four_a"), metadata(Some(0), 1), &mut state, &l);
        assert_eq!(error.code, ErrorCode::LimitExceeded, "boundary {which}");
    }
}
#[test]
fn output_failure_after_valid_open_cannot_commit_capabilities_or_generation() {
    let mut state = SessionState::default();
    let l = Limits {
        output_bytes: 64,
        ..Limits::default()
    };
    let error = atomic_error(&wire("open_four_a"), metadata(Some(0), 1), &mut state, &l);
    assert_eq!(error.code, ErrorCode::LimitExceeded);
    let output = decode("keepalive", &mut state, Some(0), 2);
    assert!(opens(&output).is_empty());
    assert_eq!(state.generation(), 0);
}
#[test]
fn notification_publication_failure_cannot_reset_existing_state() {
    let mut state = paired();
    let l = Limits {
        output_bytes: 1,
        ..Limits::default()
    };
    atomic_error(&wire("notification"), metadata(Some(1), 3), &mut state, &l);
    let output = decode("keepalive", &mut state, Some(0), 4);
    assert_eq!(opens(&output).len(), 2);
    assert_eq!(state.generation(), 0);
}
#[test]
fn active_occurrence_and_aggregate_route_budgets_are_not_silent_eviction() {
    let mut state = SessionState::default();
    decode("open_four_a", &mut state, Some(0), 1);
    let mut l = Limits {
        active: 1,
        ..Limits::default()
    };
    assert_eq!(
        atomic_error(&wire("open_four_b"), metadata(Some(1), 2), &mut state, &l).code,
        ErrorCode::LimitExceeded
    );
    l = Limits {
        elements: 1,
        ..Limits::default()
    };
    assert_eq!(
        atomic_error(
            &wire("open_duplicate"),
            metadata(Some(0), 3),
            &mut state,
            &l
        )
        .code,
        ErrorCode::LimitExceeded
    );
    let raw = changed_update(&[], &[0, 0, 0]);
    l = Limits {
        elements: 2,
        ..Limits::default()
    };
    assert_eq!(
        atomic_error(&raw, metadata(Some(0), 4), &mut state, &l).code,
        ErrorCode::LimitExceeded
    );
}
#[test]
fn route_attribute_replication_and_collection_budgets_are_preflighted() {
    let original = wire("announce_two");
    let many = changed_update(&original[23..41], &[0; 32]);
    let mut l = Limits {
        fields: 200,
        ..Limits::default()
    };
    assert_eq!(
        atomic_error(
            &many,
            metadata(Some(0), 1),
            &mut SessionState::default(),
            &l
        )
        .code,
        ErrorCode::LimitExceeded
    );
    let raw = changed_update(&[0xc0, 8, 12, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3], &[]);
    l = Limits {
        elements: 2,
        ..Limits::default()
    };
    assert_eq!(
        atomic_error(&raw, metadata(Some(0), 1), &mut SessionState::default(), &l).code,
        ErrorCode::LimitExceeded
    );
}
#[test]
fn lower_limits_recheck_retained_open_evidence_before_cloning() {
    let mut state = paired();
    let mut l = Limits {
        spans: 3,
        ..Limits::default()
    };
    assert_eq!(
        atomic_error(&wire("keepalive"), metadata(Some(0), 3), &mut state, &l).code,
        ErrorCode::LimitExceeded
    );
    l = Limits {
        active: 1,
        ..Limits::default()
    };
    assert_eq!(
        atomic_error(&wire("keepalive"), metadata(Some(0), 3), &mut state, &l).code,
        ErrorCode::LimitExceeded
    );
}
#[test]
fn exact_output_budget_has_a_passing_neighbor() {
    let mut state = SessionState::default();
    let expected = decode("keepalive", &mut state, Some(0), 1);
    let mut l = Limits {
        output_bytes: expected.encode().len(),
        ..Limits::default()
    };
    let actual = bgp::decode_pcap(
        &evidence(&wire("keepalive"), 1),
        metadata(Some(0), 1),
        &mut SessionState::default(),
        &l,
    )
    .unwrap();
    assert_eq!(actual, expected);
    l.output_bytes -= 1;
    assert_eq!(
        atomic_error(
            &wire("keepalive"),
            metadata(Some(0), 1),
            &mut SessionState::default(),
            &l
        )
        .code,
        ErrorCode::LimitExceeded
    );
}
#[test]
fn invalid_direction_and_empty_overlong_or_control_identities_are_errors() {
    for n in 0..8 {
        let mut m = metadata(Some(0), 1);
        match n {
            0 => m.direction = Some(2),
            1 => m.source_id.clear(),
            2 => m.record_id = "  ".into(),
            3 => m.record_id = "bad\nrecord".into(),
            4 => m.peer = Some(String::new()),
            5 => m.local = Some("x".repeat(1025)),
            6 => m.source_id = "x".repeat(1025),
            _ => m.direction = Some(255),
        }
        atomic_error(
            &wire("open_four_a"),
            m,
            &mut SessionState::default(),
            &Limits::default(),
        );
    }
}
#[test]
fn missing_direction_retains_open_without_updating_a_direction_zero_slot() {
    let mut state = SessionState::default();
    let before = state.clone();
    let value = decode("open_four_a", &mut state, None, 1);
    assert_eq!(state, before);
    assert_eq!(get(&value, "direction"), &Json::Null);
    assert_eq!(
        get(get(&value, "message_detail"), "four_octet_asn"),
        &Json::from(65000u32)
    );
    assert!(opens(&value).is_empty());
    assert_eq!(get(context(&value), "asn_width"), &Json::Null);
}
#[test]
fn missing_session_does_not_borrow_an_existing_generation_or_open() {
    let mut state = paired();
    state.reset().unwrap();
    let before = state.clone();
    let mut m = metadata(Some(0), 3);
    m.session = None;
    let value = bgp::decode_pcap(
        &evidence(&wire("open_four_a"), 3),
        m,
        &mut state,
        &Limits::default(),
    )
    .unwrap();
    assert_eq!(state, before);
    assert_eq!(get(&value, "generation"), &Json::Null);
    assert_eq!(get(context(&value), "scope_bound"), &Json::Bool(false));
    assert!(opens(&value).is_empty());
    assert!(Observation::from_normalized(&value, None, &Limits::default()).is_err());
}
#[test]
fn session_source_and_capture_identity_cannot_be_rebound_by_order_or_reset() {
    for n in 0..4 {
        let mut state = paired();
        if n == 3 {
            state.reset().unwrap();
        }
        let before = state.clone();
        let mut m = metadata(Some(0), 3);
        let raw = wire("keepalive");
        let mut id = packet(3);
        match n {
            0 => m.session = Some(8),
            1 => m.source_id = "different-source".into(),
            2 => id.capture = sha256::digest(b"other-capture"),
            _ => m.session = Some(9),
        }
        assert!(bgp::decode_pcap(
            &EvidenceBytes::from_packet(&raw, id, 54),
            m,
            &mut state,
            &Limits::default()
        )
        .is_err());
        assert_eq!(state, before);
    }
}
#[test]
fn one_sided_asn_advertisement_never_establishes_negotiated_width() {
    let mut state = SessionState::default();
    let open = decode("open_four_a", &mut state, Some(0), 1);
    assert_eq!(get(context(&open), "asn_width"), &Json::Null);
    // Wire layout uniquely permits two-byte ASNs despite a four-byte advertisement.
    let value = decode("announce_two", &mut state, Some(0), 2);
    assert!(!array(get(attrs(&value), "as_path")).is_empty());
    assert_eq!(
        get(&ranges(&value)[1], "interpretation"),
        &Json::from("wire_shape_only_not_negotiated")
    );
    assert_eq!(get(&value, "negotiation_established"), &Json::Bool(false));
}
#[test]
fn both_advertisements_supply_a_layout_context_without_comparing_peer_asns() {
    let mut state = paired();
    let value = decode("announce_four", &mut state, Some(0), 3);
    assert_eq!(get(context(&value), "asn_width"), &Json::from(4usize));
    assert_eq!(
        get(context(&value), "asn_width_basis"),
        &Json::from("both_four_octet_advertisements")
    );
    assert_eq!(
        get(&array(get(attrs(&value), "as_path"))[0], "values"),
        &Json::array([Json::from(65636u32)])
    );
    assert_eq!(get(&value, "negotiation_established"), &Json::Bool(false));
}
#[test]
fn missing_four_byte_advertisement_on_one_of_two_sides_preserves_two_byte_context() {
    let mut state = SessionState::default();
    decode("open_four_a", &mut state, Some(0), 1);
    decode("open_two", &mut state, Some(1), 2);
    let value = decode("announce_two", &mut state, Some(0), 3);
    assert_eq!(get(context(&value), "asn_width"), &Json::from(2usize));
    let malformed = bgp::decode_pcap(
        &evidence(&wire("announce_four"), 4),
        metadata(Some(0), 4),
        &mut state,
        &Limits::default(),
    )
    .unwrap();
    assert_eq!(
        get(&ranges(&malformed)[1], "disposition"),
        &Json::from("treat_as_withdraw")
    );
    assert_eq!(
        get(get(&malformed, "message_detail"), "update_disposition"),
        &Json::from("treat_as_withdraw")
    );
    assert!(array(get(attrs(&malformed), "as_path")).is_empty());
}
#[test]
fn ambiguous_structural_as_path_retains_both_interpretations_and_no_scalar_winner() {
    let value = decode(
        "announce_dual_width",
        &mut SessionState::default(),
        Some(0),
        1,
    );
    assert!(array(get(attrs(&value), "as_path")).is_empty());
    let a = &ranges(&value)[1];
    assert_eq!(
        get(a, "interpretation"),
        &Json::from("unresolved_asn_width")
    );
    assert_eq!(array(get(get(a, "decoded"), "interpretations")).len(), 2);
    let observation = Observation::from_normalized(&value, None, &Limits::default()).unwrap();
    assert!(observation.routes()[0].ambiguous_attributes());
}
#[test]
fn duplicate_and_conflicting_capabilities_remain_all_visible_and_unselected() {
    for name in ["open_duplicate", "open_conflict"] {
        let value = decode(name, &mut SessionState::default(), Some(0), 1);
        let d = get(&value, "message_detail");
        let occurrences = array(get(d, "capability_occurrences"));
        assert_eq!(occurrences.len(), 2);
        let conflict = name == "open_conflict";
        assert_eq!(
            get(d, "four_octet_asn"),
            &if conflict {
                Json::Null
            } else {
                Json::from(65000u32)
            }
        );
        assert_eq!(get(d, "ambiguous"), &Json::Bool(conflict));
        assert_eq!(get(&occurrences[0], "start"), &Json::from(31usize));
        assert_eq!(get(&occurrences[1], "end"), &Json::from(43usize));
        assert_eq!(get(context(&value), "asn_width"), &Json::Null);
    }
}
#[test]
fn malformed_capability_and_partial_looking_open_leave_the_prior_state_intact() {
    let mut state = paired();
    let before = state.clone();
    let malformed = bgp::decode_pcap(
        &evidence(&wire("open_bad_cap_length"), 3),
        metadata(Some(0), 3),
        &mut state,
        &Limits::default(),
    )
    .unwrap();
    assert_eq!(
        get(
            &array(get(
                get(&malformed, "message_detail"),
                "capability_occurrences"
            ))[0],
            "valid"
        ),
        &Json::Bool(false)
    );
    assert_eq!(get(context(&malformed), "asn_width"), &Json::Null);
    assert_ne!(state, before); // The invalid OPEN is retained as conflicting source evidence.
    atomic_error(
        &wire("open_cap_crosses_parameter"),
        metadata(Some(0), 4),
        &mut state,
        &Limits::default(),
    );
}
#[test]
fn repeated_open_is_an_alternative_not_an_implicit_generation_boundary() {
    let mut state = paired();
    let value = decode("open_four_a", &mut state, Some(0), 3);
    assert_eq!(state.generation(), 0);
    assert_eq!(array(get(&opens(&value)[0], "observations")).len(), 2);
    assert_eq!(get(context(&value), "asn_width"), &Json::Null);
    let route = decode("announce_two", &mut state, Some(0), 4);
    assert!(array(get(attrs(&route), "as_path")).is_empty());
    assert_eq!(
        get(&ranges(&route)[1], "interpretation"),
        &Json::from("unresolved_capability_context")
    );
    assert!(
        Observation::from_normalized(&route, None, &Limits::default())
            .unwrap()
            .routes()[0]
            .ambiguous_attributes()
    );
}
#[test]
fn exact_immutable_open_replay_does_not_append_state_or_change_identical_output() {
    let mut state = SessionState::default();
    let first = decode("open_four_a", &mut state, Some(0), 1);
    let before = state.clone();
    let again = decode("open_four_a", &mut state, Some(0), 1);
    assert_eq!(state, before);
    assert_eq!(again, first);
}
#[test]
fn notification_and_explicit_reset_retire_both_sides_without_reusing_capabilities() {
    for explicit in [false, true] {
        let mut state = paired();
        if explicit {
            state.reset().unwrap();
        } else {
            decode("notification", &mut state, None, 3);
        }
        assert_eq!(state.generation(), 1);
        let value = decode("keepalive", &mut state, Some(0), 4);
        assert!(opens(&value).is_empty());
        assert_eq!(get(context(&value), "asn_width"), &Json::Null);
    }
}
#[test]
fn reversed_open_arrival_order_has_the_same_two_sided_context() {
    let mut first = paired();
    let mut reversed = SessionState::default();
    decode("open_four_b", &mut reversed, Some(1), 2);
    decode("open_four_a", &mut reversed, Some(0), 1);
    assert_eq!(first, reversed);
    assert_eq!(
        decode("keepalive", &mut first, Some(0), 3),
        decode("keepalive", &mut reversed, Some(0), 3)
    );
}

struct ScalarDuplicateCase<'a> {
    code: u8,
    field: &'static str,
    flags: u8,
    first: &'a [u8],
    alternate: &'a [u8],
}

#[test]
fn ordinary_scalar_duplicates_keep_the_first_effective_value_and_every_source_range() {
    let examples = [
        ScalarDuplicateCase {
            code: 1,
            field: "origin",
            flags: 0x40,
            first: &[0],
            alternate: &[1],
        },
        ScalarDuplicateCase {
            code: 3,
            field: "next_hop",
            flags: 0x40,
            first: &[192, 0, 2, 1],
            alternate: &[192, 0, 2, 2],
        },
        ScalarDuplicateCase {
            code: 4,
            field: "med",
            flags: 0x80,
            first: &[0, 0, 0, 5],
            alternate: &[0, 0, 0, 9],
        },
        ScalarDuplicateCase {
            code: 5,
            field: "local_preference",
            flags: 0x40,
            first: &[0, 0, 0, 5],
            alternate: &[0, 0, 0, 9],
        },
        ScalarDuplicateCase {
            code: 7,
            field: "aggregator",
            flags: 0xc0,
            first: &[0, 1, 192, 0, 2, 1],
            alternate: &[0, 2, 192, 0, 2, 2],
        },
        ScalarDuplicateCase {
            code: 9,
            field: "originator_id",
            flags: 0x80,
            first: &[192, 0, 2, 1],
            alternate: &[192, 0, 2, 2],
        },
    ];
    for case in examples {
        for identical in [false, true] {
            let second = if identical {
                case.first
            } else {
                case.alternate
            };
            let mut baseline_values = required_attributes_except(case.code);
            baseline_values.extend(wire_attribute(case.flags, case.code, case.first));
            let mut duplicate_values = baseline_values.clone();
            duplicate_values.extend(wire_attribute(case.flags, case.code, second));

            let decode_values = |values: &[u8], frame| {
                let raw = changed_update(values, &[24, 203, 0, 113]);
                let mut state = SessionState::default();
                state.set_peer_relationship(PeerRelationship::Internal);
                bgp::decode_pcap(
                    &evidence(&raw, frame),
                    metadata(Some(0), frame),
                    &mut state,
                    &Limits::default(),
                )
                .unwrap()
            };
            let baseline = decode_values(&baseline_values, 1);
            let result = decode_values(&duplicate_values, 2);
            let baseline_route = route(&baseline);
            let duplicate_route = route(&result);

            assert_eq!(
                get(attrs(&result), case.field),
                get(attrs(&baseline), case.field)
            );
            assert_ne!(get(attrs(&baseline), case.field), &Json::Null);
            assert_eq!(ranges(&result).len(), ranges(&baseline).len() + 1);
            let later = ranges(&result).last().unwrap();
            assert_eq!(
                get(later, "disposition"),
                &Json::from("discard_later_occurrence")
            );
            assert_eq!(
                get(later, "repetition"),
                &Json::from(if identical {
                    "duplicate_identical"
                } else {
                    "conflicting"
                })
            );
            assert_eq!(
                get(get(duplicate_route, "semantic_identity"), "completeness"),
                &Json::from("complete")
            );
            assert_eq!(
                get(
                    get(duplicate_route, "semantic_identity"),
                    "fingerprint_sha256"
                ),
                get(
                    get(baseline_route, "semantic_identity"),
                    "fingerprint_sha256"
                )
            );
            assert!(
                !Observation::from_normalized(&result, None, &Limits::default())
                    .unwrap()
                    .routes()[0]
                    .ambiguous_attributes()
            );
        }
    }
}
#[test]
fn duplicate_path_and_collection_attributes_keep_the_first_value_without_concatenation() {
    for (code, field, flags, first, second) in [
        (2, "as_path", 0x40, vec![2, 1, 0, 1], vec![2, 1, 0, 2]),
        (8, "communities", 0xc0, vec![0, 0, 0, 1], vec![0, 0, 0, 2]),
        (
            10,
            "cluster_list",
            0x80,
            vec![192, 0, 2, 1],
            vec![192, 0, 2, 2],
        ),
    ] {
        let mut baseline_values = required_attributes_except(code);
        baseline_values.extend(wire_attribute(flags, code, &first));
        let mut duplicate_values = baseline_values.clone();
        duplicate_values.extend(wire_attribute(flags, code, &second));
        let decode_values = |values: &[u8], frame| {
            let raw = changed_update(values, &[24, 203, 0, 113]);
            let mut state = SessionState::default();
            state.set_peer_relationship(PeerRelationship::Internal);
            bgp::decode_pcap(
                &evidence(&raw, frame),
                metadata(Some(0), frame),
                &mut state,
                &Limits::default(),
            )
            .unwrap()
        };
        let baseline = decode_values(&baseline_values, 1);
        let value = decode_values(&duplicate_values, 2);
        assert_eq!(get(attrs(&value), field), get(attrs(&baseline), field));
        assert_eq!(array(get(attrs(&value), field)).len(), 1);
        assert_eq!(ranges(&value).len(), ranges(&baseline).len() + 1);
        let later = ranges(&value).last().unwrap();
        assert_eq!(
            get(later, "disposition"),
            &Json::from("discard_later_occurrence")
        );
        assert_eq!(get(later, "repetition"), &Json::from("conflicting"));
        let baseline_identity = get(route(&baseline), "semantic_identity");
        let duplicate_identity = get(route(&value), "semantic_identity");
        assert_eq!(
            get(duplicate_identity, "completeness"),
            &Json::from("complete")
        );
        assert_eq!(
            get(duplicate_identity, "fingerprint_sha256"),
            get(baseline_identity, "fingerprint_sha256")
        );
        assert!(
            !Observation::from_normalized(&value, None, &Limits::default())
                .unwrap()
                .routes()[0]
                .ambiguous_attributes()
        );
    }
}
#[test]
fn unsupported_attributes_survive_even_when_update_has_no_prefixes() {
    let value = decode(
        "unknown_no_routes",
        &mut SessionState::default(),
        Some(0),
        1,
    );
    assert!(array(get(&value, "routes")).is_empty());
    assert_eq!(ranges(&value).len(), 1);
    let a = &ranges(&value)[0];
    assert_eq!(get(a, "interpretation"), &Json::from("unsupported"));
    assert_eq!(get(a, "decoded"), &Json::Null);
    assert_eq!(get(a, "value_start"), &Json::from(26usize));
    assert_eq!(
        get(a, "sha256"),
        &Json::from(sha256::hex(&sha256::digest(&[0xde, 0xad])))
    );
}
#[test]
fn unknown_open_parameters_and_capabilities_are_hash_only_and_source_bound() {
    let value = decode("open_unknown", &mut SessionState::default(), Some(0), 1);
    let d = get(&value, "message_detail");
    let a = &array(get(d, "capability_occurrences"))[0];
    assert_eq!(get(a, "code"), &Json::from(200u8));
    assert_eq!(get(a, "decoded"), &Json::Null);
    assert_eq!(
        get(a, "sha256"),
        &Json::from(sha256::hex(&sha256::digest(&[0xaa, 0xbb])))
    );
    assert!(value
        .encode()
        .contains("unsupported_capability_retained_by_hash"));
    let open = &array(get(&opens(&value)[0], "observations"))[0];
    assert!(get(open, "evidence").encode().contains("packet_start"));
    let mut raw = wire("open_two");
    raw[16..18].copy_from_slice(&33u16.to_be_bytes());
    raw[28] = 4;
    raw.extend_from_slice(&[99, 2, 0xde, 0xad]);
    let unknown = bgp::decode_pcap(
        &evidence(&raw, 2),
        metadata(Some(0), 2),
        &mut SessionState::default(),
        &Limits::default(),
    )
    .unwrap();
    let parameter = &array(get(get(&unknown, "message_detail"), "parameters"))[0];
    assert_eq!(get(parameter, "type"), &Json::from(99u8));
    assert_eq!(
        get(parameter, "sha256"),
        &Json::from(sha256::hex(&sha256::digest(&[0xde, 0xad])))
    );
}
#[test]
fn source_ranges_and_payload_hashes_survive_a_split_inside_the_asn() {
    let raw = wire("announce_four");
    let mut ev = evidence(&raw[..34], 3);
    ev.append(&EvidenceBytes::from_packet(&raw[34..], packet(4), 70), 4096)
        .unwrap();
    let value =
        bgp::decode_pcap(&ev, metadata(Some(0), 3), &mut paired(), &Limits::default()).unwrap();
    let a = &ranges(&value)[1];
    assert_eq!(get(a, "start"), &Json::from(27usize));
    assert_eq!(get(a, "value_start"), &Json::from(30usize));
    assert_eq!(get(a, "end"), &Json::from(36usize));
    assert_eq!(
        get(a, "sha256"),
        &Json::from(sha256::hex(&sha256::digest(&raw[30..36])))
    );
    let spans = array(get(get(&value, "evidence"), "spans"));
    assert_eq!(spans.len(), 2);
    assert_eq!(get(&spans[0], "end"), &Json::from("34"));
    assert_eq!(get(&spans[1], "packet_start"), &Json::from("70"));
}
#[test]
fn source_movement_does_not_turn_the_same_path_into_a_conflicting_candidate() {
    let mut decoder = SessionState::default();
    let a = decode("announce_two", &mut decoder, Some(0), 1);
    let raw = wire("announce_two");
    // Add a withdrawal before the unchanged attributes. Every attribute offset moves.
    let mut b = raw.clone();
    b[16..18].copy_from_slice(&47u16.to_be_bytes());
    b[19..21].copy_from_slice(&2u16.to_be_bytes());
    b.splice(21..21, [8, 10]);
    let b = bgp::decode_pcap(
        &evidence(&b, 2),
        metadata(Some(0), 2),
        &mut decoder,
        &Limits::default(),
    )
    .unwrap();
    let mut state = CandidateState::new(Limits::default()).unwrap();
    state
        .apply(Observation::from_normalized(&a, None, &Limits::default()).unwrap())
        .unwrap();
    let outcome = state
        .apply(Observation::from_normalized(&b, None, &Limits::default()).unwrap())
        .unwrap();
    assert!(outcome
        .effects
        .iter()
        .any(|effect| effect.kind == EffectKind::RepeatedAnnouncement));
}
#[test]
fn forged_or_partial_value_ranges_are_rejected_by_existing_state_admission() {
    let value = decode("announce_two", &mut SessionState::default(), Some(0), 1);
    for field in ["value_start", "value_end"] {
        let mut forged = value.clone();
        let Json::Object(top) = &mut forged else {
            unreachable!()
        };
        let Json::Array(routes) = &mut top.iter_mut().find(|(k, _)| *k == "routes").unwrap().1
        else {
            unreachable!()
        };
        let Json::Object(route) = &mut routes[0] else {
            unreachable!()
        };
        let Json::Array(ranges) = &mut route
            .iter_mut()
            .find(|(k, _)| *k == "attribute_ranges")
            .unwrap()
            .1
        else {
            unreachable!()
        };
        set(&mut ranges[0], field, 1usize.into());
        assert!(Observation::from_normalized(&forged, None, &Limits::default()).is_err());
    }
}
#[test]
fn all_truncation_prefixes_and_attribute_boundary_failures_are_atomic() {
    let raw = wire("open_four_a");
    for n in 0..raw.len() {
        atomic_error(
            &raw[..n],
            metadata(Some(0), 3),
            &mut paired(),
            &Limits::default(),
        );
    }
    let malformed = changed_update(&[0x50, 1, 0], &[0, 0, 0]);
    atomic_error(
        &malformed,
        metadata(Some(0), 3),
        &mut paired(),
        &Limits::default(),
    );
    let mut trailing = wire("keepalive");
    trailing.extend(wire("keepalive"));
    atomic_error(
        &trailing,
        metadata(Some(0), 3),
        &mut paired(),
        &Limits::default(),
    );
}
#[test]
fn invalid_provenance_cannot_merge_capture_namespaces_or_accept_zero_packet_ids() {
    let raw = wire("announce_two");
    let mut ev = evidence(&raw[..20], 1);
    let mut id = packet(2);
    id.capture = [9; 32];
    ev.append(&EvidenceBytes::from_packet(&raw[20..], id, 70), 4096)
        .unwrap();
    let mut state = SessionState::default();
    let before = state.clone();
    assert!(bgp::decode_pcap(&ev, metadata(Some(0), 1), &mut state, &Limits::default()).is_err());
    assert_eq!(state, before);
    assert!(bgp::decode_pcap(
        &evidence(&raw, 0),
        metadata(Some(0), 0),
        &mut state,
        &Limits::default()
    )
    .is_err());
    assert_eq!(state, before);
}
#[test]
fn false_authority_flags_and_signed_unknown_time_labels_remain_explicit() {
    for time in [None, Some(i64::MIN), Some(-7), Some(i64::MAX)] {
        let mut m = metadata(Some(0), 1);
        m.observed_at_ns = time;
        let value = bgp::decode_pcap(
            &evidence(&wire("announce_two"), 1),
            m,
            &mut SessionState::default(),
            &Limits::default(),
        )
        .unwrap();
        assert_eq!(
            get(&value, "observed_at_ns"),
            &time.map_or(Json::Null, |t| t.to_string().into())
        );
        for key in [
            "endpoint_state_established",
            "rib_established",
            "best_path_selected",
            "reachability_established",
            "attack_established",
            "causality_established",
            "source_authority_established",
            "normative_conformance_certified",
            "negotiation_established",
        ] {
            assert_eq!(get(&value, key), &Json::Bool(false));
        }
    }
}
#[test]
fn captured_imported_and_replayed_records_share_schema_not_wire_or_source_authority() {
    let l = Limits::default();
    let captured = decode("announce_two", &mut SessionState::default(), Some(0), 1);
    let c = ImportContext {
        source_id: "import-source".into(),
        source_schema: "test-records".into(),
        source_version: None,
        clock: ObservationClock::default(),
        batch: SourceBatch {
            batch_id: Some("batch".into()),
            sha256: None,
            byte_length: Some(8),
        },
        checkpoint_id: "cp".into(),
        session: "s".into(),
        generation: 7,
        direction: Some(0),
        peer: None,
        local: None,
        provenance: vec![SourceRange {
            start: 0,
            end: 8,
            sha256: None,
        }],
    };
    let imported = bgp_import::normalize_with_context(
        ImportedRouteObservation {
            source_id: c.source_id.clone(),
            record_id: "r".into(),
            observed_at_ns: None,
            session: Some(c.session.clone()),
            peer: None,
            local: None,
            action: RouteAction::Announce,
            prefix: Prefix::ipv4([203, 0, 113, 0], 24).unwrap(),
            attributes: PathAttributes::default(),
        },
        c.clone(),
        &l,
    )
    .unwrap();
    assert_eq!(get(&captured, "schema"), get(&imported, "schema"));
    assert_eq!(get(&imported, "evidence"), &Json::Null);
    assert_ne!(get(&captured, "evidence"), &Json::Null);
    assert_eq!(get(&captured, "import_context"), &Json::Null);
    let record = FeedRecord::from_normalized(0, &imported, Coverage::DeclaredComplete, &l).unwrap();
    let mut declaration = c;
    declaration.direction = None;
    let mut replay = FeedReplay::new(declaration.clone(), l.clone()).unwrap();
    let page = FeedEnvelope::new(
        declaration,
        replay.cursor().clone(),
        vec![record],
        Completion::Final,
        &l,
    )
    .unwrap();
    replay.apply(&page).unwrap();
    let before = replay.receipt().encode().to_owned();
    assert_eq!(
        replay.apply(&page).unwrap().status,
        ReplayStatus::IdenticalReplay
    );
    assert_eq!(before, replay.receipt().encode());
    assert_eq!(
        get(
            replay.candidate_state().unwrap().observations()[0].normalized(),
            "schema"
        ),
        get(&captured, "schema")
    );
    assert!(FeedRecord::from_normalized(0, &captured, Coverage::DeclaredComplete, &l).is_err());
}
#[test]
fn existing_candidate_admission_and_exact_normalized_replay_are_unchanged() {
    let value = decode("announce_two", &mut SessionState::default(), Some(0), 1);
    let observation = Observation::from_normalized(&value, None, &Limits::default()).unwrap();
    let mut state = CandidateState::new(Limits::default()).unwrap();
    state.apply(observation.clone()).unwrap();
    let before = state.encode().to_owned();
    assert_eq!(
        state.apply(observation).unwrap().status,
        ApplyStatus::IdenticalReplay
    );
    assert_eq!(state.encode(), before);
}
#[test]
fn current_association_accepts_the_new_occurrence_shape_without_mutating_state() {
    let l = Limits::default();
    let value = decode("announce_two", &mut SessionState::default(), Some(0), 1);
    let mut state = CandidateState::new(l.clone()).unwrap();
    state
        .apply(Observation::from_normalized(&value, None, &l).unwrap())
        .unwrap();
    let before = state.encode().to_owned();
    let ctx = RouteContext {
        namespace: Some("domain".into()),
        flow_id: None,
        captured_or_legacy_clock: None,
        coverage: Coverage::DeclaredComplete,
    };
    let routes = RouteBatch::from_candidate_state(&state, &ctx, &l).unwrap();
    let internal = InternalEvidence::new(
        InternalInput {
            kind: InternalKind::Flow,
            source: SourceIdentity {
                source_id: "flow-source".into(),
                record_id: "f".into(),
                schema: "flow-schema".into(),
                version: None,
                batch: Some(SourceBatch {
                    batch_id: Some("flow-batch".into()),
                    sha256: None,
                    byte_length: Some(1),
                }),
                checkpoint_id: Some("fc".into()),
            },
            dimensions: Dimensions {
                scope: Scope {
                    namespace: Some("domain".into()),
                    session: None,
                    generation: None,
                    flow_id: None,
                    direction: None,
                },
                prefix: None,
                endpoint: Some(EndpointIdentity {
                    afi: 1,
                    address: "203.0.113.4".into(),
                }),
                unsupported: Vec::new(),
            },
            time: TimeLabel {
                observed_at_ns: None,
                clock: ObservationClock {
                    policy: ClockPolicy::Unknown,
                    clock_id: None,
                    reported_uncertainty_ns: None,
                },
            },
            coverage: Coverage::DeclaredComplete,
            provenance: Provenance {
                record_sha256: None,
                ranges: vec![SourceRange {
                    start: 0,
                    end: 1,
                    sha256: None,
                }],
                details: Json::Null,
            },
        },
        &l,
    )
    .unwrap();
    let policy = Policy {
        policy_id: "explicit".into(),
        session: DimensionRule::Ignore,
        generation: DimensionRule::Ignore,
        flow: DimensionRule::Ignore,
        direction: DirectionRule::Ignore,
        spatial: SpatialRule::RoutePrefixContainsEndpoint,
        time: TimePolicy::Ignore {
            reason: "time deliberately not compared".into(),
        },
    };
    let output = association::associate(&routes, &[internal], &policy, &l).unwrap();
    assert_eq!(output.associations().len(), 1);
    assert_eq!(
        output.associations()[0].status,
        AssociationStatus::CompatibleCandidate
    );
    assert_eq!(state.encode(), before);
    assert!(RouteEvidence::from_normalized(&value, 0, &ctx, &l).is_ok());
}
#[test]
fn repeated_decoding_from_equal_states_is_canonical_and_deterministic() {
    for name in [
        "announce_two",
        "unknown_no_routes",
        "open_unknown",
        "duplicate_origin",
        "refresh",
    ] {
        let a = decode(name, &mut SessionState::default(), Some(0), 1);
        let b = decode(name, &mut SessionState::default(), Some(0), 1);
        assert_eq!(a.encode(), b.encode());
        let Json::Object(fields) = a else {
            unreachable!()
        };
        assert!(fields.windows(2).all(|w| w[0].0 < w[1].0));
    }
}

#[test]
fn extended_attribute_and_zero_length_value_ranges_have_exact_boundaries() {
    let raw = changed_update(&[0x50, 5, 0, 4, 0, 0, 0, 9, 0x40, 6, 0], &[0]);
    let value = bgp::decode_pcap(
        &evidence(&raw, 1),
        metadata(Some(0), 1),
        &mut SessionState::default(),
        &Limits::default(),
    )
    .unwrap();
    let a = ranges(&value);
    assert_eq!(get(&a[0], "start"), &Json::from(23usize));
    assert_eq!(get(&a[0], "value_start"), &Json::from(27usize));
    assert_eq!(get(&a[0], "value_end"), &Json::from(31usize));
    assert_eq!(get(&a[1], "value_start"), get(&a[1], "value_end"));
    assert_eq!(get(&a[1], "decoded"), &Json::Bool(true));
    assert!(Observation::from_normalized(&value, None, &Limits::default()).is_ok());
}
#[test]
fn mixed_base_and_multiprotocol_next_hops_cannot_overwrite_each_other() {
    let mut mp = vec![0, 2, 1, 16];
    mp.extend_from_slice(&[0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    mp.extend_from_slice(&[0, 32, 0x20, 1, 0x0d, 0xb8]);
    let mut attributes = vec![0x40, 3, 4, 192, 0, 2, 1, 0x80, 14, mp.len() as u8];
    attributes.extend(mp);
    let raw = changed_update(&attributes, &[24, 203, 0, 113]);
    let mp_open = |asn: u16, identifier: [u8; 4]| {
        let mut raw = vec![255; 16];
        raw.extend_from_slice(&37u16.to_be_bytes());
        raw.extend_from_slice(&[1, 4]);
        raw.extend_from_slice(&asn.to_be_bytes());
        raw.extend_from_slice(&90u16.to_be_bytes());
        raw.extend_from_slice(&identifier);
        raw.extend_from_slice(&[8, 2, 6, 1, 4, 0, 2, 0, 1]);
        raw
    };
    let mut state = SessionState::default();
    bgp::decode_pcap(
        &evidence(&mp_open(65000, [192, 0, 2, 1]), 1),
        metadata(Some(0), 1),
        &mut state,
        &Limits::default(),
    )
    .unwrap();
    bgp::decode_pcap(
        &evidence(&mp_open(65001, [192, 0, 2, 2]), 2),
        metadata(Some(1), 2),
        &mut state,
        &Limits::default(),
    )
    .unwrap();
    let value = bgp::decode_pcap(
        &evidence(&raw, 3),
        metadata(Some(0), 3),
        &mut state,
        &Limits::default(),
    )
    .unwrap();
    assert_eq!(array(get(&value, "routes")).len(), 2);
    assert_eq!(get(attrs(&value), "next_hop"), &Json::Null);
    assert_eq!(get(&ranges(&value)[0], "decoded"), &Json::from("192.0.2.1"));
    assert_eq!(
        get(get(&ranges(&value)[1], "decoded"), "next_hop"),
        &Json::from("2001:db8::1")
    );
    assert!(
        Observation::from_normalized(&value, None, &Limits::default())
            .unwrap()
            .routes()
            .iter()
            .all(|r| r.ambiguous_attributes())
    );
}
