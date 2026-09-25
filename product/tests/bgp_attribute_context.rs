//! RFC 7606 attribute disposition depends on explicitly configured peer
//! relationship; unknown context must remain evidence-only and non-admitting.
use pcap_evidence::{
    json::Json,
    provenance::{EvidenceBytes, PacketId},
    sha256,
};
use pcap_evidence_product::deep::{
    bgp::{self, PcapMetadata, PeerRelationship, SessionState},
    bgp_mrt::{MrtLimits, MrtSource},
    bgp_mrt_store,
    bgp_state::Observation,
    Limits,
};
use std::{
    fs, io,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

static SCRATCH_SERIAL: AtomicU64 = AtomicU64::new(0);

fn attribute(flags: u8, code: u8, payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![
        flags,
        code,
        u8::try_from(payload.len()).expect("short test attribute"),
    ];
    bytes.extend_from_slice(payload);
    bytes
}

fn update_with_attribute(flags: u8, code: u8, payload: &[u8]) -> Vec<u8> {
    let mut attributes = attribute(0x40, 1, &[0]);
    attributes.extend(attribute(0x40, 2, &[2, 1, 0xfd, 0xe8]));
    attributes.extend(attribute(0x40, 3, &[192, 0, 2, 1]));
    attributes.extend(attribute(flags, code, payload));

    let mut body = vec![0, 0];
    body.extend_from_slice(
        &u16::try_from(attributes.len())
            .expect("test attribute block fits")
            .to_be_bytes(),
    );
    body.extend_from_slice(&attributes);
    body.extend_from_slice(&[24, 203, 0, 113]);

    let mut message = vec![0xff; 16];
    message.extend_from_slice(
        &u16::try_from(19 + body.len())
            .expect("test UPDATE fits")
            .to_be_bytes(),
    );
    message.push(2);
    message.extend_from_slice(&body);
    message
}

fn decode(message: &[u8], state: &mut SessionState, frame: u64) -> Json {
    let packet = PacketId {
        capture: sha256::digest(b"bgp-attribute-context-test"),
        frame,
        record_offset: frame * 128,
    };
    bgp::decode_pcap(
        &EvidenceBytes::from_packet(message, packet, 54),
        PcapMetadata {
            source_id: "attribute-context-test".into(),
            record_id: format!("attribute-context-{frame}"),
            observed_at_ns: Some(1_000),
            session: Some(7),
            direction: Some(0),
            // Address-shaped metadata is deliberately present: it must not
            // be used to infer whether the peer is internal or external.
            peer: Some("198.51.100.10:179".into()),
            local: Some("192.0.2.20:179".into()),
        },
        state,
        &Limits::default(),
    )
    .expect("synthetic UPDATE decodes")
}

fn get<'a>(value: &'a Json, key: &str) -> &'a Json {
    let Json::Object(fields) = value else {
        panic!("expected object for {key}")
    };
    &fields
        .iter()
        .find(|(name, _)| *name == key)
        .unwrap_or_else(|| panic!("missing {key}"))
        .1
}

fn get_mut<'a>(value: &'a mut Json, key: &str) -> &'a mut Json {
    let Json::Object(fields) = value else {
        panic!("expected object for {key}")
    };
    &mut fields
        .iter_mut()
        .find(|(name, _)| *name == key)
        .unwrap_or_else(|| panic!("missing {key}"))
        .1
}

fn refresh_identity_fingerprint(identity: &mut Json) {
    let payload = get_mut(identity, "canonical_payload")
        .encode_bounded(1_000_000)
        .expect("test identity payload is bounded");
    let length = u64::try_from(payload.len()).expect("test payload length fits u64");
    let mut preimage = b"pcap-evidence.bgp.semantic-route-identity.v1\0".to_vec();
    preimage.extend_from_slice(&length.to_be_bytes());
    preimage.extend_from_slice(payload.as_bytes());
    *get_mut(identity, "fingerprint_sha256") = Json::from(sha256::hex(&sha256::digest(&preimage)));
}

fn array(value: &Json) -> &[Json] {
    let Json::Array(items) = value else {
        panic!("expected array")
    };
    items
}

fn special_range(result: &Json) -> &Json {
    &array(get(get(result, "message_detail"), "attribute_ranges"))[3]
}

fn payload_hash(payload: &[u8]) -> Json {
    Json::from(sha256::hex(&sha256::digest(payload)))
}

fn route_action(result: &Json) -> Option<&Json> {
    array(get(result, "routes"))
        .first()
        .map(|route| get(route, "action"))
}

fn mandatory_attributes() -> Vec<u8> {
    let mut attributes = attribute(0x40, 1, &[0]);
    attributes.extend(attribute(0x40, 2, &[2, 1, 0xfd, 0xe8]));
    attributes.extend(attribute(0x40, 3, &[192, 0, 2, 1]));
    attributes
}

fn decode_with_attributes(attributes: &[u8], state: &mut SessionState, frame: u64) -> Json {
    decode_with_attributes_and_prefix(attributes, state, frame, [203, 0, 113, 0])
}

fn decode_with_attributes_and_prefix(
    attributes: &[u8],
    state: &mut SessionState,
    frame: u64,
    prefix: [u8; 4],
) -> Json {
    let mut body = vec![0, 0];
    body.extend_from_slice(
        &u16::try_from(attributes.len())
            .expect("test attributes fit")
            .to_be_bytes(),
    );
    body.extend_from_slice(attributes);
    body.extend_from_slice(&[24, prefix[0], prefix[1], prefix[2]]);
    let mut message = vec![0xff; 16];
    message.extend_from_slice(
        &u16::try_from(19 + body.len())
            .expect("test UPDATE fits")
            .to_be_bytes(),
    );
    message.push(2);
    message.extend_from_slice(&body);
    decode(&message, state, frame)
}

fn first_route_identity(value: &Json) -> &Json {
    get(
        array(get(value, "routes"))
            .first()
            .expect("one route candidate"),
        "semantic_identity",
    )
}

fn identity_fingerprint(value: &Json) -> &Json {
    get(value, "fingerprint_sha256")
}

#[test]
fn semantic_identity_is_source_neutral_and_state_consumer_verifies_it() {
    let community_a = [0x00, 0x01, 0x00, 0x2a];
    let community_b = [0x00, 0x02, 0x00, 0x2b];
    let mut first = attribute(0x40, 1, &[0]);
    first.extend(attribute(0x40, 2, &[2, 1, 0xfd, 0xe8]));
    first.extend(attribute(0x40, 3, &[192, 0, 2, 1]));
    first.extend(attribute(0xc0, 8, &[community_a, community_b].concat()));

    let mut reordered = attribute(0xc0, 8, &[community_b, community_a, community_a].concat());
    reordered.extend(attribute(0x40, 3, &[192, 0, 2, 1]));
    reordered.extend(attribute(0x40, 2, &[2, 1, 0xfd, 0xe8]));
    reordered.extend(attribute(0x40, 1, &[0]));

    let mut state_a = SessionState::default();
    let mut state_b = SessionState::default();
    let a = decode_with_attributes_and_prefix(&first, &mut state_a, 101, [203, 0, 113, 0]);
    let b = decode_with_attributes_and_prefix(&reordered, &mut state_b, 909, [203, 0, 113, 0]);
    let identity_a = first_route_identity(&a);
    let identity_b = first_route_identity(&b);
    assert_eq!(get(identity_a, "completeness"), &Json::from("complete"));
    assert_eq!(
        identity_fingerprint(identity_a),
        identity_fingerprint(identity_b)
    );
    assert_ne!(
        get(
            array(get(&a, "routes")).first().unwrap(),
            "attribute_ranges"
        ),
        get(
            array(get(&b, "routes")).first().unwrap(),
            "attribute_ranges"
        ),
        "wire occurrence evidence remains distinct despite semantic equality"
    );

    let mut different_prefix_state = SessionState::default();
    let different_prefix = decode_with_attributes_and_prefix(
        &first,
        &mut different_prefix_state,
        910,
        [203, 0, 114, 0],
    );
    assert_ne!(
        identity_fingerprint(first_route_identity(&a)),
        identity_fingerprint(first_route_identity(&different_prefix)),
        "a different network prefix is a different semantic route key"
    );

    let observation = Observation::from_normalized(&a, None, &Limits::default())
        .expect("state consumer accepts and verifies producer identity");
    assert_eq!(
        observation.routes()[0].semantic_identity(),
        identity_a,
        "the evidence reducer preserves identity without replacing wire identity"
    );

    let mut conflicting = a.clone();
    let Json::Object(root) = &mut conflicting else {
        panic!("normalized observation must be an object")
    };
    let routes = root
        .iter_mut()
        .find(|(name, _)| *name == "routes")
        .map(|(_, value)| value)
        .expect("routes field");
    let Json::Array(routes) = routes else {
        panic!("routes must be an array")
    };
    let Json::Object(route) = &mut routes[0] else {
        panic!("route must be an object")
    };
    let attributes = route
        .iter_mut()
        .find(|(name, _)| *name == "attributes")
        .map(|(_, value)| value)
        .expect("attributes field");
    let Json::Object(attributes) = attributes else {
        panic!("attributes must be an object")
    };
    let origin = attributes
        .iter_mut()
        .find(|(name, _)| *name == "origin")
        .map(|(_, value)| value)
        .expect("origin field");
    *origin = Json::from(1u8);
    assert!(
        Observation::from_normalized(&conflicting, None, &Limits::default()).is_err(),
        "a self-consistent identity sidecar must not bless conflicting route attributes"
    );

    let mut coordinated = a.clone();
    let routes = get_mut(&mut coordinated, "routes");
    let Json::Array(routes) = routes else {
        panic!("routes must be an array")
    };
    let route = &mut routes[0];
    *get_mut(get_mut(route, "attributes"), "origin") = Json::from(1u8);
    let identity = get_mut(route, "semantic_identity");
    *get_mut(
        get_mut(get_mut(identity, "canonical_payload"), "attributes"),
        "origin",
    ) = Json::from(1u8);
    refresh_identity_fingerprint(identity);
    assert!(
        Observation::from_normalized(&coordinated, None, &Limits::default()).is_err(),
        "coordinated route and payload edits must not disagree with the retained source occurrence"
    );

    let mut falsely_complete = a.clone();
    let routes = get_mut(&mut falsely_complete, "routes");
    let Json::Array(routes) = routes else {
        panic!("routes must be an array")
    };
    let identity = get_mut(&mut routes[0], "semantic_identity");
    let opaque = get_mut(identity, "opaque_occurrence_fingerprints");
    let Json::Array(opaque) = opaque else {
        panic!("opaque occurrences must be an array")
    };
    opaque.push(Json::object([
        ("type", 99u8.into()),
        ("flags", 0xc0u8.into()),
        ("value_sha256", "00".repeat(32).into()),
    ]));
    assert!(
        Observation::from_normalized(&falsely_complete, None, &Limits::default()).is_err(),
        "a complete identity cannot simultaneously claim opaque occurrences"
    );
}

#[test]
fn large_communities_use_set_semantics_but_keep_occurrence_evidence() {
    let a = [1u32, 65000, 7];
    let b = [2u32, 65000, 9];
    let encode = |tuples: &[[u32; 3]]| {
        let mut bytes = Vec::new();
        for tuple in tuples {
            for field in tuple {
                bytes.extend_from_slice(&field.to_be_bytes());
            }
        }
        bytes
    };
    let mut first = mandatory_attributes();
    first.extend(attribute(0xc0, 32, &encode(&[a, b])));
    let mut reordered = mandatory_attributes();
    reordered.extend(attribute(0xc0, 32, &encode(&[b, a, a])));

    let mut state_a = SessionState::default();
    let mut state_b = SessionState::default();
    let decoded_a = decode_with_attributes(&first, &mut state_a, 201);
    let decoded_b = decode_with_attributes(&reordered, &mut state_b, 202);
    let identity_a = first_route_identity(&decoded_a);
    let identity_b = first_route_identity(&decoded_b);
    assert_eq!(get(identity_a, "completeness"), &Json::from("complete"));
    assert_eq!(
        identity_fingerprint(identity_a),
        identity_fingerprint(identity_b)
    );
    assert_ne!(
        get(
            array(get(&decoded_a, "routes")).first().unwrap(),
            "attribute_ranges"
        ),
        get(
            array(get(&decoded_b, "routes")).first().unwrap(),
            "attribute_ranges"
        ),
        "the original large-community bytes and occurrence order remain evidenced"
    );

    let changed_tuple = [3u32, 65000, 11];
    let mut changed = mandatory_attributes();
    changed.extend(attribute(0xc0, 32, &encode(&[a, changed_tuple])));
    let mut changed_state = SessionState::default();
    let changed_decoded = decode_with_attributes(&changed, &mut changed_state, 203);
    assert_ne!(
        identity_fingerprint(identity_a),
        identity_fingerprint(first_route_identity(&changed_decoded)),
        "changing a Large Community changes route semantics"
    );

    let mut truncated = mandatory_attributes();
    truncated.extend(attribute(0xc0, 32, &[0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0]));
    let mut truncated_state = SessionState::default();
    let truncated_decoded = decode_with_attributes(&truncated, &mut truncated_state, 204);
    let truncated_identity = first_route_identity(&truncated_decoded);
    assert_eq!(
        get(truncated_identity, "completeness"),
        &Json::from("incomplete")
    );
    assert_eq!(identity_fingerprint(truncated_identity), &Json::Null);
}

#[test]
fn unknown_attribute_is_opaque_and_cannot_claim_semantic_equality() {
    let mut attributes = mandatory_attributes();
    attributes.extend(attribute(0xc0, 99, &[1, 2, 3, 4]));
    let mut state = SessionState::default();
    let decoded = decode_with_attributes(&attributes, &mut state, 301);
    let identity = first_route_identity(&decoded);
    assert_eq!(get(identity, "completeness"), &Json::from("incomplete"));
    assert_eq!(identity_fingerprint(identity), &Json::Null);
    assert_eq!(
        array(get(identity, "opaque_occurrence_fingerprints")).len(),
        1
    );
    assert!(array(get(identity, "incompleteness_reasons"))
        .contains(&Json::from("unsupported_path_attribute")));
    let observation = Observation::from_normalized(&decoded, None, &Limits::default())
        .expect("state consumer accepts the explicit incomplete identity");
    assert!(
        observation.routes()[0].ambiguous_attributes(),
        "an incomplete normalized announcement cannot become a trusted candidate"
    );
}

#[test]
fn reserved_flag_nibble_is_ignored_but_partial_attributes_are_not_complete() {
    let baseline_attributes = mandatory_attributes();
    let mut reserved_bits = attribute(0x4f, 1, &[0]);
    reserved_bits.extend_from_slice(&baseline_attributes[4..]);
    let mut baseline_state = SessionState::default();
    let mut reserved_state = SessionState::default();
    let baseline = decode_with_attributes(&baseline_attributes, &mut baseline_state, 401);
    let reserved = decode_with_attributes(&reserved_bits, &mut reserved_state, 402);
    assert_eq!(
        identity_fingerprint(first_route_identity(&baseline)),
        identity_fingerprint(first_route_identity(&reserved)),
        "RFC 4271 reserved low bits are retained on wire but ignored semantically"
    );

    let mut partial_attributes = mandatory_attributes();
    partial_attributes.extend(attribute(0xe0, 8, &[0, 1, 0, 42]));
    let mut partial_state = SessionState::default();
    let partial = decode_with_attributes(&partial_attributes, &mut partial_state, 403);
    let identity = first_route_identity(&partial);
    assert_eq!(get(identity, "completeness"), &Json::from("incomplete"));
    assert_eq!(identity_fingerprint(identity), &Json::Null);
    assert!(array(get(identity, "incompleteness_reasons"))
        .contains(&Json::from("partial_attribute_value")));
}

#[test]
fn ordinary_duplicate_uses_first_effective_value_and_retains_both_occurrences() {
    let single = mandatory_attributes();
    let mut duplicate = single.clone();
    duplicate.extend(attribute(0x40, 1, &[2]));
    let mut single_state = SessionState::default();
    let mut duplicate_state = SessionState::default();
    let baseline = decode_with_attributes(&single, &mut single_state, 501);
    let with_duplicate = decode_with_attributes(&duplicate, &mut duplicate_state, 502);
    let baseline_route = array(get(&baseline, "routes")).first().unwrap();
    let duplicate_route = array(get(&with_duplicate, "routes")).first().unwrap();
    assert_eq!(
        identity_fingerprint(get(baseline_route, "semantic_identity")),
        identity_fingerprint(get(duplicate_route, "semantic_identity")),
        "RFC 7606 discards later ordinary occurrences and keeps the first value"
    );
    assert_eq!(
        get(get(duplicate_route, "attributes"), "origin"),
        &Json::from(0u8)
    );
    let ranges = array(get(duplicate_route, "attribute_ranges"));
    assert_eq!(ranges.len(), 4);
    assert_eq!(
        get(ranges.last().unwrap(), "disposition"),
        &Json::from("discard_later_occurrence")
    );
    let observation = Observation::from_normalized(&with_duplicate, None, &Limits::default())
        .expect("first-occurrence disposition remains reducible");
    assert!(!observation.routes()[0].ambiguous_attributes());
}

#[test]
fn as_set_members_are_order_insensitive_but_as_sequence_order_is_preserved() {
    let path = |kind: u8, first: u16, second: u16| {
        let mut attributes = attribute(0x40, 1, &[0]);
        let mut as_path = vec![kind, 2];
        as_path.extend(first.to_be_bytes());
        as_path.extend(second.to_be_bytes());
        attributes.extend(attribute(0x40, 2, &as_path));
        attributes.extend(attribute(0x40, 3, &[192, 0, 2, 1]));
        attributes
    };
    let mut states = [SessionState::default(), SessionState::default()];
    let set_a = decode_with_attributes(&path(1, 64_512, 64_513), &mut states[0], 601);
    let set_b = decode_with_attributes(&path(1, 64_513, 64_512), &mut states[1], 602);
    assert_eq!(
        identity_fingerprint(first_route_identity(&set_a)),
        identity_fingerprint(first_route_identity(&set_b)),
        "AS_SET members are a set"
    );

    let mut states = [SessionState::default(), SessionState::default()];
    let sequence_a = decode_with_attributes(&path(2, 64_512, 64_513), &mut states[0], 603);
    let sequence_b = decode_with_attributes(&path(2, 64_513, 64_512), &mut states[1], 604);
    assert_ne!(
        identity_fingerprint(first_route_identity(&sequence_a)),
        identity_fingerprint(first_route_identity(&sequence_b)),
        "AS_SEQUENCE order carries meaning"
    );
}

#[test]
fn peer_relationship_is_explicit_unknown_by_default_and_survives_reset() {
    let mut state = SessionState::default();
    assert_eq!(state.peer_relationship(), PeerRelationship::Unknown);
    let unresolved = decode(
        &update_with_attribute(0x40, 5, &[0, 0, 0, 42]),
        &mut state,
        1,
    );
    assert_eq!(
        get(special_range(&unresolved), "peer_relationship"),
        &Json::from("unknown")
    );
    assert_eq!(
        get(special_range(&unresolved), "peer_relationship_basis"),
        &Json::from("default_unknown")
    );
    assert_eq!(
        get(
            get(&unresolved, "message_detail"),
            "peer_relationship_basis"
        ),
        &Json::from("default_unknown")
    );
    assert!(array(get(&unresolved, "routes")).is_empty());

    state.set_peer_relationship(PeerRelationship::Internal);
    state.reset().expect("reset decoder generation");
    assert_eq!(state.peer_relationship(), PeerRelationship::Internal);
    let after_reset = decode_with_attributes(&mandatory_attributes(), &mut state, 2);
    let detail = get(&after_reset, "message_detail");
    assert_eq!(get(detail, "peer_relationship"), &Json::from("internal"));
    assert_eq!(
        get(detail, "peer_relationship_basis"),
        &Json::from("explicit_configuration")
    );
}

#[test]
fn every_update_reports_relationship_and_provenance_without_dependent_attributes() {
    let cases = [
        (None, PeerRelationship::Unknown, "default_unknown"),
        (
            Some(PeerRelationship::Unknown),
            PeerRelationship::Unknown,
            "explicit_configuration",
        ),
        (
            Some(PeerRelationship::Internal),
            PeerRelationship::Internal,
            "explicit_configuration",
        ),
        (
            Some(PeerRelationship::External),
            PeerRelationship::External,
            "explicit_configuration",
        ),
    ];

    for (index, (configured, expected, basis)) in cases.iter().enumerate() {
        let mut state = SessionState::default();
        if let Some(relationship) = configured {
            state.set_peer_relationship(*relationship);
        }
        let result = decode_with_attributes(&mandatory_attributes(), &mut state, 20 + index as u64);
        let detail = get(&result, "message_detail");
        assert_eq!(
            get(detail, "peer_relationship"),
            &Json::from(relationship_name(*expected))
        );
        assert_eq!(get(detail, "peer_relationship_basis"), &Json::from(*basis));
        assert_eq!(
            get(detail, "peer_relationship_unresolved"),
            &Json::from(false),
            "no peer-dependent attribute means no unresolved disposition"
        );
        assert_eq!(
            array(get(detail, "attribute_ranges")).len(),
            3,
            "the UPDATE intentionally has no attributes 5, 9, or 10"
        );
        assert_eq!(route_action(&result), Some(&Json::from("announce")));
    }
}

#[test]
fn valid_peer_dependent_attributes_follow_explicit_relationship() {
    let cases: &[(u8, &[u8], &str, Json)] = &[
        (5, &[0, 0, 0, 42], "local_preference", Json::from(42u64)),
        (9, &[192, 0, 2, 9], "originator_id", Json::from("192.0.2.9")),
        (
            10,
            &[192, 0, 2, 10],
            "cluster_list",
            Json::array([Json::from("192.0.2.10")]),
        ),
    ];

    for (index, (code, payload, semantic_key, expected_value)) in cases.iter().enumerate() {
        for relationship in [
            PeerRelationship::Internal,
            PeerRelationship::External,
            PeerRelationship::Unknown,
        ] {
            let mut state = SessionState::default();
            state.set_peer_relationship(relationship);
            let result = decode(
                &update_with_attribute(if *code == 5 { 0x40 } else { 0x80 }, *code, payload),
                &mut state,
                10 + index as u64 * 3 + relationship as u64,
            );
            let range = special_range(&result);
            let expected_disposition = match relationship {
                PeerRelationship::Internal => "accept_evidence_only",
                PeerRelationship::External => "attribute_discard",
                PeerRelationship::Unknown => "peer_relationship_unresolved",
            };
            assert_eq!(
                get(range, "disposition"),
                &Json::from(expected_disposition),
                "attribute {code}, relationship {relationship:?}"
            );
            assert_eq!(
                get(range, "peer_relationship"),
                &Json::from(relationship_name(relationship))
            );
            assert_eq!(
                get(range, "peer_relationship_unresolved"),
                &Json::from(relationship == PeerRelationship::Unknown)
            );
            assert_eq!(
                get(range, "decoded"),
                expected_value,
                "source-byte decode evidence must be retained for attribute {code}"
            );
            assert_eq!(get(range, "sha256"), &payload_hash(payload));

            if relationship == PeerRelationship::Unknown {
                assert!(array(get(&result, "routes")).is_empty());
                assert_eq!(
                    get(get(&result, "message_detail"), "update_disposition"),
                    &Json::from("peer_relationship_unresolved")
                );
            } else {
                assert_eq!(route_action(&result), Some(&Json::from("announce")));
                let route_attributes = get(&array(get(&result, "routes"))[0], "attributes");
                let expected_semantics = if relationship == PeerRelationship::Internal {
                    expected_value
                } else if *code == 10 {
                    &Json::Array(Vec::new())
                } else {
                    &Json::Null
                };
                assert_eq!(
                    get(route_attributes, semantic_key),
                    expected_semantics,
                    "attribute {code}, relationship {relationship:?}"
                );
            }
        }
    }
}

fn relationship_name(relationship: PeerRelationship) -> &'static str {
    match relationship {
        PeerRelationship::Unknown => "unknown",
        PeerRelationship::Internal => "internal",
        PeerRelationship::External => "external",
    }
}

#[test]
fn malformed_lengths_are_relationship_sensitive_but_invalid_flags_are_not() {
    let malformed: &[(u8, &[u8])] = &[
        (5, &[0, 0, 42]),
        (9, &[192, 0, 2]),
        (10, &[]),
        (10, &[1, 2, 3, 4, 5]),
    ];
    for (case, (code, payload)) in malformed.iter().enumerate() {
        for relationship in [
            PeerRelationship::Internal,
            PeerRelationship::External,
            PeerRelationship::Unknown,
        ] {
            let mut state = SessionState::default();
            state.set_peer_relationship(relationship);
            let result = decode(
                &update_with_attribute(if *code == 5 { 0x40 } else { 0x80 }, *code, payload),
                &mut state,
                100 + case as u64 * 3 + relationship as u64,
            );
            let range = special_range(&result);
            let expected = match relationship {
                PeerRelationship::Internal => "treat_as_withdraw",
                PeerRelationship::External => "attribute_discard",
                PeerRelationship::Unknown => "peer_relationship_unresolved",
            };
            assert_eq!(get(range, "disposition"), &Json::from(expected));
            assert_eq!(
                get(get(range, "validation"), "length_valid"),
                &Json::from(false)
            );
            assert_eq!(get(range, "sha256"), &payload_hash(payload));

            match relationship {
                PeerRelationship::Internal => {
                    assert_eq!(route_action(&result), Some(&Json::from("withdraw")));
                }
                PeerRelationship::External => {
                    assert_eq!(route_action(&result), Some(&Json::from("announce")));
                }
                PeerRelationship::Unknown => {
                    assert!(array(get(&result, "routes")).is_empty());
                }
            }
        }
    }

    let invalid_flags: &[(u8, u8, &[u8])] = &[
        (5, 0xc0, &[0, 0, 0, 42]),
        (9, 0x40, &[192, 0, 2, 9]),
        (10, 0x40, &[192, 0, 2, 10]),
    ];
    for (case, (code, flags, payload)) in invalid_flags.iter().enumerate() {
        for relationship in [
            PeerRelationship::Internal,
            PeerRelationship::External,
            PeerRelationship::Unknown,
        ] {
            let mut state = SessionState::default();
            state.set_peer_relationship(relationship);
            let result = decode(
                &update_with_attribute(*flags, *code, payload),
                &mut state,
                200 + case as u64 * 3 + relationship as u64,
            );
            let range = special_range(&result);
            assert_eq!(
                get(get(range, "validation"), "flags_valid"),
                &Json::from(false)
            );
            assert_eq!(
                get(get(range, "validation"), "length_valid"),
                &Json::from(true)
            );
            assert_eq!(get(range, "disposition"), &Json::from("treat_as_withdraw"));
            assert_eq!(
                get(range, "peer_relationship_unresolved"),
                &Json::from(relationship == PeerRelationship::Unknown)
            );
            assert_eq!(
                get(get(&result, "message_detail"), "known_update_disposition"),
                &Json::from("treat_as_withdraw")
            );
            if relationship == PeerRelationship::Unknown {
                assert!(array(get(&result, "routes")).is_empty());
            } else {
                assert_eq!(route_action(&result), Some(&Json::from("withdraw")));
            }
        }
    }
}

#[test]
fn known_session_reset_wins_over_unresolved_peer_relationship_context() {
    let mut attributes = mandatory_attributes();
    attributes.extend(attribute(0x40, 5, &[0, 0, 0, 42]));
    // A malformed MP_REACH_NLRI has a known session-reset disposition,
    // independent of the unresolved relationship required by LOCAL_PREF.
    attributes.extend(attribute(0x80, 14, &[]));
    let mut state = SessionState::default();
    let result = decode_with_attributes(&attributes, &mut state, 350);
    let detail = get(&result, "message_detail");
    let ranges = array(get(detail, "attribute_ranges"));

    assert_eq!(
        get(&ranges[3], "disposition"),
        &Json::from("peer_relationship_unresolved")
    );
    assert_eq!(get(&ranges[4], "disposition"), &Json::from("session_reset"));
    assert_eq!(
        get(detail, "peer_relationship_unresolved"),
        &Json::from(true)
    );
    assert_eq!(
        get(detail, "known_update_disposition"),
        &Json::from("session_reset")
    );
    assert_eq!(
        get(detail, "update_disposition"),
        &Json::from("session_reset"),
        "a known reset is not masked by an independent unresolved context"
    );
    assert!(array(get(&result, "routes")).is_empty());
    assert_eq!(state.generation(), 1, "session-reset state was applied");
}

#[test]
fn duplicate_mp_reach_and_unreach_trigger_session_reset() {
    let valid_multiprotocol_attributes = [
        (14, vec![0, 1, 1, 4, 192, 0, 2, 1, 0, 24, 203, 0, 113]),
        (15, vec![0, 1, 1, 24, 203, 0, 113]),
    ];

    for (code, value) in valid_multiprotocol_attributes {
        let mut attributes = mandatory_attributes();
        attributes.extend(attribute(0x80, code, &value));
        attributes.extend(attribute(0x80, code, &value));
        let mut state = SessionState::default();
        let result = decode_with_attributes(&attributes, &mut state, 700 + u64::from(code));
        let detail = get(&result, "message_detail");
        let ranges = array(get(detail, "attribute_ranges"));

        assert_eq!(ranges.len(), 5, "both occurrences remain visible");
        assert_eq!(
            get(&ranges[4], "disposition"),
            &Json::from("session_reset"),
            "RFC 7606 requires a reset for duplicate MP_REACH_NLRI / MP_UNREACH_NLRI"
        );
        assert_eq!(
            get(detail, "update_disposition"),
            &Json::from("session_reset")
        );
        assert!(array(get(&result, "routes")).is_empty());
        assert_eq!(state.generation(), 1);
    }
}

#[test]
fn unrelated_attributes_keep_their_existing_disposition_under_unknown_peer_context() {
    let mut attributes = mandatory_attributes();
    attributes.extend(attribute(0x80, 4, &[0, 0, 0, 9]));
    attributes.extend(attribute(0x80, 26, &[]));
    let mut state = SessionState::default();
    let result = decode_with_attributes(&attributes, &mut state, 300);
    let ranges = array(get(get(&result, "message_detail"), "attribute_ranges"));
    assert_eq!(
        get(&ranges[3], "disposition"),
        &Json::from("accept_evidence_only")
    );
    assert_eq!(
        get(&ranges[4], "disposition"),
        &Json::from("attribute_discard")
    );
    assert_eq!(
        get(get(&result, "message_detail"), "update_disposition"),
        &Json::from("attribute_discard")
    );
    assert_eq!(route_action(&result), Some(&Json::from("announce")));
}

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        for _ in 0..1024 {
            let path = std::env::temp_dir().join(format!(
                "pcap-bgp-attribute-context-{}-{}",
                std::process::id(),
                SCRATCH_SERIAL.fetch_add(1, Ordering::Relaxed),
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Self(path),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("create isolated test directory: {error}"),
            }
        }
        panic!("temporary test directory namespace exhausted");
    }

    fn file(&self) -> PathBuf {
        self.0.join("unknown-peer.mrt-store")
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn mrt_record(seconds: u32, record_type: u16, subtype: u16, body: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&seconds.to_be_bytes());
    bytes.extend_from_slice(&record_type.to_be_bytes());
    bytes.extend_from_slice(&subtype.to_be_bytes());
    bytes.extend_from_slice(
        &u32::try_from(body.len())
            .expect("synthetic MRT body fits")
            .to_be_bytes(),
    );
    bytes.extend_from_slice(body);
    bytes
}

fn bgp_message(message_type: u8, payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0xff; 16];
    bytes.extend_from_slice(
        &u16::try_from(19 + payload.len())
            .expect("synthetic BGP message fits")
            .to_be_bytes(),
    );
    bytes.push(message_type);
    bytes.extend_from_slice(payload);
    bytes
}

fn open(asn: u16, identifier: [u8; 4]) -> Vec<u8> {
    let mut payload = vec![4];
    payload.extend_from_slice(&asn.to_be_bytes());
    payload.extend_from_slice(&90u16.to_be_bytes());
    payload.extend_from_slice(&identifier);
    payload.push(0);
    bgp_message(1, &payload)
}

fn state_change(seconds: u32, old_state: u16, new_state: u16) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&64_512u16.to_be_bytes());
    body.extend_from_slice(&64_513u16.to_be_bytes());
    body.extend_from_slice(&7u16.to_be_bytes());
    body.extend_from_slice(&1u16.to_be_bytes());
    body.extend_from_slice(&[198, 51, 100, 1, 198, 51, 100, 2]);
    body.extend_from_slice(&old_state.to_be_bytes());
    body.extend_from_slice(&new_state.to_be_bytes());
    mrt_record(seconds, 16, 0, &body)
}

fn message_record(seconds: u32, local_generated: bool, message: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&64_512u16.to_be_bytes());
    body.extend_from_slice(&64_513u16.to_be_bytes());
    body.extend_from_slice(&7u16.to_be_bytes());
    body.extend_from_slice(&1u16.to_be_bytes());
    body.extend_from_slice(&[198, 51, 100, 1, 198, 51, 100, 2]);
    body.extend_from_slice(message);
    mrt_record(seconds, 16, if local_generated { 6 } else { 1 }, &body)
}

fn established_mrt_with_update(update: &[u8]) -> Vec<u8> {
    let records = [
        state_change(300, 3, 4),
        message_record(250, false, &open(64_512, [198, 51, 100, 1])),
        message_record(200, true, &open(64_513, [198, 51, 100, 2])),
        state_change(150, 4, 5),
        state_change(100, 5, 6),
        message_record(30, false, update),
    ];
    records.concat()
}

fn string_field<'a>(value: &'a Json, key: &str) -> Option<&'a str> {
    let Json::Object(fields) = value else {
        return None;
    };
    fields
        .iter()
        .find(|(name, _)| *name == key)
        .and_then(|(_, value)| match value {
            Json::String(text) => Some(text.as_str()),
            _ => None,
        })
}

#[test]
fn mrt_unknown_relationship_never_admits_an_update_candidate() {
    let mut attributes = mandatory_attributes();
    attributes.extend(attribute(0x40, 5, &[0, 0, 0, 42]));
    let mut body = vec![0, 0];
    body.extend_from_slice(
        &u16::try_from(attributes.len())
            .expect("synthetic attributes fit")
            .to_be_bytes(),
    );
    body.extend_from_slice(&attributes);
    body.extend_from_slice(&[24, 203, 0, 113]);
    let update = bgp_message(2, &body);
    let mrt = established_mrt_with_update(&update);

    let scratch = Scratch::new();
    let archive = bgp_mrt_store::create(
        &scratch.file(),
        &mrt,
        MrtSource {
            source_id: "relationship-test-collector".into(),
            checkpoint_id: "relationship-test-checkpoint".into(),
        },
        4 * 1024 * 1024,
        MrtLimits::default(),
        Limits::default(),
    )
    .expect("synthetic MRT source validates");

    assert!(
        archive.bgp4mp_candidates.is_empty(),
        "the replay adapter must not infer peer relationship from unequal ASNs or endpoint addresses"
    );
    let update_event = archive.bgp4mp_events.last().expect("UPDATE replay event");
    assert_eq!(
        string_field(update_event, "parse_status"),
        Some("quarantined_peer_relationship_unresolved")
    );
    assert!(update_event
        .encode()
        .contains("peer_relationship_context_unresolved_update_not_admitted"));
    assert!(update_event
        .encode()
        .contains("peer_relationship_unresolved"));
    assert!(update_event
        .encode()
        .contains("\"peer_relationship\":\"unknown\""));
    assert!(update_event
        .encode()
        .contains("\"peer_relationship_basis\":\"default_unknown\""));
}

#[test]
fn mrt_replay_relationship_is_explicit_reproducible_and_reported() {
    let mut attributes = mandatory_attributes();
    attributes.extend(attribute(0x40, 5, &[0, 0, 0, 42]));
    let mut body = vec![0, 0];
    body.extend_from_slice(
        &u16::try_from(attributes.len())
            .expect("synthetic attributes fit")
            .to_be_bytes(),
    );
    body.extend_from_slice(&attributes);
    body.extend_from_slice(&[24, 203, 0, 113]);
    let mrt = established_mrt_with_update(&bgp_message(2, &body));
    let scratch = Scratch::new();
    let store = scratch.file();
    let options = bgp_mrt_store::MrtReplayOptions {
        peer_relationship: Some(PeerRelationship::Internal),
    };

    let imported = bgp_mrt_store::create_with_options(
        &store,
        &mrt,
        MrtSource {
            source_id: "relationship-test-collector".into(),
            checkpoint_id: "relationship-test-checkpoint".into(),
        },
        4 * 1024 * 1024,
        MrtLimits::default(),
        Limits::default(),
        options,
    )
    .expect("synthetic MRT source validates");
    assert_eq!(imported.peer_relationship, Some(PeerRelationship::Internal));
    assert_eq!(imported.bgp4mp_candidates.len(), 1);
    assert!(imported
        .json()
        .encode()
        .contains("\"bgp4mp_peer_relationship_scope\":\"all_sessions_in_this_replay\""));

    let replayed = bgp_mrt_store::replay_with_options(
        &store,
        4 * 1024 * 1024,
        MrtLimits::default(),
        Limits::default(),
        bgp_mrt_store::MrtReplayOptions {
            peer_relationship: Some(PeerRelationship::External),
        },
    )
    .expect("same sealed source replays with explicit analysis context");
    assert_eq!(replayed.peer_relationship, Some(PeerRelationship::External));
    assert_eq!(replayed.bgp4mp_candidates.len(), 1);
    assert!(replayed
        .json()
        .encode()
        .contains("\"bgp4mp_peer_relationship_basis\":\"explicit_configuration\""));
    let normalized = replayed
        .state
        .observations()
        .last()
        .expect("accepted route observation")
        .normalized();
    assert!(normalized.encode().contains("attribute_discard"));
}
