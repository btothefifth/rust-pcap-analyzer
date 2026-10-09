//! Hand-built Phase 1 wire cases. Byte offsets are checked independently in
//! bgp_phase1_vectors.py; these assertions exercise the public PCAP decoder.

use pcap_evidence::{
    json::Json,
    provenance::{EvidenceBytes, PacketId},
    sha256, ErrorCode,
};
use pcap_evidence_product::deep::{
    bgp::{self, PcapMetadata, SessionState},
    bgp_pipeline::CapturedSessionPipeline,
    bgp_rib::RouteStatus,
    bgp_state::Observation,
    Limits,
};
#[cfg(all(feature = "standard", feature = "binary"))]
use pcap_evidence_product::protocols::Protocol;
#[cfg(all(feature = "standard", feature = "binary"))]
use std::{
    fs,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

fn packet(frame: u64) -> PacketId {
    PacketId {
        capture: sha256::digest(b"phase1-capture"),
        frame,
        record_offset: frame * 100,
    }
}
fn evidence(bytes: &[u8], frame: u64) -> EvidenceBytes {
    EvidenceBytes::from_packet(bytes, packet(frame), 54)
}
fn metadata(direction: Option<u8>, frame: u64) -> PcapMetadata {
    PcapMetadata {
        source_id: "phase1-capture".into(),
        record_id: format!("phase1-{frame}"),
        observed_at_ns: Some(42),
        session: Some(17),
        direction,
        peer: None,
        local: None,
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
fn opened(as16: u16, capabilities: &[Vec<u8>]) -> Vec<u8> {
    let caps: Vec<u8> = capabilities.iter().flatten().copied().collect();
    let mut body = vec![4];
    body.extend_from_slice(&as16.to_be_bytes());
    body.extend_from_slice(&90u16.to_be_bytes());
    body.extend_from_slice(&[192, 0, 2, 1]);
    body.push(u8::try_from(caps.len() + 2).unwrap());
    body.extend_from_slice(&[2, u8::try_from(caps.len()).unwrap()]);
    body.extend(caps);
    message(1, &body)
}
fn attribute(flags: u8, code: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![flags, code];
    if flags & 0x10 == 0 {
        out.push(u8::try_from(payload.len()).unwrap());
    } else {
        out.extend_from_slice(&u16::try_from(payload.len()).unwrap().to_be_bytes());
    }
    out.extend_from_slice(payload);
    out
}
fn update(attrs: &[u8], nlri: &[u8]) -> Vec<u8> {
    let mut body = vec![0, 0];
    body.extend_from_slice(&u16::try_from(attrs.len()).unwrap().to_be_bytes());
    body.extend_from_slice(attrs);
    body.extend_from_slice(nlri);
    message(2, &body)
}
fn decode(bytes: &[u8], direction: Option<u8>, frame: u64, state: &mut SessionState) -> Json {
    bgp::decode_pcap(
        &evidence(bytes, frame),
        metadata(direction, frame),
        state,
        &Limits::default(),
    )
    .unwrap()
}
fn two_octet_context() -> SessionState {
    let mut state = SessionState::default();
    for direction in 0..2u8 {
        let mut body = vec![4];
        body.extend((65000 + u16::from(direction)).to_be_bytes());
        body.extend(90u16.to_be_bytes());
        body.extend([192, 0, 2, 1 + direction, 0]);
        decode(
            &message(1, &body),
            Some(direction),
            900 + u64::from(direction),
            &mut state,
        );
    }
    state
}
fn get<'a>(value: &'a Json, key: &str) -> &'a Json {
    let Json::Object(fields) = value else {
        panic!("expected object")
    };
    &fields
        .iter()
        .find(|(name, _)| *name == key)
        .unwrap_or_else(|| panic!("missing {key}"))
        .1
}
fn array(value: &Json) -> &[Json] {
    let Json::Array(items) = value else {
        panic!("expected array")
    };
    items
}
fn ranges(value: &Json) -> &[Json] {
    array(get(get(value, "message_detail"), "attribute_ranges"))
}

#[test]
fn declared_capability_occurrences_keep_exact_ranges_and_unknown_hash() {
    let pairs: &[(u8, &[u8])] = &[
        (1, &[0, 2, 0, 1]),
        (2, &[]),
        (70, &[]),
        (65, &[0, 1, 0x11, 0x70]),
        (64, &[0x8f, 0xff, 0, 2, 1, 0x80]),
        (71, &[0, 2, 1, 0x80, 0, 0, 60]),
        (69, &[0, 2, 1, 3]),
        (6, &[]),
        (9, &[4]),
        (200, &[0xde, 0xad]),
    ];
    let caps: Vec<_> = pairs
        .iter()
        .map(|(code, bytes)| capability(*code, bytes))
        .collect();
    let raw = opened(23456, &caps);
    let value = decode(&raw, Some(0), 1, &mut SessionState::default());
    let occurrences = array(get(get(&value, "message_detail"), "capability_occurrences"));
    assert_eq!(occurrences.len(), pairs.len());
    let mut start = 31;
    for ((code, payload), item) in pairs.iter().zip(occurrences) {
        assert_eq!(get(item, "code"), &Json::from(*code));
        assert_eq!(get(item, "start"), &Json::from(start));
        assert_eq!(get(item, "end"), &Json::from(start + 2 + payload.len()));
        assert_eq!(
            get(item, "sha256"),
            &Json::from(sha256::hex(&sha256::digest(payload)))
        );
        start += 2 + payload.len();
    }
    assert_eq!(start, raw.len());
    assert_eq!(get(&value, "negotiation_established"), &Json::Bool(false));
    assert_eq!(get(&occurrences[9], "decoded"), &Json::Null);
    for (index, kind) in [
        (0, "multiprotocol"),
        (1, "route_refresh"),
        (2, "enhanced_route_refresh"),
        (4, "graceful_restart"),
        (5, "long_lived_graceful_restart"),
        (6, "add_path"),
        (7, "extended_messages"),
        (8, "role"),
    ] {
        assert_eq!(
            get(get(&occurrences[index], "decoded"), "kind"),
            &Json::from(kind)
        );
        assert_eq!(get(&occurrences[index], "valid"), &Json::Bool(true));
    }
    assert_eq!(get(&occurrences[3], "decoded"), &Json::from(70000u32));
    assert_eq!(
        get(get(&occurrences[0], "decoded"), "afi"),
        &Json::from(2u16)
    );
    let add_family = &array(get(get(&occurrences[6], "decoded"), "families"))[0];
    assert_eq!(get(add_family, "send"), &Json::Bool(true));
    assert_eq!(get(add_family, "receive"), &Json::Bool(true));
    assert_eq!(
        get(get(&occurrences[8], "decoded"), "role"),
        &Json::from(4u8)
    );
}

#[test]
fn invalid_capability_value_is_retained_without_selecting_layout() {
    let raw = opened(64512, &[capability(69, &[0, 1, 1])]);
    let value = decode(&raw, Some(0), 1, &mut SessionState::default());
    let occurrence = &array(get(get(&value, "message_detail"), "capability_occurrences"))[0];
    assert_eq!(get(occurrence, "valid"), &Json::Bool(false));
    assert_eq!(
        get(occurrence, "invalid_reason"),
        &Json::from("invalid_length")
    );
    assert_eq!(get(occurrence, "decoded"), &Json::Null);
    assert_eq!(
        get(occurrence, "sha256"),
        &Json::from(sha256::hex(&sha256::digest(&[0, 1, 1])))
    );
    assert_eq!(get(&value, "negotiation_established"), &Json::Bool(false));
}

#[test]
fn duplicate_and_conflicting_add_path_advertisements_are_distinct_evidence() {
    let cap = capability(69, &[0, 2, 1, 2]);
    for second in [cap.clone(), capability(69, &[0, 2, 1, 1])] {
        let raw = opened(64512, &[cap.clone(), second]);
        let value = decode(&raw, Some(0), 1, &mut SessionState::default());
        let occurrences = array(get(get(&value, "message_detail"), "capability_occurrences"));
        assert_eq!(occurrences.len(), 2);
        assert_eq!(get(&occurrences[0], "start"), &Json::from(31usize));
        assert_eq!(get(&occurrences[1], "end"), &Json::from(43usize));
        assert_ne!(get(&occurrences[1], "repetition"), &Json::from("first"));
        assert_eq!(get(&value, "negotiation_established"), &Json::Bool(false));
    }
}

#[test]
fn malformed_capability_extent_and_every_open_truncation_are_atomic() {
    let raw = opened(64512, &[capability(69, &[0, 2, 1, 2])]);
    let mut state = SessionState::default();
    for len in 0..raw.len() {
        let before = state.clone();
        assert!(bgp::decode_pcap(
            &evidence(&raw[..len], 1),
            metadata(Some(0), 1),
            &mut state,
            &Limits::default()
        )
        .is_err());
        assert_eq!(state, before);
    }
    let mut malformed = raw;
    malformed[32] = 5;
    let before = state.clone();
    assert!(bgp::decode_pcap(
        &evidence(&malformed, 1),
        metadata(Some(0), 1),
        &mut state,
        &Limits::default()
    )
    .is_err());
    assert_eq!(state, before);
}

#[test]
fn zero_bgp_identifier_is_rejected_before_open_state_mutation() {
    let mut raw = opened(64512, &[]);
    raw[24..28].fill(0);
    let mut state = SessionState::default();
    let before = state.clone();
    let error = bgp::decode_pcap(
        &evidence(&raw, 1),
        metadata(Some(0), 1),
        &mut state,
        &Limits::default(),
    )
    .unwrap_err();
    assert_eq!(error.code, ErrorCode::ProtocolFraming);
    assert_eq!(state, before);
}

#[test]
fn unsigned_nonzero_bgp_identifiers_preserve_display_and_raw_open_evidence() {
    // RFC 6286 changed the address-class oracle: these are integer IDs.
    for (identifier, display) in [
        ([0, 0, 0, 1], "0.0.0.1"),
        ([192, 0, 2, 1], "192.0.2.1"),
        ([224, 0, 0, 1], "224.0.0.1"),
        ([255, 255, 255, 255], "255.255.255.255"),
    ] {
        let mut raw = opened(64512, &[]);
        raw.truncate(29);
        raw[16..18].copy_from_slice(&29u16.to_be_bytes());
        raw[28] = 0;
        raw[24..28].copy_from_slice(&identifier);
        let mut state = SessionState::default();
        let value = decode(&raw, Some(0), 1, &mut state);
        assert_eq!(
            get(get(&value, "message_detail"), "identifier"),
            &Json::from(display)
        );
        assert_eq!(get(&value, "negotiation_established"), &Json::Bool(false));
        assert_ne!(state, SessionState::default());
        // The decoder must continue to accept exactly the same original bytes.
        let repeated = decode(&raw, Some(0), 1, &mut state.clone());
        assert_eq!(get(&value, "evidence"), get(&repeated, "evidence"));
    }
}

#[test]
fn invalid_ipv4_next_hop_is_retained_and_treated_as_withdraw() {
    for address in [[0, 0, 0, 0], [224, 0, 0, 1], [255, 255, 255, 255]] {
        let mut attrs = attribute(0x40, 1, &[0]);
        attrs.extend(attribute(0x40, 2, &[2, 1, 0xfd, 0xe8]));
        attrs.extend(attribute(0x40, 3, &address));
        let raw = update(&attrs, &[24, 203, 0, 113]);
        let value = decode(&raw, Some(0), 3, &mut two_octet_context());
        let occurrence = &ranges(&value)[2];
        assert_eq!(get(occurrence, "start"), &Json::from(34usize));
        assert_eq!(get(occurrence, "end"), &Json::from(41usize));
        assert_eq!(
            get(occurrence, "sha256"),
            &Json::from(sha256::hex(&sha256::digest(&address)))
        );
        assert_eq!(get(occurrence, "decoded"), &Json::Null);
        assert_eq!(
            get(occurrence, "disposition"),
            &Json::from("treat_as_withdraw")
        );
        assert_eq!(
            get(get(&value, "message_detail"), "update_disposition"),
            &Json::from("treat_as_withdraw")
        );
        let routes = array(get(&value, "routes"));
        assert_eq!(routes.len(), 1);
        assert_eq!(get(&routes[0], "action"), &Json::from("withdraw"));
        Observation::from_normalized(&value, None, &Limits::default()).unwrap();
    }
    // Host/subnet/receiver relationship cannot be inferred from these bytes.
    for address in [[192, 0, 2, 9], [10, 0, 0, 1], [203, 0, 113, 255]] {
        let mut attrs = attribute(0x40, 1, &[0]);
        attrs.extend(attribute(0x40, 2, &[2, 1, 0xfd, 0xe8]));
        attrs.extend(attribute(0x40, 3, &address));
        let value = decode(
            &update(&attrs, &[24, 203, 0, 113]),
            Some(0),
            3,
            &mut two_octet_context(),
        );
        assert_eq!(
            get(&ranges(&value)[2], "disposition"),
            &Json::from("accept_evidence_only")
        );
        assert_eq!(
            get(&array(get(&value, "routes"))[0], "action"),
            &Json::from("announce")
        );
    }
}

#[test]
fn split_asn_value_retains_packet_provenance_and_exact_output_budget() {
    let mut attrs = attribute(0x40, 1, &[0]);
    attrs.extend(attribute(0x40, 2, &[2, 1, 0, 1, 0x11, 0x70]));
    attrs.extend(attribute(0x40, 3, &[192, 0, 2, 9]));
    let raw = update(&attrs, &[24, 203, 0, 113]);
    let mut open_state = SessionState::default();
    let a = opened(23456, &[capability(65, &70000u32.to_be_bytes())]);
    decode(&a, Some(0), 1, &mut open_state);
    decode(&a, Some(1), 2, &mut open_state);
    let mut split = evidence(&raw[..34], 3);
    split
        .append(&EvidenceBytes::from_packet(&raw[34..], packet(4), 70), 4096)
        .unwrap();
    let mut state = open_state.clone();
    let value =
        bgp::decode_pcap(&split, metadata(Some(0), 3), &mut state, &Limits::default()).unwrap();
    assert_eq!(get(&ranges(&value)[1], "value_start"), &Json::from(30usize));
    assert_eq!(
        get(&ranges(&value)[1], "sha256"),
        &Json::from(sha256::hex(&sha256::digest(&raw[30..36])))
    );
    assert_eq!(array(get(get(&value, "evidence"), "spans")).len(), 2);
    let mut limits = Limits {
        output_bytes: value.encode().len(),
        ..Limits::default()
    };
    let same = bgp::decode_pcap(
        &split,
        metadata(Some(0), 3),
        &mut open_state.clone(),
        &limits,
    )
    .unwrap();
    assert_eq!(same, value);
    limits.output_bytes -= 1;
    let before = open_state.clone();
    let err = bgp::decode_pcap(&split, metadata(Some(0), 3), &mut open_state, &limits).unwrap_err();
    assert_eq!(err.code, ErrorCode::LimitExceeded);
    assert_eq!(open_state, before);
}

#[test]
fn duplicate_origin_and_wrong_flags_remain_individual_occurrences() {
    let origin = attribute(0x40, 1, &[0]);
    let mut attrs = origin.clone();
    attrs.extend(origin);
    attrs.extend(attribute(0x80, 1, &[0]));
    attrs.extend(attribute(0x40, 2, &[2, 1, 0xfd, 0xe8]));
    attrs.extend(attribute(0x40, 3, &[192, 0, 2, 1]));
    let raw = update(&attrs, &[24, 203, 0, 113]);
    let value = decode(&raw, Some(0), 1, &mut two_octet_context());
    let items = ranges(&value);
    assert_eq!(items.len(), 5);
    assert_eq!(get(&items[0], "start"), &Json::from(23usize));
    assert_eq!(
        get(&items[1], "repetition"),
        &Json::from("duplicate_identical")
    );
    assert_eq!(get(&items[2], "repetition"), &Json::from("conflicting"));
    assert_eq!(
        get(get(&items[1], "validation"), "multiplicity_valid"),
        &Json::Bool(false)
    );
    assert_eq!(
        get(&items[1], "disposition"),
        &Json::from("discard_later_occurrence")
    );
    assert_eq!(
        get(get(&items[2], "validation"), "flags_valid"),
        &Json::Bool(false)
    );
    assert_eq!(
        get(&items[2], "disposition"),
        &Json::from("discard_later_occurrence")
    );
    let route = &array(get(&value, "routes"))[0];
    assert_eq!(get(get(route, "attributes"), "origin"), &Json::from(0u8));
    assert_eq!(get(route, "action"), &Json::from("announce"));
    assert_eq!(
        get(get(route, "semantic_identity"), "completeness"),
        &Json::from("complete")
    );

    let mut baseline_attributes = attribute(0x40, 1, &[0]);
    baseline_attributes.extend(attribute(0x40, 2, &[2, 1, 0xfd, 0xe8]));
    baseline_attributes.extend(attribute(0x40, 3, &[192, 0, 2, 1]));
    let baseline = decode(
        &update(&baseline_attributes, &[24, 203, 0, 113]),
        Some(0),
        1,
        &mut two_octet_context(),
    );
    let baseline_route = &array(get(&baseline, "routes"))[0];
    assert_eq!(
        get(get(route, "semantic_identity"), "fingerprint_sha256"),
        get(
            get(baseline_route, "semantic_identity"),
            "fingerprint_sha256"
        )
    );
}

#[test]
fn malformed_origin_value_and_unknown_attribute_have_distinct_dispositions() {
    let mut attrs = attribute(0x40, 1, &[9]);
    attrs.extend(attribute(0x80, 220, &[0xde, 0xad]));
    let raw = update(&attrs, &[24, 203, 0, 113]);
    let value = decode(&raw, Some(0), 1, &mut SessionState::default());
    let items = ranges(&value);
    assert_eq!(items.len(), 2);
    assert_eq!(
        get(get(&items[0], "validation"), "length_valid"),
        &Json::Bool(false)
    );
    assert_eq!(
        get(&items[0], "disposition"),
        &Json::from("treat_as_withdraw")
    );
    assert_eq!(get(&items[0], "decoded"), &Json::Null);
    assert_eq!(
        get(get(&items[1], "validation"), "known"),
        &Json::Bool(false)
    );
    assert_eq!(
        get(&items[1], "sha256"),
        &Json::from(sha256::hex(&sha256::digest(&[0xde, 0xad])))
    );
    assert_eq!(get(&value, "negotiation_established"), &Json::Bool(false));
}

#[test]
fn reserved_attribute_flag_bits_are_reported_but_ignored_on_receipt() {
    let mut attrs = attribute(0x41, 1, &[0]);
    attrs.extend(attribute(0x40, 2, &[2, 1, 0xfd, 0xe8]));
    attrs.extend(attribute(0x40, 3, &[192, 0, 2, 9]));
    let value = decode(
        &update(&attrs, &[24, 203, 0, 113]),
        Some(0),
        1,
        &mut SessionState::default(),
    );
    let origin = &ranges(&value)[0];
    assert_eq!(
        get(get(origin, "validation"), "reserved_bits_nonzero"),
        &Json::Bool(true)
    );
    assert_eq!(
        get(get(origin, "validation"), "flags_valid"),
        &Json::Bool(true)
    );
    assert_eq!(
        get(origin, "disposition"),
        &Json::from("accept_evidence_only")
    );
}

fn as4_transition_update(as4_path: &[u8], base_aggregator: u16) -> Vec<u8> {
    let mut attrs = attribute(0x40, 1, &[0]);
    attrs.extend(attribute(
        0x40,
        2,
        &[2, 3, 0xfd, 0xe8, 0x5b, 0xa0, 0xfc, 0x00],
    ));
    attrs.extend(attribute(0x40, 3, &[192, 0, 2, 9]));
    attrs.extend(attribute(0xc0, 17, as4_path));
    let mut aggregator = base_aggregator.to_be_bytes().to_vec();
    aggregator.extend([192, 0, 2, 7]);
    attrs.extend(attribute(0xc0, 7, &aggregator));
    attrs.extend(attribute(0xc0, 18, &[0, 1, 0x11, 0x70, 192, 0, 2, 7]));
    update(&attrs, &[24, 203, 0, 113])
}

fn old_new_state() -> SessionState {
    let mut state = SessionState::default();
    decode(
        &opened(23456, &[capability(65, &70000u32.to_be_bytes())]),
        Some(0),
        1,
        &mut state,
    );
    decode(&opened(64512, &[]), Some(1), 2, &mut state);
    state
}

#[test]
fn old_new_as4_suffix_and_aggregator_are_reconstructed_from_raw_occurrences() {
    let as4 = [2, 2, 0, 1, 0x11, 0x70, 0, 0, 0xfc, 0];
    let value = decode(
        &as4_transition_update(&as4, 23456),
        Some(1),
        3,
        &mut old_new_state(),
    );
    let reconstruction = get(get(&value, "message_detail"), "as4_reconstruction");
    assert_eq!(
        get(reconstruction, "status"),
        &Json::from("old_new_reconstructed")
    );
    let path = array(get(reconstruction, "effective_as_path"));
    assert_eq!(array(get(&path[0], "values")), &[Json::from(65000u32)]);
    assert_eq!(
        array(get(&path[1], "values")),
        &[Json::from(70000u32), Json::from(64512u32)]
    );
    assert_eq!(
        get(reconstruction, "effective_aggregator"),
        &Json::from("70000:192.0.2.7")
    );
    assert_eq!(ranges(&value).len(), 6);
    assert_eq!(
        get(reconstruction, "base_as_path_start"),
        &Json::from(27usize)
    );
    assert_eq!(get(&value, "negotiation_established"), &Json::Bool(false));
    let state_observation = Observation::from_normalized(&value, None, &Limits::default()).unwrap();
    assert_eq!(state_observation.routes().len(), 1);
    let state_route = &state_observation.routes()[0];
    assert_eq!(
        get(state_route.semantic_identity(), "completeness"),
        &Json::from("complete")
    );
    assert!(!state_route.ambiguous_attributes());
}

#[test]
fn longer_as4_path_and_new_new_context_do_not_replace_the_base_path() {
    let longer = [
        2, 4, 0, 1, 0x11, 0x70, 0, 1, 0x38, 0x80, 0, 1, 0x5f, 0x90, 0, 1, 0x86, 0xa0,
    ];
    let value = decode(
        &as4_transition_update(&longer, 23456),
        Some(1),
        3,
        &mut old_new_state(),
    );
    assert_eq!(
        get(
            get(get(&value, "message_detail"), "as4_reconstruction"),
            "status"
        ),
        &Json::from("longer_as4_path_ignored")
    );
    assert_eq!(
        get(&ranges(&value)[3], "disposition"),
        &Json::from("attribute_discard")
    );
    let mut both_new = SessionState::default();
    decode(
        &opened(23456, &[capability(65, &70000u32.to_be_bytes())]),
        Some(0),
        1,
        &mut both_new,
    );
    decode(
        &opened(23456, &[capability(65, &70000u32.to_be_bytes())]),
        Some(1),
        2,
        &mut both_new,
    );
    let mut attrs = attribute(0x40, 1, &[0]);
    attrs.extend(attribute(0x40, 2, &[2, 1, 0, 1, 0x11, 0x70]));
    attrs.extend(attribute(0x40, 3, &[192, 0, 2, 9]));
    attrs.extend(attribute(0xc0, 17, &[2, 1, 0, 1, 0x38, 0x80]));
    let value = decode(
        &update(&attrs, &[24, 203, 0, 113]),
        Some(0),
        3,
        &mut both_new,
    );
    assert_eq!(
        get(
            get(get(&value, "message_detail"), "as4_reconstruction"),
            "status"
        ),
        &Json::from("new_new_discard_as4_attributes")
    );
    assert_eq!(
        get(&ranges(&value)[3], "disposition"),
        &Json::from("attribute_discard")
    );
}

#[test]
fn non_as_trans_aggregator_discard_and_as4_confed_segment_discard_are_distinct() {
    let ordinary = [2, 2, 0, 1, 0x11, 0x70, 0, 0, 0xfc, 0];
    let value = decode(
        &as4_transition_update(&ordinary, 65000),
        Some(1),
        3,
        &mut old_new_state(),
    );
    let reconstructed = get(get(&value, "message_detail"), "as4_reconstruction");
    assert_eq!(
        get(reconstructed, "status"),
        &Json::from("non_as_trans_aggregator_discard_as4")
    );
    assert_eq!(
        get(&ranges(&value)[3], "disposition"),
        &Json::from("attribute_discard")
    );
    assert_eq!(
        get(&ranges(&value)[5], "disposition"),
        &Json::from("attribute_discard")
    );
    assert_eq!(
        get(reconstructed, "effective_aggregator"),
        &Json::from("65000:192.0.2.7")
    );
    let confed_as4 = [3, 1, 0, 1, 0x11, 0x70, 2, 1, 0, 1, 0x38, 0x80];
    let value = decode(
        &as4_transition_update(&confed_as4, 23456),
        Some(1),
        3,
        &mut old_new_state(),
    );
    let reconstructed = get(get(&value, "message_detail"), "as4_reconstruction");
    assert_eq!(
        get(reconstructed, "status"),
        &Json::from("old_new_reconstructed_confederation_discarded")
    );
    let as4_occurrence = get(&ranges(&value)[3], "decoded");
    assert_eq!(array(get(as4_occurrence, "raw_segments")).len(), 2);
    assert_eq!(array(get(as4_occurrence, "usable_segments")).len(), 1);
    assert_eq!(
        get(&array(get(as4_occurrence, "raw_segments"))[0], "kind"),
        &Json::from(3u8)
    );
    let path = array(get(reconstructed, "effective_as_path"));
    assert_eq!(
        array(get(&path[0], "values")),
        &[Json::from(65000u32), Json::from(23456u32)]
    );
    assert_eq!(array(get(&path[1], "values")), &[Json::from(80000u32)]);
}

#[test]
fn add_path_requires_bilateral_directional_capability_evidence() {
    let sender = capability(69, &[0, 1, 1, 2]);
    let receiver = capability(69, &[0, 1, 1, 1]);
    let mut attrs = attribute(0x40, 1, &[0]);
    attrs.extend(attribute(0x40, 2, &[2, 1, 0xfd, 0xe8]));
    attrs.extend(attribute(0x40, 3, &[192, 0, 2, 9]));
    let raw = update(&attrs, &[1, 2, 3, 4, 24, 203, 0, 113]);
    let mut paired = SessionState::default();
    decode(&opened(64512, &[sender.clone()]), Some(0), 1, &mut paired);
    decode(&opened(64513, &[receiver]), Some(1), 2, &mut paired);
    let value = decode(&raw, Some(0), 3, &mut paired);
    assert_eq!(
        get(&array(get(&value, "routes"))[0], "path_id"),
        &Json::from(0x01020304u32)
    );
    assert_eq!(get(&value, "negotiation_established"), &Json::Bool(false));
    let mut one_sided = SessionState::default();
    decode(&opened(64512, &[sender]), Some(0), 1, &mut one_sided);
    let ambiguous = decode(&raw, Some(0), 3, &mut one_sided);
    assert!(array(get(&ambiguous, "routes")).is_empty());
    assert_ne!(
        get(get(&ambiguous, "message_detail"), "opaque_nlri"),
        &Json::Null
    );
}

#[test]
fn unknown_capability_keeps_its_hash_without_erasing_known_bilateral_layout() {
    let mut state = SessionState::default();
    decode(
        &opened(
            23456,
            &[
                capability(65, &70000u32.to_be_bytes()),
                capability(200, &[0xde, 0xad]),
            ],
        ),
        Some(0),
        1,
        &mut state,
    );
    decode(
        &opened(23456, &[capability(65, &70001u32.to_be_bytes())]),
        Some(1),
        2,
        &mut state,
    );
    let mut attrs = attribute(0x40, 1, &[0]);
    attrs.extend(attribute(0x40, 2, &[2, 1, 0, 1, 0x11, 0x70]));
    attrs.extend(attribute(0x40, 3, &[192, 0, 2, 9]));
    let value = decode(&update(&attrs, &[24, 203, 0, 113]), Some(0), 3, &mut state);
    assert_eq!(
        get(get(&value, "producer_context"), "asn_width"),
        &Json::from(4usize)
    );
    let path = array(get(
        get(&array(get(&value, "routes"))[0], "attributes"),
        "as_path",
    ));
    assert_eq!(array(get(&path[0], "values")), &[Json::from(70000u32)]);
    assert_eq!(get(&value, "negotiation_established"), &Json::Bool(false));
}

#[test]
fn confederation_prefix_survives_equal_length_as4_suffix_replacement() {
    let mut attrs = attribute(0x40, 1, &[0]);
    attrs.extend(attribute(
        0x40,
        2,
        &[
            3, 1, 0xfd, 0xe9, // AS_CONFED_SEQUENCE 65001
            2, 1, 0x5b, 0xa0, // AS_SEQUENCE AS_TRANS
        ],
    ));
    attrs.extend(attribute(0x40, 3, &[192, 0, 2, 9]));
    attrs.extend(attribute(0xc0, 17, &[2, 1, 0, 1, 0x11, 0x70]));
    let value = decode(
        &update(&attrs, &[24, 203, 0, 113]),
        Some(1),
        3,
        &mut old_new_state(),
    );
    let reconstruction = get(get(&value, "message_detail"), "as4_reconstruction");
    assert_eq!(
        get(reconstruction, "status"),
        &Json::from("old_new_reconstructed")
    );
    let path = array(get(reconstruction, "effective_as_path"));
    assert_eq!(get(&path[0], "kind"), &Json::from(3u8));
    assert_eq!(array(get(&path[0], "values")), &[Json::from(65001u32)]);
    assert_eq!(array(get(&path[1], "values")), &[Json::from(70000u32)]);
}

#[test]
fn enhanced_route_refresh_markers_require_complete_receiver_layout_context() {
    let refresh = message(5, &[0, 1, 1, 1]);
    let mut state = SessionState::default();
    decode(
        &opened(65000, &[capability(70, &[])]),
        Some(0),
        1,
        &mut state,
    );
    let unilateral = decode(&refresh, Some(0), 2, &mut state);
    assert_eq!(
        get(get(&unilateral, "message_detail"), "subtype_kind"),
        &Json::from("begin_of_route_refresh")
    );
    assert_eq!(
        get(
            get(&unilateral, "message_detail"),
            "enhanced_layout_context"
        ),
        &Json::Bool(false)
    );
    decode(
        &opened(65001, &[capability(70, &[])]),
        Some(1),
        3,
        &mut state,
    );
    let bilateral = decode(&refresh, Some(0), 4, &mut state);
    assert_eq!(
        get(get(&bilateral, "message_detail"), "enhanced_layout_context"),
        &Json::Bool(true)
    );
    assert_eq!(
        get(&bilateral, "negotiation_established"),
        &Json::Bool(false)
    );
}

#[test]
fn enhanced_route_refresh_unilateral_complete_open_context_is_receiver_directional() {
    for advertising_side in 0..=1u8 {
        let mut state = SessionState::default();
        for side in 0..=1u8 {
            let caps = if side == advertising_side {
                vec![capability(70, &[])]
            } else {
                Vec::new()
            };
            decode(
                &opened(65000 + u16::from(side), &caps),
                Some(side),
                u64::from(side) + 1,
                &mut state,
            );
        }
        for subtype in [1, 2] {
            let refresh = message(5, &[0, 1, subtype, 1]);
            for sender in 0..=1u8 {
                let value = decode(
                    &refresh,
                    Some(sender),
                    10 + u64::from(subtype) * 2 + u64::from(sender),
                    &mut state,
                );
                assert_eq!(
                    get(get(&value, "message_detail"), "enhanced_layout_context"),
                    &Json::Bool(sender != advertising_side)
                );
                assert_eq!(get(&value, "negotiation_established"), &Json::Bool(false));
            }
        }
    }
}

#[test]
fn declared_extension_attributes_keep_typed_values_and_malformed_dispositions() {
    let mut attrs = attribute(0x40, 1, &[0]);
    attrs.extend(attribute(0x40, 2, &[2, 1, 0xfd, 0xe8]));
    attrs.extend(attribute(0x40, 3, &[192, 0, 2, 1]));
    attrs.extend(attribute(0xc0, 16, &[0, 2, 0, 0, 0, 0, 0, 1]));
    attrs.extend(attribute(0x80, 26, &[1, 0, 11, 0, 0, 0, 0, 0, 0, 0, 9]));
    attrs.extend(attribute(0xc0, 32, &[0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3]));
    attrs.extend(attribute(0xc0, 35, &[0, 1, 0, 100]));
    let value = decode(
        &update(&attrs, &[24, 203, 0, 113]),
        Some(0),
        1,
        &mut SessionState::default(),
    );
    let occurrences = ranges(&value);
    let community = &array(get(&occurrences[3], "decoded"))[0];
    assert_eq!(get(community, "type"), &Json::from(0u8));
    assert_eq!(get(community, "subtype"), &Json::from(2u8));
    assert_eq!(
        get(&array(get(&occurrences[4], "decoded"))[0], "metric"),
        &Json::from(9u64)
    );
    assert_eq!(
        array(get(&occurrences[5], "decoded"))[0],
        Json::array([Json::from(1u32), Json::from(2u32), Json::from(3u32)])
    );
    assert_eq!(get(&occurrences[6], "decoded"), &Json::from(65636u32));

    let mut malformed = attrs[..attrs.len() - 7].to_vec();
    malformed.extend(attribute(0xc0, 35, &[0, 1, 0]));
    let result = decode(
        &update(&malformed, &[24, 203, 0, 113]),
        Some(0),
        2,
        &mut SessionState::default(),
    );
    assert_eq!(
        get(&ranges(&result)[6], "disposition"),
        &Json::from("treat_as_withdraw")
    );
    assert_eq!(
        get(get(&result, "message_detail"), "update_disposition"),
        &Json::from("treat_as_withdraw")
    );
    assert_eq!(
        get(&array(get(&result, "routes"))[0], "action"),
        &Json::from("withdraw")
    );
}

#[test]
fn rfc7606_dispositions_control_emitted_route_actions() {
    for (code, payload) in [(8, Vec::new()), (16, Vec::new()), (32, Vec::new())] {
        let mut attrs = attribute(0x40, 1, &[0]);
        attrs.extend(attribute(0x40, 2, &[2, 1, 0xfd, 0xe8]));
        attrs.extend(attribute(0x40, 3, &[192, 0, 2, 1]));
        attrs.extend(attribute(0xc0, code, &payload));
        let value = decode(
            &update(&attrs, &[24, 203, 0, 113]),
            Some(0),
            u64::from(code),
            &mut SessionState::default(),
        );
        assert_eq!(
            get(get(&value, "message_detail"), "update_disposition"),
            &Json::from("treat_as_withdraw")
        );
        assert_eq!(
            get(&array(get(&value, "routes"))[0], "action"),
            &Json::from("withdraw")
        );
    }

    let malformed_origin = attribute(0x40, 1, &[9]);
    let mut reset_state = SessionState::default();
    let route_free = decode(
        &update(&malformed_origin, &[]),
        Some(0),
        100,
        &mut reset_state,
    );
    assert_eq!(
        get(get(&route_free, "message_detail"), "update_disposition"),
        &Json::from("session_reset")
    );
    assert!(array(get(&route_free, "routes")).is_empty());
    assert_eq!(reset_state.generation(), 1);

    let mut attrs = attribute(0x40, 1, &[0]);
    attrs.extend(attribute(0x40, 2, &[2, 1, 0xfd, 0xe8]));
    attrs.extend(attribute(0x40, 3, &[192, 0, 2, 1]));
    attrs.extend(attribute(0xc0, 17, &[]));
    let as4 = decode(
        &update(&attrs, &[24, 203, 0, 113]),
        Some(0),
        101,
        &mut SessionState::default(),
    );
    assert_eq!(
        get(&ranges(&as4)[3], "disposition"),
        &Json::from("attribute_discard")
    );
    assert_eq!(
        get(&array(get(&as4, "routes"))[0], "action"),
        &Json::from("announce")
    );

    let mut attrs = attribute(0x40, 1, &[0]);
    attrs.extend(attribute(0x40, 2, &[2, 1, 0xfd, 0xe8]));
    attrs.extend(attribute(0x40, 3, &[192, 0, 2, 1]));
    attrs.extend(attribute(0x80, 10, &[]));
    let value = decode(
        &update(&attrs, &[24, 203, 0, 113]),
        Some(0),
        210,
        &mut SessionState::default(),
    );
    assert_eq!(
        get(&ranges(&value)[3], "disposition"),
        &Json::from("peer_relationship_unresolved")
    );
    assert_eq!(
        get(&ranges(&value)[3], "peer_relationship"),
        &Json::from("unknown")
    );
    assert_eq!(
        get(get(&value, "message_detail"), "known_update_disposition"),
        &Json::from("accept_evidence_only")
    );
    assert_eq!(
        get(get(&value, "message_detail"), "update_disposition"),
        &Json::from("peer_relationship_unresolved")
    );
    assert!(array(get(&value, "routes")).is_empty());
    assert_eq!(
        get(
            &array(get(get(&value, "message_detail"), "opaque_nlri"))[0],
            "kind"
        ),
        &Json::from("peer_relationship_unresolved_route")
    );

    let code = 26;
    let mut attrs = attribute(0x40, 1, &[0]);
    attrs.extend(attribute(0x40, 2, &[2, 1, 0xfd, 0xe8]));
    attrs.extend(attribute(0x40, 3, &[192, 0, 2, 1]));
    attrs.extend(attribute(0x80, code, &[]));
    let value = decode(
        &update(&attrs, &[24, 203, 0, 113]),
        Some(0),
        200 + u64::from(code),
        &mut SessionState::default(),
    );
    assert_eq!(
        get(&ranges(&value)[3], "disposition"),
        &Json::from("attribute_discard"),
        "AIGP"
    );
    assert_eq!(
        get(&array(get(&value, "routes"))[0], "action"),
        &Json::from("announce"),
        "AIGP"
    );
}

#[test]
#[cfg(all(feature = "standard", feature = "binary"))]
fn stateless_framer_preserves_coalesced_add_path_and_extended_message_boundaries() {
    let first = update(&attribute(0x40, 1, &[0]), &[1, 2, 3, 4, 24, 203, 0, 113]);
    let second = message(4, &[]);
    let mut coalesced = first.clone();
    coalesced.extend(&second);
    let framed = Protocol::Bgp.decode(&coalesced).unwrap();
    assert_eq!(framed.consumed, first.len());
    assert_eq!(
        Protocol::Bgp
            .decode(&coalesced[framed.consumed..])
            .unwrap()
            .consumed,
        second.len()
    );

    let large = update(&attribute(0xd0, 200, &vec![0; 4070]), &[]);
    assert_eq!(large.len(), 4097);
    assert_eq!(Protocol::Bgp.decode(&large).unwrap().consumed, large.len());
    let mut state = SessionState::default();
    let before = state.clone();
    assert!(bgp::decode_pcap(
        &evidence(&large, 1),
        metadata(Some(0), 1),
        &mut state,
        &Limits::default()
    )
    .is_err());
    assert_eq!(state, before);
    decode(
        &opened(65000, &[capability(6, &[])]),
        Some(0),
        2,
        &mut state,
    );
    decode(
        &opened(65001, &[capability(6, &[])]),
        Some(1),
        3,
        &mut state,
    );
    let result = decode(&large, Some(0), 4, &mut state);
    assert_eq!(get(&result, "negotiation_established"), &Json::Bool(false));
    assert_eq!(
        get(
            get(get(&result, "producer_context"), "capability_layout"),
            "extended_messages"
        ),
        &Json::Bool(true)
    );
}

#[test]
fn extended_message_authority_is_the_receivers_advertisement() {
    let large = update(&attribute(0xd0, 200, &vec![0; 4070]), &[]);

    let mut receiver_advertised = SessionState::default();
    decode(&opened(65000, &[]), Some(0), 1, &mut receiver_advertised);
    decode(
        &opened(65001, &[capability(6, &[])]),
        Some(1),
        2,
        &mut receiver_advertised,
    );
    let accepted = decode(&large, Some(0), 3, &mut receiver_advertised);
    assert_eq!(get(&accepted, "message_type"), &Json::from(2u8));

    let mut sender_only = SessionState::default();
    decode(
        &opened(65000, &[capability(6, &[])]),
        Some(0),
        1,
        &mut sender_only,
    );
    decode(&opened(65001, &[]), Some(1), 2, &mut sender_only);
    let before = sender_only.clone();
    assert!(bgp::decode_pcap(
        &evidence(&large, 3),
        metadata(Some(0), 3),
        &mut sender_only,
        &Limits::default(),
    )
    .is_err());
    assert_eq!(sender_only, before);
}

#[test]
fn mp_reach_reserved_octet_is_observed_and_ignored_on_receipt() {
    let mut mp = vec![0, 2, 1, 16];
    mp.extend([0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    mp.extend([7, 32, 0x20, 1, 0x0d, 0xb8]);
    let mut attrs = attribute(0x40, 1, &[0]);
    attrs.extend(attribute(0x40, 2, &[2, 1, 0xfd, 0xe8]));
    attrs.extend(attribute(0x80, 14, &mp));
    let mp_capability = capability(1, &[0, 2, 0, 1]);
    let mut state = SessionState::default();
    decode(
        &opened(64512, &[mp_capability.clone()]),
        Some(0),
        1,
        &mut state,
    );
    decode(&opened(64513, &[mp_capability]), Some(1), 2, &mut state);
    let value = decode(&update(&attrs, &[]), Some(0), 3, &mut state);
    assert_eq!(array(get(&value, "routes")).len(), 1);
    assert_eq!(
        get(&ranges(&value)[2], "disposition"),
        &Json::from("accept_evidence_only")
    );
    assert!(array(get(&value, "issues")).contains(&Json::from("mp_reach_reserved_nonzero_ignored")));
}

#[test]
fn mp_nlri_without_bilateral_family_capability_stays_opaque() {
    let mut mp = vec![0, 2, 1, 16];
    mp.extend([0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    mp.extend([0, 32, 0x20, 1, 0x0d, 0xb8]);
    let mut attrs = attribute(0x40, 1, &[0]);
    attrs.extend(attribute(0x40, 2, &[2, 1, 0xfd, 0xe8]));
    attrs.extend(attribute(0x80, 14, &mp));
    let value = decode(
        &update(&attrs, &[]),
        Some(0),
        1,
        &mut SessionState::default(),
    );
    assert!(array(get(&value, "routes")).is_empty());
    assert_eq!(
        get(&ranges(&value)[2], "interpretation"),
        &Json::from("opaque_family_capability_or_add_path_layout")
    );
    assert!(array(get(&value, "issues")).contains(&Json::from("mp_reach_capability_unresolved")));
}

#[test]
#[cfg(all(feature = "standard", feature = "binary"))]
fn typed_open_capability_reaches_real_pcap_depth_output() {
    let original = include_bytes!("fixtures/bgp.pcap");
    let mut offset = 24usize;
    for _ in 0..3 {
        let length =
            u32::from_le_bytes(original[offset + 8..offset + 12].try_into().unwrap()) as usize;
        offset += 16 + length;
    }
    let mut pcap = original[..offset].to_vec();
    let original_packet_len =
        u32::from_le_bytes(original[offset + 8..offset + 12].try_into().unwrap()) as usize;
    assert!(original_packet_len >= 54);
    let mut packet = original[offset + 16..offset + 16 + 54].to_vec();
    let open = opened(23456, &[capability(65, &70000u32.to_be_bytes())]);
    packet.extend_from_slice(&open);
    let ip_length = u16::try_from(40 + open.len()).unwrap();
    packet[16..18].copy_from_slice(&ip_length.to_be_bytes());
    packet[24..26].fill(0);
    let checksum_sum: u32 = packet[14..34]
        .chunks_exact(2)
        .map(|pair| u32::from(u16::from_be_bytes([pair[0], pair[1]])))
        .sum();
    let checksum = !((checksum_sum & 0xffff) + (checksum_sum >> 16)) as u16;
    packet[24..26].copy_from_slice(&checksum.to_be_bytes());
    packet[50..52].fill(0); // The offline decoder does not authenticate TCP checksums.
    let mut record_header = original[offset..offset + 16].to_vec();
    let packet_length = u32::try_from(packet.len()).unwrap();
    record_header[8..12].copy_from_slice(&packet_length.to_le_bytes());
    record_header[12..16].copy_from_slice(&packet_length.to_le_bytes());
    pcap.extend(record_header);
    pcap.extend(packet);

    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!("bgp-phase1-pcap-{}-{nonce}", std::process::id()));
    fs::create_dir(&root).unwrap();
    let input = root.join("input.pcap");
    let output = root.join("output");
    fs::write(&input, pcap).unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_pcap-depth"))
        .args([
            "analyze",
            input.to_str().unwrap(),
            "--workspace",
            output.to_str().unwrap(),
            "--format",
            "ndjson",
        ])
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let events = fs::read_to_string(output.join("events.ndjson")).unwrap();
    assert!(events.contains("\"depth_bgp\""));
    assert!(events.contains("\"four_octet_asn\":70000"));
    assert!(events.contains("\"negotiation_established\":false"));
    fs::remove_dir_all(root).unwrap();
}

#[test]
#[cfg(all(feature = "standard", feature = "binary"))]
fn stateless_framer_admits_complete_body_errors_without_consuming_successor() {
    // RFC 7606 section 4: ORIGIN claims one byte beyond the three-byte block.
    let malformed_update = update(&[0x40, 1, 1], &[24, 203, 0, 113]);
    let withdrawal = message(2, &[0, 4, 24, 203, 0, 113, 0, 0]);
    let mut invalid_open = opened(64512, &[]);
    invalid_open[19] = 3;
    let cases = [
        malformed_update.clone(),
        update(&[0x40], &[24, 203, 0, 113]),
        update(&[0x40, 1], &[24, 203, 0, 113]),
        update(&[0x50, 1, 0], &[24, 203, 0, 113]),
        invalid_open,
        message(1, &[]),
        message(3, &[6]),
        message(4, &[0]),
        message(5, &[0, 1, 0]),
        message(5, &[0, 1, 0, 1, 0]),
    ];
    for first in cases {
        let mut coalesced = first.clone();
        coalesced.extend(&withdrawal);
        let framed = Protocol::Bgp.decode(&coalesced).unwrap();
        assert_eq!(framed.consumed, first.len());
        assert!(framed.fields.iter().all(|field| field.end <= first.len()));
        let second = Protocol::Bgp.decode(&coalesced[framed.consumed..]).unwrap();
        assert_eq!(second.consumed, withdrawal.len());
        for cut in 0..first.len() {
            assert!(Protocol::Bgp.decode(&first[..cut]).is_err(), "cut={cut}");
        }
    }
    let value = decode(&malformed_update, Some(0), 3, &mut two_octet_context());
    assert_eq!(
        get(get(&value, "message_detail"), "update_disposition"),
        &Json::from("treat_as_withdraw")
    );
    assert_eq!(
        get(&array(get(&value, "routes"))[0], "action"),
        &Json::from("withdraw")
    );
    for (at, value) in [(0, 0), (16, 0), (18, 0)] {
        let mut invalid_header = withdrawal.clone();
        invalid_header[at] = value;
        if at == 16 {
            invalid_header[17] = 18;
        }
        assert!(Protocol::Bgp.decode(&invalid_header).is_err());
    }
}

#[test]
fn declared_multiprotocol_next_hop_address_classes_keep_capability_bound_dispositions() {
    let global = [0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let link_local = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let mp_value = |afi: u16, hop: &[u8]| {
        let mut value = afi.to_be_bytes().to_vec();
        value.extend([1, hop.len() as u8]);
        value.extend(hop);
        value.push(0); // Reserved octet.
        if afi == 1 {
            value.extend([24, 203, 0, 113]);
        } else {
            value.extend([32, 0x20, 1, 0x0d, 0xb8]);
        }
        value
    };
    let observe = |afi: u16, hop: &[u8], capability_known: bool| {
        let mp = mp_value(afi, hop);
        let mut attrs = attribute(0x40, 1, &[0]);
        attrs.extend(attribute(0x40, 2, &[2, 1, 0xfd, 0xe8]));
        attrs.extend(attribute(0x80, 14, &mp));
        let mut state = SessionState::default();
        let caps = if capability_known {
            vec![capability(1, &[0, afi as u8, 0, 1])]
        } else {
            vec![]
        };
        decode(&opened(65000, &caps), Some(0), 1, &mut state);
        decode(&opened(65001, &caps), Some(1), 2, &mut state);
        (decode(&update(&attrs, &[]), Some(0), 3, &mut state), mp)
    };
    let mut unspecified = [0; 16];
    let mut multicast = unspecified;
    multicast[0] = 0xff;
    unspecified[15] = 1; // Loopback has link-local scope, not the first global field.
    let mut invalid = vec![
        (1, vec![0; 4]),
        (1, vec![224, 0, 0, 1]),
        (1, vec![255; 4]),
        (2, vec![0; 16]),
        (2, unspecified.to_vec()),
        (2, multicast.to_vec()),
        (2, link_local.to_vec()),
    ];
    invalid.push((2, [global.as_slice(), global.as_slice()].concat()));
    invalid.push((2, [global.as_slice(), multicast.as_slice()].concat()));
    for (afi, hop) in invalid {
        let (value, mp) = observe(afi, &hop, true);
        assert_eq!(
            get(&ranges(&value)[2], "sha256"),
            &Json::from(sha256::hex(&sha256::digest(&mp)))
        );
        assert_eq!(get(&ranges(&value)[2], "decoded"), &Json::Null);
        assert_eq!(
            get(&ranges(&value)[2], "disposition"),
            &Json::from("session_reset")
        );
        assert_eq!(
            get(get(&value, "message_detail"), "update_disposition"),
            &Json::from("session_reset")
        );
        assert!(array(get(&value, "routes")).is_empty());
        let (opaque, _) = observe(afi, &hop, false);
        assert_eq!(
            get(&ranges(&opaque)[2], "interpretation"),
            &Json::from("opaque_family_capability_or_add_path_layout")
        );
    }
    // Unsupported capability 77 changes the next-hop layout hypothesis;
    // retain opacity without interpreting the draft's values or negotiation.
    for hop in [
        global.to_vec(),
        link_local.to_vec(),
        [vec![0; 16], link_local.to_vec()].concat(),
    ] {
        let mp = mp_value(2, &hop);
        let mut attrs = attribute(0x40, 1, &[0]);
        attrs.extend(attribute(0x40, 2, &[2, 1, 0xfd, 0xe8]));
        attrs.extend(attribute(0x80, 14, &mp));
        for advertised_sides in [1, 2] {
            let mp_cap = capability(1, &[0, 2, 0, 1]);
            let extra = capability(77, &[]);
            let mut state = SessionState::default();
            decode(
                &opened(65000, &[mp_cap.clone(), extra.clone()]),
                Some(0),
                1,
                &mut state,
            );
            let receiver_caps = if advertised_sides == 2 {
                vec![mp_cap, extra]
            } else {
                vec![mp_cap]
            };
            decode(&opened(65001, &receiver_caps), Some(1), 2, &mut state);
            let value = decode(&update(&attrs, &[]), Some(0), 3, &mut state);
            assert_eq!(
                get(&ranges(&value)[2], "interpretation"),
                &Json::from("opaque_family_capability_or_add_path_layout")
            );
            assert_ne!(
                get(&ranges(&value)[2], "disposition"),
                &Json::from("session_reset")
            );
            assert!(array(get(&value, "routes")).is_empty());
            assert!(array(get(&value, "issues"))
                .contains(&Json::from("mp_reach_next_hop_layout_unresolved")));
            // Reach the real native consumer: prior Active becomes unresolved
            // at the opaque-layout cut, without inventing a protocol reset.
            let mut pipeline = CapturedSessionPipeline::new(
                sha256::digest(b"phase1-capture"),
                "phase1-capture".into(),
                17,
                Limits::default(),
            )
            .unwrap();
            let sender_open = opened(65000, &[capability(1, &[0, 2, 0, 1]), capability(77, &[])]);
            for (raw, direction, frame) in
                [(&sender_open, 0, 1), (&opened(65001, &receiver_caps), 1, 2)]
            {
                pipeline
                    .apply_message(&evidence(raw, frame), metadata(Some(direction), frame))
                    .unwrap();
            }
            let mut base = attribute(0x40, 1, &[0]);
            base.extend(attribute(0x40, 2, &[2, 1, 0xfd, 0xe8]));
            base.extend(attribute(0x40, 3, &[192, 0, 2, 9]));
            pipeline
                .apply_message(
                    &evidence(&update(&base, &[24, 203, 0, 113]), 3),
                    metadata(Some(0), 3),
                )
                .unwrap();
            assert!(pipeline
                .rib()
                .entries()
                .values()
                .all(|entry| entry.status == RouteStatus::Active));
            let receipt = pipeline
                .apply_message(&evidence(&update(&attrs, &[]), 4), metadata(Some(0), 4))
                .unwrap();
            assert!(!receipt.protocol_reset);
            assert_eq!(pipeline.rib().entries().len(), 1);
            assert!(pipeline
                .rib()
                .entries()
                .values()
                .all(|entry| entry.status == RouteStatus::Unresolved));
        }
    }
    let ula = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let site_local = [0xfe, 0xc0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    for (afi, hop) in [
        (1, vec![192, 0, 2, 1]),
        (2, global.to_vec()),
        (2, ula.to_vec()),
        (2, site_local.to_vec()),
        (2, [global.as_slice(), link_local.as_slice()].concat()),
    ] {
        let (value, _) = observe(afi, &hop, true);
        assert_eq!(
            get(&ranges(&value)[2], "disposition"),
            &Json::from("accept_evidence_only")
        );
        assert_eq!(
            get(&array(get(&value, "routes"))[0], "action"),
            &Json::from("announce")
        );
    }
}

#[test]
fn unsupported_multiprotocol_family_never_enters_declared_next_hop_grammar() {
    let mut mp = vec![0, 25, 70, 16];
    mp.extend([0xff; 16]);
    mp.push(0);
    let attrs = attribute(0x80, 14, &mp);
    let mut state = SessionState::default();
    let caps = [capability(1, &[0, 25, 0, 70])];
    decode(&opened(65000, &caps), Some(0), 1, &mut state);
    decode(&opened(65001, &caps), Some(1), 2, &mut state);
    let value = decode(&update(&attrs, &[]), Some(0), 3, &mut state);
    assert_eq!(
        get(&ranges(&value)[0], "interpretation"),
        &Json::from("opaque_family_capability_or_add_path_layout")
    );
    assert_ne!(
        get(&ranges(&value)[0], "disposition"),
        &Json::from("session_reset")
    );
    assert!(array(get(&value, "routes")).is_empty());
}

#[test]
fn repeated_open_bytes_retain_source_witnesses_and_bilateral_grammar() {
    let caps = [
        capability(65, &70000u32.to_be_bytes()),
        capability(1, &[0, 2, 0, 1]),
    ];
    let a = opened(23456, &caps);
    let b = opened(
        23456,
        &[capability(65, &70001u32.to_be_bytes()), caps[1].clone()],
    );
    let mut state = SessionState::default();
    decode(&a, Some(0), 1, &mut state);
    decode(&b, Some(1), 2, &mut state);
    let first_repeat = decode(&a, Some(0), 3, &mut state);
    let second_repeat = decode(&b, Some(1), 4, &mut state);
    for value in [&first_repeat, &second_repeat] {
        assert!(!array(get(value, "issues")).contains(&Json::from(
            "repeated_open_requires_explicit_generation_boundary"
        )));
        assert_eq!(
            get(get(value, "producer_context"), "asn_width"),
            &Json::from(4usize)
        );
    }
    let sides = array(get(get(&second_repeat, "producer_context"), "open_sides"));
    assert_eq!(sides.len(), 2);
    for side in sides {
        let witnesses = array(get(side, "observations"));
        assert_eq!(witnesses.len(), 2);
        assert_ne!(get(&witnesses[0], "source"), get(&witnesses[1], "source"));
        assert_ne!(
            get(&witnesses[0], "evidence"),
            get(&witnesses[1], "evidence")
        );
        assert_eq!(get(&witnesses[0], "open"), get(&witnesses[1], "open"));
        assert_eq!(get(side, "advertised_asn_width"), &Json::from(4usize));
    }
    // The exact same source occurrence remains idempotent; the two new witnesses remain.
    let replay = decode(&a, Some(0), 3, &mut state);
    assert_eq!(
        get(get(&replay, "producer_context"), "open_sides"),
        &Json::Array(sides.to_vec())
    );

    let mut attrs = attribute(0x40, 1, &[0]);
    attrs.extend(attribute(0x40, 2, &[2, 1, 0, 1, 0x11, 0x70]));
    attrs.extend(attribute(0x40, 3, &[192, 0, 2, 9]));
    let value = decode(&update(&attrs, &[24, 203, 0, 113]), Some(0), 5, &mut state);
    let routes = array(get(&value, "routes"));
    assert_eq!(routes.len(), 1);
    let path = array(get(get(&routes[0], "attributes"), "as_path"));
    assert_eq!(array(get(&path[0], "values")), &[Json::from(70000u32)]);
    Observation::from_normalized(&value, None, &Limits::default()).unwrap();

    // Byte-distinct valid OPENs remain alternatives even when capabilities are unchanged.
    let mut changed_asn = a.clone();
    changed_asn[33..37].copy_from_slice(&70002u32.to_be_bytes());
    let mut changed_hold_time = a.clone();
    changed_hold_time[23] = 91;
    let mut changed_identifier = a.clone();
    changed_identifier[27] = 9;
    let reordered_capabilities = opened(23456, &[caps[1].clone(), caps[0].clone()]);
    for changed in [
        changed_asn,
        changed_hold_time,
        changed_identifier,
        reordered_capabilities,
    ] {
        let mut conflicting_state = state.clone();
        let conflict = decode(&changed, Some(0), 6, &mut conflicting_state);
        assert_eq!(
            get(get(&conflict, "message_detail"), "ambiguous"),
            &Json::Bool(false)
        );
        assert!(array(get(&conflict, "issues")).contains(&Json::from(
            "repeated_open_requires_explicit_generation_boundary"
        )));
        assert_eq!(
            get(get(&conflict, "producer_context"), "asn_width"),
            &Json::Null
        );
        let later = decode(
            &update(&attrs, &[24, 203, 0, 113]),
            Some(0),
            7,
            &mut conflicting_state,
        );
        let retained_routes = array(get(&later, "routes"));
        assert_eq!(retained_routes.len(), 1);
        assert!(array(get(get(&retained_routes[0], "attributes"), "as_path")).is_empty());
        assert_eq!(
            get(&ranges(&later)[1], "interpretation"),
            &Json::from("unresolved_capability_context")
        );
        let observation = Observation::from_normalized(&later, None, &Limits::default()).unwrap();
        assert_eq!(observation.routes().len(), 1);
        assert!(observation.routes()[0].ambiguous_attributes());
    }
}
