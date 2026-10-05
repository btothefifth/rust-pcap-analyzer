//! Independent, tiny RFC 6793 and semantic-profile vectors. Complete meanings
//! remain source-distinct through the captured and sealed imported consumers.
use pcap_evidence::{
    json::Json,
    provenance::{EvidenceBytes, PacketId},
    sha256,
};
use pcap_evidence_product::deep::{
    bgp::{self, PcapMetadata, PeerRelationship, SessionState},
    bgp_mrt::{MrtLimits, MrtSource},
    bgp_mrt_store,
    bgp_pipeline::CapturedSessionPipeline,
    bgp_state::Observation,
    bgp_store, Limits,
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
            "bgp-semantic-parity-{}-{}",
            std::process::id(),
            SERIAL.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn file(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn field<'a>(value: &'a Json, name: &str) -> &'a Json {
    let Json::Object(fields) = value else {
        panic!("object expected")
    };
    &fields
        .iter()
        .find(|(key, _)| *key == name)
        .unwrap_or_else(|| panic!("missing {name}"))
        .1
}
fn field_mut<'a>(value: &'a mut Json, name: &str) -> &'a mut Json {
    let Json::Object(fields) = value else {
        panic!("object expected")
    };
    &mut fields.iter_mut().find(|(key, _)| *key == name).unwrap().1
}
fn array_mut(value: &mut Json) -> &mut Vec<Json> {
    let Json::Array(values) = value else {
        panic!("array expected")
    };
    values
}
fn refresh_v2_fingerprint(identity: &mut Json) {
    let encoded = field(identity, "canonical_payload").encode();
    let mut preimage = b"pcap-evidence.bgp.semantic-route-identity.v2\0".to_vec();
    preimage.extend((encoded.len() as u64).to_be_bytes());
    preimage.extend(encoded.as_bytes());
    *field_mut(identity, "fingerprint_sha256") =
        Json::from(sha256::hex(&sha256::digest(&preimage)));
}
fn array(value: &Json) -> &[Json] {
    let Json::Array(values) = value else {
        panic!("array expected")
    };
    values
}
fn message(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut bytes = vec![255; 16];
    bytes.extend(u16::try_from(19 + body.len()).unwrap().to_be_bytes());
    bytes.push(kind);
    bytes.extend(body);
    bytes
}
fn attribute(flags: u8, code: u8, value: &[u8]) -> Vec<u8> {
    let mut bytes = vec![flags, code];
    if flags & 0x10 == 0 {
        bytes.push(u8::try_from(value.len()).unwrap());
    } else {
        bytes.extend(u16::try_from(value.len()).unwrap().to_be_bytes());
    }
    bytes.extend(value);
    bytes
}
fn open(asn: u16, as4: bool, identifier: [u8; 4]) -> Vec<u8> {
    let mut body = vec![4];
    body.extend(asn.to_be_bytes());
    body.extend(90u16.to_be_bytes());
    body.extend(identifier);
    if as4 {
        body.extend([8, 2, 6, 65, 4]);
        body.extend(
            if asn == 23456 {
                70000u32
            } else {
                u32::from(asn)
            }
            .to_be_bytes(),
        );
    } else {
        body.push(0);
    }
    message(1, &body)
}
fn update(attributes: &[u8]) -> Vec<u8> {
    let mut body = vec![0, 0];
    body.extend(u16::try_from(attributes.len()).unwrap().to_be_bytes());
    body.extend(attributes);
    body.extend([24, 203, 0, 113]);
    message(2, &body)
}
fn ordinary_attributes() -> Vec<u8> {
    [
        attribute(0x40, 1, &[0]),
        attribute(0x40, 2, &[2, 1, 0xfd, 0xe8]),
        attribute(0x40, 3, &[192, 0, 2, 9]),
    ]
    .concat()
}
fn transition_attributes() -> Vec<u8> {
    [
        attribute(0x40, 1, &[0]),
        attribute(0x40, 2, &[2, 3, 0xfd, 0xe8, 0x5b, 0xa0, 0xfc, 0x00]),
        attribute(0x40, 3, &[192, 0, 2, 9]),
        attribute(0xc0, 17, &[2, 2, 0, 1, 0x11, 0x70, 0, 0, 0xfc, 0]),
        attribute(0xc0, 7, &[0x5b, 0xa0, 192, 0, 2, 7]),
        attribute(0xc0, 18, &[0, 1, 0x11, 0x70, 192, 0, 2, 7]),
        attribute(0x40, 6, &[]),
    ]
    .concat()
}
fn native_attributes() -> Vec<u8> {
    // Independent four-octet representation of 65000 ; 70000,64512.
    [
        attribute(0x40, 6, &[]),
        attribute(0xd0, 7, &[0, 1, 0x11, 0x70, 192, 0, 2, 7]),
        attribute(0x50, 3, &[192, 0, 2, 9]),
        attribute(
            0x50,
            2,
            &[
                2, 1, 0, 0, 0xfd, 0xe8, 2, 2, 0, 1, 0x11, 0x70, 0, 0, 0xfc, 0,
            ],
        ),
        attribute(0x50, 1, &[0]),
    ]
    .concat()
}
fn evidence(bytes: &[u8], frame: u64) -> EvidenceBytes {
    EvidenceBytes::from_packet(
        bytes,
        PacketId {
            capture: sha256::digest(b"semantic-capture"),
            frame,
            record_offset: 100 * frame,
        },
        54,
    )
}
fn metadata(frame: u64, direction: u8) -> PcapMetadata {
    PcapMetadata {
        source_id: "semantic-capture".into(),
        record_id: format!("capture-{frame}"),
        observed_at_ns: Some(900 - frame as i64),
        session: Some(17),
        direction: Some(direction),
        peer: Some(format!("peer-{direction}")),
        local: Some("capture-local".into()),
    }
}
// These identity tests require admitted internal announcements. Supply their
// common LOCAL_PREF prerequisite without duplicating the attribute when its
// value is the semantic variable under test. Keep Unknown-source parity vectors
// unchanged; they do not carry this explicitly configured internal relationship.
fn internal_attributes(attributes: &[u8]) -> Vec<u8> {
    let mut at = 0;
    while at < attributes.len() {
        let flags = attributes[at];
        let code = attributes[at + 1];
        let (header, length) = if flags & 0x10 == 0 {
            (3, usize::from(attributes[at + 2]))
        } else {
            (
                4,
                usize::from(u16::from_be_bytes([attributes[at + 2], attributes[at + 3]])),
            )
        };
        if code == 5 {
            return attributes.to_vec();
        }
        at += header + length;
        assert!(
            at <= attributes.len(),
            "fixture attribute envelope is complete"
        );
    }
    [attribute(0x40, 5, &[0, 0, 0, 100]), attributes.to_vec()].concat()
}

fn decode_with(attributes: &[u8], four: bool, relationship: PeerRelationship) -> Json {
    let mut state = SessionState::default();
    state.set_peer_relationship(relationship);
    for (frame, direction) in [(1, 0), (2, 1)] {
        let bytes = open(65000 + direction as u16, four, [192, 0, 2, 1 + direction]);
        bgp::decode_pcap(
            &evidence(&bytes, frame),
            metadata(frame, direction),
            &mut state,
            &Limits::default(),
        )
        .unwrap();
    }
    let attributes = if relationship == PeerRelationship::Internal {
        internal_attributes(attributes)
    } else {
        attributes.to_vec()
    };
    let bytes = update(&attributes);
    bgp::decode_pcap(
        &evidence(&bytes, 3),
        metadata(3, 0),
        &mut state,
        &Limits::default(),
    )
    .unwrap()
}
fn route(value: &Json) -> &Json {
    let routes = array(field(value, "routes"));
    assert_eq!(
        routes.len(),
        1,
        "semantic fixture must reach route admission: {}",
        field(value, "message_detail").encode()
    );
    &routes[0]
}
fn identity(value: &Json) -> &Json {
    field(route(value), "semantic_identity")
}
fn fingerprint(value: &Json) -> &Json {
    field(identity(value), "fingerprint_sha256")
}
fn mrt_record(subtype: u16, seconds: u32, body: &[u8]) -> Vec<u8> {
    let mut out = seconds.to_be_bytes().to_vec();
    out.extend(16u16.to_be_bytes());
    out.extend(subtype.to_be_bytes());
    out.extend(u32::try_from(body.len()).unwrap().to_be_bytes());
    out.extend(body);
    out
}
fn mrt_body(four: bool) -> Vec<u8> {
    let mut body = Vec::new();
    if four {
        body.extend(65000u32.to_be_bytes());
        body.extend(65001u32.to_be_bytes());
    } else {
        body.extend(65000u16.to_be_bytes());
        body.extend(65001u16.to_be_bytes());
    }
    body.extend([0, 7, 0, 1, 198, 51, 100, 1, 198, 51, 100, 2]);
    body
}
fn mrt_state(old: u16, new: u16, seconds: u32, four: bool) -> Vec<u8> {
    let mut body = mrt_body(four);
    body.extend(old.to_be_bytes());
    body.extend(new.to_be_bytes());
    mrt_record(if four { 5 } else { 0 }, seconds, &body)
}
fn mrt_message(bytes: &[u8], local: bool, seconds: u32, four: bool) -> Vec<u8> {
    let mut body = mrt_body(four);
    body.extend(bytes);
    mrt_record(
        match (four, local) {
            (true, true) => 7,
            (true, false) => 4,
            (false, true) => 6,
            (false, false) => 1,
        },
        seconds,
        &body,
    )
}
fn mrt_flow(update: &[u8], four: bool) -> Vec<u8> {
    [
        mrt_state(3, 4, 300, four),
        mrt_message(&open(65000, four, [198, 51, 100, 1]), false, 250, four),
        mrt_message(&open(65001, four, [198, 51, 100, 2]), true, 200, four),
        mrt_state(4, 5, 150, four),
        mrt_state(5, 6, 100, four),
        mrt_message(update, false, 30, four),
    ]
    .concat()
}

#[test]
fn as4_transition_and_native_bgp4mp_match_through_real_consumers_without_source_collapse() {
    let scratch = Scratch::new();
    let limits = Limits::default();
    let capture_namespace = sha256::digest(b"semantic-capture");
    let mut pipeline = CapturedSessionPipeline::new(
        capture_namespace,
        "semantic-capture".into(),
        17,
        limits.clone(),
    )
    .unwrap();
    let mut journal = bgp_store::JournalWriter::create(
        &scratch.file("capture.bgp"),
        "semantic-capture".into(),
        capture_namespace,
        1_000_000,
        limits.clone(),
    )
    .unwrap();
    let messages = [
        open(65000, false, [192, 0, 2, 1]),
        open(23456, true, [192, 0, 2, 2]),
        update(&transition_attributes()),
    ];
    let mut captured = Json::Null;
    for (index, bytes) in messages.iter().enumerate() {
        let frame = index as u64 + 1;
        let direction = if index == 1 { 1 } else { 0 };
        let raw = evidence(bytes, frame);
        let meta = metadata(frame, direction);
        journal.message(17, &raw, &meta).unwrap();
        captured = pipeline.apply_message(&raw, meta).unwrap().normalized;
    }
    journal.seal().unwrap();
    assert_eq!(
        field(identity(&captured), "completeness"),
        &Json::from("complete")
    );
    assert_eq!(
        field(
            field(
                field(identity(&captured), "canonical_payload"),
                "attributes"
            ),
            "atomic_aggregate"
        ),
        &Json::Bool(true)
    );
    assert_eq!(pipeline.rib().entries().len(), 1);
    let replayed_capture =
        bgp_store::replay(&scratch.file("capture.bgp"), 1_000_000, limits.clone()).unwrap();
    assert_eq!(replayed_capture.messages, 3);
    assert_eq!(replayed_capture.rejected_records, 0);
    assert_eq!(replayed_capture.sessions[0].summary.active_routes, 1);
    let bytes = mrt_flow(&update(&native_attributes()), true);
    let source = MrtSource {
        source_id: "independent-collector".into(),
        checkpoint_id: "parity-1".into(),
    };
    let imported = bgp_mrt_store::create(
        &scratch.file("collector.mrt"),
        &bytes,
        source,
        1_000_000,
        MrtLimits::default(),
        limits.clone(),
    )
    .unwrap();
    assert_eq!(imported.bgp4mp_candidates.len(), 1);
    let observation = imported
        .bgp4mp_candidate_observation(&imported.bgp4mp_candidates[0])
        .unwrap();
    assert_eq!(
        field(
            observation.routes()[0].semantic_identity(),
            "fingerprint_sha256"
        ),
        fingerprint(&captured)
    );
    assert_eq!(observation.source().kind, bgp::SourceKind::Imported);
    assert_ne!(observation.source().source_id, "semantic-capture");
    assert_ne!(
        field(observation.normalized(), "evidence"),
        field(&captured, "evidence")
    );
    assert_eq!(
        field(observation.normalized(), "endpoint_state_established"),
        &Json::Bool(false)
    );
    let fresh = bgp_mrt_store::replay(
        &scratch.file("collector.mrt"),
        1_000_000,
        MrtLimits::default(),
        limits,
    )
    .unwrap();
    let fresh_observation = fresh
        .bgp4mp_candidate_observation(&fresh.bgp4mp_candidates[0])
        .unwrap();
    assert_eq!(
        fresh_observation.routes()[0].semantic_identity(),
        observation.routes()[0].semantic_identity()
    );
    let mut forged = observation.normalized().clone();
    let route = &mut array_mut(field_mut(&mut forged, "routes"))[0];
    *field_mut(field_mut(route, "attributes"), "origin") = Json::from(1u8);
    let occurrences = array_mut(field_mut(
        field_mut(route, "imported_attribute_occurrences"),
        "occurrences",
    ));
    // Native ORIGIN is last in the independently reordered wire inventory.
    *field_mut(occurrences.last_mut().unwrap(), "decoded") = Json::from(1u8);
    let identity = field_mut(route, "semantic_identity");
    *field_mut(
        field_mut(field_mut(identity, "canonical_payload"), "attributes"),
        "origin",
    ) = Json::from(1u8);
    refresh_v2_fingerprint(identity);
    let error = Observation::from_normalized(&forged, None, &Limits::default()).unwrap_err();
    assert_eq!(error.field, "bgp_state_semantic_identity");
    assert!(error.detail.contains("raw scalar or collection projection"));
    let mut forged_flags = observation.normalized().clone();
    let route = &mut array_mut(field_mut(&mut forged_flags, "routes"))[0];
    let occurrences = array_mut(field_mut(
        field_mut(route, "imported_attribute_occurrences"),
        "occurrences",
    ));
    let origin = occurrences.last_mut().unwrap();
    assert_eq!(field(origin, "type"), &Json::from(1u8));
    assert_eq!(field(origin, "flags"), &Json::from(0x50u8));
    assert_eq!(field(origin, "value_hex"), &Json::from("00"));
    assert_eq!(
        field(field(origin, "validation"), "flags_valid"),
        &Json::Bool(true)
    );
    // The donor's validation label cannot override the source flag octet.
    // Preserve the extended-length bit so this reaches flag-class admission
    // rather than the earlier header-width consistency guard.
    *field_mut(origin, "flags") = Json::from(0x10u8);
    let error = Observation::from_normalized(&forged_flags, None, &Limits::default()).unwrap_err();
    assert_eq!(error.field, "bgp_state_semantic_identity", "{error:?}");
    assert!(
        error.detail.contains("imported message closure digest"),
        "{error:?}"
    );
    let mut captured_flags = captured;
    let route = &mut array_mut(field_mut(&mut captured_flags, "routes"))[0];
    let atomic = array_mut(field_mut(route, "attribute_ranges"))
        .iter_mut()
        .find(|occurrence| field(occurrence, "type") == &Json::from(6u8))
        .unwrap();
    assert_eq!(
        field(field(atomic, "validation"), "flags_valid"),
        &Json::Bool(true)
    );
    *field_mut(atomic, "flags") = Json::from(0u8);
    let error =
        Observation::from_normalized(&captured_flags, None, &Limits::default()).unwrap_err();
    assert_eq!(error.field, "bgp_state_semantic_identity", "{error:?}");
    assert!(
        error
            .detail
            .contains("incomplete occurrence in complete identity"),
        "{error:?}"
    );
}

#[test]
fn imported_message_closure_rejects_omitted_attributes_and_forged_boundaries() {
    let scratch = Scratch::new();
    let create = |name: &str, attributes: &[u8]| {
        bgp_mrt_store::create(
            &scratch.file(name),
            &mrt_flow(&update(attributes), true),
            MrtSource {
                source_id: "closure-source".into(),
                checkpoint_id: name.into(),
            },
            1_000_000,
            MrtLimits::default(),
            Limits::default(),
        )
        .unwrap()
    };
    let control = create("control.mrt", &native_attributes());
    let control_normalized = control
        .state
        .observations()
        .iter()
        .find(|observation| !observation.routes().is_empty())
        .unwrap()
        .normalized();
    Observation::from_normalized(control_normalized, None, &Limits::default()).unwrap();
    let complete_identity = identity(control_normalized).clone();
    for middle in [false, true] {
        let mut attributes = native_attributes();
        let unknown = attribute(0xc0, 99, &[1, 2, 3]);
        if middle {
            attributes.splice(3..3, unknown);
        } else {
            attributes.extend(unknown);
        }
        let archive = create(if middle { "middle.mrt" } else { "tail.mrt" }, &attributes);
        let normalized = archive
            .state
            .observations()
            .iter()
            .find(|observation| !observation.routes().is_empty())
            .unwrap()
            .normalized();
        assert_eq!(fingerprint(normalized), &Json::Null);
        Observation::from_normalized(normalized, None, &Limits::default()).unwrap();
        for empty in [false, true] {
            let mut omitted = normalized.clone();
            let route = &mut array_mut(field_mut(&mut omitted, "routes"))[0];
            *field_mut(route, "semantic_identity") = complete_identity.clone();
            let occurrences = array_mut(field_mut(
                field_mut(route, "imported_attribute_occurrences"),
                "occurrences",
            ));
            occurrences
                .retain(|occurrence| !empty && field(occurrence, "type") != &Json::from(99u8));
            let error =
                Observation::from_normalized(&omitted, None, &Limits::default()).unwrap_err();
            assert_eq!(error.field, "bgp_state_semantic_identity", "{error:?}");
            assert!(
                error
                    .detail
                    .contains("imported message closure inventory length"),
                "{error:?}"
            );
        }
    }
    for mutation in 0..3 {
        let mut forged = control_normalized.clone();
        let route = &mut array_mut(field_mut(&mut forged, "routes"))[0];
        let inventory = field_mut(route, "imported_attribute_occurrences");
        let expected = match mutation {
            0 => {
                let Json::String(prefix) = field_mut(inventory, "message_prefix_hex") else {
                    unreachable!()
                };
                prefix.truncate(prefix.len() - 2);
                prefix.push_str("00");
                "imported message closure declared attribute extent"
            }
            1 => {
                let Json::String(prefix) = field_mut(inventory, "message_prefix_hex") else {
                    unreachable!()
                };
                let moved = prefix.split_off(prefix.len() - 2);
                let Json::String(suffix) = field_mut(inventory, "message_suffix_hex") else {
                    unreachable!()
                };
                suffix.insert_str(0, &moved);
                "imported message closure UPDATE header"
            }
            _ => {
                let Json::String(suffix) = field_mut(inventory, "message_suffix_hex") else {
                    unreachable!()
                };
                suffix.replace_range(0..2, "19");
                "imported message closure digest"
            }
        };
        let error = Observation::from_normalized(&forged, None, &Limits::default()).unwrap_err();
        assert_eq!(error.field, "bgp_state_semantic_identity", "{error:?}");
        assert!(error.detail.contains(expected), "{error:?}");
    }
    let mut legacy_carrier = control_normalized.clone();
    let route = &mut array_mut(field_mut(&mut legacy_carrier, "routes"))[0];
    let Json::Object(fields) = field_mut(route, "imported_attribute_occurrences") else {
        unreachable!()
    };
    fields.retain(|(name, _)| !matches!(*name, "message_prefix_hex" | "message_suffix_hex"));
    let error =
        Observation::from_normalized(&legacy_carrier, None, &Limits::default()).unwrap_err();
    assert!(
        error
            .detail
            .contains("complete imported identity needs message closure"),
        "{error:?}"
    );
    let mut absent_carrier = control_normalized.clone();
    let route = &mut array_mut(field_mut(&mut absent_carrier, "routes"))[0];
    let Json::Object(fields) = route else {
        unreachable!()
    };
    fields.retain(|(name, _)| *name != "imported_attribute_occurrences");
    let error =
        Observation::from_normalized(&absent_carrier, None, &Limits::default()).unwrap_err();
    assert!(
        error
            .detail
            .contains("complete imported wire identity needs occurrence inventory"),
        "{error:?}"
    );
}

#[test]
fn every_complete_scalar_or_set_profile_attribute_changes_meaning_when_its_value_changes() {
    let baseline = decode_with(&ordinary_attributes(), false, PeerRelationship::Internal);
    let vectors = [
        (4, 0x80, vec![0, 0, 0, 9]),
        (5, 0x40, vec![0, 0, 0, 200]),
        (6, 0x40, vec![]),
        (7, 0xc0, vec![0xfd, 0xe8, 192, 0, 2, 7]),
        (8, 0xc0, vec![0xfd, 0xe8, 0, 7]),
        (9, 0x80, vec![192, 0, 2, 8]),
        (10, 0x80, vec![192, 0, 2, 8]),
        (32, 0xc0, vec![0, 1, 0x11, 0x70, 0, 0, 0, 1, 0, 0, 0, 2]),
    ];
    for (code, flags, value) in vectors {
        let mut attributes = ordinary_attributes();
        attributes.extend(attribute(flags, code, &value));
        let decoded = decode_with(&attributes, false, PeerRelationship::Internal);
        assert_eq!(
            field(identity(&decoded), "completeness"),
            &Json::from("complete"),
            "type {code}"
        );
        assert_ne!(fingerprint(&decoded), fingerprint(&baseline), "type {code}");
        assert!(
            !Observation::from_normalized(&decoded, None, &Limits::default())
                .unwrap()
                .routes()[0]
                .ambiguous_attributes()
        );
    }
    for (code, flags, value) in [
        (16, 0xc0, vec![0; 8]),
        (26, 0x80, vec![1, 0, 11, 0, 0, 0, 0, 0, 0, 0, 1]),
        (35, 0xc0, vec![0, 0, 0, 1]),
        (99, 0xc0, vec![1]),
    ] {
        let mut attributes = ordinary_attributes();
        attributes.extend(attribute(flags, code, &value));
        let decoded = decode_with(&attributes, false, PeerRelationship::Internal);
        assert_eq!(
            fingerprint(&decoded),
            &Json::Null,
            "structural-only or unknown type {code}"
        );
    }
}

#[test]
fn partial_unresolved_and_malformed_transition_neighbors_never_acquire_fingerprints() {
    for attr in [
        attribute(0xe0, 17, &[2, 1, 0, 1, 0x11, 0x70]),
        attribute(0xc0, 17, &[2, 0]),
        attribute(0xc0, 18, &[0; 7]),
        attribute(0xe0, 8, &[0, 1, 0, 1]),
    ] {
        let mut attributes = ordinary_attributes();
        attributes.extend(attr);
        let value = decode_with(&attributes, false, PeerRelationship::Internal);
        assert_eq!(fingerprint(&value), &Json::Null);
        assert!(
            Observation::from_normalized(&value, None, &Limits::default())
                .unwrap()
                .routes()[0]
                .ambiguous_attributes()
        );
    }
    let bytes = update(&ordinary_attributes());
    let mut state = SessionState::default();
    let value = bgp::decode_pcap(
        &evidence(&bytes, 3),
        metadata(3, 0),
        &mut state,
        &Limits::default(),
    )
    .unwrap();
    assert_eq!(
        fingerprint(&value),
        &Json::Null,
        "unique wire shape cannot prove a resolved ASN layout"
    );
}

#[test]
fn aggregator_resolution_is_independent_of_missing_mandatory_as_path() {
    let attributes = [
        attribute(0x40, 1, &[0]),
        attribute(0x40, 3, &[192, 0, 2, 9]),
        attribute(0xc0, 7, &[0x5b, 0xa0, 192, 0, 2, 7]),
        attribute(0xc0, 18, &[0, 1, 0x11, 0x70, 192, 0, 2, 8]),
    ]
    .concat();
    let value = decode_with(&attributes, false, PeerRelationship::Internal);
    let reconstruction = field(field(&value, "message_detail"), "as4_reconstruction");
    assert_eq!(
        field(reconstruction, "effective_aggregator"),
        &Json::from("70000:192.0.2.8")
    );
    assert_eq!(fingerprint(&value), &Json::Null);
}

#[test]
fn set_order_duplicates_and_encoding_lengths_preserve_semantics_and_source_occurrences() {
    let left = [
        ordinary_attributes(),
        attribute(0xc0, 8, &[0xfd, 0xe8, 0, 2, 0xfd, 0xe8, 0, 1]),
        attribute(0xc0, 32, &[0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3]),
    ]
    .concat();
    let right = [
        ordinary_attributes(),
        attribute(
            0xd0,
            32,
            &[
                0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3,
            ],
        ),
        attribute(
            0xd0,
            8,
            &[0xfd, 0xe8, 0, 1, 0xfd, 0xe8, 0, 2, 0xfd, 0xe8, 0, 1],
        ),
        attribute(0, 8, &[1]),
    ]
    .concat();
    let left = decode_with(&left, false, PeerRelationship::Internal);
    let right = decode_with(&right, false, PeerRelationship::Internal);
    assert_eq!(fingerprint(&left), fingerprint(&right));
    assert_ne!(
        field(route(&left), "attribute_ranges"),
        field(route(&right), "attribute_ranges")
    );
    assert_eq!(array(field(route(&right), "attribute_ranges")).len(), 7);
    assert_eq!(
        field(
            array(field(route(&right), "attribute_ranges"))
                .last()
                .unwrap(),
            "disposition"
        ),
        &Json::from("discard_later_occurrence")
    );
    Observation::from_normalized(&right, None, &Limits::default()).unwrap();
}

#[test]
fn core_origin_path_and_next_hop_have_distinct_meanings() {
    let baseline = decode_with(&ordinary_attributes(), false, PeerRelationship::Internal);
    for attributes in [
        [
            attribute(0x40, 1, &[1]),
            attribute(0x40, 2, &[2, 1, 0xfd, 0xe8]),
            attribute(0x40, 3, &[192, 0, 2, 9]),
        ]
        .concat(),
        [
            attribute(0x40, 1, &[0]),
            attribute(0x40, 2, &[2, 1, 0xfd, 0xe9]),
            attribute(0x40, 3, &[192, 0, 2, 9]),
        ]
        .concat(),
        [
            attribute(0x40, 1, &[0]),
            attribute(0x40, 2, &[2, 1, 0xfd, 0xe8]),
            attribute(0x40, 3, &[192, 0, 2, 10]),
        ]
        .concat(),
    ] {
        assert_ne!(
            fingerprint(&decode_with(&attributes, false, PeerRelationship::Internal)),
            fingerprint(&baseline)
        );
    }
}

#[test]
fn complete_identity_must_match_source_reconstruction_even_after_fingerprint_is_rebuilt() {
    let value = decode_with(&transition_attributes(), false, PeerRelationship::Internal);
    Observation::from_normalized(&value, None, &Limits::default()).unwrap();
    let mut rebuilt = value.clone();
    let Json::Object(root) = &mut rebuilt else {
        unreachable!()
    };
    let Json::Array(routes) = &mut root.iter_mut().find(|(key, _)| *key == "routes").unwrap().1
    else {
        unreachable!()
    };
    let Json::Object(route) = &mut routes[0] else {
        unreachable!()
    };
    let Json::Object(attributes) = &mut route
        .iter_mut()
        .find(|(key, _)| *key == "attributes")
        .unwrap()
        .1
    else {
        unreachable!()
    };
    attributes
        .iter_mut()
        .find(|(key, _)| *key == "aggregator")
        .unwrap()
        .1 = Json::from("70001:192.0.2.7");
    let Json::Object(identity) = &mut route
        .iter_mut()
        .find(|(key, _)| *key == "semantic_identity")
        .unwrap()
        .1
    else {
        unreachable!()
    };
    let payload = &mut identity
        .iter_mut()
        .find(|(key, _)| *key == "canonical_payload")
        .unwrap()
        .1;
    let Json::Object(payload_fields) = payload else {
        unreachable!()
    };
    let Json::Object(attributes) = &mut payload_fields
        .iter_mut()
        .find(|(key, _)| *key == "attributes")
        .unwrap()
        .1
    else {
        unreachable!()
    };
    attributes
        .iter_mut()
        .find(|(key, _)| *key == "aggregator")
        .unwrap()
        .1 = Json::from("70001:192.0.2.7");
    let encoded = payload.encode();
    let mut preimage = b"pcap-evidence.bgp.semantic-route-identity.v2\0".to_vec();
    preimage.extend((encoded.len() as u64).to_be_bytes());
    preimage.extend(encoded.as_bytes());
    identity
        .iter_mut()
        .find(|(key, _)| *key == "fingerprint_sha256")
        .unwrap()
        .1 = Json::from(sha256::hex(&sha256::digest(&preimage)));
    let error = Observation::from_normalized(&rebuilt, None, &Limits::default()).unwrap_err();
    assert_eq!(error.field, "bgp_state_semantic_identity");
    assert!(error.detail.contains("AGGREGATOR source projection"));
    let mut relabeled = value;
    let route = &mut array_mut(field_mut(&mut relabeled, "routes"))[0];
    *field_mut(field_mut(route, "attributes"), "aggregator") = Json::from("23456:192.0.2.7");
    let occurrences = array_mut(field_mut(route, "attribute_ranges"));
    let as4_aggregator = occurrences
        .iter_mut()
        .find(|occurrence| field(occurrence, "type") == &Json::from(18u8))
        .unwrap();
    *field_mut(as4_aggregator, "disposition") = Json::from("attribute_discard");
    let identity = field_mut(route, "semantic_identity");
    *field_mut(
        field_mut(field_mut(identity, "canonical_payload"), "attributes"),
        "aggregator",
    ) = Json::from("23456:192.0.2.7");
    refresh_v2_fingerprint(identity);
    let error = Observation::from_normalized(&relabeled, None, &Limits::default()).unwrap_err();
    assert_eq!(error.field, "bgp_state_semantic_identity", "{error:?}");
    assert!(
        error
            .detail
            .contains("AS4 discard category source projection"),
        "{error:?}"
    );
}

#[test]
fn as4_discard_boundaries_are_complete_and_later_duplicates_keep_their_own_disposition() {
    let longer = attribute(0xc0, 17, &[2, 2, 0, 1, 0x11, 0x70, 0, 1, 0x38, 0x80]);
    let mut attributes = ordinary_attributes();
    attributes.extend(&longer);
    attributes.extend(attribute(0, 17, &[2, 0]));
    let decoded = decode_with(&attributes, false, PeerRelationship::Internal);
    assert_eq!(
        field(identity(&decoded), "completeness"),
        &Json::from("complete")
    );
    assert_eq!(
        fingerprint(&decoded),
        fingerprint(&decode_with(
            &ordinary_attributes(),
            false,
            PeerRelationship::Internal
        ))
    );
    let ranges: Vec<_> = array(field(route(&decoded), "attribute_ranges"))
        .iter()
        .filter(|range| field(range, "type") == &Json::from(17u8))
        .collect();
    assert_eq!(ranges.len(), 2);
    assert_eq!(
        field(ranges[0], "disposition"),
        &Json::from("attribute_discard")
    );
    assert_eq!(
        field(ranges[1], "disposition"),
        &Json::from("discard_later_occurrence")
    );
    Observation::from_normalized(&decoded, None, &Limits::default()).unwrap();
    // A valid NEW/NEW transition occurrence is explicitly discarded and cannot
    // change a native four-octet path or its independently retained inventory.
    let mut attributes = native_attributes();
    attributes.extend(attribute(0xc0, 17, &[2, 1, 0, 1, 0x38, 0x80]));
    let decoded = decode_with(&attributes, true, PeerRelationship::Internal);
    assert_eq!(
        fingerprint(&decoded),
        fingerprint(&decode_with(
            &native_attributes(),
            true,
            PeerRelationship::Internal
        ))
    );
    Observation::from_normalized(&decoded, None, &Limits::default()).unwrap();
}

fn downgrade_test_identity(value: &mut Json) {
    let Json::Object(root) = value else {
        unreachable!()
    };
    let Json::Array(routes) = &mut root.iter_mut().find(|(key, _)| *key == "routes").unwrap().1
    else {
        unreachable!()
    };
    let Json::Object(route) = &mut routes[0] else {
        unreachable!()
    };
    let Json::Object(identity) = &mut route
        .iter_mut()
        .find(|(key, _)| *key == "semantic_identity")
        .unwrap()
        .1
    else {
        unreachable!()
    };
    identity
        .iter_mut()
        .find(|(key, _)| *key == "schema")
        .unwrap()
        .1 = Json::from(bgp::LEGACY_SEMANTIC_IDENTITY_SCHEMA);
    let payload = &mut identity
        .iter_mut()
        .find(|(key, _)| *key == "canonical_payload")
        .unwrap()
        .1;
    let Json::Object(payload_fields) = payload else {
        unreachable!()
    };
    let Json::Object(attributes) = &mut payload_fields
        .iter_mut()
        .find(|(key, _)| *key == "attributes")
        .unwrap()
        .1
    else {
        unreachable!()
    };
    attributes.retain(|(key, _)| *key != "atomic_aggregate");
    let encoded = payload.encode();
    let mut preimage = b"pcap-evidence.bgp.semantic-route-identity.v1\0".to_vec();
    preimage.extend((encoded.len() as u64).to_be_bytes());
    preimage.extend(encoded.as_bytes());
    identity
        .iter_mut()
        .find(|(key, _)| *key == "fingerprint_sha256")
        .unwrap()
        .1 = Json::from(sha256::hex(&sha256::digest(&preimage)));
}

#[test]
fn legacy_v1_acceptance_cannot_erase_v2_atomic_or_transition_semantics() {
    let mut old_subset = decode_with(&ordinary_attributes(), false, PeerRelationship::Internal);
    downgrade_test_identity(&mut old_subset);
    Observation::from_normalized(&old_subset, None, &Limits::default()).unwrap();
    for attributes in [
        transition_attributes(),
        [ordinary_attributes(), attribute(0x40, 6, &[])].concat(),
    ] {
        let mut erased = decode_with(&attributes, false, PeerRelationship::Internal);
        downgrade_test_identity(&mut erased);
        let error = Observation::from_normalized(&erased, None, &Limits::default()).unwrap_err();
        assert_eq!(error.field, "bgp_state_semantic_identity");
        assert!(error.detail.contains("legacy identity omits"));
    }
}
