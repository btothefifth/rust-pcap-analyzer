//! Explicit EOR metadata projection is distinct from empty route evidence.
use pcap_evidence::{
    json::Json,
    provenance::{EvidenceBytes, PacketId},
};
use pcap_evidence_product::deep::{
    bgp::{self, PcapMetadata, SessionState},
    bgp_session::Family,
    bgp_state::Observation,
    Limits,
};

fn normalized_update() -> Json {
    let mut raw = vec![255; 16];
    raw.extend_from_slice(&[0, 23, 2, 0, 0, 0, 0]);
    let bytes = EvidenceBytes::from_packet(
        &raw,
        PacketId {
            capture: [7; 32],
            frame: 1,
            record_offset: 20,
        },
        54,
    );
    bgp::decode_pcap(
        &bytes,
        PcapMetadata {
            source_id: "eor-capture".into(),
            record_id: "update-1".into(),
            observed_at_ns: None,
            session: Some(1),
            direction: Some(0),
            peer: None,
            local: None,
        },
        &mut SessionState::default(),
        &Limits::default(),
    )
    .unwrap()
}
fn detail_mut(value: &mut Json) -> &mut Vec<(&'static str, Json)> {
    let Json::Object(root) = value else {
        panic!("root object")
    };
    let Json::Object(detail) = &mut root
        .iter_mut()
        .find(|(name, _)| *name == "message_detail")
        .unwrap()
        .1
    else {
        panic!("detail object")
    };
    detail
}
fn observation(value: &Json) -> Observation {
    Observation::from_normalized(value, None, &Limits::default()).unwrap()
}
#[test]
fn explicit_captured_eor_has_exact_family() {
    let normalized = normalized_update();
    let observation = observation(&normalized);
    assert!(observation.routes().is_empty());
    assert_eq!(
        observation.end_of_rib_families().unwrap(),
        Some(vec![Family { afi: 1, safi: 1 }])
    );
}
#[test]
fn empty_routes_without_eor_metadata_remain_unresolved() {
    let mut normalized = normalized_update();
    detail_mut(&mut normalized).retain(|(name, _)| *name != "end_of_rib");
    let observation = observation(&normalized);
    assert!(observation.routes().is_empty());
    assert_eq!(observation.end_of_rib_families().unwrap(), None);
}
#[test]
fn explicit_empty_eor_projection_is_known_non_eor() {
    let mut normalized = normalized_update();
    detail_mut(&mut normalized)
        .iter_mut()
        .find(|(name, _)| *name == "end_of_rib")
        .unwrap()
        .1 = Json::Array(Vec::new());
    assert_eq!(
        observation(&normalized).end_of_rib_families().unwrap(),
        Some(Vec::new())
    );
}
#[test]
fn malformed_or_zero_family_eor_metadata_is_rejected() {
    for invalid in [
        Json::Null,
        Json::array([Json::object([("afi", 0u16.into()), ("safi", 1u8.into())])]),
        Json::array([Json::object([("afi", 1u16.into()), ("safi", 0u8.into())])]),
    ] {
        let mut normalized = normalized_update();
        detail_mut(&mut normalized)
            .iter_mut()
            .find(|(name, _)| *name == "end_of_rib")
            .unwrap()
            .1 = invalid;
        assert!(observation(&normalized).end_of_rib_families().is_err());
    }
}
