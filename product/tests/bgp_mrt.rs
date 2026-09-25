use pcap_evidence::{
    json::Json,
    provenance::{EvidenceBytes, PacketId},
    sha256,
};
use pcap_evidence_product::deep::bgp_mrt::{
    AsnWidthSource, Bgp4mpPayload, MrtBatch, MrtBody, MrtLimits, MrtSource,
};
use pcap_evidence_product::deep::{
    bgp::{self, PcapMetadata, SessionState},
    bgp_state::{CandidateState, Observation},
    Limits,
};

fn record(seconds: u32, kind: u16, subtype: u16, body: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend(seconds.to_be_bytes());
    v.extend(kind.to_be_bytes());
    v.extend(subtype.to_be_bytes());
    v.extend((body.len() as u32).to_be_bytes());
    v.extend(body);
    v
}
fn source() -> MrtSource {
    MrtSource {
        source_id: "collector-a".into(),
        checkpoint_id: "dump-7".into(),
    }
}
fn parse(bytes: &[u8]) -> MrtBatch {
    MrtBatch::parse(bytes, source(), &MrtLimits::default()).unwrap()
}
fn table() -> Vec<u8> {
    let mut b = vec![
        192, 0, 2, 1, 0, 1, b'v', 0, 1, 2, 192, 0, 2, 2, 203, 0, 113, 9,
    ];
    b.extend(65551u32.to_be_bytes());
    record(11, 13, 1, &b)
}
fn table_two() -> Vec<u8> {
    let first = table();
    let mut body = first[12..].to_vec();
    body[7..9].copy_from_slice(&2u16.to_be_bytes());
    body.extend([2, 192, 0, 2, 3, 203, 0, 113, 10]);
    body.extend(65552u32.to_be_bytes());
    record(11, 13, 1, &body)
}
fn attrs() -> Vec<u8> {
    let mut a = vec![0x40, 1, 1, 0, 0x40, 2, 6, 2, 1];
    a.extend(65551u32.to_be_bytes());
    a.extend([0x40, 3, 4, 192, 0, 2, 9]);
    a
}
fn rib_v4() -> Vec<u8> {
    rib_v4_with_attributes(&attrs())
}
fn rib_v4_with_attributes(a: &[u8]) -> Vec<u8> {
    let mut b = vec![0, 0, 0, 7, 8, 10, 0, 1, 0, 0];
    b.extend(10u32.to_be_bytes());
    b.extend((a.len() as u16).to_be_bytes());
    b.extend(a);
    record(12, 13, 2, &b)
}
fn rib_two() -> Vec<u8> {
    let a = attrs();
    let mut b = vec![0, 0, 0, 7, 16, 10, 1, 0, 2];
    for peer in 0..2u16 {
        b.extend(peer.to_be_bytes());
        b.extend(10u32.to_be_bytes());
        b.extend((a.len() as u16).to_be_bytes());
        b.extend(&a);
    }
    record(12, 13, 2, &b)
}
fn rib_v6_generic() -> Vec<u8> {
    let mut b = vec![0, 0, 0, 8, 0, 2, 1, 32, 0x20, 0x01, 0x0d, 0xb8, 0, 1, 0, 0];
    b.extend(10u32.to_be_bytes());
    b.extend(0u16.to_be_bytes());
    record(13, 13, 6, &b)
}
fn bgp_message() -> Vec<u8> {
    let mut b = vec![0xff; 16];
    b.extend(19u16.to_be_bytes());
    b.push(4);
    b
}
fn bgp4mp(subtype: u16, et: bool, state: bool) -> Vec<u8> {
    let mut b = Vec::new();
    if et {
        b.extend(345_678u32.to_be_bytes());
    }
    if subtype == 0 || subtype == 1 || subtype == 6 || subtype == 8 || subtype == 10 {
        b.extend(64512u16.to_be_bytes());
        b.extend(64513u16.to_be_bytes());
    } else {
        b.extend(65551u32.to_be_bytes());
        b.extend(65552u32.to_be_bytes());
    }
    b.extend(2u16.to_be_bytes());
    b.extend(1u16.to_be_bytes());
    b.extend([203, 0, 113, 9, 192, 0, 2, 1]);
    if state {
        b.extend([0, 1, 0, 6]);
    } else {
        b.extend(bgp_message());
    }
    record(21, if et { 17 } else { 16 }, subtype, &b)
}
fn bgp4mp_v6_state() -> Vec<u8> {
    let mut body = Vec::new();
    body.extend(65551u32.to_be_bytes());
    body.extend(65552u32.to_be_bytes());
    body.extend(2u16.to_be_bytes());
    body.extend(2u16.to_be_bytes());
    body.extend([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    body.extend([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
    body.extend([0, 1, 0, 6]);
    record(22, 16, 5, &body)
}
fn get<'a>(v: &'a Json, key: &str) -> &'a Json {
    let Json::Object(fields) = v else {
        panic!("object")
    };
    &fields.iter().find(|(k, _)| *k == key).unwrap().1
}

fn get_mut<'a>(v: &'a mut Json, key: &str) -> &'a mut Json {
    let Json::Object(fields) = v else {
        panic!("object")
    };
    &mut fields.iter_mut().find(|(k, _)| *k == key).unwrap().1
}

fn attr(flags: u8, code: u8, value: &[u8]) -> Vec<u8> {
    let mut out = vec![flags, code, u8::try_from(value.len()).unwrap()];
    out.extend(value);
    out
}

fn capture_update(attributes: &[u8]) -> Json {
    let mut body = vec![0, 0];
    body.extend(u16::try_from(attributes.len()).unwrap().to_be_bytes());
    body.extend(attributes);
    body.extend([8, 10]); // 10.0.0.0/8, matching the MRT fixture.
    let mut message = vec![0xff; 16];
    message.extend(u16::try_from(19 + body.len()).unwrap().to_be_bytes());
    message.push(2);
    message.extend(body);
    let packet_id = PacketId {
        capture: sha256::digest(b"semantic-identity-capture-fixture"),
        frame: 37,
        record_offset: 128,
    };
    bgp::decode_pcap(
        &EvidenceBytes::from_packet(&message, packet_id, 54),
        PcapMetadata {
            source_id: "packet-capture-fixture".into(),
            record_id: "capture-update-37".into(),
            observed_at_ns: Some(9_876_543_210),
            session: Some(44),
            direction: Some(0),
            peer: Some("192.0.2.9:179".into()),
            local: Some("192.0.2.1:179".into()),
        },
        &mut SessionState::default(),
        &Limits::default(),
    )
    .unwrap()
}

fn identity(route_envelope: &Json) -> &Json {
    let Json::Array(routes) = get(route_envelope, "routes") else {
        panic!("routes")
    };
    get(routes.first().expect("one route"), "semantic_identity")
}

#[test]
fn peer_rib_and_generic_preserve_identity_and_normalize_only_safe_subset() {
    let t = table();
    let r = rib_v4();
    let g = rib_v6_generic();
    let bytes = [t.clone(), r.clone(), g.clone()].concat();
    let b = parse(&bytes);
    assert_eq!(b.schema, "pcap-evidence.bgp.mrt-adapter.v1");
    assert_eq!(b.byte_length, bytes.len() as u64);
    assert_eq!(
        b.records.iter().map(|r| r.offset).collect::<Vec<_>>(),
        vec![0, t.len() as u64, (t.len() + r.len()) as u64]
    );
    assert_eq!(b.records[1].length, (r.len() - 12) as u32);
    assert_eq!(b.records[1].time.seconds, 12);
    let MrtBody::PeerIndex(p) = &b.records[0].body else {
        panic!("peer table")
    };
    assert_eq!(p.view_name, b"v");
    assert_eq!(p.peers[0].asn, 65551);
    assert_eq!(p.peers[0].asn_width, 4);
    assert_eq!(p.peers[0].asn_width_source, AsnWidthSource::PeerIndexType);
    let MrtBody::Rib(v4) = &b.records[1].body else {
        panic!("v4")
    };
    assert_eq!(v4.peer_table_offset, 0);
    assert_eq!(v4.peer_table_sha256, b.records[0].sha256);
    assert_eq!(v4.sequence, 7);
    assert_eq!(v4.entries[0].attributes, attrs());
    assert_eq!(v4.entries[0].as_path_asn_width, 4);
    assert_eq!(
        v4.entries[0].as_path_asn_width_source,
        AsnWidthSource::TableDumpV2Rib
    );
    let j = b
        .normalize_rib_entry(1, 0, &Limits::default())
        .unwrap()
        .unwrap();
    assert_eq!(get(&j, "source_kind"), &Json::String("imported".into()));
    assert_eq!(get(&j, "direction"), &Json::Null);
    assert_eq!(
        get(&j, "observed_at_ns"),
        &Json::String("10000000000".into())
    );
    assert!(format!("{j:?}").contains(&b.records[0].sha256));
    let MrtBody::Rib(v6) = &b.records[2].body else {
        panic!("generic v6")
    };
    assert_eq!((v6.afi, v6.safi, v6.prefix.length), (2, 1, 32));
    assert_eq!(v6.prefix.address[..4], [0x20, 0x01, 0x0d, 0xb8]);
    let j = b
        .normalize_rib_entry(2, 0, &Limits::default())
        .unwrap()
        .unwrap();
    assert_eq!(get(&j, "source_kind"), &Json::String("imported".into()));
}

#[test]
fn capture_and_mrt_share_semantic_identity_without_merging_evidence_partitions() {
    let large_a = [1u32, 65_000, 7];
    let large_b = [2u32, 65_000, 9];
    let encode_large = |tuples: &[[u32; 3]]| {
        let mut out = Vec::new();
        for tuple in tuples {
            for field in tuple {
                out.extend(field.to_be_bytes());
            }
        }
        out
    };
    let mut mrt_attributes = attrs();
    mrt_attributes.extend(attr(0xc0, 32, &encode_large(&[large_a, large_b])));
    let mut capture_attributes = attr(0xc0, 32, &encode_large(&[large_b, large_a, large_a]));
    capture_attributes.extend(attr(0x40, 3, &[192, 0, 2, 9]));
    let mut as_path = vec![2, 1];
    as_path.extend(65_551u32.to_be_bytes());
    capture_attributes.extend(attr(0x40, 2, &as_path));
    capture_attributes.extend(attr(0x40, 1, &[0]));

    let mrt = parse(&[table(), rib_v4_with_attributes(&mrt_attributes)].concat());
    let imported = mrt
        .normalize_rib_entry(1, 0, &Limits::default())
        .unwrap()
        .unwrap();
    let captured = capture_update(&capture_attributes);
    let imported_identity = identity(&imported);
    let captured_identity = identity(&captured);
    assert_eq!(
        get(imported_identity, "completeness"),
        &Json::from("complete"),
        "MRT identity: {imported_identity:?}"
    );
    assert_eq!(
        get(captured_identity, "completeness"),
        &Json::from("complete")
    );
    assert_eq!(
        get(imported_identity, "fingerprint_sha256"),
        get(captured_identity, "fingerprint_sha256"),
        "source, timestamps, offsets, attribute order, and repeated set values are excluded"
    );
    assert_ne!(
        get(&imported, "source_id"),
        get(&captured, "source_id"),
        "matching semantics never rewrite the source evidence"
    );

    let imported_observation = Observation::from_normalized(&imported, None, &Limits::default())
        .expect("MRT identity validates through the evidence consumer");
    let Json::Array(imported_routes) = get(&imported, "routes") else {
        panic!("routes")
    };
    let imported_attributes = get(
        get(imported_routes.first().expect("one route"), "attributes"),
        "large_communities",
    );
    let Json::Array(imported_large_communities) = imported_attributes else {
        panic!("normalized imported Large Communities projection")
    };
    assert_eq!(imported_large_communities.len(), 2);

    let mut forged = imported.clone();
    let Json::Array(routes) = get_mut(&mut forged, "routes") else {
        panic!("routes")
    };
    let attributes = get_mut(routes.first_mut().expect("one route"), "attributes");
    *get_mut(attributes, "large_communities") = Json::Array(Vec::new());
    assert!(
        Observation::from_normalized(&forged, None, &Limits::default()).is_err(),
        "a self-consistent identity digest cannot override the independent MRT projection"
    );

    let captured_observation = Observation::from_normalized(&captured, None, &Limits::default())
        .expect("capture identity validates through the evidence consumer");
    assert_ne!(
        imported_observation.source().source_id,
        captured_observation.source().source_id
    );
    assert_eq!(
        get(
            imported_observation.routes()[0].semantic_identity(),
            "fingerprint_sha256"
        ),
        get(
            captured_observation.routes()[0].semantic_identity(),
            "fingerprint_sha256"
        )
    );
    let mut state = CandidateState::new(Limits::default()).unwrap();
    state
        .apply_batch(vec![imported_observation, captured_observation])
        .expect("equal semantics are accepted as separate source observations");
    assert_eq!(state.observations().len(), 2);
    assert_ne!(
        state.observations()[0].source().source_id,
        state.observations()[1].source().source_id,
        "source-bound observations remain distinct"
    );
}

#[test]
fn mrt_identity_obeys_flag_duplicate_and_nonempty_set_rules() {
    let baseline = parse(&[table(), rib_v4()].concat());
    let baseline_route = baseline
        .normalize_rib_entry(1, 0, &Limits::default())
        .unwrap()
        .unwrap();

    let mut reserved_attributes = attrs();
    reserved_attributes[0] |= 0x0f;
    let reserved = parse(&[table(), rib_v4_with_attributes(&reserved_attributes)].concat());
    let reserved_route = reserved
        .normalize_rib_entry(1, 0, &Limits::default())
        .unwrap()
        .unwrap();
    assert_eq!(
        get(identity(&baseline_route), "fingerprint_sha256"),
        get(identity(&reserved_route), "fingerprint_sha256"),
        "reserved low flag bits are ignored semantically"
    );

    let mut duplicate_attributes = attrs();
    duplicate_attributes.extend([0x40, 1, 1, 2]);
    let duplicate = parse(&[table(), rib_v4_with_attributes(&duplicate_attributes)].concat());
    let duplicate_route = duplicate
        .normalize_rib_entry(1, 0, &Limits::default())
        .unwrap()
        .unwrap();
    assert_eq!(
        get(identity(&baseline_route), "fingerprint_sha256"),
        get(identity(&duplicate_route), "fingerprint_sha256"),
        "later duplicate ordinary attribute is discarded"
    );

    let mut partial_attributes = attrs();
    partial_attributes.extend([0xe0, 32, 12]);
    partial_attributes.extend([0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3]);
    let partial = parse(&[table(), rib_v4_with_attributes(&partial_attributes)].concat());
    let partial_route = partial
        .normalize_rib_entry(1, 0, &Limits::default())
        .unwrap()
        .unwrap();
    assert_eq!(
        get(identity(&partial_route), "completeness"),
        &Json::from("incomplete")
    );
    assert_eq!(
        get(identity(&partial_route), "fingerprint_sha256"),
        &Json::Null
    );

    for empty_set_attribute in [[0xc0, 8, 0], [0x80, 10, 0]] {
        let mut attributes = attrs();
        attributes.extend(empty_set_attribute);
        let parsed = parse(&[table(), rib_v4_with_attributes(&attributes)].concat());
        assert!(parsed
            .normalize_rib_entry(1, 0, &Limits::default())
            .unwrap()
            .is_none());
    }

    let encode_large = |tuple: [u32; 3]| {
        tuple
            .into_iter()
            .flat_map(u32::to_be_bytes)
            .collect::<Vec<_>>()
    };
    let mut changed_attributes = attrs();
    changed_attributes.extend(attr(0xc0, 32, &encode_large([1, 65_000, 7])));
    let changed = parse(&[table(), rib_v4_with_attributes(&changed_attributes)].concat());
    let changed_route = changed
        .normalize_rib_entry(1, 0, &Limits::default())
        .unwrap()
        .unwrap();
    assert_ne!(
        get(identity(&baseline_route), "fingerprint_sha256"),
        get(identity(&changed_route), "fingerprint_sha256"),
        "a changed Large Community tuple changes semantic identity"
    );

    let mut truncated_attributes = attrs();
    truncated_attributes.extend(attr(0xc0, 32, &[0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0]));
    let truncated = parse(&[table(), rib_v4_with_attributes(&truncated_attributes)].concat());
    assert!(truncated
        .normalize_rib_entry(1, 0, &Limits::default())
        .unwrap()
        .is_none());
}
#[test]
fn identical_route_bytes_from_distinct_collectors_keep_distinct_partitions() {
    let bytes = [table(), rib_v4()].concat();
    let a = parse(&bytes);
    let mut source_b = source();
    source_b.source_id = "collector-b".into();
    let b = MrtBatch::parse(&bytes, source_b, &MrtLimits::default()).unwrap();
    assert_eq!(a.sha256, b.sha256); // hashes identify bytes, not collectors
    let x = a
        .normalize_rib_entry(1, 0, &Limits::default())
        .unwrap()
        .unwrap();
    let y = b
        .normalize_rib_entry(1, 0, &Limits::default())
        .unwrap()
        .unwrap();
    assert_ne!(get(&x, "source_id"), get(&y, "source_id"));
    assert_ne!(get(&x, "import_context"), get(&y, "import_context"));
    assert!(!a.source_authenticated && !b.source_authenticated);
}
#[test]
fn rfc_padding_bits_are_ignored_semantically_but_record_bytes_remain_identified() {
    let padded = record(12, 13, 2, &[0, 0, 0, 9, 9, 10, 0xff, 0, 0]);
    let canonical = record(12, 13, 2, &[0, 0, 0, 9, 9, 10, 0x80, 0, 0]);
    let a = parse(&[table(), padded].concat());
    let b = parse(&[table(), canonical].concat());
    let MrtBody::Rib(ar) = &a.records[1].body else {
        panic!("rib")
    };
    let MrtBody::Rib(br) = &b.records[1].body else {
        panic!("rib")
    };
    assert_eq!(ar.prefix, br.prefix);
    assert_eq!(ar.prefix.address, [10, 128, 0, 0]);
    assert_ne!(a.records[1].sha256, b.records[1].sha256);
}
#[test]
fn unknown_types_families_and_attribute_semantics_remain_source_bound() {
    let unknown = record(1, 999, 7, &[1, 2, 3]);
    let b = parse(&unknown);
    assert!(
        matches!(&b.records[0].body,MrtBody::Opaque {reason:"unsupported_type_or_subtype",bytes} if bytes==&[1,2,3])
    );
    let b = parse(&record(1, 13, 12, &[0, 0, 0, 1]));
    assert!(matches!(
        &b.records[0].body,
        MrtBody::Opaque {
            reason: "unsupported_type_or_subtype",
            ..
        }
    ));
    let b = parse(&record(1, 16, 2, &[7, 8]));
    assert!(matches!(
        &b.records[0].body,
        MrtBody::Opaque {
            reason: "unsupported_bgp4mp_subtype_or_afi",
            ..
        }
    ));
    let generic = vec![0, 0, 0, 9, 0, 25, 99, 0xaa, 0xbb];
    let data = [table(), record(2, 13, 6, &generic)].concat();
    let b = parse(&data);
    assert!(
        matches!(&b.records[1].body,MrtBody::Opaque {reason:"unsupported_afi_safi",bytes} if bytes==&generic)
    );
    let b = parse(&record(2, 13, 6, &generic));
    assert!(matches!(
        &b.records[0].body,
        MrtBody::Opaque {
            reason: "unsupported_afi_safi",
            ..
        }
    ));
    let mut unknown_afi = bgp4mp(4, false, false);
    unknown_afi[12 + 8 + 2..12 + 8 + 4].copy_from_slice(&25u16.to_be_bytes());
    let b = parse(&unknown_afi);
    assert!(matches!(
        &b.records[0].body,
        MrtBody::Opaque {
            reason: "unsupported_bgp4mp_subtype_or_afi",
            ..
        }
    ));
    let mut r = vec![0, 0, 0, 7, 8, 10, 0, 1, 0, 0];
    r.extend(10u32.to_be_bytes());
    r.extend(3u16.to_be_bytes());
    r.extend([0x80, 99, 0]);
    let b = parse(&[table(), record(2, 13, 2, &r)].concat());
    assert!(b
        .normalize_rib_entry(1, 0, &Limits::default())
        .unwrap()
        .is_none());
    assert!(matches!(b.records[1].body, MrtBody::Rib(_)));
    let mut atomic = vec![0, 0, 0, 7, 8, 10, 0, 1, 0, 0];
    atomic.extend(10u32.to_be_bytes());
    atomic.extend(3u16.to_be_bytes());
    atomic.extend([0x40, 6, 0]);
    let b = parse(&[table(), record(2, 13, 2, &atomic)].concat());
    assert!(b
        .normalize_rib_entry(1, 0, &Limits::default())
        .unwrap()
        .is_none());
}
#[test]
fn bgp4mp_state_message_et_and_addpath_keep_explicit_outer_context() {
    let data = [
        bgp4mp(0, false, true),
        bgp4mp(4, false, false),
        bgp4mp(7, true, false),
        bgp4mp(9, false, false),
    ]
    .concat();
    let b = parse(&data);
    assert_eq!(b.records[2].time.microseconds, Some(345_678));
    let MrtBody::Bgp4mp(s) = &b.records[0].body else {
        panic!("state")
    };
    assert_eq!(s.asn_width, 2);
    assert_eq!(s.payload, Bgp4mpPayload::State { old: 1, new: 6 });
    let MrtBody::Bgp4mp(m) = &b.records[1].body else {
        panic!("message")
    };
    assert_eq!(m.asn_width, 4);
    assert_eq!(m.asn_width_source, AsnWidthSource::Bgp4mpSubtype);
    assert_eq!(m.peer_asn, 65551);
    assert_eq!(m.payload, Bgp4mpPayload::Message(bgp_message()));
    let MrtBody::Bgp4mp(et) = &b.records[2].body else {
        panic!("et")
    };
    assert!(et.locally_generated);
    assert!(!et.add_path);
    let MrtBody::Bgp4mp(ap) = &b.records[3].body else {
        panic!("addpath")
    };
    assert!(ap.add_path);
    let v6 = parse(&bgp4mp_v6_state());
    let MrtBody::Bgp4mp(v6) = &v6.records[0].body else {
        panic!("v6 state")
    };
    assert_eq!(v6.address_afi, 2);
    assert_eq!(v6.peer_address.to_string(), "2001:db8::1");
    assert_eq!(v6.local_address.to_string(), "2001:db8::2");
}
#[test]
fn every_partial_record_boundary_and_invalid_index_fail_atomically() {
    assert!(MrtBatch::parse(&[], source(), &MrtLimits::default()).is_err());
    for full in [
        table(),
        bgp4mp(0, false, true),
        bgp4mp(4, true, false),
        record(4, 999, 1, &[1, 2]),
    ] {
        for cut in 1..full.len() {
            assert!(
                MrtBatch::parse(&full[..cut], source(), &MrtLimits::default()).is_err(),
                "cut {cut}"
            );
        }
    }
    let t = table();
    let r = rib_v4();
    for cut in 1..r.len() {
        assert!(
            MrtBatch::parse(
                &[t.clone(), r[..cut].to_vec()].concat(),
                source(),
                &MrtLimits::default()
            )
            .is_err(),
            "rib cut {cut}"
        );
    }
    let mut invalid = r;
    // Header 12 + seq 4 + prefix length 1 + prefix octet 1 + count 2 = 20.
    invalid[20] = 0;
    invalid[21] = 1;
    assert!(MrtBatch::parse(&[t, invalid].concat(), source(), &MrtLimits::default()).is_err());
}
#[test]
fn peer_table_view_is_utf8_and_context_does_not_cross_unrelated_records() {
    let mut invalid_view = table();
    invalid_view[18] = 0xff;
    assert!(MrtBatch::parse(&invalid_view, source(), &MrtLimits::default()).is_err());

    let unrelated = record(12, 999, 1, &[1, 2, 3]);
    assert!(MrtBatch::parse(
        &[table(), unrelated, rib_v4()].concat(),
        source(),
        &MrtLimits::default()
    )
    .is_err());
}
#[test]
fn contradictory_lengths_et_and_malformed_attributes_are_rejected() {
    let mut b = bgp4mp(4, false, false);
    let end = b.len();
    b[end - 2] = 0; // BGP length no longer agrees
    assert!(MrtBatch::parse(&b, source(), &MrtLimits::default()).is_err());
    let mut b = bgp4mp(7, true, false);
    b[12..16].copy_from_slice(&1_000_000u32.to_be_bytes());
    let parsed = MrtBatch::parse(&b, source(), &MrtLimits::default())
        .expect("BGP4MP_ET microsecond offsets are full-width u32 values");
    assert_eq!(parsed.records[0].time.microseconds, Some(1_000_000));
    b[12..16].copy_from_slice(&u32::MAX.to_be_bytes());
    let parsed = MrtBatch::parse(&b, source(), &MrtLimits::default())
        .expect("maximum BGP4MP_ET microsecond offset is preserved");
    assert_eq!(parsed.records[0].time.microseconds, Some(u32::MAX));
    let mut r = rib_v4();
    r[8..12].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(MrtBatch::parse(&[table(), r].concat(), source(), &MrtLimits::default()).is_err());
    let mut r = vec![0, 0, 0, 7, 8, 10, 0, 1, 0, 0];
    r.extend(10u32.to_be_bytes());
    r.extend(3u16.to_be_bytes());
    r.extend([0x40, 1, 4]);
    assert!(MrtBatch::parse(
        &[table(), record(2, 13, 2, &r)].concat(),
        source(),
        &MrtLimits::default()
    )
    .is_err());
}
#[test]
fn exact_and_one_below_budgets_cover_all_amplification_axes() {
    let bytes = [table_two(), rib_two()].concat();
    let b = parse(&bytes);
    let l = MrtLimits {
        input_bytes: bytes.len(),
        records: 2,
        peers: 2,
        rib_entries: 2,
        prefix_bytes: 2,
        path_attributes: 6,
        retained_bytes: b.retained_bytes,
        work: b.work_charge,
        output_bytes: b.output_charge,
    };
    assert!(MrtBatch::parse(&bytes, source(), &l).is_ok());
    for axis in 0..9 {
        let mut x = l.clone();
        match axis {
            0 => x.input_bytes -= 1,
            1 => x.records -= 1,
            2 => x.peers -= 1,
            3 => x.rib_entries -= 1,
            4 => x.prefix_bytes -= 1,
            5 => x.path_attributes -= 1,
            6 => x.retained_bytes -= 1,
            7 => x.work -= 1,
            _ => x.output_bytes -= 1,
        }
        assert!(
            MrtBatch::parse(&bytes, source(), &x).is_err(),
            "axis {axis}"
        );
    }
}
#[test]
fn contextual_conversion_preflights_its_own_attribute_limit() {
    let b = parse(&[table(), rib_v4()].concat());
    let l = Limits {
        input_bytes: attrs().len() - 1,
        ..Limits::default()
    };
    assert!(b.normalize_rib_entry(1, 0, &l).is_err());
    let l = Limits {
        elements: 1,
        ..Limits::default()
    };
    assert!(b.normalize_rib_entry(1, 0, &l).is_err());
}
