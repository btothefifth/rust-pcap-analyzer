//! Source-built contracts for conservative, source-order BGP4MP replay.
//! Fixtures are synthetic and prove parser behavior only, not collector truth.
use pcap_evidence::{json::Json, sha256};
use pcap_evidence_product::deep::{
    bgp::RouteAction,
    bgp_mrt::{MrtLimits, MrtSource},
    bgp_mrt_store,
    bgp_state::{ApplyStatus, CandidateState, ObservationKind},
    Limits,
};
use std::{
    fs, io,
    path::PathBuf,
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
};

static SERIAL: AtomicU64 = AtomicU64::new(0);

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        for _ in 0..1024 {
            let path = std::env::temp_dir().join(format!(
                "pcap-bgp4mp-replay-{}-{}",
                std::process::id(),
                SERIAL.fetch_add(1, Ordering::Relaxed),
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Self(path),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("create isolated test directory: {error}"),
            }
        }
        panic!("test directory namespace exhausted");
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

fn source(checkpoint_id: &str) -> MrtSource {
    MrtSource {
        source_id: "collector-fixture-a".into(),
        checkpoint_id: checkpoint_id.into(),
    }
}

fn mrt_record(seconds: u32, record_type: u16, subtype: u16, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&seconds.to_be_bytes());
    out.extend_from_slice(&record_type.to_be_bytes());
    out.extend_from_slice(&subtype.to_be_bytes());
    out.extend_from_slice(
        &u32::try_from(body.len())
            .expect("fixture length fits MRT")
            .to_be_bytes(),
    );
    out.extend_from_slice(body);
    out
}

fn bgp_message(message_type: u8, payload: &[u8]) -> Vec<u8> {
    let length = 19 + payload.len();
    let mut out = vec![0xff; 16];
    out.extend_from_slice(
        &u16::try_from(length)
            .expect("fixture fits BGP")
            .to_be_bytes(),
    );
    out.push(message_type);
    out.extend_from_slice(payload);
    out
}

fn open(actual_asn: u32, as4: bool, identifier: [u8; 4]) -> Vec<u8> {
    let legacy_asn = if as4 { 23_456 } else { actual_asn as u16 };
    let mut payload = vec![4];
    payload.extend_from_slice(&legacy_asn.to_be_bytes());
    payload.extend_from_slice(&90u16.to_be_bytes());
    payload.extend_from_slice(&identifier);
    if as4 {
        payload.push(8);
        payload.extend_from_slice(&[2, 6, 65, 4]);
        payload.extend_from_slice(&actual_asn.to_be_bytes());
    } else {
        payload.push(0);
    }
    bgp_message(1, &payload)
}

fn open_with_unknown_capability(actual_asn: u32, identifier: [u8; 4]) -> Vec<u8> {
    let mut message = open(actual_asn, false, identifier);
    message[16..18].copy_from_slice(&33u16.to_be_bytes());
    message[28] = 4;
    message.extend_from_slice(&[2, 2, 99, 0]);
    message
}

fn update(asn_width: u8, add_path: bool) -> Vec<u8> {
    let as_path_length = if asn_width == 4 { 6 } else { 4 };
    let mut attributes = vec![0x40, 1, 1, 0, 0x40, 2, as_path_length, 2, 1];
    if asn_width == 4 {
        attributes.extend_from_slice(&65_551u32.to_be_bytes());
    } else {
        attributes.extend_from_slice(&64_512u16.to_be_bytes());
    }
    attributes.extend_from_slice(&[0x40, 3, 4, 192, 0, 2, 9]);
    let mut payload = vec![0, 0];
    payload.extend_from_slice(
        &u16::try_from(attributes.len())
            .expect("fixture attributes fit BGP")
            .to_be_bytes(),
    );
    payload.extend_from_slice(&attributes);
    if add_path {
        payload.extend_from_slice(&7u32.to_be_bytes());
    }
    payload.extend_from_slice(&[24, 198, 51, 100]);
    bgp_message(2, &payload)
}

#[derive(Clone, Copy)]
struct Bgp4mpMetadata {
    width: u8,
    peer_asn: u32,
    local_asn: u32,
    interface_index: u16,
}

impl Bgp4mpMetadata {
    fn new(width: u8, peer_asn: u32, local_asn: u32, interface_index: u16) -> Self {
        Self {
            width,
            peer_asn,
            local_asn,
            interface_index,
        }
    }
}

fn state_record(
    metadata: Bgp4mpMetadata,
    subtype: u16,
    seconds: u32,
    old: u16,
    new: u16,
) -> Vec<u8> {
    let mut body = Vec::new();
    if metadata.width == 2 {
        body.extend_from_slice(
            &u16::try_from(metadata.peer_asn)
                .expect("fixture peer ASN fits")
                .to_be_bytes(),
        );
        body.extend_from_slice(
            &u16::try_from(metadata.local_asn)
                .expect("fixture local ASN fits")
                .to_be_bytes(),
        );
    } else {
        body.extend_from_slice(&metadata.peer_asn.to_be_bytes());
        body.extend_from_slice(&metadata.local_asn.to_be_bytes());
    }
    body.extend_from_slice(&metadata.interface_index.to_be_bytes());
    body.extend_from_slice(&1u16.to_be_bytes());
    body.extend_from_slice(&[198, 51, 100, 1, 198, 51, 100, 2]);
    body.extend_from_slice(&old.to_be_bytes());
    body.extend_from_slice(&new.to_be_bytes());
    mrt_record(seconds, 16, subtype, &body)
}

struct MessageRecordMetadata {
    bgp4mp: Bgp4mpMetadata,
    record_type: u16,
    subtype: u16,
    seconds: u32,
    microseconds: Option<u32>,
    locally_generated: bool,
}

impl MessageRecordMetadata {
    fn new(
        bgp4mp: Bgp4mpMetadata,
        record_type: u16,
        subtype: u16,
        seconds: u32,
        microseconds: Option<u32>,
        locally_generated: bool,
    ) -> Self {
        Self {
            bgp4mp,
            record_type,
            subtype,
            seconds,
            microseconds,
            locally_generated,
        }
    }
}

fn message_record(metadata: MessageRecordMetadata, message: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    if let Some(microseconds) = metadata.microseconds {
        body.extend_from_slice(&microseconds.to_be_bytes());
    }
    if metadata.bgp4mp.width == 2 {
        body.extend_from_slice(
            &u16::try_from(metadata.bgp4mp.peer_asn)
                .expect("fixture peer ASN fits")
                .to_be_bytes(),
        );
        body.extend_from_slice(
            &u16::try_from(metadata.bgp4mp.local_asn)
                .expect("fixture local ASN fits")
                .to_be_bytes(),
        );
    } else {
        body.extend_from_slice(&metadata.bgp4mp.peer_asn.to_be_bytes());
        body.extend_from_slice(&metadata.bgp4mp.local_asn.to_be_bytes());
    }
    body.extend_from_slice(&metadata.bgp4mp.interface_index.to_be_bytes());
    body.extend_from_slice(&1u16.to_be_bytes());
    body.extend_from_slice(&[198, 51, 100, 1, 198, 51, 100, 2]);
    body.extend_from_slice(message);
    let message_subtype = if metadata.locally_generated {
        if metadata.bgp4mp.width == 2 {
            6
        } else {
            7
        }
    } else {
        metadata.subtype
    };
    mrt_record(
        metadata.seconds,
        metadata.record_type,
        message_subtype,
        &body,
    )
}

fn established_flow(message_subtype: u16, add_path_wire: bool, microseconds: u32) -> Vec<u8> {
    established_flow_with_as4_capability(message_subtype, add_path_wire, microseconds, false)
}

fn established_flow_with_as4_capability(
    message_subtype: u16,
    add_path_wire: bool,
    microseconds: u32,
    force_as4_capability: bool,
) -> Vec<u8> {
    established_flow_with_options(
        message_subtype,
        add_path_wire,
        microseconds,
        force_as4_capability,
        false,
    )
}

fn established_flow_with_unknown_capability() -> Vec<u8> {
    established_flow_with_options(1, false, 654_321, false, true)
}

fn established_flow_with_options(
    message_subtype: u16,
    add_path_wire: bool,
    microseconds: u32,
    force_as4_capability: bool,
    unknown_capability: bool,
) -> Vec<u8> {
    let width = if matches!(message_subtype, 1 | 8) {
        2
    } else {
        4
    };
    let state_subtype = if width == 2 { 0 } else { 5 };
    let as4 = width == 4 || force_as4_capability;
    let peer_asn = if width == 2 {
        if as4 {
            23_456
        } else {
            64_512
        }
    } else {
        65_551
    };
    let local_asn = if width == 2 {
        if as4 {
            23_456
        } else {
            64_513
        }
    } else {
        65_552
    };
    let open_peer_asn = if as4 { 65_551 } else { peer_asn };
    let open_local_asn = if as4 { 65_552 } else { local_asn };
    let peer_open = if unknown_capability {
        open_with_unknown_capability(open_peer_asn, [198, 51, 100, 1])
    } else {
        open(open_peer_asn, as4, [198, 51, 100, 1])
    };
    let local_open = if unknown_capability {
        open_with_unknown_capability(open_local_asn, [198, 51, 100, 2])
    } else {
        open(open_local_asn, as4, [198, 51, 100, 2])
    };
    let mut records = vec![
        state_record(
            Bgp4mpMetadata::new(width, 0, local_asn, 0),
            state_subtype,
            300,
            3,
            4,
        ),
        message_record(
            MessageRecordMetadata::new(
                Bgp4mpMetadata::new(width, peer_asn, local_asn, 7),
                16,
                if width == 2 { 1 } else { 4 },
                250,
                None,
                false,
            ),
            &peer_open,
        ),
        message_record(
            MessageRecordMetadata::new(
                Bgp4mpMetadata::new(width, peer_asn, local_asn, 7),
                16,
                if width == 2 { 1 } else { 4 },
                200,
                None,
                true,
            ),
            &local_open,
        ),
        state_record(
            Bgp4mpMetadata::new(width, peer_asn, local_asn, 7),
            state_subtype,
            150,
            4,
            5,
        ),
        state_record(
            Bgp4mpMetadata::new(width, peer_asn, local_asn, 7),
            state_subtype,
            100,
            5,
            6,
        ),
    ];
    let update = update(width, add_path_wire);
    let update_record = message_record(
        MessageRecordMetadata::new(
            Bgp4mpMetadata::new(width, peer_asn, local_asn, 7),
            17,
            message_subtype,
            30,
            Some(microseconds),
            false,
        ),
        &update,
    );
    records.push(update_record);
    records.concat()
}

fn two_generation_fixture() -> Vec<u8> {
    let metadata = Bgp4mpMetadata::new(4, 65_551, 65_552, 7);
    let mut bytes = established_flow(4, false, 654_321);
    bytes.extend(message_record(
        MessageRecordMetadata::new(metadata, 16, 4, 25, None, false),
        &bgp_message(3, &[6, 0]),
    ));
    bytes.extend(established_flow(4, false, 654_321));
    bytes.extend(state_record(metadata, 5, 10, 6, 1));
    bytes
}

fn rewrite_bgp4mp_fixture_peer_address(bytes: &mut [u8], peer: [u8; 4]) {
    let mut record_start = 0usize;
    while record_start < bytes.len() {
        let header_end = record_start.checked_add(12).expect("MRT header end");
        assert!(header_end <= bytes.len(), "complete MRT record header");
        let record_type = u16::from_be_bytes(
            bytes[record_start + 4..record_start + 6]
                .try_into()
                .expect("record type"),
        );
        let extended_timestamp_bytes = match record_type {
            16 => 0,
            17 => 4,
            _ => panic!("fixture uses BGP4MP or BGP4MP_ET records"),
        };
        let body_length = u32::from_be_bytes(
            bytes[record_start + 8..record_start + 12]
                .try_into()
                .expect("record length"),
        ) as usize;
        let record_end = header_end.checked_add(body_length).expect("MRT record end");
        assert!(record_end <= bytes.len(), "record is within fixture");
        // MRT header (12), optional ET timestamp (4), two four-octet ASNs
        // (8), interface (2), and AFI (2) precede the peer address.
        let peer_start = record_start + 24 + extended_timestamp_bytes;
        let peer_end = peer_start
            .checked_add(peer.len())
            .expect("peer address end");
        assert!(peer_end <= record_end, "peer address is within the record");
        bytes[peer_start..peer_end].copy_from_slice(&peer);
        record_start = record_end;
    }
    assert_eq!(
        record_start,
        bytes.len(),
        "fixture ends on a record boundary"
    );
}

fn field_number(value: &Json, key: &str) -> Option<u64> {
    match value {
        Json::Object(fields) => {
            fields
                .iter()
                .find(|(name, _)| *name == key)
                .and_then(|(_, value)| match value {
                    Json::Number(number) => Some(*number),
                    _ => None,
                })
        }
        _ => None,
    }
}

fn field_string<'a>(value: &'a Json, key: &str) -> Option<&'a str> {
    match value {
        Json::Object(fields) => {
            fields
                .iter()
                .find(|(name, _)| *name == key)
                .and_then(|(_, value)| match value {
                    Json::String(text) => Some(text.as_str()),
                    _ => None,
                })
        }
        _ => None,
    }
}

fn import(
    path: &std::path::Path,
    bytes: &[u8],
    checkpoint_id: &str,
) -> bgp_mrt_store::MrtReplayArchive {
    bgp_mrt_store::create(
        path,
        bytes,
        source(checkpoint_id),
        4 * 1024 * 1024,
        MrtLimits::default(),
        Limits::default(),
    )
    .expect("source-built BGP4MP replay fixture imports")
}

fn unsupported_rib_fixture() -> (Vec<u8>, Vec<u8>) {
    let mut peer_table = vec![
        192, 0, 2, 1, 0, 1, b'v', 0, 1, 2, 192, 0, 2, 2, 203, 0, 113, 9,
    ];
    peer_table.extend_from_slice(&65_551u32.to_be_bytes());
    let peer_record = mrt_record(10, 13, 1, &peer_table);

    let mut attributes = vec![0x40, 1, 1, 0, 0x40, 2, 6, 2, 1];
    attributes.extend_from_slice(&65_551u32.to_be_bytes());
    attributes.extend_from_slice(&[0x40, 3, 4, 192, 0, 2, 9]);
    // Unknown optional-transitive attribute: retain the RIB source evidence,
    // but do not project an incomplete route candidate.
    attributes.extend_from_slice(&[0xc0, 99, 1, 42]);

    let mut rib = vec![0, 0, 0, 7, 8, 10, 0, 1, 0, 0];
    rib.extend_from_slice(&10u32.to_be_bytes());
    rib.extend_from_slice(&(attributes.len() as u16).to_be_bytes());
    rib.extend_from_slice(&attributes);
    let rib_record = mrt_record(11, 13, 2, &rib);

    ([peer_record, rib_record].concat(), attributes)
}

fn json_field<'a>(value: &'a Json, key: &str) -> &'a Json {
    let Json::Object(fields) = value else {
        panic!("expected JSON object while reading {key}");
    };
    fields
        .iter()
        .find(|(name, _)| *name == key)
        .map(|(_, value)| value)
        .unwrap_or_else(|| panic!("missing JSON field {key}"))
}

#[test]
fn unsupported_rib_entry_is_exposed_as_opaque_evidence_not_a_route_candidate() {
    let scratch = Scratch::new();
    let (bytes, attributes) = unsupported_rib_fixture();
    let archive = import(
        &scratch.file("unsupported-rib.mrt-store"),
        &bytes,
        "opaque-rib",
    );

    assert_eq!(archive.unsupported_rib_entries, 1);
    assert!(archive.candidates.is_empty());
    assert!(archive.state.observations().is_empty());
    assert!(archive.state.routes().is_empty());

    let replay = archive.json();
    let Json::Array(entries) = json_field(&replay, "unsupported_rib_entry_evidence") else {
        panic!("unsupported RIB evidence is an array");
    };
    assert_eq!(entries.len(), 1);
    let evidence = &entries[0];
    let identity = json_field(evidence, "semantic_identity_status");
    assert_eq!(field_string(identity, "completeness"), Some("opaque_only"));
    assert_eq!(json_field(identity, "fingerprint_sha256"), &Json::Null);
    assert_eq!(
        field_string(identity, "reason"),
        Some("path_attribute_semantics_not_normalized")
    );
    assert_eq!(
        json_field(identity, "candidate_admitted"),
        &Json::Bool(false)
    );

    let source_record = json_field(evidence, "source_record");
    assert_eq!(field_number(source_record, "record_index"), Some(1));
    assert_eq!(field_number(source_record, "entry_index"), Some(0));
    assert_eq!(
        field_string(source_record, "record_sha256"),
        Some(archive.batch().records[1].sha256.as_str())
    );
    let attribute_block = json_field(evidence, "attribute_block");
    assert_eq!(
        field_number(attribute_block, "byte_length"),
        Some(attributes.len() as u64)
    );
    assert_eq!(
        field_string(attribute_block, "block_sha256"),
        Some(sha256::hex(&sha256::digest(&attributes)).as_str())
    );

    let body_bytes = archive.encoded_len_bounded(usize::MAX).unwrap();
    let mut exact_line = Vec::new();
    assert_eq!(
        archive
            .write_bounded_line(&mut exact_line, body_bytes + 1)
            .unwrap(),
        body_bytes + 1
    );
    let mut short_line = Vec::new();
    assert!(archive
        .write_bounded_line(&mut short_line, body_bytes)
        .is_err());
    assert!(
        short_line.is_empty(),
        "failed preflight writes no partial line"
    );

    let exact_path = scratch.file("unsupported-rib-exact-output.mrt-store");
    let exact_limits = Limits {
        output_bytes: body_bytes,
        ..Limits::default()
    };
    bgp_mrt_store::create(
        &exact_path,
        &bytes,
        source("opaque-rib"),
        4 * 1024 * 1024,
        MrtLimits::default(),
        exact_limits,
    )
    .expect("store preflight accepts exact aggregate output budget");

    let short_path = scratch.file("unsupported-rib-short-output.mrt-store");
    let short_limits = Limits {
        output_bytes: body_bytes - 1,
        ..Limits::default()
    };
    assert!(bgp_mrt_store::create(
        &short_path,
        &bytes,
        source("opaque-rib"),
        4 * 1024 * 1024,
        MrtLimits::default(),
        short_limits,
    )
    .is_err());
    assert!(
        !short_path.exists(),
        "one-byte-short preflight must reject before creating the store"
    );
}

#[test]
fn established_replay_uses_shared_update_parser_and_exact_et_message_provenance() {
    let scratch = Scratch::new();
    let bytes = established_flow(1, false, 654_321);
    let archive = import(&scratch.file("messages.mrt-store"), &bytes, "checkpoint-7");

    assert_eq!(archive.bgp4mp_candidates.len(), 1);
    assert_eq!(archive.bgp4mp_events.len(), 6);
    let candidate = &archive.bgp4mp_candidates[0];
    assert_eq!(candidate.source_id, "collector-fixture-a");
    assert_eq!(candidate.checkpoint_id, "checkpoint-7");
    assert_eq!(candidate.direction, 0);
    assert_eq!(candidate.observed_at_ns, Some(30_654_321_000));
    assert!(candidate.session.contains("collector-fixture-a"));
    assert!(candidate.session.contains("checkpoint-7"));
    assert_eq!(
        field_string(&archive.bgp4mp_events[0], "session"),
        Some(candidate.session.as_str()),
        "unknown peer-AS/interface fields enrich without splitting one source session"
    );
    assert_eq!(candidate.prefix.address, "198.51.100.0");
    assert_eq!(candidate.route_index, 0);

    let record = &archive.batch().records[candidate.record_index];
    assert_eq!(record.time.seconds, 30);
    assert_eq!(record.time.microseconds, Some(654_321));
    let range = archive
        .batch()
        .bgp4mp_message_source_range(candidate.record_index)
        .unwrap()
        .unwrap();
    assert_eq!(candidate.source_range_start, range.start);
    assert_eq!(candidate.source_range_end, range.end);
    let exact_message = &bytes[range.start as usize..range.end as usize];
    assert_eq!(
        candidate.message_sha256,
        sha256::hex(&sha256::digest(exact_message))
    );
    assert_eq!(exact_message[18], 2);

    let observation = archive
        .bgp4mp_candidate_observation(candidate)
        .expect("candidate is bound to its normalized observation and source range");
    assert_eq!(
        observation.source().observed_at_ns,
        candidate.observed_at_ns
    );
    assert_eq!(observation.routes()[0].prefix().address, "198.51.100.0");
    assert!(observation.import_context().is_some());
    let normalized = observation.normalized().encode();
    assert!(normalized.contains("\"import_context\":{"));
    assert!(normalized.contains("\"message_type\":0"));
    assert!(normalized.contains("\"field_start\":0"));
    assert!(normalized.contains("\"field_end\":0"));
    assert!(normalized.contains("\"attribute_ranges\":[]"));
    assert!(normalized.contains("\"evidence\":null"));
    assert!(!normalized.contains("pcap_packet"));

    let event_indexes: Vec<_> = archive
        .bgp4mp_events
        .iter()
        .map(|event| field_number(event, "record_index").expect("event record index"))
        .collect();
    assert_eq!(event_indexes, vec![0, 1, 2, 3, 4, 5]);
    assert_eq!(
        field_string(&archive.bgp4mp_events[5], "parse_status"),
        Some("decoded_update_candidate")
    );
    assert!(archive
        .json()
        .encode()
        .contains("pcap-evidence.bgp.mrt-replay.v3"));

    let mut query = Vec::new();
    archive
        .write_session_query_bounded_line(&candidate.session, &mut query, 1024 * 1024)
        .expect("session query includes imported BGP4MP candidates");
    let query = String::from_utf8(query).expect("query UTF-8");
    assert!(query.contains("pcap-evidence.bgp.imported-session-query.v3"));
    assert!(query.contains("bgp4mp_candidates"));
}

#[test]
fn imported_generation_boundaries_preserve_order_and_fail_closed_when_missing_or_reversed() {
    let scratch = Scratch::new();
    let bytes = two_generation_fixture();
    let archive = import(&scratch.file("epochs.mrt-store"), &bytes, "epochs");
    assert_eq!(archive.bgp4mp_candidates.len(), 2);
    assert_eq!(archive.bgp4mp_candidates[0].action, RouteAction::Announce);
    assert_eq!(archive.bgp4mp_candidates[1].action, RouteAction::Announce);
    assert!(archive.bgp4mp_candidates[0].record_index < 6);
    assert!(archive.bgp4mp_candidates[1].record_index > 6);
    assert_eq!(archive.batch().records[6].time.seconds, 25);
    assert_eq!(archive.batch().records[7].time.seconds, 300);
    assert_eq!(archive.batch().records[12].time.seconds, 30);
    assert_eq!(archive.batch().records[13].time.seconds, 10);
    assert!(
        archive.batch().records[0].time.seconds > archive.batch().records[1].time.seconds,
        "fixture deliberately contains a decreasing source timestamp"
    );
    assert!(
        archive.batch().records[6].time.seconds < archive.batch().records[7].time.seconds,
        "the second epoch starts later in file order but has a later source timestamp"
    );
    assert!(
        archive.batch().records[13].time.seconds < archive.batch().records[12].time.seconds,
        "the terminal reset follows its UPDATE in file order despite its earlier timestamp"
    );

    let first_context = archive
        .bgp4mp_candidate_observation(&archive.bgp4mp_candidates[0])
        .expect("first epoch candidate observation")
        .import_context()
        .expect("first epoch import context");
    let second_context = archive
        .bgp4mp_candidate_observation(&archive.bgp4mp_candidates[1])
        .expect("second epoch candidate observation")
        .import_context()
        .expect("second epoch import context");
    assert_eq!(first_context.source_id, second_context.source_id);
    assert_eq!(first_context.checkpoint_id, second_context.checkpoint_id);
    assert_eq!(first_context.source_schema, second_context.source_schema);
    assert_eq!(first_context.source_version, second_context.source_version);
    assert_eq!(first_context.batch, second_context.batch);
    assert_eq!(first_context.session, second_context.session);
    assert_eq!(first_context.peer, second_context.peer);
    assert_eq!(first_context.local, second_context.local);
    assert_eq!(first_context.generation, 0);
    assert_eq!(second_context.generation, 1);

    let observations = archive.state.observations();
    assert_eq!(observations.len(), 4);
    let first_update = archive.bgp4mp_candidates[0].observation_index;
    let second_update = archive.bgp4mp_candidates[1].observation_index;
    let boundaries: Vec<_> = observations
        .iter()
        .enumerate()
        .filter(|(_, observation)| observation.import_boundary().is_some())
        .collect();
    assert_eq!(boundaries.len(), 2);
    let (notification_boundary_index, notification_boundary) = boundaries[0];
    let (terminal_boundary_index, terminal_boundary) = boundaries[1];
    assert!(first_update < notification_boundary_index);
    assert!(notification_boundary_index < second_update);
    assert!(second_update < terminal_boundary_index);
    assert_eq!(
        notification_boundary
            .import_boundary()
            .unwrap()
            .previous_generation,
        0
    );
    assert_eq!(
        terminal_boundary
            .import_boundary()
            .unwrap()
            .previous_generation,
        1
    );

    for (boundary, record_index) in [
        (notification_boundary, 6usize),
        (terminal_boundary, 13usize),
    ] {
        assert_eq!(boundary.kind(), ObservationKind::Reset);
        assert!(
            boundary.routes().is_empty(),
            "reset must not invent withdrawals"
        );
        let context = boundary.import_context().expect("reset import context");
        assert_eq!(context.direction, None);
        assert_eq!(context.provenance.len(), 1);
        let record = &archive.batch().records[record_index];
        let range = &context.provenance[0];
        assert_eq!(range.start, record.offset);
        assert_eq!(range.end, record.offset + 12 + u64::from(record.length));
        assert_eq!(range.sha256.as_deref(), Some(record.sha256.as_str()));
        assert_eq!(
            boundary.source().record_id,
            format!(
                "mrt-bgp4mp-reset:{}:{}:{}:{}",
                record.offset, record.subtype, record_index, record.sha256
            )
        );
    }

    for (candidate, expected_generation) in archive.bgp4mp_candidates.iter().zip([0, 1]) {
        let observation = archive
            .bgp4mp_candidate_observation(candidate)
            .expect("epoch candidate remains bound to its source message");
        assert_eq!(observation.source().generation, Some(expected_generation));
        let outcome = archive
            .state
            .outcomes()
            .iter()
            .find(|outcome| outcome.observation == candidate.observation_index)
            .expect("candidate reduction outcome");
        assert_eq!(outcome.status, ApplyStatus::Applied);
    }
    assert!(archive.state.routes().is_empty());
    assert_eq!(archive.state.sessions().len(), 1);
    assert_eq!(archive.state.sessions()[0].generation, 2);

    let without_notification_boundary = vec![
        observations[first_update].clone(),
        observations[second_update].clone(),
    ];
    let mut missing = CandidateState::new(Limits::default()).expect("new candidate state");
    assert!(missing.apply_batch(without_notification_boundary).is_err());
    assert!(missing.observations().is_empty(), "failed batch is atomic");

    let reversed_boundary = vec![
        observations[first_update].clone(),
        observations[second_update].clone(),
        observations[notification_boundary_index].clone(),
    ];
    let mut reversed = CandidateState::new(Limits::default()).expect("new candidate state");
    assert!(reversed.apply_batch(reversed_boundary).is_err());
    assert!(reversed.observations().is_empty(), "failed batch is atomic");
}

#[test]
fn terminal_reset_without_notification_closes_only_its_peer_partition() {
    let scratch = Scratch::new();
    let metadata = Bgp4mpMetadata::new(4, 65_551, 65_552, 7);
    let mut first_peer = established_flow(4, false, 654_321);
    let mut second_peer = established_flow(4, false, 654_321);
    rewrite_bgp4mp_fixture_peer_address(&mut second_peer, [198, 51, 100, 3]);
    first_peer.extend(second_peer);
    first_peer.extend(state_record(metadata, 5, 10, 6, 1));

    let archive = import(
        &scratch.file("peer-partitions.mrt-store"),
        &first_peer,
        "peer-partitions",
    );
    assert_eq!(archive.bgp4mp_candidates.len(), 2);
    let first_candidate = &archive.bgp4mp_candidates[0];
    let second_candidate = &archive.bgp4mp_candidates[1];
    assert_ne!(
        first_candidate.session, second_candidate.session,
        "peer/local endpoint partitions must not share a session identity"
    );
    assert_eq!(first_candidate.source_id, second_candidate.source_id);
    assert_eq!(
        first_candidate.checkpoint_id,
        second_candidate.checkpoint_id
    );
    let first_context = archive
        .bgp4mp_candidate_observation(first_candidate)
        .expect("first peer candidate observation")
        .import_context()
        .expect("first peer import context");
    let second_context = archive
        .bgp4mp_candidate_observation(second_candidate)
        .expect("second peer candidate observation")
        .import_context()
        .expect("second peer import context");
    assert_eq!(first_context.source_schema, second_context.source_schema);
    assert_eq!(first_context.source_version, second_context.source_version);
    assert_eq!(first_context.batch, second_context.batch);
    assert_eq!(first_context.checkpoint_id, second_context.checkpoint_id);
    assert_eq!(first_context.local, second_context.local);
    assert_ne!(first_context.peer, second_context.peer);

    let boundary = archive
        .state
        .observations()
        .iter()
        .find(|observation| observation.import_boundary().is_some())
        .expect("terminal reset boundary without a preceding NOTIFICATION");
    let boundary_context = boundary.import_context().expect("terminal reset context");
    assert_eq!(boundary_context.session, first_candidate.session);
    assert_eq!(boundary_context.peer, first_context.peer);
    assert_eq!(boundary_context.local, first_context.local);
    assert_ne!(boundary_context.peer, second_context.peer);
    assert_eq!(boundary.import_boundary().unwrap().previous_generation, 0);
    assert_eq!(boundary.kind(), ObservationKind::Reset);
    assert!(
        boundary.routes().is_empty(),
        "reset never fabricates withdrawals"
    );
    assert_eq!(
        archive.state.observations().len(),
        3,
        "two accepted UPDATEs and one terminal reset"
    );
    assert_eq!(
        archive.state.routes().len(),
        1,
        "the reset for peer one must not clear peer two's route"
    );
    assert!(
        archive
            .bgp4mp_events
            .iter()
            .all(|event| field_string(event, "parse_status") != Some("decoded_notification_reset")),
        "this fixture contains no NOTIFICATION"
    );
    let reset_event = archive.bgp4mp_events.last().expect("terminal reset event");
    assert_eq!(
        field_string(reset_event, "session"),
        Some(first_candidate.session.as_str())
    );
    assert_eq!(
        field_string(reset_event, "peer_address"),
        Some("198.51.100.1")
    );
    assert_eq!(
        field_string(reset_event, "local_address"),
        Some("198.51.100.2")
    );

    let record = archive
        .batch()
        .records
        .last()
        .expect("terminal reset record");
    let range = &boundary_context.provenance[0];
    assert_eq!(range.start, record.offset);
    assert_eq!(range.end, record.offset + 12 + u64::from(record.length));
    assert_eq!(range.sha256.as_deref(), Some(record.sha256.as_str()));
    assert_eq!(
        boundary.source().record_id,
        format!(
            "mrt-bgp4mp-reset:{}:{}:{}:{}",
            record.offset,
            record.subtype,
            archive.batch().records.len() - 1,
            record.sha256
        )
    );
    let second_outcome = archive
        .state
        .outcomes()
        .iter()
        .find(|outcome| outcome.observation == second_candidate.observation_index)
        .expect("second peer UPDATE reduction outcome");
    assert_eq!(second_outcome.status, ApplyStatus::Applied);

    // One source-store batch fixes schema/version/hash/length and checkpoint.
    // session_key additionally encodes source/checkpoint and peer/local
    // identity, so these are the only varying partition fields in one archive.
    let other_checkpoint = import(
        &scratch.file("peer-partitions-other-checkpoint.mrt-store"),
        &first_peer,
        "other-checkpoint",
    );
    assert_ne!(
        first_candidate.session, other_checkpoint.bgp4mp_candidates[0].session,
        "session identity must bind its checkpoint partition"
    );
}

#[test]
fn open_seen_in_connect_survives_following_open_sent_transition() {
    let scratch = Scratch::new();
    let records = [
        state_record(Bgp4mpMetadata::new(2, 64_512, 64_513, 7), 0, 300, 1, 2),
        message_record(
            MessageRecordMetadata::new(
                Bgp4mpMetadata::new(2, 64_512, 64_513, 7),
                16,
                1,
                250,
                None,
                false,
            ),
            &open(64_512, false, [198, 51, 100, 1]),
        ),
        state_record(Bgp4mpMetadata::new(2, 64_512, 64_513, 7), 0, 240, 2, 4),
        message_record(
            MessageRecordMetadata::new(
                Bgp4mpMetadata::new(2, 64_512, 64_513, 7),
                16,
                1,
                230,
                None,
                true,
            ),
            &open(64_513, false, [198, 51, 100, 2]),
        ),
        state_record(Bgp4mpMetadata::new(2, 64_512, 64_513, 7), 0, 220, 4, 5),
        state_record(Bgp4mpMetadata::new(2, 64_512, 64_513, 7), 0, 210, 5, 6),
        message_record(
            MessageRecordMetadata::new(
                Bgp4mpMetadata::new(2, 64_512, 64_513, 7),
                16,
                1,
                200,
                None,
                false,
            ),
            &update(2, false),
        ),
    ]
    .concat();
    let archive = import(
        &scratch.file("open-source-order.mrt-store"),
        &records,
        "open-order",
    );

    assert_eq!(archive.bgp4mp_candidates.len(), 1);
    assert_eq!(
        field_string(&archive.bgp4mp_events[1], "parse_status"),
        Some("decoded_open")
    );
    assert_eq!(
        field_string(&archive.bgp4mp_events[2], "parse_status"),
        Some("reported_transition")
    );
    assert_eq!(
        field_string(archive.bgp4mp_events.last().unwrap(), "parse_status"),
        Some("decoded_update_candidate")
    );
}

#[test]
fn opensent_to_active_transport_failure_clears_old_attempt_capabilities() {
    let scratch = Scratch::new();
    let records = [
        state_record(Bgp4mpMetadata::new(2, 64_512, 64_513, 7), 0, 400, 1, 2),
        state_record(Bgp4mpMetadata::new(2, 64_512, 64_513, 7), 0, 390, 2, 4),
        message_record(
            MessageRecordMetadata::new(
                Bgp4mpMetadata::new(2, 64_512, 64_513, 7),
                16,
                1,
                380,
                None,
                false,
            ),
            &open(64_512, false, [198, 51, 100, 1]),
        ),
        state_record(Bgp4mpMetadata::new(2, 64_512, 64_513, 7), 0, 370, 4, 3),
        message_record(
            MessageRecordMetadata::new(
                Bgp4mpMetadata::new(2, 64_512, 64_513, 7),
                16,
                1,
                360,
                None,
                false,
            ),
            &open(64_512, false, [198, 51, 100, 1]),
        ),
        message_record(
            MessageRecordMetadata::new(
                Bgp4mpMetadata::new(2, 64_512, 64_513, 7),
                16,
                1,
                350,
                None,
                true,
            ),
            &open(64_513, false, [198, 51, 100, 2]),
        ),
        state_record(Bgp4mpMetadata::new(2, 64_512, 64_513, 7), 0, 340, 3, 4),
        state_record(Bgp4mpMetadata::new(2, 64_512, 64_513, 7), 0, 330, 4, 5),
        state_record(Bgp4mpMetadata::new(2, 64_512, 64_513, 7), 0, 320, 5, 6),
        message_record(
            MessageRecordMetadata::new(
                Bgp4mpMetadata::new(2, 64_512, 64_513, 7),
                16,
                1,
                310,
                None,
                false,
            ),
            &update(2, false),
        ),
    ]
    .concat();
    let archive = import(
        &scratch.file("opensent-active-retry.mrt-store"),
        &records,
        "opensent-active-retry",
    );

    assert_eq!(
        archive.bgp4mp_candidates.len(),
        1,
        "retry should produce a candidate from fresh OPENs; events: {}",
        archive
            .bgp4mp_events
            .iter()
            .map(Json::encode)
            .collect::<Vec<_>>()
            .join("\n")
    );
    assert_eq!(
        field_number(&archive.bgp4mp_events[2], "generation"),
        Some(0),
        "the first OPEN belongs to the failed transport attempt"
    );
    assert_eq!(
        field_number(&archive.bgp4mp_events[3], "generation"),
        Some(1),
        "OpenSent -> Active starts a fresh capability generation"
    );
    assert_eq!(
        field_string(&archive.bgp4mp_events[3], "parse_status"),
        Some("reported_transition")
    );
    assert_eq!(
        field_string(archive.bgp4mp_events.last().unwrap(), "parse_status"),
        Some("decoded_update_candidate"),
        "the retry's two OPENs, not stale evidence, authorize decoding"
    );
}

#[test]
fn source_checkpoint_partition_and_as4_outer_width_do_not_alias_or_change_as_path_grammar() {
    let scratch = Scratch::new();
    let bytes = established_flow(4, false, 654_321);
    let first = import(&scratch.file("first.mrt-store"), &bytes, "checkpoint-a");
    let second = import(&scratch.file("second.mrt-store"), &bytes, "checkpoint-b");

    assert_eq!(first.bgp4mp_candidates.len(), 1);
    assert_eq!(second.bgp4mp_candidates.len(), 1);
    assert_ne!(
        first.bgp4mp_candidates[0].session, second.bgp4mp_candidates[0].session,
        "the same endpoints in separate collector checkpoints are separate sessions"
    );
    let route = first
        .bgp4mp_candidate_observation(&first.bgp4mp_candidates[0])
        .unwrap()
        .routes()[0]
        .attributes()
        .encode();
    assert!(
        route.contains("65551"),
        "AS_PATH uses negotiated OPEN width"
    );
}

#[test]
fn update_without_established_state_and_unnegotiated_add_path_layout_are_quarantined() {
    let scratch = Scratch::new();
    let orphan = message_record(
        MessageRecordMetadata::new(
            Bgp4mpMetadata::new(2, 64_512, 64_513, 0),
            16,
            1,
            20,
            None,
            false,
        ),
        &update(2, false),
    );
    let orphan_archive = import(&scratch.file("orphan.mrt-store"), &orphan, "orphan");
    assert!(orphan_archive.bgp4mp_candidates.is_empty());
    assert_eq!(
        field_string(&orphan_archive.bgp4mp_events[0], "parse_status"),
        Some("quarantined")
    );
    let orphan_session = field_string(&orphan_archive.bgp4mp_events[0], "session")
        .expect("orphan event session")
        .to_owned();
    let mut orphan_query = Vec::new();
    orphan_archive
        .write_session_query_bounded_line(&orphan_session, &mut orphan_query, 1024 * 1024)
        .expect("event-only sessions remain queryable");
    let orphan_query = String::from_utf8(orphan_query).expect("query UTF-8");
    assert!(orphan_query.contains("quarantined"));
    assert!(orphan_query.contains("bgp4mp_events"));
    assert!(orphan_query.contains("\"bgp4mp_candidates\":[]"));

    let add_path_bytes = established_flow(8, true, 654_321);
    let add_path_archive = import(
        &scratch.file("addpath-mismatch.mrt-store"),
        &add_path_bytes,
        "addpath-mismatch",
    );
    assert!(add_path_archive.bgp4mp_candidates.is_empty());
    let last = add_path_archive.bgp4mp_events.last().expect("UPDATE event");
    assert_eq!(field_string(last, "parse_status"), Some("quarantined"));
    assert!(last
        .encode()
        .contains("container_add_path_layout_conflicts_with_bilateral_open"));
}

#[test]
fn illegal_fsm_transition_cannot_admit_an_update_after_two_open_messages() {
    let scratch = Scratch::new();
    for (case, initial, old, new) in [
        ("connect-openconfirm", 2, 2, 5),
        ("active-openconfirm", 3, 3, 5),
        ("opensent-established", 4, 4, 6),
    ] {
        let mut records = if initial == 4 {
            vec![
                state_record(Bgp4mpMetadata::new(2, 64_512, 64_513, 7), 0, 310, 1, 2),
                state_record(Bgp4mpMetadata::new(2, 64_512, 64_513, 7), 0, 300, 2, 4),
            ]
        } else {
            vec![state_record(
                Bgp4mpMetadata::new(2, 64_512, 64_513, 7),
                0,
                300,
                1,
                initial,
            )]
        };
        records.extend([
            message_record(
                MessageRecordMetadata::new(
                    Bgp4mpMetadata::new(2, 64_512, 64_513, 7),
                    16,
                    1,
                    250,
                    None,
                    false,
                ),
                &open(64_512, false, [198, 51, 100, 1]),
            ),
            message_record(
                MessageRecordMetadata::new(
                    Bgp4mpMetadata::new(2, 64_512, 64_513, 7),
                    16,
                    1,
                    200,
                    None,
                    true,
                ),
                &open(64_513, false, [198, 51, 100, 2]),
            ),
            state_record(Bgp4mpMetadata::new(2, 64_512, 64_513, 7), 0, 150, old, new),
            message_record(
                MessageRecordMetadata::new(
                    Bgp4mpMetadata::new(2, 64_512, 64_513, 7),
                    17,
                    1,
                    100,
                    Some(1_000_000),
                    false,
                ),
                &update(2, false),
            ),
        ]);
        let archive = import(
            &scratch.file(&format!("{case}.mrt-store")),
            &records.concat(),
            case,
        );

        assert!(archive.bgp4mp_candidates.is_empty(), "{case}");
        assert_eq!(
            field_string(
                &archive.bgp4mp_events[archive.bgp4mp_events.len() - 2],
                "parse_status"
            ),
            Some("quarantined"),
            "{case} transition"
        );
        assert!(
            archive.bgp4mp_events[archive.bgp4mp_events.len() - 2]
                .encode()
                .contains("illegal_reported_fsm_transition"),
            "{case}"
        );
        assert_eq!(
            field_string(archive.bgp4mp_events.last().unwrap(), "parse_status"),
            Some("quarantined"),
            "{case} UPDATE"
        );
    }
}

#[test]
fn imported_update_event_preserves_capability_warnings_from_the_shared_parser() {
    let scratch = Scratch::new();
    let bytes = established_flow_with_unknown_capability();
    let archive = import(
        &scratch.file("capability-warning.mrt-store"),
        &bytes,
        "warning",
    );

    assert_eq!(archive.bgp4mp_candidates.len(), 1);
    let update_event = archive.bgp4mp_events.last().expect("UPDATE event");
    assert_eq!(
        field_string(update_event, "parse_status"),
        Some("decoded_update_candidate")
    );
    assert!(update_event
        .encode()
        .contains("unsupported_session_capabilities_not_interpreted"));
    let observation = archive
        .bgp4mp_candidate_observation(&archive.bgp4mp_candidates[0])
        .expect("candidate remains bound after warning propagation");
    assert!(observation
        .normalized()
        .encode()
        .contains("unsupported_session_capabilities_not_interpreted"));
}

#[test]
fn cli_import_fresh_replay_query_and_export_retain_bgp4mp_events_and_routes() {
    let scratch = Scratch::new();
    let source_path = scratch.file("source.mrt");
    let workspace = scratch.file("workspace");
    let bytes = two_generation_fixture();
    let relationship_options = bgp_mrt_store::MrtReplayOptions {
        peer_relationship: Some(pcap_evidence_product::deep::bgp::PeerRelationship::Internal),
    };
    let reference = bgp_mrt_store::create_with_options(
        &scratch.file("reference.mrt-store"),
        &bytes,
        source("cli-checkpoint"),
        4 * 1024 * 1024,
        MrtLimits::default(),
        Limits::default(),
        relationship_options,
    )
    .expect("explicitly configured reference replay");
    fs::write(&source_path, &bytes).expect("write source fixture");

    let imported = Command::new(env!("CARGO_BIN_EXE_pcap-depth"))
        .args(["bgp", "import-mrt"])
        .arg(&source_path)
        .args(["--workspace"])
        .arg(&workspace)
        .args([
            "--source-id",
            "collector-fixture-a",
            "--checkpoint",
            "cli-checkpoint",
            "--peer-relationship",
            "internal",
        ])
        .output()
        .expect("run MRT import process");
    assert!(
        imported.status.success(),
        "import failed: {}",
        String::from_utf8_lossy(&imported.stderr)
    );
    let receipt = fs::read_to_string(workspace.join("receipt.json")).expect("import receipt");
    assert!(receipt.contains("\"bgp4mp_route_candidates\":\"2\""));
    assert!(receipt.contains("\"bgp4mp_events\":\"14\""));

    let store = workspace.join("bgp.mrt");
    assert!(
        store.is_file(),
        "the import process created a durable source store"
    );
    let session = reference.bgp4mp_candidates[0].session.clone();

    let state_path = scratch.file("state.json");
    let state = Command::new(env!("CARGO_BIN_EXE_pcap-depth"))
        .args(["bgp", "state"])
        .arg(&store)
        .args(["--peer-relationship", "internal"])
        .args(["--output"])
        .arg(&state_path)
        .output()
        .expect("run fresh state process");
    assert!(
        state.status.success(),
        "state: {}",
        String::from_utf8_lossy(&state.stderr)
    );
    let state = fs::read_to_string(state_path).expect("state report");
    assert!(state.contains("pcap-evidence.bgp.mrt-replay.v3"));
    assert!(
        state.contains("\"fresh_process_reduction\":true"),
        "the state command replayed the persisted store in its own pcap-depth process"
    );
    let mut expected_state = Vec::new();
    reference
        .write_bounded_line(&mut expected_state, 4 * 1024 * 1024)
        .expect("reference state serialization");
    assert_eq!(
        state.as_bytes(),
        expected_state,
        "fresh-process replay state and both generation candidates match the source-store reference"
    );

    let query_path = scratch.file("query.json");
    let query = Command::new(env!("CARGO_BIN_EXE_pcap-depth"))
        .args(["bgp", "query"])
        .arg(&store)
        .args(["--session"])
        .arg(&session)
        .args(["--peer-relationship", "internal"])
        .args(["--output"])
        .arg(&query_path)
        .output()
        .expect("run fresh query process");
    assert!(
        query.status.success(),
        "query: {}",
        String::from_utf8_lossy(&query.stderr)
    );
    let query = fs::read_to_string(query_path).expect("session query");
    assert!(query.contains("pcap-evidence.bgp.imported-session-query.v3"));
    let mut expected_query = Vec::new();
    reference
        .write_session_query_bounded_line(&session, &mut expected_query, 4 * 1024 * 1024)
        .expect("reference session-query serialization");
    assert_eq!(
        query.as_bytes(),
        expected_query,
        "fresh-process query preserves source-ordered candidates and reset provenance"
    );

    let export_path = scratch.file("export.ndjson");
    let exported = Command::new(env!("CARGO_BIN_EXE_pcap-depth"))
        .args(["bgp", "export"])
        .arg(&store)
        .args(["--peer-relationship", "internal"])
        .args(["--output"])
        .arg(&export_path)
        .output()
        .expect("run fresh export process");
    assert!(
        exported.status.success(),
        "export: {}",
        String::from_utf8_lossy(&exported.stderr)
    );
    let export = fs::read_to_string(export_path).expect("export stream");
    assert!(export.contains("pcap-evidence.bgp.export-header.v3"));
    assert!(export.contains("pcap-evidence.bgp.mrt-session-event.v1"));
    assert!(export.contains("pcap-evidence.bgp.bgp4mp-candidate.v1"));
    for event in &reference.bgp4mp_events {
        let expected_line = event.encode();
        assert!(
            export.lines().any(|line| line == expected_line),
            "fresh-process export retains event {}",
            field_number(event, "record_index").unwrap()
        );
    }
    for candidate in &reference.bgp4mp_candidates {
        let expected_line = candidate.json().encode();
        assert!(
            export.lines().any(|line| line == expected_line),
            "fresh-process export retains candidate from record {}",
            candidate.record_index
        );
    }
    assert_eq!(
        reference
            .state
            .observations()
            .iter()
            .filter(|observation| observation.import_boundary().is_some())
            .count(),
        2,
        "reference archive retains NOTIFICATION and terminal-reset boundaries"
    );
}

#[test]
fn reset_requires_fresh_open_evidence_and_extended_timestamp_offsets_are_full_width() {
    let scratch = Scratch::new();
    let mut after_reset = established_flow(1, false, 654_321);
    for (seconds, old, new) in [(80, 6, 1), (70, 1, 2), (60, 2, 4), (50, 4, 5), (40, 5, 6)] {
        after_reset.extend(state_record(
            Bgp4mpMetadata::new(2, 64_512, 64_513, 7),
            0,
            seconds,
            old,
            new,
        ));
    }
    after_reset.extend(message_record(
        MessageRecordMetadata::new(
            Bgp4mpMetadata::new(2, 64_512, 64_513, 7),
            17,
            1,
            20,
            Some(1_000_000),
            false,
        ),
        &update(2, false),
    ));
    let archive = import(&scratch.file("reset.mrt-store"), &after_reset, "reset");
    assert_eq!(archive.bgp4mp_candidates.len(), 1);
    assert_eq!(
        field_string(archive.bgp4mp_events.last().unwrap(), "parse_status"),
        Some("quarantined")
    );
    assert!(archive
        .bgp4mp_events
        .last()
        .unwrap()
        .encode()
        .contains("capability_context_unresolved"));

    for (index, microseconds) in [1_000_000, u32::MAX].into_iter().enumerate() {
        let bytes = established_flow(4, false, microseconds);
        let extended = import(
            &scratch.file(&format!("extended-{index}.mrt-store")),
            &bytes,
            &format!("extended-{index}"),
        );
        let candidate = &extended.bgp4mp_candidates[0];
        let expected = 30_000_000_000i64 + i64::from(microseconds) * 1_000;
        assert_eq!(candidate.observed_at_ns, Some(expected));
        assert_eq!(
            extended.batch().records[candidate.record_index]
                .time
                .microseconds,
            Some(microseconds)
        );
    }
}

#[test]
fn as_trans_open_is_compared_at_container_width_but_as4_subtype_conflict_is_quarantined() {
    let scratch = Scratch::new();
    let bytes = established_flow_with_as4_capability(1, false, 654_321, true);
    let archive = import(
        &scratch.file("as4-width-conflict.mrt-store"),
        &bytes,
        "as4-width",
    );

    assert!(archive.bgp4mp_candidates.is_empty());
    for open_event in &archive.bgp4mp_events[1..=2] {
        assert_eq!(
            field_string(open_event, "parse_status"),
            Some("decoded_open")
        );
        assert!(!open_event
            .encode()
            .contains("open_asn_disagrees_with_mrt_peer_metadata"));
    }
    assert!(archive
        .bgp4mp_events
        .last()
        .unwrap()
        .encode()
        .contains("container_asn_width_conflicts_with_bilateral_open"));
}
