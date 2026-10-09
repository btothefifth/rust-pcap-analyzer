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

// Mutate only independently encoded outer interface fields, including the
// initially unknown metadata: this creates two precise, distinct sessions.
fn feedback_interface(mut bytes: Vec<u8>, interface: u16) -> Vec<u8> {
    let mut at = 0;
    while at < bytes.len() {
        let length = u32::from_be_bytes(bytes[at + 8..at + 12].try_into().unwrap()) as usize;
        let et = usize::from(bytes[at + 5] == 17) * 4;
        let offset = at + 12 + et + 8;
        bytes[offset..offset + 2].copy_from_slice(&interface.to_be_bytes());
        at += 12 + length;
    }
    assert_eq!(at, bytes.len());
    bytes
}

fn feedback_three_peers() -> Vec<u8> {
    let mut sibling = feedback_interface(established_flow(4, false, 654_321), 9);
    rewrite_bgp4mp_fixture_peer_address(&mut sibling, [198, 51, 100, 3]);
    [
        feedback_interface(established_flow(4, false, 654_321), 7),
        feedback_interface(established_flow(4, false, 654_321), 8),
        sibling,
    ]
    .concat()
}

fn feedback_current_count(archive: &bgp_mrt_store::MrtReplayArchive, expected: usize) {
    use pcap_evidence_product::deep::bgp_rib::RouteStatus;
    assert_eq!(
        archive
            .bgp4mp_rib
            .entries()
            .values()
            .filter(|e| e.status == RouteStatus::Active)
            .count(),
        expected,
        "only scopes with established continuity are active"
    );
    assert!(archive
        .bgp4mp_rib
        .entries()
        .values()
        .all(|e| e.status != RouteStatus::Withdrawn));
}

fn feedback_fresh_selection(
    path: &std::path::Path,
    archive: &bgp_mrt_store::MrtReplayArchive,
    expected: usize,
) {
    use pcap_evidence_product::deep::bgp_persisted::{Query, VerifiedStore};
    let replay = bgp_mrt_store::replay(
        path,
        4 * 1024 * 1024,
        MrtLimits::default(),
        Limits::default(),
    )
    .unwrap();
    assert_eq!(archive.batch(), replay.batch());
    assert_eq!(archive.bgp4mp_events, replay.bgp4mp_events);
    assert_eq!(archive.bgp4mp_rib_json(None), replay.bgp4mp_rib_json(None));
    feedback_current_count(&replay, expected);
    let verified = VerifiedStore::load(
        path,
        4 * 1024 * 1024,
        MrtLimits::default(),
        Limits::default(),
        bgp_mrt_store::MrtReplayOptions::default(),
    )
    .unwrap();
    let selection = verified
        .query(
            &Query {
                status: Some("active".into()),
                ..Query::default()
            },
            &Limits::default(),
        )
        .unwrap();
    assert_eq!(
        selection.matches("\"native_current\":true").count(),
        expected
    );
    let query_path = path.with_extension("active.json");
    let result = Command::new(env!("CARGO_BIN_EXE_pcap-depth"))
        .args(["bgp", "query"])
        .arg(path)
        .arg("--output")
        .arg(&query_path)
        .args([
            "--status",
            "active",
            "--max-journal-bytes",
            "4194304",
            "--max-output-bytes",
            "4194304",
        ])
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "fresh persisted query: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    let selection = fs::read_to_string(query_path).unwrap();
    assert_eq!(
        selection.matches("\"native_current\":true").count(),
        expected
    );
}

fn feedback_session_event(
    archive: &bgp_mrt_store::MrtReplayArchive,
    session: &str,
    event: &Json,
    included: bool,
) {
    let mut bytes = Vec::new();
    let size = archive
        .write_session_query_bounded_line(session, &mut bytes, 4 * 1024 * 1024)
        .unwrap();
    assert_eq!(size, bytes.len());
    assert_eq!(
        std::str::from_utf8(&bytes)
            .unwrap()
            .contains(&event.encode_bounded(1024 * 1024).unwrap()),
        included,
        "complete original event belongs only to each affected session"
    );
    let mut exact = Vec::new();
    assert_eq!(
        archive
            .write_session_query_bounded_line(session, &mut exact, size)
            .unwrap(),
        size
    );
    assert_eq!(exact, bytes);
    let mut short = Vec::new();
    assert!(archive
        .write_session_query_bounded_line(session, &mut short, size - 1)
        .is_err());
    assert!(short.is_empty(), "query preflight leaves no partial output");
}

fn assert_exact_negative_partition_cuts(
    archive: &bgp_mrt_store::MrtReplayArchive,
    expected_partitions: usize,
    expected_sessions: usize,
) {
    use std::collections::BTreeSet;
    let gaps = archive.bgp4mp_rib.gaps();
    assert_eq!(
        gaps.len(),
        expected_partitions,
        "negative evidence covers decoder-only and route-bearing exact partitions"
    );
    let partitions: BTreeSet<_> = gaps
        .iter()
        .map(|(scope, _)| {
            (
                &scope.source,
                &scope.session,
                scope.generation,
                scope.direction,
            )
        })
        .collect();
    assert_eq!(
        partitions.len(),
        expected_partitions,
        "no duplicate initial native cut"
    );
    let sessions: BTreeSet<_> = gaps.iter().map(|(scope, _)| &scope.session).collect();
    assert_eq!(
        sessions.len(),
        expected_sessions,
        "unrelated sessions remain outside the cut"
    );
    let record = archive.batch().records.last().unwrap();
    let witness = format!(
        "mrt-bgp4mp-quarantine:{}:{}",
        archive.batch().records.len() - 1,
        record.sha256
    );
    assert!(gaps.iter().all(|(scope, record_id)| scope.generation == 0
        && scope.direction.is_none()
        && record_id == &witness));
}

#[test]
fn feedback_identifiable_empty_and_one_byte_payloads_invalidate_only_their_peer() {
    use pcap_evidence_product::deep::bgp_rib::RouteStatus;
    let scratch = Scratch::new();
    for subtype in [1, 4, 6, 7, 8, 9, 10, 11] {
        let width = if matches!(subtype, 1 | 6 | 8 | 10) {
            2
        } else {
            4
        };
        let asn = if width == 2 { 64_512 } else { 65_551 };
        let flow_subtype = if width == 2 { 1 } else { 4 };
        let mut first = established_flow(flow_subtype, false, 654_321);
        let mut sibling = established_flow(flow_subtype, false, 654_321);
        // Address offset depends only on this independent outer layout.
        if width == 4 {
            rewrite_bgp4mp_fixture_peer_address(&mut sibling, [198, 51, 100, 3]);
        } else {
            let mut at = 0;
            while at < sibling.len() {
                let length =
                    u32::from_be_bytes(sibling[at + 8..at + 12].try_into().unwrap()) as usize;
                let et = usize::from(sibling[at + 5] == 17) * 4;
                sibling[at + 20 + et..at + 24 + et].copy_from_slice(&[198, 51, 100, 3]);
                at += 12 + length;
            }
        }
        first.extend(sibling);
        for (record_type, micros) in [(16, None), (17, Some(123_456))] {
            // One byte is the nearest contrast: deleting it cannot restore
            // continuity or promote a malformed container to successful BGP.
            for payload in [&[0xff][..], &[][..]] {
                let malformed = message_record(
                    MessageRecordMetadata::new(
                        Bgp4mpMetadata::new(width, asn, asn + 1, 7),
                        record_type,
                        subtype,
                        1,
                        micros,
                        false,
                    ),
                    payload,
                );
                let bytes = [first.clone(), malformed.clone()].concat();
                assert!(bytes.len() < 2048, "fixture storage preflight");
                let path = scratch.file(&format!(
                    "scope-{subtype}-{record_type}-{}.store",
                    payload.len()
                ));
                let archive = import(&path, &bytes, "feedback-empty");
                assert_eq!(archive.bgp4mp_candidates.len(), 2);
                assert_eq!(
                    archive.batch().records.last().unwrap().sha256,
                    sha256::hex(&sha256::digest(&malformed))
                );
                feedback_current_count(&archive, 1);
                let entries = archive.bgp4mp_rib.entries();
                assert!(entries.values().any(|e| e.status == RouteStatus::Active
                    && e.key.scope.peer.as_deref()
                        == Some(format!("{asn}@198.51.100.3").as_str())));
                assert!(entries.values().any(|e| e.status == RouteStatus::Unresolved
                    && e.key.scope.peer.as_deref()
                        == Some(format!("{asn}@198.51.100.1").as_str())));
                assert_exact_negative_partition_cuts(&archive, 2, 1);
                let event = archive.bgp4mp_events.last().unwrap();
                assert_eq!(field_string(event, "parse_status"), Some("rejected"));
                assert_eq!(
                    field_number(json_field(event, "record_range"), "start"),
                    Some(first.len() as u64)
                );
                assert_eq!(
                    field_number(json_field(event, "record_range"), "end"),
                    Some(bytes.len() as u64)
                );
                if payload.is_empty() {
                    assert_eq!(json_field(event, "message_range"), &Json::Null);
                    assert_eq!(
                        archive
                            .batch()
                            .bgp4mp_message_source_range(archive.batch().records.len() - 1)
                            .unwrap(),
                        None
                    );
                }
                assert_eq!(
                    archive.state.observations().len(),
                    2,
                    "no fabricated reset or withdrawal observation"
                );
                feedback_fresh_selection(&path, &archive, 1);
                if subtype == 4 && record_type == 16 {
                    let update = message_record(
                        MessageRecordMetadata::new(
                            Bgp4mpMetadata::new(4, 65_551, 65_552, 7),
                            16,
                            4,
                            0,
                            None,
                            false,
                        ),
                        &update(4, false),
                    );
                    let bytes = [bytes, update].concat();
                    let path =
                        scratch.file(&format!("missing-new-context-{}.store", payload.len()));
                    let archive = import(&path, &bytes, "feedback-empty");
                    assert_eq!(
                        archive.bgp4mp_candidates.len(),
                        2,
                        "a malformed frame clears old OPEN/FSM decoding evidence"
                    );
                    feedback_current_count(&archive, 1);
                    feedback_fresh_selection(&path, &archive, 1);
                }
            }
        }
    }
}

#[test]
fn feedback_unknown_interface_ambiguity_invalidates_all_compatible_real_scopes() {
    use pcap_evidence_product::deep::bgp_rib::RouteStatus;
    let scratch = Scratch::new();
    for state_change in [false, true] {
        let unknown = Bgp4mpMetadata::new(4, 65_551, 65_552, 0);
        let ambiguous = if state_change {
            state_record(unknown, 5, 1, 6, 1)
        } else {
            message_record(
                MessageRecordMetadata::new(unknown, 16, 4, 1, None, false),
                &bgp_message(4, &[]),
            )
        };
        let bytes = [feedback_three_peers(), ambiguous].concat();
        assert!(bytes.len() < 2048, "fixture storage preflight");
        let path = scratch.file(&format!("ambiguous-{state_change}.store"));
        let archive = import(&path, &bytes, "feedback-ambiguous");
        feedback_current_count(&archive, 1);
        assert_exact_negative_partition_cuts(&archive, 4, 2);
        assert_eq!(
            archive.state.observations().len(),
            3,
            "ambiguity cannot invent a reported reset or routes"
        );
        assert!(archive
            .bgp4mp_rib
            .entries()
            .values()
            .all(|e| e.key.scope.generation == 0));
        assert_eq!(
            archive
                .bgp4mp_rib
                .entries()
                .values()
                .filter(|e| e.status == RouteStatus::Unresolved)
                .count(),
            2
        );
        let last = archive.bgp4mp_events.last().unwrap();
        assert_eq!(
            field_string(last, "parse_status"),
            Some("quarantined_ambiguous_session")
        );
        let Json::Array(scopes) = json_field(json_field(last, "detail"), "affected_scopes") else {
            panic!("explicit real scopes");
        };
        assert_eq!(scopes.len(), 2);
        // Independent source-order mapping: six encoded records per flow,
        // with each final UPDATE at 5/11/17 on interfaces 7/8/9 respectively.
        for (record_index, interface, peer, affected) in [
            (5, 7, "65551@198.51.100.1", true),
            (11, 8, "65551@198.51.100.1", true),
            (17, 9, "65551@198.51.100.3", false),
        ] {
            let pcap_evidence_product::deep::bgp_mrt::MrtBody::Bgp4mp(outer) =
                &archive.batch().records[record_index].body
            else {
                panic!("encoded final UPDATE");
            };
            assert_eq!(outer.interface_index, interface);
            let candidate = archive
                .bgp4mp_candidates
                .iter()
                .find(|c| c.record_index == record_index)
                .unwrap();
            let entry = archive
                .bgp4mp_rib
                .entries()
                .values()
                .find(|e| e.key.scope.session == candidate.session)
                .unwrap();
            assert_eq!(entry.key.scope.peer.as_deref(), Some(peer));
            assert_eq!(entry.key.scope.generation, 0);
            assert_eq!(
                entry.status,
                if affected {
                    RouteStatus::Unresolved
                } else {
                    RouteStatus::Active
                }
            );
            assert_eq!(entry.versions.len(), 1);
            assert_eq!(entry.versions[0].witnesses.len(), 1);
            assert_eq!(
                scopes.iter().any(|scope| field_string(scope, "session")
                    == Some(candidate.session.as_str())
                    && field_number(scope, "generation") == Some(0)),
                affected
            );
            feedback_session_event(&archive, &candidate.session, last, affected);
        }
        let mut missing = Vec::new();
        assert!(archive
            .write_session_query_bounded_line(
                "missing-source-session",
                &mut missing,
                4 * 1024 * 1024
            )
            .is_err());
        assert!(missing.is_empty());
        feedback_fresh_selection(&path, &archive, 1);
    }
}

#[test]
fn feedback_repeated_ambiguity_precise_recovery_preserves_generation_predecessor() {
    use pcap_evidence_product::deep::bgp_rib::{RouteStatus, VersionDisposition};
    let scratch = Scratch::new();
    let unknown = Bgp4mpMetadata::new(4, 65_551, 65_552, 0);
    let ambiguity = message_record(
        MessageRecordMetadata::new(unknown, 16, 4, 1, None, false),
        &bgp_message(4, &[]),
    );
    let bytes = [
        feedback_three_peers(),
        ambiguity.clone(),
        ambiguity,
        feedback_interface(established_flow(4, false, 654_321), 7),
    ]
    .concat();
    assert!(bytes.len() < 2048, "fixture storage preflight");
    let path = scratch.file("precise-recovery.store");
    let archive = import(&path, &bytes, "feedback-recovery");
    feedback_current_count(&archive, 1);
    assert_eq!(archive.bgp4mp_rib.entries().len(), 3);
    assert!(archive
        .bgp4mp_rib
        .entries()
        .values()
        .all(|e| e.key.scope.generation == 0));
    assert_eq!(
        archive.state.observations().len(),
        4,
        "precise OPEN/FSM can recover decoding but cannot erase a generation gap"
    );
    assert_eq!(
        archive
            .bgp4mp_rib
            .entries()
            .values()
            .filter(|e| e.status == RouteStatus::Unresolved)
            .count(),
        2
    );
    let recovered = archive
        .bgp4mp_rib
        .entries()
        .values()
        .find(|e| e.versions.len() == 2)
        .unwrap();
    assert_eq!(
        recovered.versions[0].disposition,
        VersionDisposition::Replaced
    );
    feedback_fresh_selection(&path, &archive, 1);
    let reset = state_record(Bgp4mpMetadata::new(4, 65_551, 65_552, 7), 5, 0, 6, 1);
    let bytes = [bytes, reset].concat();
    let path = scratch.file("precise-reset.store");
    let archive = import(&path, &bytes, "feedback-recovery");
    feedback_current_count(&archive, 1);
    assert_eq!(archive.state.observations().len(), 5);
    assert_eq!(
        archive
            .bgp4mp_rib
            .entries()
            .values()
            .filter(|e| e.status == RouteStatus::Superseded)
            .count(),
        1
    );
    feedback_fresh_selection(&path, &archive, 1);
    let bytes = [
        bytes,
        state_record(Bgp4mpMetadata::new(4, 65_551, 65_552, 7), 5, 0, 1, 3),
        feedback_interface(established_flow(4, false, 654_321), 7),
    ]
    .concat();
    let path = scratch.file("next-generation-recovery.store");
    let archive = import(&path, &bytes, "feedback-recovery");
    feedback_current_count(&archive, 2);
    assert_eq!(archive.bgp4mp_rib.entries().len(), 4);
    assert_eq!(archive.state.observations().len(), 6);
    assert_eq!(
        archive
            .bgp4mp_rib
            .entries()
            .values()
            .filter(|e| e.key.scope.generation == 1 && e.status == RouteStatus::Active)
            .count(),
        1
    );
    feedback_fresh_selection(&path, &archive, 2);
}

#[test]
fn feedback_unidentifiable_malformed_records_expose_conservative_coverage_gap() {
    let scratch = Scratch::new();
    for (case, record) in [
        ("preamble", mrt_record(0, 16, 4, &[0, 1, 2])),
        ("et-zero", mrt_record(0, 17, 4, &[])),
        ("et-three", mrt_record(0, 17, 4, &[0, 1, 2])),
    ] {
        let bytes = [feedback_three_peers(), record.clone()].concat();
        assert!(bytes.len() < 2048, "fixture storage preflight");
        let path = scratch.file(&format!("unknown-{case}.store"));
        let archive = import(&path, &bytes, "feedback-coverage");
        feedback_current_count(&archive, 0);
        assert_exact_negative_partition_cuts(&archive, 6, 3);
        assert_eq!(archive.state.observations().len(), 3);
        assert!(archive
            .bgp4mp_rib
            .entries()
            .values()
            .all(|e| e.key.scope.generation == 0));
        let event = archive.bgp4mp_events.last().unwrap();
        assert_eq!(
            field_string(event, "parse_status"),
            Some("quarantined_coverage_unknown")
        );
        assert_eq!(
            json_field(event, "session"),
            &Json::Null,
            "no invented peer identity"
        );
        assert_eq!(json_field(event, "message_range"), &Json::Null);
        let Json::Array(scopes) = json_field(json_field(event, "detail"), "affected_scopes") else {
            panic!("tracked coverage scopes");
        };
        assert_eq!(scopes.len(), 3);
        for entry in archive.bgp4mp_rib.entries().values() {
            feedback_session_event(&archive, &entry.key.scope.session, event, true);
        }
        assert_eq!(
            field_string(event, "record_sha256"),
            Some(sha256::hex(&sha256::digest(&record)).as_str())
        );
        feedback_fresh_selection(&path, &archive, 0);
        // A session first observed later does not inherit the earlier event.
        let mut later_peer = feedback_interface(established_flow(4, false, 654_321), 9);
        rewrite_bgp4mp_fixture_peer_address(&mut later_peer, [198, 51, 100, 4]);
        let bytes = [bytes, later_peer].concat();
        let path = scratch.file(&format!("unknown-{case}-later-peer.store"));
        let later = import(&path, &bytes, "feedback-coverage");
        let later_session = &later
            .bgp4mp_rib
            .entries()
            .values()
            .find(|entry| entry.key.scope.peer.as_deref() == Some("65551@198.51.100.4"))
            .unwrap()
            .key
            .scope
            .session;
        feedback_session_event(&later, later_session, event, false);
        feedback_fresh_selection(&path, &later, 1);
    }
}

#[test]
fn feedback_malformed_state_metadata_is_scoped_and_unsupported_opaque_is_excluded() {
    let scratch = Scratch::new();
    let metadata = Bgp4mpMetadata::new(4, 65_551, 65_552, 7);
    for payload in [&[][..], &[0][..], &[0, 6, 0][..], &[0, 6, 0, 1, 0][..]] {
        let malformed = message_record(
            MessageRecordMetadata::new(metadata, 16, 5, 0, None, false),
            payload,
        );
        let bytes = [feedback_three_peers(), malformed].concat();
        let path = scratch.file(&format!("state-malformed-{}.store", payload.len()));
        let archive = import(&path, &bytes, "feedback-state");
        feedback_current_count(&archive, 2);
        assert_exact_negative_partition_cuts(&archive, 2, 1);
        assert_eq!(archive.state.observations().len(), 3);
        feedback_fresh_selection(&path, &archive, 2);
    }
    let mut unsupported_afi = message_record(
        MessageRecordMetadata::new(metadata, 16, 4, 0, None, false),
        &[],
    );
    unsupported_afi[22..24].copy_from_slice(&25u16.to_be_bytes());
    for (case, unsupported) in [
        ("subtype", mrt_record(0, 16, 12, &[0])),
        ("afi", unsupported_afi),
        ("unrelated", mrt_record(0, 999, 1, &[0])),
    ] {
        let bytes = [feedback_three_peers(), unsupported].concat();
        let path = scratch.file(&format!("unsupported-{case}.store"));
        let archive = import(&path, &bytes, "feedback-unsupported");
        feedback_current_count(&archive, 3);
        assert!(archive.bgp4mp_rib.gaps().is_empty());
        assert_eq!(archive.bgp4mp_events.len(), 18);
        feedback_fresh_selection(&path, &archive, 3);
    }
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
    let Json::Object(envelope) = observation.normalized() else {
        panic!("envelope")
    };
    let Json::Array(routes) = &envelope.iter().find(|(key, _)| *key == "routes").unwrap().1 else {
        panic!("routes")
    };
    let Json::Object(route) = &routes[0] else {
        panic!("route")
    };
    let carrier = &route
        .iter()
        .find(|(key, _)| *key == "imported_attribute_occurrences")
        .unwrap()
        .1;
    let withdrawn_length = usize::from(u16::from_be_bytes([exact_message[19], exact_message[20]]));
    let attribute_length_start = 21 + withdrawn_length;
    let attribute_start = attribute_length_start + 2;
    let attribute_end = attribute_start
        + usize::from(u16::from_be_bytes([
            exact_message[attribute_length_start],
            exact_message[attribute_length_start + 1],
        ]));
    assert_eq!(
        field_string(carrier, "message_prefix_hex"),
        Some(sha256::hex(&exact_message[..attribute_start]).as_str())
    );
    assert_eq!(
        field_string(carrier, "message_suffix_hex"),
        Some(sha256::hex(&exact_message[attribute_end..]).as_str())
    );
    assert_eq!(
        field_number(carrier, "message_length"),
        Some(exact_message.len() as u64)
    );
    assert_eq!(
        field_string(carrier, "message_sha256"),
        Some(candidate.message_sha256.as_str())
    );

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
        .contains("pcap-evidence.bgp.mrt-replay.v4"));

    let mut query = Vec::new();
    archive
        .write_session_query_bounded_line(&candidate.session, &mut query, 1024 * 1024)
        .expect("session query includes imported BGP4MP candidates");
    let query = String::from_utf8(query).expect("query UTF-8");
    assert!(query.contains("pcap-evidence.bgp.imported-session-query.v4"));
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
    use pcap_evidence_product::deep::bgp_rib::RouteStatus;
    assert_eq!(archive.bgp4mp_rib.entries().len(), 2);
    assert_eq!(
        archive
            .bgp4mp_rib
            .entries()
            .values()
            .filter(|entry| entry.status == RouteStatus::Active)
            .count(),
        1
    );
    assert_eq!(
        archive
            .bgp4mp_rib
            .entries()
            .values()
            .filter(|entry| entry.status == RouteStatus::Superseded)
            .count(),
        1
    );

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
    let bytes = continuity_internal_cli_fixture();
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
    assert!(state.contains("pcap-evidence.bgp.mrt-replay.v4"));
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
    assert!(query.contains("pcap-evidence.bgp.imported-session-query.v4"));
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
    assert!(export.contains("pcap-evidence.bgp.export-header.v4"));
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

    for (index, microseconds) in [0, 999_999, 1_000_000, u32::MAX].into_iter().enumerate() {
        let bytes = established_flow(4, false, microseconds);
        let extended = import(
            &scratch.file(&format!("extended-{index}.mrt-store")),
            &bytes,
            &format!("extended-{index}"),
        );
        let candidate = &extended.bgp4mp_candidates[0];
        let expected =
            (microseconds < 1_000_000).then(|| 30_000_000_000i64 + i64::from(microseconds) * 1_000);
        assert_eq!(candidate.observed_at_ns, expected);
        assert_eq!(
            extended
                .bgp4mp_events
                .last()
                .unwrap()
                .encode()
                .contains("invalid_mrt_record_timestamp"),
            expected.is_none(),
        );
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

// RFC 4271 UPDATE arithmetic is built here independently: a withdrawn /24
// occupies four bytes, with no path attributes and no trailing announcement.
fn withdrawal(path_id: Option<u32>) -> Vec<u8> {
    let mut withdrawn = Vec::new();
    if let Some(path_id) = path_id {
        withdrawn.extend_from_slice(&path_id.to_be_bytes());
    }
    withdrawn.extend_from_slice(&[24, 198, 51, 100]);
    let mut payload = (withdrawn.len() as u16).to_be_bytes().to_vec();
    payload.extend(withdrawn);
    payload.extend_from_slice(&[0, 0]);
    bgp_message(2, &payload)
}

#[test]
fn imported_rib_replaces_withdraws_and_reannounces_in_file_order() {
    use pcap_evidence_product::deep::bgp_rib::{RouteStatus, VersionDisposition};
    let scratch = Scratch::new();
    let metadata = Bgp4mpMetadata::new(4, 65_551, 65_552, 7);
    let mut bytes = established_flow(4, false, 654_321);
    let mut replacement = update(4, false);
    let nh = replacement
        .windows(7)
        .position(|window| window == [0x40, 3, 4, 192, 0, 2, 9])
        .unwrap();
    replacement[nh + 6] = 10;
    let wrap = |seconds, message: &[u8]| {
        message_record(
            MessageRecordMetadata::new(metadata, 16, 4, seconds, None, false),
            message,
        )
    };
    bytes.extend(wrap(20, &replacement));
    let archive = import(&scratch.file("replaced.store"), &bytes, "replacement");
    let entry = archive.bgp4mp_rib.entries().values().next().unwrap();
    assert_eq!(entry.status, RouteStatus::Active);
    assert_eq!(entry.versions.len(), 2);
    assert_eq!(entry.versions[0].disposition, VersionDisposition::Replaced);
    assert_eq!(entry.versions[1].disposition, VersionDisposition::Current);
    assert_eq!(
        json_field(&entry.versions[1].attributes, "next_hop"),
        &Json::String("192.0.2.10".into())
    );
    bytes.extend(wrap(10, &withdrawal(None)));
    let archive = import(&scratch.file("withdrawn.store"), &bytes, "withdrawal");
    let entry = archive.bgp4mp_rib.entries().values().next().unwrap();
    assert_eq!(entry.status, RouteStatus::Withdrawn);
    assert!(entry
        .versions
        .iter()
        .all(|version| version.disposition != VersionDisposition::Current));
    bytes.extend(wrap(1, &update(4, false)));
    let path = scratch.file("reannounced.store");
    let archive = import(&path, &bytes, "reannouncement");
    let entry = archive.bgp4mp_rib.entries().values().next().unwrap();
    assert_eq!(entry.status, RouteStatus::Active);
    assert_eq!(entry.versions.len(), 3);
    assert_eq!(archive.bgp4mp_candidates.len(), 4);
    let replay = bgp_mrt_store::replay(
        &path,
        4 * 1024 * 1024,
        MrtLimits::default(),
        Limits::default(),
    )
    .unwrap();
    assert_eq!(archive.bgp4mp_rib_json(None), replay.bgp4mp_rib_json(None));
    assert_eq!(archive.state.observations().len(), 4);
}

#[test]
fn malformed_complete_bgp4mp_messages_remain_sealed_and_quarantine_only_their_session() {
    use pcap_evidence_product::deep::bgp_rib::RouteStatus;
    let scratch = Scratch::new();
    let metadata = Bgp4mpMetadata::new(4, 65_551, 65_552, 7);
    let mut first = established_flow(4, false, 654_321);
    let mut sibling = established_flow(4, false, 654_321);
    rewrite_bgp4mp_fixture_peer_address(&mut sibling, [198, 51, 100, 3]);
    first.extend(sibling);
    for (case, malformed) in [
        ("marker", {
            let mut v = update(4, false);
            v[0] = 0;
            v
        }),
        ("length", {
            let mut v = update(4, false);
            v[17] = 19;
            v
        }),
        ("short", vec![0xff; 7]),
    ] {
        let mut bytes = first.clone();
        let exact_record = message_record(
            MessageRecordMetadata::new(metadata, 16, 4, 1, None, false),
            &malformed,
        );
        let record_start = bytes.len();
        bytes.extend(&exact_record);
        let path = scratch.file(&format!("{case}.store"));
        let archive = import(&path, &bytes, case);
        assert_eq!(archive.bgp4mp_candidates.len(), 2);
        let last = archive.bgp4mp_events.last().unwrap();
        assert_eq!(field_string(last, "parse_status"), Some("rejected"));
        assert_eq!(
            field_number(last, "record_offset"),
            Some(record_start as u64)
        );
        let range = json_field(last, "message_range");
        let start = field_number(range, "start").unwrap() as usize;
        let end = field_number(range, "end").unwrap() as usize;
        assert_eq!(&bytes[start..end], malformed);
        assert_eq!(
            field_string(range, "sha256"),
            Some(sha256::hex(&sha256::digest(&malformed)).as_str())
        );
        assert_exact_negative_partition_cuts(&archive, 2, 1);
        assert_eq!(
            archive
                .bgp4mp_rib
                .entries()
                .values()
                .filter(|entry| entry.status == RouteStatus::Active)
                .count(),
            1
        );
        assert_eq!(
            archive
                .bgp4mp_rib
                .entries()
                .values()
                .filter(|entry| entry.status == RouteStatus::Unresolved)
                .count(),
            1
        );
        let replay = bgp_mrt_store::replay(
            &path,
            4 * 1024 * 1024,
            MrtLimits::default(),
            Limits::default(),
        )
        .unwrap();
        assert_eq!(archive.bgp4mp_rib_json(None), replay.bgp4mp_rib_json(None));
        let mut altered = fs::read(&path).unwrap();
        let location = altered
            .windows(exact_record.len())
            .position(|window| window == exact_record)
            .unwrap();
        altered[location + exact_record.len() - 1] ^= 1;
        let corrupt = scratch.file(&format!("{case}-corrupt.store"));
        fs::write(&corrupt, altered).unwrap();
        assert!(bgp_mrt_store::replay(
            &corrupt,
            4 * 1024 * 1024,
            MrtLimits::default(),
            Limits::default()
        )
        .is_err());
    }
}

#[test]
fn malformed_bgp4mp_preamble_and_empty_message_retain_exact_opaque_record() {
    use pcap_evidence_product::deep::bgp_mrt::MrtBody;
    let scratch = Scratch::new();
    let metadata = Bgp4mpMetadata::new(4, 65_551, 65_552, 7);
    for (case, bytes) in [
        ("preamble", mrt_record(0, 16, 4, &[0, 1, 2])),
        ("et-zero", mrt_record(0, 17, 4, &[])),
        ("et-one", mrt_record(0, 17, 4, &[0])),
        ("et-two", mrt_record(0, 17, 4, &[0, 1])),
        ("et-three", mrt_record(0, 17, 4, &[0, 1, 2])),
        (
            "empty",
            message_record(
                MessageRecordMetadata::new(metadata, 16, 4, 0, None, false),
                &[],
            ),
        ),
    ] {
        let path = scratch.file(&format!("{case}.store"));
        let malformed_end = bytes.len();
        let adjacent = state_record(metadata, 5, 1, 1, 2);
        let bytes = [bytes, adjacent].concat();
        let archive = import(&path, &bytes, case);
        let MrtBody::Opaque {
            reason,
            bytes: retained,
        } = &archive.batch().records[0].body
        else {
            panic!("malformed record remains opaque");
        };
        assert_eq!(*reason, "malformed_bgp4mp_record");
        assert_eq!(retained, &bytes[12..malformed_end]);
        assert!(
            matches!(archive.batch().records[1].body, MrtBody::Bgp4mp(_)),
            "adjacent valid record survives opaque retention"
        );
        assert_eq!(archive.opaque_records, 1);
        assert!(archive.bgp4mp_rib.entries().is_empty());
        let replay = bgp_mrt_store::replay(
            &path,
            4 * 1024 * 1024,
            MrtLimits::default(),
            Limits::default(),
        )
        .unwrap();
        assert_eq!(archive.batch(), replay.batch());
        // The outer MRT framing still refuses partial declared records.
        assert!(pcap_evidence_product::deep::bgp_mrt::MrtBatch::parse(
            &bytes[..bytes.len() - 1],
            source(case),
            &MrtLimits::default()
        )
        .is_err());
    }
}

#[test]
fn imported_eor_retains_own_family_and_generation_without_routes_or_sibling_effects() {
    use pcap_evidence_product::deep::bgp_rib::RouteStatus;
    let scratch = Scratch::new();
    let metadata = Bgp4mpMetadata::new(4, 65_551, 65_552, 7);
    let mut bytes = established_flow(4, false, 654_321);
    let mut sibling = established_flow(4, false, 654_321);
    rewrite_bgp4mp_fixture_peer_address(&mut sibling, [198, 51, 100, 3]);
    bytes.extend(sibling);
    let wrap = |message: &[u8]| {
        message_record(
            MessageRecordMetadata::new(metadata, 16, 4, 1, None, false),
            message,
        )
    };
    bytes.extend(wrap(&bgp_message(2, &[0, 0, 0, 0])));
    let archive = import(&scratch.file("eor.store"), &bytes, "eor");
    assert_eq!(archive.bgp4mp_candidates.len(), 2);
    assert_eq!(archive.bgp4mp_rib.eors().len(), 1);
    let eor = &archive.bgp4mp_rib.eors()[0];
    assert_eq!(
        (eor.family.afi, eor.family.safi, eor.scope.generation),
        (1, 1, 0)
    );
    assert_eq!(eor.scope.session, archive.bgp4mp_candidates[0].session);
    assert_ne!(eor.scope.session, archive.bgp4mp_candidates[1].session);
    assert!(archive
        .state
        .observations()
        .last()
        .unwrap()
        .routes()
        .is_empty());
    assert!(archive
        .bgp4mp_rib
        .entries()
        .values()
        .all(|entry| entry.status == RouteStatus::Active));

    // Raw MP_UNREACH has an unsupported AFI/SAFI immediately next to the
    // supported IPv4 EOR. It cannot become a supported-family marker.
    bytes.extend(wrap(&bgp_message(2, &[0, 0, 0, 6, 0x80, 15, 3, 0, 25, 70])));
    let archive = import(
        &scratch.file("unsupported-eor.store"),
        &bytes,
        "unsupported-eor",
    );
    assert_eq!(archive.bgp4mp_rib.eors().len(), 1);
    assert_eq!(archive.bgp4mp_candidates.len(), 2);

    // An Idle boundary retires exactly its own generation. An UPDATE before
    // the next bilateral OPEN/Established evidence cannot create a new EOR.
    bytes.extend(state_record(metadata, 5, 0, 6, 1));
    bytes.extend(wrap(&bgp_message(2, &[0, 0, 0, 0])));
    let archive = import(
        &scratch.file("reset-before-eor.store"),
        &bytes,
        "reset-before-eor",
    );
    assert_eq!(archive.bgp4mp_rib.eors().len(), 1);
    assert_eq!(archive.bgp4mp_rib.eors()[0].scope.generation, 0);
    assert_eq!(
        archive
            .bgp4mp_rib
            .entries()
            .values()
            .filter(|entry| entry.status == RouteStatus::Active)
            .count(),
        1
    );
    assert_eq!(
        archive
            .bgp4mp_rib
            .entries()
            .values()
            .filter(|entry| entry.status == RouteStatus::Superseded)
            .count(),
        1
    );
}

#[test]
fn imported_session_rib_exact_output_and_store_limits_fail_before_publication() {
    let scratch = Scratch::new();
    let bytes = two_generation_fixture();
    let reference_path = scratch.file("reference.store");
    let reference = import(&reference_path, &bytes, "limits");
    let output_bytes = reference.encoded_len_bounded(4 * 1024 * 1024).unwrap();
    let store_bytes = fs::metadata(&reference_path).unwrap().len();
    let exact_path = scratch.file("exact.store");
    let exact = bgp_mrt_store::create(
        &exact_path,
        &bytes,
        source("limits"),
        store_bytes,
        MrtLimits::default(),
        Limits {
            output_bytes,
            ..Limits::default()
        },
    )
    .unwrap();
    assert_eq!(exact.bgp4mp_rib_json(None), reference.bgp4mp_rib_json(None));
    assert_eq!(fs::metadata(&exact_path).unwrap().len(), store_bytes);
    let replay = bgp_mrt_store::replay(
        &exact_path,
        store_bytes,
        MrtLimits::default(),
        Limits {
            output_bytes,
            ..Limits::default()
        },
    )
    .unwrap();
    assert_eq!(
        replay.bgp4mp_rib_json(None),
        reference.bgp4mp_rib_json(None)
    );
    for (case, retained_bytes, work) in [
        (
            "retained-below-native-state",
            reference.bgp4mp_rib.retained_bytes() - 1,
            Limits::default().work,
        ),
        (
            "work-below-native-state",
            Limits::default().retained_bytes,
            reference.bgp4mp_rib.accounted_work() - 1,
        ),
    ] {
        let path = scratch.file(case);
        assert!(bgp_mrt_store::create(
            &path,
            &bytes,
            source("limits"),
            store_bytes,
            MrtLimits::default(),
            Limits {
                retained_bytes,
                work,
                output_bytes,
                ..Limits::default()
            },
        )
        .is_err());
        assert!(!path.exists(), "resource refusal must precede publication");
    }
    for (case, maximum, output_cap) in [
        ("output-below", store_bytes, output_bytes - 1),
        ("store-below", store_bytes - 1, output_bytes),
    ] {
        let path = scratch.file(case);
        assert!(bgp_mrt_store::create(
            &path,
            &bytes,
            source("limits"),
            maximum,
            MrtLimits::default(),
            Limits {
                output_bytes: output_cap,
                ..Limits::default()
            }
        )
        .is_err());
        assert!(
            !path.exists(),
            "budget failure must precede destination creation"
        );
    }
    let mut exact_line = Vec::new();
    reference
        .write_bounded_line(&mut exact_line, output_bytes + 1)
        .unwrap();
    assert_eq!(exact_line.len(), output_bytes + 1);
    let mut unpublished = Vec::new();
    assert!(reference
        .write_bounded_line(&mut unpublished, output_bytes)
        .is_err());
    assert!(unpublished.is_empty());
    let rib_line = reference
        .bgp4mp_rib_json(None)
        .encode_bounded_line(4 * 1024 * 1024)
        .unwrap();
    let mut streamed_rib = Vec::new();
    reference
        .write_bgp4mp_rib_bounded_line(None, &mut streamed_rib, rib_line.len())
        .unwrap();
    assert_eq!(
        streamed_rib,
        rib_line.as_bytes(),
        "typed RIB stream preserves exact projection bytes"
    );
    for cap in [rib_line.len() - 1, 1] {
        let mut unpublished = Vec::new();
        assert!(reference
            .write_bgp4mp_rib_bounded_line(None, &mut unpublished, cap)
            .is_err());
        assert!(unpublished.is_empty(), "RIB preflight precedes all output");
    }
    let session = reference.bgp4mp_candidates[0].session.clone();
    let mut query = Vec::new();
    reference
        .write_session_query_bounded_line(&session, &mut query, 4 * 1024 * 1024)
        .unwrap();
    let mut exact_query = Vec::new();
    reference
        .write_session_query_bounded_line(&session, &mut exact_query, query.len())
        .unwrap();
    assert_eq!(exact_query, query);
    let mut unpublished = Vec::new();
    assert!(reference
        .write_session_query_bounded_line(&session, &mut unpublished, query.len() - 1)
        .is_err());
    assert!(unpublished.is_empty());
}

#[test]
fn cli_malformed_source_roundtrip_keeps_exact_ranges_and_quarantined_rib() {
    let scratch = Scratch::new();
    let metadata = Bgp4mpMetadata::new(4, 65_551, 65_552, 7);
    let mut bytes = established_flow(4, false, 654_321);
    let malformed = vec![0xff; 7];
    bytes.extend(message_record(
        MessageRecordMetadata::new(metadata, 16, 4, 1, None, false),
        &malformed,
    ));
    let source_path = scratch.file("malformed.mrt");
    fs::write(&source_path, &bytes).unwrap();
    let workspace = scratch.file("workspace");
    let output = Command::new(env!("CARGO_BIN_EXE_pcap-depth"))
        .args(["bgp", "import-mrt"])
        .arg(&source_path)
        .arg("--workspace")
        .arg(&workspace)
        .args([
            "--source-id",
            "collector-fixture-a",
            "--checkpoint",
            "malformed-cli",
            "--max-mrt-bytes",
            "65536",
            "--max-journal-bytes",
            "65536",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "import: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let store = workspace.join("bgp.mrt");
    let reference =
        bgp_mrt_store::replay(&store, 65536, MrtLimits::default(), Limits::default()).unwrap();
    let session = reference.bgp4mp_candidates[0].session.clone();
    let malformed_digest = sha256::hex(&sha256::digest(&malformed));
    for command in ["state", "replay", "query", "export"] {
        let path = scratch.file(&format!("{command}.json"));
        let mut child = Command::new(env!("CARGO_BIN_EXE_pcap-depth"));
        child
            .args(["bgp", command])
            .arg(&store)
            .arg("--output")
            .arg(&path)
            .args([
                "--max-journal-bytes",
                "65536",
                "--max-output-bytes",
                "1048576",
            ]);
        if command == "query" {
            child.arg("--session").arg(&session);
        }
        let output = child.output().unwrap();
        assert!(
            output.status.success(),
            "{command}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let report = fs::read_to_string(path).unwrap();
        assert!(
            report.contains(&malformed_digest),
            "{command} preserves malformed exact message binding"
        );
        assert!(report.contains("\"parse_status\":\"rejected\""));
        assert!(report.contains("\"source_authenticated\":false"));
        assert!(
            report.contains("\"status\":\"unresolved\""),
            "{command} retains native session uncertainty"
        );
    }
}

fn continuity_internal_update(local_pref: bool) -> Vec<u8> {
    let mut wire = update(4, false);
    if local_pref {
        let attrs = u16::from_be_bytes([wire[21], wire[22]]) as usize;
        wire.splice(23 + attrs..23 + attrs, [0x40, 5, 4, 0, 0, 0, 100]);
        wire[21..23].copy_from_slice(&((attrs + 7) as u16).to_be_bytes());
        let length = wire.len() as u16;
        wire[16..18].copy_from_slice(&length.to_be_bytes());
    }
    wire
}
fn continuity_internal_message(interface: u16, local_pref: bool) -> Vec<u8> {
    message_record(
        MessageRecordMetadata::new(
            Bgp4mpMetadata::new(4, 65_551, 65_552, interface),
            16,
            4,
            31,
            None,
            false,
        ),
        &continuity_internal_update(local_pref),
    )
}
fn continuity_internal_flow(interface: u16, prior: bool) -> Vec<u8> {
    let metadata = Bgp4mpMetadata::new(4, 65_551, 65_552, interface);
    let mut bytes = state_record(metadata, 5, 1, 2, 4);
    for local in [false, true] {
        bytes.extend(message_record(
            MessageRecordMetadata::new(metadata, 16, 4, 2, None, local),
            &open(
                if local { 65_552 } else { 65_551 },
                true,
                [198, 51, 100, if local { 2 } else { 1 }],
            ),
        ));
    }
    bytes.extend(state_record(metadata, 5, 3, 4, 5));
    bytes.extend(state_record(metadata, 5, 4, 5, 6));
    if prior {
        bytes.extend(continuity_internal_message(interface, true));
    }
    bytes
}

#[test]
fn opaque_internal_update_preserves_mrt_gap_evidence_and_fresh_policy_currency() {
    use pcap_evidence_product::deep::{
        bgp::PeerRelationship,
        bgp_persisted::{PolicyProfile, Query, VerifiedStore},
        bgp_rib::RouteStatus,
    };
    let options = bgp_mrt_store::MrtReplayOptions {
        peer_relationship: Some(PeerRelationship::Internal),
    };
    for prior in [false, true] {
        for recover in [false, true] {
            let scratch = Scratch::new();
            let path = scratch.file("opaque.mrt");
            let mut bytes = continuity_internal_flow(7, prior);
            bytes.extend(continuity_internal_flow(8, true));
            bytes.extend(continuity_internal_message(7, false));
            bytes.extend(continuity_internal_message(7, true));
            if recover {
                bytes.extend(state_record(
                    Bgp4mpMetadata::new(4, 65_551, 65_552, 7),
                    5,
                    32,
                    6,
                    1,
                ));
                bytes.extend(state_record(
                    Bgp4mpMetadata::new(4, 65_551, 65_552, 7),
                    5,
                    33,
                    1,
                    2,
                ));
                bytes.extend(continuity_internal_flow(7, true));
            }
            let archive = bgp_mrt_store::create_with_options(
                &path,
                &bytes,
                source("opaque-continuity"),
                4 * 1024 * 1024,
                MrtLimits::default(),
                Limits::default(),
                options,
            )
            .unwrap();
            assert_eq!(
                archive.bgp4mp_rib.gaps().len(),
                1,
                "prior={prior} recover={recover}"
            );
            assert_eq!(
                archive
                    .bgp4mp_rib
                    .entries()
                    .values()
                    .filter(|e| e.status == RouteStatus::Active)
                    .count(),
                1 + usize::from(recover)
            );
            assert!(archive
                .bgp4mp_rib
                .entries()
                .values()
                .all(|e| e.status != RouteStatus::Withdrawn));
            let opaque = archive
                .state
                .observations()
                .iter()
                .find(|o| {
                    o.normalized()
                        .encode()
                        .contains("internal_local_pref_missing_route")
                })
                .expect("opaque UPDATE remains journal evidence");
            assert!(opaque.routes().is_empty());
            assert!(opaque
                .normalized()
                .encode()
                .contains("\"internal_local_pref_missing\":true"));
            let session = opaque.source().session.clone().unwrap();
            let replay = bgp_mrt_store::replay_with_options(
                &path,
                4 * 1024 * 1024,
                MrtLimits::default(),
                Limits::default(),
                options,
            )
            .unwrap();
            assert_eq!(archive.bgp4mp_rib_json(None), replay.bgp4mp_rib_json(None));
            assert_eq!(archive.state.encode(), replay.state.encode());
            let verified = VerifiedStore::load(
                &path,
                4 * 1024 * 1024,
                MrtLimits::default(),
                Limits::default(),
                options,
            )
            .unwrap();
            let output = verified
                .query(
                    &Query {
                        status: Some("active".into()),
                        ..Query::default()
                    },
                    &Limits::default(),
                )
                .unwrap();
            assert_eq!(
                output.matches("\"native_current\":true").count(),
                1 + usize::from(recover),
                "{output}"
            );
            let profile = PolicyProfile::parse(b"schema=pcap-evidence.bgp.persisted-policy.v1\nprovenance=synthetic-owner\ncomparison_context=fixture\nmissing_local_preference=100\nmed_rule=skip\nage_rule=skip\n", &Limits::default()).unwrap();
            let policy = verified
                .policy(
                    &Query {
                        session: Some(session),
                        ..Query::default()
                    },
                    &profile,
                    &Limits::default(),
                )
                .unwrap();
            assert_eq!(policy.contains("\"selected\":\""), recover, "{policy}");
        }
    }
}

#[test]
fn opaque_mrt_multiprotocol_payload_and_stronger_dispositions_keep_distinct_semantics() {
    use pcap_evidence_product::deep::{bgp::PeerRelationship, bgp_rib::RouteStatus};
    let options = bgp_mrt_store::MrtReplayOptions {
        peer_relationship: Some(PeerRelationship::Internal),
    };
    let mut malformed = continuity_internal_update(false);
    malformed[26] = 3; // Invalid ORIGIN plus known announcement: treat-as-withdraw.
    for (wire, gap, status) in [
        (
            bgp_message(2, &[0, 0, 0, 6, 0x80, 15, 3, 0, 25, 70]),
            0,
            RouteStatus::Active,
        ),
        (
            bgp_message(2, &[0, 0, 0, 7, 0x80, 15, 4, 0, 25, 70, 0]),
            1,
            RouteStatus::Unresolved,
        ),
        (
            continuity_opaque_mp_reach(false),
            1,
            RouteStatus::Unresolved,
        ),
        (continuity_opaque_mp_reach(true), 1, RouteStatus::Unresolved),
        (malformed, 0, RouteStatus::Withdrawn),
    ] {
        let scratch = Scratch::new();
        let mut bytes = continuity_internal_flow(7, true);
        bytes.extend(message_record(
            MessageRecordMetadata::new(
                Bgp4mpMetadata::new(4, 65_551, 65_552, 7),
                16,
                4,
                31,
                None,
                false,
            ),
            &wire,
        ));
        let archive = bgp_mrt_store::create_with_options(
            &scratch.file("dispositions.mrt"),
            &bytes,
            source("continuity"),
            4 * 1024 * 1024,
            MrtLimits::default(),
            Limits::default(),
            options,
        )
        .unwrap();
        assert_eq!(archive.bgp4mp_rib.gaps().len(), gap);
        assert_eq!(
            archive.bgp4mp_rib.entries().values().next().unwrap().status,
            status
        );
    }
}

fn continuity_opaque_mp_reach(conventional: bool) -> Vec<u8> {
    let mut wire = continuity_internal_update(true);
    let attrs = u16::from_be_bytes([wire[21], wire[22]]) as usize;
    let mp = [0x80, 14, 13, 0, 1, 1, 4, 192, 0, 2, 9, 0, 24, 198, 51, 100];
    wire.splice(23 + attrs..23 + attrs, mp);
    wire[21..23].copy_from_slice(&((attrs + mp.len()) as u16).to_be_bytes());
    if !conventional {
        wire.truncate(23 + attrs + mp.len());
    }
    let length = wire.len() as u16;
    wire[16..18].copy_from_slice(&length.to_be_bytes());
    wire
}

// This CLI witness explicitly requests internal replay and must therefore
// supply LOCAL_PREF on both generations' valid announcements.
fn continuity_internal_cli_fixture() -> Vec<u8> {
    let mut bytes = two_generation_fixture();
    let mut at = 0;
    while at < bytes.len() {
        let record_type = u16::from_be_bytes(bytes[at + 4..at + 6].try_into().unwrap());
        let subtype = u16::from_be_bytes(bytes[at + 6..at + 8].try_into().unwrap());
        let mut body_length =
            u32::from_be_bytes(bytes[at + 8..at + 12].try_into().unwrap()) as usize;
        if matches!(subtype, 4 | 7) {
            let message = at + 12 + usize::from(record_type == 17) * 4 + 20;
            if bytes[message + 18] == 2 {
                let attrs =
                    u16::from_be_bytes(bytes[message + 21..message + 23].try_into().unwrap())
                        as usize;
                bytes.splice(
                    message + 23 + attrs..message + 23 + attrs,
                    [0x40, 5, 4, 0, 0, 0, 100],
                );
                bytes[message + 21..message + 23]
                    .copy_from_slice(&((attrs + 7) as u16).to_be_bytes());
                let length =
                    u16::from_be_bytes(bytes[message + 16..message + 18].try_into().unwrap());
                bytes[message + 16..message + 18].copy_from_slice(&(length + 7).to_be_bytes());
                body_length += 7;
                bytes[at + 8..at + 12].copy_from_slice(&(body_length as u32).to_be_bytes());
            }
        }
        at += 12 + body_length;
    }
    bytes
}

#[test]
fn rejected_bgp4mp_body_retains_gap_before_first_route_and_native_only_reset() {
    use pcap_evidence_product::deep::{bgp::PeerRelationship, bgp_rib::RouteStatus};
    let options = bgp_mrt_store::MrtReplayOptions {
        peer_relationship: Some(PeerRelationship::Internal),
    };
    // Every message has a valid common BGP header and exact enclosing extent.
    // These errors share semantic rejection without a decoder-generation reset.
    for (wire, issue) in [
        (bgp_message(4, &[0]), "bgp4mp_keepalive_rejected"),
        (bgp_message(2, &[0, 0, 0]), "bgp4mp_update_rejected"),
        (bgp_message(3, &[0]), "bgp4mp_notification_rejected"),
        (bgp_message(5, &[0, 1, 0]), "bgp4mp_route_refresh_rejected"),
    ] {
        for prior in [false, true] {
            for recover in [false, true] {
                let scratch = Scratch::new();
                let mut bytes = continuity_internal_flow(7, prior);
                bytes.extend(continuity_internal_flow(8, true));
                let rejected = message_record(
                    MessageRecordMetadata::new(
                        Bgp4mpMetadata::new(4, 65_551, 65_552, 7),
                        16,
                        4,
                        31,
                        None,
                        false,
                    ),
                    &wire,
                );
                let offset = bytes.len();
                bytes.extend(&rejected);
                if recover {
                    // Reset before the first normalized observation when prior=false.
                    bytes.extend(state_record(
                        Bgp4mpMetadata::new(4, 65_551, 65_552, 7),
                        5,
                        32,
                        6,
                        1,
                    ));
                    bytes.extend(state_record(
                        Bgp4mpMetadata::new(4, 65_551, 65_552, 7),
                        5,
                        32,
                        1,
                        2,
                    ));
                    bytes.extend(continuity_internal_flow(7, false));
                }
                bytes.extend(continuity_internal_message(7, true));
                let path = scratch.file("semantic-rejection.mrt");
                let archive = bgp_mrt_store::create_with_options(
                    &path,
                    &bytes,
                    source("semantic-rejection"),
                    4 * 1024 * 1024,
                    MrtLimits::default(),
                    Limits::default(),
                    options,
                )
                .unwrap();
                let message_hash = sha256::hex(&sha256::digest(&wire));
                let rejected_hash = sha256::hex(&sha256::digest(&rejected));
                let event = archive
                    .bgp4mp_events
                    .iter()
                    .find(|event| event.encode().contains(issue))
                    .expect("original semantic rejection survives");
                let event_json = event.encode();
                assert!(
                    event_json.contains("\"parse_status\":\"rejected\""),
                    "{event_json}"
                );
                assert!(event_json.contains(&message_hash), "{event_json}");
                assert!(event_json.contains(&rejected_hash), "{event_json}");
                assert!(event_json.contains("\"generation\":0"), "{event_json}");
                let session = match event {
                    Json::Object(fields) => fields.iter().find_map(|(key, value)| {
                        if *key == "session" {
                            if let Json::String(s) = value {
                                Some(s.clone())
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    }),
                    _ => None,
                }
                .unwrap();
                assert_eq!(
                    archive.bgp4mp_rib.gaps().len(),
                    1,
                    "issue={issue} prior={prior} recover={recover}"
                );
                let target: Vec<_> = archive
                    .bgp4mp_rib
                    .entries()
                    .values()
                    .filter(|entry| entry.key.scope.session == session)
                    .collect();
                assert_eq!(
                    target
                        .iter()
                        .filter(|entry| entry.status == RouteStatus::Active)
                        .count(),
                    usize::from(recover)
                );
                assert_eq!(
                    target
                        .iter()
                        .filter(|entry| entry.status == RouteStatus::Unresolved)
                        .count(),
                    usize::from(!recover)
                );
                assert!(target
                    .iter()
                    .all(|entry| entry.status != RouteStatus::Withdrawn));
                assert_eq!(
                    archive
                        .bgp4mp_rib
                        .entries()
                        .values()
                        .filter(|entry| entry.key.scope.session != session
                            && entry.status == RouteStatus::Active)
                        .count(),
                    1
                );
                let gap = &archive.bgp4mp_rib.gaps()[0];
                assert_eq!(gap.0.session, session);
                assert_eq!(gap.0.generation, 0);
                assert!(gap.1.contains(&rejected_hash));
                let sealed = bgp_mrt_store::read_source(&path, 4 * 1024 * 1024).unwrap();
                let source_start = sealed
                    .windows(bytes.len())
                    .position(|part| part == bytes.as_slice())
                    .expect("sealed store retains exact original source bytes");
                assert_eq!(
                    sealed[source_start + offset..source_start + offset + rejected.len()],
                    rejected
                );
                let replay = bgp_mrt_store::replay_with_options(
                    &path,
                    4 * 1024 * 1024,
                    MrtLimits::default(),
                    Limits::default(),
                    options,
                )
                .unwrap();
                assert_eq!(archive.bgp4mp_rib_json(None), replay.bgp4mp_rib_json(None));
                assert_eq!(archive.state.encode(), replay.state.encode());
            }
        }
    }
}

#[test]
fn valid_route_free_bgp4mp_controls_and_unrelated_opaque_record_preserve_currency() {
    use pcap_evidence_product::deep::{bgp::PeerRelationship, bgp_rib::RouteStatus};
    let options = bgp_mrt_store::MrtReplayOptions {
        peer_relationship: Some(PeerRelationship::Internal),
    };
    for wire in [bgp_message(4, &[]), bgp_message(2, &[0, 0, 0, 0])] {
        let scratch = Scratch::new();
        let mut bytes = continuity_internal_flow(7, false);
        bytes.extend(message_record(
            MessageRecordMetadata::new(
                Bgp4mpMetadata::new(4, 65_551, 65_552, 7),
                16,
                4,
                31,
                None,
                false,
            ),
            &wire,
        ));
        bytes.extend(mrt_record(32, 99, 0, b"unsupported unrelated record"));
        bytes.extend(continuity_internal_message(7, true));
        let archive = bgp_mrt_store::create_with_options(
            &scratch.file("controls.mrt"),
            &bytes,
            source("valid-controls"),
            4 * 1024 * 1024,
            MrtLimits::default(),
            Limits::default(),
            options,
        )
        .unwrap();
        assert!(archive.bgp4mp_rib.gaps().is_empty());
        assert_eq!(
            archive.bgp4mp_rib.entries().values().next().unwrap().status,
            RouteStatus::Active
        );
        assert_eq!(archive.bgp4mp_rib.eors().len(), usize::from(wire[18] == 2));
    }
}

#[test]
fn incremental_bgp4mp_semantic_rejection_carries_exact_pre_route_cut() {
    use pcap_evidence_product::deep::{
        bgp::PeerRelationship,
        bgp_mrt_stream::visit_verified,
        bgp_mrt_stream_store::{write_stream, MrtStreamLimits},
    };
    use std::io::Cursor;
    let wire = bgp_message(4, &[0]);
    let rejected = message_record(
        MessageRecordMetadata::new(
            Bgp4mpMetadata::new(4, 65_551, 65_552, 7),
            16,
            4,
            31,
            None,
            false,
        ),
        &wire,
    );
    let mut bytes = continuity_internal_flow(7, false);
    bytes.extend(continuity_internal_flow(8, true));
    let offset = bytes.len();
    bytes.extend(&rejected);
    bytes.extend(continuity_internal_message(7, true));
    let mut stored = Vec::new();
    let limits = MrtStreamLimits::default();
    write_stream(
        &mut Cursor::new(&bytes),
        &mut stored,
        bytes.len() as u64,
        source("incremental-semantic-rejection"),
        &limits,
    )
    .unwrap();
    let mut cuts = Vec::new();
    let mut first_route_session = None;
    visit_verified(
        &mut Cursor::new(stored),
        &limits,
        &Limits::default(),
        &bgp_mrt_store::MrtReplayOptions {
            peer_relationship: Some(PeerRelationship::Internal),
        },
        |event| {
            if event.event.encode().contains("bgp4mp_keepalive_rejected") {
                assert!(event.observation.is_none());
                assert_eq!(event.continuity_cuts.len(), 1);
                assert_eq!(event.record_offset, offset as u64);
                assert_eq!(event.record_sha256, sha256::hex(&sha256::digest(&rejected)));
                cuts.extend_from_slice(event.continuity_cuts);
            } else {
                assert!(event.continuity_cuts.is_empty());
                if event.record_offset > offset as u64 {
                    if let Some(normalized) = event.observation {
                        let observation =
                            pcap_evidence_product::deep::bgp_state::Observation::from_normalized(
                                normalized,
                                None,
                                &Limits::default(),
                            )?;
                        first_route_session = observation.source().session.clone();
                    }
                }
            }
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(cuts.len(), 1);
    assert_eq!(Some(cuts[0].context.session.clone()), first_route_session);
    assert_eq!(cuts[0].context.generation, 0);
    assert_eq!(
        cuts[0].context.batch.sha256,
        Some(sha256::hex(&sha256::digest(&bytes)))
    );
    assert_eq!(cuts[0].context.provenance[0].start, offset as u64);
    assert_eq!(
        cuts[0].context.provenance[0].end,
        (offset + rejected.len()) as u64
    );
    assert_eq!(
        cuts[0].context.provenance[0].sha256,
        Some(sha256::hex(&sha256::digest(&rejected)))
    );
}

#[test]
fn rejected_unknown_asn_header_transfers_original_gap_to_enriched_partition() {
    use pcap_evidence_product::deep::{bgp::PeerRelationship, bgp_rib::RouteStatus};
    let options = bgp_mrt_store::MrtReplayOptions {
        peer_relationship: Some(PeerRelationship::Internal),
    };
    for recover in [false, true] {
        let scratch = Scratch::new();
        let rejected = message_record(
            MessageRecordMetadata::new(Bgp4mpMetadata::new(4, 0, 0, 7), 16, 4, 1, None, false),
            &bgp_message(4, &[0]),
        );
        let hash = sha256::hex(&sha256::digest(&rejected));
        let mut bytes = rejected.clone();
        bytes.extend(continuity_internal_flow(7, false));
        bytes.extend(continuity_internal_flow(8, true));
        if recover {
            bytes.extend(state_record(
                Bgp4mpMetadata::new(4, 65_551, 65_552, 7),
                5,
                32,
                6,
                1,
            ));
            bytes.extend(state_record(
                Bgp4mpMetadata::new(4, 65_551, 65_552, 7),
                5,
                32,
                1,
                2,
            ));
            bytes.extend(continuity_internal_flow(7, false));
        }
        bytes.extend(continuity_internal_message(7, true));
        let path = scratch.file("enriched.mrt");
        let archive = bgp_mrt_store::create_with_options(
            &path,
            &bytes,
            source("enriched"),
            4 * 1024 * 1024,
            MrtLimits::default(),
            Limits::default(),
            options,
        )
        .unwrap();
        let target = archive
            .bgp4mp_candidates
            .iter()
            .find(|c| c.record_index == archive.batch().records.len() - 1)
            .unwrap_or_else(|| {
                panic!(
                    "final route candidate absent; producer events={} native={}",
                    Json::array(archive.bgp4mp_events.clone()).encode(),
                    archive.bgp4mp_rib_json(None).encode()
                )
            });
        let entry = archive
            .bgp4mp_rib
            .entries()
            .values()
            .find(|entry| {
                entry.key.scope.session == target.session
                    && entry.key.scope.generation == u64::from(recover)
            })
            .unwrap();
        assert_eq!(
            entry.status,
            if recover {
                RouteStatus::Active
            } else {
                RouteStatus::Unresolved
            }
        );
        assert!(archive
            .bgp4mp_rib
            .gaps()
            .iter()
            .all(|(scope, witness)| scope.generation == 0 && witness.contains(&hash)));
        assert!(archive
            .bgp4mp_rib
            .gaps()
            .iter()
            .any(|(scope, _)| scope.peer.as_deref() == Some("65551@198.51.100.1")));
        assert_eq!(
            archive
                .bgp4mp_rib
                .entries()
                .values()
                .filter(|entry| entry.key.scope.session != target.session
                    && entry.status == RouteStatus::Active)
                .count(),
            1
        );
        let replay = bgp_mrt_store::replay_with_options(
            &path,
            4 * 1024 * 1024,
            MrtLimits::default(),
            Limits::default(),
            options,
        )
        .unwrap();
        assert_eq!(archive.bgp4mp_rib_json(None), replay.bgp4mp_rib_json(None));
    }
}

#[test]
fn opaque_update_gap_transfers_exact_direction_and_witness_to_future_partition() {
    use pcap_evidence_product::deep::{bgp::PeerRelationship, bgp_rib::RouteStatus};
    let options = bgp_mrt_store::MrtReplayOptions {
        peer_relationship: Some(PeerRelationship::Internal),
    };
    for already_known in [false, true] {
        for recover in [false, true] {
            let scratch = Scratch::new();
            let mut bytes = continuity_internal_flow(7, false);
            bytes.extend(continuity_internal_flow(8, true));
            if already_known {
                bytes.extend(message_record(
                    MessageRecordMetadata::new(
                        Bgp4mpMetadata::new(4, 0, 0, 7),
                        16,
                        4,
                        30,
                        None,
                        false,
                    ),
                    &bgp_message(4, &[]),
                ));
            }
            let opaque_index = 11 + usize::from(already_known);
            bytes.extend(continuity_internal_message(7, false));
            if recover {
                bytes.extend(state_record(
                    Bgp4mpMetadata::new(4, 65_551, 65_552, 7),
                    5,
                    32,
                    6,
                    1,
                ));
                bytes.extend(state_record(
                    Bgp4mpMetadata::new(4, 65_551, 65_552, 7),
                    5,
                    32,
                    1,
                    2,
                ));
                bytes.extend(continuity_internal_flow(7, false));
            }
            bytes.extend(message_record(
                MessageRecordMetadata::new(Bgp4mpMetadata::new(4, 0, 0, 7), 16, 4, 33, None, false),
                &continuity_internal_update(true),
            ));
            let path = scratch.file("opaque-enriched.mrt");
            let archive = bgp_mrt_store::create_with_options(
                &path,
                &bytes,
                source("opaque-enriched"),
                4 * 1024 * 1024,
                MrtLimits::default(),
                Limits::default(),
                options,
            )
            .unwrap();
            let target = archive
                .bgp4mp_candidates
                .iter()
                .find(|c| c.record_index == archive.batch().records.len() - 1)
                .unwrap_or_else(|| {
                    panic!(
                        "final route candidate absent; producer events={} native={}",
                        Json::array(archive.bgp4mp_events.clone()).encode(),
                        archive.bgp4mp_rib_json(None).encode()
                    )
                });
            let entry = archive
                .bgp4mp_rib
                .entries()
                .values()
                .find(|entry| {
                    entry.key.scope.session == target.session
                        && entry.key.scope.peer == target.peer
                        && entry.key.scope.generation == u64::from(recover)
                })
                .unwrap();
            assert_eq!(
                entry.status,
                if recover {
                    RouteStatus::Active
                } else {
                    RouteStatus::Unresolved
                }
            );
            let original = archive
                .state
                .observations()
                .iter()
                .find(|observation| {
                    observation.import_context().is_some_and(|c| {
                        c.provenance[0].sha256
                            == archive
                                .batch()
                                .bgp4mp_message_source_range(opaque_index)
                                .unwrap()
                                .unwrap()
                                .sha256
                    })
                })
                .unwrap();
            let witness = &original.source().record_id;
            let gaps = archive.bgp4mp_rib.gaps();
            assert_eq!(
                gaps.len(),
                if recover && !already_known { 1 } else { 2 },
                "initial normalized Gap is not duplicated"
            );
            assert!(gaps
                .iter()
                .all(|(scope, record_id)| scope.direction == Some(0)
                    && scope.generation == 0
                    && record_id == witness));
            assert_eq!(
                archive
                    .bgp4mp_rib
                    .entries()
                    .values()
                    .filter(|entry| entry.key.scope.session != target.session
                        && entry.status == RouteStatus::Active)
                    .count(),
                1
            );
            let replay = bgp_mrt_store::replay_with_options(
                &path,
                4 * 1024 * 1024,
                MrtLimits::default(),
                Limits::default(),
                options,
            )
            .unwrap();
            assert_eq!(archive.bgp4mp_rib_json(None), replay.bgp4mp_rib_json(None));
            assert_eq!(archive.state.encode(), replay.state.encode());
        }
    }
}

#[test]
fn identical_repeated_receiver_open_qualifies_enhanced_refresh_sender_layout() {
    for changed in [false, true] {
        let scratch = Scratch::new();
        let metadata = Bgp4mpMetadata::new(4, 65_551, 65_552, 7);
        let mut bytes = state_record(metadata, 5, 1, 2, 4);
        bytes.extend(message_record(
            MessageRecordMetadata::new(metadata, 16, 4, 2, None, false),
            &open(65_551, true, [198, 51, 100, 1]),
        ));
        for identifier in [
            [198, 51, 100, 2],
            [198, 51, 100, if changed { 3 } else { 2 }],
        ] {
            let mut receiver = open(65_552, true, identifier);
            receiver[28] += 4;
            receiver.extend_from_slice(&[2, 2, 70, 0]);
            let length = receiver.len() as u16;
            receiver[16..18].copy_from_slice(&length.to_be_bytes());
            bytes.extend(message_record(
                MessageRecordMetadata::new(metadata, 16, 4, 2, None, true),
                &receiver,
            ));
        }
        bytes.extend(state_record(metadata, 5, 3, 4, 5));
        bytes.extend(state_record(metadata, 5, 4, 5, 6));
        bytes.extend(message_record(
            MessageRecordMetadata::new(metadata, 16, 4, 5, None, false),
            &bgp_message(5, &[0, 1, 1, 1]),
        ));
        let archive = bgp_mrt_store::create(
            &scratch.file("repeat-refresh.mrt"),
            &bytes,
            source("repeat-refresh"),
            4 * 1024 * 1024,
            MrtLimits::default(),
            Limits::default(),
        )
        .unwrap();
        assert_eq!(
            json_field(archive.bgp4mp_events.last().unwrap(), "parse_status"),
            &Json::String(
                if changed {
                    "quarantined_route_refresh_capability_context"
                } else {
                    "decoded_route_refresh"
                }
                .to_owned()
            )
        );
        assert_eq!(
            archive
                .bgp4mp_events
                .iter()
                .filter(|event| json_field(event, "parse_status")
                    == &Json::String("decoded_open".to_owned()))
                .count(),
            3
        );
    }
}

#[test]
fn imported_source_events_retain_route_free_negative_boundary_and_observation_bindings() {
    use pcap_evidence_product::deep::{
        bgp::PeerRelationship, bgp_import::ImportedSourceEventKind as Kind,
    };
    let scratch = Scratch::new();
    let options = bgp_mrt_store::MrtReplayOptions {
        peer_relationship: Some(PeerRelationship::Internal),
    };
    let mut bytes = continuity_internal_flow(7, false);
    let metadata = Bgp4mpMetadata::new(4, 65_551, 65_552, 7);
    let wrap = |message: &[u8]| {
        message_record(
            MessageRecordMetadata::new(metadata, 16, 4, 30, None, false),
            message,
        )
    };
    bytes.extend(wrap(&bgp_message(4, &[])));
    bytes.extend(wrap(&bgp_message(2, &[0, 0, 0, 0])));
    bytes.extend(wrap(&bgp_message(4, &[0])));
    bytes.extend(continuity_internal_message(7, false));
    bytes.extend(state_record(metadata, 5, 32, 6, 1));
    bytes.extend(mrt_record(33, 99, 0, &[1, 2, 3]));
    let path = scratch.file("source-events.mrt");
    let archive = bgp_mrt_store::create_with_options(
        &path,
        &bytes,
        source("source-events"),
        4 * 1024 * 1024,
        MrtLimits::default(),
        Limits::default(),
        options,
    )
    .unwrap();
    let events = &archive.source_events;
    assert!(events
        .windows(2)
        .all(|pair| pair[0].source_record_index <= pair[1].source_record_index));
    for index in 0..archive.batch().records.len() {
        assert_eq!(
            events
                .iter()
                .filter(
                    |event| event.source_record_index == index && event.observation_index.is_none()
                )
                .count(),
            1,
            "source container ordinal={index}"
        );
    }
    assert_eq!(
        events
            .iter()
            .filter(|event| event.kind == Kind::Open)
            .count(),
        2
    );
    let valid = events
        .iter()
        .find(|event| event.source_record_index == 5)
        .unwrap();
    assert_eq!(valid.kind, Kind::Keepalive);
    assert!(valid.continuity_cuts.is_empty());
    assert_eq!(valid.context.as_ref().unwrap().direction, Some(0));
    let eor = events
        .iter()
        .find(|event| event.source_record_index == 6 && event.observation_index.is_some())
        .unwrap();
    assert_eq!(eor.kind, Kind::Update);
    assert!(eor.continuity_cuts.is_empty());
    let reject = events
        .iter()
        .find(|event| event.source_record_index == 7)
        .unwrap();
    assert_eq!(reject.kind, Kind::ContinuityGap);
    assert!(reject.observation_index.is_none());
    assert_eq!(reject.continuity_cuts.len(), 1);
    assert_eq!(reject.continuity_cuts[0].context.direction, None);
    assert_eq!(
        reject.continuity_cuts[0].context.provenance[0]
            .sha256
            .as_deref(),
        Some(archive.batch().records[7].sha256.as_str())
    );
    let opaque = events
        .iter()
        .find(|event| event.source_record_index == 8 && event.observation_index.is_none())
        .unwrap();
    assert_eq!(opaque.kind, Kind::ContinuityGap);
    assert!(opaque
        .continuity_cuts
        .iter()
        .any(|cut| cut.context.direction == Some(0)
            && cut.reason == "decoded_update_opaque_route_evidence"));
    let reset = events
        .iter()
        .find(|event| event.source_record_index == 9 && event.observation_index.is_none())
        .unwrap();
    assert_eq!(reset.kind, Kind::GenerationBoundary);
    assert_eq!(reset.context.as_ref().unwrap().generation, 1);
    assert!(reset.continuity_cuts.is_empty());
    let unsupported = events.last().unwrap();
    assert_eq!(unsupported.kind, Kind::Opaque);
    assert!(unsupported.context.is_none() && unsupported.continuity_cuts.is_empty());
    for event in events {
        if let Some(index) = event.observation_index {
            assert_eq!(
                event.context.as_ref(),
                archive.state.observations()[index].import_context()
            );
        }
    }
    let replay = bgp_mrt_store::replay_with_options(
        &path,
        4 * 1024 * 1024,
        MrtLimits::default(),
        Limits::default(),
        options,
    )
    .unwrap();
    assert_eq!(events.len(), replay.source_events.len());
    for (a, b) in events.iter().zip(&replay.source_events) {
        assert_eq!(
            (a.source_record_index, a.observation_index, a.kind),
            (b.source_record_index, b.observation_index, b.kind)
        );
        assert_eq!(a.context, b.context);
        assert_eq!(a.continuity_cuts, b.continuity_cuts);
        assert_eq!(a.reference, b.reference);
    }
}

#[test]
fn pending_continuity_direction_session_generation_twins_use_exact_scopes() {
    use pcap_evidence_product::deep::{bgp::PeerRelationship, bgp_rib::RouteStatus};
    let options = bgp_mrt_store::MrtReplayOptions {
        peer_relationship: Some(PeerRelationship::Internal),
    };
    for semantic in [false, true] {
        for recover in [false, true] {
            let scratch = Scratch::new();
            let metadata = Bgp4mpMetadata::new(4, 65_551, 65_552, 7);
            let mut bytes = continuity_internal_flow(7, false);
            bytes.extend(continuity_internal_flow(8, true));
            for local in [false, true] {
                bytes.extend(message_record(
                    MessageRecordMetadata::new(metadata, 16, 4, 30, None, local),
                    &continuity_internal_update(false),
                ));
            }
            if semantic {
                bytes.extend(message_record(
                    MessageRecordMetadata::new(metadata, 16, 4, 31, None, false),
                    &bgp_message(4, &[0]),
                ));
            }
            if recover {
                bytes.extend(state_record(metadata, 5, 32, 6, 1));
                bytes.extend(state_record(metadata, 5, 32, 1, 2));
                bytes.extend(continuity_internal_flow(7, false));
            }
            let unknown_index = 13 + usize::from(semantic) + if recover { 7 } else { 0 };
            for local in [false, true] {
                bytes.extend(message_record(
                    MessageRecordMetadata::new(
                        Bgp4mpMetadata::new(4, 0, 0, 7),
                        16,
                        4,
                        33,
                        None,
                        local,
                    ),
                    &continuity_internal_update(true),
                ));
            }
            let path = scratch.file("direction-twins.mrt");
            let archive = bgp_mrt_store::create_with_options(
                &path,
                &bytes,
                source("direction-twins"),
                4 * 1024 * 1024,
                MrtLimits::default(),
                Limits::default(),
                options,
            )
            .unwrap();
            let target = archive
                .bgp4mp_candidates
                .iter()
                .find(|c| c.record_index == unknown_index)
                .unwrap();
            let entries: Vec<_> = archive
                .bgp4mp_rib
                .entries()
                .values()
                .filter(|entry| {
                    entry.key.scope.session == target.session
                        && entry.key.scope.peer.as_deref() == Some("0@198.51.100.1")
                        && entry.key.scope.generation == u64::from(recover)
                })
                .collect();
            assert_eq!(entries.len(), 2);
            assert_eq!(
                entries
                    .iter()
                    .filter(|entry| entry.key.scope.direction == Some(0))
                    .count(),
                1
            );
            assert_eq!(
                entries
                    .iter()
                    .filter(|entry| entry.key.scope.direction == Some(1))
                    .count(),
                1
            );
            assert!(entries.iter().all(|entry| entry.status
                == if recover {
                    RouteStatus::Active
                } else {
                    RouteStatus::Unresolved
                }));
            assert_eq!(
                archive
                    .bgp4mp_rib
                    .entries()
                    .values()
                    .filter(|entry| entry.key.scope.session != target.session
                        && entry.status == RouteStatus::Active)
                    .count(),
                1
            );
            let count = 2 + usize::from(semantic);
            assert_eq!(
                archive.bgp4mp_rib.gaps().len(),
                count * if recover { 1 } else { 2 }
            );
            assert!(archive
                .bgp4mp_rib
                .gaps()
                .iter()
                .all(|(scope, _)| scope.session == target.session && scope.generation == 0));
            let row = archive
                .source_events
                .iter()
                .find(|event| {
                    event.source_record_index == unknown_index && event.observation_index.is_none()
                })
                .unwrap();
            assert_eq!(row.continuity_cuts.len(), if recover { 0 } else { count });
            if !recover {
                assert_eq!(
                    row.continuity_cuts
                        .iter()
                        .filter(|cut| cut.context.direction == Some(0))
                        .count(),
                    1
                );
                assert_eq!(
                    row.continuity_cuts
                        .iter()
                        .filter(|cut| cut.context.direction == Some(1))
                        .count(),
                    1
                );
                assert_eq!(
                    row.continuity_cuts
                        .iter()
                        .filter(|cut| cut.context.direction.is_none())
                        .count(),
                    usize::from(semantic)
                );
                for cut in &row.continuity_cuts {
                    let origin = archive
                        .source_events
                        .iter()
                        .find(|event| {
                            event.observation_index.is_none()
                                && event.continuity_cuts.iter().any(|original| {
                                    original.record_id == cut.record_id
                                        && original.context.peer.as_deref()
                                            == Some("65551@198.51.100.1")
                                })
                        })
                        .unwrap();
                    let original = origin
                        .continuity_cuts
                        .iter()
                        .find(|original| original.record_id == cut.record_id)
                        .unwrap();
                    assert_eq!(cut.reason, original.reason);
                    assert_eq!(cut.context.direction, original.context.direction);
                    assert_eq!(cut.context.provenance, original.context.provenance);
                }
            }
            let replay = bgp_mrt_store::replay_with_options(
                &path,
                4 * 1024 * 1024,
                MrtLimits::default(),
                Limits::default(),
                options,
            )
            .unwrap();
            assert_eq!(archive.bgp4mp_rib_json(None), replay.bgp4mp_rib_json(None));
        }
    }
}

#[test]
fn native_mrt_versions_bind_exact_observation_occurrence_and_route_ordinal() {
    use pcap_evidence_product::deep::{bgp::PeerRelationship, bgp_rib::VersionDisposition};
    let scratch = Scratch::new();
    let options = bgp_mrt_store::MrtReplayOptions {
        peer_relationship: Some(PeerRelationship::Internal),
    };
    let mut wire = continuity_internal_update(true);
    wire.extend_from_slice(&[24, 198, 51, 101]);
    let length = wire.len() as u16;
    wire[16..18].copy_from_slice(&length.to_be_bytes());
    let update = message_record(
        MessageRecordMetadata::new(
            Bgp4mpMetadata::new(4, 65_551, 65_552, 7),
            16,
            4,
            31,
            None,
            false,
        ),
        &wire,
    );
    let mut bytes = continuity_internal_flow(7, false);
    bytes.extend(&update);
    bytes.extend(&update);
    let path = scratch.file("native-origins.mrt");
    let archive = bgp_mrt_store::create_with_options(
        &path,
        &bytes,
        source("native-origins"),
        4 * 1024 * 1024,
        MrtLimits::default(),
        Limits::default(),
        options,
    )
    .unwrap();
    let observations = archive.state.observations();
    assert_eq!(observations.len(), 2);
    assert_ne!(observations[0].sha256(), observations[1].sha256());
    assert_eq!(archive.bgp4mp_rib.events().len(), 2);
    assert_eq!(archive.bgp4mp_rib.entries().len(), 2);
    for entry in archive.bgp4mp_rib.entries().values() {
        assert_eq!(entry.versions.len(), 1);
        let version = &entry.versions[0];
        assert_eq!(version.disposition, VersionDisposition::Current);
        assert_eq!(version.occurrences.len(), 2);
        for (index, occurrence) in version.occurrences.iter().enumerate() {
            assert_eq!(occurrence.event_index, index);
            assert_eq!(occurrence.observation_sha256, observations[index].sha256());
            assert_eq!(
                observations[index].routes()[occurrence.route_index].prefix(),
                &entry.key.prefix
            );
            assert_eq!(
                archive.bgp4mp_rib.events()[occurrence.event_index].record_id,
                observations[index].source().record_id
            );
        }
    }
    let replay = bgp_mrt_store::replay_with_options(
        &path,
        4 * 1024 * 1024,
        MrtLimits::default(),
        Limits::default(),
        options,
    )
    .unwrap();
    for (key, entry) in archive.bgp4mp_rib.entries() {
        let fresh = replay.bgp4mp_rib.entries().get(key).unwrap();
        assert_eq!(entry.versions, fresh.versions);
    }
}
