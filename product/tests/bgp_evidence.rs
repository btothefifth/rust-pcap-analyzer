use pcap_evidence::sha256;
use pcap_evidence_product::deep::{
    bgp::PeerRelationship,
    bgp_evidence::{
        self, AsnRole, AsnSelector, ClockScope, EvidenceLimits, TimeBasis, WindowQuery,
    },
    bgp_mrt::MrtSource,
    bgp_mrt_store::MrtReplayOptions,
    bgp_mrt_stream_store::{write_stream, MrtStreamLimits},
    Limits,
};
use std::{
    fs::{self, OpenOptions},
    io::{self, Cursor, Read},
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "bgp-evidence-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn store(&self, name: &str, source_id: &str, raw: &[u8], split: usize) -> PathBuf {
        let path = self.0.join(name);
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&path)
            .unwrap();
        let mut reader = Split {
            inner: Cursor::new(raw),
            split,
        };
        write_stream(
            &mut reader,
            &mut file,
            raw.len() as u64,
            MrtSource {
                source_id: source_id.into(),
                checkpoint_id: "checkpoint".into(),
            },
            &MrtStreamLimits::default(),
        )
        .unwrap();
        path
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
struct Split<'a> {
    inner: Cursor<&'a [u8]>,
    split: usize,
}
impl Read for Split<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let n = out.len().min(self.split);
        self.inner.read(&mut out[..n])
    }
}
fn record(time: u32, kind: u16, subtype: u16, body: &[u8]) -> Vec<u8> {
    let mut raw = time.to_be_bytes().to_vec();
    raw.extend(kind.to_be_bytes());
    raw.extend(subtype.to_be_bytes());
    raw.extend((body.len() as u32).to_be_bytes());
    raw.extend(body);
    raw
}
fn table(time: u32) -> Vec<u8> {
    let mut body = vec![
        192, 0, 2, 1, 0, 1, b'v', 0, 1, 2, 192, 0, 2, 2, 203, 0, 113, 9,
    ];
    body.extend(65551u32.to_be_bytes());
    record(time, 13, 1, &body)
}
fn rib(time: u32, originated: u32, segment_kind: u8, asn: u32) -> Vec<u8> {
    // Independently encoded RFC 6396 IPv4 RIB and RFC 4271 attributes.
    let mut attributes = vec![0x40, 1, 1, 0, 0x40, 2, 6, segment_kind, 1];
    attributes.extend(asn.to_be_bytes());
    attributes.extend([0x40, 3, 4, 192, 0, 2, 9]);
    let mut body = vec![0, 0, 0, 7, 24, 203, 0, 113, 0, 1, 0, 0];
    body.extend(originated.to_be_bytes());
    body.extend((attributes.len() as u16).to_be_bytes());
    body.extend(attributes);
    record(time, 13, 2, &body)
}
fn bgp_message(kind: u8, payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0xff; 16];
    bytes.extend(((payload.len() + 19) as u16).to_be_bytes());
    bytes.push(kind);
    bytes.extend(payload);
    bytes
}
fn bgp4mp_body(payload: &[u8]) -> Vec<u8> {
    let mut body = 64512u16.to_be_bytes().to_vec();
    body.extend(64513u16.to_be_bytes());
    body.extend(7u16.to_be_bytes());
    body.extend(1u16.to_be_bytes());
    body.extend([198, 51, 100, 1, 198, 51, 100, 2]);
    body.extend(payload);
    body
}
fn established_et_update(microseconds: u32) -> Vec<u8> {
    let open = |asn: u16, identifier: [u8; 4]| {
        let mut payload = vec![4];
        payload.extend(asn.to_be_bytes());
        payload.extend(90u16.to_be_bytes());
        payload.extend(identifier);
        payload.push(0);
        bgp_message(1, &payload)
    };
    let state = |seconds: u32, old: u16, new: u16| {
        let mut payload = old.to_be_bytes().to_vec();
        payload.extend(new.to_be_bytes());
        record(seconds, 16, 0, &bgp4mp_body(&payload))
    };
    let mut attributes = vec![0x40, 1, 1, 0, 0x40, 2, 4, 2, 1];
    attributes.extend(64512u16.to_be_bytes());
    attributes.extend([0x40, 3, 4, 192, 0, 2, 9]);
    let mut update = vec![0, 0];
    update.extend((attributes.len() as u16).to_be_bytes());
    update.extend(attributes);
    update.extend([24, 198, 51, 100]);
    let mut et = microseconds.to_be_bytes().to_vec();
    et.extend(bgp4mp_body(&bgp_message(2, &update)));
    [
        state(10, 3, 4),
        record(11, 16, 1, &bgp4mp_body(&open(64512, [198, 51, 100, 1]))),
        record(12, 16, 6, &bgp4mp_body(&open(64513, [198, 51, 100, 2]))),
        state(13, 4, 5),
        state(14, 5, 6),
        record(32, 17, 1, &et),
    ]
    .concat()
}
fn export(
    paths: &[PathBuf],
    limits: &EvidenceLimits,
    query: Option<&WindowQuery>,
    options: &MrtReplayOptions,
) -> (bgp_evidence::EvidenceManifest, Vec<u8>) {
    let mut bytes = Vec::new();
    let manifest = bgp_evidence::export_sequence(
        paths,
        &MrtStreamLimits::default(),
        &Limits::default(),
        limits,
        options,
        query,
        &mut bytes,
    )
    .unwrap();
    (manifest, bytes)
}
fn window(basis: TimeBasis, start: i128, end: i128, role: Option<AsnRole>) -> WindowQuery {
    WindowQuery {
        asn: role.map(|role| AsnSelector { asn: 65551, role }),
        time_basis: basis,
        clock_scope: "collector".into(),
        start_ns: start,
        end_ns: end,
    }
}

#[test]
fn caller_order_and_all_records_survive_clock_regressions() {
    let scratch = Scratch::new();
    let first = scratch.store(
        "first",
        "collector",
        &[table(30), rib(20, 11, 2, 65551), record(10, 99, 0, &[9])].concat(),
        1,
    );
    let second = scratch.store(
        "second",
        "other",
        &[table(2), rib(1, 1, 2, 65551)].concat(),
        7,
    );
    let (manifest, bytes) = export(
        &[first, second],
        &EvidenceLimits::default(),
        None,
        &MrtReplayOptions::default(),
    );
    assert_eq!(manifest.rows, 5);
    assert_eq!(manifest.coverage.records, 5);
    assert_eq!(manifest.coverage.timestamp_regressions, 3);
    assert_eq!(manifest.coverage.route_free, 3);
    assert_eq!(manifest.coverage.opaque, 1);
    assert_eq!(manifest.sequence.entries[0].source_id, "collector");
    assert_eq!(manifest.sequence.entries[1].source_id, "other");
    let text = String::from_utf8(bytes).unwrap();
    let lines: Vec<_> = text.lines().collect();
    assert_eq!(lines.len(), 6);
    assert!(lines[0].contains("\"seconds\":\"30\""));
    assert!(lines[1].contains("\"seconds\":\"20\""));
    assert!(lines[2].contains("opaque_record"));
    assert!(lines[3].contains("\"sequence_ordinal\":\"1\""));
    assert!(lines[3].contains("\"seconds\":\"2\""));
    assert!(lines.last().unwrap().contains("\"complete\":true"));
}

#[test]
fn plain_quarantine_has_distinct_counts_and_bounded_witnesses_with_valid_neighbor() {
    let scratch = Scratch::new();
    // Independently encoded BGP4MP FSM reports: Idle -> Established is illegal;
    // the separate source's Idle -> Connect is the nearest legal transition.
    let state_record = |time, old: u16, new: u16| {
        let mut payload = old.to_be_bytes().to_vec();
        payload.extend(new.to_be_bytes());
        record(time, 16, 0, &bgp4mp_body(&payload))
    };
    let quarantined = scratch.store("quarantined", "collector", &state_record(10, 1, 6), 1);
    let neighbor = scratch.store("neighbor", "other", &state_record(20, 1, 2), 3);
    let paths = [quarantined, neighbor];
    let query = WindowQuery {
        asn: None,
        time_basis: TimeBasis::MrtRecordTime,
        clock_scope: "other".into(),
        start_ns: 20_000_000_000,
        end_ns: 21_000_000_000,
    };
    for selected_window in [None, Some(&query)] {
        for cap in [0, 1] {
            let limits = EvidenceLimits {
                witnesses: cap,
                ..EvidenceLimits::default()
            };
            let (manifest, bytes) = export(
                &paths,
                &limits,
                selected_window,
                &MrtReplayOptions::default(),
            );
            assert_eq!(manifest.coverage.records, 2);
            assert_eq!(manifest.coverage.rows, 2);
            assert!(manifest
                .coverage
                .json()
                .encode()
                .contains("\"quarantined\":\"1\""));
            assert_eq!(manifest.coverage.rejected, 0);
            assert_eq!(manifest.coverage.opaque, 0);
            assert_eq!(manifest.coverage.unsupported, 0);
            assert_eq!(
                manifest.coverage.selected,
                if selected_window.is_some() { 1 } else { 2 }
            );
            assert_eq!(manifest.coverage.witnesses.len(), cap);
            assert_eq!(manifest.coverage.witnesses_truncated, (1 - cap) as u64);
            if cap == 1 {
                let witness = manifest.coverage.witnesses[0].encode();
                assert!(witness.contains("\"reason\":\"quarantined\""));
                assert!(witness.contains("\"sequence_ordinal\":\"0\""));
                assert!(witness.contains("\"record_ordinal\":\"0\""));
                assert!(witness.contains("\"record_offset\":\"0\""));
            }
            let text = String::from_utf8(bytes).unwrap();
            let rows = text.lines().collect::<Vec<_>>();
            assert!(rows[0].contains("\"parse_status\":\"quarantined\""));
            assert!(rows[0].contains("illegal_reported_fsm_transition"));
            assert!(rows[1].contains("\"parse_status\":\"reported_transition\""));
            if selected_window.is_some() {
                assert!(rows[0].contains("outside_clock_scope"));
                assert!(rows[0].contains("\"selected\":false"));
                assert!(rows[1].contains("\"selected\":true"));
            }
        }
    }
}

#[test]
fn independent_checkpoints_cannot_borrow_an_earlier_peer_table() {
    let scratch = Scratch::new();
    let first = scratch.store("pit", "collector", &table(20), 3);
    let missing_pit = rib(10, 9, 2, 65551);
    let mut output = Vec::new();
    assert!(write_stream(
        &mut Cursor::new(&missing_pit),
        &mut output,
        missing_pit.len() as u64,
        MrtSource {
            source_id: "collector".into(),
            checkpoint_id: "independent".into()
        },
        &MrtStreamLimits::default()
    )
    .is_err());
    // The completed prior checkpoint still exports normally; a serialized
    // sequence reference carries no peer table or decoder continuation.
    let (manifest, _) = export(
        &[first],
        &EvidenceLimits::default(),
        None,
        &MrtReplayOptions::default(),
    );
    assert_eq!(manifest.coverage.records, 1);
    assert_eq!(manifest.coverage.observations, 0);
    assert_eq!(manifest.sequence.entries.len(), 1);
}

#[test]
fn exact_half_open_labels_and_missing_selected_clock_are_preserved() {
    let scratch = Scratch::new();
    let path = scratch.store(
        "window",
        "collector",
        &[
            table(30),
            rib(20, 11, 2, 65551),
            rib(21, 12, 2, 65551),
            record(22, 99, 0, &[7]),
        ]
        .concat(),
        2,
    );
    let query = window(
        TimeBasis::RibOriginatedTime,
        11_000_000_000,
        12_000_000_000,
        None,
    );
    let (manifest, bytes) = export(
        std::slice::from_ref(&path),
        &EvidenceLimits::default(),
        Some(&query),
        &MrtReplayOptions::default(),
    );
    assert_eq!(manifest.coverage.selected, 1);
    assert_eq!(manifest.coverage.unknown_time, 2);
    assert_eq!(manifest.rows, 4);
    let text = String::from_utf8(bytes).unwrap();
    let rows: Vec<_> = text.lines().collect();
    assert!(rows[0].contains("\"rib_originated_time_ns\":null"));
    assert!(rows[0].contains("unknown_time"));
    assert!(rows[1].contains("inside_label_window"));
    assert!(rows[2].contains("outside_label_window"));
    assert!(rows[3].contains("unknown_time"));
    // An observation clock does not adopt the MRT time of route-free records.
    let observation = window(TimeBasis::ObservationTime, 0, 100_000_000_000, None);
    let (manifest, _) = export(
        &[path],
        &EvidenceLimits::default(),
        Some(&observation),
        &MrtReplayOptions::default(),
    );
    assert_eq!(manifest.coverage.unknown_time, 2);
}

#[test]
fn exact_microseconds_and_clock_scope_never_sort_or_merge_sources() {
    let scratch = Scratch::new();
    // RFC 6396 BGP4MP_ET four-byte microsecond field followed by KEEPALIVE.
    let mut body = 123456u32.to_be_bytes().to_vec();
    body.extend(65551u32.to_be_bytes());
    body.extend(65552u32.to_be_bytes());
    body.extend(0u16.to_be_bytes());
    body.extend(1u16.to_be_bytes());
    body.extend([203, 0, 113, 9, 192, 0, 2, 1]);
    body.extend([0xff; 16]);
    body.extend(19u16.to_be_bytes());
    body.push(4);
    let first = scratch.store("et", "collector", &record(5, 17, 4, &body), 1);
    let other = scratch.store("other", "other", &record(5, 99, 0, &[]), 1);
    let query = window(TimeBasis::MrtRecordTime, 5_123_456_000, 5_123_456_001, None);
    let (manifest, bytes) = export(
        &[first, other],
        &EvidenceLimits::default(),
        Some(&query),
        &MrtReplayOptions::default(),
    );
    assert_eq!(manifest.coverage.selected, 1);
    let text = String::from_utf8(bytes).unwrap();
    assert!(text
        .lines()
        .next()
        .unwrap()
        .contains("\"microseconds\":\"123456\""));
    assert!(text.lines().nth(1).unwrap().contains("outside_clock_scope"));
}

#[test]
fn literal_all_source_clocks_selects_exact_source_and_explicit_all_selects_both() {
    let scratch = Scratch::new();
    let raw = [table(10), rib(20, 19, 2, 65551)].concat();
    let literal = scratch.store("literal", "all-source-clocks", &raw, 1);
    let other = scratch.store("other", "other", &raw, 7);
    let paths = [literal, other.clone()];
    // Both sources carry the same timestamps and ASN. Only scope can distinguish
    // them; source-order rows must remain present even when not selected.
    for (basis, start) in [
        (TimeBasis::MrtRecordTime, 20_000_000_000),
        (TimeBasis::RibOriginatedTime, 19_000_000_000),
    ] {
        let mut query = window(basis, start, start + 1, Some(AsnRole::Origin));
        query.clock_scope = "all-source-clocks".into();
        assert_eq!(
            query.clock_scope,
            ClockScope::Source("all-source-clocks".into())
        );
        assert_eq!(
            ClockScope::from(String::from("all-source-clocks")),
            query.clock_scope
        );
        let (exact, bytes) = export(
            &paths,
            &EvidenceLimits::default(),
            Some(&query),
            &MrtReplayOptions::default(),
        );
        assert_eq!(exact.rows, 4);
        assert_eq!(exact.coverage.selected, 1);
        let text = String::from_utf8(bytes).unwrap();
        let rows = text.lines().collect::<Vec<_>>();
        assert!(rows[1].contains("\"selected\":true"));
        for row in &rows[2..4] {
            assert!(row.contains("\"source_id\":\"other\""));
            assert!(row.contains("\"window_disposition\":\"outside_clock_scope\""));
            assert!(row.contains("\"selected\":false"));
        }
        assert!(exact
            .json()
            .encode()
            .contains("\"clock_scope\":\"all-source-clocks\",\"clock_scope_kind\":\"source\""));

        query.clock_scope = ClockScope::AllSourceClocks;
        let (all, bytes) = export(
            &paths,
            &EvidenceLimits::default(),
            Some(&query),
            &MrtReplayOptions::default(),
        );
        assert_eq!(all.rows, 4);
        assert_eq!(all.coverage.selected, 2);
        let text = String::from_utf8(bytes).unwrap();
        assert!(!text.contains("outside_clock_scope"));
        assert_eq!(text.matches("\"selected\":true").count(), 2);
        assert!(all.json().encode().contains(
            "\"clock_scope\":\"all-source-clocks\",\"clock_scope_kind\":\"all_source_clocks\""
        ));
    }
    // An absent literal sentinel is an error, not permission to broaden scope.
    let mut query = window(TimeBasis::MrtRecordTime, 0, 100_000_000_000, None);
    query.clock_scope = "all-source-clocks".into();
    let mut bytes = Vec::new();
    let error = bgp_evidence::export_sequence(
        &[other],
        &MrtStreamLimits::default(),
        &Limits::default(),
        &EvidenceLimits::default(),
        &MrtReplayOptions::default(),
        Some(&query),
        &mut bytes,
    )
    .unwrap_err();
    assert_eq!(error.field, "bgp_evidence_clock_scope");
    assert!(bytes.is_empty());
}

#[test]
fn missing_and_invalid_et_microseconds_remain_unknown_without_zero_fallback() {
    let scratch = Scratch::new();
    let raw = [
        record(30, 16, 99, &[]),
        record(31, 17, 1, &[0, 0]),
        record(32, 17, 99, &1_000_000u32.to_be_bytes()),
        record(20, 16, 99, &[]),
        record(33, 17, 99, &999_999u32.to_be_bytes()),
    ]
    .concat();
    let path = scratch.store("et-unknown", "collector", &raw, 1);
    // Both formerly invented labels (31 seconds and 32 + 1 seconds)
    // lie inside this interval. Every actual usable label lies outside.
    let query = window(
        TimeBasis::MrtRecordTime,
        31_000_000_000,
        33_000_000_001,
        None,
    );
    let (manifest, bytes) = export(
        std::slice::from_ref(&path),
        &EvidenceLimits::default(),
        Some(&query),
        &MrtReplayOptions::default(),
    );
    assert_eq!(manifest.rows, 5);
    assert_eq!(manifest.coverage.selected, 0);
    assert_eq!(manifest.coverage.unknown_time, 2);
    assert_eq!(manifest.coverage.unknown_mrt_record_time, 2);
    assert_eq!(manifest.coverage.timestamp_regressions, 0);
    let text = String::from_utf8(bytes).unwrap();
    let rows: Vec<_> = text.lines().collect();
    assert!(rows[0].contains("\"validity\":\"seconds\""));
    assert!(rows[0].contains("\"time_ns\":\"30000000000\""));
    assert!(rows[1].contains("\"seconds\":\"31\""));
    assert!(rows[1].contains("\"microseconds\":null"));
    assert!(rows[1].contains("\"validity\":\"missing_microseconds\""));
    assert!(rows[1].contains("\"precision\":\"unknown\""));
    assert!(rows[1].contains("\"time_ns\":null"));
    assert!(rows[1].contains("\"window_disposition\":\"unknown_time\""));
    assert!(rows[2].contains("\"microseconds\":\"1000000\""));
    assert!(rows[2].contains("\"validity\":\"invalid_microseconds\""));
    assert!(rows[2].contains("\"time_ns\":null"));
    assert!(rows[2].contains("\"selected\":false"));
    assert!(rows[4].contains("\"microseconds\":\"999999\""));
    assert!(rows[4].contains("\"validity\":\"microseconds\""));
    assert!(rows[4].contains("\"time_ns\":\"33999999000\""));
    assert!(manifest
        .coverage
        .witnesses
        .iter()
        .any(|witness| witness.encode().contains("missing_microseconds")));
    assert!(manifest
        .coverage
        .witnesses
        .iter()
        .any(|witness| witness.encode().contains("invalid_microseconds")));
    // Chronology also retains the invalid-label count without a selector.
    let (chronology, _) = export(
        &[path],
        &EvidenceLimits::default(),
        None,
        &MrtReplayOptions::default(),
    );
    assert_eq!(chronology.coverage.unknown_mrt_record_time, 2);
    assert_eq!(chronology.coverage.unknown_time, 0);
}

#[test]
fn invalid_et_cannot_acquire_numeric_precision_through_observation_clock() {
    let scratch = Scratch::new();
    let invalid = scratch.store(
        "et-observation-invalid",
        "collector",
        &established_et_update(1_000_000),
        1,
    );
    let valid = scratch.store(
        "et-observation-valid",
        "collector",
        &established_et_update(999_999),
        3,
    );
    let options = MrtReplayOptions {
        peer_relationship: Some(PeerRelationship::External),
    };
    // The old canonical calculation turned 32 seconds + invalid 1,000,000
    // microseconds into the apparently exact observation label 33 seconds.
    let invalid_query = window(
        TimeBasis::ObservationTime,
        33_000_000_000,
        33_000_000_001,
        None,
    );
    let (manifest, bytes) = export(
        &[invalid],
        &EvidenceLimits::default(),
        Some(&invalid_query),
        &options,
    );
    assert_eq!(manifest.rows, 6);
    assert_eq!(manifest.coverage.observations, 1);
    assert_eq!(manifest.coverage.unknown_mrt_record_time, 1);
    assert_eq!(manifest.coverage.selected, 0);
    let text = String::from_utf8(bytes).unwrap();
    let update = text.lines().nth(5).unwrap();
    assert!(update.contains("\"microseconds\":\"1000000\""));
    assert!(update.contains("\"observation_time_ns\":null"));
    assert!(update.contains("\"observed_at_ns\":null"));
    assert!(update.contains("\"window_disposition\":\"unknown_time\""));
    assert!(update.contains("\"observation\":{\"schema\":\"pcap-evidence.bgp.route-evidence.v1\""));
    assert!(update.contains("\"address\":\"198.51.100.0\""));
    assert!(!update.contains("\"observed_at_ns\":\"33000000000\""));
    // Adjacent valid ET evidence still reaches the same normalizer and selector.
    let valid_query = window(
        TimeBasis::ObservationTime,
        32_999_999_000,
        32_999_999_001,
        None,
    );
    let (manifest, bytes) = export(
        &[valid],
        &EvidenceLimits::default(),
        Some(&valid_query),
        &options,
    );
    assert_eq!(manifest.coverage.observations, 1);
    assert_eq!(manifest.coverage.unknown_mrt_record_time, 0);
    assert_eq!(manifest.coverage.selected, 1);
    let text = String::from_utf8(bytes).unwrap();
    let update = text.lines().nth(5).unwrap();
    assert!(update.contains("\"observation_time_ns\":\"32999999000\""));
    assert!(update.contains("\"observed_at_ns\":\"32999999000\""));
    assert!(update.contains("\"window_disposition\":\"inside_label_window\""));
}

#[test]
fn origin_set_is_unknown_while_validated_path_membership_can_match() {
    let scratch = Scratch::new();
    let path = scratch.store(
        "set",
        "collector",
        &[table(11), rib(12, 10, 1, 65551)].concat(),
        3,
    );
    let origin = window(
        TimeBasis::MrtRecordTime,
        0,
        20_000_000_000,
        Some(AsnRole::Origin),
    );
    let member = window(
        TimeBasis::MrtRecordTime,
        0,
        20_000_000_000,
        Some(AsnRole::PathMember),
    );
    let (origins, output) = export(
        std::slice::from_ref(&path),
        &EvidenceLimits::default(),
        Some(&origin),
        &MrtReplayOptions::default(),
    );
    assert_eq!(origins.coverage.selected, 0);
    assert_eq!(origins.coverage.unknown_asn, 2);
    assert!(String::from_utf8(output)
        .unwrap()
        .lines()
        .nth(1)
        .unwrap()
        .contains("unknown_asn"));
    let (members, _) = export(
        &[path],
        &EvidenceLimits::default(),
        Some(&member),
        &MrtReplayOptions::default(),
    );
    assert_eq!(members.coverage.selected, 1);
    assert_eq!(members.coverage.unknown_asn, 1);
}

#[test]
fn peer_labels_and_as_trans_do_not_become_origin_roles() {
    let scratch = Scratch::new();
    let path = scratch.store(
        "as-trans",
        "collector",
        &[table(11), rib(12, 10, 2, 23456)].concat(),
        5,
    );
    let query = window(
        TimeBasis::MrtRecordTime,
        -1,
        20_000_000_000,
        Some(AsnRole::Origin),
    );
    let (manifest, _) = export(
        &[path],
        &EvidenceLimits::default(),
        Some(&query),
        &MrtReplayOptions::default(),
    );
    assert_eq!(manifest.coverage.selected, 0);
    assert_eq!(manifest.coverage.unknown_asn, 2);
}

#[test]
fn source_policy_and_rows_bind_identity_but_read_splits_and_paths_do_not() {
    let scratch = Scratch::new();
    let raw = [table(11), rib(12, 10, 2, 65551)].concat();
    let first = scratch.store("one", "collector", &raw, 1);
    let second = scratch.store("seven", "collector", &raw, 7);
    let options = MrtReplayOptions::default();
    let (one, bytes_one) = export(
        std::slice::from_ref(&first),
        &EvidenceLimits::default(),
        None,
        &options,
    );
    let (seven, bytes_seven) = export(&[second], &EvidenceLimits::default(), None, &options);
    assert_eq!(one.semantic_identity, seven.semantic_identity);
    assert_eq!(bytes_one, bytes_seven);
    let external = MrtReplayOptions {
        peer_relationship: Some(PeerRelationship::External),
    };
    let (different_policy, _) = export(&[first], &EvidenceLimits::default(), None, &external);
    assert_ne!(one.semantic_identity, different_policy.semantic_identity);
    let changed = scratch.store(
        "changed",
        "collector",
        &[table(11), rib(13, 10, 2, 65551)].concat(),
        1,
    );
    let (different_source, _) = export(&[changed], &EvidenceLimits::default(), None, &options);
    assert_ne!(one.semantic_identity, different_source.semantic_identity);
    let rows_end = bytes_one
        .iter()
        .enumerate()
        .filter(|(_, byte)| **byte == b'\n')
        .nth(one.rows as usize - 1)
        .unwrap()
        .0
        + 1;
    assert_eq!(one.rows_bytes, rows_end as u64);
    assert_eq!(
        one.rows_sha256,
        sha256::hex(&sha256::digest(&bytes_one[..rows_end]))
    );
}

#[test]
fn tampered_sequence_references_and_swapped_paths_are_rejected_before_completion() {
    let scratch = Scratch::new();
    let a = scratch.store("a", "collector", &table(10), 1);
    let b = scratch.store("b", "other", &table(11), 1);
    let paths = [a.clone(), b.clone()];
    let limits = EvidenceLimits::default();
    let sequence =
        bgp_evidence::create_sequence(&paths, &MrtStreamLimits::default(), &limits).unwrap();
    for mutate in 0..5 {
        let mut candidate = sequence.clone();
        match mutate {
            0 => candidate.entries[1].ordinal = 0,
            1 => candidate.entries[1].predecessor_digest = "0".repeat(64),
            2 => candidate.entries[0].store_seal = "0".repeat(64),
            3 => candidate.entries[0].source_sha256 = "0".repeat(64),
            _ => candidate.entries[0].checkpoint_id = "different".into(),
        }
        let mut output = Vec::new();
        assert!(bgp_evidence::export_verified_sequence(
            &candidate,
            &paths,
            &MrtStreamLimits::default(),
            &Limits::default(),
            &limits,
            &MrtReplayOptions::default(),
            None,
            &mut output
        )
        .is_err());
        assert!(output.is_empty());
    }
    let mut output = Vec::new();
    assert!(bgp_evidence::export_verified_sequence(
        &sequence,
        &[b, a],
        &MrtStreamLimits::default(),
        &Limits::default(),
        &limits,
        &MrtReplayOptions::default(),
        None,
        &mut output
    )
    .is_err());
    assert!(output.is_empty());
}

#[test]
fn exact_output_and_row_caps_never_publish_a_partial_complete_manifest() {
    let scratch = Scratch::new();
    let path = scratch.store(
        "caps",
        "collector",
        &[table(11), rib(12, 10, 2, 65551)].concat(),
        4,
    );
    let options = MrtReplayOptions::default();
    let (baseline, bytes) = export(
        std::slice::from_ref(&path),
        &EvidenceLimits::default(),
        None,
        &options,
    );
    let exact = EvidenceLimits {
        rows: baseline.rows,
        output_bytes: bytes.len(),
        ..EvidenceLimits::default()
    };
    let (_, equal) = export(std::slice::from_ref(&path), &exact, None, &options);
    assert_eq!(equal.len(), bytes.len());
    for limits in [
        EvidenceLimits {
            output_bytes: bytes.len() - 1,
            ..exact.clone()
        },
        EvidenceLimits {
            rows: baseline.rows - 1,
            ..exact.clone()
        },
        EvidenceLimits {
            source_bytes: baseline.sequence.entries[0].source_bytes - 1,
            ..exact.clone()
        },
        EvidenceLimits { work: 1, ..exact },
    ] {
        let mut output = Vec::new();
        assert!(bgp_evidence::export_sequence(
            std::slice::from_ref(&path),
            &MrtStreamLimits::default(),
            &Limits::default(),
            &limits,
            &options,
            None,
            &mut output
        )
        .is_err());
        let text = String::from_utf8(output).unwrap();
        assert!(!text.contains("\"complete\":true"));
    }
}

#[test]
fn witnesses_are_bounded_without_erasing_unknown_counts() {
    let scratch = Scratch::new();
    let path = scratch.store(
        "unknown",
        "collector",
        &[table(11), record(12, 99, 0, &[]), record(13, 99, 0, &[])].concat(),
        1,
    );
    let query = window(
        TimeBasis::RibOriginatedTime,
        0,
        20_000_000_000,
        Some(AsnRole::Origin),
    );
    let limits = EvidenceLimits {
        witnesses: 1,
        ..EvidenceLimits::default()
    };
    let (manifest, _) = export(&[path], &limits, Some(&query), &MrtReplayOptions::default());
    assert_eq!(manifest.coverage.unknown_time, 3);
    assert_eq!(manifest.coverage.unknown_asn, 3);
    assert_eq!(manifest.coverage.witnesses.len(), 1);
    assert!(manifest.coverage.witnesses_truncated >= 5);
    assert_eq!(manifest.rows, 3);
}
