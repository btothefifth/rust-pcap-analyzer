//! Publication-boundary tests. Expected JSON literals and scalar work counts
//! are independently specified; these tests do not imply source or RIB truth.
use super::*;
use crate::deep::bgp::{ImportedRouteObservation, PathAttributes, Prefix, RouteAction};
use crate::deep::bgp_import::{self, ClockPolicy, ObservationClock, SourceBatch, SourceRange};
use pcap_evidence::ErrorCode;

fn declaration() -> ImportContext {
    ImportContext {
        source_id: "route-source".into(),
        source_schema: "synthetic-route-sequence".into(),
        source_version: Some("1".into()),
        clock: ObservationClock {
            policy: ClockPolicy::SourceLabel,
            clock_id: Some("clock-a".into()),
            reported_uncertainty_ns: None,
        },
        batch: SourceBatch {
            batch_id: Some("batch-a".into()),
            sha256: Some(digest(b"synthetic batch")),
            byte_length: Some(512),
        },
        checkpoint_id: "checkpoint-a".into(),
        session: "session-a".into(),
        generation: 7,
        direction: None,
        peer: Some("peer-a".into()),
        local: Some("local-a".into()),
        provenance: vec![SourceRange {
            start: 0,
            end: 512,
            sha256: None,
        }],
    }
}

fn record(ordinal: u64, id: &str, med: u32) -> FeedRecord {
    let mut context = declaration();
    context.direction = Some(0);
    context.provenance = vec![SourceRange {
        start: 10,
        end: 20,
        sha256: Some(digest(b"record")),
    }];
    let value = bgp_import::normalize_with_context(
        ImportedRouteObservation {
            source_id: context.source_id.clone(),
            record_id: id.into(),
            observed_at_ns: Some(100),
            session: Some(context.session.clone()),
            peer: context.peer.clone(),
            local: context.local.clone(),
            action: RouteAction::Announce,
            prefix: Prefix::ipv4([203, 0, 113, 0], 24).unwrap(),
            attributes: PathAttributes {
                med: Some(med),
                ..PathAttributes::default()
            },
        },
        context,
        &Limits::default(),
    )
    .unwrap();
    FeedRecord::from_normalized(
        ordinal,
        &value,
        Coverage::DeclaredComplete,
        &Limits::default(),
    )
    .unwrap()
}

fn envelope(cursor: &Cursor, records: Vec<FeedRecord>, completion: Completion) -> FeedEnvelope {
    FeedEnvelope::new(
        declaration(),
        cursor.clone(),
        records,
        completion,
        &Limits::default(),
    )
    .unwrap()
}

fn route_context() -> RouteContext {
    RouteContext {
        namespace: Some("explicit-test-namespace".into()),
        flow_id: None,
        captured_or_legacy_clock: None,
        coverage: Coverage::DeclaredComplete,
    }
}

#[derive(Debug, Eq, PartialEq)]
struct Snapshot {
    receipt: String,
    receipt_value: Json,
    state: String,
    cursors: Vec<Cursor>,
    records: Vec<Vec<String>>,
    state_indices: Vec<usize>,
    generation: u64,
    completion: Completion,
    quarantined: bool,
}
fn snapshot(r: &FeedReplay) -> Snapshot {
    Snapshot {
        receipt: r.receipt.encode().to_owned(),
        receipt_value: r.receipt.json().clone(),
        // Include the staged historical candidate state even in quarantine.
        state: r.state.encode().to_owned(),
        cursors: r.cursors.clone(),
        records: r
            .records
            .iter()
            .map(|w| {
                std::iter::once(&w.original)
                    .chain(w.alternatives.iter())
                    .map(|r| r.encode().to_owned())
                    .collect()
            })
            .collect(),
        state_indices: r.records.iter().map(|w| w.state_observation).collect(),
        generation: r.generation,
        completion: r.completion,
        quarantined: r.quarantined,
    }
}
fn rejected(r: &mut FeedReplay, page: &FeedEnvelope) -> Error {
    let before = snapshot(r);
    let error = r.apply(page).unwrap_err();
    assert_eq!(
        snapshot(r),
        before,
        "a rejected page changed retained/public evidence"
    );
    error
}

/// Test-only lowering of the replay-owned budget isolates publication from the
/// separately bounded CandidateState (constructed under the original limits).
/// Every rejected trial compares all journal, cursor, receipt and state bytes.
fn work_boundary(seed: &FeedReplay, page: &FeedEnvelope) -> usize {
    let mut expected = seed.clone();
    expected.apply(page).unwrap();
    let expected = snapshot(&expected);
    let mut low = 1;
    let mut high = Limits::default().work;
    while low < high {
        let mid = low + (high - low) / 2;
        let mut trial = seed.clone();
        trial.limits.work = mid;
        let before = snapshot(&trial);
        match trial.apply(page) {
            Ok(_) => {
                assert_eq!(snapshot(&trial), expected);
                high = mid;
            }
            Err(error) => {
                assert_eq!(error.code, ErrorCode::LimitExceeded);
                assert_eq!(snapshot(&trial), before);
                low = mid + 1;
            }
        }
    }
    let mut exact = seed.clone();
    exact.limits.work = low;
    exact.apply(page).unwrap();
    assert_eq!(snapshot(&exact), expected);
    let mut below = seed.clone();
    below.limits.work = low - 1;
    assert_eq!(rejected(&mut below, page).code, ErrorCode::LimitExceeded);
    low
}

#[test]
fn scalar_work_is_reserved_before_encoding_at_the_exact_boundary() {
    // false: one visited node + 4 * five rendered bytes = 21 units.
    let exact = Limits {
        work: 21,
        output_bytes: 5,
        ..Limits::default()
    };
    let mut guard = Guard::new(&exact);
    let (value, encoded) = guard.encode(&Json::Bool(false), 5).unwrap();
    assert_eq!(value, Json::Bool(false));
    assert_eq!(encoded, "false");
    assert_eq!(guard.work, 21);
    let below = Limits {
        work: 20,
        ..exact.clone()
    };
    // prepare_encoding cannot clone/render; a rejected reservation stops here.
    let error = Guard::new(&below)
        .prepare_encoding(&Json::Bool(false), 5)
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::LimitExceeded);
    assert_eq!(error.field, "bgp_replay_work");
    let error = Guard::new(&exact)
        .encode(&Json::Bool(false), 4)
        .unwrap_err();
    assert_eq!(error.field, "report_bytes");
}

#[test]
fn a_second_encoding_cannot_reset_the_work_counter() {
    let limits = Limits {
        work: 42,
        ..Limits::default()
    };
    let mut guard = Guard::new(&limits);
    for _ in 0..2 {
        assert_eq!(guard.encode(&Json::Bool(false), 5).unwrap().1, "false");
    }
    assert_eq!(guard.work, 42);
    assert_eq!(
        guard.prepare_encoding(&Json::Null, 4).unwrap_err().field,
        "bgp_replay_work"
    );
    let below = Limits { work: 41, ..limits };
    let mut guard = Guard::new(&below);
    guard.encode(&Json::Bool(false), 5).unwrap();
    assert_eq!(
        guard
            .prepare_encoding(&Json::Bool(false), 5)
            .unwrap_err()
            .field,
        "bgp_replay_work"
    );
}

#[test]
fn nested_canonical_output_has_exact_utf8_and_escape_lengths() {
    let value = Json::object([
        (
            "z",
            Json::array([
                Json::Null,
                Json::Bool(true),
                Json::Bool(false),
                Json::Number(0),
                Json::Number(u64::MAX),
                Json::String("\"\\\n\r\t\u{8}\u{c}\u{0}é😀".into()),
            ]),
        ),
        (
            "a",
            Json::object([("b", Json::Array(vec![])), ("a", Json::Object(vec![]))]),
        ),
    ]);
    let expected = r#"{"a":{"a":{},"b":[]},"z":[null,true,false,0,18446744073709551615,"\"\\\n\r\t\b\f\u0000é😀"]}"#;
    let limits = Limits::default();
    let mut guard = Guard::new(&limits);
    assert_eq!(
        guard.measure(&value, expected.len()).unwrap(),
        expected.len()
    );
    let (canonical, output) = Guard::new(&limits).encode(&value, expected.len()).unwrap();
    assert_eq!(output, expected);
    assert_eq!(canonical.encode(), expected);
    assert_eq!(
        Guard::new(&limits)
            .encode(&value, expected.len() - 1)
            .unwrap_err()
            .field,
        "report_bytes"
    );
}

#[test]
fn measurement_matches_shared_encoder_for_every_control_and_decimal_boundary() {
    let limits = Limits::default();
    for c in (0u8..=127).map(char::from).chain(['é', '水', '😀']) {
        let value = Json::String(c.to_string());
        let expected = value.encode();
        assert_eq!(
            Guard::new(&limits).measure(&value, expected.len()).unwrap(),
            expected.len()
        );
    }
    for n in [0, 1, 9, 10, 99, 100, 999, 1000, 9_999_999_999, u64::MAX] {
        let value = Json::Number(n);
        assert_eq!(
            Guard::new(&limits).measure(&value, 20).unwrap(),
            value.encode().len()
        );
    }
    // 27 generic control escapes * 6 + five short escapes * 2 + quotes.
    let controls: String = (0u8..32).map(char::from).collect();
    assert_eq!(
        Guard::new(&limits)
            .measure(&Json::String(controls), 174)
            .unwrap(),
        174
    );
}

#[test]
fn preflight_preserves_structural_reference_and_authority_rejections() {
    let limits = Limits::default();
    let duplicate = Json::object([("a", Json::Null), ("a", Json::Null)]);
    assert_eq!(
        Guard::new(&limits)
            .prepare_encoding(&duplicate, usize::MAX)
            .unwrap_err()
            .field,
        "bgp_replay_duplicate_key"
    );
    let authority = Json::object([("causality_established", true.into())]);
    assert_eq!(
        Guard::new(&limits)
            .prepare_encoding(&authority, usize::MAX)
            .unwrap_err()
            .field,
        "bgp_replay_authority"
    );
    let nested = Json::array([Json::array([Json::Null])]);
    let shallow = Limits {
        depth: 2,
        ..limits.clone()
    };
    assert_eq!(
        Guard::new(&shallow)
            .prepare_encoding(&nested, usize::MAX)
            .unwrap_err()
            .field,
        "bgp_replay_depth"
    );
    let references = Json::object([("ranges", Json::array([Json::Null, Json::Null]))]);
    let small = Limits {
        spans: 1,
        ..limits.clone()
    };
    assert_eq!(
        Guard::new(&small)
            .prepare_encoding(&references, usize::MAX)
            .unwrap_err()
            .field,
        "bgp_replay_spans"
    );
    let small = Limits {
        fields: 1,
        ..limits
    };
    assert_eq!(
        Guard::new(&small)
            .prepare_encoding(&nested, usize::MAX)
            .unwrap_err()
            .field,
        "bgp_replay_fields"
    );
}

#[test]
fn constructor_receipt_succeeds_at_exact_output_cap_and_rejects_one_below() {
    let baseline = FeedReplay::new(declaration(), Limits::default()).unwrap();
    let cap = baseline.receipt().encode().len();
    let exact = FeedReplay::new(
        declaration(),
        Limits {
            output_bytes: cap,
            ..Limits::default()
        },
    )
    .unwrap();
    assert_eq!(snapshot(&exact), snapshot(&baseline));
    assert!(FeedReplay::new(
        declaration(),
        Limits {
            output_bytes: cap - 1,
            ..Limits::default()
        }
    )
    .is_err());
}

#[test]
fn page_receipt_output_boundary_is_atomic_and_byte_preserving() {
    let seed = FeedReplay::new(declaration(), Limits::default()).unwrap();
    let page = envelope(seed.cursor(), vec![record(0, "a", 5)], Completion::Partial);
    let mut expected = seed.clone();
    expected.apply(&page).unwrap();
    let cap = expected.receipt().encode().len();
    assert!(cap >= page.encode().len());
    let mut exact = seed.clone();
    exact.limits.output_bytes = cap;
    exact.apply(&page).unwrap();
    assert_eq!(snapshot(&exact), snapshot(&expected));
    let mut below = seed;
    below.limits.output_bytes = cap - 1;
    assert_eq!(rejected(&mut below, &page).field, "report_bytes");
}

#[test]
fn work_boundary_covers_application_and_identical_replay() {
    let seed = FeedReplay::new(declaration(), Limits::default()).unwrap();
    let page = envelope(seed.cursor(), vec![record(0, "a", 5)], Completion::Partial);
    work_boundary(&seed, &page);
    let mut accepted = seed;
    accepted.apply(&page).unwrap();
    work_boundary(&accepted, &page);
    let before = snapshot(&accepted);
    for _ in 0..3 {
        assert_eq!(
            accepted.apply(&page).unwrap().status,
            ReplayStatus::IdenticalReplay
        );
    }
    assert_eq!(snapshot(&accepted), before);
}

#[test]
fn finalization_work_and_output_failures_do_not_publish_a_final_marker() {
    let mut seed = FeedReplay::new(declaration(), Limits::default()).unwrap();
    seed.apply(&envelope(
        seed.cursor(),
        vec![record(0, "a", 5)],
        Completion::Partial,
    ))
    .unwrap();
    let page = envelope(seed.cursor(), vec![], Completion::Final);
    work_boundary(&seed, &page);
    let mut expected = seed.clone();
    assert_eq!(
        expected.apply(&page).unwrap().status,
        ReplayStatus::Finalized
    );
    let cap = expected.receipt().encode().len();
    let mut exact = seed.clone();
    exact.limits.output_bytes = cap;
    exact.apply(&page).unwrap();
    assert_eq!(snapshot(&exact), snapshot(&expected));
    let mut below = seed;
    below.limits.output_bytes = cap - 1;
    assert_eq!(rejected(&mut below, &page).code, ErrorCode::LimitExceeded);
    assert_eq!(below.completion(), Completion::Partial);
    assert_eq!(
        exact.apply(&page).unwrap().status,
        ReplayStatus::IdenticalReplay
    );
}

#[test]
fn conflict_work_and_output_failures_do_not_publish_quarantine_or_alternatives() {
    let mut seed = FeedReplay::new(declaration(), Limits::default()).unwrap();
    let first = seed.cursor().clone();
    seed.apply(&envelope(
        &first,
        vec![record(0, "a", 5)],
        Completion::Final,
    ))
    .unwrap();
    let conflict = envelope(&first, vec![record(0, "a", 6)], Completion::Partial);
    work_boundary(&seed, &conflict);
    let mut expected = seed.clone();
    assert_eq!(
        expected.apply(&conflict).unwrap().status,
        ReplayStatus::Quarantined
    );
    let cap = expected.receipt().encode().len();
    let mut exact = seed.clone();
    exact.limits.output_bytes = cap;
    exact.apply(&conflict).unwrap();
    assert_eq!(snapshot(&exact), snapshot(&expected));
    let mut below = seed;
    below.limits.output_bytes = cap - 1;
    assert_eq!(
        rejected(&mut below, &conflict).code,
        ErrorCode::LimitExceeded
    );
    assert!(!below.is_quarantined());
    assert!(exact.candidate_state().is_err());
    work_boundary(&expected, &conflict); // replaying a retained conflict is a no-op
    let before = snapshot(&exact);
    assert!(exact
        .association_receipt(&route_context(), &Limits::default())
        .is_err());
    assert_eq!(snapshot(&exact), before);
}

#[test]
fn association_receipt_exact_output_and_work_boundaries_are_read_only() {
    // Empty state isolates the association receipt encoder's exact output cap.
    let replay = FeedReplay::new(declaration(), Limits::default()).unwrap();
    let before = snapshot(&replay);
    let expected = replay
        .association_receipt(&route_context(), &Limits::default())
        .unwrap();
    let cap = expected.encode().len();
    let exact = replay
        .association_receipt(
            &route_context(),
            &Limits {
                output_bytes: cap,
                ..Limits::default()
            },
        )
        .unwrap();
    assert_eq!(exact.encode(), expected.encode());
    assert!(replay
        .association_receipt(
            &route_context(),
            &Limits {
                output_bytes: cap - 1,
                ..Limits::default()
            }
        )
        .is_err());
    assert_eq!(snapshot(&replay), before);

    let mut low = 1;
    let mut high = Limits::default().work;
    while low < high {
        let mid = low + (high - low) / 2;
        let result = replay.association_receipt(
            &route_context(),
            &Limits {
                work: mid,
                ..Limits::default()
            },
        );
        match result {
            Ok(receipt) => {
                assert_eq!(receipt.encode(), expected.encode());
                high = mid;
            }
            Err(error) => {
                assert_eq!(error.code, ErrorCode::LimitExceeded);
                low = mid + 1;
            }
        }
        assert_eq!(snapshot(&replay), before);
    }
    assert_eq!(
        replay
            .association_receipt(
                &route_context(),
                &Limits {
                    work: low,
                    ..Limits::default()
                }
            )
            .unwrap()
            .encode(),
        expected.encode()
    );
    assert!(replay
        .association_receipt(
            &route_context(),
            &Limits {
                work: low - 1,
                ..Limits::default()
            }
        )
        .is_err());
    assert_eq!(snapshot(&replay), before);
}

#[test]
fn partial_final_and_nested_source_values_survive_association_without_clock_upgrade() {
    let mut replay = FeedReplay::new(declaration(), Limits::default()).unwrap();
    let mut normalized = record(0, "nested", 5).observation().normalized().clone();
    let Json::Object(fields) = &mut normalized else {
        panic!("normalized object")
    };
    fields.push((
        "uninterpreted_extension",
        Json::object([
            ("z", Json::array(["é".into(), "quote\"slash\\".into()])),
            ("a", Json::Number(u64::MAX)),
        ]),
    ));
    let item =
        FeedRecord::from_normalized(0, &normalized, Coverage::Unknown, &Limits::default()).unwrap();
    replay
        .apply(&envelope(replay.cursor(), vec![item], Completion::Partial))
        .unwrap();
    let before = snapshot(&replay);
    let partial = replay
        .association_receipt(&route_context(), &Limits::default())
        .unwrap();
    assert_eq!(partial.coverage(), Coverage::Incomplete);
    assert_eq!(snapshot(&replay), before);
    replay
        .apply(&envelope(replay.cursor(), vec![], Completion::Final))
        .unwrap();
    let before = snapshot(&replay);
    let receipt = replay
        .association_receipt(&route_context(), &Limits::default())
        .unwrap();
    assert_eq!(receipt.coverage(), Coverage::Unknown);
    assert!(receipt.encode().contains("uninterpreted_extension"));
    assert!(receipt.encode().contains("18446744073709551615"));
    assert!(receipt
        .encode()
        .contains("\"reported_uncertainty_ns\":null"));
    assert!(receipt.encode().contains("\"causality_established\":false"));
    assert_eq!(snapshot(&replay), before);
}

#[test]
fn independently_fixed_cursor_commitments_remain_unchanged() {
    fn expected(name: &str) -> &str {
        include_str!("../../../tests/fixtures/bgp_replay_hashes.tsv")
            .lines()
            .find_map(|line| {
                let (key, value) = line.split_once('\t')?;
                (key == name).then_some(value)
            })
            .unwrap()
    }
    let mut replay = FeedReplay::new(declaration(), Limits::default()).unwrap();
    assert_eq!(replay.cursor().feed_sha256, expected("feed"));
    assert_eq!(replay.cursor().prefix_sha256, expected("prefix0"));
    replay
        .apply(&envelope(
            replay.cursor(),
            vec![record(0, "a", 5)],
            Completion::Partial,
        ))
        .unwrap();
    assert_eq!(replay.cursor().prefix_sha256, expected("prefix1"));
    replay
        .apply(&envelope(
            replay.cursor(),
            vec![record(1, "b", 5)],
            Completion::Final,
        ))
        .unwrap();
    assert_eq!(replay.cursor().prefix_sha256, expected("prefix2"));
}

#[test]
fn missing_or_changed_predecessors_remain_atomic_after_accounting_repair() {
    let mut replay = FeedReplay::new(declaration(), Limits::default()).unwrap();
    let mut page = envelope(
        replay.cursor(),
        vec![record(0, "a", 5)],
        Completion::Partial,
    );
    page.previous.next_ordinal = 1;
    assert_eq!(rejected(&mut replay, &page).field, "bgp_replay_predecessor");
    let mut page = envelope(
        replay.cursor(),
        vec![record(0, "a", 5)],
        Completion::Partial,
    );
    page.previous.prefix_sha256 = "00".repeat(32);
    assert_eq!(rejected(&mut replay, &page).field, "bgp_replay_predecessor");
}

#[test]
fn valid_first_record_then_missing_generation_boundary_does_not_publish_partial_state() {
    fn generation(value: &mut Json, next: u64) {
        let Json::Object(fields) = value else {
            panic!("expected object")
        };
        for (key, value) in fields {
            if *key == "generation" {
                *value = next.to_string().into();
            } else if *key == "import_context" {
                generation(value, next);
            }
        }
    }
    let mut replay = FeedReplay::new(declaration(), Limits::default()).unwrap();
    let mut later = record(1, "b", 5).observation().normalized().clone();
    generation(&mut later, 8);
    let later =
        FeedRecord::from_normalized(1, &later, Coverage::DeclaredComplete, &Limits::default())
            .unwrap();
    let page = envelope(
        replay.cursor(),
        vec![record(0, "a", 5), later],
        Completion::Final,
    );
    assert_eq!(rejected(&mut replay, &page).field, "bgp_replay_generation");
    assert_eq!(replay.cursor().next_ordinal, 0);
    assert_eq!(replay.completion(), Completion::Partial);
}

#[test]
fn association_rejection_with_retained_nested_records_preserves_the_entire_replay() {
    let mut replay = FeedReplay::new(declaration(), Limits::default()).unwrap();
    replay
        .apply(&envelope(
            replay.cursor(),
            vec![record(0, "a", 5)],
            Completion::Final,
        ))
        .unwrap();
    let before = snapshot(&replay);
    let expected = replay
        .association_receipt(&route_context(), &Limits::default())
        .unwrap();
    for limits in [
        Limits {
            output_bytes: 1,
            ..Limits::default()
        },
        Limits {
            work: 1,
            ..Limits::default()
        },
        Limits {
            spans: 1,
            ..Limits::default()
        },
        Limits {
            fields: 1,
            ..Limits::default()
        },
    ] {
        let error = replay
            .association_receipt(&route_context(), &limits)
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::LimitExceeded);
        assert_eq!(snapshot(&replay), before);
    }
    assert_eq!(
        replay
            .association_receipt(&route_context(), &Limits::default())
            .unwrap()
            .encode(),
        expected.encode()
    );
}
