//! Fixed sequence expectations, not endpoint, source-authentication or RIB truth.
use pcap_evidence::{
    json::Json,
    provenance::{EvidenceBytes, PacketId},
    sha256, ErrorCode,
};
use pcap_evidence_product::deep::{
    bgp::{self, ImportedRouteObservation, PathAttributes, PcapMetadata, Prefix, RouteAction},
    bgp_association::{self as association, AssociationStatus, Coverage, Reason, RouteContext},
    bgp_import::{
        self, ClockPolicy, GenerationBoundary, ImportContext, ObservationClock, SourceBatch,
        SourceRange,
    },
    bgp_replay::{
        Completion, Cursor, FeedEnvelope, FeedRecord, FeedReplay, ReplayStatus, FEED_SCHEMA,
        RECEIPT_SCHEMA,
    },
    bgp_state::Observation,
    Limits,
};

fn digest(b: &[u8]) -> String {
    sha256::hex(&sha256::digest(b))
}
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
fn normalized(
    c: &ImportContext,
    id: &str,
    direction: Option<u8>,
    generation: u64,
    action: RouteAction,
    time: Option<i64>,
    med: u32,
) -> Json {
    let mut c = c.clone();
    c.generation = generation;
    c.direction = direction;
    c.provenance = vec![SourceRange {
        start: 10,
        end: 20,
        sha256: Some(digest(b"record")),
    }];
    bgp_import::normalize_with_context(
        ImportedRouteObservation {
            source_id: c.source_id.clone(),
            record_id: id.into(),
            observed_at_ns: time,
            session: Some(c.session.clone()),
            peer: c.peer.clone(),
            local: c.local.clone(),
            action,
            prefix: Prefix::ipv4([203, 0, 113, 0], 24).unwrap(),
            attributes: PathAttributes {
                med: Some(med),
                ..PathAttributes::default()
            },
        },
        c,
        &Limits::default(),
    )
    .unwrap()
}
fn record(c: &ImportContext, ordinal: u64, id: &str) -> FeedRecord {
    FeedRecord::from_normalized(
        ordinal,
        &normalized(c, id, Some(0), 7, RouteAction::Announce, Some(100), 5),
        Coverage::DeclaredComplete,
        &Limits::default(),
    )
    .unwrap()
}
fn boundary(c: &ImportContext, ordinal: u64, id: &str, previous: u64, next: u64) -> FeedRecord {
    let mut c = c.clone();
    c.generation = next;
    c.direction = None;
    let value = bgp_import::normalize_boundary(
        c,
        GenerationBoundary {
            previous_generation: previous,
            reason: "explicit generation boundary".into(),
        },
        id.into(),
        None,
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
fn page(
    c: &ImportContext,
    previous: &Cursor,
    records: Vec<FeedRecord>,
    completion: Completion,
) -> FeedEnvelope {
    FeedEnvelope::new(
        c.clone(),
        previous.clone(),
        records,
        completion,
        &Limits::default(),
    )
    .unwrap()
}
fn get<'a>(v: &'a Json, key: &str) -> &'a Json {
    let Json::Object(items) = v else {
        panic!("not object")
    };
    &items.iter().find(|(k, _)| *k == key).unwrap().1
}
fn set(v: &mut Json, key: &'static str, value: Json) {
    let Json::Object(items) = v else {
        panic!("not object")
    };
    if let Some((_, old)) = items.iter_mut().find(|(k, _)| *k == key) {
        *old = value;
    } else {
        items.push((key, value));
    }
}
fn changed_record(c: &ImportContext, ordinal: u64, id: &str, med: u32) -> FeedRecord {
    FeedRecord::from_normalized(
        ordinal,
        &normalized(c, id, Some(0), 7, RouteAction::Announce, Some(100), med),
        Coverage::DeclaredComplete,
        &Limits::default(),
    )
    .unwrap()
}
fn assert_atomic(replay: &mut FeedReplay, envelope: &FeedEnvelope) -> pcap_evidence::Error {
    let before = replay.receipt().encode().to_owned();
    let state = replay.candidate_state().unwrap().encode().to_owned();
    let cursor = replay.cursor().clone();
    let error = replay.apply(envelope).unwrap_err();
    assert_eq!(replay.receipt().encode(), before);
    assert_eq!(replay.candidate_state().unwrap().encode(), state);
    assert_eq!(replay.cursor(), &cursor);
    error
}

#[test]
fn empty_partial_and_final_feeds_never_invent_routes() {
    let c = declaration();
    let mut r = FeedReplay::new(c.clone(), Limits::default()).unwrap();
    let original = r.receipt().encode().to_owned();
    assert_eq!(
        r.apply(&page(&c, r.cursor(), Vec::new(), Completion::Partial))
            .unwrap()
            .status,
        ReplayStatus::IdenticalReplay
    );
    assert_eq!(r.receipt().encode(), original);
    assert_eq!(r.effective_coverage(), Coverage::Incomplete);
    let final_page = page(&c, r.cursor(), Vec::new(), Completion::Final);
    assert_eq!(
        r.apply(&final_page).unwrap().status,
        ReplayStatus::Finalized
    );
    assert!(r.candidate_state().unwrap().routes().is_empty());
    let final_output = r.receipt().encode().to_owned();
    assert_eq!(
        r.apply(&final_page).unwrap().status,
        ReplayStatus::IdenticalReplay
    );
    assert_eq!(r.receipt().encode(), final_output);
}
#[test]
fn exact_page_and_record_replay_leave_journal_and_output_bytes_unchanged() {
    let c = declaration();
    let mut r = FeedReplay::new(c.clone(), Limits::default()).unwrap();
    let first = page(
        &c,
        r.cursor(),
        vec![record(&c, 0, "a")],
        Completion::Partial,
    );
    r.apply(&first).unwrap();
    let before = r.receipt().encode().to_owned();
    let state = r.candidate_state().unwrap().encode().to_owned();
    for _ in 0..3 {
        assert_eq!(
            r.apply(&first).unwrap().status,
            ReplayStatus::IdenticalReplay
        );
        assert_eq!(r.records().len(), 1);
        assert_eq!(r.receipt().encode(), before);
        assert_eq!(r.candidate_state().unwrap().encode(), state);
    }
}
#[test]
fn page_segmentation_is_not_evidence_order_and_does_not_change_final_bytes() {
    let c = declaration();
    let records = vec![record(&c, 0, "a"), record(&c, 1, "b")];
    let mut one = FeedReplay::new(c.clone(), Limits::default()).unwrap();
    let mut pages = FeedReplay::new(c.clone(), Limits::default()).unwrap();
    one.apply(&page(&c, one.cursor(), records.clone(), Completion::Final))
        .unwrap();
    pages
        .apply(&page(
            &c,
            pages.cursor(),
            vec![records[0].clone()],
            Completion::Partial,
        ))
        .unwrap();
    pages
        .apply(&page(
            &c,
            pages.cursor(),
            vec![records[1].clone()],
            Completion::Final,
        ))
        .unwrap();
    assert_eq!(one.receipt().encode(), pages.receipt().encode());
    assert_eq!(
        one.candidate_state().unwrap().encode(),
        pages.candidate_state().unwrap().encode()
    );
}
#[test]
fn overlapping_replay_prefix_may_append_only_a_verified_contiguous_suffix() {
    let c = declaration();
    let mut r = FeedReplay::new(c.clone(), Limits::default()).unwrap();
    let start = r.cursor().clone();
    r.apply(&page(
        &c,
        &start,
        vec![record(&c, 0, "a")],
        Completion::Partial,
    ))
    .unwrap();
    r.apply(&page(
        &c,
        &start,
        vec![record(&c, 0, "a"), record(&c, 1, "b")],
        Completion::Final,
    ))
    .unwrap();
    assert_eq!(r.records().len(), 2);
    assert_eq!(r.candidate_state().unwrap().observations().len(), 2);
}
#[test]
fn changed_content_at_an_existing_ordinal_is_retained_and_quarantined() {
    let c = declaration();
    let mut r = FeedReplay::new(c.clone(), Limits::default()).unwrap();
    let start = r.cursor().clone();
    r.apply(&page(
        &c,
        &start,
        vec![record(&c, 0, "a")],
        Completion::Final,
    ))
    .unwrap();
    let conflict = page(
        &c,
        &start,
        vec![changed_record(&c, 0, "a", 9)],
        Completion::Final,
    );
    assert_eq!(
        r.apply(&conflict).unwrap().status,
        ReplayStatus::Quarantined
    );
    assert!(r.is_quarantined());
    assert!(r.candidate_state().is_err());
    assert_eq!(r.records()[0].alternatives().len(), 1);
    assert!(r
        .receipt()
        .encode()
        .contains("\"candidate_state_sha256\":null"));
    let after = r.receipt().encode().to_owned();
    assert_eq!(
        r.apply(&conflict).unwrap().status,
        ReplayStatus::IdenticalReplay
    );
    assert_eq!(r.receipt().encode(), after);
}
#[test]
fn changed_ordered_identity_and_coverage_are_conflicts_not_winner_choices() {
    for change in 0..2 {
        let c = declaration();
        let mut r = FeedReplay::new(c.clone(), Limits::default()).unwrap();
        let start = r.cursor().clone();
        r.apply(&page(
            &c,
            &start,
            vec![record(&c, 0, "a")],
            Completion::Partial,
        ))
        .unwrap();
        let other = if change == 0 {
            record(&c, 0, "different-record")
        } else {
            FeedRecord::from_normalized(
                0,
                record(&c, 0, "a").observation().normalized(),
                Coverage::Unknown,
                &Limits::default(),
            )
            .unwrap()
        };
        r.apply(&page(&c, &start, vec![other], Completion::Partial))
            .unwrap();
        assert!(r.is_quarantined());
        assert_eq!(r.records()[0].alternatives().len(), 1);
    }
}
#[test]
fn conflicts_cannot_authorize_an_append_or_clear_with_a_final_marker() {
    let c = declaration();
    let mut r = FeedReplay::new(c.clone(), Limits::default()).unwrap();
    let start = r.cursor().clone();
    r.apply(&page(
        &c,
        &start,
        vec![record(&c, 0, "a")],
        Completion::Partial,
    ))
    .unwrap();
    let mixed = page(
        &c,
        &start,
        vec![changed_record(&c, 0, "a", 9), record(&c, 1, "b")],
        Completion::Final,
    );
    assert_eq!(
        assert_atomic(&mut r, &mixed).field,
        "bgp_replay_ambiguous_extension"
    );
    r.apply(&page(
        &c,
        &start,
        vec![changed_record(&c, 0, "a", 9)],
        Completion::Final,
    ))
    .unwrap();
    assert_eq!(r.completion(), Completion::Partial);
    let before = r.receipt().encode().to_owned();
    assert!(r
        .apply(&page(
            &c,
            r.cursor(),
            vec![record(&c, 1, "b")],
            Completion::Partial
        ))
        .is_err());
    assert_eq!(r.receipt().encode(), before);
}
#[test]
fn same_record_id_at_a_new_ordinal_is_explicit_reordered_identity_error() {
    let c = declaration();
    let mut r = FeedReplay::new(c.clone(), Limits::default()).unwrap();
    r.apply(&page(
        &c,
        r.cursor(),
        vec![record(&c, 0, "a")],
        Completion::Partial,
    ))
    .unwrap();
    let moved = page(
        &c,
        r.cursor(),
        vec![record(&c, 1, "a")],
        Completion::Partial,
    );
    assert_eq!(
        assert_atomic(&mut r, &moved).field,
        "bgp_replay_reordered_identity"
    );
}
#[test]
fn duplicate_new_record_identity_in_one_page_is_atomic() {
    let c = declaration();
    let mut r = FeedReplay::new(c.clone(), Limits::default()).unwrap();
    let duplicates = page(
        &c,
        r.cursor(),
        vec![record(&c, 0, "a"), record(&c, 1, "a")],
        Completion::Final,
    );
    assert_atomic(&mut r, &duplicates);
    assert!(r.records().is_empty());
}
#[test]
fn generation_boundary_retires_both_directions_and_preserves_old_replay() {
    let c = declaration();
    let mut r = FeedReplay::new(c.clone(), Limits::default()).unwrap();
    let start = r.cursor().clone();
    let reverse = FeedRecord::from_normalized(
        1,
        &normalized(&c, "b", Some(1), 7, RouteAction::Announce, Some(-1), 5),
        Coverage::DeclaredComplete,
        &Limits::default(),
    )
    .unwrap();
    let old = page(
        &c,
        &start,
        vec![record(&c, 0, "a"), reverse],
        Completion::Partial,
    );
    r.apply(&old).unwrap();
    assert_eq!(r.candidate_state().unwrap().routes().len(), 2);
    r.apply(&page(
        &c,
        r.cursor(),
        vec![boundary(&c, 2, "boundary", 7, 8)],
        Completion::Partial,
    ))
    .unwrap();
    assert!(r.candidate_state().unwrap().routes().is_empty());
    let after = r.receipt().encode().to_owned();
    r.apply(&old).unwrap();
    assert_eq!(r.receipt().encode(), after);
    assert!(r.candidate_state().unwrap().routes().is_empty());
    let next = FeedRecord::from_normalized(
        3,
        &normalized(&c, "next", Some(0), 8, RouteAction::Announce, None, 6),
        Coverage::DeclaredComplete,
        &Limits::default(),
    )
    .unwrap();
    r.apply(&page(&c, r.cursor(), vec![next], Completion::Final))
        .unwrap();
    assert_eq!(r.candidate_state().unwrap().routes()[0].generation, 8);
}
#[test]
fn missing_skipped_reversed_and_nonexistent_generation_predecessors_fail_atomically() {
    let c = declaration();
    for (generation, expected) in [(8, "bgp_replay_generation"), (6, "bgp_replay_generation")] {
        let mut r = FeedReplay::new(c.clone(), Limits::default()).unwrap();
        r.apply(&page(
            &c,
            r.cursor(),
            vec![record(&c, 0, "a")],
            Completion::Partial,
        ))
        .unwrap();
        let wrong = FeedRecord::from_normalized(
            1,
            &normalized(
                &c,
                "wrong",
                Some(0),
                generation,
                RouteAction::Withdraw,
                None,
                0,
            ),
            Coverage::Unknown,
            &Limits::default(),
        )
        .unwrap();
        let p = page(&c, r.cursor(), vec![wrong], Completion::Partial);
        assert_eq!(assert_atomic(&mut r, &p).field, expected);
    }
    let mut r = FeedReplay::new(c.clone(), Limits::default()).unwrap();
    let missing = page(
        &c,
        r.cursor(),
        vec![boundary(&c, 0, "reset", 7, 8)],
        Completion::Partial,
    );
    assert_atomic(&mut r, &missing);
    r.apply(&page(
        &c,
        r.cursor(),
        vec![record(&c, 0, "a")],
        Completion::Partial,
    ))
    .unwrap();
    let skipped = page(
        &c,
        r.cursor(),
        vec![boundary(&c, 1, "reset", 8, 9)],
        Completion::Partial,
    );
    assert_eq!(
        assert_atomic(&mut r, &skipped).field,
        "bgp_replay_generation"
    );
}
#[test]
fn malformed_boundary_and_generation_overflow_are_rejected_before_feed_creation() {
    for (previous, next) in [(7, 9), (7, 7), (7, 6), (u64::MAX, 0)] {
        let mut c = declaration();
        c.generation = next;
        assert!(bgp_import::normalize_boundary(
            c,
            GenerationBoundary {
                previous_generation: previous,
                reason: "boundary".into()
            },
            "boundary".into(),
            None,
            &Limits::default()
        )
        .is_err());
    }
}
#[test]
fn a_late_validation_error_rolls_back_every_earlier_record_in_the_page() {
    let c = declaration();
    let mut r = FeedReplay::new(c.clone(), Limits::default()).unwrap();
    let missing = FeedRecord::from_normalized(
        1,
        &normalized(&c, "b", Some(0), 8, RouteAction::Announce, None, 0),
        Coverage::DeclaredComplete,
        &Limits::default(),
    )
    .unwrap();
    let p = page(
        &c,
        r.cursor(),
        vec![record(&c, 0, "a"), missing],
        Completion::Final,
    );
    assert_atomic(&mut r, &p);
    assert!(r.records().is_empty());
}
#[test]
fn checkpoint_and_source_batch_changes_are_distinct_instances_not_continuations() {
    let c = declaration();
    let mut first = FeedReplay::new(c.clone(), Limits::default()).unwrap();
    first
        .apply(&page(
            &c,
            first.cursor(),
            vec![record(&c, 0, "a")],
            Completion::Partial,
        ))
        .unwrap();
    for change in 0..4 {
        let mut other = c.clone();
        match change {
            0 => other.checkpoint_id = "checkpoint-b".into(),
            1 => other.batch.sha256 = Some(digest(b"changed batch")),
            2 => other.batch.batch_id = Some("batch-b".into()),
            _ => other.source_version = Some("2".into()),
        }
        let mut second = FeedReplay::new(other.clone(), Limits::default()).unwrap();
        let withdrawal = FeedRecord::from_normalized(
            0,
            &normalized(&other, "w", Some(0), 7, RouteAction::Withdraw, None, 0),
            Coverage::DeclaredComplete,
            &Limits::default(),
        )
        .unwrap();
        let p = page(&other, second.cursor(), vec![withdrawal], Completion::Final);
        assert_atomic(&mut first, &p);
        second.apply(&p).unwrap();
        assert!(second.candidate_state().unwrap().routes().is_empty());
        assert_eq!(first.candidate_state().unwrap().routes().len(), 1);
    }
}
#[test]
fn cross_partition_record_and_boundary_cannot_be_smuggled_under_a_feed_declaration() {
    let c = declaration();
    let mut other = c.clone();
    other.checkpoint_id = "other".into();
    let r = FeedReplay::new(c.clone(), Limits::default()).unwrap();
    for item in [
        record(&other, 0, "a"),
        boundary(&other, 0, "boundary", 7, 8),
    ] {
        assert!(FeedEnvelope::new(
            c.clone(),
            r.cursor().clone(),
            vec![item],
            Completion::Partial,
            &Limits::default()
        )
        .is_err());
    }
}
#[test]
fn missing_skipped_or_changed_cursor_never_authorizes_a_partial_start() {
    let c = declaration();
    let mut r = FeedReplay::new(c.clone(), Limits::default()).unwrap();
    let mut later = r.cursor().clone();
    later.next_ordinal = 10;
    assert_atomic(&mut r, &page(&c, &later, Vec::new(), Completion::Partial));
    let mut wrong = r.cursor().clone();
    wrong.prefix_sha256 = digest(b"different prefix");
    assert_atomic(
        &mut r,
        &page(&c, &wrong, vec![record(&c, 0, "a")], Completion::Partial),
    );
    let mut wrong = r.cursor().clone();
    wrong.feed_sha256 = digest(b"different feed");
    assert_atomic(&mut r, &page(&c, &wrong, Vec::new(), Completion::Partial));
}
#[test]
fn reversed_or_skipped_ordinals_are_rejected_not_timestamp_sorted() {
    let c = declaration();
    let r = FeedReplay::new(c.clone(), Limits::default()).unwrap();
    for records in [
        vec![record(&c, 1, "b"), record(&c, 0, "a")],
        vec![record(&c, 0, "a"), record(&c, 2, "c")],
    ] {
        assert!(FeedEnvelope::new(
            c.clone(),
            r.cursor().clone(),
            records,
            Completion::Partial,
            &Limits::default()
        )
        .is_err());
    }
}
#[test]
fn final_marker_cannot_hide_a_tail_or_allow_later_extension() {
    let c = declaration();
    let mut r = FeedReplay::new(c.clone(), Limits::default()).unwrap();
    let start = r.cursor().clone();
    r.apply(&page(
        &c,
        &start,
        vec![record(&c, 0, "a"), record(&c, 1, "b")],
        Completion::Partial,
    ))
    .unwrap();
    assert_atomic(
        &mut r,
        &page(&c, &start, vec![record(&c, 0, "a")], Completion::Final),
    );
    let final_page = page(&c, r.cursor(), Vec::new(), Completion::Final);
    r.apply(&final_page).unwrap();
    let extended = page(&c, r.cursor(), vec![record(&c, 2, "c")], Completion::Final);
    assert_atomic(&mut r, &extended);
    let before = r.receipt().encode().to_owned();
    r.apply(&page(
        &c,
        &start,
        vec![record(&c, 0, "a")],
        Completion::Partial,
    ))
    .unwrap();
    assert_eq!(r.receipt().encode(), before);
    assert_eq!(r.completion(), Completion::Final);
}
#[test]
fn signed_time_unknown_time_and_uncertainty_are_preserved_in_input_order() {
    let c = declaration();
    let mut r = FeedReplay::new(c.clone(), Limits::default()).unwrap();
    let times = [Some(i64::MAX), Some(i64::MIN), None];
    let records = times
        .iter()
        .enumerate()
        .map(|(i, t)| {
            FeedRecord::from_normalized(
                i as u64,
                &normalized(
                    &c,
                    &format!("r{i}"),
                    Some(0),
                    7,
                    RouteAction::Announce,
                    *t,
                    5,
                ),
                Coverage::DeclaredComplete,
                &Limits::default(),
            )
            .unwrap()
        })
        .collect();
    r.apply(&page(&c, r.cursor(), records, Completion::Final))
        .unwrap();
    for (w, t) in r.records().iter().zip(times) {
        assert_eq!(w.original().observation().source().observed_at_ns, t);
        assert_eq!(
            w.original()
                .observation()
                .import_context()
                .unwrap()
                .clock
                .reported_uncertainty_ns,
            None
        );
    }
    assert!(r.receipt().encode().contains("-9223372036854775808"));
    assert!(r
        .receipt()
        .encode()
        .contains("\"reported_uncertainty_ns\":null"));
}
#[test]
fn explicit_zero_uncertainty_and_unknown_clock_are_not_interchanged() {
    for clock in [
        ObservationClock::default(),
        ObservationClock {
            policy: ClockPolicy::SourceLabel,
            clock_id: Some("clock-a".into()),
            reported_uncertainty_ns: Some(0),
        },
    ] {
        let mut c = declaration();
        c.clock = clock.clone();
        let mut r = FeedReplay::new(c.clone(), Limits::default()).unwrap();
        r.apply(&page(
            &c,
            r.cursor(),
            vec![record(&c, 0, "a")],
            Completion::Final,
        ))
        .unwrap();
        assert_eq!(
            r.records()[0]
                .original()
                .observation()
                .import_context()
                .unwrap()
                .clock,
            clock
        );
    }
}
#[test]
fn feed_clock_context_cannot_override_a_record_clock() {
    let c = declaration();
    let mut other = c.clone();
    other.clock.reported_uncertainty_ns = Some(0);
    let r = FeedReplay::new(c.clone(), Limits::default()).unwrap();
    assert!(FeedEnvelope::new(
        c,
        r.cursor().clone(),
        vec![record(&other, 0, "a")],
        Completion::Partial,
        &Limits::default()
    )
    .is_err());
}
#[test]
fn malformed_identity_hash_ranges_and_duplicate_keys_are_typed_errors() {
    for change in 0..7 {
        let mut c = declaration();
        match change {
            0 => c.source_id.clear(),
            1 => c.checkpoint_id = " \t ".into(),
            2 => c.source_schema.clear(),
            3 => c.batch.sha256 = Some("ab".into()),
            4 => c.batch.sha256 = Some("A".repeat(64)),
            5 => c.provenance[0].end = 513,
            _ => c.provenance[0].start = 512,
        }
        assert!(FeedReplay::new(c, Limits::default()).is_err());
    }
    let c = declaration();
    let mut value = normalized(&c, "a", Some(0), 7, RouteAction::Announce, None, 5);
    let Json::Object(items) = &mut value else {
        panic!()
    };
    items.push(("source_id", "duplicate".into()));
    assert!(FeedRecord::from_normalized(0, &value, Coverage::Unknown, &Limits::default()).is_err());
    let mut value = normalized(&c, "a", Some(0), 7, RouteAction::Announce, None, 5);
    set(&mut value, "record_id", "   ".into());
    assert!(FeedRecord::from_normalized(0, &value, Coverage::Unknown, &Limits::default()).is_err());
}
#[test]
fn malformed_cursor_hash_ordinal_overflow_and_overlong_metadata_fail() {
    let c = declaration();
    let r = FeedReplay::new(c.clone(), Limits::default()).unwrap();
    let mut cursor = r.cursor().clone();
    cursor.feed_sha256 = "bad".into();
    assert!(FeedEnvelope::new(
        c.clone(),
        cursor,
        Vec::new(),
        Completion::Partial,
        &Limits::default()
    )
    .is_err());
    let mut cursor = r.cursor().clone();
    cursor.next_ordinal = u64::MAX;
    assert!(FeedEnvelope::new(
        c.clone(),
        cursor,
        vec![record(&c, u64::MAX, "last")],
        Completion::Partial,
        &Limits::default()
    )
    .is_err());
    let mut c = c;
    c.source_version = Some("x".repeat(1025));
    assert!(FeedReplay::new(c, Limits::default()).is_err());
}
#[test]
fn unsupported_fields_and_incomplete_coverage_survive_canonical_replay() {
    let c = declaration();
    let mut value = normalized(&c, "a", Some(0), 7, RouteAction::Announce, None, 5);
    set(
        &mut value,
        "uninterpreted_extension",
        Json::object([("numbers", Json::array([3u8.into(), 1u8.into(), 3u8.into()]))]),
    );
    let mut r = FeedReplay::new(c.clone(), Limits::default()).unwrap();
    let item =
        FeedRecord::from_normalized(0, &value, Coverage::Unknown, &Limits::default()).unwrap();
    r.apply(&page(&c, r.cursor(), vec![item], Completion::Final))
        .unwrap();
    assert_eq!(r.effective_coverage(), Coverage::Unknown);
    assert_eq!(
        get(
            r.records()[0].original().observation().normalized(),
            "uninterpreted_extension"
        ),
        get(&value, "uninterpreted_extension")
    );
}
#[test]
fn authority_claims_are_false_and_positive_nested_claims_are_rejected() {
    let c = declaration();
    let r = FeedReplay::new(c.clone(), Limits::default()).unwrap();
    for key in [
        "endpoint_state_established",
        "rib_established",
        "best_path_selected",
        "reachability_established",
        "attack_established",
        "causality_established",
        "source_authority_established",
        "source_verified",
        "normative_conformance_certified",
    ] {
        assert_eq!(get(r.receipt().json(), key), &Json::Bool(false));
        let mut value = normalized(&c, "a", Some(0), 7, RouteAction::Announce, None, 5);
        set(
            &mut value,
            "opaque_extension",
            Json::object([(key, true.into())]),
        );
        assert!(FeedRecord::from_normalized(
            0,
            &value,
            Coverage::DeclaredComplete,
            &Limits::default()
        )
        .is_err());
    }
    assert!(r.receipt().encode().contains(RECEIPT_SCHEMA));
}
#[test]
fn source_kind_parity_does_not_turn_captured_or_legacy_records_into_imported_feeds() {
    let c = declaration();
    let imported = normalized(&c, "a", Some(0), 7, RouteAction::Announce, Some(100), 5);
    let hex = include_str!("fixtures/bgp_state.hex")
        .lines()
        .find(|s| s.starts_with("announce "))
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap();
    let raw: Vec<_> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect();
    let evidence = EvidenceBytes::from_packet(
        &raw,
        PacketId {
            capture: sha256::digest(b"synthetic captured source"),
            frame: 1,
            record_offset: 24,
        },
        54,
    );
    let captured = bgp::decode_pcap(
        &evidence,
        PcapMetadata {
            source_id: "capture".into(),
            record_id: "packet-1".into(),
            observed_at_ns: Some(100),
            session: Some(7),
            direction: Some(0),
            peer: None,
            local: None,
        },
        &mut bgp::SessionState::default(),
        &Limits::default(),
    )
    .unwrap();
    assert_eq!(get(&captured, "schema"), get(&imported, "schema"));
    assert_ne!(get(&captured, "source_kind"), get(&imported, "source_kind"));
    assert_ne!(get(&captured, "evidence"), &Json::Null);
    assert_eq!(get(&imported, "evidence"), &Json::Null);
    assert!(FeedRecord::from_normalized(
        0,
        &captured,
        Coverage::DeclaredComplete,
        &Limits::default()
    )
    .is_err());
    let mut legacy = imported.clone();
    set(&mut legacy, "import_context", Json::Null);
    set(&mut legacy, "generation", Json::Null);
    set(&mut legacy, "direction", Json::Null);
    assert!(Observation::from_normalized(&legacy, None, &Limits::default()).is_ok());
    assert!(
        FeedRecord::from_normalized(0, &legacy, Coverage::Unknown, &Limits::default()).is_err()
    );
}

fn route_context() -> RouteContext {
    RouteContext {
        namespace: Some("explicit-comparison".into()),
        flow_id: None,
        captured_or_legacy_clock: None,
        coverage: Coverage::DeclaredComplete,
    }
}
fn internal() -> association::InternalEvidence {
    association::InternalEvidence::new(
        association::InternalInput {
            kind: association::InternalKind::Flow,
            source: association::SourceIdentity {
                source_id: "independent-source".into(),
                record_id: "flow-1".into(),
                schema: "flow-summary.v1".into(),
                version: None,
                batch: None,
                checkpoint_id: None,
            },
            dimensions: association::Dimensions {
                scope: association::Scope {
                    namespace: Some("explicit-comparison".into()),
                    session: Some("session-a".into()),
                    generation: Some(7),
                    flow_id: None,
                    direction: Some(0),
                },
                prefix: None,
                endpoint: Some(association::EndpointIdentity {
                    afi: 1,
                    address: "203.0.113.9".into(),
                }),
                unsupported: Vec::new(),
            },
            time: association::TimeLabel {
                observed_at_ns: None,
                clock: ObservationClock::default(),
            },
            coverage: Coverage::DeclaredComplete,
            provenance: association::Provenance {
                record_sha256: Some(digest(b"independent summary")),
                ranges: Vec::new(),
                details: Json::Null,
            },
        },
        &Limits::default(),
    )
    .unwrap()
}
fn policy() -> association::Policy {
    association::Policy {
        policy_id: "explicit-spatial-only".into(),
        session: association::DimensionRule::RequireEqual,
        generation: association::DimensionRule::RequireEqual,
        flow: association::DimensionRule::Ignore,
        direction: association::DirectionRule::Equal,
        spatial: association::SpatialRule::RoutePrefixContainsEndpoint,
        time: association::TimePolicy::Ignore {
            reason: "no comparable time assertions".into(),
        },
    }
}
#[test]
fn association_receipt_preserves_partition_clocks_and_partial_coverage_without_mutation() {
    let c = declaration();
    let mut r = FeedReplay::new(c.clone(), Limits::default()).unwrap();
    r.apply(&page(
        &c,
        r.cursor(),
        vec![record(&c, 0, "a")],
        Completion::Partial,
    ))
    .unwrap();
    let before = r.receipt().encode().to_owned();
    let state = r.candidate_state().unwrap().encode().to_owned();
    let receipt = r
        .association_receipt(&route_context(), &Limits::default())
        .unwrap();
    assert_eq!(receipt.coverage(), Coverage::Incomplete);
    let result = association::associate(
        receipt.routes(),
        &[internal()],
        &policy(),
        &Limits::default(),
    )
    .unwrap();
    assert!(result.associations()[0]
        .reasons
        .contains(&Reason::InsufficientCoverage));
    assert_eq!(
        result.associations()[0].status,
        AssociationStatus::Unresolved
    );
    for text in [
        "checkpoint-a",
        "batch-a",
        "clock-a",
        "reported_uncertainty_ns",
        "\"ordinal\":\"0\"",
    ] {
        assert!(receipt.encode().contains(text));
    }
    assert_eq!(r.receipt().encode(), before);
    assert_eq!(r.candidate_state().unwrap().encode(), state);
}
#[test]
fn a_final_feed_can_supply_generic_association_but_not_a_causal_claim() {
    let c = declaration();
    let mut r = FeedReplay::new(c.clone(), Limits::default()).unwrap();
    r.apply(&page(
        &c,
        r.cursor(),
        vec![record(&c, 0, "a")],
        Completion::Final,
    ))
    .unwrap();
    let receipt = r
        .association_receipt(&route_context(), &Limits::default())
        .unwrap();
    assert_eq!(receipt.coverage(), Coverage::DeclaredComplete);
    let result = association::associate(
        receipt.routes(),
        &[internal()],
        &policy(),
        &Limits::default(),
    )
    .unwrap();
    assert_eq!(
        result.associations()[0].status,
        AssociationStatus::CompatibleCandidate
    );
    assert!(result.encode().contains("\"causality_established\":false"));
    assert_eq!(
        receipt.encode(),
        r.association_receipt(&route_context(), &Limits::default())
            .unwrap()
            .encode()
    );
}
#[test]
fn final_does_not_upgrade_unknown_record_coverage_and_quarantine_blocks_association() {
    let c = declaration();
    let mut r = FeedReplay::new(c.clone(), Limits::default()).unwrap();
    let start = r.cursor().clone();
    let original = FeedRecord::from_normalized(
        0,
        record(&c, 0, "a").observation().normalized(),
        Coverage::Unknown,
        &Limits::default(),
    )
    .unwrap();
    r.apply(&page(&c, &start, vec![original], Completion::Final))
        .unwrap();
    assert_eq!(
        r.association_receipt(&route_context(), &Limits::default())
            .unwrap()
            .coverage(),
        Coverage::Unknown
    );
    r.apply(&page(
        &c,
        &start,
        vec![changed_record(&c, 0, "a", 9)],
        Completion::Final,
    ))
    .unwrap();
    assert!(r
        .association_receipt(&route_context(), &Limits::default())
        .is_err());
    assert!(r.receipt().encode().contains("\"quarantined\":true"));
}
#[test]
fn association_does_not_infer_namespace_or_allow_clock_override() {
    let c = declaration();
    let mut r = FeedReplay::new(c.clone(), Limits::default()).unwrap();
    r.apply(&page(
        &c,
        r.cursor(),
        vec![record(&c, 0, "a")],
        Completion::Final,
    ))
    .unwrap();
    let mut context = route_context();
    context.namespace = None;
    let receipt = r.association_receipt(&context, &Limits::default()).unwrap();
    let result = association::associate(
        receipt.routes(),
        &[internal()],
        &policy(),
        &Limits::default(),
    )
    .unwrap();
    assert!(result.associations()[0]
        .reasons
        .contains(&Reason::MissingNamespace));
    context.captured_or_legacy_clock = Some(c.clock);
    assert!(r.association_receipt(&context, &Limits::default()).is_err());
}
#[test]
fn replay_rechecks_record_and_output_limits_and_failure_is_atomic() {
    let c = declaration();
    let initial = FeedReplay::new(c.clone(), Limits::default()).unwrap();
    let p = page(
        &c,
        initial.cursor(),
        vec![record(&c, 0, "a"), record(&c, 1, "b")],
        Completion::Final,
    );
    let mut limited = FeedReplay::new(
        c.clone(),
        Limits {
            elements: 1,
            ..Limits::default()
        },
    )
    .unwrap();
    assert_eq!(
        assert_atomic(&mut limited, &p).code,
        ErrorCode::LimitExceeded
    );
    let initial_size = initial.receipt().encode().len();
    let cap = initial_size.max(p.encode().len()) + 64;
    let mut limited = FeedReplay::new(
        c.clone(),
        Limits {
            output_bytes: cap,
            ..Limits::default()
        },
    )
    .unwrap();
    assert_eq!(
        assert_atomic(&mut limited, &p).code,
        ErrorCode::LimitExceeded
    );
    let mut limited = FeedReplay::new(
        c,
        Limits {
            work: 20_000,
            ..Limits::default()
        },
    )
    .unwrap();
    assert_eq!(
        assert_atomic(&mut limited, &p).code,
        ErrorCode::LimitExceeded
    );
}
#[test]
fn context_record_node_span_string_and_association_limits_are_enforced() {
    let c = declaration();
    for l in [
        Limits {
            spans: 1,
            ..Limits::default()
        },
        Limits {
            fields: 1,
            ..Limits::default()
        },
        Limits {
            depth: 1,
            ..Limits::default()
        },
        Limits {
            input_bytes: 32,
            ..Limits::default()
        },
        Limits {
            retained_bytes: 32,
            ..Limits::default()
        },
    ] {
        let fresh = FeedReplay::new(c.clone(), l.clone());
        match fresh {
            Ok(mut replay) => {
                let p = page(
                    &c,
                    replay.cursor(),
                    vec![record(&c, 0, "a")],
                    Completion::Partial,
                );
                assert_eq!(
                    assert_atomic(&mut replay, &p).code,
                    ErrorCode::LimitExceeded
                );
            }
            Err(error) => assert_eq!(error.code, ErrorCode::LimitExceeded),
        }
    }
    let mut replay = FeedReplay::new(c.clone(), Limits::default()).unwrap();
    replay
        .apply(&page(
            &c,
            replay.cursor(),
            vec![record(&c, 0, "a")],
            Completion::Final,
        ))
        .unwrap();
    let before = replay.receipt().encode().to_owned();
    assert!(replay
        .association_receipt(
            &route_context(),
            &Limits {
                input_bytes: 32,
                ..Limits::default()
            }
        )
        .is_err());
    assert_eq!(replay.receipt().encode(), before);
}
#[test]
fn object_key_order_is_canonical_but_record_array_order_is_evidence() {
    fn reverse(v: &mut Json) {
        match v {
            Json::Object(items) => {
                for (_, v) in items.iter_mut() {
                    reverse(v);
                }
                items.reverse();
            }
            Json::Array(items) => {
                for v in items {
                    reverse(v);
                }
            }
            _ => {}
        }
    }
    let c = declaration();
    let v = normalized(&c, "a", Some(0), 7, RouteAction::Announce, None, 5);
    let mut other = v.clone();
    reverse(&mut other);
    let a =
        FeedRecord::from_normalized(0, &v, Coverage::DeclaredComplete, &Limits::default()).unwrap();
    let b = FeedRecord::from_normalized(0, &other, Coverage::DeclaredComplete, &Limits::default())
        .unwrap();
    assert_eq!(a.encode(), b.encode());
    let mut r = FeedReplay::new(c.clone(), Limits::default()).unwrap();
    let start = r.cursor().clone();
    r.apply(&page(&c, &start, vec![a], Completion::Final))
        .unwrap();
    let before = r.receipt().encode().to_owned();
    r.apply(&page(&c, &start, vec![b], Completion::Final))
        .unwrap();
    assert_eq!(r.receipt().encode(), before);
    assert!(r.receipt().encode().contains(FEED_SCHEMA));
}
#[test]
fn replaying_the_same_declared_sequence_in_a_fresh_instance_is_reproducible() {
    let c = declaration();
    let mut a = FeedReplay::new(c.clone(), Limits::default()).unwrap();
    let pages = [page(
        &c,
        a.cursor(),
        vec![record(&c, 0, "a")],
        Completion::Partial,
    )];
    a.apply(&pages[0]).unwrap();
    let last = page(
        &c,
        a.cursor(),
        vec![boundary(&c, 1, "b", 7, 8)],
        Completion::Final,
    );
    a.apply(&last).unwrap();
    let mut b = FeedReplay::new(c, Limits::default()).unwrap();
    b.apply(&pages[0]).unwrap();
    b.apply(&last).unwrap();
    assert_eq!(a.receipt().encode(), b.receipt().encode());
    assert_eq!(a.cursor(), b.cursor());
    assert_eq!(
        a.candidate_state().unwrap().encode(),
        b.candidate_state().unwrap().encode()
    );
}

#[test]
fn fixed_independent_cursor_vectors_match_the_typed_normalized_feed() {
    fn expected(name: &str) -> &str {
        include_str!("fixtures/bgp_replay_hashes.tsv")
            .lines()
            .find_map(|line| {
                let (key, value) = line.split_once('\t')?;
                (key == name).then_some(value)
            })
            .unwrap()
    }
    let c = declaration();
    let mut r = FeedReplay::new(c.clone(), Limits::default()).unwrap();
    assert_eq!(r.cursor().feed_sha256, expected("feed"));
    assert_eq!(r.cursor().prefix_sha256, expected("prefix0"));
    r.apply(&page(
        &c,
        r.cursor(),
        vec![record(&c, 0, "a")],
        Completion::Partial,
    ))
    .unwrap();
    assert_eq!(r.cursor().prefix_sha256, expected("prefix1"));
    r.apply(&page(
        &c,
        r.cursor(),
        vec![record(&c, 1, "b")],
        Completion::Final,
    ))
    .unwrap();
    assert_eq!(r.cursor().prefix_sha256, expected("prefix2"));
}
#[test]
fn differing_path_records_are_preserved_as_alternatives_not_replay_conflicts() {
    let c = declaration();
    let mut r = FeedReplay::new(c.clone(), Limits::default()).unwrap();
    r.apply(&page(
        &c,
        r.cursor(),
        vec![record(&c, 0, "a"), changed_record(&c, 1, "b", 9)],
        Completion::Final,
    ))
    .unwrap();
    assert!(!r.is_quarantined());
    let routes = r.candidate_state().unwrap().routes();
    assert_eq!(routes.len(), 1);
    assert!(routes[0].conflicting());
    assert_eq!(routes[0].alternatives.len(), 2);
    let receipt = r
        .association_receipt(&route_context(), &Limits::default())
        .unwrap();
    let result = association::associate(
        receipt.routes(),
        &[internal()],
        &policy(),
        &Limits::default(),
    )
    .unwrap();
    assert!(result
        .associations()
        .iter()
        .all(|a| a.reasons.contains(&Reason::ConflictingAttributes)));
}
#[test]
fn unsupported_prefix_semantics_are_retained_not_promoted_into_active_routes() {
    let c = declaration();
    let mut value = normalized(&c, "a", Some(0), 7, RouteAction::Announce, None, 5);
    let Json::Array(mut routes) = get(&value, "routes").clone() else {
        panic!()
    };
    set(
        &mut routes[0],
        "prefix",
        Json::object([
            ("afi", 65000u16.into()),
            ("safi", 1u8.into()),
            ("length", 4u8.into()),
            ("address", "opaque-address".into()),
        ]),
    );
    set(&mut value, "routes", Json::Array(routes));
    let item =
        FeedRecord::from_normalized(0, &value, Coverage::Unknown, &Limits::default()).unwrap();
    let mut r = FeedReplay::new(c.clone(), Limits::default()).unwrap();
    r.apply(&page(&c, r.cursor(), vec![item], Completion::Final))
        .unwrap();
    assert!(r.candidate_state().unwrap().routes().is_empty());
    assert_eq!(
        r.candidate_state().unwrap().outcomes()[0].effects[0].kind,
        pcap_evidence_product::deep::bgp_state::EffectKind::UnsupportedPrefix
    );
    assert!(r.receipt().encode().contains("opaque-address"));
}
#[test]
fn missing_direction_is_retained_without_inventing_a_session_boundary() {
    let c = declaration();
    let mut r = FeedReplay::new(c.clone(), Limits::default()).unwrap();
    let unknown = FeedRecord::from_normalized(
        0,
        &normalized(&c, "a", None, 7, RouteAction::Announce, None, 5),
        Coverage::Unknown,
        &Limits::default(),
    )
    .unwrap();
    r.apply(&page(&c, r.cursor(), vec![unknown], Completion::Partial))
        .unwrap();
    assert_eq!(
        r.candidate_state().unwrap().outcomes()[0].status,
        pcap_evidence_product::deep::bgp_state::ApplyStatus::MissingScope
    );
    assert!(r.candidate_state().unwrap().routes().is_empty());
    let b = page(
        &c,
        r.cursor(),
        vec![boundary(&c, 1, "b", 7, 8)],
        Completion::Final,
    );
    assert_atomic(&mut r, &b);
}

#[test]
fn changed_historical_record_after_reset_cannot_revive_retired_state() {
    let c = declaration();
    let mut r = FeedReplay::new(c.clone(), Limits::default()).unwrap();
    let start = r.cursor().clone();
    r.apply(&page(
        &c,
        &start,
        vec![record(&c, 0, "a"), boundary(&c, 1, "boundary", 7, 8)],
        Completion::Final,
    ))
    .unwrap();
    assert!(r.candidate_state().unwrap().routes().is_empty());
    let changed = page(
        &c,
        &start,
        vec![changed_record(&c, 0, "a", 42)],
        Completion::Partial,
    );
    assert_eq!(r.apply(&changed).unwrap().status, ReplayStatus::Quarantined);
    assert_eq!(r.records().len(), 2);
    assert_eq!(r.records()[0].alternatives().len(), 1);
    assert!(r.candidate_state().is_err());
    assert_eq!(get(r.receipt().json(), "current_generation"), &Json::Null);
    assert_eq!(
        get(r.receipt().json(), "candidate_state_sha256"),
        &Json::Null
    );
}
#[test]
fn boundary_metadata_and_retired_route_witnesses_survive_association_receipt() {
    let c = declaration();
    let mut r = FeedReplay::new(c.clone(), Limits::default()).unwrap();
    r.apply(&page(
        &c,
        r.cursor(),
        vec![record(&c, 0, "a"), boundary(&c, 1, "boundary", 7, 8)],
        Completion::Final,
    ))
    .unwrap();
    let receipt = r
        .association_receipt(&route_context(), &Limits::default())
        .unwrap();
    assert_eq!(receipt.routes().notes().len(), 1);
    assert_eq!(receipt.routes().routes().len(), 1);
    assert!(receipt.encode().contains("previous_generation"));
    let associated = association::associate(
        receipt.routes(),
        &[internal()],
        &policy(),
        &Limits::default(),
    )
    .unwrap();
    assert!(associated.associations()[0]
        .reasons
        .contains(&Reason::NotCurrentCandidate));
    assert_eq!(
        associated.associations()[0].status,
        AssociationStatus::Unresolved
    );
}
#[test]
fn immutable_hash_only_or_batch_only_context_is_retained_without_fabrication() {
    for hash_only in [false, true] {
        let mut c = declaration();
        if hash_only {
            c.batch.batch_id = None;
        } else {
            c.batch.sha256 = None;
        }
        let mut r = FeedReplay::new(c.clone(), Limits::default()).unwrap();
        r.apply(&page(
            &c,
            r.cursor(),
            vec![record(&c, 0, "a")],
            Completion::Final,
        ))
        .unwrap();
        assert_eq!(
            r.records()[0]
                .original()
                .observation()
                .import_context()
                .unwrap()
                .batch,
            c.batch
        );
    }
    let mut missing = declaration();
    missing.batch.sha256 = None;
    missing.batch.batch_id = None;
    assert!(FeedReplay::new(missing, Limits::default()).is_err());
}
#[test]
fn conflict_alternative_retention_exhaustion_is_atomic() {
    let c = declaration();
    let mut r = FeedReplay::new(
        c.clone(),
        Limits {
            elements: 1,
            ..Limits::default()
        },
    )
    .unwrap();
    let start = r.cursor().clone();
    r.apply(&page(
        &c,
        &start,
        vec![record(&c, 0, "a")],
        Completion::Final,
    ))
    .unwrap();
    let conflict = page(
        &c,
        &start,
        vec![changed_record(&c, 0, "a", 9)],
        Completion::Partial,
    );
    assert_eq!(
        assert_atomic(&mut r, &conflict).code,
        ErrorCode::LimitExceeded
    );
    assert!(!r.is_quarantined());
}
