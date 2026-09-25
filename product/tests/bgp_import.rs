//! Fixed expected boundaries for caller-asserted imports, not a reference RIB.
use pcap_evidence::{
    json::Json,
    provenance::{EvidenceBytes, PacketId},
    sha256, ErrorCode,
};
use pcap_evidence_product::deep::{
    bgp::{
        self, ImportedRouteObservation, PathAttributes, PcapMetadata, Prefix, RouteAction,
        SessionState,
    },
    bgp_import::{
        self, ClockPolicy, GenerationBoundary, ImportContext, ObservationClock, SourceBatch,
        SourceRange,
    },
    bgp_state::{ApplyStatus, CandidateState, EffectKind, ImportScope, Observation},
    Limits,
};

const HASH_A: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
const HASH_B: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
fn get<'a>(j: &'a Json, key: &str) -> &'a Json {
    let Json::Object(v) = j else {
        panic!("object required")
    };
    &v.iter().find(|(k, _)| *k == key).unwrap().1
}
fn set(j: &mut Json, key: &'static str, value: Json) {
    let Json::Object(v) = j else {
        panic!("object required")
    };
    if let Some((_, old)) = v.iter_mut().find(|(k, _)| *k == key) {
        *old = value;
    } else {
        v.push((key, value));
    }
}
fn context() -> ImportContext {
    ImportContext {
        source_id: "synthetic-source".into(),
        source_schema: "route-record".into(),
        source_version: Some("1".into()),
        clock: ObservationClock::default(),
        batch: SourceBatch {
            batch_id: Some("batch-a".into()),
            sha256: Some(HASH_A.into()),
            byte_length: Some(3),
        },
        checkpoint_id: "checkpoint-a".into(),
        session: "session-a".into(),
        generation: 7,
        direction: Some(0),
        peer: Some("peer-label".into()),
        local: None,
        provenance: vec![SourceRange {
            start: 0,
            end: 3,
            sha256: Some(HASH_A.into()),
        }],
    }
}
fn input(c: &ImportContext, id: &str, action: RouteAction) -> ImportedRouteObservation {
    ImportedRouteObservation {
        source_id: c.source_id.clone(),
        record_id: id.into(),
        observed_at_ns: Some(-17),
        session: Some(c.session.clone()),
        peer: c.peer.clone(),
        local: c.local.clone(),
        action,
        prefix: Prefix::ipv4([203, 0, 113, 0], 24).unwrap(),
        attributes: PathAttributes {
            med: Some(5),
            ..PathAttributes::default()
        },
    }
}
fn normalized(c: &ImportContext, id: &str, action: RouteAction) -> Json {
    bgp_import::normalize_with_context(input(c, id, action), c.clone(), &Limits::default()).unwrap()
}
fn observation(c: &ImportContext, id: &str, action: RouteAction) -> Observation {
    Observation::from_normalized(&normalized(c, id, action), None, &Limits::default()).unwrap()
}
fn boundary(c: &ImportContext, id: &str) -> Observation {
    let mut next = c.clone();
    next.generation += 1;
    next.direction = None;
    let v = bgp_import::normalize_boundary(
        next,
        GenerationBoundary {
            previous_generation: c.generation,
            reason: "explicit_reset".into(),
        },
        id.into(),
        None,
        &Limits::default(),
    )
    .unwrap();
    Observation::from_normalized(&v, None, &Limits::default()).unwrap()
}
fn state() -> CandidateState {
    CandidateState::new(Limits::default()).unwrap()
}

#[test]
fn typed_context_round_trip_preserves_exact_metadata_and_ranges() {
    let c = context();
    let json = c.to_json(&Limits::default()).unwrap();
    assert_eq!(
        ImportContext::from_json(&json, &Limits::default()).unwrap(),
        c
    );
    let o = observation(&c, "record-a", RouteAction::Announce);
    assert_eq!(o.import_context(), Some(&c));
    assert_eq!(o.source().generation, Some(7));
    assert_eq!(o.source().observed_at_ns, Some(-17));
    assert_eq!(get(o.normalized(), "evidence"), &Json::Null);
    assert_eq!(o.routes()[0].field_range(), 0..0);
}
#[test]
fn legacy_api_has_explicit_unknowns_and_accepts_old_zero_placeholder() {
    let c = context();
    let mut j = bgp::normalize_imported(
        input(&c, "legacy", RouteAction::Announce),
        &Limits::default(),
    )
    .unwrap();
    for k in [
        "generation",
        "direction",
        "import_context",
        "import_boundary",
        "evidence",
    ] {
        assert_eq!(get(&j, k), &Json::Null);
    }
    let mut s = state();
    assert_eq!(
        s.apply(Observation::from_normalized(&j, None, &Limits::default()).unwrap())
            .unwrap()
            .status,
        ApplyStatus::MissingScope
    );
    assert!(s.routes().is_empty());
    set(&mut j, "generation", 0u8.into());
    let old = Observation::from_normalized(&j, None, &Limits::default()).unwrap();
    assert_eq!(old.source().generation, None);
    assert!(old.import_context().is_none());
    let scoped = Observation::from_normalized(
        &j,
        Some(ImportScope {
            generation: 4,
            direction: 1,
        }),
        &Limits::default(),
    )
    .unwrap();
    assert_eq!(scoped.source().generation, Some(4));
    assert_eq!(scoped.source().direction, Some(1));
}
#[test]
fn new_and_old_legacy_envelopes_can_omit_context_without_guessing_a_batch() {
    let c = context();
    let mut j = bgp::normalize_imported(
        input(&c, "legacy", RouteAction::Announce),
        &Limits::default(),
    )
    .unwrap();
    if let Json::Object(fields) = &mut j {
        fields.retain(|(k, _)| !matches!(*k, "import_context" | "import_boundary"));
    }
    set(&mut j, "generation", 0u8.into());
    assert!(Observation::from_normalized(&j, None, &Limits::default())
        .unwrap()
        .import_context()
        .is_none());
}
#[test]
fn same_immutable_record_is_idempotent_without_journal_or_json_mutation() {
    let c = context();
    let o = observation(&c, "r", RouteAction::Announce);
    let mut s = state();
    s.apply(o.clone()).unwrap();
    let before = s.encode().to_owned();
    let retained = s.retained_bytes();
    assert_eq!(s.apply(o).unwrap().status, ApplyStatus::IdenticalReplay);
    assert_eq!(s.encode(), before);
    assert_eq!(s.retained_bytes(), retained);
    assert_eq!(s.observations().len(), 1);
}
#[test]
fn changed_hash_batch_checkpoint_and_schema_partition_without_preference() {
    for axis in 0..7 {
        let a = context();
        let mut b = a.clone();
        match axis {
            0 => b.batch.sha256 = Some(HASH_B.into()),
            1 => b.batch.batch_id = Some("batch-b".into()),
            2 => b.checkpoint_id = "checkpoint-b".into(),
            3 => b.source_schema = "other-schema".into(),
            4 => b.source_version = Some("2".into()),
            5 => b.peer = Some("other-peer".into()),
            _ => b.local = Some("local-label".into()),
        }
        let mut s = state();
        s.apply(observation(&a, "r", RouteAction::Announce))
            .unwrap();
        s.apply(observation(&b, "r", RouteAction::Announce))
            .unwrap();
        assert_eq!(s.routes().len(), 2, "axis {axis}");
        assert_eq!(s.sessions().len(), 2);
        assert_ne!(
            s.routes()[0].import_partition,
            s.routes()[1].import_partition
        );
        s.apply(observation(&b, "w", RouteAction::Withdraw))
            .unwrap();
        assert_eq!(s.routes().len(), 1);
        assert_eq!(
            s.routes()[0]
                .import_partition
                .as_ref()
                .unwrap()
                .checkpoint_id,
            a.checkpoint_id
        );
    }
}
#[test]
fn new_checkpoint_withdrawal_is_absent_and_cannot_withdraw_old_checkpoint() {
    let a = context();
    let mut b = a.clone();
    b.checkpoint_id = "checkpoint-b".into();
    let mut s = state();
    s.apply(observation(&a, "r", RouteAction::Announce))
        .unwrap();
    let result = s
        .apply(observation(&b, "w", RouteAction::Withdraw))
        .unwrap();
    assert_eq!(result.effects[0].kind, EffectKind::AbsentWithdrawal);
    assert_eq!(s.routes().len(), 1);
}
#[test]
fn explicit_boundary_clears_both_directions_only_in_its_partition() {
    let a = context();
    let mut reverse = a.clone();
    reverse.direction = Some(1);
    let mut other = a.clone();
    other.checkpoint_id = "other".into();
    let mut s = state();
    for (i, c) in [&a, &reverse, &other].into_iter().enumerate() {
        s.apply(observation(c, &format!("r-{i}"), RouteAction::Announce))
            .unwrap();
    }
    assert_eq!(s.routes().len(), 3);
    assert_eq!(
        s.apply(boundary(&a, "reset")).unwrap().status,
        ApplyStatus::Reset
    );
    assert_eq!(s.routes().len(), 1);
    assert_eq!(
        s.routes()[0]
            .import_partition
            .as_ref()
            .unwrap()
            .checkpoint_id,
        "other"
    );
    let mut next = a.clone();
    next.generation = 8;
    s.apply(observation(&next, "next-record", RouteAction::Announce))
        .unwrap();
    assert_eq!(s.routes().len(), 2);
}
#[test]
fn replay_before_a_reset_does_not_resurrect_retired_routes() {
    let c = context();
    let a = observation(&c, "a", RouteAction::Announce);
    let b = boundary(&c, "b");
    let mut s = state();
    s.apply(a.clone()).unwrap();
    s.apply(b.clone()).unwrap();
    let snapshot = s.encode().to_owned();
    assert_eq!(s.apply(a).unwrap().status, ApplyStatus::IdenticalReplay);
    assert_eq!(s.apply(b).unwrap().status, ApplyStatus::IdenticalReplay);
    assert!(s.routes().is_empty());
    assert_eq!(s.encode(), snapshot);
}
#[test]
fn missing_backward_skipped_and_cross_checkpoint_boundaries_fail_atomically() {
    let a = context();
    let mut s = state();
    s.apply(observation(&a, "r", RouteAction::Announce))
        .unwrap();
    let before = s.encode().to_owned();
    for generation in [0, 6, 8, u64::MAX] {
        let mut b = a.clone();
        b.generation = generation;
        assert!(s
            .apply(observation(&b, "bad-transition", RouteAction::Withdraw))
            .is_err());
        assert_eq!(s.encode(), before);
    }
    let mut b = a.clone();
    b.checkpoint_id = "new".into();
    assert!(s.apply(boundary(&b, "reset")).is_err());
    assert_eq!(s.encode(), before);
    let mut empty = state();
    assert!(empty.apply(boundary(&a, "no-predecessor")).is_err());
    assert!(empty.observations().is_empty());
}

#[test]
fn contextual_batch_uses_ordered_boundaries_and_rolls_back_as_a_unit() {
    let c = context();
    let mut invalid_successor = c.clone();
    invalid_successor.generation += 1;
    let first = observation(&c, "first", RouteAction::Announce);
    let invalid = observation(
        &invalid_successor,
        "missing-boundary",
        RouteAction::Withdraw,
    );

    let mut rejected = state();
    let before = rejected.encode().to_owned();
    assert!(rejected.apply_batch(vec![first.clone(), invalid]).is_err());
    assert_eq!(rejected.encode(), before);
    assert!(rejected.observations().is_empty());

    let mut accepted = state();
    let receipts = accepted
        .apply_batch(vec![first, boundary(&c, "reset")])
        .unwrap();
    assert_eq!(receipts.len(), 2);
    assert_eq!(receipts[0].status, ApplyStatus::Applied);
    assert_eq!(receipts[1].status, ApplyStatus::Reset);
    assert!(accepted.routes().is_empty());
    assert_eq!(accepted.observations().len(), 2);

    let conflicting = vec![
        observation(&c, "same-record", RouteAction::Announce),
        observation(&c, "same-record", RouteAction::Withdraw),
        boundary(&c, "cannot-clear-identity-conflict"),
    ];
    let mut quarantined = state();
    let before = quarantined.encode().to_owned();
    assert!(quarantined.apply_batch(conflicting).is_err());
    assert_eq!(quarantined.encode(), before);
    assert!(quarantined.observations().is_empty());
}

#[test]
fn malformed_boundary_successor_direction_reason_and_overflow_are_rejected() {
    for (previous, generation, direction, reason) in [
        (7, 7, None, "reset"),
        (7, 9, None, "reset"),
        (7, 8, Some(0), "reset"),
        (7, 8, None, ""),
        (u64::MAX, 0, None, "reset"),
        (7, 8, None, "\n"),
    ] {
        let mut c = context();
        c.generation = generation;
        c.direction = direction;
        assert!(bgp_import::normalize_boundary(
            c,
            GenerationBoundary {
                previous_generation: previous,
                reason: reason.into()
            },
            "b".into(),
            None,
            &Limits::default()
        )
        .is_err());
    }
}
#[test]
fn changed_record_payload_is_a_conflict_not_a_vote_and_does_not_escape_partition() {
    let c = context();
    let mut other = c.clone();
    other.checkpoint_id = "other".into();
    let mut s = state();
    s.apply(observation(&c, "r", RouteAction::Announce))
        .unwrap();
    s.apply(observation(&other, "r", RouteAction::Announce))
        .unwrap();
    let mut changed = input(&c, "r", RouteAction::Announce);
    changed.attributes.med = Some(6);
    let j = bgp_import::normalize_with_context(changed, c.clone(), &Limits::default()).unwrap();
    let o = Observation::from_normalized(&j, None, &Limits::default()).unwrap();
    assert_eq!(
        s.apply(o.clone()).unwrap().status,
        ApplyStatus::IdentityConflict
    );
    assert_eq!(s.routes().len(), 1);
    assert_eq!(s.apply(o).unwrap().status, ApplyStatus::IdenticalReplay);
    assert!(s.apply(boundary(&c, "cannot-clear-conflict")).is_err());
}
#[test]
fn clock_uncertainty_and_unknown_timestamp_are_not_zero_or_ordering() {
    let mut c = context();
    c.clock = ObservationClock {
        policy: ClockPolicy::SourceLabel,
        clock_id: Some("clock-label".into()),
        reported_uncertainty_ns: None,
    };
    let mut value = input(&c, "r", RouteAction::Announce);
    value.observed_at_ns = None;
    let j = bgp_import::normalize_with_context(value, c, &Limits::default()).unwrap();
    assert_eq!(get(&j, "observed_at_ns"), &Json::Null);
    let clock = get(get(&j, "import_context"), "clock");
    assert_eq!(get(clock, "reported_uncertainty_ns"), &Json::Null);
    assert_eq!(get(clock, "ordering_established"), &Json::Bool(false));
}
#[test]
fn reversed_clock_labels_do_not_reorder_announcements_and_withdrawals() {
    let mut c = context();
    c.clock = ObservationClock {
        policy: ClockPolicy::IngestionLabel,
        clock_id: None,
        reported_uncertainty_ns: Some(u64::MAX),
    };
    let mut a = input(&c, "a", RouteAction::Announce);
    a.observed_at_ns = Some(i64::MAX);
    let mut w = input(&c, "w", RouteAction::Withdraw);
    w.observed_at_ns = Some(i64::MIN);
    let mut s = state();
    for v in [a, w] {
        let j = bgp_import::normalize_with_context(v, c.clone(), &Limits::default()).unwrap();
        s.apply(Observation::from_normalized(&j, None, &Limits::default()).unwrap())
            .unwrap();
    }
    assert!(s.routes().is_empty());
    assert!(s.encode().contains(&u64::MAX.to_string()));
}
#[test]
fn clock_metadata_change_on_one_record_remains_identity_conflict() {
    let a = context();
    let mut b = a.clone();
    b.clock.policy = ClockPolicy::SourceLabel;
    let mut s = state();
    s.apply(observation(&a, "r", RouteAction::Announce))
        .unwrap();
    assert_eq!(
        s.apply(observation(&b, "r", RouteAction::Announce))
            .unwrap()
            .status,
        ApplyStatus::IdentityConflict
    );
    assert!(s.routes().is_empty());
}
#[test]
fn missing_immutable_identities_and_empty_metadata_are_rejected() {
    for axis in 0..9 {
        let mut c = context();
        match axis {
            0 => c.source_id.clear(),
            1 => c.source_schema.clear(),
            2 => c.session.clear(),
            3 => c.checkpoint_id.clear(),
            4 => {
                c.batch.batch_id = None;
                c.batch.sha256 = None;
            }
            5 => c.source_version = Some(String::new()),
            6 => c.batch.batch_id = Some(" ".into()),
            7 => c.peer = Some("\t".into()),
            _ => c.direction = Some(2),
        }
        assert!(c.validate(&Limits::default()).is_err(), "axis {axis}");
    }
}
#[test]
fn malformed_hashes_are_rejected_on_batch_and_provenance() {
    for hash in [
        "",
        "abc",
        &"0".repeat(63),
        &"0".repeat(65),
        &"G".repeat(64),
        &HASH_A.to_uppercase(),
    ] {
        let mut c = context();
        c.batch.sha256 = Some(hash.into());
        assert!(c.validate(&Limits::default()).is_err());
        let mut c = context();
        c.provenance[0].sha256 = Some(hash.into());
        assert!(c.validate(&Limits::default()).is_err());
    }
}
#[test]
fn hash_only_and_batch_only_identities_preserve_unknowns() {
    for hash_only in [true, false] {
        let mut c = context();
        c.source_version = None;
        if hash_only {
            c.batch.batch_id = None;
        } else {
            c.batch.sha256 = None;
        }
        let o = observation(&c, "r", RouteAction::Announce);
        assert_eq!(o.import_context(), Some(&c));
    }
}
#[test]
fn unknown_clock_policy_cannot_claim_accuracy() {
    let mut c = context();
    c.clock.reported_uncertainty_ns = Some(0);
    assert!(c.validate(&Limits::default()).is_err());
    c.clock.reported_uncertainty_ns = None;
    c.clock.clock_id = Some("clock".into());
    assert!(c.validate(&Limits::default()).is_err());
}
#[test]
fn malformed_ranges_are_rejected_but_reordered_duplicate_ranges_are_retained() {
    for (start, end) in [(0, 0), (3, 2), (0, 4), (u64::MAX, u64::MAX)] {
        let mut c = context();
        c.provenance[0].start = start;
        c.provenance[0].end = end;
        assert!(c.validate(&Limits::default()).is_err());
    }
    let mut c = context();
    c.provenance = vec![
        SourceRange {
            start: 2,
            end: 3,
            sha256: None,
        },
        SourceRange {
            start: 0,
            end: 2,
            sha256: None,
        },
        SourceRange {
            start: 0,
            end: 2,
            sha256: None,
        },
    ];
    assert_eq!(
        observation(&c, "r", RouteAction::Announce)
            .import_context()
            .unwrap()
            .provenance,
        c.provenance
    );
}
#[test]
fn mismatched_outer_source_session_peer_generation_and_direction_are_rejected() {
    let c = context();
    for (key, value) in [
        ("source_id", "other".into()),
        ("session", "other".into()),
        ("peer", Json::Null),
        ("local", "other".into()),
        ("generation", 8u8.into()),
        ("direction", 1u8.into()),
    ] {
        let mut j = normalized(&c, "r", RouteAction::Announce);
        set(&mut j, key, value);
        assert!(
            Observation::from_normalized(&j, None, &Limits::default()).is_err(),
            "{key}"
        );
    }
    let mut v = input(&c, "r", RouteAction::Announce);
    v.session = None;
    assert!(bgp_import::normalize_with_context(v, c.clone(), &Limits::default()).is_err());
    assert!(Observation::from_normalized(
        &normalized(&c, "r", RouteAction::Announce),
        Some(ImportScope {
            generation: 7,
            direction: 0
        }),
        &Limits::default()
    )
    .is_err());
}
#[test]
fn invented_packet_evidence_and_boundary_routes_are_rejected() {
    let c = context();
    let mut j = normalized(&c, "r", RouteAction::Announce);
    set(&mut j, "evidence", Json::object([]));
    assert!(Observation::from_normalized(&j, None, &Limits::default()).is_err());
    let mut j = boundary(&c, "b").normalized().clone();
    set(
        &mut j,
        "routes",
        get(&normalized(&c, "r", RouteAction::Announce), "routes").clone(),
    );
    assert!(Observation::from_normalized(&j, None, &Limits::default()).is_err());
}
#[test]
fn duplicate_unknown_missing_and_authoritative_context_fields_are_rejected() {
    for case in 0..5 {
        let mut v = context().to_json(&Limits::default()).unwrap();
        match case {
            0 => {
                let Json::Object(fields) = &mut v else {
                    panic!()
                };
                fields.push(("generation", 7u8.into()));
            }
            1 => set(&mut v, "extra", Json::Null),
            2 => {
                let Json::Object(fields) = &mut v else {
                    panic!()
                };
                fields.retain(|(k, _)| *k != "checkpoint_id");
            }
            3 => set(&mut v, "wire_verified", true.into()),
            _ => set(&mut v, "schema", "future".into()),
        }
        assert!(
            ImportContext::from_json(&v, &Limits::default()).is_err(),
            "case {case}"
        );
    }
}
#[test]
fn metadata_string_node_span_depth_input_and_output_limits_are_typed() {
    let mut c = context();
    c.source_schema = "x".repeat(1025);
    assert_eq!(
        c.validate(&Limits::default()).unwrap_err().code,
        ErrorCode::LimitExceeded
    );
    let c = context();
    for l in [
        Limits {
            fields: 4,
            ..Limits::default()
        },
        Limits {
            depth: 2,
            ..Limits::default()
        },
        Limits {
            input_bytes: 32,
            ..Limits::default()
        },
        Limits {
            output_bytes: 32,
            ..Limits::default()
        },
        Limits {
            work: 8,
            ..Limits::default()
        },
    ] {
        assert_eq!(c.validate(&l).unwrap_err().code, ErrorCode::LimitExceeded);
    }
    let mut c = context();
    c.provenance.push(c.provenance[0].clone());
    assert_eq!(
        c.validate(&Limits {
            spans: 1,
            ..Limits::default()
        })
        .unwrap_err()
        .code,
        ErrorCode::LimitExceeded
    );
}
#[test]
fn legacy_normalizer_enforces_bounds_before_path_allocation() {
    let c = context();
    let mut v = input(&c, "r", RouteAction::Announce);
    v.attributes.communities = vec![1; 1025];
    assert_eq!(
        bgp::normalize_imported(v, &Limits::default())
            .unwrap_err()
            .code,
        ErrorCode::LimitExceeded
    );
    let mut v = input(&c, "r", RouteAction::Announce);
    v.source_id = "x".repeat(1025);
    assert_eq!(
        bgp::normalize_imported(v, &Limits::default())
            .unwrap_err()
            .code,
        ErrorCode::LimitExceeded
    );
    let mut v = input(&c, "r", RouteAction::Announce);
    v.prefix.address[3] = 1;
    assert!(bgp::normalize_imported(v, &Limits::default()).is_err());
}
#[test]
fn aggregate_span_route_and_partition_exhaustion_leave_snapshot_unchanged() {
    let c = context();
    for l in [
        Limits {
            spans: 1,
            ..Limits::default()
        },
        Limits {
            elements: 1,
            ..Limits::default()
        },
        Limits {
            active: 1,
            ..Limits::default()
        },
    ] {
        let mut s = CandidateState::new(l).unwrap();
        s.apply(observation(&c, "a", RouteAction::Announce))
            .unwrap();
        let before = s.encode().to_owned();
        let count = s.observations().len();
        let mut other = c.clone();
        other.checkpoint_id = "other".into();
        assert_eq!(
            s.apply(observation(&other, "b", RouteAction::Announce))
                .unwrap_err()
                .code,
            ErrorCode::LimitExceeded
        );
        assert_eq!(s.encode(), before);
        assert_eq!(s.observations().len(), count);
    }
}
#[test]
fn sampled_subthreshold_apply_work_budgets_fail_atomically() {
    let c = context();
    let o = observation(&c, "r", RouteAction::Announce);
    let mut success = false;
    for work in [
        1, 64, 256, 1024, 4096, 16384, 65536, 262144, 1048576, 8388608,
    ] {
        let mut s = CandidateState::new(Limits {
            work,
            ..Limits::default()
        })
        .unwrap();
        let before = s.encode().to_owned();
        match s.apply(o.clone()) {
            Ok(_) => {
                success = true;
                break;
            }
            Err(e) => {
                assert_eq!(e.code, ErrorCode::LimitExceeded);
                assert_eq!(s.encode(), before);
            }
        }
    }
    assert!(success);
}
#[test]
fn small_output_and_retention_limits_cannot_partially_publish_a_reset() {
    let c = context();
    let a = observation(&c, "a", RouteAction::Announce);
    let b = boundary(&c, "b");
    let mut wide = state();
    wide.apply(a.clone()).unwrap();
    let len = wide.encode().len();
    let mut s = CandidateState::new(Limits {
        output_bytes: len,
        ..Limits::default()
    })
    .unwrap();
    s.apply(a).unwrap();
    let before = s.encode().to_owned();
    assert!(s.apply(b).is_err());
    assert_eq!(s.encode(), before);
    assert_eq!(s.routes().len(), 1);
    let mut small = CandidateState::new(Limits {
        retained_bytes: 1024,
        ..Limits::default()
    })
    .unwrap();
    let before = small.encode().to_owned();
    assert!(small
        .apply(observation(&c, "r", RouteAction::Announce))
        .is_err());
    assert_eq!(small.encode(), before);
}
#[test]
fn deterministic_output_keeps_context_and_all_non_authority_flags() {
    let c = context();
    let mut a = state();
    let mut b = state();
    for s in [&mut a, &mut b] {
        s.apply(observation(&c, "a", RouteAction::Announce))
            .unwrap();
        s.apply(observation(&c, "w", RouteAction::Withdraw))
            .unwrap();
    }
    assert_eq!(a.encode(), b.encode());
    for k in [
        "endpoint_state_established",
        "rib_established",
        "best_path_selected",
        "causality_established",
        "reachability_established",
        "source_authority_established",
    ] {
        assert!(a.encode().contains(&format!("\"{k}\":false")));
    }
    assert!(a.encode().contains("checkpoint-a"));
    assert!(a.encode().contains(HASH_A));
}
#[test]
fn captured_and_imported_envelopes_share_schema_but_not_context_or_candidates() {
    let bytes = std::iter::repeat_n(255, 16)
        .chain([0, 19, 4])
        .collect::<Vec<u8>>();
    let raw = EvidenceBytes::from_packet(
        &bytes,
        PacketId {
            capture: sha256::digest(b"source"),
            frame: 1,
            record_offset: 0,
        },
        54,
    );
    let captured = bgp::decode_pcap(
        &raw,
        PcapMetadata {
            source_id: "synthetic-source".into(),
            record_id: "r".into(),
            observed_at_ns: None,
            session: Some(7),
            direction: Some(0),
            peer: None,
            local: None,
        },
        &mut SessionState::default(),
        &Limits::default(),
    )
    .unwrap();
    let imported = normalized(&context(), "r", RouteAction::Announce);
    assert_eq!(get(&captured, "schema"), get(&imported, "schema"));
    assert_eq!(get(&captured, "import_context"), &Json::Null);
    assert_ne!(get(&captured, "source_kind"), get(&imported, "source_kind"));
    assert_ne!(get(&captured, "evidence"), &Json::Null);
    let mut forged = captured.clone();
    set(
        &mut forged,
        "import_context",
        get(&imported, "import_context").clone(),
    );
    assert!(Observation::from_normalized(&forged, None, &Limits::default()).is_err());
}
#[test]
fn same_source_record_legacy_and_contextual_imports_cannot_merge() {
    let c = context();
    let legacy =
        bgp::normalize_imported(input(&c, "r", RouteAction::Announce), &Limits::default()).unwrap();
    let mut s = state();
    s.apply(
        Observation::from_normalized(
            &legacy,
            Some(ImportScope {
                generation: 7,
                direction: 0,
            }),
            &Limits::default(),
        )
        .unwrap(),
    )
    .unwrap();
    s.apply(observation(&c, "r", RouteAction::Announce))
        .unwrap();
    assert_eq!(s.routes().len(), 2);
    assert_eq!(
        s.routes()
            .iter()
            .filter(|r| r.import_partition.is_some())
            .count(),
        1
    );
}
#[test]
fn unknown_direction_does_not_create_or_advance_a_session() {
    let mut c = context();
    c.direction = None;
    let mut s = state();
    assert_eq!(
        s.apply(observation(&c, "r", RouteAction::Announce))
            .unwrap()
            .status,
        ApplyStatus::MissingScope
    );
    assert!(s.routes().is_empty());
    assert!(s.sessions().is_empty());
}

#[test]
fn one_immutable_record_cannot_be_reassigned_to_another_direction() {
    let a = context();
    let mut b = a.clone();
    b.direction = Some(1);
    let mut s = state();
    s.apply(observation(&a, "r", RouteAction::Announce))
        .unwrap();
    assert_eq!(
        s.apply(observation(&b, "r", RouteAction::Announce))
            .unwrap()
            .status,
        ApplyStatus::IdentityConflict
    );
    assert!(s.routes().is_empty());
}

#[test]
fn optional_authority_claims_cannot_be_laundered_through_normalized_input() {
    for key in [
        "rib_established",
        "best_path_selected",
        "reachability_established",
        "source_authority_established",
        "normative_conformance_certified",
    ] {
        let mut j = normalized(&context(), "r", RouteAction::Announce);
        set(&mut j, key, true.into());
        assert!(Observation::from_normalized(&j, None, &Limits::default()).is_err());
        set(&mut j, key, false.into());
        assert!(Observation::from_normalized(&j, None, &Limits::default()).is_ok());
    }
}
