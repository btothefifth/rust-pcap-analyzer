//! Hand-calculated prefix/time relations and source-scope/atomicity regressions.
//! Nothing in these tests establishes an endpoint path, attack or causal relation.
use pcap_evidence::{
    json::Json,
    provenance::{EvidenceBytes, PacketId},
    sha256, ErrorCode,
};
use pcap_evidence_product::deep::{
    bgp::{self, ImportedRouteObservation, PathAttributes, Prefix, RouteAction},
    bgp_association::*,
    bgp_import::{
        self, ClockPolicy, GenerationBoundary, ImportContext, ObservationClock, SourceBatch,
        SourceRange,
    },
    bgp_state::{CandidateState, Observation, PrefixIdentity},
    Limits,
};

fn digest(b: &[u8]) -> String {
    sha256::hex(&sha256::digest(b))
}
fn clock() -> ObservationClock {
    ObservationClock {
        policy: ClockPolicy::SourceLabel,
        clock_id: Some("shared-clock-label".into()),
        reported_uncertainty_ns: Some(0),
    }
}
fn import_context() -> ImportContext {
    ImportContext {
        source_id: "route-producer".into(),
        source_schema: "synthetic-route-record".into(),
        source_version: Some("1".into()),
        clock: clock(),
        batch: SourceBatch {
            batch_id: Some("batch-a".into()),
            sha256: Some(digest(b"route fixture")),
            byte_length: Some(13),
        },
        checkpoint_id: "checkpoint-a".into(),
        session: "session-a".into(),
        generation: 7,
        direction: Some(0),
        peer: Some("peer-a".into()),
        local: Some("local-a".into()),
        provenance: vec![SourceRange {
            start: 0,
            end: 13,
            sha256: Some(digest(b"route fixture")),
        }],
    }
}
fn route_context() -> RouteContext {
    RouteContext {
        namespace: Some("comparison-domain".into()),
        flow_id: Some("flow-a".into()),
        captured_or_legacy_clock: None,
        coverage: Coverage::DeclaredComplete,
    }
}
fn normalized(
    c: &ImportContext,
    id: &str,
    med: u32,
    action: RouteAction,
    time: Option<i64>,
) -> Json {
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
        c.clone(),
        &Limits::default(),
    )
    .unwrap()
}
fn route(id: &str) -> RouteEvidence {
    RouteEvidence::from_normalized(
        &normalized(&import_context(), id, 5, RouteAction::Announce, Some(100)),
        0,
        &route_context(),
        &Limits::default(),
    )
    .unwrap()
}
fn internal_input(id: &str) -> InternalInput {
    InternalInput {
        kind: InternalKind::Flow,
        source: SourceIdentity {
            source_id: "independent-observer".into(),
            record_id: id.into(),
            schema: "synthetic-flow-summary".into(),
            version: Some("1".into()),
            batch: Some(SourceBatch {
                batch_id: Some("internal-batch".into()),
                sha256: Some(digest(b"flow record")),
                byte_length: Some(11),
            }),
            checkpoint_id: Some("internal-checkpoint".into()),
        },
        dimensions: Dimensions {
            scope: Scope {
                namespace: Some("comparison-domain".into()),
                session: Some("session-a".into()),
                generation: Some(7),
                flow_id: Some("flow-a".into()),
                direction: Some(0),
            },
            prefix: Some(PrefixIdentity {
                afi: 1,
                safi: 1,
                length: 24,
                address: "203.0.113.0".into(),
            }),
            endpoint: Some(EndpointIdentity {
                afi: 1,
                address: "203.0.113.9".into(),
            }),
            unsupported: Vec::new(),
        },
        time: TimeLabel {
            observed_at_ns: Some(100),
            clock: clock(),
        },
        coverage: Coverage::DeclaredComplete,
        provenance: Provenance {
            record_sha256: Some(digest(b"flow record")),
            ranges: vec![SourceRange {
                start: 0,
                end: 11,
                sha256: None,
            }],
            details: Json::object([
                ("measurement_kind", "independent_summary".into()),
                ("observed_octets", 4096u32.into()),
            ]),
        },
    }
}
fn internal(id: &str) -> InternalEvidence {
    InternalEvidence::new(internal_input(id), &Limits::default()).unwrap()
}
fn policy() -> Policy {
    Policy {
        policy_id: "explicit-policy-v1".into(),
        session: DimensionRule::RequireEqual,
        generation: DimensionRule::RequireEqual,
        flow: DimensionRule::RequireEqual,
        direction: DirectionRule::Equal,
        spatial: SpatialRule::EqualPrefix,
        time: TimePolicy::Window {
            max_distance_ns: 10,
            clocks: ClockRelation::SamePolicyAndId,
            missing: MissingClockHandling::Unresolved,
            semantics: WindowSemantics::AllReportedBounds,
        },
    }
}
fn run(routes: Vec<RouteEvidence>, other: Vec<InternalEvidence>, p: Policy) -> AssociationReport {
    associate(
        &RouteBatch::new(routes, &Limits::default()).unwrap(),
        &other,
        &p,
        &Limits::default(),
    )
    .unwrap()
}
fn has(r: &AssociationReport, reason: Reason) -> bool {
    r.associations().iter().any(|a| a.reasons.contains(&reason))
}
fn all(r: &AssociationReport, s: AssociationStatus) -> bool {
    r.associations().iter().all(|a| a.status == s)
}
fn get<'a>(v: &'a Json, key: &str) -> &'a Json {
    let Json::Object(fields) = v else {
        panic!("not object")
    };
    &fields.iter().find(|(k, _)| *k == key).unwrap().1
}
fn set(v: &mut Json, key: &'static str, item: Json) {
    let Json::Object(fields) = v else {
        panic!("not object")
    };
    if let Some((_, v)) = fields.iter_mut().find(|(k, _)| *k == key) {
        *v = item;
    } else {
        fields.push((key, item));
    }
}
fn observation(c: &ImportContext, id: &str, med: u32, action: RouteAction) -> Observation {
    Observation::from_normalized(
        &normalized(c, id, med, action, Some(100)),
        None,
        &Limits::default(),
    )
    .unwrap()
}

#[test]
fn exact_match_retains_both_identities_and_provenance_without_authority() {
    let result = run(vec![route("r1")], vec![internal("i1")], policy());
    assert_eq!(result.associations().len(), 1);
    assert!(all(&result, AssociationStatus::CompatibleCandidate));
    assert_eq!(result.associations()[0].time.label_distance_ns, Some(0));
    for text in [
        "route-producer",
        "independent-observer",
        "checkpoint-a",
        "internal-checkpoint",
        "record_sha256",
        "provenance",
        "observed_octets",
    ] {
        assert!(result.encode().contains(text));
    }
    for key in [
        "endpoint_state_established",
        "rib_established",
        "best_path_selected",
        "reachability_established",
        "attack_established",
        "causality_established",
        "source_authority_established",
        "normative_conformance_certified",
    ] {
        assert!(result.encode().contains(&format!("\"{key}\":false")));
        assert!(!result.encode().contains(&format!("\"{key}\":true")));
    }
}

#[test]
fn independently_shaped_security_record_uses_same_generic_dimensions() {
    let mut other = internal_input("security-1");
    other.kind = InternalKind::Security;
    other.provenance.details = Json::object([
        ("category_label", "caller_classification".into()),
        ("reference", "record-anchor".into()),
    ]);
    let r = run(
        vec![route("r")],
        vec![InternalEvidence::new(other, &Limits::default()).unwrap()],
        policy(),
    );
    assert!(all(&r, AssociationStatus::CompatibleCandidate));
    assert!(r.encode().contains("internal_security"));
    assert!(r.encode().contains("caller_classification"));
}
#[test]
fn containment_uses_prefix_bits_not_next_hop_or_reachability() {
    let mut p = policy();
    p.spatial = SpatialRule::RoutePrefixContainsEndpoint;
    assert!(all(
        &run(vec![route("r")], vec![internal("i")], p.clone()),
        AssociationStatus::CompatibleCandidate
    ));
    let mut i = internal_input("outside");
    i.dimensions.endpoint.as_mut().unwrap().address = "203.0.114.9".into();
    let r = run(
        vec![route("r")],
        vec![InternalEvidence::new(i, &Limits::default()).unwrap()],
        p,
    );
    assert!(has(&r, Reason::IncompatibleEndpoint));
}
#[test]
fn namespace_and_session_are_isolated_and_missing_namespace_is_not_wildcard() {
    for (which, expected) in [
        (0, Reason::IncompatibleNamespace),
        (1, Reason::IncompatibleSession),
        (2, Reason::MissingNamespace),
        (3, Reason::MissingSession),
    ] {
        let mut i = internal_input("i");
        match which {
            0 => i.dimensions.scope.namespace = Some("other-domain".into()),
            1 => i.dimensions.scope.session = Some("other-session".into()),
            2 => i.dimensions.scope.namespace = None,
            _ => i.dimensions.scope.session = None,
        }
        let r = run(
            vec![route("r")],
            vec![InternalEvidence::new(i, &Limits::default()).unwrap()],
            policy(),
        );
        assert!(has(&r, expected));
        assert!(!all(&r, AssociationStatus::CompatibleCandidate));
    }
}
#[test]
fn generation_and_flow_dimensions_need_explicit_equal_values_when_required() {
    for which in 0..4 {
        let mut i = internal_input("i");
        let expected = match which {
            0 => {
                i.dimensions.scope.generation = Some(8);
                Reason::IncompatibleGeneration
            }
            1 => {
                i.dimensions.scope.generation = None;
                Reason::MissingGeneration
            }
            2 => {
                i.dimensions.scope.flow_id = Some("other-flow".into());
                Reason::IncompatibleFlow
            }
            _ => {
                i.dimensions.scope.flow_id = None;
                Reason::MissingFlow
            }
        };
        let r = run(
            vec![route("r")],
            vec![InternalEvidence::new(i, &Limits::default()).unwrap()],
            policy(),
        );
        assert!(has(&r, expected));
    }
}
#[test]
fn ignoring_a_dimension_is_recorded_policy_not_an_implicit_namespace_join() {
    let mut i = internal_input("i");
    i.dimensions.scope.session = None;
    i.dimensions.scope.generation = None;
    i.dimensions.scope.flow_id = None;
    let mut p = policy();
    p.session = DimensionRule::Ignore;
    p.generation = DimensionRule::Ignore;
    p.flow = DimensionRule::Ignore;
    let r = run(
        vec![route("r")],
        vec![InternalEvidence::new(i, &Limits::default()).unwrap()],
        p,
    );
    assert!(all(&r, AssociationStatus::CompatibleCandidate));
    assert!(r.encode().contains("\"generation\":\"ignore\""));
    assert!(r.encode().contains("\"namespace\":\"require_equal\""));
}
#[test]
fn directions_are_only_compared_under_explicit_equal_or_opposite_policy() {
    let mut i = internal_input("i");
    i.dimensions.scope.direction = Some(1);
    let i = InternalEvidence::new(i, &Limits::default()).unwrap();
    assert!(has(
        &run(vec![route("r")], vec![i.clone()], policy()),
        Reason::IncompatibleDirection
    ));
    let mut p = policy();
    p.direction = DirectionRule::Opposite;
    assert!(all(
        &run(vec![route("r")], vec![i], p),
        AssociationStatus::CompatibleCandidate
    ));
    let mut unknown = internal_input("i");
    unknown.dimensions.scope.direction = None;
    assert!(has(
        &run(
            vec![route("r")],
            vec![InternalEvidence::new(unknown, &Limits::default()).unwrap()],
            policy()
        ),
        Reason::MissingDirection
    ));
}
#[test]
fn missing_timestamp_does_not_become_zero_and_error_mode_has_no_partial_output() {
    let mut i = internal_input("i");
    i.time.observed_at_ns = None;
    let i = InternalEvidence::new(i, &Limits::default()).unwrap();
    let r = run(vec![route("r")], vec![i.clone()], policy());
    assert!(has(&r, Reason::MissingTime));
    assert_eq!(r.associations()[0].time.label_distance_ns, None);
    assert!(r.encode().contains("\"observed_at_ns\":null"));
    let mut p = policy();
    if let TimePolicy::Window { missing, .. } = &mut p.time {
        *missing = MissingClockHandling::Error;
    }
    let batch = RouteBatch::new(vec![route("r")], &Limits::default()).unwrap();
    let before = batch.routes()[0].data().clone();
    assert!(associate(&batch, &[internal("known"), i], &p, &Limits::default()).is_err());
    assert_eq!(batch.routes()[0].data(), &before);
}
#[test]
fn explicit_zero_and_negative_timestamps_remain_exact_signed_labels() {
    for (a, b, expected) in [(0, 0, 0), (-17, -8, 9)] {
        let route = RouteEvidence::from_normalized(
            &normalized(&import_context(), "r", 5, RouteAction::Announce, Some(a)),
            0,
            &route_context(),
            &Limits::default(),
        )
        .unwrap();
        let mut i = internal_input("i");
        i.time.observed_at_ns = Some(b);
        let r = run(
            vec![route],
            vec![InternalEvidence::new(i, &Limits::default()).unwrap()],
            policy(),
        );
        assert_eq!(r.associations()[0].time.label_distance_ns, Some(expected));
        assert!(all(&r, AssociationStatus::CompatibleCandidate));
    }
}
#[test]
fn unknown_clock_and_unknown_uncertainty_are_distinct_unresolved_states() {
    for unknown_policy in [true, false] {
        let mut i = internal_input("i");
        if unknown_policy {
            i.time.clock = ObservationClock::default();
        } else {
            i.time.clock.reported_uncertainty_ns = None;
        }
        let r = run(
            vec![route("r")],
            vec![InternalEvidence::new(i, &Limits::default()).unwrap()],
            policy(),
        );
        assert!(has(
            &r,
            if unknown_policy {
                Reason::UnknownClock
            } else {
                Reason::UnknownUncertainty
            }
        ));
    }
}
#[test]
fn clock_comparability_is_explicit_and_source_vs_ingestion_is_not_inferred_equal() {
    for change_policy in [false, true] {
        let mut i = internal_input("i");
        if change_policy {
            i.time.clock.policy = ClockPolicy::IngestionLabel;
        } else {
            i.time.clock.clock_id = Some("different-clock".into());
        }
        let i = InternalEvidence::new(i, &Limits::default()).unwrap();
        assert!(has(
            &run(vec![route("r")], vec![i.clone()], policy()),
            Reason::IncompatibleClock
        ));
        let mut p = policy();
        if let TimePolicy::Window { clocks, .. } = &mut p.time {
            *clocks = ClockRelation::CallerComparable {
                basis: "explicit-comparability-label".into(),
            };
        }
        let r = run(vec![route("r")], vec![i], p);
        assert!(all(&r, AssociationStatus::CompatibleCandidate));
        assert!(r.encode().contains("explicit-comparability-label"));
    }
}
#[test]
fn reported_bounds_use_inclusive_distance_and_preserve_straddling_uncertainty() {
    for (distance, uncertainty, expected, min, max) in [
        (8, 2, AssociationStatus::CompatibleCandidate, 6, 10),
        (10, 1, AssociationStatus::Unresolved, 9, 11),
        (13, 2, AssociationStatus::Incompatible, 11, 15),
    ] {
        let mut i = internal_input("i");
        i.time.observed_at_ns = Some(100 + distance);
        i.time.clock.reported_uncertainty_ns = Some(uncertainty);
        let r = run(
            vec![route("r")],
            vec![InternalEvidence::new(i, &Limits::default()).unwrap()],
            policy(),
        );
        assert!(all(&r, expected));
        assert_eq!(r.associations()[0].time.minimum_distance_ns, Some(min));
        assert_eq!(r.associations()[0].time.maximum_distance_ns, Some(max));
        assert!(r.associations()[0].time.uncertainty_used);
    }
}
#[test]
fn label_distance_policy_does_not_claim_missing_uncertainty_is_zero() {
    let mut i = internal_input("i");
    i.time.clock.reported_uncertainty_ns = None;
    let mut p = policy();
    if let TimePolicy::Window { semantics, .. } = &mut p.time {
        *semantics = WindowSemantics::LabelDistance;
    }
    let r = run(
        vec![route("r")],
        vec![InternalEvidence::new(i, &Limits::default()).unwrap()],
        p,
    );
    assert!(all(&r, AssociationStatus::CompatibleCandidate));
    assert!(!r.associations()[0].time.uncertainty_used);
    assert_eq!(r.associations()[0].time.minimum_distance_ns, None);
    assert!(r.encode().contains("\"reported_uncertainty_ns\":null"));
}
#[test]
fn ignore_time_requires_a_reason_and_does_not_fabricate_a_distance() {
    let mut i = internal_input("i");
    i.time.clock = ObservationClock::default();
    i.time.observed_at_ns = None;
    let mut p = policy();
    p.time = TimePolicy::Ignore {
        reason: "spatial_only_review".into(),
    };
    let r = run(
        vec![route("r")],
        vec![InternalEvidence::new(i, &Limits::default()).unwrap()],
        p.clone(),
    );
    assert!(all(&r, AssociationStatus::CompatibleCandidate));
    assert_eq!(r.associations()[0].time.label_distance_ns, None);
    p.time = TimePolicy::Ignore {
        reason: String::new(),
    };
    assert!(associate(
        &RouteBatch::new(vec![route("r")], &Limits::default()).unwrap(),
        &[internal("i")],
        &p,
        &Limits::default()
    )
    .is_err());
}
#[test]
fn full_signed_time_and_uncertainty_ranges_do_not_overflow_or_round() {
    let mut c = import_context();
    c.clock.reported_uncertainty_ns = Some(u64::MAX);
    let route = RouteEvidence::from_normalized(
        &normalized(&c, "r", 5, RouteAction::Announce, Some(i64::MIN)),
        0,
        &route_context(),
        &Limits::default(),
    )
    .unwrap();
    let mut i = internal_input("i");
    i.time.observed_at_ns = Some(i64::MAX);
    i.time.clock.reported_uncertainty_ns = Some(u64::MAX);
    let r = run(
        vec![route],
        vec![InternalEvidence::new(i, &Limits::default()).unwrap()],
        policy(),
    );
    assert!(has(&r, Reason::UncertainWindow));
    assert_eq!(
        r.associations()[0].time.label_distance_ns,
        Some(u128::from(u64::MAX))
    );
    assert_eq!(
        r.associations()[0].time.maximum_distance_ns,
        Some(u128::from(u64::MAX) * 3)
    );
    assert!(r.encode().contains("55340232221128654845"));
}
#[test]
fn identical_duplicate_inputs_are_explicit_not_extra_votes() {
    let a = route("r");
    let b = internal("i");
    let r = run(vec![a.clone(), a], vec![b.clone(), b], policy());
    assert_eq!(r.routes().len(), 1);
    assert_eq!(r.internal().len(), 1);
    assert_eq!(r.routes()[0].occurrences(), 2);
    assert_eq!(r.internal()[0].occurrences(), 2);
    assert!(has(&r, Reason::DuplicateIdentity));
    assert!(all(&r, AssociationStatus::Unresolved));
}
#[test]
fn changed_record_contents_remain_conflicting_alternatives_not_first_or_last() {
    let changed = RouteEvidence::from_normalized(
        &normalized(&import_context(), "r", 6, RouteAction::Announce, Some(100)),
        0,
        &route_context(),
        &Limits::default(),
    )
    .unwrap();
    let r = run(vec![route("r"), changed], vec![internal("i")], policy());
    assert_eq!(r.routes().len(), 2);
    assert_eq!(r.associations().len(), 2);
    assert!(r
        .routes()
        .iter()
        .all(|e| e.reasons().contains(&Reason::ChangedContentConflict)));
    assert!(all(&r, AssociationStatus::Unresolved));
}
#[test]
fn changed_internal_hash_or_time_does_not_evade_record_identity_conflict() {
    for change_hash in [true, false] {
        let mut i = internal_input("i");
        if change_hash {
            i.provenance.record_sha256 = Some(digest(b"other-record"));
        } else {
            i.time.observed_at_ns = Some(101);
        }
        let r = run(
            vec![route("r")],
            vec![
                internal("i"),
                InternalEvidence::new(i, &Limits::default()).unwrap(),
            ],
            policy(),
        );
        assert_eq!(r.internal().len(), 2);
        assert!(r
            .internal()
            .iter()
            .all(|e| e.reasons().contains(&Reason::ChangedContentConflict)));
    }
}
#[test]
fn conflicting_attributes_and_multiple_matches_retain_every_witness_without_ranking() {
    let changed = RouteEvidence::from_normalized(
        &normalized(
            &import_context(),
            "different-record",
            999,
            RouteAction::Announce,
            Some(100),
        ),
        0,
        &route_context(),
        &Limits::default(),
    )
    .unwrap();
    let r = run(vec![route("r"), changed], vec![internal("i")], policy());
    assert_eq!(r.associations().len(), 2);
    assert!(r
        .associations()
        .iter()
        .all(|a| a.reasons.contains(&Reason::ConflictingAttributes)
            && a.reasons.contains(&Reason::MultipleCandidates)));
    assert!(!has(&r, Reason::ChangedContentConflict));
}
#[test]
fn imported_batches_checkpoints_and_generations_never_collapse_into_one_route() {
    for axis in 0..4 {
        let mut c = import_context();
        match axis {
            0 => c.batch.batch_id = Some("batch-b".into()),
            1 => c.checkpoint_id = "checkpoint-b".into(),
            2 => c.batch.sha256 = Some(digest(b"different-source")),
            _ => c.generation = 8,
        }
        let other = RouteEvidence::from_normalized(
            &normalized(&c, "r", 5, RouteAction::Announce, Some(100)),
            0,
            &route_context(),
            &Limits::default(),
        )
        .unwrap();
        let r = run(vec![route("r"), other], vec![internal("i")], policy());
        assert_eq!(r.routes().len(), 2);
        if axis == 3 {
            assert!(has(&r, Reason::ChangedContentConflict));
        } else {
            assert!(!has(&r, Reason::ChangedContentConflict));
            assert!(has(&r, Reason::MultipleCandidates));
        }
    }
}
#[test]
fn reversing_inputs_and_object_key_order_produces_identical_canonical_output() {
    let a = route("a");
    let b = route("b");
    let x = internal("x");
    let y = internal("y");
    let forward = run(
        vec![a.clone(), b.clone()],
        vec![x.clone(), y.clone()],
        policy(),
    );
    let reverse = run(vec![b, a], vec![y, x], policy());
    assert_eq!(forward.encode(), reverse.encode());
    let mut i = internal_input("z");
    let one = InternalEvidence::new(i.clone(), &Limits::default()).unwrap();
    if let Json::Object(v) = &mut i.provenance.details {
        v.reverse();
    }
    let two = InternalEvidence::new(i, &Limits::default()).unwrap();
    let r = run(vec![route("r")], vec![one, two], policy());
    assert_eq!(r.internal().len(), 1);
    assert_eq!(r.internal()[0].occurrences(), 2);
}
#[test]
fn original_provenance_order_duplicates_and_signed_labels_are_not_sorted_away() {
    let mut i = internal_input("i");
    i.source.batch.as_mut().unwrap().byte_length = Some(20);
    i.provenance.ranges = vec![
        SourceRange {
            start: 10,
            end: 12,
            sha256: None,
        },
        SourceRange {
            start: 0,
            end: 2,
            sha256: None,
        },
        SourceRange {
            start: 10,
            end: 12,
            sha256: None,
        },
    ];
    let original = i.provenance.ranges.clone();
    let i = InternalEvidence::new(i, &Limits::default()).unwrap();
    assert_eq!(i.input().provenance.ranges, original);
    let r = run(vec![route("r")], vec![i], policy());
    let spans = get(get(r.internal()[0].data(), "provenance"), "ranges");
    let Json::Array(spans) = spans else {
        panic!("ranges")
    };
    assert_eq!(get(&spans[0], "start"), &Json::from("10"));
    assert_eq!(get(&spans[1], "start"), &Json::from("0"));
    assert_eq!(spans[0], spans[2]);
}
#[test]
fn malformed_prefix_endpoint_and_noncanonical_host_bits_are_typed_errors() {
    for axis in 0..4 {
        let mut i = internal_input("i");
        match axis {
            0 => i.dimensions.prefix.as_mut().unwrap().length = 33,
            1 => i.dimensions.prefix.as_mut().unwrap().address = "203.0.113.1".into(),
            2 => i.dimensions.endpoint.as_mut().unwrap().address = "999.2.3.4".into(),
            _ => {
                i.dimensions.endpoint = Some(EndpointIdentity {
                    afi: 2,
                    address: "203.0.113.1".into(),
                })
            }
        }
        assert!(InternalEvidence::new(i, &Limits::default()).is_err());
    }
}
#[test]
fn ipv6_equivalent_spellings_compare_equal_but_original_labels_are_retained() {
    let c = import_context();
    let value = bgp_import::normalize_with_context(
        ImportedRouteObservation {
            source_id: c.source_id.clone(),
            record_id: "v6".into(),
            observed_at_ns: Some(100),
            session: Some(c.session.clone()),
            peer: c.peer.clone(),
            local: c.local.clone(),
            action: RouteAction::Announce,
            prefix: Prefix::ipv6(
                [0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                32,
            )
            .unwrap(),
            attributes: PathAttributes::default(),
        },
        c,
        &Limits::default(),
    )
    .unwrap();
    let route =
        RouteEvidence::from_normalized(&value, 0, &route_context(), &Limits::default()).unwrap();
    let mut i = internal_input("i");
    i.dimensions.prefix = Some(PrefixIdentity {
        afi: 2,
        safi: 1,
        length: 32,
        address: "2001:0db8:0000:0:0:0:0:0".into(),
    });
    let r = run(
        vec![route],
        vec![InternalEvidence::new(i, &Limits::default()).unwrap()],
        policy(),
    );
    assert!(all(&r, AssociationStatus::CompatibleCandidate));
    assert!(r.encode().contains("2001:0db8:0000:0:0:0:0:0"));
}
#[test]
fn unsupported_families_safi_and_dimension_tokens_are_unresolved_not_guessed() {
    for axis in 0..3 {
        let mut i = internal_input("i");
        match axis {
            0 => {
                i.dimensions.prefix = Some(PrefixIdentity {
                    afi: 99,
                    safi: 1,
                    length: 1,
                    address: "opaque-address".into(),
                })
            }
            1 => i.dimensions.prefix.as_mut().unwrap().safi = 128,
            _ => i
                .dimensions
                .unsupported
                .push("unreviewed-port-relation".into()),
        }
        let r = run(
            vec![route("r")],
            vec![InternalEvidence::new(i, &Limits::default()).unwrap()],
            policy(),
        );
        assert!(has(&r, Reason::UnsupportedDimension));
        assert!(all(&r, AssociationStatus::Unresolved));
    }
}
#[test]
fn incomplete_coverage_and_missing_provenance_are_explicit() {
    let mut i = internal_input("i");
    i.coverage = Coverage::Incomplete;
    i.provenance = Provenance {
        record_sha256: None,
        ranges: Vec::new(),
        details: Json::Null,
    };
    let r = run(
        vec![route("r")],
        vec![InternalEvidence::new(i, &Limits::default()).unwrap()],
        policy(),
    );
    assert!(has(&r, Reason::InsufficientCoverage));
    assert!(has(&r, Reason::InsufficientProvenance));
}
#[test]
fn empty_sides_and_missing_spatial_fields_are_unresolved_rows_not_silence() {
    assert!(has(
        &run(Vec::new(), vec![internal("i")], policy()),
        Reason::NoRouteEvidence
    ));
    assert!(has(
        &run(vec![route("r")], Vec::new(), policy()),
        Reason::NoInternalEvidence
    ));
    assert_eq!(
        run(Vec::new(), Vec::new(), policy()).associations().len(),
        1
    );
    let mut i = internal_input("i");
    i.dimensions.prefix = None;
    assert!(has(
        &run(
            vec![route("r")],
            vec![InternalEvidence::new(i, &Limits::default()).unwrap()],
            policy()
        ),
        Reason::MissingPrefix
    ));
}
#[test]
fn current_candidate_state_adapter_preserves_snapshot_and_independent_record_shape() {
    let mut state = CandidateState::new(Limits::default()).unwrap();
    state
        .apply(observation(
            &import_context(),
            "r",
            5,
            RouteAction::Announce,
        ))
        .unwrap();
    let before = state.encode().to_owned();
    let batch =
        RouteBatch::from_candidate_state(&state, &route_context(), &Limits::default()).unwrap();
    assert_eq!(
        batch.snapshot_sha256(),
        Some(digest(before.as_bytes()).as_str())
    );
    let report = associate(&batch, &[internal("flow")], &policy(), &Limits::default()).unwrap();
    assert!(all(&report, AssociationStatus::CompatibleCandidate));
    assert_eq!(state.encode(), before);
    assert!(report.encode().contains("current_candidate_witness"));
    assert!(report.encode().contains("independent_summary"));
}
#[test]
fn state_reset_quarantine_and_inactive_witnesses_remain_visible_without_resurrection() {
    let c = import_context();
    let mut state = CandidateState::new(Limits::default()).unwrap();
    state
        .apply(observation(&c, "r", 5, RouteAction::Announce))
        .unwrap();
    let mut next = c.clone();
    next.generation = 8;
    next.direction = None;
    let boundary = bgp_import::normalize_boundary(
        next,
        GenerationBoundary {
            previous_generation: 7,
            reason: "explicit-session-boundary".into(),
        },
        "reset".into(),
        None,
        &Limits::default(),
    )
    .unwrap();
    state
        .apply(Observation::from_normalized(&boundary, None, &Limits::default()).unwrap())
        .unwrap();
    let before = state.encode().to_owned();
    let batch =
        RouteBatch::from_candidate_state(&state, &route_context(), &Limits::default()).unwrap();
    assert_eq!(batch.routes().len(), 1);
    assert_eq!(batch.notes().len(), 1);
    let result = associate(&batch, &[internal("i")], &policy(), &Limits::default()).unwrap();
    assert!(has(&result, Reason::NotCurrentCandidate));
    assert!(result.encode().contains("explicit-session-boundary"));
    assert_eq!(state.encode(), before);
    let mut conflicted = CandidateState::new(Limits::default()).unwrap();
    conflicted
        .apply(observation(&c, "same", 5, RouteAction::Announce))
        .unwrap();
    conflicted
        .apply(observation(&c, "same", 6, RouteAction::Announce))
        .unwrap();
    let batch = RouteBatch::from_candidate_state(&conflicted, &route_context(), &Limits::default())
        .unwrap();
    let result = associate(&batch, &[internal("i")], &policy(), &Limits::default()).unwrap();
    assert!(has(&result, Reason::ChangedContentConflict));
    assert!(all(&result, AssociationStatus::Unresolved));
    assert!(conflicted.routes().is_empty());
}
#[test]
fn retired_attributes_do_not_contaminate_a_current_state_candidate() {
    let c = import_context();
    let mut state = CandidateState::new(Limits::default()).unwrap();
    state
        .apply(observation(&c, "old", 5, RouteAction::Announce))
        .unwrap();
    state
        .apply(observation(&c, "withdraw", 0, RouteAction::Withdraw))
        .unwrap();
    state
        .apply(observation(&c, "new", 9, RouteAction::Announce))
        .unwrap();
    let batch =
        RouteBatch::from_candidate_state(&state, &route_context(), &Limits::default()).unwrap();
    let r = associate(&batch, &[internal("i")], &policy(), &Limits::default()).unwrap();
    assert_eq!(
        r.associations()
            .iter()
            .filter(|a| a.status == AssociationStatus::CompatibleCandidate)
            .count(),
        1
    );
    assert!(!has(&r, Reason::MultipleCandidates));
}
#[test]
fn legacy_import_does_not_invent_an_immutable_batch_or_checkpoint() {
    let c = import_context();
    let v = bgp::normalize_imported(
        ImportedRouteObservation {
            source_id: c.source_id,
            record_id: "legacy".into(),
            observed_at_ns: Some(100),
            session: Some(c.session),
            peer: c.peer,
            local: c.local,
            action: RouteAction::Announce,
            prefix: Prefix::ipv4([203, 0, 113, 0], 24).unwrap(),
            attributes: PathAttributes::default(),
        },
        &Limits::default(),
    )
    .unwrap();
    let route =
        RouteEvidence::from_normalized(&v, 0, &route_context(), &Limits::default()).unwrap();
    let r = run(vec![route], vec![internal("i")], policy());
    assert!(has(&r, Reason::MissingImportContext));
    assert!(has(&r, Reason::MissingGeneration));
}
#[test]
fn contextual_import_clock_cannot_be_overridden_and_malformed_clocks_fail() {
    let mut ctx = route_context();
    ctx.captured_or_legacy_clock = Some(clock());
    assert!(RouteEvidence::from_normalized(
        &normalized(&import_context(), "r", 5, RouteAction::Announce, Some(100)),
        0,
        &ctx,
        &Limits::default()
    )
    .is_err());
    let mut i = internal_input("i");
    i.time.clock.policy = ClockPolicy::Unknown;
    assert!(InternalEvidence::new(i, &Limits::default()).is_err());
}
#[test]
fn captured_normalized_case_preserves_packet_spans_and_remains_distinct_from_imports() {
    // Fixed 45-byte UPDATE: 18 attribute bytes, prefix [41,45), no withdrawals.
    let hex = "ffffffffffffffffffffffffffffffff002d0200000012400101004002040201fde8400304c000020118cb0071";
    let raw: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|n| u8::from_str_radix(&hex[n..n + 2], 16).unwrap())
        .collect();
    assert_eq!(raw.len(), 45);
    let packet = PacketId {
        capture: [0x31; 32],
        frame: 7,
        record_offset: 420,
    };
    let evidence = EvidenceBytes::from_packet(&raw, packet, 54);
    let v = bgp::decode_pcap(
        &evidence,
        bgp::PcapMetadata {
            source_id: "captured-source".into(),
            record_id: "packet-seven".into(),
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
    let mut ctx = route_context();
    ctx.captured_or_legacy_clock = Some(clock());
    let captured = RouteEvidence::from_normalized(&v, 0, &ctx, &Limits::default()).unwrap();
    let original = captured.data().clone();
    let mut p = policy();
    p.session = DimensionRule::Ignore;
    p.generation = DimensionRule::Ignore;
    let r = run(vec![captured, route("r")], vec![internal("i")], p);
    assert_eq!(r.routes().len(), 2);
    assert!(has(&r, Reason::MultipleCandidates));
    assert!(r.encode().contains("packet-seven"));
    assert!(r.encode().contains("\"packet_start\":\"54\""));
    let preserved = get(get(&original, "record"), "normalized");
    assert_eq!(get(preserved, "source_id"), get(&v, "source_id"));
    assert_eq!(
        get(get(preserved, "evidence"), "reconstructed_sha256"),
        get(get(&v, "evidence"), "reconstructed_sha256")
    );
    let Json::Array(spans) = get(get(preserved, "evidence"), "spans") else {
        panic!("spans")
    };
    assert_eq!(get(&spans[0], "packet_start"), &Json::from("54"));
    assert_eq!(get(&spans[0], "frame"), &Json::from("7"));
    assert!(!has(&r, Reason::ChangedContentConflict));
}
#[test]
fn unknown_attributes_and_upstream_incomplete_issues_are_retained_without_repair() {
    let mut v = normalized(&import_context(), "r", 5, RouteAction::Announce, Some(100));
    let Json::Object(fields) = &mut v else {
        panic!()
    };
    let Json::Array(routes) = &mut fields.iter_mut().find(|(k, _)| *k == "routes").unwrap().1
    else {
        panic!()
    };
    let Json::Object(route) = &mut routes[0] else {
        panic!()
    };
    let attributes = &mut route
        .iter_mut()
        .find(|(k, _)| *k == "attributes")
        .unwrap()
        .1;
    set(
        attributes,
        "unreviewed_attribute",
        Json::object([("value_token", "opaque-not-a-verdict".into())]),
    );
    set(
        &mut v,
        "issues",
        Json::array(["unreviewed_semantics".into()]),
    );
    let route =
        RouteEvidence::from_normalized(&v, 0, &route_context(), &Limits::default()).unwrap();
    let r = run(vec![route], vec![internal("i")], policy());
    assert!(has(&r, Reason::InsufficientCoverage));
    assert!(r.encode().contains("opaque-not-a-verdict"));
}
#[test]
fn forged_authority_claims_in_either_side_are_rejected() {
    let mut i = internal_input("i");
    i.provenance.details = Json::object([("attack_established", true.into())]);
    assert!(InternalEvidence::new(i, &Limits::default()).is_err());
    let mut v = normalized(&import_context(), "r", 5, RouteAction::Announce, Some(100));
    set(&mut v, "attack_established", true.into());
    assert!(RouteEvidence::from_normalized(&v, 0, &route_context(), &Limits::default()).is_err());
}
#[test]
fn malformed_identity_hash_ranges_duplicate_keys_and_overlong_metadata_fail_closed() {
    for axis in 0..8 {
        let mut i = internal_input("i");
        match axis {
            0 => i.source.record_id.clear(),
            1 => i.source.schema = "bad\nidentity".into(),
            2 => i.source.version = Some("x".repeat(1025)),
            3 => i.provenance.record_sha256 = Some("not-a-digest".into()),
            4 => i.provenance.ranges[0].end = 12,
            5 => i.provenance.ranges[0].start = 11,
            6 => i.source.source_id = "   ".into(),
            _ => {
                i.provenance.details =
                    Json::Object(vec![("same", 1u8.into()), ("same", 2u8.into())])
            }
        }
        assert!(
            InternalEvidence::new(i, &Limits::default()).is_err(),
            "axis {axis}"
        );
    }
}
#[test]
fn every_limit_class_fails_atomically_under_lower_consumer_limits() {
    // A frozen observation made with larger limits cannot bypass the route cap.
    let mut normalized = normalized(
        &import_context(),
        "multi",
        5,
        RouteAction::Announce,
        Some(100),
    );
    let Json::Object(fields) = &mut normalized else {
        panic!("envelope")
    };
    let Json::Array(routes) = &mut fields.iter_mut().find(|(k, _)| *k == "routes").unwrap().1
    else {
        panic!("routes")
    };
    routes.push(routes[0].clone());
    let observation = Observation::from_normalized(&normalized, None, &Limits::default()).unwrap();
    let small = Limits {
        elements: 1,
        ..Limits::default()
    };
    assert_eq!(
        RouteEvidence::from_observation(&observation, 0, &route_context(), &small)
            .unwrap_err()
            .code,
        ErrorCode::LimitExceeded
    );
    let batch = RouteBatch::new(vec![route("r")], &Limits::default()).unwrap();
    let other = vec![internal("i")];
    let original = batch.routes()[0].data().clone();
    for axis in 0..9 {
        let mut l = Limits::default();
        match axis {
            0 => l.input_bytes = 1,
            1 => l.fields = 1,
            2 => l.elements = 1,
            3 => l.depth = 1,
            4 => l.spans = 1,
            5 => l.active = 1,
            6 => l.retained_bytes = 1,
            7 => l.work = 1,
            _ => l.output_bytes = 1,
        }
        let error = associate(&batch, &other, &policy(), &l).unwrap_err();
        assert_eq!(error.code, ErrorCode::LimitExceeded, "axis {axis}");
        assert_eq!(batch.routes()[0].data(), &original);
        assert_eq!(other.len(), 1);
    }
}
#[test]
fn cartesian_pair_budget_is_checked_before_returning_any_comparisons() {
    let batch = RouteBatch::new(vec![route("a"), route("b")], &Limits::default()).unwrap();
    let l = Limits {
        elements: 7,
        ..Limits::default()
    }; // 2 + 2 inputs plus 4 pairs needs 8.
    assert!(associate(&batch, &[internal("x"), internal("y")], &policy(), &l).is_err());
}
#[test]
fn selection_failure_cannot_mutate_caller_candidate_state() {
    let mut state = CandidateState::new(Limits::default()).unwrap();
    state
        .apply(observation(
            &import_context(),
            "r",
            5,
            RouteAction::Announce,
        ))
        .unwrap();
    let before = state.encode().to_owned();
    let l = Limits {
        input_bytes: 1,
        ..Limits::default()
    };
    assert!(RouteBatch::from_candidate_state(&state, &route_context(), &l).is_err());
    assert_eq!(state.encode(), before);
}

#[test]
fn fixed_independent_time_vectors_reach_the_native_association_seam() {
    let vectors = include_str!("fixtures/bgp_association_time.tsv");
    let parse_i = |s: &str| {
        if s == "unknown" {
            None
        } else {
            Some(s.parse::<i64>().unwrap())
        }
    };
    let parse_u = |s: &str| {
        if s == "unknown" {
            None
        } else {
            Some(s.parse::<u64>().unwrap())
        }
    };
    let parse_wide = |s: &str| {
        if s == "unknown" {
            None
        } else {
            Some(s.parse::<u128>().unwrap())
        }
    };
    let mut count = 0;
    for row in vectors.lines().filter(|r| !r.starts_with('#')).skip(1) {
        let f: Vec<_> = row.split('\t').collect();
        assert_eq!(f.len(), 11);
        let mut c = import_context();
        c.clock.reported_uncertainty_ns = parse_u(f[3]);
        let route = RouteEvidence::from_normalized(
            &normalized(&c, "r", 5, RouteAction::Announce, parse_i(f[1])),
            0,
            &route_context(),
            &Limits::default(),
        )
        .unwrap();
        let mut i = internal_input("i");
        i.time.observed_at_ns = parse_i(f[2]);
        i.time.clock.reported_uncertainty_ns = parse_u(f[4]);
        let mut p = policy();
        if let TimePolicy::Window {
            max_distance_ns, ..
        } = &mut p.time
        {
            *max_distance_ns = f[5].parse().unwrap();
        }
        let report = run(
            vec![route],
            vec![InternalEvidence::new(i, &Limits::default()).unwrap()],
            p,
        );
        let a = &report.associations()[0];
        assert_eq!(a.status.name(), f[6], "{}", f[0]);
        if f[7] != "-" {
            assert!(a.reasons.iter().any(|r| r.name() == f[7]), "{}", f[0]);
        }
        assert_eq!(a.time.label_distance_ns, parse_wide(f[8]), "{}", f[0]);
        assert_eq!(a.time.minimum_distance_ns, parse_wide(f[9]), "{}", f[0]);
        assert_eq!(a.time.maximum_distance_ns, parse_wide(f[10]), "{}", f[0]);
        count += 1;
    }
    assert_eq!(count, 9);
}
