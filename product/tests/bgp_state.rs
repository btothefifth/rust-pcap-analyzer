//! Independent expected state transitions; no reference RIB or majority oracle.
use pcap_evidence::{
    json::Json,
    provenance::{EvidenceBytes, PacketId},
    sha256, ErrorCode,
};
use pcap_evidence_product::deep::{
    bgp::{
        self, ImportedRouteObservation, PathAttributes, PcapMetadata, Prefix, RouteAction,
        SessionState, SourceKind,
    },
    bgp_state::{
        ApplyStatus, CandidateState, EffectKind, ImportScope, Observation, RoutePathId, Source,
    },
    Limits,
};

fn get<'a>(value: &'a Json, key: &str) -> &'a Json {
    let Json::Object(fields) = value else {
        panic!("expected object")
    };
    &fields.iter().find(|(k, _)| *k == key).unwrap().1
}
fn set(value: &mut Json, key: &'static str, item: Json) {
    let Json::Object(fields) = value else {
        panic!("expected object")
    };
    if let Some((_, old)) = fields.iter_mut().find(|(k, _)| *k == key) {
        *old = item;
    } else {
        fields.push((key, item));
    }
}
fn vector(name: &str) -> Vec<u8> {
    let hex = include_str!("fixtures/bgp_state.hex")
        .lines()
        .find_map(|line| {
            let mut words = line.split_whitespace();
            if words.next() == Some(name) {
                words.next()
            } else {
                None
            }
        })
        .unwrap();
    (0..hex.len())
        .step_by(2)
        .map(|p| u8::from_str_radix(&hex[p..p + 2], 16).unwrap())
        .collect()
}
fn raw(name: &str, frame: u64) -> EvidenceBytes {
    EvidenceBytes::from_packet(
        &vector(name),
        PacketId {
            capture: sha256::digest(b"synthetic-bgp-source"),
            frame,
            record_offset: frame * 100,
        },
        54,
    )
}
fn metadata(id: &str, direction: Option<u8>) -> PcapMetadata {
    PcapMetadata {
        source_id: "source-a".into(),
        record_id: id.into(),
        observed_at_ns: Some(-42),
        session: Some(7),
        direction,
        peer: None,
        local: None,
    }
}
fn captured(
    name: &str,
    id: &str,
    frame: u64,
    direction: Option<u8>,
    state: &mut SessionState,
) -> Json {
    bgp::decode_pcap(
        &raw(name, frame),
        metadata(id, direction),
        state,
        &Limits::default(),
    )
    .unwrap()
}
fn input(id: &str, action: RouteAction, med: u32) -> Json {
    bgp::normalize_imported(
        ImportedRouteObservation {
            source_id: "source-a".into(),
            record_id: id.into(),
            observed_at_ns: Some(42),
            session: Some("7".into()),
            peer: None,
            local: None,
            action,
            prefix: Prefix::ipv4([203, 0, 113, 0], 24).unwrap(),
            attributes: PathAttributes {
                med: Some(med),
                ..PathAttributes::default()
            },
        },
        &Limits::default(),
    )
    .unwrap()
}
fn observe(v: &Json, scope: Option<ImportScope>) -> Observation {
    Observation::from_normalized(v, scope, &Limits::default()).unwrap()
}
fn scoped(id: &str, generation: u64, direction: u8, action: RouteAction, med: u32) -> Observation {
    observe(
        &input(id, action, med),
        Some(ImportScope {
            generation,
            direction,
        }),
    )
}
fn scoped_unique(id: &str, address: [u8; 4]) -> Observation {
    let normalized = bgp::normalize_imported(
        ImportedRouteObservation {
            source_id: "source-a".into(),
            record_id: id.into(),
            observed_at_ns: Some(42),
            session: Some("7".into()),
            peer: None,
            local: None,
            action: RouteAction::Announce,
            prefix: Prefix::ipv4(address, 32).unwrap(),
            attributes: PathAttributes::default(),
        },
        &Limits::default(),
    )
    .unwrap();
    observe(
        &normalized,
        Some(ImportScope {
            generation: 0,
            direction: 0,
        }),
    )
}
fn fresh() -> CandidateState {
    CandidateState::new(Limits::default()).unwrap()
}
fn source(kind: SourceKind, id: &str, generation: u64) -> Source {
    Source {
        kind,
        source_id: "source-a".into(),
        record_id: id.into(),
        session: Some("7".into()),
        generation: Some(generation),
        direction: None,
        observed_at_ns: None,
        peer: None,
        local: None,
    }
}

#[test]
fn independent_wire_vector_has_exact_fields_and_provenance() {
    let mut decoder = SessionState::default();
    let normalized = captured("announce", "1", 1, Some(0), &mut decoder);
    let o = observe(&normalized, None);
    assert_eq!(o.routes().len(), 1);
    assert_eq!(o.routes()[0].prefix().address, "203.0.113.0");
    assert_eq!(o.routes()[0].field_range(), 41..45);
    assert_eq!(o.source().observed_at_ns, Some(-42));
    let evidence = get(o.normalized(), "evidence").clone();
    assert_eq!(
        get(&evidence, "reconstructed_sha256"),
        &sha256::hex(&sha256::digest(&vector("announce"))).into()
    );
    let Json::Array(spans) = get(&evidence, "spans") else {
        panic!()
    };
    assert_eq!(get(&spans[0], "packet_start"), &"54".into());
    let mut state = fresh();
    assert_eq!(
        state.apply(o).unwrap().effects[0].kind,
        EffectKind::Announced
    );
    assert_eq!(state.routes()[0].alternatives[0].witnesses[0].route, 0);
    assert_eq!(
        get(state.observations()[0].normalized(), "evidence"),
        &evidence
    );
}

#[test]
fn two_directions_and_exact_prefixes_are_isolated() {
    let mut state = fresh();
    state
        .apply(scoped("a", 0, 0, RouteAction::Announce, 10))
        .unwrap();
    state
        .apply(scoped("b", 0, 1, RouteAction::Announce, 20))
        .unwrap();
    let mut other = input("c", RouteAction::Announce, 30);
    let Json::Array(mut routes) = get(&other, "routes").clone() else {
        panic!()
    };
    set(
        &mut routes[0],
        "prefix",
        Json::object([
            ("afi", 1u8.into()),
            ("safi", 1u8.into()),
            ("length", 24u8.into()),
            ("address", "198.51.100.0".into()),
        ]),
    );
    set(&mut other, "routes", Json::Array(routes));
    state
        .apply(observe(
            &other,
            Some(ImportScope {
                generation: 0,
                direction: 0,
            }),
        ))
        .unwrap();
    let outcome = state
        .apply(scoped("w", 0, 0, RouteAction::Withdraw, 0))
        .unwrap();
    assert_eq!(outcome.effects[0].kind, EffectKind::Withdrawn);
    assert_eq!(state.routes().len(), 2);
    assert!(state
        .routes()
        .iter()
        .any(|r| r.direction == 1 && r.prefix.address == "203.0.113.0"));
    assert!(state
        .routes()
        .iter()
        .any(|r| r.direction == 0 && r.prefix.address == "198.51.100.0"));
}

#[test]
fn add_path_identifiers_are_part_of_the_candidate_and_withdrawal_key() {
    let scope = Some(ImportScope {
        generation: 0,
        direction: 0,
    });
    let mut state = fresh();
    for (record, path_id) in [("path-1", 1u32), ("path-2", 2u32)] {
        let mut value = input(record, RouteAction::Announce, path_id);
        let Json::Array(mut routes) = get(&value, "routes").clone() else {
            panic!()
        };
        set(&mut routes[0], "path_id", path_id.into());
        set(&mut value, "routes", Json::Array(routes));
        state.apply(observe(&value, scope)).unwrap();
    }
    assert_eq!(state.routes().len(), 2);
    assert!(state
        .routes()
        .iter()
        .any(|route| route.path_id == RoutePathId::Present(1)));
    assert!(state
        .routes()
        .iter()
        .any(|route| route.path_id == RoutePathId::Present(2)));

    let mut withdrawal = input("withdraw-path-1", RouteAction::Withdraw, 0);
    let Json::Array(mut routes) = get(&withdrawal, "routes").clone() else {
        panic!()
    };
    set(&mut routes[0], "path_id", 1u32.into());
    set(&mut withdrawal, "routes", Json::Array(routes));
    let outcome = state.apply(observe(&withdrawal, scope)).unwrap();
    assert_eq!(outcome.effects[0].kind, EffectKind::Withdrawn);
    assert_eq!(outcome.effects[0].path_id, RoutePathId::Present(1));
    assert_eq!(state.routes().len(), 1);
    assert_eq!(state.routes()[0].path_id, RoutePathId::Present(2));
}

#[test]
fn sources_sessions_and_source_kinds_never_merge() {
    let mut state = fresh();
    state
        .apply(scoped("a", 0, 0, RouteAction::Announce, 10))
        .unwrap();
    let mut second_source = input("a", RouteAction::Announce, 10);
    set(&mut second_source, "source_id", "source-b".into());
    state
        .apply(observe(
            &second_source,
            Some(ImportScope {
                generation: 0,
                direction: 0,
            }),
        ))
        .unwrap();
    let mut second_session = input("a", RouteAction::Announce, 10);
    set(&mut second_session, "session", "8".into());
    state
        .apply(observe(
            &second_session,
            Some(ImportScope {
                generation: 0,
                direction: 0,
            }),
        ))
        .unwrap();
    let captured = captured("announce", "a", 1, Some(0), &mut SessionState::default());
    state.apply(observe(&captured, None)).unwrap();
    assert_eq!(state.routes().len(), 4);
    state
        .apply(scoped("w", 0, 0, RouteAction::Withdraw, 0))
        .unwrap();
    assert_eq!(state.routes().len(), 3);
    assert!(state
        .routes()
        .iter()
        .any(|r| r.source_kind == SourceKind::Captured));
}

#[test]
fn generation_advance_clears_both_directions_and_late_withdrawal_is_inert() {
    let mut state = fresh();
    state
        .apply(scoped("a", 10, 0, RouteAction::Announce, 1))
        .unwrap();
    state
        .apply(scoped("b", 10, 1, RouteAction::Announce, 1))
        .unwrap();
    state
        .apply(scoped("c", 11, 0, RouteAction::Announce, 2))
        .unwrap();
    assert_eq!(state.routes().len(), 1);
    assert_eq!(state.routes()[0].generation, 11);
    let outcome = state
        .apply(scoped("old", 10, 0, RouteAction::Withdraw, 0))
        .unwrap();
    assert_eq!(outcome.status, ApplyStatus::LateGeneration);
    assert_eq!(state.routes().len(), 1);
    assert_eq!(state.observations().len(), 4);
}

#[test]
fn captured_notification_closes_only_its_session_and_generation() {
    let mut state = fresh();
    let mut decoder = SessionState::default();
    state
        .apply(observe(
            &captured("announce", "a", 1, Some(0), &mut decoder),
            None,
        ))
        .unwrap();
    let old = captured("announce", "old", 2, Some(1), &mut decoder);
    state.apply(observe(&old, None)).unwrap();
    state
        .apply(scoped("imported", 0, 0, RouteAction::Announce, 1))
        .unwrap();
    let notification = captured("notification", "n", 3, None, &mut decoder);
    assert_eq!(
        state.apply(observe(&notification, None)).unwrap().status,
        ApplyStatus::Notification
    );
    assert_eq!(state.routes().len(), 1); // independent imported scope survives
    let mut late = old.clone();
    set(&mut late, "record_id", "late".into());
    assert_eq!(
        state.apply(observe(&late, None)).unwrap().status,
        ApplyStatus::ClosedGeneration
    );
    state
        .apply(observe(
            &captured("announce", "new", 4, Some(0), &mut decoder),
            None,
        ))
        .unwrap();
    assert!(state
        .routes()
        .iter()
        .any(|r| r.source_kind == SourceKind::Captured && r.generation == 1));
    // A replayed old notification must not close the newer generation.
    assert_eq!(
        state.apply(observe(&notification, None)).unwrap().status,
        ApplyStatus::IdenticalReplay
    );
    assert_eq!(state.routes().len(), 2);
}

#[test]
fn explicit_reset_is_source_bound_replay_safe_and_never_wraps() {
    let mut state = fresh();
    let a = scoped("a", u64::MAX - 1, 0, RouteAction::Announce, 0);
    state.apply(a.clone()).unwrap();
    let reset = Observation::reset(
        source(SourceKind::Imported, "r", u64::MAX),
        "input boundary",
        Json::Null,
        &Limits::default(),
    )
    .unwrap();
    assert_eq!(
        state.apply(reset.clone()).unwrap().status,
        ApplyStatus::Reset
    );
    assert!(state.routes().is_empty());
    assert_eq!(state.apply(a).unwrap().status, ApplyStatus::IdenticalReplay);
    state
        .apply(scoped("next", u64::MAX, 0, RouteAction::Announce, 2))
        .unwrap();
    assert_eq!(
        state.apply(reset).unwrap().status,
        ApplyStatus::IdenticalReplay
    );
    let nonadvancing = Observation::reset(
        source(SourceKind::Imported, "r2", u64::MAX),
        "another boundary",
        Json::Null,
        &Limits::default(),
    )
    .unwrap();
    assert_eq!(
        state.apply(nonadvancing).unwrap().status,
        ApplyStatus::NonAdvancingReset
    );
    assert_eq!(
        state
            .apply(scoped("wrapped", 0, 0, RouteAction::Withdraw, 0))
            .unwrap()
            .status,
        ApplyStatus::LateGeneration
    );
    assert_eq!(state.routes().len(), 1);
}

#[test]
fn withdrawal_of_absent_candidate_is_retained_explicitly() {
    let mut state = fresh();
    let o = state
        .apply(scoped("w", 0, 0, RouteAction::Withdraw, 0))
        .unwrap();
    assert_eq!(o.effects[0].kind, EffectKind::AbsentWithdrawal);
    assert!(state.routes().is_empty());
    assert_eq!(state.observations().len(), 1);
}

#[test]
fn identical_replay_is_byte_for_byte_idempotent() {
    let mut state = fresh();
    let o = scoped("a", 0, 0, RouteAction::Announce, 42);
    state.apply(o.clone()).unwrap();
    let before = state.encode().to_owned();
    let retained = state.retained_bytes();
    for _ in 0..5 {
        assert_eq!(
            state.apply(o.clone()).unwrap().status,
            ApplyStatus::IdenticalReplay
        );
        assert_eq!(state.encode(), before);
        assert_eq!(state.retained_bytes(), retained);
    }
}

#[test]
fn repeated_announcement_retains_each_record_not_a_vote() {
    let mut state = fresh();
    for id in ["a", "b", "c"] {
        state
            .apply(scoped(id, 0, 0, RouteAction::Announce, 42))
            .unwrap();
    }
    assert_eq!(state.routes()[0].alternatives.len(), 1);
    assert_eq!(state.routes()[0].alternatives[0].witnesses.len(), 3);
    let conflict = state
        .apply(scoped("d", 0, 0, RouteAction::Announce, 99))
        .unwrap();
    assert_eq!(
        conflict.effects[0].kind,
        EffectKind::ConflictingAnnouncement
    );
    assert!(state.routes()[0].conflicting());
    assert_eq!(state.routes()[0].alternatives.len(), 2);
    // Three agreeing records never override the one different observation.
    assert_eq!(state.routes()[0].alternatives[0].witnesses.len(), 3);
}

#[test]
fn conflicting_record_identity_quarantines_old_and_new_effects() {
    let mut state = fresh();
    state
        .apply(scoped("base", 0, 0, RouteAction::Announce, 42))
        .unwrap();
    state
        .apply(scoped("same", 0, 0, RouteAction::Withdraw, 0))
        .unwrap();
    assert!(state.routes().is_empty());
    let outcome = state
        .apply(scoped("same", 0, 0, RouteAction::Announce, 3))
        .unwrap();
    assert_eq!(outcome.status, ApplyStatus::IdentityConflict);
    assert!(state.sessions()[0].identity_conflict);
    assert!(state.routes().is_empty()); // no formerly selected winner survives
    assert_eq!(state.outcomes()[1].status, ApplyStatus::IdentityConflict);
    assert_eq!(state.outcomes()[0].status, ApplyStatus::IdentityConflict);
    assert_eq!(state.observations().len(), 3); // all alternatives remain inspectable
    let other = scoped("new-generation", 1, 0, RouteAction::Announce, 4);
    assert_eq!(
        state.apply(other).unwrap().status,
        ApplyStatus::IdentityConflict
    );
}

#[test]
fn captured_content_identity_does_not_collapse_distinct_packet_occurrences() {
    let mut state = fresh();
    let mut decoder = SessionState::default();
    state
        .apply(observe(
            &captured("announce", "same-content-hash", 1, Some(0), &mut decoder),
            None,
        ))
        .unwrap();
    let outcome = state
        .apply(observe(
            &captured("announce", "same-content-hash", 2, Some(0), &mut decoder),
            None,
        ))
        .unwrap();
    assert_eq!(outcome.effects[0].kind, EffectKind::RepeatedAnnouncement);
    assert_eq!(state.observations().len(), 2);
    assert_eq!(state.routes()[0].alternatives[0].witnesses.len(), 2);
    assert!(!state.sessions()[0].identity_conflict);
}

#[test]
fn discarded_duplicate_attributes_do_not_create_ambiguity_and_unknown_tokens_survive() {
    let mut state = fresh();
    let v = captured(
        "duplicate_origin",
        "dup",
        1,
        Some(0),
        &mut SessionState::default(),
    );
    let o = observe(&v, None);
    assert!(!o.routes()[0].ambiguous_attributes());
    let Json::Array(occurrences) = o.routes()[0].attribute_identity() else {
        panic!("captured occurrence identities must remain an array");
    };
    assert_eq!(occurrences.len(), 4);
    assert_eq!(get(&occurrences[0], "type"), &Json::from(1u8));
    assert_eq!(get(&occurrences[1], "type"), &Json::from(1u8));
    assert_eq!(
        get(&occurrences[1], "disposition"),
        &Json::from("discard_later_occurrence")
    );
    assert_eq!(
        state.apply(o).unwrap().effects[0].kind,
        EffectKind::Announced
    );
    assert!(!state.routes()[0].conflicting());
    assert!(state
        .encode()
        .contains("attribute_identity_tokens_are_opaque_not_verified_digests"));
    // An extension unknown to the consumer survives both the journal and path key.
    let mut first = input("unknown-a", RouteAction::Announce, 1);
    let Json::Array(mut r) = get(&first, "routes").clone() else {
        panic!()
    };
    let mut attributes = get(&r[0], "attributes").clone();
    set(
        &mut attributes,
        "unreviewed_attribute",
        Json::Array(vec![123u8.into(), 7u8.into()]),
    );
    set(&mut r[0], "attributes", attributes);
    set(&mut first, "routes", Json::Array(r));
    let mut second = first.clone();
    set(&mut second, "record_id", "unknown-b".into());
    let Json::Array(mut r) = get(&second, "routes").clone() else {
        panic!()
    };
    let mut attributes = get(&r[0], "attributes").clone();
    set(&mut attributes, "unreviewed_attribute", Json::Null);
    set(&mut r[0], "attributes", attributes);
    set(&mut second, "routes", Json::Array(r));
    let mut imported = fresh();
    let scope = Some(ImportScope {
        generation: 0,
        direction: 0,
    });
    imported.apply(observe(&first, scope)).unwrap();
    imported.apply(observe(&second, scope)).unwrap();
    assert!(imported.routes()[0].conflicting());
    assert!(imported.encode().contains("unreviewed_attribute"));
}

#[test]
fn mixed_actions_in_one_record_do_not_impose_a_winner() {
    let mut v = input("mixed", RouteAction::Announce, 0);
    let Json::Array(mut routes) = get(&v, "routes").clone() else {
        panic!()
    };
    let mut withdrawal = routes[0].clone();
    set(&mut withdrawal, "action", "withdraw".into());
    routes.push(withdrawal);
    set(&mut v, "routes", Json::Array(routes));
    let mut state = fresh();
    let o = state
        .apply(observe(
            &v,
            Some(ImportScope {
                generation: 0,
                direction: 0,
            }),
        ))
        .unwrap();
    assert_eq!(o.effects[0].kind, EffectKind::MixedActions);
    assert_eq!(state.routes()[0].alternatives.len(), 2);
    assert!(state.routes()[0].conflicting());
    state
        .apply(scoped("later-withdrawal", 0, 0, RouteAction::Withdraw, 0))
        .unwrap();
    assert!(state.routes().is_empty());
    assert_eq!(state.observations().len(), 2);
}

#[test]
fn missing_scope_is_unresolved_not_zero_direction_or_generation() {
    let mut state = fresh();
    let imported = observe(&input("a", RouteAction::Announce, 0), None);
    assert_eq!(imported.source().generation, None);
    assert_eq!(
        state.apply(imported).unwrap().status,
        ApplyStatus::MissingScope
    );
    let captured = captured("announce", "b", 1, None, &mut SessionState::default());
    assert_eq!(
        state.apply(observe(&captured, None)).unwrap().status,
        ApplyStatus::MissingScope
    );
    let mut missing = input("c", RouteAction::Announce, 0);
    set(&mut missing, "session", Json::Null);
    assert_eq!(
        state
            .apply(observe(
                &missing,
                Some(ImportScope {
                    generation: 0,
                    direction: 0
                })
            ))
            .unwrap()
            .status,
        ApplyStatus::MissingScope
    );
    assert!(state.routes().is_empty());
}

#[test]
fn metadata_and_timestamps_never_select_best_path_or_sort_observations() {
    let mut state = fresh();
    let mut newer = input("a", RouteAction::Announce, 100);
    set(&mut newer, "observed_at_ns", "9223372036854775807".into());
    let mut older = input("b", RouteAction::Announce, 1);
    set(&mut older, "observed_at_ns", "-9223372036854775808".into());
    let scope = Some(ImportScope {
        generation: 0,
        direction: 0,
    });
    state.apply(observe(&newer, scope)).unwrap();
    state.apply(observe(&older, scope)).unwrap();
    assert_eq!(state.routes()[0].alternatives.len(), 2);
    assert_eq!(state.observations()[0].source().record_id, "a");
    assert!(state.encode().contains("\"best_path_selected\":false"));
    assert!(state.encode().contains("\"rib_established\":false"));
    assert!(state
        .encode()
        .contains("\"source_authority_established\":false"));
}

#[test]
fn deterministic_json_and_object_key_order_independent_replay() {
    let mut a = fresh();
    let mut b = fresh();
    for id in ["a", "b", "w"] {
        let action = if id == "w" {
            RouteAction::Withdraw
        } else {
            RouteAction::Announce
        };
        a.apply(scoped(id, 0, 0, action, 3)).unwrap();
        b.apply(scoped(id, 0, 0, action, 3)).unwrap();
    }
    assert_eq!(a.encode(), b.encode());
    let mut reordered = input("w", RouteAction::Withdraw, 3);
    let Json::Object(fields) = &mut reordered else {
        panic!()
    };
    fields.reverse();
    let before = a.encode().to_owned();
    assert_eq!(
        a.apply(observe(
            &reordered,
            Some(ImportScope {
                generation: 0,
                direction: 0
            })
        ))
        .unwrap()
        .status,
        ApplyStatus::IdenticalReplay
    );
    assert_eq!(a.encode(), before);
}

#[test]
fn imported_and_captured_share_state_shape_without_sharing_authority() {
    let mut a = fresh();
    let mut b = fresh();
    a.apply(scoped("a", 0, 0, RouteAction::Announce, 0))
        .unwrap();
    b.apply(observe(
        &captured("announce", "b", 1, Some(0), &mut SessionState::default()),
        None,
    ))
    .unwrap();
    assert_eq!(a.routes()[0].prefix, b.routes()[0].prefix);
    assert_eq!(
        a.outcomes()[0].effects[0].kind,
        b.outcomes()[0].effects[0].kind
    );
    for s in [&a, &b] {
        assert!(s.encode().contains("pcap-evidence.bgp.candidate-state.v1"));
        assert!(s.encode().contains("\"causality_established\":false"));
    }
    assert_eq!(
        get(a.observations()[0].normalized(), "evidence"),
        &Json::Null
    );
    assert_ne!(
        get(b.observations()[0].normalized(), "evidence"),
        &Json::Null
    );
}

#[test]
fn ipv6_default_routes_and_safi_are_exact_keys() {
    let mut state = fresh();
    for (id, afi, safi, length, addr) in [
        ("a", 1u16, 1u8, 0u8, "0.0.0.0"),
        ("b", 1, 2, 0, "0.0.0.0"),
        ("c", 2, 1, 0, "::"),
        ("d", 2, 1, 64, "2001:db8::"),
    ] {
        let mut v = input(id, RouteAction::Announce, 0);
        let Json::Array(mut r) = get(&v, "routes").clone() else {
            panic!()
        };
        set(
            &mut r[0],
            "prefix",
            Json::object([
                ("afi", afi.into()),
                ("safi", safi.into()),
                ("length", length.into()),
                ("address", addr.into()),
            ]),
        );
        set(&mut v, "routes", Json::Array(r));
        state
            .apply(observe(
                &v,
                Some(ImportScope {
                    generation: 0,
                    direction: 0,
                }),
            ))
            .unwrap();
    }
    assert_eq!(state.routes().len(), 4);
}

#[test]
fn unsupported_prefix_is_retained_but_not_applied() {
    let mut v = input("unknown", RouteAction::Announce, 0);
    let Json::Array(mut r) = get(&v, "routes").clone() else {
        panic!()
    };
    let mut p = get(&r[0], "prefix").clone();
    set(&mut p, "safi", 128u8.into());
    set(&mut r[0], "prefix", p);
    set(&mut v, "routes", Json::Array(r));
    let mut state = fresh();
    assert_eq!(
        state
            .apply(observe(
                &v,
                Some(ImportScope {
                    generation: 0,
                    direction: 0
                })
            ))
            .unwrap()
            .effects[0]
            .kind,
        EffectKind::UnsupportedPrefix
    );
    assert!(state.routes().is_empty());
    assert_eq!(state.observations().len(), 1);
}

#[test]
fn malformed_normalized_fields_are_rejected_without_mutation() {
    let good = input("a", RouteAction::Announce, 1);
    for (field, value) in [
        ("schema", "unknown".into()),
        ("source_id", "".into()),
        ("session", "".into()),
        ("endpoint_state_established", true.into()),
        ("causality_established", true.into()),
        ("direction", 2u8.into()),
        ("message_type", 255u8.into()),
        ("observed_at_ns", "1.5".into()),
        ("routes", Json::Null),
    ] {
        let mut v = good.clone();
        set(&mut v, field, value);
        assert!(
            Observation::from_normalized(&v, None, &Limits::default()).is_err(),
            "{field}"
        );
    }
    let mut duplicate_key = good.clone();
    let Json::Object(fields) = &mut duplicate_key else {
        panic!()
    };
    fields.push(("source_id", "other".into()));
    assert!(Observation::from_normalized(&duplicate_key, None, &Limits::default()).is_err());
    let mut state = fresh();
    let before = state.encode().to_owned();
    assert_eq!(state.encode(), before);
    // Use the otherwise mutable public Prefix as an adversarial imported input.
    let mut bad_prefix = good;
    let Json::Array(mut r) = get(&bad_prefix, "routes").clone() else {
        panic!()
    };
    let mut p = get(&r[0], "prefix").clone();
    set(&mut p, "address", "203.0.113.1".into());
    set(&mut r[0], "prefix", p);
    set(&mut bad_prefix, "routes", Json::Array(r));
    assert!(Observation::from_normalized(&bad_prefix, None, &Limits::default()).is_err());
    state
        .apply(scoped("good", 0, 0, RouteAction::Announce, 0))
        .unwrap();
}

#[test]
fn malformed_captured_spans_ranges_and_digest_shape_fail_closed() {
    let original = captured("announce", "a", 1, Some(0), &mut SessionState::default());
    for field in ["byte_length", "spans", "packets", "reconstructed_sha256"] {
        let mut v = original.clone();
        let mut e = get(&v, "evidence").clone();
        set(&mut e, field, Json::Null);
        set(&mut v, "evidence", e);
        assert!(Observation::from_normalized(&v, None, &Limits::default()).is_err());
    }
    let mut v = original.clone();
    let Json::Array(mut r) = get(&v, "routes").clone() else {
        panic!()
    };
    set(&mut r[0], "field_end", 46usize.into());
    set(&mut v, "routes", Json::Array(r));
    assert!(Observation::from_normalized(&v, None, &Limits::default()).is_err());
    assert!(Observation::from_normalized(
        &original,
        Some(ImportScope {
            generation: 0,
            direction: 0
        }),
        &Limits::default()
    )
    .is_err());
}

#[test]
fn retention_element_session_output_and_work_limits_are_atomic() {
    let observation = scoped("a", 0, 0, RouteAction::Announce, 0);
    let mut state = CandidateState::new(Limits {
        elements: 1,
        ..Limits::default()
    })
    .unwrap();
    state.apply(observation.clone()).unwrap();
    let before = state.encode().to_owned();
    assert_eq!(
        state
            .apply(scoped("b", 0, 0, RouteAction::Withdraw, 0))
            .unwrap_err()
            .code,
        ErrorCode::LimitExceeded
    );
    assert_eq!(state.encode(), before);
    assert_eq!(
        state.apply(observation.clone()).unwrap().status,
        ApplyStatus::IdenticalReplay
    );
    let empty_size = fresh().encode().len();
    for limits in [
        Limits {
            output_bytes: empty_size,
            ..Limits::default()
        },
        Limits {
            retained_bytes: empty_size,
            ..Limits::default()
        },
        Limits {
            work: 1,
            ..Limits::default()
        },
        Limits {
            input_bytes: 1,
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
    ] {
        let mut limited = CandidateState::new(limits).unwrap();
        let before = limited.encode().to_owned();
        assert_eq!(
            limited.apply(observation.clone()).unwrap_err().code,
            ErrorCode::LimitExceeded
        );
        assert_eq!(limited.encode(), before);
    }
    let mut limited = CandidateState::new(Limits {
        active: 1,
        ..Limits::default()
    })
    .unwrap();
    limited.apply(observation).unwrap();
    let before = limited.encode().to_owned();
    let mut other = input("b", RouteAction::Announce, 1);
    set(&mut other, "session", "other-session".into());
    assert_eq!(
        limited
            .apply(observe(
                &other,
                Some(ImportScope {
                    generation: 0,
                    direction: 0
                })
            ))
            .unwrap_err()
            .code,
        ErrorCode::LimitExceeded
    );
    assert_eq!(limited.encode(), before);
}

#[test]
fn context_free_batch_matches_final_sequential_state_and_preserves_replay_conflicts() {
    let first = scoped("first", 0, 0, RouteAction::Announce, 10);
    let conflict_a = scoped("conflict", 0, 0, RouteAction::Announce, 20);
    let conflict_b = scoped("conflict", 0, 0, RouteAction::Announce, 21);
    let batch_input = vec![
        first.clone(),
        first.clone(),
        conflict_a,
        conflict_b,
        scoped("withdraw", 0, 0, RouteAction::Withdraw, 0),
    ];

    let mut sequential = fresh();
    for observation in batch_input.iter().cloned() {
        sequential.apply(observation).unwrap();
    }
    let mut batched = fresh();
    let receipts = batched.apply_batch(batch_input).unwrap();

    assert_eq!(batched.encode(), sequential.encode());
    assert_eq!(batched.outcomes(), sequential.outcomes());
    assert_eq!(receipts.len(), 5);
    assert_eq!(receipts[1].status, ApplyStatus::IdenticalReplay);
    assert_eq!(receipts[1].observation, 0);
    assert_eq!(receipts[2].status, ApplyStatus::IdentityConflict);
    assert_eq!(receipts[3].status, ApplyStatus::IdentityConflict);
}

#[test]
fn empty_batch_resets_work_diagnostic_without_changing_snapshot() {
    let mut state = fresh();
    state
        .apply(scoped_unique("empty-batch", [10, 0, 0, 1]))
        .unwrap();
    assert!(state.last_work() > 0);
    let before = state.encode().to_owned();

    assert!(state
        .apply_batch(Vec::<Observation>::new())
        .unwrap()
        .is_empty());
    assert_eq!(state.last_work(), 0);
    assert_eq!(state.encode(), before);
}

#[test]
fn batch_logical_work_is_near_linear_against_sequential_full_reduction() {
    fn records(count: usize) -> Vec<Observation> {
        (0..count)
            .map(|index| {
                scoped_unique(
                    &format!("scale-{index}"),
                    [10, (index >> 16) as u8, (index >> 8) as u8, index as u8],
                )
            })
            .collect()
    }

    let input = records(256);
    let mut sequential = fresh();
    let mut sequential_work = 0usize;
    for observation in input.iter().cloned() {
        sequential.apply(observation).unwrap();
        sequential_work = sequential_work.checked_add(sequential.last_work()).unwrap();
    }

    let mut batched = fresh();
    let receipts = batched.apply_batch(input).unwrap();
    assert_eq!(receipts.len(), 256);
    assert_eq!(batched.encode(), sequential.encode());
    assert_eq!(batched.outcomes(), sequential.outcomes());
    assert!(
        sequential_work > batched.last_work().saturating_mul(3),
        "sequential work {sequential_work} should materially exceed batch work {}",
        batched.last_work()
    );
}

#[test]
fn nested_unknown_values_and_aggregate_spans_have_explicit_budgets() {
    let mut deep = input("a", RouteAction::Announce, 1);
    let mut nested = Json::Null;
    for _ in 0..=Limits::default().depth {
        nested = Json::Array(vec![nested]);
    }
    set(&mut deep, "unknown_extension", nested);
    assert_eq!(
        Observation::from_normalized(&deep, None, &Limits::default())
            .unwrap_err()
            .code,
        ErrorCode::LimitExceeded
    );
    let mut s = CandidateState::new(Limits {
        spans: 2,
        ..Limits::default()
    })
    .unwrap();
    let mut decoder = SessionState::default();
    s.apply(observe(
        &captured("announce", "a", 1, Some(0), &mut decoder),
        None,
    ))
    .unwrap();
    let before = s.encode().to_owned();
    assert_eq!(
        s.apply(observe(
            &captured("announce", "b", 2, Some(0), &mut decoder),
            None
        ))
        .unwrap_err()
        .code,
        ErrorCode::LimitExceeded
    );
    assert_eq!(s.encode(), before);
}

#[test]
fn valid_prefix_truncations_of_normalized_envelopes_never_become_state() {
    let original = input("a", RouteAction::Announce, 1);
    let Json::Object(fields) = original else {
        panic!()
    };
    for n in 0..fields.len() {
        let short = Json::Object(fields[..n].to_vec());
        assert!(Observation::from_normalized(&short, None, &Limits::default()).is_err());
    }
}

#[test]
fn packet_split_preserves_prefix_and_attribute_span_references() {
    let bytes = vector("announce");
    let mut joined = EvidenceBytes::from_packet(
        &bytes[..42],
        PacketId {
            capture: sha256::digest(b"split-source"),
            frame: 1,
            record_offset: 24,
        },
        54,
    );
    joined
        .append(
            &EvidenceBytes::from_packet(
                &bytes[42..],
                PacketId {
                    capture: sha256::digest(b"split-source"),
                    frame: 2,
                    record_offset: 150,
                },
                70,
            ),
            4096,
        )
        .unwrap();
    let v = bgp::decode_pcap(
        &joined,
        metadata("split", Some(0)),
        &mut SessionState::default(),
        &Limits::default(),
    )
    .unwrap();
    let o = observe(&v, None);
    assert_eq!(o.routes()[0].field_range(), 41..45);
    let Json::Array(spans) = get(get(o.normalized(), "evidence"), "spans") else {
        panic!()
    };
    assert_eq!(spans.len(), 2);
    assert_eq!(get(&spans[0], "end"), &"42".into());
    assert_eq!(get(&spans[1], "start"), &"42".into());
    assert_eq!(get(&spans[1], "packet_start"), &"70".into());
    let mut state = fresh();
    state.apply(o.clone()).unwrap();
    assert_eq!(state.observations()[0].normalized(), o.normalized());
    let prefix = joined.slice(41..45).unwrap();
    assert_eq!(prefix.data(), &[24, 203, 0, 113]);
    assert_eq!(prefix.spans()[0].packet_start, 95);
    assert_eq!(prefix.spans()[1].packet_start, 70);
}

#[test]
fn late_notification_and_new_generation_withdrawal_do_not_clear_current_routes() {
    let mut decoder = SessionState::default();
    let old_notification = captured("notification", "late", 1, Some(0), &mut decoder);
    let new = captured("announce", "new", 2, Some(0), &mut decoder);
    let mut state = fresh();
    state.apply(observe(&new, None)).unwrap();
    assert_eq!(
        state
            .apply(observe(&old_notification, None))
            .unwrap()
            .status,
        ApplyStatus::LateGeneration
    );
    assert_eq!(state.routes().len(), 1);
    let withdrawal = captured("withdraw", "w", 3, Some(1), &mut decoder);
    assert_eq!(
        state.apply(observe(&withdrawal, None)).unwrap().effects[0].kind,
        EffectKind::AbsentWithdrawal
    );
    assert_eq!(state.routes().len(), 1);
}

#[test]
fn ordinary_attribute_conflict_ends_only_on_explicit_withdrawal_or_generation_change() {
    let mut state = fresh();
    state
        .apply(scoped("a", 0, 0, RouteAction::Announce, 10))
        .unwrap();
    state
        .apply(scoped("b", 0, 0, RouteAction::Announce, 20))
        .unwrap();
    assert!(state.routes()[0].conflicting());
    state
        .apply(scoped("c", 1, 0, RouteAction::Announce, 20))
        .unwrap();
    assert_eq!(state.routes()[0].alternatives.len(), 1);
    assert!(!state.routes()[0].conflicting());
    assert_eq!(state.observations().len(), 3);
}

#[test]
fn multiple_routes_charge_the_aggregate_budget_and_duplicate_indices_survive() {
    let mut v = input("a", RouteAction::Announce, 3);
    let Json::Array(mut routes) = get(&v, "routes").clone() else {
        panic!()
    };
    routes.push(routes[0].clone());
    set(&mut v, "routes", Json::Array(routes));
    let o = observe(
        &v,
        Some(ImportScope {
            generation: 0,
            direction: 0,
        }),
    );
    let mut state = fresh();
    let outcome = state.apply(o.clone()).unwrap();
    assert_eq!(outcome.effects[0].kind, EffectKind::RepeatedAnnouncement);
    assert_eq!(outcome.effects[0].routes, vec![0, 1]);
    assert_eq!(state.routes()[0].alternatives[0].witnesses.len(), 2);
    let mut limited = CandidateState::new(Limits {
        elements: 1,
        ..Limits::default()
    })
    .unwrap();
    let before = limited.encode().to_owned();
    assert_eq!(limited.apply(o).unwrap_err().code, ErrorCode::LimitExceeded);
    assert_eq!(limited.encode(), before);
}

#[test]
fn unknown_attribute_range_fields_participate_in_identity() {
    let mut first = captured("announce", "a", 1, Some(0), &mut SessionState::default());
    let mut second = captured("announce", "b", 2, Some(0), &mut SessionState::default());
    for (value, token) in [(&mut first, "one"), (&mut second, "two")] {
        let Json::Array(mut routes) = get(value, "routes").clone() else {
            panic!()
        };
        let Json::Array(mut ranges) = get(&routes[0], "attribute_ranges").clone() else {
            panic!()
        };
        set(&mut ranges[0], "future_identity", token.into());
        set(&mut routes[0], "attribute_ranges", Json::Array(ranges));
        set(value, "routes", Json::Array(routes));
    }
    let mut state = fresh();
    state.apply(observe(&first, None)).unwrap();
    state.apply(observe(&second, None)).unwrap();
    assert!(state.routes()[0].conflicting());
    assert!(state.encode().contains("future_identity"));
}

#[test]
fn caller_reset_requires_explicit_session_generation_reason_and_boundary_scope() {
    let l = Limits::default();
    let valid = source(SourceKind::Imported, "r", 1);
    let evidence = Json::object([("packets", Json::Array(vec![Json::Null, Json::Null]))]);
    assert_eq!(
        Observation::reset(
            valid.clone(),
            "boundary",
            evidence,
            &Limits {
                spans: 1,
                ..Limits::default()
            }
        )
        .unwrap_err()
        .code,
        ErrorCode::LimitExceeded
    );
    for mode in 0..4 {
        let mut s = valid.clone();
        let reason = if mode == 3 { "" } else { "boundary" };
        match mode {
            0 => s.session = None,
            1 => s.generation = None,
            2 => s.direction = Some(0),
            _ => {}
        }
        assert!(Observation::reset(s, reason, Json::Null, &l).is_err());
    }
}

#[test]
fn keepalive_is_metadata_only_and_never_a_route_state_assertion() {
    let v = captured("keepalive", "k", 1, Some(0), &mut SessionState::default());
    let mut state = fresh();
    let outcome = state.apply(observe(&v, None)).unwrap();
    assert_eq!(outcome.status, ApplyStatus::MetadataOnly);
    assert!(outcome.effects.is_empty());
    assert!(state.routes().is_empty());
}
