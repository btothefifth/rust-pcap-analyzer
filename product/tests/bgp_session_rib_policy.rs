//! Hand-built event traces; these tests do not use the reducer as an oracle.
use pcap_evidence::json::Json;
use pcap_evidence_product::deep::{
    bgp::{self, ImportedRouteObservation, PathAttributes, Prefix, RouteAction},
    bgp_import::{ImportContext, ObservationClock, SourceBatch, SourceRange},
    bgp_policy::{
        self, AgeRule, BestPathInputs, MedEvidence, MedRule, PolicyCandidate, PolicyConfig,
        StepResult,
    },
    bgp_rib::{
        self, AdjRibIn, PathId, RibAction, RibEvent, RibEventKind, RibScope, RouteStatus,
        VersionDisposition,
    },
    bgp_session::{
        self, Capability, CapabilityContext, Event, EventKind, Family, OpenAdvertisement,
        PartitionKind, ProtocolResetKind, SessionKey, SessionObserver, SourcePartition, StaleKind,
    },
    bgp_state::{CandidateState, ImportScope, Observation, PrefixIdentity},
    Limits,
};
use std::net::{IpAddr, Ipv4Addr};

fn partition() -> SourcePartition {
    SourcePartition {
        kind: PartitionKind::Captured,
        source_id: "capture-a".into(),
        partition_id: "sha256:one".into(),
    }
}

#[test]
fn import_partition_follows_batch_and_checkpoint_not_generation_or_clock() {
    let mut context = ImportContext {
        source_id: "collector-label".into(),
        source_schema: "import-v1".into(),
        source_version: None,
        clock: ObservationClock::default(),
        batch: SourceBatch {
            batch_id: Some("batch-a".into()),
            sha256: None,
            byte_length: Some(100),
        },
        checkpoint_id: "checkpoint-a".into(),
        session: "session-a".into(),
        generation: 1,
        direction: Some(0),
        peer: None,
        local: None,
        provenance: vec![SourceRange {
            start: 0,
            end: 10,
            sha256: None,
        }],
    };
    let first = SourcePartition::from_import_context(&context, &Limits::default()).unwrap();
    context.generation = 2;
    assert_eq!(
        first,
        SourcePartition::from_import_context(&context, &Limits::default()).unwrap()
    );
    context.checkpoint_id = "checkpoint-b".into();
    assert_ne!(
        first,
        SourcePartition::from_import_context(&context, &Limits::default()).unwrap()
    );
    assert_eq!(first.kind, PartitionKind::Imported);
}
fn session() -> SessionKey {
    SessionKey {
        source: partition(),
        session: "tcp-tuple-7".into(),
    }
}
fn family() -> Family {
    Family { afi: 1, safi: 1 }
}
fn open(code: u8) -> EventKind {
    EventKind::Open(OpenAdvertisement {
        capabilities: vec![Capability {
            code,
            value_sha256: "00".repeat(32),
        }],
        ambiguous: false,
    })
}
fn event(id: &str, generation: u64, direction: Option<u8>, kind: EventKind) -> Event {
    Event {
        session: session(),
        generation,
        direction,
        record_id: id.into(),
        kind,
    }
}
fn scope(generation: u64, direction: Option<u8>) -> RibScope {
    RibScope {
        source: partition(),
        session: "tcp-tuple-7".into(),
        generation,
        direction,
        peer: Some("peer-label".into()),
    }
}
fn prefix() -> PrefixIdentity {
    PrefixIdentity {
        afi: 1,
        safi: 1,
        length: 24,
        address: "203.0.113.0".into(),
    }
}
fn rib_event(id: &str, generation: u64, direction: Option<u8>, kind: RibEventKind) -> RibEvent {
    RibEvent {
        scope: scope(generation, direction),
        record_id: id.into(),
        kind,
    }
}
fn announce(id: &str, generation: u64, med: u32) -> RibEvent {
    rib_event(
        id,
        generation,
        Some(0),
        RibEventKind::Update(vec![RibAction::Announce {
            prefix: prefix(),
            path_id: PathId::Absent,
            attributes: Json::object([("med", med.into())]),
            attribute_identity: format!("med-{med}"),
        }]),
    )
}

#[test]
fn asymmetric_open_and_conflict_never_establish_context() {
    let mut observer = SessionObserver::new(session(), Limits::default()).unwrap();
    observer
        .apply(event("open-a", 4, Some(0), open(65)))
        .unwrap();
    assert!(matches!(
        observer.view().unwrap().context,
        CapabilityContext::Unresolved(_)
    ));
    observer
        .apply(event("ka-b", 4, Some(1), EventKind::Keepalive))
        .unwrap();
    assert!(matches!(
        observer.view().unwrap().context,
        CapabilityContext::Unresolved(_)
    ));
    observer
        .apply(event("open-b", 4, Some(1), open(65)))
        .unwrap();
    assert_eq!(
        observer.view().unwrap().context,
        CapabilityContext::BilateralCandidate {
            common_codes: vec![65]
        }
    );
    observer
        .apply(event("open-b-alt", 4, Some(1), open(2)))
        .unwrap();
    assert_eq!(observer.view().unwrap().directions[1].opens.len(), 2);
    assert!(matches!(
        observer.view().unwrap().context,
        CapabilityContext::Unresolved(_)
    ));
    assert_eq!(observer.events().len(), 4);
}

#[test]
fn repeated_identical_open_is_not_a_negotiation_vote() {
    let mut observer = SessionObserver::new(session(), Limits::default()).unwrap();
    let a = event("a", 0, Some(0), open(65));
    observer.apply(a.clone()).unwrap();
    observer.apply(event("b", 0, Some(1), open(65))).unwrap();
    assert!(matches!(
        observer.view().unwrap().context,
        CapabilityContext::BilateralCandidate { .. }
    ));
    assert_eq!(
        observer.apply(a).unwrap(),
        bgp_session::ApplyStatus::IdenticalReplay
    );
    observer
        .apply(event("a-duplicate", 0, Some(0), open(65)))
        .unwrap();
    assert_eq!(
        observer.view().unwrap().directions[0].opens[0]
            .witnesses
            .len(),
        2
    );
    assert!(matches!(
        observer.view().unwrap().context,
        CapabilityContext::Unresolved(_)
    ));
}

#[test]
fn changed_record_identity_quarantines_bilateral_context() {
    let mut observer = SessionObserver::new(session(), Limits::default()).unwrap();
    observer
        .apply(event("same-id", 0, Some(0), open(65)))
        .unwrap();
    observer
        .apply(event("other", 0, Some(1), open(65)))
        .unwrap();
    assert!(matches!(
        observer.view().unwrap().context,
        CapabilityContext::BilateralCandidate { .. }
    ));
    let conflicting = event("same-id", 0, Some(0), open(2));
    assert_eq!(
        observer.apply(conflicting.clone()).unwrap(),
        bgp_session::ApplyStatus::IdentityConflict
    );
    assert!(observer.view().unwrap().identity_conflict);
    assert!(matches!(
        observer.view().unwrap().context,
        CapabilityContext::Unresolved("record_identity_conflict")
    ));
    assert_eq!(observer.events().len(), 3);
    assert_eq!(
        observer.apply(conflicting).unwrap(),
        bgp_session::ApplyStatus::IdenticalReplay
    );
    assert_eq!(observer.events().len(), 3);
    assert_eq!(
        observer
            .apply(event(
                "reset-after-conflict",
                1,
                None,
                EventKind::Reset {
                    previous_generation: 0,
                    reason: "must use a distinct partition".into(),
                },
            ))
            .unwrap(),
        bgp_session::ApplyStatus::IdentityConflict
    );
    assert_eq!(observer.view().unwrap().generation, 0);
}

#[test]
fn capability_multiplicity_is_preserved_without_code_only_ambiguity() {
    let advertisement = EventKind::Open(OpenAdvertisement {
        capabilities: vec![
            Capability {
                code: 1,
                value_sha256: "11".repeat(32),
            },
            Capability {
                code: 1,
                value_sha256: "22".repeat(32),
            },
        ],
        ambiguous: false,
    });
    let mut observer = SessionObserver::new(session(), Limits::default()).unwrap();
    observer
        .apply(event("left", 0, Some(0), advertisement.clone()))
        .unwrap();
    observer
        .apply(event("right", 0, Some(1), advertisement))
        .unwrap();
    assert_eq!(
        observer.view().unwrap().context,
        CapabilityContext::BilateralCandidate {
            common_codes: vec![1]
        }
    );
    assert!(observer
        .apply(event(
            "bad-hash",
            0,
            Some(0),
            EventKind::Open(OpenAdvertisement {
                capabilities: vec![Capability {
                    code: 65,
                    value_sha256: "not-a-hash".into(),
                }],
                ambiguous: false,
            }),
        ))
        .is_err());
}

#[test]
fn tuple_reuse_needs_reset_and_old_replay_is_inert() {
    let mut observer = SessionObserver::new(session(), Limits::default()).unwrap();
    let first = event("open-old", 10, Some(0), open(65));
    observer.apply(first.clone()).unwrap();
    assert!(observer
        .apply(event("new-implicit", 11, Some(0), open(65)))
        .is_err());
    assert_eq!(observer.events().len(), 1);
    observer
        .apply(event("notification", 10, Some(1), EventKind::Notification))
        .unwrap();
    assert!(observer.view().unwrap().closed_by_notification);
    observer
        .apply(event(
            "reset",
            11,
            None,
            EventKind::Reset {
                previous_generation: 10,
                reason: "observed transport reset".into(),
            },
        ))
        .unwrap();
    assert!(!observer.view().unwrap().closed_by_notification);
    assert_eq!(
        observer.apply(first).unwrap(),
        bgp_session::ApplyStatus::IdenticalReplay
    );
    assert_eq!(
        observer.apply(event("late", 10, Some(1), open(2))).unwrap(),
        bgp_session::ApplyStatus::Historical
    );
    assert_eq!(observer.view().unwrap().generation, 11);
    assert!(observer
        .view()
        .unwrap()
        .directions
        .iter()
        .all(|d| d.opens.is_empty()));
}

#[test]
fn decoded_protocol_reset_requires_exact_successor_and_is_replay_safe() {
    let mut observer = SessionObserver::new(session(), Limits::default()).unwrap();
    observer.apply(event("a", 7, Some(0), open(65))).unwrap();
    observer.apply(event("b", 7, Some(1), open(65))).unwrap();
    let reset = event(
        "notification",
        7,
        Some(1),
        EventKind::ProtocolReset {
            next_generation: 8,
            kind: ProtocolResetKind::Notification,
        },
    );
    assert_eq!(
        observer.apply(reset.clone()).unwrap(),
        bgp_session::ApplyStatus::Applied
    );
    assert_eq!(observer.view().unwrap().generation, 8);
    assert_eq!(observer.view().unwrap().resets, ["notification"]);
    assert_eq!(
        observer.apply(reset).unwrap(),
        bgp_session::ApplyStatus::IdenticalReplay
    );

    let before = observer.events().len();
    assert!(observer
        .apply(event(
            "skipped",
            8,
            Some(0),
            EventKind::ProtocolReset {
                next_generation: 10,
                kind: ProtocolResetKind::UpdateError,
            },
        ))
        .is_err());
    assert_eq!(observer.events().len(), before);
    assert_eq!(observer.view().unwrap().generation, 8);
}

#[test]
fn imported_generations_require_the_exact_successor() {
    let mut imported_key = session();
    imported_key.source.kind = PartitionKind::Imported;
    let mut observer = SessionObserver::new(imported_key.clone(), Limits::default()).unwrap();
    let mut first = event("first", 5, Some(0), EventKind::Keepalive);
    first.session = imported_key.clone();
    observer.apply(first).unwrap();
    let mut skipped = event(
        "skipped",
        7,
        None,
        EventKind::Reset {
            previous_generation: 5,
            reason: "invalid skipped generation".into(),
        },
    );
    skipped.session = imported_key;
    assert!(observer.apply(skipped).is_err());
    assert_eq!(observer.view().unwrap().generation, 5);

    let mut initial = announce("initial", 5, 10);
    initial.scope.source.kind = PartitionKind::Imported;
    let mut rib = AdjRibIn::new(Limits::default()).unwrap();
    rib.apply(initial).unwrap();
    let mut skipped = rib_event(
        "skipped",
        7,
        None,
        RibEventKind::Reset {
            previous_generation: 5,
            reason: "invalid skipped generation".into(),
        },
    );
    skipped.scope.source.kind = PartitionKind::Imported;
    assert!(rib.apply(skipped).is_err());
    assert_eq!(rib.events().len(), 1);
}

#[test]
fn gap_stale_eor_and_refresh_are_explicit_observations() {
    let mut observer = SessionObserver::new(session(), Limits::default()).unwrap();
    observer.apply(event("a", 1, Some(0), open(65))).unwrap();
    observer.apply(event("b", 1, Some(1), open(65))).unwrap();
    observer
        .apply(event(
            "stale",
            1,
            Some(0),
            EventKind::Stale {
                family: family(),
                kind: StaleKind::LongLivedGraceful,
            },
        ))
        .unwrap();
    assert_eq!(observer.view().unwrap().directions[0].stale.len(), 1);
    observer
        .apply(event(
            "refresh",
            1,
            Some(0),
            EventKind::RouteRefresh {
                family: family(),
                subtype: Some(1),
            },
        ))
        .unwrap();
    assert_eq!(observer.view().unwrap().directions[0].refreshes.len(), 1);
    observer
        .apply(event("eor", 1, Some(0), EventKind::EndOfRib(family())))
        .unwrap();
    assert!(observer.view().unwrap().directions[0].stale.is_empty());
    observer
        .apply(event(
            "gap",
            1,
            None,
            EventKind::Gap {
                reason: "missing packet range".into(),
            },
        ))
        .unwrap();
    assert_eq!(observer.view().unwrap().gaps, ["gap"]);
    observer
        .apply(event("after-gap", 1, Some(1), EventKind::Update))
        .unwrap();
    assert_eq!(
        observer.view().unwrap().directions[1].updates,
        ["after-gap"]
    );
    assert!(matches!(
        observer.view().unwrap().context,
        CapabilityContext::Unresolved("explicit_gap")
    ));
}

#[test]
fn directionless_messages_remain_evidence_without_a_side() {
    let mut observer = SessionObserver::new(session(), Limits::default()).unwrap();
    observer
        .apply(event("unknown-open", 0, None, open(65)))
        .unwrap();
    observer.apply(event("a", 0, Some(0), open(65))).unwrap();
    observer.apply(event("b", 0, Some(1), open(65))).unwrap();
    assert_eq!(observer.view().unwrap().unscoped, ["unknown-open"]);
    assert!(matches!(
        observer.view().unwrap().context,
        CapabilityContext::Unresolved("unscoped_open_alternative")
    ));
    let mut rib = AdjRibIn::new(Limits::default()).unwrap();
    let mut unscoped = announce("route", 0, 10);
    unscoped.scope.direction = None;
    assert_eq!(
        rib.apply(unscoped).unwrap(),
        bgp_rib::ApplyStatus::MissingScope
    );
    assert_eq!(rib.events().len(), 1);
    assert!(rib.entries().is_empty());
}

#[test]
fn session_budget_exact_and_one_below_are_atomic() {
    let input = event("ka", 0, Some(0), EventKind::Keepalive);
    let mut reference = SessionObserver::new(session(), Limits::default()).unwrap();
    reference.apply(input.clone()).unwrap();
    let size = reference.retained_bytes();
    let work = reference.accounted_work();
    let mut exact = SessionObserver::new(
        session(),
        Limits {
            retained_bytes: size,
            output_bytes: size,
            work,
            ..Limits::default()
        },
    )
    .unwrap();
    exact.apply(input.clone()).unwrap();
    for limits in [
        Limits {
            retained_bytes: size - 1,
            ..Limits::default()
        },
        Limits {
            output_bytes: size - 1,
            ..Limits::default()
        },
        Limits {
            work: work - 1,
            ..Limits::default()
        },
    ] {
        let mut limited = SessionObserver::new(session(), limits).unwrap();
        assert!(limited.apply(input.clone()).is_err());
        assert!(limited.events().is_empty());
        assert!(limited.view().is_none());
    }
}

#[test]
fn rib_withdraw_reannounce_reset_and_historical_replay() {
    let mut rib = AdjRibIn::new(Limits::default()).unwrap();
    let original = announce("first", 3, 10);
    rib.apply(original.clone()).unwrap();
    rib.apply(announce("duplicate", 3, 10)).unwrap();
    let entry = rib.entries().values().next().unwrap();
    assert_eq!(entry.versions.len(), 1);
    assert_eq!(entry.versions[0].witnesses.len(), 2);
    rib.apply(announce("replacement", 3, 20)).unwrap();
    let entry = rib.entries().values().next().unwrap();
    assert_eq!(entry.versions[0].disposition, VersionDisposition::Replaced);
    assert_eq!(entry.versions.len(), 2);
    rib.apply(rib_event(
        "withdraw",
        3,
        Some(0),
        RibEventKind::Update(vec![RibAction::Withdraw {
            prefix: prefix(),
            path_id: PathId::Absent,
        }]),
    ))
    .unwrap();
    assert_eq!(
        rib.entries().values().next().unwrap().status,
        RouteStatus::Withdrawn
    );
    rib.apply(announce("reannounce", 3, 30)).unwrap();
    assert_eq!(
        rib.entries().values().next().unwrap().status,
        RouteStatus::Active
    );
    assert!(rib.apply(announce("implicit", 4, 1)).is_err());
    rib.apply(rib_event(
        "reset",
        4,
        None,
        RibEventKind::Reset {
            previous_generation: 3,
            reason: "transport boundary".into(),
        },
    ))
    .unwrap();
    assert_eq!(
        rib.entries().values().next().unwrap().status,
        RouteStatus::Superseded
    );
    assert_eq!(
        rib.apply(original).unwrap(),
        bgp_rib::ApplyStatus::IdenticalReplay
    );
    assert_eq!(
        rib.apply(announce("old-new-record", 3, 99)).unwrap(),
        bgp_rib::ApplyStatus::Historical
    );
    rib.apply(announce("current", 4, 40)).unwrap();
    assert_eq!(
        rib.entries()
            .values()
            .filter(|e| e.status == RouteStatus::Active)
            .count(),
        1
    );
    assert_eq!(
        rib.entries()
            .values()
            .filter(|e| e.status == RouteStatus::Superseded)
            .count(),
        1
    );
}

#[test]
fn rib_stale_eor_gap_and_identity_conflict_preserve_alternatives() {
    let mut rib = AdjRibIn::new(Limits::default()).unwrap();
    rib.apply(announce("a", 0, 10)).unwrap();
    rib.apply(rib_event(
        "stale",
        0,
        Some(0),
        RibEventKind::Stale {
            family: family(),
            kind: StaleKind::Graceful,
        },
    ))
    .unwrap();
    assert_eq!(
        rib.entries().values().next().unwrap().status,
        RouteStatus::Stale(StaleKind::Graceful)
    );
    rib.apply(rib_event(
        "eor",
        0,
        Some(0),
        RibEventKind::EndOfRib(family()),
    ))
    .unwrap();
    assert_eq!(rib.eors().len(), 1);
    assert_eq!(
        rib.entries().values().next().unwrap().status,
        RouteStatus::StaleAtEor
    );
    rib.apply(announce("fresh", 0, 20)).unwrap();
    assert_eq!(
        rib.entries().values().next().unwrap().status,
        RouteStatus::Active
    );
    rib.apply(rib_event(
        "gap",
        0,
        None,
        RibEventKind::Gap {
            reason: "lost sequence".into(),
        },
    ))
    .unwrap();
    assert_eq!(
        rib.entries().values().next().unwrap().status,
        RouteStatus::Unresolved
    );
    rib.apply(announce("after-gap", 0, 30)).unwrap();
    assert_eq!(
        rib.entries().values().next().unwrap().status,
        RouteStatus::Unresolved
    );
    let conflicting = announce("a", 0, 11);
    assert_eq!(
        rib.apply(conflicting.clone()).unwrap(),
        bgp_rib::ApplyStatus::IdentityConflict
    );
    let entry = rib.entries().values().next().unwrap();
    assert_eq!(entry.status, RouteStatus::Unresolved);
    assert!(entry
        .versions
        .iter()
        .any(|v| v.attribute_identity == "med-11"
            && v.disposition == VersionDisposition::Conflicting));
    let count = rib.events().len();
    assert_eq!(
        rib.apply(conflicting).unwrap(),
        bgp_rib::ApplyStatus::IdenticalReplay
    );
    assert_eq!(rib.events().len(), count);
    assert_eq!(
        rib.apply(rib_event(
            "reset-after-conflict",
            1,
            None,
            RibEventKind::Reset {
                previous_generation: 0,
                reason: "new partition required".into(),
            },
        ))
        .unwrap(),
        bgp_rib::ApplyStatus::IdentityConflict
    );
    assert_eq!(
        rib.apply(announce("later", 1, 12)).unwrap(),
        bgp_rib::ApplyStatus::IdentityConflict
    );
    assert!(rib
        .entries()
        .values()
        .all(|entry| entry.status == RouteStatus::Unresolved));
}

#[test]
fn multi_prefix_update_is_one_atomic_record() {
    let mut second = prefix();
    second.address = "198.51.100.0".into();
    let update = rib_event(
        "multi",
        0,
        Some(0),
        RibEventKind::Update(vec![
            RibAction::Announce {
                prefix: prefix(),
                path_id: PathId::Absent,
                attributes: Json::object([("med", 10u32.into())]),
                attribute_identity: "first".into(),
            },
            RibAction::Announce {
                prefix: second,
                path_id: PathId::Absent,
                attributes: Json::object([("med", 20u32.into())]),
                attribute_identity: "second".into(),
            },
        ]),
    );
    let mut rib = AdjRibIn::new(Limits::default()).unwrap();
    assert_eq!(
        rib.apply(update.clone()).unwrap(),
        bgp_rib::ApplyStatus::Applied
    );
    assert_eq!(rib.entries().len(), 2);
    assert_eq!(
        rib.apply(update).unwrap(),
        bgp_rib::ApplyStatus::IdenticalReplay
    );

    let mut invalid = announce("invalid-record", 0, 1);
    if let RibEventKind::Update(actions) = &mut invalid.kind {
        actions.push(RibAction::Withdraw {
            prefix: PrefixIdentity {
                address: "203.0.113.1".into(),
                ..prefix()
            },
            path_id: PathId::Absent,
        });
    }
    let before = rib.events().len();
    assert!(rib.apply(invalid).is_err());
    assert_eq!(rib.events().len(), before);
}

#[test]
fn peer_binding_drift_cannot_leave_an_active_withdrawn_route() {
    let mut rib = AdjRibIn::new(Limits::default()).unwrap();
    rib.apply(announce("announce", 0, 10)).unwrap();
    let mut withdrawal = rib_event(
        "withdraw",
        0,
        Some(0),
        RibEventKind::Update(vec![RibAction::Withdraw {
            prefix: prefix(),
            path_id: PathId::Absent,
        }]),
    );
    withdrawal.scope.peer = None;
    assert_eq!(
        rib.apply(withdrawal).unwrap(),
        bgp_rib::ApplyStatus::MissingScope
    );
    assert_eq!(rib.entries().len(), 1);
    assert_eq!(
        rib.entries().values().next().unwrap().status,
        RouteStatus::Unresolved
    );
}

#[test]
fn rib_partition_path_and_direction_and_atomic_budget() {
    let input = announce("one", 0, 10);
    let mut reference = AdjRibIn::new(Limits::default()).unwrap();
    reference.apply(input.clone()).unwrap();
    let size = reference.retained_bytes();
    let work = reference.accounted_work();
    let mut exact = AdjRibIn::new(Limits {
        retained_bytes: size,
        output_bytes: size,
        work,
        ..Limits::default()
    })
    .unwrap();
    exact.apply(input.clone()).unwrap();
    for limits in [
        Limits {
            retained_bytes: size - 1,
            ..Limits::default()
        },
        Limits {
            output_bytes: size - 1,
            ..Limits::default()
        },
        Limits {
            work: work - 1,
            ..Limits::default()
        },
        Limits {
            elements: 1,
            ..Limits::default()
        },
    ] {
        let mut limited = AdjRibIn::new(limits).unwrap();
        assert!(limited.apply(input.clone()).is_err());
        assert!(limited.events().is_empty());
        assert!(limited.entries().is_empty());
    }
    let mut separate = input.clone();
    separate.record_id = "two".into();
    separate.scope.direction = Some(1);
    reference.apply(separate).unwrap();
    let mut separate = input;
    separate.record_id = "three".into();
    separate.scope.source.partition_id = "other-capture".into();
    reference.apply(separate).unwrap();
    let mut separate = announce("four", 0, 10);
    if let RibEventKind::Update(actions) = &mut separate.kind {
        if let RibAction::Announce { path_id, .. } = &mut actions[0] {
            *path_id = PathId::Present(7);
        }
    }
    reference.apply(separate).unwrap();
    assert_eq!(reference.entries().len(), 4);
}

#[test]
fn rejected_record_does_not_erase_an_older_candidate() {
    let mut rib = AdjRibIn::new(Limits::default()).unwrap();
    rib.apply(announce("good", 0, 10)).unwrap();
    rib.apply(rib_event(
        "bad",
        0,
        Some(0),
        RibEventKind::Update(vec![RibAction::Reject {
            prefix: prefix(),
            path_id: PathId::Absent,
            reason: "caller_classified_malformed_update".into(),
        }]),
    ))
    .unwrap();
    assert_eq!(rib.rejections().len(), 1);
    assert_eq!(
        rib.entries().values().next().unwrap().status,
        RouteStatus::Active
    );
    assert_eq!(rib.rejections()[0].record_id, "bad");
}

fn policy_config() -> PolicyConfig {
    PolicyConfig {
        provenance: "router-config-export-asserted".into(),
        comparison_context: "local-router-a".into(),
        missing_local_preference: Some(100),
        med_rule: Some(MedRule::SameNeighborAs),
        age_rule: Some(AgeRule::Skip),
    }
}
fn candidate(id: &str, neighbor: [u8; 4]) -> PolicyCandidate {
    let mut rib = AdjRibIn::new(Limits::default()).unwrap();
    rib.apply(announce(id, 0, 10)).unwrap();
    let key = rib.entries().keys().next().unwrap().clone();
    PolicyCandidate {
        id: id.into(),
        key,
        comparison_context: "local-router-a".into(),
        status: RouteStatus::Active,
        inputs: BestPathInputs {
            local_preference: None,
            locally_originated: Some(false),
            as_path_length: Some(2),
            origin: Some(0),
            med: Some(MedEvidence::Present(10)),
            neighboring_as: Some(64500),
            ebgp: Some(true),
            igp_metric: Some(20),
            age: None,
            router_id: Some(Ipv4Addr::new(1, 1, 1, 1)),
            neighbor_address: Some(IpAddr::V4(Ipv4Addr::from(neighbor))),
        },
    }
}

#[test]
fn policy_equal_through_last_tie_break_and_permutation_invariant() {
    let a = candidate("a", [192, 0, 2, 1]);
    let b = candidate("b", [192, 0, 2, 2]);
    let c = candidate("c", [192, 0, 2, 3]);
    let first = bgp_policy::evaluate(
        &policy_config(),
        &[c.clone(), a.clone(), b.clone()],
        &Limits::default(),
    )
    .unwrap();
    let second = bgp_policy::evaluate(&policy_config(), &[b, c, a], &Limits::default()).unwrap();
    assert_eq!(first, second);
    assert_eq!(
        first.encode_canonical(&Limits::default()).unwrap(),
        second.encode_canonical(&Limits::default()).unwrap()
    );
    assert_eq!(
        first.config_fingerprint_sha256,
        second.config_fingerprint_sha256
    );
    assert_eq!(
        first.candidate_set_fingerprint_sha256,
        second.candidate_set_fingerprint_sha256
    );
    assert_eq!(first.selected.as_deref(), Some("a"));
    assert_eq!(first.comparisons.len(), 3);
    assert_eq!(first.comparisons[0].steps.len(), bgp_policy::ORDER.len());
    assert_eq!(
        first.comparisons[0].steps.last().unwrap().result,
        StepResult::Left
    );
    assert!(!first.endpoint_rib_established && !first.propagated_route_established);
}

#[test]
fn policy_missing_config_med_scope_and_age_are_unresolved() {
    let a = candidate("a", [192, 0, 2, 1]);
    let mut b = candidate("b", [192, 0, 2, 2]);
    let mut config = policy_config();
    config.med_rule = None;
    assert!(
        bgp_policy::evaluate(&config, &[a.clone(), b.clone()], &Limits::default())
            .unwrap()
            .selected
            .is_none()
    );
    config.med_rule = Some(MedRule::SameNeighborAs);
    b.inputs.neighboring_as = Some(64501);
    assert_eq!(
        bgp_policy::evaluate(&config, &[a.clone(), b.clone()], &Limits::default())
            .unwrap()
            .selected
            .as_deref(),
        Some("a")
    );
    b.inputs.neighboring_as = Some(64500);
    config.missing_local_preference = None;
    assert!(
        bgp_policy::evaluate(&config, &[a.clone(), b.clone()], &Limits::default())
            .unwrap()
            .unresolved
            .iter()
            .any(|x| x.contains("incomparable_at_local_preference"))
    );
    config.missing_local_preference = Some(100);
    config.age_rule = Some(AgeRule::SameClock);
    assert!(bgp_policy::evaluate(&config, &[a, b], &Limits::default())
        .unwrap()
        .selected
        .is_none());
}

#[test]
fn policy_missing_late_rules_do_not_block_an_early_winner() {
    let mut a = candidate("a", [192, 0, 2, 1]);
    let mut b = candidate("b", [192, 0, 2, 2]);
    a.inputs.local_preference = Some(200);
    b.inputs.local_preference = Some(100);
    let mut config = policy_config();
    config.med_rule = None;
    config.age_rule = None;

    let result = bgp_policy::evaluate(&config, &[a, b], &Limits::default()).unwrap();
    assert_eq!(result.selected.as_deref(), Some("a"));
    assert!(result.unresolved.is_empty());
    let steps = &result.comparisons[0].steps;
    assert_eq!(
        steps
            .iter()
            .find(|step| step.criterion == "med")
            .unwrap()
            .result,
        StepResult::Skipped
    );
    assert_eq!(
        steps
            .iter()
            .find(|step| step.criterion == "age")
            .unwrap()
            .result,
        StepResult::Skipped
    );
}

#[test]
fn policy_missing_med_rule_is_unresolved_when_med_is_reached() {
    let mut a = candidate("a", [192, 0, 2, 1]);
    let mut b = candidate("b", [192, 0, 2, 2]);
    a.inputs.med = Some(MedEvidence::Present(10));
    b.inputs.med = Some(MedEvidence::Present(20));
    let mut config = policy_config();
    config.med_rule = None;
    config.age_rule = Some(AgeRule::Skip);

    let result = bgp_policy::evaluate(&config, &[a, b], &Limits::default()).unwrap();
    assert!(result.selected.is_none());
    assert!(result
        .unresolved
        .iter()
        .any(|reason| reason.ends_with("incomparable_at_med")));
    let med = result.comparisons[0]
        .steps
        .iter()
        .find(|step| step.criterion == "med")
        .unwrap();
    assert_eq!(med.result, StepResult::Unresolved);
    assert_eq!(med.reason, "med_policy_configuration_missing");
}

#[test]
fn policy_missing_age_rule_is_unresolved_when_age_is_reached() {
    let mut a = candidate("a", [192, 0, 2, 1]);
    let mut b = candidate("b", [192, 0, 2, 2]);
    a.inputs.age = Some(bgp_policy::AgeEvidence {
        clock_id: "collector-clock".into(),
        observed_order: 1,
    });
    b.inputs.age = Some(bgp_policy::AgeEvidence {
        clock_id: "collector-clock".into(),
        observed_order: 2,
    });
    let mut config = policy_config();
    config.med_rule = Some(MedRule::Skip);
    config.age_rule = None;

    let result = bgp_policy::evaluate(&config, &[a, b], &Limits::default()).unwrap();
    assert!(result.selected.is_none());
    assert!(result
        .unresolved
        .iter()
        .any(|reason| reason.ends_with("incomparable_at_age")));
    let age = result.comparisons[0]
        .steps
        .iter()
        .find(|step| step.criterion == "age")
        .unwrap();
    assert_eq!(age.result, StepResult::Unresolved);
    assert_eq!(age.reason, "age_policy_configuration_missing");
}

#[test]
fn policy_stops_at_the_first_decisive_criterion() {
    let mut a = candidate("a", [192, 0, 2, 1]);
    let mut b = candidate("b", [192, 0, 2, 2]);
    a.inputs.local_preference = Some(200);
    b.inputs.local_preference = Some(100);
    a.inputs.router_id = None;
    b.inputs.router_id = None;
    a.inputs.neighboring_as = Some(64500);
    b.inputs.neighboring_as = Some(64501);
    assert_eq!(
        bgp_policy::evaluate(&policy_config(), &[a, b], &Limits::default())
            .unwrap()
            .selected
            .as_deref(),
        Some("a")
    );
}

#[test]
fn absent_med_is_zero_and_public_route_keys_are_validated() {
    let mut a = candidate("a", [192, 0, 2, 1]);
    let mut b = candidate("b", [192, 0, 2, 2]);
    a.inputs.med = Some(MedEvidence::Absent);
    b.inputs.med = Some(MedEvidence::Present(10));
    assert_eq!(
        bgp_policy::evaluate(&policy_config(), &[a.clone(), b], &Limits::default())
            .unwrap()
            .selected
            .as_deref(),
        Some("a")
    );
    a.key.prefix.address = "not-an-address".into();
    assert!(bgp_policy::evaluate(&policy_config(), &[a], &Limits::default()).is_err());
}

#[test]
fn policy_complete_trace_exact_limit_and_one_below() {
    let candidates = [
        candidate("a", [192, 0, 2, 1]),
        candidate("b", [192, 0, 2, 2]),
    ];
    let config = policy_config();
    let reference = bgp_policy::evaluate(&config, &candidates, &Limits::default()).unwrap();
    let canonical = reference.encode_canonical(&Limits::default()).unwrap();
    let size = canonical.len();
    assert_eq!(reference.encoded_len(size).unwrap(), size);
    assert!(canonical.starts_with("{\"candidate_set_fingerprint_sha256\":"));
    assert!(canonical.contains("\"schema\":\"pcap-evidence.bgp.policy-result.v1\""));
    assert!(canonical.contains("\"candidate_store_binding\":\"not_provided_by_policy_api\""));
    assert!(canonical.contains("\"identity_scope\":\"canonical_policy_inputs_only\""));
    assert!(canonical.contains("\"endpoint_rib_established\":false"));
    assert!(canonical.contains("\"propagated_route_established\":false"));
    let exact = Limits {
        output_bytes: size,
        ..Limits::default()
    };
    assert_eq!(reference.encode_canonical(&exact).unwrap(), canonical);
    assert!(reference
        .encode_canonical(&Limits {
            output_bytes: size - 1,
            ..Limits::default()
        })
        .is_err());
    assert_eq!(
        bgp_policy::evaluate(&config, &candidates, &exact).unwrap(),
        reference
    );
    let mut published = b"prefix:".to_vec();
    assert_eq!(
        reference.write_canonical(&mut published, &exact).unwrap(),
        size
    );
    assert_eq!(&published[b"prefix:".len()..], canonical.as_bytes());
    let mut unchanged = b"prefix:".to_vec();
    let too_small = Limits {
        output_bytes: size - 1,
        ..Limits::default()
    };
    assert_eq!(
        reference
            .write_canonical(&mut unchanged, &too_small)
            .unwrap_err()
            .field,
        "bgp_policy_output_bytes"
    );
    assert_eq!(unchanged, b"prefix:");
    for limits in [
        Limits {
            output_bytes: size - 1,
            ..Limits::default()
        },
        Limits {
            retained_bytes: size - 1,
            ..Limits::default()
        },
        Limits {
            // Pair/trace amplification must be rejected before comparisons
            // are expanded, independently of the output-size check.
            work: 1,
            ..Limits::default()
        },
    ] {
        assert!(bgp_policy::evaluate(&config, &candidates, &limits).is_err());
    }
}

#[test]
fn policy_fingerprints_bind_config_and_source_partitioned_candidate_inputs() {
    let base_candidate = candidate("route-a", [192, 0, 2, 1]);
    let base_config = policy_config();
    let base = bgp_policy::evaluate(
        &base_config,
        std::slice::from_ref(&base_candidate),
        &Limits::default(),
    )
    .unwrap();

    let mut changed_config = base_config.clone();
    changed_config.missing_local_preference = Some(101);
    let config_changed = bgp_policy::evaluate(
        &changed_config,
        std::slice::from_ref(&base_candidate),
        &Limits::default(),
    )
    .unwrap();
    assert_ne!(
        base.config_fingerprint_sha256,
        config_changed.config_fingerprint_sha256
    );
    assert_eq!(
        base.candidate_set_fingerprint_sha256,
        config_changed.candidate_set_fingerprint_sha256
    );

    let mut changed_candidate = base_candidate.clone();
    changed_candidate.key.scope.session.push_str("-other");
    let candidate_changed =
        bgp_policy::evaluate(&base_config, &[changed_candidate], &Limits::default()).unwrap();
    assert_eq!(
        base.config_fingerprint_sha256,
        candidate_changed.config_fingerprint_sha256
    );
    assert_ne!(
        base.candidate_set_fingerprint_sha256,
        candidate_changed.candidate_set_fingerprint_sha256
    );

    let mut changed_partition = base_candidate.clone();
    changed_partition
        .key
        .scope
        .source
        .partition_id
        .push_str("-other");
    let partition_changed =
        bgp_policy::evaluate(&base_config, &[changed_partition], &Limits::default()).unwrap();
    assert_ne!(
        base.candidate_set_fingerprint_sha256,
        partition_changed.candidate_set_fingerprint_sha256
    );

    let mut changed_source = base_candidate;
    changed_source.key.scope.source.source_id.push_str("-other");
    let source_changed =
        bgp_policy::evaluate(&base_config, &[changed_source], &Limits::default()).unwrap();
    assert_ne!(
        base.candidate_set_fingerprint_sha256,
        source_changed.candidate_set_fingerprint_sha256
    );
}

#[test]
fn policy_preflights_long_id_pair_amplification_before_trace_construction() {
    let candidates: Vec<_> = (0..24)
        .map(|index| {
            let id = format!("{index:02}-{}", "x".repeat(1021));
            candidate(&id, [192, 0, 2, index as u8])
        })
        .collect();
    let limits = Limits {
        work: 64 * 1024,
        ..Limits::default()
    };
    let error = bgp_policy::evaluate(&policy_config(), &candidates, &limits).unwrap_err();
    assert_eq!(error.field, "bgp_policy_trace_budget");
}

#[test]
fn policy_work_budget_exact_limit_and_one_below() {
    let candidates = [
        candidate("a", [192, 0, 2, 1]),
        candidate("b", [192, 0, 2, 2]),
    ];
    let config = policy_config();
    let mut lower = 1usize;
    let mut upper = Limits::default().work;
    while lower < upper {
        let middle = lower + (upper - lower) / 2;
        let limits = Limits {
            work: middle,
            ..Limits::default()
        };
        if bgp_policy::evaluate(&config, &candidates, &limits).is_ok() {
            upper = middle;
        } else {
            lower = middle + 1;
        }
    }
    let exact = Limits {
        work: lower,
        ..Limits::default()
    };
    assert!(bgp_policy::evaluate(&config, &candidates, &exact).is_ok());
    let one_below = Limits {
        work: lower - 1,
        ..Limits::default()
    };
    assert_eq!(
        bgp_policy::evaluate(&config, &candidates, &one_below)
            .unwrap_err()
            .field,
        "bgp_policy_budget"
    );
}

#[test]
fn policy_excludes_stale_and_rejected_candidates() {
    let a = candidate("a", [192, 0, 2, 1]);
    let mut stale = candidate("stale", [192, 0, 2, 0]);
    stale.status = RouteStatus::Stale(StaleKind::Graceful);
    let mut rejected = candidate("rejected", [192, 0, 2, 0]);
    rejected.status = RouteStatus::Rejected;
    let result =
        bgp_policy::evaluate(&policy_config(), &[rejected, stale, a], &Limits::default()).unwrap();
    assert_eq!(result.selected.as_deref(), Some("a"));
    assert_eq!(result.excluded.len(), 2);
}

#[test]
fn legacy_adapter_preserves_exact_candidate_snapshot() {
    let mut legacy = CandidateState::new(Limits::default()).unwrap();
    for (id, med) in [("a", 10), ("b", 20)] {
        let normalized = bgp::normalize_imported(
            ImportedRouteObservation {
                source_id: "legacy-source".into(),
                record_id: id.into(),
                observed_at_ns: None,
                session: Some("legacy-session".into()),
                peer: None,
                local: None,
                action: RouteAction::Announce,
                prefix: Prefix::ipv4([203, 0, 113, 0], 24).unwrap(),
                attributes: PathAttributes {
                    med: Some(med),
                    ..PathAttributes::default()
                },
            },
            &Limits::default(),
        )
        .unwrap();
        legacy
            .apply(
                Observation::from_normalized(
                    &normalized,
                    Some(ImportScope {
                        generation: 0,
                        direction: 0,
                    }),
                    &Limits::default(),
                )
                .unwrap(),
            )
            .unwrap();
    }
    assert_eq!(legacy.routes()[0].alternatives.len(), 2);
    let mut adapted = AdjRibIn::from_candidate_state(&legacy, Limits::default()).unwrap();
    assert_eq!(adapted.entries().len(), 1);
    assert_eq!(adapted.entries().values().next().unwrap().versions.len(), 2);
    assert_eq!(
        adapted.entries().values().next().unwrap().status,
        RouteStatus::Unresolved
    );
    assert_eq!(
        adapted.legacy().unwrap().snapshot().encode(),
        legacy.encode()
    );
    assert!(adapted.legacy_snapshot_sha256().is_some());
    assert!(adapted.apply(announce("new", 0, 1)).is_err());
}
