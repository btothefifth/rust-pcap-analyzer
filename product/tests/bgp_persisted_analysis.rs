//! Finite source-built witnesses. Assertions derive from the explicit wire
//! announcements and caller expectations, not the analysis result builder.
use pcap_evidence::{
    provenance::{EvidenceBytes, PacketId},
    sha256,
};
use pcap_evidence_product::deep::{
    bgp::PcapMetadata,
    bgp_mrt::MrtLimits,
    bgp_mrt_store::MrtReplayOptions,
    bgp_persisted::{analysis::ExpectationProfile, Query, VerifiedStore},
    bgp_store::JournalWriter,
    Limits,
};
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!(
            "bgp-analysis-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&p).unwrap();
        Self(p)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn message(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut v = vec![255; 16];
    v.extend_from_slice(&((19 + body.len()) as u16).to_be_bytes());
    v.push(kind);
    v.extend_from_slice(body);
    v
}
fn update(med: u32, partial: bool) -> Vec<u8> {
    let mut a = vec![
        0x40, 1, 1, 0, 0x40, 2, 4, 2, 1, 0xfd, 0xe9, 0x40, 3, 4, 192, 0, 2, 9, 0x80, 4, 4,
    ];
    a.extend_from_slice(&med.to_be_bytes());
    if partial {
        a.extend_from_slice(&[0xe0, 32, 12, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3]);
    }
    let mut b = vec![0, 0];
    b.extend_from_slice(&(a.len() as u16).to_be_bytes());
    b.extend(a);
    b.extend_from_slice(&[24, 203, 0, 113]);
    message(2, &b)
}
fn append(w: &mut JournalWriter, bytes: &[u8], record: &str, frame: u64, direction: u8, time: i64) {
    append_optional_time(w, bytes, record, frame, direction, Some(time));
}
fn append_optional_time(
    w: &mut JournalWriter,
    bytes: &[u8],
    record: &str,
    frame: u64,
    direction: u8,
    time: Option<i64>,
) {
    let e = EvidenceBytes::from_packet(
        bytes,
        PacketId {
            capture: [7; 32],
            frame,
            record_offset: frame * 100,
        },
        0,
    );
    w.message(
        1,
        &e,
        &PcapMetadata {
            source_id: "capture-a".into(),
            record_id: record.into(),
            observed_at_ns: time,
            session: Some(1),
            direction: Some(direction),
            peer: Some("192.0.2.1".into()),
            local: Some("192.0.2.100".into()),
        },
    )
    .unwrap();
}
fn fixture(updates: &[(u32, bool)], gap: bool) -> (Scratch, VerifiedStore) {
    let s = Scratch::new();
    let path = s.0.join("source.store");
    let mut w = JournalWriter::create(
        &path,
        "capture-a".into(),
        [7; 32],
        1_048_576,
        Limits::default(),
    )
    .unwrap();
    for d in [0, 1] {
        let open = message(1, &[4, 0xfd, 0xe9, 0, 90, 192, 0, 2, d + 1, 0]);
        append(&mut w, &open, &format!("open-{d}"), 100 + d as u64, d, 10);
    }
    for (i, &(med, partial)) in updates.iter().enumerate() {
        append(
            &mut w,
            &update(med, partial),
            &format!("update-{i}"),
            i as u64 + 1,
            0,
            100 - i as i64,
        );
        if gap && i == 0 {
            w.gap(1, "gap-1", "synthetic bounded gap").unwrap();
        }
    }
    w.seal().unwrap();
    let v = VerifiedStore::load(
        &path,
        1_048_576,
        MrtLimits::default(),
        Limits::default(),
        MrtReplayOptions::default(),
    )
    .unwrap();
    (s, v)
}
fn profile(presence: &str, prefix: &str, asn: &str, coverage: &str) -> String {
    format!("schema=pcap-evidence.bgp.expectation-profile.v1\nprovenance=explicit-synthetic-caller\ntime_basis=source_occurrence_order\ncoverage={coverage}\nexpectation=row-1|{presence}|capture-a|capture-namespace-sha256:{}:captured-lifecycle:0|1|0|0|192.0.2.1|absent|0|1|1|{prefix}|absent|{asn}|unknown|unknown|unknown|unknown\n",sha256::hex(&[7;32]))
}
#[test]
fn repeated_occurrences_and_complete_changes_follow_source_order() {
    let (_s, v) = fixture(&[(1, false), (1, false), (9, false)], false);
    let out = v.changes(&Query::default(), &Limits::default()).unwrap();
    assert!(out.contains("unchanged_repeated_announcement"));
    assert!(out.contains("complete_attribute_identity_changed"));
    assert!(out.find("update-0").unwrap() < out.find("update-1").unwrap());
    assert!(out.find("update-1").unwrap() < out.find("update-2").unwrap());
    assert!(out.contains("\"route_installation_claimed\":false"));
}
#[test]
fn observed_match_supports_present_and_contradicts_absent_with_all_repeats() {
    let (_s, v) = fixture(&[(1, false), (1, false)], false);
    for (presence, status) in [("present", "supported"), ("absent", "contradicted")] {
        let p = ExpectationProfile::parse(
            profile(presence, "203.0.113.0/24", "origin:65001", "unknown").as_bytes(),
            &Limits::default(),
        )
        .unwrap();
        let out = v.expectations(&p, &Limits::default()).unwrap();
        assert!(out.contains(&format!("\"status\":\"{status}\"")));
        assert!(out.contains("update-0"));
        assert!(out.contains("update-1"));
        assert!(out.contains("\"verified_source_coverage\":\"unknown\""));
    }
}
#[test]
fn nonmatching_unknown_coverage_and_partial_attributes_remain_unresolved() {
    let (_s, v) = fixture(&[(1, false)], false);
    let p = ExpectationProfile::parse(
        profile("absent", "203.0.113.0/24", "origin:65002", "unknown").as_bytes(),
        &Limits::default(),
    )
    .unwrap();
    assert!(v
        .expectations(&p, &Limits::default())
        .unwrap()
        .contains("\"status\":\"unresolved\""));
    let (_s, v) = fixture(&[(1, true)], false);
    let p = ExpectationProfile::parse(
        profile(
            "absent",
            "203.0.113.0/24",
            "origin:65002",
            "caller_declared_complete",
        )
        .as_bytes(),
        &Limits::default(),
    )
    .unwrap();
    assert!(v
        .expectations(&p, &Limits::default())
        .unwrap()
        .contains("\"status\":\"unresolved\""));
}
#[test]
fn complete_coverage_declaration_remains_explicitly_conditional() {
    let (_s, v) = fixture(&[(1, false)], false);
    let p = ExpectationProfile::parse(
        profile(
            "absent",
            "203.0.113.0/24",
            "origin:65002",
            "caller_declared_complete",
        )
        .as_bytes(),
        &Limits::default(),
    )
    .unwrap();
    let out = v.expectations(&p, &Limits::default()).unwrap();
    assert!(out.contains("\"status\":\"supported\""));
    assert!(out.contains("conditional_on_caller_declared_complete_coverage"));
    assert!(out.contains("\"verified_source_coverage\":\"unknown\""));
}
#[test]
fn gaps_break_comparisons_and_block_conditional_absence() {
    let (_s, v) = fixture(&[(1, false), (1, false)], true);
    let out = v.changes(&Query::default(), &Limits::default()).unwrap();
    assert!(out.contains("\"kind\":\"gap\""));
    assert!(!out.contains("unchanged_repeated_announcement"));
    let p = ExpectationProfile::parse(
        profile(
            "absent",
            "203.0.113.0/24",
            "origin:65002",
            "caller_declared_complete",
        )
        .as_bytes(),
        &Limits::default(),
    )
    .unwrap();
    let out = v.expectations(&p, &Limits::default()).unwrap();
    assert!(out.contains("\"status\":\"unresolved\""));
    assert!(out.contains("gap-1"));
}
#[test]
fn empty_sealed_store_cannot_establish_absence() {
    let s = Scratch::new();
    let path = s.0.join("empty.store");
    JournalWriter::create(&path, "capture-a".into(), [7; 32], 4096, Limits::default())
        .unwrap()
        .seal()
        .unwrap();
    let v = VerifiedStore::load(
        &path,
        4096,
        MrtLimits::default(),
        Limits::default(),
        MrtReplayOptions::default(),
    )
    .unwrap();
    let p = ExpectationProfile::parse(
        profile(
            "absent",
            "203.0.113.0/24",
            "unknown",
            "caller_declared_complete",
        )
        .as_bytes(),
        &Limits::default(),
    )
    .unwrap();
    let out = v.expectations(&p, &Limits::default()).unwrap();
    assert!(out.contains("\"status\":\"unresolved\""));
    assert!(out.contains("no_observed_exact_scope"));
}
#[test]
fn strict_profiles_reject_aliases_duplicates_and_mixed_scope() {
    let valid = profile("present", "203.0.113.0/24", "origin:65001", "unknown");
    for invalid in [
        valid.replace("|1|0|0|", "|1|00|0|"),
        valid.replace("|absent|0|1|1|", "|checkpoint|0|1|1|"),
        valid.replace("203.0.113.0/24", "203.0.113.1/24"),
        valid.replace("origin:65001", "origin:0"),
        format!("{valid}coverage=unknown\n"),
        valid.replace('\n', "\r\n"),
    ] {
        assert!(ExpectationProfile::parse(invalid.as_bytes(), &Limits::default()).is_err());
    }
}
#[test]
fn exact_output_byte_boundary_and_one_below_are_distinct() {
    let (_s, v) = fixture(&[(1, false)], false);
    let p = ExpectationProfile::parse(
        profile("present", "203.0.113.0/24", "origin:65001", "unknown").as_bytes(),
        &Limits::default(),
    )
    .unwrap();
    let out = v.expectations(&p, &Limits::default()).unwrap();
    let mut limit = Limits {
        output_bytes: out.len(),
        ..Limits::default()
    };
    assert_eq!(v.expectations(&p, &limit).unwrap(), out);
    limit.output_bytes -= 1;
    assert!(v.expectations(&p, &limit).is_err());
    let out = v.changes(&Query::default(), &Limits::default()).unwrap();
    let mut limit = Limits {
        output_bytes: out.len(),
        ..Limits::default()
    };
    assert_eq!(v.changes(&Query::default(), &limit).unwrap(), out);
    limit.output_bytes -= 1;
    assert!(v.changes(&Query::default(), &limit).is_err());
}
#[test]
fn explicit_eor_reset_end_and_lifecycle_reuse_are_retained() {
    let s = Scratch::new();
    let path = s.0.join("boundaries.store");
    let mut w = JournalWriter::create(
        &path,
        "capture-a".into(),
        [7; 32],
        1_048_576,
        Limits::default(),
    )
    .unwrap();
    for d in [0, 1] {
        append(
            &mut w,
            &message(1, &[4, 0xfd, 0xe9, 0, 90, 192, 0, 2, d + 1, 0]),
            &format!("open-{d}"),
            100 + d as u64,
            d,
            10,
        );
    }
    append(&mut w, &update(1, false), "before-eor", 1, 0, 100);
    append(&mut w, &message(2, &[0, 0, 0, 0]), "eor", 2, 0, 101);
    w.reset(1, "explicit-reset", "synthetic reset").unwrap();
    w.end_session(1).unwrap();
    for d in [0, 1] {
        append(
            &mut w,
            &message(1, &[4, 0xfd, 0xe9, 0, 90, 192, 0, 2, d + 1, 0]),
            &format!("reopen-{d}"),
            110 + d as u64,
            d,
            11,
        );
    }
    append(&mut w, &update(1, false), "reused-session-update", 3, 0, 99);
    w.end_session(1).unwrap();
    w.seal().unwrap();
    let v = VerifiedStore::load(
        &path,
        1_048_576,
        MrtLimits::default(),
        Limits::default(),
        MrtReplayOptions::default(),
    )
    .unwrap();
    let out = v.changes(&Query::default(), &Limits::default()).unwrap();
    assert!(out.contains("\"kind\":\"end_of_rib\""));
    assert!(out.contains("\"kind\":\"reset\""));
    assert!(out.contains("\"kind\":\"end_session\""));
    assert!(out.contains("\"captured_lifecycle\":1"));
    assert!(!out.contains("unchanged_repeated_announcement"));
}
#[test]
fn exact_profile_input_and_work_admission_boundaries() {
    let text = profile("present", "203.0.113.0/24", "origin:65001", "unknown");
    let mut limit = Limits {
        input_bytes: text.len(),
        ..Limits::default()
    };
    assert!(ExpectationProfile::parse(text.as_bytes(), &limit).is_ok());
    limit.input_bytes -= 1;
    assert!(ExpectationProfile::parse(text.as_bytes(), &limit).is_err());
    let mut limit = Limits {
        work: text.len() * 6 + 4096,
        ..Limits::default()
    };
    assert!(ExpectationProfile::parse(text.as_bytes(), &limit).is_ok());
    limit.work -= 1;
    assert!(ExpectationProfile::parse(text.as_bytes(), &limit).is_err());
    let mut limit = Limits {
        retained_bytes: text.len() * 6 + 4096,
        ..Limits::default()
    };
    assert!(ExpectationProfile::parse(text.as_bytes(), &limit).is_ok());
    limit.retained_bytes -= 1;
    assert!(ExpectationProfile::parse(text.as_bytes(), &limit).is_err());
}
#[test]
fn scope_absence_tokens_and_lifecycle_are_exact() {
    let (_s, v) = fixture(&[(1, false)], false);
    for input in [
        profile(
            "present",
            "203.0.113.0/24",
            "origin:65001",
            "caller_declared_complete",
        )
        .replace("|192.0.2.1|absent|0|", "|absent|absent|0|"),
        profile(
            "present",
            "203.0.113.0/24",
            "origin:65001",
            "caller_declared_complete",
        )
        .replace(":captured-lifecycle:0", ":captured-lifecycle:1")
        .replace("|192.0.2.1|absent|0|", "|192.0.2.1|absent|1|"),
    ] {
        let p = ExpectationProfile::parse(input.as_bytes(), &Limits::default()).unwrap();
        let out = v.expectations(&p, &Limits::default()).unwrap();
        assert!(out.contains("\"status\":\"unresolved\""));
        assert!(out.contains("no_observed_exact_scope"));
    }
    let out = v
        .changes(
            &Query {
                source: Some("unrelated-source".into()),
                ..Query::default()
            },
            &Limits::default(),
        )
        .unwrap();
    assert!(out.contains("\"events\":[]"));
}
#[test]
fn changes_reject_terminal_row_selectors() {
    let (_s, v) = fixture(&[(1, false)], false);
    assert!(v
        .changes(
            &Query {
                status: Some("active".into()),
                ..Query::default()
            },
            &Limits::default()
        )
        .is_err());
    assert!(v
        .changes(
            &Query {
                version_index: Some(0),
                ..Query::default()
            },
            &Limits::default()
        )
        .is_err());
}
fn imported_update(width: usize, local_pref: bool) -> Vec<u8> {
    let mut attrs = vec![0x40, 1, 1, 0, 0x40, 2, (width + 2) as u8, 2, 1];
    if width == 2 {
        attrs.extend_from_slice(&65001u16.to_be_bytes());
    } else {
        attrs.extend_from_slice(&65001u32.to_be_bytes());
    }
    attrs.extend_from_slice(&[0x40, 3, 4, 192, 0, 2, 9]);
    if local_pref {
        attrs.extend_from_slice(&[0x40, 5, 4, 0, 0, 0, 100]);
    }
    let mut body = vec![0, 0];
    body.extend_from_slice(&(attrs.len() as u16).to_be_bytes());
    body.extend(attrs);
    body.extend_from_slice(&[24, 203, 0, 113]);
    message(2, &body)
}
fn imported_source(format: &str, gap: bool, sibling: bool) -> Vec<u8> {
    let open = |asn: u16, id: u8| {
        message(
            1,
            &[4, (asn >> 8) as u8, asn as u8, 0, 90, 192, 0, 2, id, 0],
        )
    };
    if format == "mrt" {
        let record = |peer: u8, subtype: u16, payload: &[u8]| {
            let mut body = vec![0xfd, 0xe9, 0xfd, 0xe8, 0, 7, 0, 1];
            body.extend_from_slice(&[192, 0, 2, peer, 192, 0, 2, 254]);
            body.extend_from_slice(payload);
            let mut out = 100u32.to_be_bytes().to_vec();
            out.extend_from_slice(&16u16.to_be_bytes());
            out.extend_from_slice(&subtype.to_be_bytes());
            out.extend_from_slice(&(body.len() as u32).to_be_bytes());
            out.extend(body);
            out
        };
        let mut records = vec![
            record(1, 0, &[0, 3, 0, 4]),
            record(1, 1, &open(65001, 1)),
            record(1, 6, &open(65000, 254)),
            record(1, 0, &[0, 4, 0, 5]),
            record(1, 0, &[0, 5, 0, 6]),
            record(1, 1, &imported_update(2, true)),
        ];
        if sibling {
            // A separate peer owns a separate canonical session/partition.
            // The opposite direction of peer 1 shares its Gap scope.
            records.extend([
                record(2, 0, &[0, 3, 0, 4]),
                record(2, 1, &open(65001, 2)),
                record(2, 6, &open(65000, 254)),
                record(2, 0, &[0, 4, 0, 5]),
                record(2, 0, &[0, 5, 0, 6]),
                record(2, 1, &imported_update(2, true)),
            ]);
        }
        if gap {
            records.push(record(1, 1, &imported_update(2, false)));
        }
        records.push(record(1, 1, &imported_update(2, true)));
        if sibling {
            records.push(record(2, 1, &imported_update(2, true)));
        }
        records.concat()
    } else {
        let peer = |flags: u8| {
            let mut p = vec![0, flags];
            p.extend_from_slice(&[0; 20]);
            p.extend_from_slice(&[192, 0, 2, 1]);
            p.extend_from_slice(&65001u32.to_be_bytes());
            p.extend_from_slice(&[192, 0, 2, 1]);
            p.extend_from_slice(&100u32.to_be_bytes());
            p.extend_from_slice(&0u32.to_be_bytes());
            p
        };
        let record = |kind: u8, payload: &[u8]| {
            let mut out = vec![3];
            out.extend_from_slice(&((6 + payload.len()) as u32).to_be_bytes());
            out.push(kind);
            out.extend_from_slice(payload);
            out
        };
        let rm = |flags: u8, complete: bool| {
            let mut body = peer(flags);
            body.extend(imported_update(4, complete));
            record(0, &body)
        };
        let mut up = peer(0);
        up.extend_from_slice(&[0; 12]);
        up.extend_from_slice(&[192, 0, 2, 254, 0, 179, 0x9c, 0x40]);
        up.extend(open(65000, 254));
        up.extend(open(65001, 1));
        let mut records = vec![record(3, &up), rm(0, true)];
        if sibling {
            records.push(rm(0x40, true));
        }
        if gap {
            records.push(rm(0, false));
        }
        records.push(rm(0, true));
        if sibling {
            records.push(rm(0x40, true));
        }
        records.concat()
    }
}
fn native_import_fixture(format: &str, gap: bool, sibling: bool) -> (Scratch, VerifiedStore) {
    use pcap_evidence_product::deep::{
        bgp::PeerRelationship,
        bgp_bmp::{BmpLimits, BmpSource},
        bgp_bmp_store,
        bgp_mrt::MrtSource,
        bgp_mrt_store,
    };
    let scratch = Scratch::new();
    let path = scratch.0.join("source.store");
    let bytes = imported_source(format, gap, sibling);
    let options = MrtReplayOptions {
        peer_relationship: Some(PeerRelationship::Internal),
    };
    if format == "mrt" {
        bgp_mrt_store::create_with_options(
            &path,
            &bytes,
            MrtSource {
                source_id: "collector".into(),
                checkpoint_id: "checkpoint-a".into(),
            },
            1_048_576,
            MrtLimits::default(),
            Limits::default(),
            options,
        )
        .unwrap();
    } else {
        bgp_bmp_store::create_with_options(
            &path,
            &bytes,
            BmpSource {
                source_id: "collector".into(),
                checkpoint_id: "checkpoint-a".into(),
            },
            1_048_576,
            BmpLimits::default(),
            Limits::default(),
            bgp_bmp_store::BmpReplayOptions {
                peer_relationship: options.peer_relationship,
            },
        )
        .unwrap();
    }
    let store = VerifiedStore::load(
        &path,
        1_048_576,
        MrtLimits::default(),
        Limits::default(),
        options,
    )
    .unwrap();
    (scratch, store)
}
#[test]
fn native_mrt_and_bmp_route_free_gaps_break_exact_predecessors() {
    for format in ["mrt", "bmp"] {
        let (_s, positive) = native_import_fixture(format, false, false);
        let out = positive
            .changes(&Query::default(), &Limits::default())
            .unwrap();
        assert!(
            out.contains("unchanged_repeated_announcement"),
            "{format}: {out}"
        );
        let (_s, negative) = native_import_fixture(format, true, false);
        let native_gap = negative
            .imported_source_events()
            .iter()
            .find(|e| {
                matches!(
                    e.kind,
                    pcap_evidence_product::deep::bgp_import::ImportedSourceEventKind::ContinuityGap
                ) && e.observation_index.is_some()
            })
            .expect("owning route-free native gap reaches typed archive");
        let observation = &negative.observations()[native_gap.observation_index.unwrap()];
        assert!(observation.routes().is_empty());
        let out = negative
            .changes(&Query::default(), &Limits::default())
            .unwrap();
        assert!(out.contains("ContinuityGap"), "{format}: {out}");
        assert!(
            !out.contains("unchanged_repeated_announcement"),
            "{format}: {out}"
        );
    }
}
#[test]
fn filtered_native_gap_cannot_bridge_selected_events_and_sibling_remains_valid() {
    for format in ["mrt", "bmp"] {
        let (_s, store) = native_import_fixture(format, true, true);
        let scopes: Vec<_> = store
            .observations()
            .iter()
            .filter(|observation| !observation.routes().is_empty())
            .filter_map(|observation| observation.import_context())
            .map(|context| pcap_evidence_product::deep::bgp_rib::RibScope {
                source:
                    pcap_evidence_product::deep::bgp_session::SourcePartition::from_import_context(
                        context,
                        &Limits::default(),
                    )
                    .unwrap(),
                session: context.session.clone(),
                generation: context.generation,
                direction: context.direction,
                peer: context.peer.clone(),
            })
            .collect();
        let main = &scopes[0];
        let sibling = scopes
            .iter()
            .find(|scope| scope.source != main.source || scope.session != main.session)
            .expect("sibling has an independent canonical partition or session");
        let effects: Vec<_> = store
            .imported_source_events()
            .iter()
            .flat_map(|event| &event.native_continuity)
            .filter(|effect| !effect.is_reset())
            .collect();
        assert!(effects.iter().any(|effect| effect.affects_scope(main)));
        assert!(effects.iter().all(|effect| !effect.affects_scope(sibling)));
        // A known nonmatching next hop excludes every announcement, but the
        // complete source predecessor/boundary walk still executes.
        let out = store
            .changes(
                &Query {
                    next_hop: Some("192.0.2.8".parse().unwrap()),
                    ..Query::default()
                },
                &Limits::default(),
            )
            .unwrap();
        assert!(out.contains("ContinuityGap"));
        assert!(!out.contains("unchanged_repeated_announcement"));
        let all = store
            .changes(&Query::default(), &Limits::default())
            .unwrap();
        assert_eq!(
            all.matches("unchanged_repeated_announcement").count(),
            1,
            "one exact sibling remains continuous: {format}: {all}"
        );
    }
}
#[test]
fn captured_partition_profile_copies_query_native_partition_exactly() {
    let (_s, store) = fixture(&[(1, false)], false);
    let partition = format!(
        "capture-namespace-sha256:{}:captured-lifecycle:0",
        sha256::hex(&[7; 32])
    );
    let query = Query {
        partition: Some(partition.clone()),
        prefix: Some("203.0.113.0/24".into()),
        ..Query::default()
    };
    assert!(store
        .query(&query, &Limits::default())
        .unwrap()
        .contains(&partition));
    assert!(store
        .changes(&query, &Limits::default())
        .unwrap()
        .contains("\"kind\":\"announce\""));
    let p = ExpectationProfile::parse(
        profile("present", "203.0.113.0/24", "origin:65001", "unknown").as_bytes(),
        &Limits::default(),
    )
    .unwrap();
    assert!(store
        .expectations(&p, &Limits::default())
        .unwrap()
        .contains("\"status\":\"supported\""));
    let invalid = profile("present", "203.0.113.0/24", "origin:65001", "unknown")
        .replace(":captured-lifecycle:0", ":captured-lifecycle:1");
    assert!(ExpectationProfile::parse(invalid.as_bytes(), &Limits::default()).is_err());
}
#[test]
fn unknown_generation_boundary_remains_uncertain_after_first_observed_generation() {
    let scratch = Scratch::new();
    let path = scratch.0.join("initial-gap.store");
    let mut writer = JournalWriter::create(
        &path,
        "capture-a".into(),
        [7; 32],
        1_048_576,
        Limits::default(),
    )
    .unwrap();
    writer
        .gap(1, "gap-before-generation", "synthetic initial gap")
        .unwrap();
    for d in [0, 1] {
        append(
            &mut writer,
            &message(1, &[4, 0xfd, 0xe9, 0, 90, 192, 0, 2, d + 1, 0]),
            &format!("open-{d}"),
            100 + d as u64,
            d,
            10,
        );
    }
    append(&mut writer, &update(1, false), "valid-after-gap", 1, 0, 100);
    writer.seal().unwrap();
    let store = VerifiedStore::load(
        &path,
        1_048_576,
        MrtLimits::default(),
        Limits::default(),
        MrtReplayOptions::default(),
    )
    .unwrap();
    assert_eq!(store.captured_source_events()[0].scopes[0].generation, None);
    let p = ExpectationProfile::parse(
        profile(
            "absent",
            "203.0.113.0/24",
            "origin:65002",
            "caller_declared_complete",
        )
        .as_bytes(),
        &Limits::default(),
    )
    .unwrap();
    let out = store.expectations(&p, &Limits::default()).unwrap();
    assert!(out.contains("\"status\":\"unresolved\""));
    assert!(out.contains("gap-before-generation"));
}
#[test]
fn changes_preserves_unknown_field_availability_despite_another_known_no() {
    use pcap_evidence_product::deep::bgp_evidence::{AsnRole, AsnSelector};
    let scratch = Scratch::new();
    let path = scratch.0.join("as-set.store");
    let mut writer = JournalWriter::create(
        &path,
        "capture-a".into(),
        [7; 32],
        1_048_576,
        Limits::default(),
    )
    .unwrap();
    for d in [0, 1] {
        append(
            &mut writer,
            &message(1, &[4, 0xfd, 0xe9, 0, 90, 192, 0, 2, d + 1, 0]),
            &format!("open-{d}"),
            100 + d as u64,
            d,
            10,
        );
    }
    let mut set = update(1, false);
    set[30] = 1;
    append(&mut writer, &set, "as-set-route", 1, 0, 100);
    writer.seal().unwrap();
    let store = VerifiedStore::load(
        &path,
        1_048_576,
        MrtLimits::default(),
        Limits::default(),
        MrtReplayOptions::default(),
    )
    .unwrap();
    let out = store
        .changes(
            &Query {
                asn: Some(AsnSelector {
                    asn: 65001,
                    role: AsnRole::Origin,
                }),
                next_hop: Some("192.0.2.8".parse().unwrap()),
                ..Query::default()
            },
            &Limits::default(),
        )
        .unwrap();
    assert!(out.contains("unresolved_asn"));
    assert!(out.contains("\"match_disposition\":\"not_matched\""));
    assert!(!out.contains("\"kind\":\"announce\""));
    assert!(out.contains("\"source_coverage\":\"unknown\""));
}
#[test]
fn profile_file_read_admits_input_work_and_retained_before_reading() {
    let scratch = Scratch::new();
    let path = scratch.0.join("profile.txt");
    let text = profile("present", "203.0.113.0/24", "origin:65001", "unknown");
    fs::write(&path, &text).unwrap();
    for target in ["input", "work", "retained"] {
        let mut limit = Limits::default();
        let exact = if target == "input" {
            text.len()
        } else {
            text.len() * 6 + 4096
        };
        match target {
            "input" => limit.input_bytes = exact,
            "work" => limit.work = exact,
            _ => limit.retained_bytes = exact,
        };
        assert!(ExpectationProfile::read(&path, &limit).is_ok());
        match target {
            "input" => limit.input_bytes -= 1,
            "work" => limit.work -= 1,
            _ => limit.retained_bytes -= 1,
        };
        assert!(ExpectationProfile::read(&path, &limit).is_err());
    }
}
fn aggregate_spans(output: &str) -> usize {
    use std::process::Command;
    let python = std::env::var("PYTHON").unwrap_or_else(|_| {
        if cfg!(windows) {
            "python".into()
        } else {
            "python3".into()
        }
    });
    let program="import json,sys\ndef count(v):\n if isinstance(v,list): return sum(map(count,v))\n if isinstance(v,dict): return sum(count(x)+(len(x) if k in ('spans','packets','provenance','ranges') and isinstance(x,list) else 0) for k,x in v.items())\n return 0\nprint(count(json.loads(sys.argv[1])))";
    let run = Command::new(python)
        .args(["-c", program, output])
        .output()
        .unwrap();
    assert!(
        run.status.success(),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );
    String::from_utf8(run.stdout)
        .unwrap()
        .trim()
        .parse()
        .unwrap()
}
#[test]
fn both_outputs_admit_aggregate_span_references_at_exact_and_one_below() {
    let (_scratch, store) = fixture(&[(1, false)], false);
    let changes = store
        .changes(&Query::default(), &Limits::default())
        .unwrap();
    let spans = aggregate_spans(&changes);
    assert!(spans > 1);
    let mut limits = Limits {
        spans,
        ..Limits::default()
    };
    assert_eq!(store.changes(&Query::default(), &limits).unwrap(), changes);
    limits.spans -= 1;
    let error = store.changes(&Query::default(), &limits).unwrap_err();
    assert!(
        error.to_string().contains("bgp_analysis_spans"),
        "owning aggregate span guard: {error}"
    );
    // The captured match has journal coordinates but no counted packet span
    // arrays in this projection. Use owning native imported provenance instead.
    let (_import_scratch, imported) = native_import_fixture("mrt", false, false);
    let o = imported
        .observations()
        .iter()
        .find(|o| !o.routes().is_empty())
        .unwrap();
    let context = o.import_context().unwrap();
    let partition = pcap_evidence_product::deep::bgp_session::SourcePartition::from_import_context(
        context,
        &Limits::default(),
    )
    .unwrap();
    let text = format!(
        "schema=pcap-evidence.bgp.expectation-profile.v1\nprovenance=finite-native-source\ntime_basis=source_occurrence_order\ncoverage=unknown\nexpectation=native-present|present|{}|{}|{}|{}|{}|{}|{}|absent|1|1|203.0.113.0/24|absent|origin:65001|unknown|unknown|unknown|unknown\n",
        context.source_id, partition.partition_id, context.session, context.generation,
        context.direction.map_or_else(|| "absent".into(), |d| d.to_string()),
        context.peer.as_deref().unwrap_or("absent"), context.checkpoint_id,
    );
    let p = ExpectationProfile::parse(text.as_bytes(), &Limits::default()).unwrap();
    let expected = imported.expectations(&p, &Limits::default()).unwrap();
    assert!(expected.contains("\"status\":\"supported\""));
    let spans = aggregate_spans(&expected);
    assert!(spans > 1);
    let mut limits = Limits {
        spans,
        ..Limits::default()
    };
    assert_eq!(imported.expectations(&p, &limits).unwrap(), expected);
    limits.spans -= 1;
    let error = imported.expectations(&p, &limits).unwrap_err();
    assert!(
        error.to_string().contains("bgp_analysis_spans"),
        "owning aggregate span guard: {error}"
    );
}

#[test]
fn selected_a_unselected_b_selected_a_uses_b_as_exact_predecessor() {
    use pcap_evidence_product::deep::bgp_evidence::{AsnRole, AsnSelector};
    let scratch = Scratch::new();
    let path = scratch.0.join("filtered-predecessor.store");
    let mut writer = JournalWriter::create(
        &path,
        "capture-a".into(),
        [7; 32],
        1_048_576,
        Limits::default(),
    )
    .unwrap();
    for d in [0, 1] {
        append(
            &mut writer,
            &message(1, &[4, 0xfd, 0xe9, 0, 90, 192, 0, 2, d + 1, 0]),
            &format!("open-{d}"),
            100 + d as u64,
            d,
            10,
        );
    }
    append(&mut writer, &update(1, false), "selected-a1", 1, 0, 100);
    let mut middle = update(1, false);
    middle[32..34].copy_from_slice(&65002u16.to_be_bytes());
    append(&mut writer, &middle, "unselected-b", 2, 0, 101);
    append(&mut writer, &update(1, false), "selected-a2", 3, 0, 102);
    writer.seal().unwrap();
    let store = VerifiedStore::load(
        &path,
        1_048_576,
        MrtLimits::default(),
        Limits::default(),
        MrtReplayOptions::default(),
    )
    .unwrap();
    let output = store
        .changes(
            &Query {
                asn: Some(AsnSelector {
                    asn: 65001,
                    role: AsnRole::Origin,
                }),
                ..Query::default()
            },
            &Limits::default(),
        )
        .unwrap();
    assert!(!output.contains("unchanged_repeated_announcement"));
    let python = std::env::var("PYTHON").unwrap_or_else(|_| {
        if cfg!(windows) {
            "python".into()
        } else {
            "python3".into()
        }
    });
    let program="import json,sys; e=[x for x in json.loads(sys.argv[1])['events'] if x['kind']=='announce']; assert len(e)==2; assert e[-1]['reference']['record_id']=='selected-a2'; assert e[-1]['before_reference']['observation']['record_id']=='unselected-b'; assert e[-1]['before_reference']['route_index']==0; assert e[-1]['difference']=='complete_attribute_identity_changed'";
    let run = std::process::Command::new(python)
        .args(["-c", program, &output])
        .output()
        .unwrap();
    assert!(
        run.status.success(),
        "{}\n{output}",
        String::from_utf8_lossy(&run.stderr)
    );
}
#[test]
fn missing_reported_time_and_attribute_no_preserve_availability_without_fabricating_mismatches() {
    use pcap_evidence_product::deep::{
        bgp_import::ClockPolicy,
        bgp_persisted::query::{PrefixRelation, PrefixSelector, ReportedTimeWindow},
    };
    let scratch = Scratch::new();
    let path = scratch.0.join("no-time.store");
    let mut writer = JournalWriter::create(
        &path,
        "capture-a".into(),
        [7; 32],
        1_048_576,
        Limits::default(),
    )
    .unwrap();
    for d in [0, 1] {
        append(
            &mut writer,
            &message(1, &[4, 0xfd, 0xe9, 0, 90, 192, 0, 2, d + 1, 0]),
            &format!("open-{d}"),
            100 + d as u64,
            d,
            10,
        );
    }
    append_optional_time(&mut writer, &update(1, false), "no-time-route", 1, 0, None);
    writer.seal().unwrap();
    let store = VerifiedStore::load(
        &path,
        1_048_576,
        MrtLimits::default(),
        Limits::default(),
        MrtReplayOptions::default(),
    )
    .unwrap();
    let window = ReportedTimeWindow {
        source: "capture-a".into(),
        clock_policy: ClockPolicy::SourceLabel,
        clock_id: format!("capture:{}", sha256::hex(&[7; 32])),
        start_ns: 0,
        end_ns: 1000,
    };
    let mut query = Query {
        next_hop: Some("192.0.2.8".parse().unwrap()),
        time_window: Some(window.clone()),
        prefix_selector: Some(
            PrefixSelector::parse("203.0.113.0/24", PrefixRelation::Exact).unwrap(),
        ),
        ..Query::default()
    };
    let output = store.changes(&query, &Limits::default()).unwrap();
    assert!(output.contains("missing_reported_clock_or_time"));
    assert!(output.contains("\"match_disposition\":\"not_matched\""));
    assert!(!output.contains("\"kind\":\"announce\""));
    assert!(!output.contains("unsupported_prefix"));
    query.time_window.as_mut().unwrap().source = "other-source".into();
    let output = store.changes(&query, &Limits::default()).unwrap();
    assert!(!output.contains("missing_reported_clock_or_time"));
    let (_known_scratch, known) = fixture(&[(1, false)], false);
    query.time_window = Some(window);
    query.time_window.as_mut().unwrap().clock_id = "other-clock".into();
    let output = known.changes(&query, &Limits::default()).unwrap();
    assert!(!output.contains("missing_reported_clock_or_time"));
    assert!(!output.contains("\"kind\":\"announce\""));
    query.time_window.as_mut().unwrap().clock_id = format!("capture:{}", sha256::hex(&[7; 32]));
    query.next_hop = Some("192.0.2.9".parse().unwrap());
    let output = known.changes(&query, &Limits::default()).unwrap();
    assert!(output.contains("\"kind\":\"announce\""));
    assert!(!output.contains("missing_reported_clock_or_time"));
    assert!(!output.contains("unsupported_prefix"));
}

// Sealed native captured effect regressions: no new carrier API is required
// to compile these against the pre-repair source. The direct typed producer
// trace proves fixture reachability; analysis expectations come from the
// continuity contract and the explicit source occurrence sequence.
struct CapturedEffectRecord {
    session: u64,
    record: String,
    frame: u64,
    direction: u8,
    bytes: Vec<u8>,
}
fn effect_record(
    session: u64,
    record: &str,
    frame: u64,
    direction: u8,
    bytes: Vec<u8>,
) -> CapturedEffectRecord {
    CapturedEffectRecord {
        session,
        record: record.into(),
        frame,
        direction,
        bytes,
    }
}
fn effect_open() -> Vec<u8> {
    message(1, &[4, 0xfd, 0xe9, 0, 90, 192, 0, 2, 1, 0])
}
fn effect_opens(session: u64, frame: u64) -> Vec<CapturedEffectRecord> {
    vec![
        effect_record(
            session,
            &format!("session-{session}-open-0"),
            frame,
            0,
            effect_open(),
        ),
        effect_record(
            session,
            &format!("session-{session}-open-1"),
            frame + 1,
            1,
            effect_open(),
        ),
    ]
}
fn mp_opaque_effect_update() -> Vec<u8> {
    // Complete legacy attribute encodings plus unsupported MP family25/1,
    // with MP NLRI retained as opaque. No ordinary NLRI occurs in this record.
    let mut attrs = vec![
        0x40, 1, 1, 0, 0x40, 2, 4, 2, 1, 0xfd, 0xe9, 0x40, 3, 4, 192, 0, 2, 9,
    ];
    attrs.extend_from_slice(&[0x80, 14, 13, 0, 25, 1, 4, 192, 0, 2, 9, 0, 24, 203, 0, 113]);
    let mut body = vec![0, 0];
    body.extend_from_slice(&(attrs.len() as u16).to_be_bytes());
    body.extend(attrs);
    message(2, &body)
}
struct NativeGapProof {
    record: String,
    reason: String,
    session: String,
    generation: u64,
}
fn sealed_captured_effect_fixture(
    records: Vec<CapturedEffectRecord>,
) -> (Scratch, VerifiedStore, Vec<NativeGapProof>, usize) {
    use pcap_evidence_product::deep::{
        bgp_pipeline::CapturedSessionPipeline, bgp_rib::RibEventKind,
    };
    let scratch = Scratch::new();
    let path = scratch.0.join("native-effects.store");
    let mut writer = JournalWriter::create(
        &path,
        "capture-a".into(),
        [7; 32],
        1_048_576,
        Limits::default(),
    )
    .unwrap();
    let mut pipelines = std::collections::BTreeMap::new();
    let mut gaps = Vec::new();
    let mut inert_replays = 0;
    for r in records {
        let evidence = EvidenceBytes::from_packet(
            &r.bytes,
            PacketId {
                capture: [7; 32],
                frame: r.frame,
                record_offset: r.frame * 100,
            },
            0,
        );
        let metadata = PcapMetadata {
            source_id: "capture-a".into(),
            record_id: r.record.clone(),
            observed_at_ns: Some(r.frame as i64),
            session: Some(r.session),
            direction: Some(r.direction),
            peer: Some("192.0.2.1".into()),
            local: Some("192.0.2.100".into()),
        };
        let pipeline = pipelines.entry(r.session).or_insert_with(|| {
            CapturedSessionPipeline::new([7; 32], "capture-a".into(), r.session, Limits::default())
                .unwrap()
        });
        let before = pipeline.rib().events().len();
        let gap_before = pipeline.rib().gaps().len();
        let receipt = pipeline.apply_message(&evidence, metadata.clone()).unwrap();
        if receipt.replayed {
            inert_replays += 1;
            assert_eq!(
                pipeline.rib().events().len(),
                before,
                "immutable old source replay must be natively inert"
            );
        }
        for event in &pipeline.rib().events()[before..] {
            if let RibEventKind::Gap { reason } = &event.kind {
                gaps.push(NativeGapProof {
                    record: event.record_id.clone(),
                    reason: reason.clone(),
                    session: event.scope.session.clone(),
                    generation: event.scope.generation,
                });
            }
        }
        // An applied identity collision may quarantine without appending a
        // new immutable native event. Its actual gap index is still evidence.
        for (scope, record) in &pipeline.rib().gaps()[gap_before..] {
            if !gaps.iter().any(|g| g.record == *record) {
                gaps.push(NativeGapProof {
                    record: record.clone(),
                    reason: "native_quarantine_without_new_event".into(),
                    session: scope.session.clone(),
                    generation: scope.generation,
                });
            }
        }
        writer.message(r.session, &evidence, &metadata).unwrap();
    }
    writer.seal().unwrap();
    let store = VerifiedStore::load(
        &path,
        1_048_576,
        MrtLimits::default(),
        Limits::default(),
        MrtReplayOptions::default(),
    )
    .unwrap();
    (scratch, store, gaps, inert_replays)
}
fn decoded_gap_absence(store: &VerifiedStore) -> String {
    let p = ExpectationProfile::parse(
        profile(
            "absent",
            "203.0.113.0/24",
            "origin:65002",
            "caller_declared_complete",
        )
        .as_bytes(),
        &Limits::default(),
    )
    .unwrap();
    store.expectations(&p, &Limits::default()).unwrap()
}
#[test]
fn captured_decoded_gap_mp_opaque_breaks_sealed_source_predecessor() {
    let mut records = effect_opens(1, 100);
    records.push(effect_record(1, "before-mp-gap", 1, 0, update(1, false)));
    records.push(effect_record(
        1,
        "mp-native-gap",
        2,
        0,
        mp_opaque_effect_update(),
    ));
    records.push(effect_record(1, "after-mp-gap", 3, 0, update(1, false)));
    let (_scratch, store, gaps, _) = sealed_captured_effect_fixture(records);
    assert_eq!(gaps.len(), 1);
    assert_eq!(gaps[0].reason, "decoded_update_opaque_route_evidence");
    assert_eq!(gaps[0].session, "1");
    assert_eq!(gaps[0].generation, 0);
    assert!(store
        .observations()
        .iter()
        .find(|o| o.source().record_id == "mp-native-gap")
        .unwrap()
        .routes()
        .is_empty());
    let output = store
        .changes(&Query::default(), &Limits::default())
        .unwrap();
    assert!(
        !output.contains("unchanged_repeated_announcement"),
        "same sealed source cannot compare across actual native Gap: {output}"
    );
    assert!(
        output.contains("decoded_update_opaque_route_evidence"),
        "actual native barrier witness retained: {output}"
    );
}
#[test]
fn captured_decoded_gap_ordinary_before_first_route_blocks_conditional_absence() {
    // Unilateral ADD-PATH send advertisement leaves ordinary IPv4 layout
    // unresolved; the producer retains this UPDATE as route-free opaque NLRI.
    let unilateral = message(
        1,
        &[
            4, 0xfd, 0xe9, 0, 90, 192, 0, 2, 1, 8, 2, 6, 69, 4, 0, 1, 1, 2,
        ],
    );
    let records = vec![
        effect_record(1, "unilateral-addpath-open", 100, 0, unilateral),
        effect_record(1, "ordinary-native-gap", 1, 0, update(1, false)),
    ];
    let (_scratch, store, gaps, _) = sealed_captured_effect_fixture(records);
    assert_eq!(gaps.len(), 1);
    assert_eq!(gaps[0].record, "ordinary-native-gap");
    assert_eq!(gaps[0].reason, "decoded_update_opaque_route_evidence");
    assert!(store.observations().iter().all(|o| o.routes().is_empty()));
    let output = decoded_gap_absence(&store);
    assert!(
        output.contains("\"status\":\"unresolved\""),
        "opaque ordinary source Gap is not caller-conditional absence proof: {output}"
    );
    assert!(output.contains("ordinary-native-gap"));
}
#[test]
fn captured_decoded_gap_mp_before_first_route_blocks_conditional_absence() {
    let mut records = effect_opens(1, 100);
    records.push(effect_record(
        1,
        "early-mp-gap",
        1,
        0,
        mp_opaque_effect_update(),
    ));
    records.push(effect_record(1, "first-after-gap", 2, 0, update(1, false)));
    let (_scratch, store, gaps, _) = sealed_captured_effect_fixture(records);
    assert_eq!(gaps.len(), 1);
    let output = decoded_gap_absence(&store);
    assert!(
        output.contains("\"status\":\"unresolved\""),
        "before-first-route native Gap remains uncertainty: {output}"
    );
    assert!(output.contains("early-mp-gap"));
}
#[test]
fn captured_decoded_gap_contradictory_open_is_actual_bilateral_uncertainty() {
    let mut records = effect_opens(1, 100);
    records.push(effect_record(
        1,
        "before-open-conflict",
        1,
        0,
        update(1, false),
    ));
    let mut changed = effect_open();
    changed[23] = 91;
    records.push(effect_record(1, "contradictory-open", 2, 0, changed));
    let (_scratch, store, gaps, _) = sealed_captured_effect_fixture(records);
    assert_eq!(gaps.len(), 1);
    assert_eq!(gaps[0].reason, "captured_open_content_contradiction");
    let output = decoded_gap_absence(&store);
    assert!(
        output.contains("\"status\":\"unresolved\""),
        "actual contradictory OPEN native Gap remains uncertainty: {output}"
    );
    assert!(output.contains("contradictory-open"));
}
#[test]
fn captured_decoded_gap_identity_conflict_preserves_native_quarantine_uncertainty() {
    let mut records = effect_opens(1, 100);
    records.push(effect_record(
        1,
        "same-source-identity",
        1,
        0,
        update(1, false),
    ));
    records.push(effect_record(
        1,
        "same-source-identity",
        2,
        0,
        update(9, false),
    ));
    let (_scratch, store, gaps, _) = sealed_captured_effect_fixture(records);
    assert_eq!(gaps.len(), 1);
    assert_eq!(gaps[0].record, "same-source-identity");
    let output = decoded_gap_absence(&store);
    assert!(
        output.contains("\"status\":\"unresolved\""),
        "native identity conflict is uncertainty: {output}"
    );
}
#[test]
fn captured_decoded_gap_does_not_clear_unrelated_captured_session() {
    let mut records = effect_opens(1, 100);
    records.extend(effect_opens(2, 200));
    records.push(effect_record(1, "session1-before", 1, 0, update(1, false)));
    records.push(effect_record(2, "session2-before", 2, 0, update(1, false)));
    records.push(effect_record(
        1,
        "session1-mp-gap",
        3,
        0,
        mp_opaque_effect_update(),
    ));
    records.push(effect_record(1, "session1-after", 4, 0, update(1, false)));
    records.push(effect_record(2, "session2-after", 5, 0, update(1, false)));
    let (_scratch, store, gaps, _) = sealed_captured_effect_fixture(records);
    assert_eq!(gaps.len(), 1);
    assert_eq!(gaps[0].session, "1");
    let output = store
        .changes(&Query::default(), &Limits::default())
        .unwrap();
    assert_eq!(
        output.matches("unchanged_repeated_announcement").count(),
        1,
        "only unrelated session remains continuous: {output}"
    );
}
#[test]
fn captured_decoded_gap_immutable_replay_does_not_reapply_old_barrier() {
    let mut records = effect_opens(1, 100);
    records.push(effect_record(
        1,
        "before-replayed-gap",
        1,
        0,
        update(1, false),
    ));
    records.push(effect_record(
        1,
        "immutable-gap",
        2,
        0,
        mp_opaque_effect_update(),
    ));
    records.push(effect_record(1, "after-first-gap", 3, 0, update(1, false)));
    records.push(effect_record(
        1,
        "immutable-gap",
        2,
        0,
        mp_opaque_effect_update(),
    ));
    records.push(effect_record(
        1,
        "after-inert-replay",
        4,
        0,
        update(1, false),
    ));
    let (_scratch, store, gaps, replays) = sealed_captured_effect_fixture(records);
    assert_eq!(gaps.len(), 1);
    assert_eq!(replays, 1);
    let output = store
        .changes(&Query::default(), &Limits::default())
        .unwrap();
    assert_eq!(
        output.matches("unchanged_repeated_announcement").count(),
        1,
        "only post-gap immutable replay repeat remains comparable: {output}"
    );
    let python = std::env::var("PYTHON").unwrap_or_else(|_| {
        if cfg!(windows) {
            "python".into()
        } else {
            "python3".into()
        }
    });
    let program="import json,sys; e={x['reference']['record_id']:x for x in json.loads(sys.argv[1])['events'] if x['kind']=='announce'}; assert e['after-first-gap']['before_reference'] is None; assert e['after-inert-replay']['before_reference']['observation']['record_id']=='after-first-gap'";
    let run = std::process::Command::new(python)
        .args(["-c", program, &output])
        .output()
        .unwrap();
    assert!(
        run.status.success(),
        "{}\n{output}",
        String::from_utf8_lossy(&run.stderr)
    );
}
#[test]
fn captured_decoded_gap_valid_empty_non_eor_and_eor_controls_preserve_continuity() {
    for (label, control, eor) in [
        (
            "empty-non-eor",
            message(2, &[0, 0, 0, 4, 0x40, 1, 1, 0]),
            false,
        ),
        ("explicit-eor", message(2, &[0, 0, 0, 0]), true),
    ] {
        let mut records = effect_opens(1, 100);
        records.push(effect_record(
            1,
            "before-valid-control",
            1,
            0,
            update(1, false),
        ));
        records.push(effect_record(1, label, 2, 0, control));
        records.push(effect_record(
            1,
            "after-valid-control",
            3,
            0,
            update(1, false),
        ));
        let (_scratch, store, gaps, _) = sealed_captured_effect_fixture(records);
        assert!(gaps.is_empty());
        let o = store
            .observations()
            .iter()
            .find(|o| o.source().record_id == label)
            .unwrap();
        assert!(o.routes().is_empty());
        assert_eq!(!o.end_of_rib_families().unwrap().unwrap().is_empty(), eor);
        let output = store
            .changes(&Query::default(), &Limits::default())
            .unwrap();
        assert_eq!(
            output.matches("unchanged_repeated_announcement").count(),
            1,
            "valid control preserves comparable source: {output}"
        );
        let expected = decoded_gap_absence(&store);
        assert!(expected.contains("conditional_on_caller_declared_complete_coverage"));
        assert!(expected.contains("\"status\":\"supported\""));
        assert!(expected.contains("\"verified_source_coverage\":\"unknown\""));
    }
}

#[test]
fn captured_decoded_gap_native_session_generation_includes_opposite_direction() {
    let mut records = effect_opens(1, 100);
    records.push(effect_record(
        1,
        "opposite-before-gap",
        1,
        1,
        update(1, false),
    ));
    records.push(effect_record(
        1,
        "reporting-direction-gap",
        2,
        0,
        mp_opaque_effect_update(),
    ));
    records.push(effect_record(
        1,
        "opposite-after-gap",
        3,
        1,
        update(1, false),
    ));
    let (_scratch, store, gaps, _) = sealed_captured_effect_fixture(records);
    assert_eq!(gaps.len(), 1);
    assert_eq!(gaps[0].reason, "decoded_update_opaque_route_evidence");
    let query = Query {
        direction: Some(1),
        ..Query::default()
    };
    let output = store.changes(&query, &Limits::default()).unwrap();
    assert!(
        !output.contains("unchanged_repeated_announcement"),
        "{output}"
    );
    assert!(
        output.contains("decoded_update_opaque_route_evidence"),
        "native whole-generation boundary must remain selected: {output}"
    );
    let text = profile(
        "absent",
        "203.0.113.0/24",
        "origin:65002",
        "caller_declared_complete",
    )
    .replace("|0|192.0.2.1|", "|1|192.0.2.1|");
    let expectation = ExpectationProfile::parse(text.as_bytes(), &Limits::default()).unwrap();
    let output = store
        .expectations(&expectation, &Limits::default())
        .unwrap();
    assert!(output.contains("\"status\":\"unresolved\""), "{output}");
}

#[test]
fn captured_decoded_gap_protocol_reset_vetoes_predecessor_generation_absence() {
    let mut records = effect_opens(1, 100);
    records.push(effect_record(
        1,
        "before-native-reset",
        1,
        0,
        update(1, false),
    ));
    records.push(effect_record(
        1,
        "protocol-notification-reset",
        2,
        1,
        message(3, &[6, 0]),
    ));
    let (_scratch, store, gaps, _) = sealed_captured_effect_fixture(records);
    assert!(gaps.is_empty(), "a Reset must retain its exact kind");
    let boundary = store
        .captured_source_events()
        .iter()
        .find_map(|event| event.continuity.as_ref())
        .expect("the actual protocol reset effect must survive sealed replay");
    assert!(boundary.decision.is_reset());
    assert_eq!(boundary.decision.generations(), (0, 1));
    assert!(boundary.decision.newly_applied);
    let output = decoded_gap_absence(&store);
    assert!(output.contains("\"status\":\"unresolved\""), "{output}");
    assert!(output.contains("decoded_reset"), "{output}");
    let output = store
        .changes(&Query::default(), &Limits::default())
        .unwrap();
    assert!(output.contains("decoded_reset"), "{output}");
}

#[test]
fn captured_decoded_gap_boundary_outputs_admit_exact_and_one_below_spans() {
    let mut records = effect_opens(1, 100);
    records.push(effect_record(
        1,
        "bounded-native-gap",
        1,
        0,
        mp_opaque_effect_update(),
    ));
    records.push(effect_record(
        1,
        "bounded-native-gap-2",
        2,
        0,
        mp_opaque_effect_update(),
    ));
    records.push(effect_record(
        1,
        "bounded-after-gap",
        3,
        0,
        update(1, false),
    ));
    let (_scratch, store, gaps, _) = sealed_captured_effect_fixture(records);
    assert_eq!(gaps.len(), 2);
    let text = profile(
        "absent",
        "203.0.113.0/24",
        "origin:65002",
        "caller_declared_complete",
    );
    let profile = ExpectationProfile::parse(text.as_bytes(), &Limits::default()).unwrap();
    for expectation_mode in [false, true] {
        let output = if expectation_mode {
            store.expectations(&profile, &Limits::default()).unwrap()
        } else {
            store
                .changes(&Query::default(), &Limits::default())
                .unwrap()
        };
        let spans = aggregate_spans(&output);
        assert!(
            spans > 1,
            "native captured boundary packet spans must be projected"
        );
        let mut limits = Limits {
            spans,
            ..Limits::default()
        };
        let exact = if expectation_mode {
            store.expectations(&profile, &limits).unwrap()
        } else {
            store.changes(&Query::default(), &limits).unwrap()
        };
        assert_eq!(exact, output);
        limits.spans -= 1;
        let error = if expectation_mode {
            store.expectations(&profile, &limits).unwrap_err()
        } else {
            store.changes(&Query::default(), &limits).unwrap_err()
        };
        assert!(
            error.to_string().contains("bgp_analysis_spans"),
            "owning aggregate span guard: {error}"
        );
    }
}
