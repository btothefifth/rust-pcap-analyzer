//! Tiny independently constructed journals exercise selector behavior at sealed replay.
use pcap_evidence::provenance::{EvidenceBytes, PacketId};
use pcap_evidence_product::deep::{
    bgp::PcapMetadata,
    bgp_import::ClockPolicy,
    bgp_mrt::MrtLimits,
    bgp_mrt_store::MrtReplayOptions,
    bgp_persisted::{
        AsnRole, AsnSelector, AttributeScope, PrefixRelation, PrefixSelector, Query,
        ReportedTimeWindow, VerifiedStore,
    },
    bgp_store::JournalWriter,
    Limits,
};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
};
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "bgp-selectors-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
fn envelope(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut bytes = vec![255; 16];
    bytes.extend_from_slice(&((19 + body.len()) as u16).to_be_bytes());
    bytes.push(kind);
    bytes.extend_from_slice(body);
    bytes
}
fn update(asn: u16, community: u16, large: [u32; 3], next_hop: [u8; 4]) -> Vec<u8> {
    let mut attributes = vec![0x40, 1, 1, 0, 0x40, 2, 4, 2, 1];
    attributes.extend_from_slice(&asn.to_be_bytes());
    attributes.extend_from_slice(&[0x40, 3, 4]);
    attributes.extend_from_slice(&next_hop);
    attributes.extend_from_slice(&[0xc0, 8, 4, 0xfc, 0x00]);
    attributes.extend_from_slice(&community.to_be_bytes());
    attributes.extend_from_slice(&[0xc0, 32, 12]);
    for v in large {
        attributes.extend_from_slice(&v.to_be_bytes());
    }
    let mut body = vec![0, 0];
    body.extend_from_slice(&(attributes.len() as u16).to_be_bytes());
    body.extend(attributes);
    body.extend_from_slice(&[24, 203, 0, 113]);
    envelope(2, &body)
}
fn message(writer: &mut JournalWriter, bytes: &[u8], frame: u64, direction: u8) {
    message_time(
        writer,
        bytes,
        frame,
        direction,
        Some(if frame == 3 { -10 } else { 0 }),
    );
}
fn message_time(
    writer: &mut JournalWriter,
    bytes: &[u8],
    frame: u64,
    direction: u8,
    observed_at_ns: Option<i64>,
) {
    let evidence = EvidenceBytes::from_packet(
        bytes,
        PacketId {
            capture: [7; 32],
            frame,
            record_offset: frame * 100,
        },
        0,
    );
    writer
        .message(
            1,
            &evidence,
            &PcapMetadata {
                source_id: "capture-q".into(),
                record_id: format!("record-{frame}"),
                observed_at_ns,
                session: Some(1),
                direction: Some(direction),
                peer: Some("192.0.2.1".into()),
                local: Some("192.0.2.100".into()),
            },
        )
        .unwrap();
}
fn fixture(path: &Path, withdraw: bool) {
    fixture_clock(path, withdraw, false);
}
fn fixture_clock(path: &Path, withdraw: bool, missing_time: bool) {
    let mut writer = JournalWriter::create(
        path,
        "capture-q".into(),
        [7; 32],
        1024 * 1024,
        Limits::default(),
    )
    .unwrap();
    for direction in 0..2 {
        let open = envelope(1, &[4, 0xfd, 0xe9, 0, 90, 192, 0, 2, direction + 1, 0]);
        message(&mut writer, &open, u64::from(direction) + 1, direction);
    }
    message_time(
        &mut writer,
        &update(65010, 100, [64512, 1, 2], [192, 0, 2, 9]),
        3,
        0,
        if missing_time { None } else { Some(-10) },
    );
    message_time(
        &mut writer,
        &update(65020, 200, [64512, 3, 4], [192, 0, 2, 10]),
        4,
        0,
        if missing_time { None } else { Some(0) },
    );
    if withdraw {
        message_time(
            &mut writer,
            &envelope(2, &[0, 4, 24, 203, 0, 113, 0, 0]),
            5,
            0,
            if missing_time { None } else { Some(0) },
        );
    }
    writer.seal().unwrap();
}
fn load(path: &Path) -> VerifiedStore {
    VerifiedStore::load(
        path,
        1024 * 1024,
        MrtLimits::default(),
        Limits::default(),
        MrtReplayOptions::default(),
    )
    .unwrap()
}
fn route_count(text: &str) -> usize {
    // Native current is a top-level route member, absent from normalized observations.
    text.matches("\"native_current\":").count()
}
#[test]
fn canonical_prefix_and_selector_contract_rejects_aliases_and_conflicts() {
    for value in [
        "203.0.113.1/24",
        "203.0.113.0/024",
        "2001:0db8::/32",
        "2001:db8::1/32",
        "0.0.0.0/33",
    ] {
        assert!(
            PrefixSelector::parse(value, PrefixRelation::Contains).is_err(),
            "{value}"
        );
    }
    assert!(PrefixSelector::parse("0.0.0.0/0", PrefixRelation::Contains).is_ok());
    assert!(PrefixSelector::parse("::/0", PrefixRelation::ContainedBy).is_ok());
    let q = Query {
        prefix: Some("203.0.113.0/24".into()),
        prefix_selector: Some(
            PrefixSelector::parse("203.0.113.0/24", PrefixRelation::Exact).unwrap(),
        ),
        ..Query::default()
    };
    assert!(q.validate().is_err());
    assert!(Query {
        asn: Some(AsnSelector {
            asn: 0,
            role: AsnRole::Origin
        }),
        ..Query::default()
    }
    .validate()
    .is_err());
    assert!(Query {
        direction: Some(2),
        ..Query::default()
    }
    .validate()
    .is_err());
    assert!(Query {
        time_window: Some(ReportedTimeWindow {
            source: "capture-q".into(),
            clock_policy: ClockPolicy::Unknown,
            clock_id: "clock".into(),
            start_ns: -10,
            end_ns: 0
        }),
        ..Query::default()
    }
    .validate()
    .is_err());
}
#[test]
fn historical_attributes_never_match_current_and_conjunction_stays_in_one_version() {
    let scratch = Scratch::new();
    let path = scratch.path("journal");
    fixture(&path, false);
    let store = load(&path);
    let old = Query {
        asn: Some(AsnSelector {
            asn: 65010,
            role: AsnRole::Origin,
        }),
        community: Some((64512u32 << 16) | 100),
        large_community: Some([64512, 1, 2]),
        next_hop: Some("192.0.2.9".parse().unwrap()),
        ..Query::default()
    };
    assert_eq!(
        route_count(&store.query(&old, &Limits::default()).unwrap()),
        0
    );
    let retained = Query {
        attribute_scope: Some(AttributeScope::AnyRetainedVersion),
        ..old.clone()
    };
    let output = store.query(&retained, &Limits::default()).unwrap();
    assert_eq!(route_count(&output), 1, "{output}");
    assert!(output.contains("\"disposition\":\"replaced\""));
    assert!(output.contains("\"source_occurrence_id\""));
    assert!(output.contains("\"normalized_observation\""));
    let split = Query {
        community: Some((64512u32 << 16) | 200),
        ..retained.clone()
    };
    assert_eq!(
        route_count(&store.query(&split, &Limits::default()).unwrap()),
        0
    );
    let current = Query {
        asn: Some(AsnSelector {
            asn: 65020,
            role: AsnRole::PathMember,
        }),
        community: Some((64512u32 << 16) | 200),
        large_community: Some([64512, 3, 4]),
        next_hop: Some("192.0.2.10".parse().unwrap()),
        ..Query::default()
    };
    assert_eq!(
        route_count(&store.query(&current, &Limits::default()).unwrap()),
        1
    );
    let legacy = store.query(&Query::default(), &Limits::default()).unwrap();
    assert!(legacy.contains("pcap-evidence.bgp.persisted-query.v1"));
    assert!(!legacy.contains("selector_coverage"));
}
#[test]
fn withdrawn_current_and_missing_reported_clock_are_uncertainty_not_absence() {
    let scratch = Scratch::new();
    let path = scratch.path("journal");
    fixture(&path, true);
    let store = load(&path);
    let current = Query {
        community: Some((64512u32 << 16) | 200),
        ..Query::default()
    };
    let output = store.query(&current, &Limits::default()).unwrap();
    assert_eq!(route_count(&output), 0);
    assert!(output.contains("\"selector_uncertain_rows\":1"));
    assert!(output.contains("current_attributes_unavailable"));
    assert!(output.contains("\"coverage_scope\":\"selector_fields\""));
    assert!(output.contains("\"source_coverage\":\"unknown\""));
    let retained = Query {
        attribute_scope: Some(AttributeScope::AnyRetainedVersion),
        ..current
    };
    assert_eq!(
        route_count(&store.query(&retained, &Limits::default()).unwrap()),
        1
    );
    let clock = Query {
        time_window: Some(ReportedTimeWindow {
            source: "capture-q".into(),
            clock_policy: ClockPolicy::SourceLabel,
            clock_id: "capture-clock".into(),
            start_ns: -10,
            end_ns: 0,
        }),
        ..retained
    };
    let output = store.query(&clock, &Limits::default()).unwrap();
    assert_eq!(route_count(&output), 0);
    assert!(output.contains("\"selector_uncertain_rows\":0"));
    let untimed = scratch.path("untimed");
    fixture_clock(&untimed, true, true);
    let store = load(&untimed);
    let output = store.query(&clock, &Limits::default()).unwrap();
    assert_eq!(route_count(&output), 0);
    assert!(output.contains("missing_reported_clock_or_time"));
    assert!(output.contains("\"selector_uncertain_rows\":1"));
}
#[test]
fn prefix_containment_is_directional_and_full_output_limits_are_exact() {
    let scratch = Scratch::new();
    let path = scratch.path("journal");
    fixture(&path, false);
    let store = load(&path);
    for (prefix, relation, count) in [
        ("203.0.112.0/23", PrefixRelation::Contains, 1),
        ("203.0.113.0/25", PrefixRelation::Contains, 0),
        ("203.0.113.0/25", PrefixRelation::ContainedBy, 1),
        ("2001:db8::/32", PrefixRelation::Contains, 0),
    ] {
        let q = Query {
            prefix_selector: Some(PrefixSelector::parse(prefix, relation).unwrap()),
            ..Query::default()
        };
        assert_eq!(
            route_count(&store.query(&q, &Limits::default()).unwrap()),
            count
        );
    }
    let q = Query {
        attribute_scope: Some(AttributeScope::AnyRetainedVersion),
        ..Query::default()
    };
    let output = store.query(&q, &Limits::default()).unwrap();
    let exact = Limits {
        output_bytes: output.len(),
        ..Limits::default()
    };
    assert_eq!(store.query(&q, &exact).unwrap(), output);
    assert!(store
        .query(
            &q,
            &Limits {
                output_bytes: output.len() - 1,
                ..exact
            }
        )
        .is_err());
}
#[test]
fn cli_rejects_duplicate_partial_and_noncanonical_selectors_before_store_io() {
    let scratch = Scratch::new();
    let missing = scratch.path("missing");
    for flags in [
        vec!["--asn", "65010"],
        vec!["--asn", "065010", "--asn-role", "origin"],
        vec!["--generation", "00"],
        vec!["--direction", "2"],
        vec!["--next-hop", "2001:0db8::1"],
        vec!["--community", "64512:01"],
        vec!["--extended-community", "000000000000000A"],
        vec!["--partition", "x", "--partition", "y"],
        vec!["--reported-start-ns", "-0"],
        vec!["--prefix-mode", "contains"],
        vec!["--evidence", "legacy", "--generation", "0"],
    ] {
        let output = scratch.path("result");
        let result = Command::new(env!("CARGO_BIN_EXE_pcap-depth"))
            .args(["bgp", "query"])
            .arg(&missing)
            .arg("--output")
            .arg(&output)
            .args(&flags)
            .output()
            .unwrap();
        assert!(!result.status.success(), "{flags:?}");
        assert!(!output.exists());
        let stderr = String::from_utf8_lossy(&result.stderr);
        assert!(
            stderr.contains("Usage") || stderr.contains("usage"),
            "{flags:?}: {stderr}"
        );
    }
}

#[test]
fn reported_clock_windows_use_exact_occurrences_and_half_open_boundaries() {
    use pcap_evidence_product::deep::{bgp_mrt::MrtSource, bgp_mrt_store};
    fn record(seconds: u32, subtype: u16, body: &[u8]) -> Vec<u8> {
        let mut out = seconds.to_be_bytes().to_vec();
        out.extend_from_slice(&13u16.to_be_bytes());
        out.extend_from_slice(&subtype.to_be_bytes());
        out.extend_from_slice(&(body.len() as u32).to_be_bytes());
        out.extend_from_slice(body);
        out
    }
    let mut peers = vec![
        192, 0, 2, 1, 0, 1, b'v', 0, 1, 2, 192, 0, 2, 2, 203, 0, 113, 9,
    ];
    peers.extend_from_slice(&65551u32.to_be_bytes());
    let mut attrs = vec![0x40, 1, 1, 0, 0x40, 2, 6, 2, 1];
    attrs.extend_from_slice(&65551u32.to_be_bytes());
    attrs.extend_from_slice(&[0x40, 3, 4, 192, 0, 2, 9]);
    let mut rib = vec![0, 0, 0, 7, 24, 203, 0, 113, 0, 2];
    for originated in [10u32, 11] {
        rib.extend_from_slice(&0u16.to_be_bytes());
        rib.extend_from_slice(&originated.to_be_bytes());
        rib.extend_from_slice(&(attrs.len() as u16).to_be_bytes());
        rib.extend_from_slice(&attrs);
    }
    let scratch = Scratch::new();
    let path = scratch.path("mrt");
    bgp_mrt_store::create(
        &path,
        &[record(11, 1, &peers), record(12, 2, &rib)].concat(),
        MrtSource {
            source_id: "collector-q".into(),
            checkpoint_id: "checkpoint-q".into(),
        },
        1024 * 1024,
        MrtLimits::default(),
        Limits::default(),
    )
    .unwrap();
    let store = load(&path);
    for (start, end, count) in [
        (10_000_000_000, 11_000_000_000, 1),
        (11_000_000_000, 12_000_000_000, 1),
        (-10, 0, 0),
        (10_000_000_001, 11_000_000_000, 0),
    ] {
        let query = Query {
            attribute_scope: Some(AttributeScope::AnyRetainedVersion),
            asn: Some(AsnSelector {
                asn: 65551,
                role: AsnRole::Origin,
            }),
            time_window: Some(ReportedTimeWindow {
                source: "collector-q".into(),
                clock_policy: ClockPolicy::SourceLabel,
                clock_id: "mrt-originated-seconds".into(),
                start_ns: start,
                end_ns: end,
            }),
            ..Query::default()
        };
        let output = store.query(&query, &Limits::default()).unwrap();
        assert_eq!(route_count(&output), count, "{output}");
        assert!(output.contains("\"selector_uncertain_rows\":0"));
    }
    let query = Query {
        attribute_scope: Some(AttributeScope::AnyRetainedVersion),
        time_window: Some(ReportedTimeWindow {
            source: "collector-q".into(),
            clock_policy: ClockPolicy::IngestionLabel,
            clock_id: "mrt-originated-seconds".into(),
            start_ns: 10_000_000_000,
            end_ns: 12_000_000_000,
        }),
        ..Query::default()
    };
    assert_eq!(
        route_count(&store.query(&query, &Limits::default()).unwrap()),
        0
    );
}

#[test]
fn cli_full_output_is_create_new_and_counts_the_newline_exactly() {
    let scratch = Scratch::new();
    let input = scratch.path("journal");
    fixture(&input, false);
    let run = |output: &Path, maximum: Option<usize>| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_pcap-depth"));
        command
            .args(["bgp", "query"])
            .arg(&input)
            .arg("--output")
            .arg(output)
            .args(["--attribute-scope", "any-retained-version"]);
        if let Some(maximum) = maximum {
            command.arg("--max-output-bytes").arg(maximum.to_string());
        }
        command.output().unwrap()
    };
    let initial = scratch.path("initial");
    let result = run(&initial, None);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let bytes = fs::read(&initial).unwrap();
    assert_eq!(bytes.last(), Some(&b'\n'));
    let exact = scratch.path("exact");
    let result = run(&exact, Some(bytes.len()));
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(fs::read(&exact).unwrap(), bytes);
    let below = scratch.path("below");
    assert!(!run(&below, Some(bytes.len() - 1)).status.success());
    assert!(!below.exists());
    let protected = scratch.path("protected");
    fs::write(&protected, b"retain-original").unwrap();
    assert!(!run(&protected, None).status.success());
    assert_eq!(fs::read(&protected).unwrap(), b"retain-original");
}

#[test]
fn observation_events_match_raw_unknown_communities_without_admitting_native_versions() {
    use pcap_evidence_product::deep::bgp_persisted::PolicyProfile;
    let scratch = Scratch::new();
    let path = scratch.path("journal");
    let mut writer = JournalWriter::create(
        &path,
        "capture-q".into(),
        [7; 32],
        1024 * 1024,
        Limits::default(),
    )
    .unwrap();
    for direction in 0..2 {
        message(
            &mut writer,
            &envelope(1, &[4, 0xfd, 0xe9, 0, 90, 192, 0, 2, direction + 1, 0]),
            u64::from(direction) + 1,
            direction,
        );
    }
    let raw = [0x80, 0x99, 0, 1, 2, 3, 4, 5];
    let mut update = update(65010, 100, [64512, 1, 2], [192, 0, 2, 9]);
    let attribute_length = u16::from_be_bytes([update[21], update[22]]);
    let nlri = update.split_off(update.len() - 4);
    update.extend_from_slice(&[0xc0, 16, 8]);
    update.extend_from_slice(&raw);
    update.extend(nlri);
    update[21..23].copy_from_slice(&(attribute_length + 11).to_be_bytes());
    let length = update.len() as u16;
    update[16..18].copy_from_slice(&length.to_be_bytes());
    message(&mut writer, &update, 3, 0);
    writer.seal().unwrap();
    let store = load(&path);
    let retained = Query {
        attribute_scope: Some(AttributeScope::AnyRetainedVersion),
        extended_community: Some(raw),
        ..Query::default()
    };
    let native = store.query(&retained, &Limits::default()).unwrap();
    assert_eq!(route_count(&native), 0);
    assert!(native.contains("missing_version_occurrence"));
    let events = Query {
        attribute_scope: Some(AttributeScope::ObservationEvent),
        ..retained
    };
    let output = store.query(&events, &Limits::default()).unwrap();
    assert!(output.contains("\"routes\":[]"));
    assert!(output.contains("\"attribute_matches\":[]"));
    assert!(output.contains("\"observation_matches\":[{"));
    assert!(output.contains("\"semantics_unknown\":true"));
    assert!(output.contains("\"native_version_claimed\":false"));
    assert!(output.contains("\"route_index\":0"));
    assert!(output.contains("\"source_occurrence_id\""));
    let exact = Limits {
        output_bytes: output.len(),
        ..Limits::default()
    };
    assert_eq!(store.query(&events, &exact).unwrap(), output);
    assert!(store
        .query(
            &events,
            &Limits {
                output_bytes: output.len() - 1,
                ..exact
            }
        )
        .is_err());
    let known_false_unknown = Query {
        asn: Some(AsnSelector {
            asn: 65010,
            role: AsnRole::Origin,
        }),
        extended_community: Some([0; 8]),
        ..events.clone()
    };
    let output = store
        .query(&known_false_unknown, &Limits::default())
        .unwrap();
    assert!(output.contains("\"selector_uncertain_rows\":0"));
    assert!(output.contains("\"excluded_rows\":1"));
    assert!(output.contains("\"field_unavailable_rows\":1"));
    assert!(output.contains("unresolved_asn"));
    let profile=PolicyProfile::parse(b"schema=pcap-evidence.bgp.persisted-policy.v1\nprovenance=selector-fixture\ncomparison_context=offline-fixture\nmissing_local_preference=100\nmed_rule=skip\nage_rule=skip\n",&Limits::default()).unwrap();
    assert!(store.policy(&events, &profile, &Limits::default()).is_err());
    assert!(Query {
        status: Some("rejected".into()),
        ..events.clone()
    }
    .validate()
    .is_err());
    assert!(Query {
        version_index: Some(0),
        ..events
    }
    .validate()
    .is_err());
}

fn append_attribute(mut message: Vec<u8>, code: u8, value: &[u8]) -> Vec<u8> {
    let length = u16::from_be_bytes([message[21], message[22]]);
    let nlri = message.split_off(message.len() - 4);
    message.extend([0xc0, code, value.len() as u8]);
    message.extend_from_slice(value);
    message.extend(nlri);
    message[21..23].copy_from_slice(&(length + 3 + value.len() as u16).to_be_bytes());
    let length = message.len() as u16;
    message[16..18].copy_from_slice(&length.to_be_bytes());
    message
}

#[test]
fn captured_raw_values_preserve_malformed_neighbors_and_literal_nonmatches() {
    let raw = [0x80, 0x99, 0, 1, 2, 3, 4, 5];
    let scratch = Scratch::new();
    for (name, malformed_value) in [
        ("valid-raw-malformed-neighbor", false),
        ("malformed-raw", true),
    ] {
        let path = scratch.path(name);
        let mut writer = JournalWriter::create(
            &path,
            "capture-q".into(),
            [7; 32],
            1024 * 1024,
            Limits::default(),
        )
        .unwrap();
        for direction in 0..2 {
            message(
                &mut writer,
                &envelope(1, &[4, 0xfd, 0xe9, 0, 90, 192, 0, 2, direction + 1, 0]),
                u64::from(direction) + 1,
                direction,
            );
        }
        let wire = append_attribute(
            update(65010, 100, [64512, 1, 2], [192, 0, 2, 9]),
            16,
            if malformed_value { &raw[..7] } else { &raw },
        );
        // A malformed MED neighbor retains its RFC disposition and raw evidence.
        let wire = append_attribute(wire, 4, &[0, 1, 2]);
        message(&mut writer, &wire, 3, 0);
        writer.seal().unwrap();
        let store = load(&path);
        let query = Query {
            attribute_scope: Some(AttributeScope::ObservationEvent),
            extended_community: Some(raw),
            ..Query::default()
        };
        let output = store.query(&query, &Limits::default()).unwrap();
        assert!(
            output.contains("malformed_path_attribute_retained") || malformed_value,
            "{output}"
        );
        if malformed_value {
            assert!(output.contains("\"observation_matches\":[]"), "{output}");
            assert!(output.contains("unresolved_extended_community"), "{output}");
        } else {
            assert!(output.contains("\"observation_matches\":[{"), "{output}");
            assert!(output.contains("8099000102030405"), "{output}");
            assert!(
                output.contains("\"native_version_claimed\":false"),
                "{output}"
            );
            let nonmatch = Query {
                extended_community: Some([0; 8]),
                ..query
            };
            let negative = store.query(&nonmatch, &Limits::default()).unwrap();
            assert!(
                negative.contains("\"observation_matches\":[]"),
                "{negative}"
            );
            assert!(
                negative.contains("\"selector_uncertain_rows\":0"),
                "{negative}"
            );
        }
    }
}

#[test]
fn captured_raw_values_validate_digest_ranges_and_keep_attribute_identity() {
    use pcap_evidence::json::Json;
    use pcap_evidence_product::deep::{
        bgp::{decode_pcap, SessionState},
        bgp_state::Observation,
    };
    let limits = Limits::default();
    let mut state = SessionState::default();
    let metadata = |frame, direction| PcapMetadata {
        source_id: "capture-q".into(),
        record_id: format!("r-{frame}"),
        observed_at_ns: Some(0),
        session: Some(1),
        direction: Some(direction),
        peer: Some("192.0.2.1".into()),
        local: Some("192.0.2.100".into()),
    };
    let evidence = |wire: &[u8], frame| {
        EvidenceBytes::from_packet(
            wire,
            PacketId {
                capture: [7; 32],
                frame,
                record_offset: frame * 100,
            },
            0,
        )
    };
    for direction in 0..2 {
        let wire = envelope(1, &[4, 0xfd, 0xe9, 0, 90, 192, 0, 2, direction + 1, 0]);
        decode_pcap(
            &evidence(&wire, u64::from(direction) + 1),
            metadata(u64::from(direction) + 1, direction),
            &mut state,
            &limits,
        )
        .unwrap();
    }
    let wire = append_attribute(
        update(65010, 100, [64512, 1, 2], [192, 0, 2, 9]),
        16,
        &[0x80, 0x99, 0, 1, 2, 3, 4, 5],
    );
    let value = decode_pcap(&evidence(&wire, 3), metadata(3, 0), &mut state, &limits).unwrap();
    let valid = Observation::from_normalized(&value, None, &limits).unwrap();
    assert!(value
        .encode_bounded(limits.output_bytes)
        .unwrap()
        .contains("\"value_hex\":\"8099000102030405\""));
    fn range(value: &mut Json) -> &mut Vec<(&'static str, Json)> {
        let Json::Object(root) = value else { panic!() };
        let Json::Array(routes) = &mut root.iter_mut().find(|(k, _)| *k == "routes").unwrap().1
        else {
            panic!()
        };
        let Json::Object(route) = &mut routes[0] else {
            panic!()
        };
        let Json::Array(ranges) = &mut route
            .iter_mut()
            .find(|(k, _)| *k == "attribute_ranges")
            .unwrap()
            .1
        else {
            panic!()
        };
        let raw=ranges.iter_mut().find(|v|matches!(v,Json::Object(xs) if xs.iter().any(|(k,v)|*k=="type" && v==&Json::from(16u8)))).unwrap();
        let Json::Object(raw) = raw else { panic!() };
        raw
    }
    let mut legacy = value.clone();
    range(&mut legacy).retain(|(k, _)| *k != "value_hex");
    let old = Observation::from_normalized(&legacy, None, &limits).unwrap();
    assert_eq!(
        old.routes()[0].attribute_identity(),
        valid.routes()[0].attribute_identity()
    );
    for replacement in ["8099000102030404", "80990001020304", "809900010203040A"] {
        let mut invalid = value.clone();
        range(&mut invalid)
            .iter_mut()
            .find(|(k, _)| *k == "value_hex")
            .unwrap()
            .1 = replacement.into();
        assert!(
            Observation::from_normalized(&invalid, None, &limits).is_err(),
            "{replacement}"
        );
    }
    // Same raw bytes and unchanged value digest isolate lowercase validation.
    let wire = append_attribute(
        update(65010, 100, [64512, 1, 2], [192, 0, 2, 9]),
        16,
        &[0x80, 0x99, 0, 1, 2, 3, 4, 0xab],
    );
    let mut alphabetic =
        decode_pcap(&evidence(&wire, 4), metadata(4, 0), &mut state, &limits).unwrap();
    Observation::from_normalized(&alphabetic, None, &limits).unwrap();
    range(&mut alphabetic)
        .iter_mut()
        .find(|(k, _)| *k == "value_hex")
        .unwrap()
        .1 = "80990001020304AB".into();
    assert!(Observation::from_normalized(&alphabetic, None, &limits).is_err());
}

#[test]
fn imported_raw_extended_community_event_uses_same_literal_selector() {
    use pcap_evidence_product::deep::{bgp_mrt::MrtSource, bgp_mrt_store};
    fn record(subtype: u16, payload: &[u8]) -> Vec<u8> {
        let mut body = 65001u16.to_be_bytes().to_vec();
        body.extend(65002u16.to_be_bytes());
        body.extend(0u16.to_be_bytes());
        body.extend(1u16.to_be_bytes());
        body.extend([198, 51, 100, 1, 198, 51, 100, 2]);
        body.extend(payload);
        let mut out = 12u32.to_be_bytes().to_vec();
        out.extend(16u16.to_be_bytes());
        out.extend(subtype.to_be_bytes());
        out.extend((body.len() as u32).to_be_bytes());
        out.extend(body);
        out
    }
    // BGP4MP has a validated wire occurrence inventory. TABLE_DUMP_V2's
    // documented safe-subset normalizer intentionally omits unsupported16.
    let raw = [0x80, 0x99, 0, 1, 2, 3, 4, 5];
    let peer_open = envelope(1, &[4, 0xfd, 0xe9, 0, 90, 198, 51, 100, 1, 0]);
    let local_open = envelope(1, &[4, 0xfd, 0xea, 0, 90, 198, 51, 100, 2, 0]);
    let wire = append_attribute(update(65010, 100, [64512, 1, 2], [192, 0, 2, 9]), 16, &raw);
    let mrt = [
        record(0, &[0, 3, 0, 4]),
        record(1, &peer_open),
        record(6, &local_open),
        record(0, &[0, 4, 0, 5]),
        record(0, &[0, 5, 0, 6]),
        record(1, &wire),
    ]
    .concat();
    let scratch = Scratch::new();
    let path = scratch.path("mrt");
    bgp_mrt_store::create(
        &path,
        &mrt,
        MrtSource {
            source_id: "collector-q".into(),
            checkpoint_id: "checkpoint-q".into(),
        },
        1024 * 1024,
        MrtLimits::default(),
        Limits::default(),
    )
    .unwrap();
    let store = load(&path);
    let query = Query {
        attribute_scope: Some(AttributeScope::ObservationEvent),
        extended_community: Some(raw),
        ..Query::default()
    };
    let output = store.query(&query, &Limits::default()).unwrap();
    assert!(output.contains("\"observation_matches\":[{"), "{output}");
    assert!(output.contains("\"semantics_unknown\":true"), "{output}");
    assert!(output.contains("\"source_kind\":\"imported\""), "{output}");
    assert!(
        output.contains("\"native_version_claimed\":false"),
        "{output}"
    );
    let retained = Query {
        attribute_scope: Some(AttributeScope::AnyRetainedVersion),
        ..query.clone()
    };
    let native = store.query(&retained, &Limits::default()).unwrap();
    assert_eq!(route_count(&native), 0, "{native}");
    assert!(native.contains("missing_version_occurrence"), "{native}");
    let negative = store
        .query(
            &Query {
                extended_community: Some([0; 8]),
                ..query
            },
            &Limits::default(),
        )
        .unwrap();
    assert!(
        negative.contains("\"observation_matches\":[]"),
        "{negative}"
    );
    assert!(
        negative.contains("\"selector_uncertain_rows\":0"),
        "{negative}"
    );
}
