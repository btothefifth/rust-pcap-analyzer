//! Source-built imported analysis regressions with independent wire witnesses.
use pcap_evidence_product::deep::{
    bgp::PeerRelationship,
    bgp_bmp::{BmpLimits, BmpSource},
    bgp_bmp_store,
    bgp_mrt::{MrtLimits, MrtSource},
    bgp_mrt_store::{self, MrtReplayOptions},
    bgp_persisted::{analysis::ExpectationProfile, Query, VerifiedStore},
    bgp_session::SourcePartition,
    Limits,
};
use std::{
    fs,
    path::PathBuf,
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
};
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture {
    root: PathBuf,
    path: PathBuf,
    store: VerifiedStore,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
fn bgp(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut v = vec![255; 16];
    v.extend_from_slice(&((19 + body.len()) as u16).to_be_bytes());
    v.push(kind);
    v.extend(body);
    v
}
fn open(asn: u16, id: u8) -> Vec<u8> {
    bgp(
        1,
        &[4, (asn >> 8) as u8, asn as u8, 0, 90, 192, 0, 2, id, 0],
    )
}
fn update(width: usize) -> Vec<u8> {
    let mut a = vec![0x40, 1, 1, 0, 0x40, 2, (width + 2) as u8, 2, 1];
    if width == 2 {
        a.extend(65001u16.to_be_bytes());
    } else {
        a.extend(65001u32.to_be_bytes());
    }
    a.extend([0x40, 3, 4, 192, 0, 2, 9, 0x40, 5, 4, 0, 0, 0, 100]);
    let mut b = vec![0, 0];
    b.extend((a.len() as u16).to_be_bytes());
    b.extend(a);
    b.extend([24, 203, 0, 113]);
    bgp(2, &b)
}
fn bmp(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut v = vec![3];
    v.extend(((6 + body.len()) as u32).to_be_bytes());
    v.push(kind);
    v.extend(body);
    v
}
fn peer(id: u8, flags: u8) -> Vec<u8> {
    let mut p = vec![0, flags];
    p.extend([0; 20]);
    p.extend([192, 0, 2, id]);
    p.extend(65001u32.to_be_bytes());
    p.extend([192, 0, 2, id]);
    p.extend(100u32.to_be_bytes());
    p.extend(0u32.to_be_bytes());
    assert_eq!(p.len(), 42);
    p
}
fn up(id: u8) -> Vec<u8> {
    let mut p = peer(id, 0);
    p.extend([0; 12]);
    p.extend([192, 0, 2, 254, 0, 179, 0x9c, 0x40]);
    p.extend(open(65000, 254));
    p.extend(open(65001, id));
    bmp(3, &p)
}
fn rm(id: u8, flags: u8) -> Vec<u8> {
    let mut p = peer(id, flags);
    p.extend(update(4));
    bmp(0, &p)
}
fn bmp_bytes(routes: bool, gap: bool, after: bool, recovery: bool) -> (Vec<u8>, usize, usize) {
    let mut b = up(1);
    if !routes {
        return (b, 0, 0);
    }
    b.extend(rm(1, 0));
    b.extend(rm(1, 0x40));
    b.extend(up(2));
    b.extend(rm(2, 0));
    let start = b.len();
    if gap {
        b.extend(bmp(0, &peer(1, 0)));
    }
    let end = b.len();
    if after {
        b.extend(rm(1, 0));
        b.extend(rm(1, 0x40));
        b.extend(rm(2, 0));
    }
    if recovery {
        b.extend(up(1));
        b.extend(rm(1, 0));
        b.extend(rm(1, 0x40));
    }
    (b, start, end)
}
fn mrt(sub: u16, payload: &[u8]) -> Vec<u8> {
    let mut b = vec![0xfd, 0xe9, 0xfd, 0xe8, 0, 7, 0, 1];
    b.extend([192, 0, 2, 1, 192, 0, 2, 254]);
    b.extend(payload);
    let mut r = 100u32.to_be_bytes().to_vec();
    r.extend(16u16.to_be_bytes());
    r.extend(sub.to_be_bytes());
    r.extend((b.len() as u32).to_be_bytes());
    r.extend(b);
    r
}
fn mrt_bytes(gap: bool, reset: bool) -> Vec<u8> {
    let mut b = [
        mrt(0, &[0, 3, 0, 4]),
        mrt(1, &open(65001, 1)),
        mrt(6, &open(65000, 254)),
        mrt(0, &[0, 4, 0, 5]),
        mrt(0, &[0, 5, 0, 6]),
        mrt(1, &update(2)),
        mrt(6, &update(2)),
    ]
    .concat();
    if gap {
        b.extend(mrt(1, &[]));
    }
    if reset {
        b.extend(mrt(0, &[0, 6, 0, 1]));
    }
    b
}
fn fixture(format: &str, bytes: &[u8], checkpoint: &str) -> Fixture {
    fixture_labeled(format, bytes, "source-a", checkpoint)
}
fn fixture_labeled(format: &str, bytes: &[u8], source: &str, checkpoint: &str) -> Fixture {
    let root = std::env::temp_dir().join(format!(
        "bgp-imported-analysis-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&root).unwrap();
    let path = root.join("source.store");
    let options = MrtReplayOptions {
        peer_relationship: Some(PeerRelationship::Internal),
    };
    if format == "bmp" {
        bgp_bmp_store::create_with_options(
            &path,
            bytes,
            BmpSource {
                source_id: source.into(),
                checkpoint_id: checkpoint.into(),
            },
            1_048_576,
            BmpLimits::default(),
            Limits::default(),
            bgp_bmp_store::BmpReplayOptions {
                peer_relationship: options.peer_relationship,
            },
        )
        .unwrap();
    } else {
        bgp_mrt_store::create_with_options(
            &path,
            bytes,
            MrtSource {
                source_id: source.into(),
                checkpoint_id: checkpoint.into(),
            },
            1_048_576,
            MrtLimits::default(),
            Limits::default(),
            options,
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
    Fixture { root, path, store }
}
fn profile(store: &VerifiedStore, session: &str, prefix: &str, presence: &str) -> String {
    let o = store
        .observations()
        .iter()
        .find(|o| !o.routes().is_empty() && o.source().session.as_deref() == Some(session))
        .unwrap();
    let c = o.import_context().unwrap();
    let partition = SourcePartition::from_import_context(c, &Limits::default()).unwrap();
    format!("schema=pcap-evidence.bgp.expectation-profile.v1\nprovenance=source-built-fixture\ntime_basis=source_occurrence_order\ncoverage=caller_declared_complete\nexpectation=row|{presence}|{}|{}|{}|{}|{}|{}|{}|absent|1|1|{prefix}|absent|origin:65001|unknown|unknown|unknown|unknown\n",c.source_id,partition.partition_id,c.session,c.generation,c.direction.map_or_else(||"absent".into(),|d|d.to_string()),c.peer.as_deref().unwrap_or("absent"),c.checkpoint_id)
}
fn changes(f: &Fixture, q: &Query) -> String {
    f.store.changes(q, &Limits::default()).unwrap()
}
fn assert_json(output: &str, predicate: &str, arguments: &[&str]) {
    // Reuse the owner suite's independent Python stdlib JSON traversal.
    let python = std::env::var("PYTHON").unwrap_or_else(|_| {
        if cfg!(windows) { "python".into() } else { "python3".into() }
    });
    let program = format!("import json,sys\nd=json.load(sys.stdin)\n{predicate}");
    let mut child = Command::new(python).args(["-c", &program, "stdin"]).args(arguments)
        .stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped()).spawn().unwrap();
    {
        use std::io::Write;
        child.stdin.take().unwrap().write_all(output.as_bytes()).unwrap();
    }
    let run = child.wait_with_output().unwrap();
    assert!(run.status.success(), "{}\n{output}", String::from_utf8_lossy(&run.stderr));
}
fn expect(f: &Fixture, session: &str, prefix: &str, presence: &str, status: &str) {
    let text = profile(&f.store, session, prefix, presence);
    let p = ExpectationProfile::parse(text.as_bytes(), &Limits::default()).unwrap();
    let out = f.store.expectations(&p, &Limits::default()).unwrap();
    assert_json(&out, "r=d['results']; assert len(r)==1; r=r[0]; assert r['id']=='row'; assert r['status']==sys.argv[2]; assert r['scope']['session']==sys.argv[3]; assert r['scope']['prefix']==sys.argv[4]; assert r['scope']['source_id']==sys.argv[5]; assert r['scope']['checkpoint_id']==sys.argv[6]; assert r['scope']['captured_lifecycle'] is None", &[status, session, prefix,
        &f.store.observations().iter().find(|o| o.source().session.as_deref()==Some(session)).unwrap().import_context().unwrap().source_id,
        &f.store.observations().iter().find(|o| o.source().session.as_deref()==Some(session)).unwrap().import_context().unwrap().checkpoint_id]);
}
fn cli(f: &Fixture, command: &str, extra: &[&str]) -> String {
    cli_with_relationship(f, command, extra, Some("internal"))
}
fn cli_with_relationship(
    f: &Fixture,
    command: &str,
    extra: &[&str],
    relationship: Option<&str>,
) -> String {
    let out = f.root.join(format!(
        "{command}-{}.json",
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let mut invocation = Command::new(env!("CARGO_BIN_EXE_pcap-depth"));
    invocation.args(["bgp", command, f.path.to_str().unwrap()]);
    if let Some(relationship) = relationship {
        invocation.args(["--peer-relationship", relationship]);
    }
    let result = invocation
        .args(["--output", out.to_str().unwrap()])
        .args(extra)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    fs::read_to_string(out).unwrap()
}
#[test]
fn bmp_directional_cut_keeps_missing_prefix_unresolved_and_historical_match_supported() {
    let (bytes, start, end) = bmp_bytes(true, true, false, false);
    let f = fixture("bmp", &bytes, "checkpoint-a");
    assert_eq!(end - start, 48);
    for session in ["bmp:0:pre", "bmp:0:post"] {
        for presence in ["present", "absent"] {
            expect(&f, session, "198.51.100.0/24", presence, "unresolved");
        }
        expect(&f, session, "203.0.113.0/24", "present", "supported");
    }
    expect(&f, "bmp:1:pre", "198.51.100.0/24", "absent", "supported");
    let q = Query {
        session: Some("bmp:0:pre".into()),
        direction: Some(0),
        ..Query::default()
    };
    let out = f.store.changes(&q, &Limits::default()).unwrap();
    assert!(out.contains("malformed_known_record"), "{out}");
    assert!(out.contains(&format!("\"start\":{start}")), "{out}");
    assert!(out.contains(&format!("\"end\":{end}")), "{out}");
    let text = profile(&f.store, "bmp:0:pre", "198.51.100.0/24", "absent");
    let path = f.root.join("profile.txt");
    fs::write(&path, text).unwrap();
    let out = cli(&f, "expectations", &["--profile", path.to_str().unwrap()]);
    assert!(out.contains("\"status\":\"unresolved\""), "{out}");
    let out = cli(
        &f,
        "changes",
        &["--session", "bmp:0:pre", "--direction", "0"],
    );
    assert!(out.contains("malformed_known_record"), "{out}");
}
#[test]
fn bmp_gap_then_update_cannot_bridge_predecessors_but_sibling_and_recovery_survive() {
    let (bytes, _, _) = bmp_bytes(true, true, true, true);
    let f = fixture("bmp", &bytes, "checkpoint-a");
    let out = f
        .store
        .changes(
            &Query::default(),
            &Limits {
                fields: 65_536,
                ..Limits::default()
            },
        )
        .unwrap();
    // Only the unaffected sibling peer may retain its identical predecessor.
    assert_json(&out, "events=[e for e in d['events'] if e['kind']=='announce']; repeated=[e for e in events if e['difference']=='unchanged_repeated_announcement']; assert len(repeated)==1; e=repeated[0]; assert e['native_scope']['session']=='bmp:1:pre'; assert e['before_reference']['observation']['observation_index']<e['reference']['observation_index']; assert e['native_scope']['source_id']=='source-a'; assert e['native_scope']['checkpoint_id']=='checkpoint-a'; assert all(e['before_reference'] is None for e in events if e['native_scope']['session'] in ('bmp:0:pre','bmp:0:post'))", &[]);
    for session in ["bmp:0:pre", "bmp:0:post"] {
        expect(&f, session, "198.51.100.0/24", "absent", "unresolved");
    }
}
#[test]
fn contextless_metadata_honors_known_source_for_metadata_only_and_route_stores() {
    for routes in [false, true] {
        let (bytes, _, _) = bmp_bytes(routes, false, false, false);
        let f = fixture("bmp", &bytes, "checkpoint-a");
        let all = changes(&f, &Query::default());
        let matching = changes(
            &f,
            &Query {
                source: Some("source-a".into()),
                ..Query::default()
            },
        );
        assert_eq!(all, matching);
        assert!(!all.contains("\"events\":[]"));
        let wrong = changes(
            &f,
            &Query {
                source: Some("source-b".into()),
                ..Query::default()
            },
        );
        assert!(wrong.contains("\"events\":[]"), "{wrong:?}");
        for source in ["source-a", "source-b"] {
            let out = cli(&f, "changes", &["--source", source]);
            assert_eq!(out.contains("\"events\":[]"), source == "source-b", "{out}");
        }
        let out = cli(&f, "changes", &[]);
        assert!(!out.contains("\"events\":[]"));
    }
}
fn mrt_boundary_witness(gap: bool, reset: bool) {
    let f = fixture("mrt", &mrt_bytes(gap, reset), "checkpoint-a");
    let session = f
        .store
        .observations()
        .iter()
        .find(|o| !o.routes().is_empty())
        .unwrap()
        .source()
        .session
        .clone()
        .unwrap();
    expect(&f, &session, "198.51.100.0/24", "absent", "unresolved");
    expect(&f, &session, "203.0.113.0/24", "present", "supported");
    let out = f
        .store
        .changes(
            &Query {
                session: Some(session),
                generation: Some(0),
                direction: Some(0),
                ..Query::default()
            },
            &Limits::default(),
        )
        .unwrap();
    assert!(
        out.contains("source_metadata_or_boundary_no_route_action"),
        "{out}"
    );
}
#[test]
fn mrt_native_gap_affects_direction_selected_generation() {
    mrt_boundary_witness(true, false);
}
#[test]
fn mrt_native_reset_affects_previous_generation_under_direction_selection() {
    mrt_boundary_witness(false, true);
}
#[test]
fn legacy_absent_checkpoint_collision_is_explicit() {
    let (bytes, _, _) = bmp_bytes(true, false, false, false);
    let f = fixture("bmp", &bytes, "absent");
    let out = f
        .store
        .query(
            &Query {
                checkpoint: Some("absent".into()),
                ..Query::default()
            },
            &Limits::default(),
        )
        .unwrap();
    assert!(out.contains("203.0.113.0"));
    let text = profile(&f.store, "bmp:0:pre", "203.0.113.0/24", "present");
    let e = ExpectationProfile::parse(text.as_bytes(), &Limits::default()).unwrap_err();
    assert!(e
        .to_string()
        .contains("exact capture lifecycle or import checkpoint required"));
}

fn encode_optional_text(value: &str) -> String {
    let mut out = String::from("text:");
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}
fn v2_profile(text: &str) -> String {
    text.lines()
        .map(|line| {
            if line.starts_with("schema=") {
                return "schema=pcap-evidence.bgp.expectation-profile.v2".into();
            }
            if let Some(row) = line.strip_prefix("expectation=") {
                let mut fields: Vec<String> = row.split('|').map(String::from).collect();
                for i in [2, 4] {
                    fields[i] = encode_optional_text(&fields[i]);
                }
                for i in [7, 8] {
                    fields[i] = if fields[i] == "absent" {
                        "none".into()
                    } else {
                        encode_optional_text(&fields[i])
                    };
                }
                return format!("expectation={}", fields.join("|"));
            }
            line.to_string()
        })
        .collect::<Vec<_>>()
        .join("\n")
        + "\n"
}
fn checkpoint_profile(f: &Fixture, checkpoint: &str, prefix: &str, presence: &str) -> String {
    // Build the ordinary profile using the same exact native partition, then
    // independently encode the optional labels for the actual checkpoint.
    let o = f
        .store
        .observations()
        .iter()
        .find(|o| !o.routes().is_empty() && o.source().session.as_deref() == Some("bmp:0:pre"))
        .unwrap();
    let c = o.import_context().unwrap();
    let p = SourcePartition::from_import_context(c, &Limits::default()).unwrap();
    format!("schema=pcap-evidence.bgp.expectation-profile.v2\nprovenance=source-built-fixture\ntime_basis=source_occurrence_order\ncoverage=caller_declared_complete\nexpectation=row|{presence}|{}|{}|{}|{}|0|{}|{}|absent|1|1|{prefix}|absent|origin:65001|unknown|unknown|unknown|unknown\n",
        encode_optional_text(&c.source_id),p.partition_id,encode_optional_text(&c.session),c.generation,encode_optional_text(c.peer.as_ref().unwrap()),encode_optional_text(checkpoint))
}
#[test]
fn v2_optional_text_preserves_literal_checkpoint_and_legacy_prefix_labels_api_and_cli() {
    for checkpoint in [
        "absent",
        "checkpoint-a",
        "none",
        "text:foo",
        "a|b%:é",
        " spaced ",
    ] {
        let (bytes, _, _) = bmp_bytes(true, false, false, false);
        let f = fixture("bmp", &bytes, checkpoint);
        let q = Query {
            checkpoint: Some(checkpoint.into()),
            ..Query::default()
        };
        assert!(f
            .store
            .query(&q, &Limits::default())
            .unwrap()
            .contains("203.0.113.0"));
        let cli_query = cli(&f, "query", &["--checkpoint", checkpoint]);
        assert!(cli_query.contains("203.0.113.0"));
        for (prefix, presence, status) in [
            ("203.0.113.0/24", "present", "supported"),
            ("203.0.113.0/24", "absent", "contradicted"),
            ("198.51.100.0/24", "absent", "supported"),
        ] {
            let text = checkpoint_profile(&f, checkpoint, prefix, presence);
            let p = ExpectationProfile::parse(text.as_bytes(), &Limits::default()).unwrap();
            let out = f.store.expectations(&p, &Limits::default()).unwrap();
            assert!(out.contains(&format!("\"status\":\"{status}\"")), "{out}");
            assert!(out.contains("\"profile_schema\":\"pcap-evidence.bgp.expectation-profile.v2\""));
            let path = f.root.join("v2-profile.txt");
            fs::write(&path, text).unwrap();
            let out = cli(&f, "expectations", &["--profile", path.to_str().unwrap()]);
            assert!(out.contains(&format!("\"status\":\"{status}\"")), "{out}");
        }
        if checkpoint == "text:foo" {
            expect(&f, "bmp:0:pre", "203.0.113.0/24", "present", "supported");
        }
    }
}
#[test]
fn v2_optional_labels_are_canonical_bounded_and_header_order_independent() {
    let (bytes, _, _) = bmp_bytes(true, false, false, false);
    let f = fixture("bmp", &bytes, "checkpoint-a");
    let original = v2_profile(&profile(&f.store, "bmp:0:pre", "203.0.113.0/24", "present"));
    // Header order retains v1 behavior even with the schema after the row.
    let mut lines = original.lines().collect::<Vec<_>>();
    let schema = lines.remove(0);
    lines.push(schema);
    let reordered = lines.join("\n") + "\n";
    assert!(ExpectationProfile::parse(reordered.as_bytes(), &Limits::default()).is_ok());
    for invalid in [
        "text:",
        "text:%",
        "text:%0",
        "text:%gg",
        "text:%7c",
        "text:%41",
        "text:%00",
        "text:%0A",
        "text:%FF",
        "text:%C0%AF",
        "text:a|b",
        "text:a:b",
        "text: ",
        "absent",
        "unknown",
    ] {
        let bad = original.replace("text:checkpoint-a", invalid);
        assert!(
            ExpectationProfile::parse(bad.as_bytes(), &Limits::default()).is_err(),
            "{invalid}"
        );
    }
    // Every byte may need escaping: 512 two-byte Unicode characters are 1024
    // decoded bytes, 3072 encoded bytes, plus the optional-text type prefix.
    let exact = "é".repeat(512);
    let text = original.replace("text:checkpoint-a", &encode_optional_text(&exact));
    assert!(ExpectationProfile::parse(text.as_bytes(), &Limits::default()).is_ok());
    let below = text.len() - 1;
    assert!(ExpectationProfile::parse(
        text.as_bytes(),
        &Limits {
            input_bytes: below,
            ..Limits::default()
        }
    )
    .is_err());
    let too_long = original.replace("text:checkpoint-a", &encode_optional_text(&(exact + "a")));
    assert!(ExpectationProfile::parse(too_long.as_bytes(), &Limits::default()).is_err());
    for peer in ["absent", "none", "text:foo", "a|b%:é"] {
        let c = f
            .store
            .observations()
            .iter()
            .find(|o| !o.routes().is_empty())
            .unwrap()
            .import_context()
            .unwrap();
        let text = original.replace(
            &encode_optional_text(c.peer.as_ref().unwrap()),
            &encode_optional_text(peer),
        );
        let p = ExpectationProfile::parse(text.as_bytes(), &Limits::default()).unwrap();
        let out = f.store.expectations(&p, &Limits::default()).unwrap();
        assert!(
            out.contains("\"status\":\"unresolved\""),
            "literal peer cannot wildcard {out}"
        );
    }
}
#[test]
fn opaque_mrt_route_content_retains_coverage_uncertainty_without_native_mutation() {
    let mut bytes = mrt_bytes(false, false);
    bytes.extend(mrt(99, &[0, 0, 0, 0]));
    let f = fixture("mrt", &bytes, "checkpoint-a");
    let opaque = f
        .store
        .imported_source_events()
        .iter()
        .find(|e| {
            matches!(
                e.kind,
                pcap_evidence_product::deep::bgp_import::ImportedSourceEventKind::Opaque
            )
        })
        .unwrap();
    assert!(opaque.native_continuity.is_empty());
    assert!(opaque.context.is_none());
    let session = f
        .store
        .observations()
        .iter()
        .find(|o| !o.routes().is_empty())
        .unwrap()
        .source()
        .session
        .as_ref()
        .unwrap();
    expect(&f, session, "198.51.100.0/24", "absent", "unresolved");
    expect(&f, session, "203.0.113.0/24", "present", "supported");
    let mut text = profile(&f.store, session, "198.51.100.0/24", "absent");
    text = text.replace("|source-a|", "|source-b|");
    let p = ExpectationProfile::parse(text.as_bytes(), &Limits::default()).unwrap();
    let out = f.store.expectations(&p, &Limits::default()).unwrap();
    assert!(out.contains("\"imported_boundary_witnesses\":[]"));
    let events = changes(
        &f,
        &Query {
            source: Some("source-b".into()),
            ..Query::default()
        },
    );
    assert!(events.contains("\"events\":[]"));
}
#[test]
fn captured_v2_exact_optional_absence_remains_distinct_from_literal_labels() {
    use pcap_evidence::{
        provenance::{EvidenceBytes, PacketId},
        sha256,
    };
    use pcap_evidence_product::deep::{bgp::PcapMetadata, bgp_store::JournalWriter};
    let root = std::env::temp_dir().join(format!(
        "bgp-imported-analysis-capture-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&root).unwrap();
    let path = root.join("source.store");
    let mut w = JournalWriter::create(
        &path,
        "capture-a".into(),
        [3; 32],
        1_048_576,
        Limits::default(),
    )
    .unwrap();
    // Capture replay uses the wire evidence under its default relationship.
    // ORIGIN, two-byte AS_PATH and NEXT_HOP are complete without LOCAL_PREF.
    let attributes = [
        0x40, 1, 1, 0, 0x40, 2, 4, 2, 1, 0xfd, 0xe9, 0x40, 3, 4, 192, 0, 2, 9,
    ];
    let mut update_body = vec![0, 0];
    update_body.extend((attributes.len() as u16).to_be_bytes());
    update_body.extend(attributes);
    update_body.extend([24, 203, 0, 113]);
    let captured_update = bgp(2, &update_body);
    for (frame, direction, message) in [
        (1, 0, open(65001, 1)),
        (2, 1, open(65001, 2)),
        (3, 0, captured_update),
    ] {
        let evidence = EvidenceBytes::from_packet(
            &message,
            PacketId {
                capture: [3; 32],
                frame,
                record_offset: 100 * frame,
            },
            0,
        );
        w.message(
            1,
            &evidence,
            &PcapMetadata {
                source_id: "capture-a".into(),
                record_id: format!("capture-{frame}"),
                observed_at_ns: None,
                session: Some(1),
                direction: Some(direction),
                peer: None,
                local: None,
            },
        )
        .unwrap();
    }
    w.seal().unwrap();
    let store = VerifiedStore::load(
        &path,
        1_048_576,
        MrtLimits::default(),
        Limits::default(),
        MrtReplayOptions::default(),
    )
    .unwrap();
    let f = Fixture { root, path, store };
    let routes: Vec<_> = f
        .store
        .observations()
        .iter()
        .flat_map(|observation| observation.routes())
        .collect();
    assert_eq!(routes.len(), 1);
    assert_eq!(routes[0].prefix().address, "203.0.113.0");
    assert_eq!(routes[0].prefix().length, 24);
    assert!(!routes[0].ambiguous_attributes());
    let pcap_evidence::json::Json::Object(identity) = routes[0].semantic_identity() else {
        panic!("captured route retains its typed semantic identity");
    };
    assert!(identity.iter().any(|(key, value)| {
        *key == "completeness" && value == &pcap_evidence::json::Json::String("complete".into())
    }));
    let pcap_evidence::json::Json::Object(attributes) = routes[0].attributes() else {
        panic!("captured route retains its decoded attributes");
    };
    for (name, expected) in [
        ("origin", pcap_evidence::json::Json::Number(0)),
        (
            "next_hop",
            pcap_evidence::json::Json::String("192.0.2.9".into()),
        ),
        ("local_preference", pcap_evidence::json::Json::Null),
    ] {
        assert!(attributes
            .iter()
            .any(|(key, value)| *key == name && *value == expected));
    }
    let versions: Vec<_> = f.store.retained_route_versions().collect();
    assert_eq!(versions.len(), 1);
    let (key, _, version) = versions[0];
    assert_eq!(key.scope.peer, None);
    assert_eq!(key.scope.direction, Some(0));
    assert_eq!(key.scope.generation, 0);
    assert!(version.native_version_index.is_some());
    assert_eq!(
        version.disposition,
        pcap_evidence_product::deep::bgp_rib::VersionDisposition::Current
    );
    let native = f
        .store
        .query(&Query::default(), &Limits::default())
        .unwrap();
    assert!(native.contains("\"status\":\"active\""), "{native}");
    assert!(native.contains("\"native_current\":true"), "{native}");
    let text=format!("schema=pcap-evidence.bgp.expectation-profile.v2\nprovenance=source-built-capture\ntime_basis=source_occurrence_order\ncoverage=unknown\nexpectation=row|present|text:capture-a|capture-namespace-sha256:{}:captured-lifecycle:0|text:1|0|0|none|none|0|1|1|203.0.113.0/24|absent|origin:65001|unknown|unknown|unknown|unknown\n",sha256::hex(&[3;32]));
    let p = ExpectationProfile::parse(text.as_bytes(), &Limits::default()).unwrap();
    let out = f.store.expectations(&p, &Limits::default()).unwrap();
    assert!(out.contains("\"status\":\"supported\""), "{out}");
    let path = f.root.join("capture-profile.txt");
    fs::write(&path, &text).unwrap();
    let out = cli_with_relationship(
        &f,
        "expectations",
        &["--profile", path.to_str().unwrap()],
        None,
    );
    assert!(out.contains("\"status\":\"supported\""), "{out}");
    let p = ExpectationProfile::parse(
        text.replace("|none|none|0|", "|text:absent|none|0|")
            .as_bytes(),
        &Limits::default(),
    )
    .unwrap();
    let out = f.store.expectations(&p, &Limits::default()).unwrap();
    assert!(out.contains("\"status\":\"unresolved\""), "{out}");
}

#[test]
fn imported_boundary_peer_filters_use_actual_peer_and_keep_omitted_filter_api_and_cli() {
    let (bytes, _, _) = bmp_bytes(true, true, false, false);
    let f = fixture("bmp", &bytes, "checkpoint-a");
    let actual = f
        .store
        .observations()
        .iter()
        .find_map(|o| {
            o.import_context()
                .filter(|c| c.session == "bmp:0:pre")
                .and_then(|c| c.peer.clone())
        })
        .unwrap();
    for peer in [None, Some(actual.as_str()), Some("unrelated-peer")] {
        let q = Query {
            session: Some("bmp:0:pre".into()),
            direction: Some(0),
            peer: peer.map(String::from),
            ..Query::default()
        };
        let out = changes(&f, &q);
        assert_json(&out, "effects=[e for e in d['events'] if e.get('native_continuity')]; assert bool(effects)==(sys.argv[2]=='true'); assert all(e['source_id']=='source-a' and e['checkpoint_id']=='checkpoint-a' for e in effects); assert all(x['source_id']=='source-a' and x['peer']==sys.argv[3] for e in effects for x in e['native_continuity'])", &[if peer != Some("unrelated-peer") { "true" } else { "false" }, &actual]);
        let mut args = vec!["--session", "bmp:0:pre", "--direction", "0"];
        if let Some(peer) = peer {
            args.extend(["--peer", peer]);
        }
        let out = cli(&f, "changes", &args);
        assert_json(&out, "effects=[e for e in d['events'] if e.get('native_continuity')]; assert bool(effects)==(sys.argv[2]=='true'); assert all(e['source_id']=='source-a' and e['checkpoint_id']=='checkpoint-a' for e in effects); assert all(x['source_id']=='source-a' and x['peer']==sys.argv[3] for e in effects for x in e['native_continuity'])", &[if peer != Some("unrelated-peer") { "true" } else { "false" }, &actual]);
    }
    let base = v2_profile(&profile(&f.store, "bmp:0:pre", "203.0.114.0/24", "present"));
    for peer in ["none".to_string(), encode_optional_text("unrelated-peer")] {
        let mut lines = base.lines().map(String::from).collect::<Vec<_>>();
        let row = lines
            .iter_mut()
            .find(|line| line.starts_with("expectation="))
            .unwrap();
        let mut fields = row
            .strip_prefix("expectation=")
            .unwrap()
            .split('|')
            .map(String::from)
            .collect::<Vec<_>>();
        fields[7] = peer;
        *row = format!("expectation={}", fields.join("|"));
        let parsed =
            ExpectationProfile::parse((lines.join("\n") + "\n").as_bytes(), &Limits::default())
                .unwrap();
        let out = f.store.expectations(&parsed, &Limits::default()).unwrap();
        assert!(out.contains("\"imported_boundary_witnesses\":[]"), "{out}");
        assert!(out.contains("\"status\":\"unresolved\""));
    }
}
#[test]
fn v2_source_and_derived_mrt_session_preserve_native_labels_api_and_cli() {
    let bytes = mrt_bytes(false, false);
    for label in ["absent", "none", "text:foo", "a|b%:é", " spaced "] {
        let f = fixture_labeled("mrt", &bytes, label, label);
        let o = f
            .store
            .observations()
            .iter()
            .find(|o| !o.routes().is_empty())
            .unwrap();
        let c = o.import_context().unwrap();
        let partition = SourcePartition::from_import_context(c, &Limits::default()).unwrap();
        let text = format!("schema=pcap-evidence.bgp.expectation-profile.v2\nprovenance=source-built-fixture\ntime_basis=source_occurrence_order\ncoverage=unknown\nexpectation=row|present|{}|{}|{}|{}|{}|{}|{}|absent|1|1|203.0.113.0/24|absent|origin:65001|unknown|unknown|unknown|unknown\n", encode_optional_text(&c.source_id), partition.partition_id, encode_optional_text(&c.session), c.generation, c.direction.unwrap(), encode_optional_text(c.peer.as_ref().unwrap()), encode_optional_text(label));
        let parsed = ExpectationProfile::parse(text.as_bytes(), &Limits::default()).unwrap();
        assert!(f
            .store
            .expectations(&parsed, &Limits::default())
            .unwrap()
            .contains("\"status\":\"supported\""));
        let path = f.root.join("profile-v2.txt");
        fs::write(&path, &text).unwrap();
        assert!(
            cli(&f, "expectations", &["--profile", path.to_str().unwrap()])
                .contains("\"status\":\"supported\"")
        );
        let q = Query {
            source: Some(label.into()),
            session: Some(c.session.clone()),
            checkpoint: Some(label.into()),
            ..Query::default()
        };
        assert!(!f
            .store
            .query(&q, &Limits::default())
            .unwrap()
            .contains("\"rows\":[]"));
        assert!(!cli(
            &f,
            "query",
            &[
                "--source",
                label,
                "--session",
                &c.session,
                "--checkpoint",
                label
            ]
        )
        .contains("\"rows\":[]"));
        let window = pcap_evidence_product::deep::bgp_persisted::query::ReportedTimeWindow {
            source: label.into(),
            clock_policy: pcap_evidence_product::deep::bgp_import::ClockPolicy::SourceLabel,
            clock_id: "mrt-bgp4mp-record-timestamp".into(),
            start_ns: 0,
            end_ns: 200_000_000_000,
        };
        let timed = Query {
            time_window: Some(window.clone()),
            ..q.clone()
        };
        assert!(timed.validate().is_ok());
        assert!(!f
            .store
            .query(&timed, &Limits::default())
            .unwrap()
            .contains("\"rows\":[]"));
        assert!(!cli(
            &f,
            "query",
            &[
                "--source",
                label,
                "--session",
                &c.session,
                "--checkpoint",
                label,
                "--reported-clock-policy",
                "source-label",
                "--reported-clock-id",
                "mrt-bgp4mp-record-timestamp",
                "--reported-clock-source",
                label,
                "--reported-start-ns",
                "0",
                "--reported-end-ns",
                "200000000000"
            ]
        )
        .contains("\"rows\":[]"));
        let wrong = Query {
            time_window: Some(
                pcap_evidence_product::deep::bgp_persisted::query::ReportedTimeWindow {
                    source: "other-source".into(),
                    ..window
                },
            ),
            ..q
        };
        assert!(wrong.validate().is_err());
        if label == "text:foo" {
            expect(&f, &c.session, "203.0.113.0/24", "present", "supported");
        }
        for field in [2, 4] {
            for (label, accepted) in [("é".repeat(512), true), ("é".repeat(512) + "a", false)] {
                let mut lines = text.lines().map(String::from).collect::<Vec<_>>();
                let row = lines
                    .iter_mut()
                    .find(|line| line.starts_with("expectation="))
                    .unwrap();
                let mut fields = row
                    .strip_prefix("expectation=")
                    .unwrap()
                    .split('|')
                    .map(String::from)
                    .collect::<Vec<_>>();
                fields[field] = encode_optional_text(&label);
                *row = format!("expectation={}", fields.join("|"));
                assert_eq!(
                    ExpectationProfile::parse(
                        (lines.join("\n") + "\n").as_bytes(),
                        &Limits::default()
                    )
                    .is_ok(),
                    accepted
                );
            }
            for invalid in [
                "none", "bare", "text:", "text:%41", "text:%ff", "text:%FF", "text:%00",
            ] {
                let mut lines = text.lines().map(String::from).collect::<Vec<_>>();
                let row = lines
                    .iter_mut()
                    .find(|line| line.starts_with("expectation="))
                    .unwrap();
                let mut fields = row
                    .strip_prefix("expectation=")
                    .unwrap()
                    .split('|')
                    .map(String::from)
                    .collect::<Vec<_>>();
                fields[field] = invalid.into();
                *row = format!("expectation={}", fields.join("|"));
                assert!(ExpectationProfile::parse(
                    (lines.join("\n") + "\n").as_bytes(),
                    &Limits::default()
                )
                .is_err());
            }
        }
    }
}
#[test]
fn effectful_changes_output_admits_exact_and_one_below_all_owned_dimensions() {
    let (bytes, _, _) = bmp_bytes(true, true, false, false);
    let f = fixture("bmp", &bytes, "checkpoint-a");
    // Select the complete source document so output-copy admission exceeds
    // the VerifiedStore construction preflight, which precedes this consumer.
    // Direction-filtered behavior is covered by the separate boundary cases.
    let q = Query::default();
    let high = Limits {
        fields: 65536,
        ..Limits::default()
    };
    let expected = f.store.changes(&q, &high).unwrap();
    assert!(expected.contains("\"native_continuity\":[{"));
    // Independent JSON traversal checks the complete public projection rather
    // than reusing product node/span counters.
    let python = std::env::var("PYTHON").unwrap_or_else(|_| {
        if cfg!(windows) {
            "python".into()
        } else {
            "python3".into()
        }
    });
    let census = Command::new(python).args(["-c", "import json,sys\ndef walk(v):\n n=1; s=0\n if isinstance(v,list):\n  for x in v: a,b=walk(x); n+=a; s+=b\n if isinstance(v,dict):\n  for k,x in v.items():\n   a,b=walk(x); n+=a; s+=b\n   if k in ('spans','packets','provenance','ranges') and isinstance(x,list): s+=len(x)\n return n,s\nprint(*walk(json.loads(sys.argv[1])))", &expected]).output().unwrap();
    assert!(census.status.success());
    let counts = String::from_utf8(census.stdout)
        .unwrap()
        .split_whitespace()
        .map(|n| n.parse::<usize>().unwrap())
        .collect::<Vec<_>>();
    // Locate each owning admission frontier without weakening any other cap.
    // This tests the complete effectful public document, not just its carrier.
    for dimension in ["bytes", "spans", "fields", "allocation", "work"] {
        let set = |n| {
            let mut limits = high.clone();
            match dimension {
                "bytes" => limits.output_bytes = n,
                "spans" => limits.spans = n,
                "fields" => limits.fields = n,
                "allocation" => limits.retained_bytes = n,
                _ => limits.work = n,
            }
            limits
        };
        let mut low = 1usize;
        let mut upper = match dimension {
            "bytes" => high.output_bytes,
            "spans" => high.spans,
            "fields" => high.fields,
            "allocation" => high.retained_bytes,
            _ => high.work,
        };
        assert!(f.store.changes(&q, &set(upper)).is_ok());
        while low < upper {
            let middle = low + (upper - low) / 2;
            if f.store.changes(&q, &set(middle)).is_ok() {
                upper = middle;
            } else {
                low = middle + 1;
            }
        }
        assert_eq!(
            f.store.changes(&q, &set(low)).unwrap(),
            expected,
            "{dimension}"
        );
        let error = f.store.changes(&q, &set(low - 1)).unwrap_err();
        assert!(
            error.code == pcap_evidence::ErrorCode::LimitExceeded,
            "{dimension}: {error}"
        );
        if dimension == "bytes" {
            assert_eq!(low, expected.len());
        }
        if dimension == "spans" {
            assert_eq!(low, counts[1]);
        }
        if dimension == "fields" {
            assert!(low >= counts[0]);
        }
        if dimension == "allocation" {
            assert!(error.field.contains("allocation"), "{error}");
        }
        if dimension == "work" {
            assert!(
                error.field.contains("allocation") || error.field.contains("work"),
                "{error}"
            );
        }
    }
}

#[test]
fn multi_effect_bmp_mrt_producer_limits_reject_without_publishing_destination() {
    let (bmp_bytes, _, _) = bmp_bytes(true, true, true, true);
    for (format, bytes) in [("bmp", bmp_bytes), ("mrt", mrt_bytes(true, true))] {
        let f = fixture(format, &bytes, "checkpoint-a");
        let high = Limits {
            fields: 65536,
            ..Limits::default()
        };
        let options = MrtReplayOptions {
            peer_relationship: Some(PeerRelationship::Internal),
        };
        let (effects, native_bytes) = if format == "bmp" {
            let archive = bgp_bmp_store::replay_with_options(
                &f.path,
                1_048_576,
                BmpLimits::default(),
                high.clone(),
                bgp_bmp_store::BmpReplayOptions {
                    peer_relationship: options.peer_relationship,
                },
            )
            .unwrap();
            (
                archive
                    .source_events
                    .iter()
                    .map(|e| e.native_continuity.len())
                    .sum::<usize>(),
                archive.bmp_rib.retained_bytes(),
            )
        } else {
            let archive = bgp_mrt_store::replay_with_options(
                &f.path,
                1_048_576,
                MrtLimits::default(),
                high.clone(),
                options,
            )
            .unwrap();
            (
                archive
                    .source_events
                    .iter()
                    .map(|e| e.native_continuity.len())
                    .sum::<usize>(),
                archive.bgp4mp_rib.retained_bytes(),
            )
        };
        assert!(
            effects >= 2,
            "{format}: expected multiple actual native effects"
        );
        assert!(native_bytes > 0);
        let probe = f.root.join("bounded-producer.store");
        let attempt = |limits: Limits| {
            let result = if format == "bmp" {
                bgp_bmp_store::create_with_options(
                    &probe,
                    &bytes,
                    BmpSource {
                        source_id: "source-a".into(),
                        checkpoint_id: "checkpoint-a".into(),
                    },
                    1_048_576,
                    BmpLimits::default(),
                    limits,
                    bgp_bmp_store::BmpReplayOptions {
                        peer_relationship: options.peer_relationship,
                    },
                )
                .map(|_| ())
            } else {
                bgp_mrt_store::create_with_options(
                    &probe,
                    &bytes,
                    MrtSource {
                        source_id: "source-a".into(),
                        checkpoint_id: "checkpoint-a".into(),
                    },
                    1_048_576,
                    MrtLimits::default(),
                    limits,
                    options,
                )
                .map(|_| ())
            };
            if result.is_ok() {
                assert!(probe.is_file());
                fs::remove_file(&probe).unwrap();
            } else {
                assert!(
                    !probe.exists(),
                    "{format}: rejected transaction published its destination"
                );
            }
            result
        };
        for work in [false, true] {
            let set = |n| {
                if work {
                    Limits {
                        work: n,
                        ..high.clone()
                    }
                } else {
                    Limits {
                        retained_bytes: n,
                        ..high.clone()
                    }
                }
            };
            let mut low = 1;
            let mut upper = if work { high.work } else { high.retained_bytes };
            attempt(set(upper)).unwrap();
            while low < upper {
                let middle = low + (upper - low) / 2;
                if attempt(set(middle)).is_ok() {
                    upper = middle;
                } else {
                    low = middle + 1;
                }
            }
            attempt(set(low)).unwrap();
            assert_eq!(
                attempt(set(low - 1)).unwrap_err().code,
                pcap_evidence::ErrorCode::LimitExceeded
            );
        }
    }
}
