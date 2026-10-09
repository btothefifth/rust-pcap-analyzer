//! Finite synthetic witnesses through sealed replay and the public consumers.
//! Expected relations/statuses come from independently authored wire inputs.
use pcap_evidence::{
    json::Json,
    provenance::{EvidenceBytes, PacketId},
    sha256, ErrorCode,
};
use pcap_evidence_product::deep::{
    bgp::PcapMetadata,
    bgp_association::*,
    bgp_bmp::{BmpLimits, BmpSource},
    bgp_bmp_store,
    bgp_import::ImportedSourceEventKind,
    bgp_mrt::{MrtLimits, MrtSource},
    bgp_mrt_store::{self, MrtReplayOptions},
    bgp_persisted::{AttributeScope, PolicyProfile, Query, VerifiedStore},
    bgp_pipeline::CapturedSessionPipeline,
    bgp_rib::VersionDisposition,
    bgp_store::{self, JournalWriter},
    Limits,
};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
};
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!(
            "bgp-closure-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&p).unwrap();
        Self(p)
    }
    fn path(&self, n: &str) -> PathBuf {
        self.0.join(n)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn limits() -> Limits {
    Limits {
        fields: 65536,
        work: 32 * 1024 * 1024,
        retained_bytes: 32 * 1024 * 1024,
        ..Limits::default()
    }
}
fn wire(med: u32, opaque: bool) -> Vec<u8> {
    let mut attrs = vec![
        0x40, 1, 1, 0, 0x40, 2, 4, 2, 1, 0xfd, 0xe9, 0x40, 3, 4, 192, 0, 2, 9, 0x80, 4, 4,
    ];
    attrs.extend_from_slice(&med.to_be_bytes());
    if opaque {
        attrs.extend_from_slice(&[0x80, 99, 1, 7]);
    }
    let mut body = vec![0, 0];
    body.extend_from_slice(&(attrs.len() as u16).to_be_bytes());
    body.extend(attrs);
    body.extend_from_slice(&[24, 203, 0, 113]);
    let mut out = vec![0xff; 16];
    out.extend_from_slice(&((19 + body.len()) as u16).to_be_bytes());
    out.push(2);
    out.extend(body);
    out
}
fn send(
    w: &mut JournalWriter,
    ns: [u8; 32],
    session: u64,
    frame: u64,
    label: &str,
    bytes: Vec<u8>,
) {
    let e = EvidenceBytes::from_packet(
        &bytes,
        PacketId {
            capture: ns,
            frame,
            record_offset: frame * 100,
        },
        0,
    );
    w.message(
        session,
        &e,
        &PcapMetadata {
            source_id: "capture".into(),
            record_id: label.into(),
            observed_at_ns: Some(frame as i64),
            session: Some(session),
            direction: Some(0),
            peer: Some(format!("192.0.2.{session}")),
            local: Some("192.0.2.254".into()),
        },
    )
    .unwrap();
}
fn opens(w: &mut JournalWriter, ns: [u8; 32], session: u64, base: u64) {
    for d in [0u8, 1] {
        let mut b = vec![0xff; 16];
        b.extend_from_slice(&29u16.to_be_bytes());
        b.push(1);
        b.extend_from_slice(&[4, 0xfd, 0xe9, 0, 90, 192, 0, 2, d + 1, 0]);
        let e = EvidenceBytes::from_packet(
            &b,
            PacketId {
                capture: ns,
                frame: base + u64::from(d),
                record_offset: (base + u64::from(d)) * 100,
            },
            0,
        );
        w.message(
            session,
            &e,
            &PcapMetadata {
                source_id: "capture".into(),
                record_id: format!("open-{base}-{d}"),
                observed_at_ns: Some(base as i64),
                session: Some(session),
                direction: Some(d),
                peer: Some(format!("192.0.2.{session}")),
                local: Some("192.0.2.254".into()),
            },
        )
        .unwrap();
    }
}
fn writer(path: &Path, ns: [u8; 32]) -> JournalWriter {
    JournalWriter::create(path, "capture".into(), ns, 1024 * 1024, limits()).unwrap()
}
fn load(path: &Path) -> VerifiedStore {
    VerifiedStore::load(
        path,
        1024 * 1024,
        MrtLimits::default(),
        limits(),
        MrtReplayOptions::default(),
    )
    .unwrap()
}
fn get<'a>(v: &'a Json, k: &str) -> &'a Json {
    let Json::Object(f) = v else {
        panic!("object required")
    };
    &f.iter().find(|(n, _)| *n == k).unwrap().1
}
fn parsed_assert(value: &str, assertion: &str) {
    let py = std::env::var("PYTHON").unwrap_or_else(|_| "python3".into());
    let code = format!("import json,sys\nx=json.load(sys.stdin)\n{assertion}\n");
    let mut c = Command::new(py)
        .args(["-B", "-c", &code])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    c.stdin.take().unwrap().write_all(value.as_bytes()).unwrap();
    let r = c.wait_with_output().unwrap();
    assert!(r.status.success(), "{}", String::from_utf8_lossy(&r.stderr));
}
fn validate_occurrence_refs(value: &str) {
    let schema = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("docs/product/bgp-route-occurrence-reference.schema.json");
    parsed_assert(value, &format!("import jsonschema\ns=json.load(open({:?}))\nrefs=[o for r in x.get('routes',x.get('alternatives',[])) for v in r['version_occurrences'] for o in v['occurrences']]\nassert refs\nfor o in refs: jsonschema.validate(o,s)", schema.to_str().unwrap()));
}
fn policy() -> Policy {
    Policy {
        policy_id: "finite-explicit".into(),
        session: DimensionRule::Ignore,
        generation: DimensionRule::Ignore,
        flow: DimensionRule::Ignore,
        direction: DirectionRule::Ignore,
        spatial: SpatialRule::EqualPrefix,
        time: TimePolicy::Ignore {
            reason: "explicitly_ignored_finite_test".into(),
        },
    }
}
fn single(path: &Path, n: u8, med: u32, opaque: bool) {
    let ns = [n; 32];
    let mut w = writer(path, ns);
    opens(&mut w, ns, 1, 100);
    send(&mut w, ns, 1, 1, "same-label", wire(med, opaque));
    w.seal().unwrap();
}

#[test]
fn accepted_versions_keep_exact_occurrences_across_reused_labels_and_lifecycles() {
    let s = Scratch::new();
    let path = s.path("history");
    let ns = [10; 32];
    let mut w = writer(&path, ns);
    opens(&mut w, ns, 1, 100);
    send(&mut w, ns, 1, 1, "shared", wire(10, false));
    send(&mut w, ns, 1, 2, "changed", wire(20, false));
    w.end_session(1).unwrap();
    opens(&mut w, ns, 1, 200);
    send(&mut w, ns, 1, 3, "shared", wire(30, false));
    opens(&mut w, ns, 2, 300);
    send(&mut w, ns, 2, 4, "shared", wire(40, false));
    w.seal().unwrap();
    let store = load(&path);
    let versions = store.retained_route_versions().collect::<Vec<_>>();
    assert_eq!(versions.len(), 4);
    assert!(versions
        .iter()
        .any(|(_, _, v)| v.disposition == VersionDisposition::Replaced));
    let mut occurrence_ids = std::collections::BTreeSet::new();
    for (key, life, version) in &versions {
        assert_eq!(version.occurrences.len(), 1);
        let o = &version.occurrences[0];
        let observation = &store.observations()[o.observation_index];
        let route = &observation.routes()[o.route_index];
        assert_eq!(route.prefix(), &key.prefix);
        assert_eq!(
            observation.source().session.as_deref(),
            Some(key.scope.session.as_str())
        );
        assert_eq!(
            get(&o.occurrence_ref, "captured_lifecycle"),
            &life.unwrap().into()
        );
        assert_eq!(
            get(&o.occurrence_ref, "normalized_observation_sha256"),
            &sha256::hex(&observation.sha256()).into()
        );
        occurrence_ids.insert(get(&o.occurrence_ref, "source_occurrence_id").encode());
    }
    assert_eq!(occurrence_ids.len(), 4);
    let full = store.query_evidence(&Query::default(), &limits()).unwrap();
    parsed_assert(&full,"assert x['schema']=='pcap-evidence.bgp.persisted-query.v2'\nrefs=[o for r in x['routes'] for v in r['version_occurrences'] for o in v['occurrences']]\nassert len(refs)==4\nassert all(o['provenance']['coordinate_system']=='captured_packet' and o['provenance']['captured_evidence']['spans'] for o in refs)\nassert all(o['clock']['clock_id']=='capture:'+('0a'*32) for o in refs)");
}

#[test]
fn policy_preserves_withdrawn_and_superseded_exclusions_and_suppresses_historical_active() {
    let s = Scratch::new();
    let path = s.path("history");
    let ns = [11; 32];
    let mut w = writer(&path, ns);
    opens(&mut w, ns, 1, 100);
    send(&mut w, ns, 1, 1, "active", wire(10, false));
    w.end_session(1).unwrap();
    opens(&mut w, ns, 1, 200);
    send(&mut w, ns, 1, 2, "before-withdraw", wire(20, false));
    let mut withdrawal = vec![0xff; 16];
    withdrawal.extend_from_slice(&27u16.to_be_bytes());
    withdrawal.push(2);
    withdrawal.extend_from_slice(&[0, 4, 24, 203, 0, 113, 0, 0]);
    send(&mut w, ns, 1, 3, "withdraw", withdrawal);
    w.end_session(1).unwrap();
    opens(&mut w, ns, 1, 300);
    send(&mut w, ns, 1, 4, "before-reset", wire(30, false));
    w.reset(1, "reset", "explicit-generation").unwrap();
    opens(&mut w, ns, 1, 400);
    send(&mut w, ns, 1, 5, "current", wire(40, false));
    w.seal().unwrap();
    let p=PolicyProfile::parse(b"schema=pcap-evidence.bgp.persisted-policy.v1\nprovenance=finite\ncomparison_context=finite\nmissing_local_preference=100\nmed_rule=skip\nage_rule=skip\n",&limits()).unwrap();
    let result = load(&path)
        .policy(&Query::default(), &p, &limits())
        .unwrap();
    parsed_assert(&result,"excluded=[e for p in x['policy_results'] for e in p['excluded']]\nassert {'withdrawn','superseded','unresolved'} <= {e['status'] for e in excluded}\nassert len(x['alternatives'])-len({e['id'] for e in excluded})==1");
}

#[test]
fn semantic_relation_is_separate_from_current_admission_and_keeps_source_occurrences() {
    let s = Scratch::new();
    let a = s.path("a");
    let b = s.path("b");
    let c = s.path("c");
    let d = s.path("d");
    single(&a, 12, 10, false);
    single(&b, 13, 10, false);
    single(&c, 14, 20, false);
    single(&d, 15, 10, true);
    let left = load(&a);
    for (path, expected) in [(&b, "equal"), (&c, "distinct"), (&d, "unavailable")] {
        let right = load(path);
        let full = left
            .associate_evidence(&right, "explicit-shared", &policy(), &limits())
            .unwrap();
        parsed_assert(&full,&format!("r=x['association_report']\nassert r['schema']=='pcap-evidence.bgp.association.v3'\nassert [a['semantic_relation'] for a in r['associations']]==['{expected}']\nassert x['occurrences_merged'] is False\nassert r['best_path_selected'] is False and r['source_authority_established'] is False\nassert len(r['route_evidence'])==1 and len(r['internal_evidence'])==1\nassert {{n['witness']['side'] for n in r['selection_notes']}}=={{'left','right'}}"));
    }
    let legacy = left
        .associate(&load(&b), "explicit-shared", &policy(), &limits())
        .unwrap();
    parsed_assert(&legacy,"assert x['association_report']['schema']=='pcap-evidence.bgp.association.v2'\nassert all('semantic_relation' not in a for a in x['association_report']['associations'])");
}

#[test]
fn route_free_and_rejected_container_notes_preserve_boundaries_without_routes() {
    let s = Scratch::new();
    let a = s.path("a");
    let b = s.path("b");
    let ns = [16; 32];
    let mut w = writer(&a, ns);
    opens(&mut w, ns, 1, 100);
    w.gap(1, "gap", "source-gap").unwrap();
    w.reset(1, "reset", "source-reset").unwrap();
    let mut bad = vec![0xff; 16];
    bad.extend_from_slice(&20u16.to_be_bytes());
    bad.extend_from_slice(&[4, 0]);
    send(&mut w, ns, 1, 1, "rejected", bad);
    w.end_session(1).unwrap();
    w.clear().unwrap();
    w.seal().unwrap();
    let mut other = writer(&b, [17; 32]);
    opens(&mut other, [17; 32], 2, 200);
    other.seal().unwrap();
    let archive = bgp_store::replay(&a, 1024 * 1024, limits()).unwrap();
    assert_eq!(archive.source_events.len(), 5);
    assert!(archive
        .source_events
        .windows(2)
        .all(|v| v[0].source_record_index < v[1].source_record_index));
    assert!(archive
        .source_events
        .iter()
        .all(|e| e.source_start < e.source_end));
    let full = load(&a)
        .associate_evidence(&load(&b), "route-free", &policy(), &limits())
        .unwrap();
    parsed_assert(&full,"r=x['association_report']\nassert r['route_evidence']==[] and r['internal_evidence']==[]\nassert {'open','gap','reset','rejected_container','end_session','clear'} <= {n['source_event_kind'] for n in r['selection_notes']}\nassert r['associations'][0]['semantic_relation']=='unavailable'");
    let mut exact = limits();
    exact.output_bytes = full.len();
    assert_eq!(
        load(&a)
            .associate_evidence(&load(&b), "route-free", &policy(), &exact)
            .unwrap(),
        full
    );
    exact.output_bytes -= 1;
    assert_eq!(
        load(&a)
            .associate_evidence(&load(&b), "route-free", &policy(), &exact)
            .unwrap_err()
            .code,
        ErrorCode::LimitExceeded
    );
    let mut low = limits();
    low.elements = 1;
    assert_eq!(
        load(&a)
            .associate_evidence(&load(&b), "route-free", &policy(), &low)
            .unwrap_err()
            .code,
        ErrorCode::LimitExceeded
    );
}

#[test]
fn imported_collector_refs_keep_source_ranges_and_exact_output_limit() {
    fn record(subtype: u16, body: &[u8]) -> Vec<u8> {
        let mut v = 12u32.to_be_bytes().to_vec();
        v.extend_from_slice(&13u16.to_be_bytes());
        v.extend_from_slice(&subtype.to_be_bytes());
        v.extend_from_slice(&(body.len() as u32).to_be_bytes());
        v.extend_from_slice(body);
        v
    }
    let mut peers = vec![
        192, 0, 2, 1, 0, 1, b'v', 0, 1, 2, 192, 0, 2, 2, 203, 0, 113, 9,
    ];
    peers.extend_from_slice(&65551u32.to_be_bytes());
    let mut attrs = vec![0x40, 1, 1, 0, 0x40, 2, 6, 2, 1];
    attrs.extend_from_slice(&65551u32.to_be_bytes());
    attrs.extend_from_slice(&[0x40, 3, 4, 192, 0, 2, 9]);
    let mut rib = vec![0, 0, 0, 7, 24, 203, 0, 113, 0, 1];
    rib.extend_from_slice(&0u16.to_be_bytes());
    rib.extend_from_slice(&10u32.to_be_bytes());
    rib.extend_from_slice(&(attrs.len() as u16).to_be_bytes());
    rib.extend(attrs);
    let raw = [record(1, &peers), record(2, &rib)].concat();
    let s = Scratch::new();
    let path = s.path("import");
    bgp_mrt_store::create(
        &path,
        &raw,
        MrtSource {
            source_id: "collector".into(),
            checkpoint_id: "checkpoint".into(),
        },
        1024 * 1024,
        MrtLimits::default(),
        limits(),
    )
    .unwrap();
    let store = load(&path);
    let full = store.query_evidence(&Query::default(), &limits()).unwrap();
    validate_occurrence_refs(&full);
    parsed_assert(&full,"o=x['routes'][0]['version_occurrences'][0]['occurrences'][0]\nassert o['captured_lifecycle'] is None\nassert o['provenance']['coordinate_system']=='source_relative'\nassert o['provenance']['captured_evidence'] is None\nassert o['provenance']['import_context']['provenance']\nassert all(int(s['start'])<int(s['end']) for s in o['provenance']['import_context']['provenance'])");
    let mut exact = limits();
    exact.output_bytes = full.len();
    assert_eq!(
        store.query_evidence(&Query::default(), &exact).unwrap(),
        full
    );
    exact.output_bytes -= 1;
    assert_eq!(
        store
            .query_evidence(&Query::default(), &exact)
            .unwrap_err()
            .code,
        ErrorCode::LimitExceeded
    );
}

#[test]
fn mixed_route_and_gap_association_keeps_boundary_scope_without_synthetic_withdrawal() {
    let s = Scratch::new();
    let a = s.path("mixed-a");
    let b = s.path("mixed-b");
    let ns = [21; 32];
    let mut w = writer(&a, ns);
    opens(&mut w, ns, 1, 100);
    send(&mut w, ns, 1, 1, "route-before-gap", wire(10, false));
    w.gap(1, "gap-after-route", "exact-source-gap").unwrap();
    w.seal().unwrap();
    single(&b, 22, 10, false);
    let full = load(&a)
        .associate_evidence(&load(&b), "mixed", &policy(), &limits())
        .unwrap();
    parsed_assert(&full, "r=x['association_report']\nassert len(r['route_evidence'])==1 and len(r['internal_evidence'])==1\nassert any(n.get('source_event_kind')=='gap' and n['witness']['side']=='left' for n in r['selection_notes'])\nassert r['associations'][0]['semantic_relation']=='equal'\nassert x['occurrences_merged'] is False\nassert not r['source_authority_established'] and not r['best_path_selected']");
}

#[test]
fn bmp_monitoring_container_never_claims_embedded_kind_without_bound_observation() {
    fn bgp_message(kind: u8, body: &[u8]) -> Vec<u8> {
        let mut v = vec![255; 16];
        v.extend_from_slice(&((19 + body.len()) as u16).to_be_bytes());
        v.push(kind);
        v.extend_from_slice(body);
        v
    }
    fn open(asn: u16, id: u8) -> Vec<u8> {
        let mut b = vec![4];
        b.extend_from_slice(&asn.to_be_bytes());
        b.extend_from_slice(&90u16.to_be_bytes());
        b.extend_from_slice(&[10, 0, 0, id]);
        b.push(0);
        bgp_message(1, &b)
    }
    fn peer(seconds: u32) -> Vec<u8> {
        let mut b = vec![0, 0x20];
        b.extend_from_slice(&[0; 8]);
        b.extend_from_slice(&[0; 12]);
        b.extend_from_slice(&[192, 0, 2, 1]);
        b.extend_from_slice(&65001u32.to_be_bytes());
        b.extend_from_slice(&[10, 0, 0, 1]);
        b.extend_from_slice(&seconds.to_be_bytes());
        b.extend_from_slice(&7u32.to_be_bytes());
        assert_eq!(b.len(), 42);
        b
    }
    fn bmp(kind: u8, body: &[u8]) -> Vec<u8> {
        let mut v = vec![3];
        v.extend_from_slice(&((6 + body.len()) as u32).to_be_bytes());
        v.push(kind);
        v.extend_from_slice(body);
        v
    }
    let mut up = peer(100);
    up.extend_from_slice(&[0; 12]);
    up.extend_from_slice(&[192, 0, 2, 254]);
    up.extend_from_slice(&179u16.to_be_bytes());
    up.extend_from_slice(&40000u16.to_be_bytes());
    up.extend_from_slice(&open(65000, 254));
    up.extend_from_slice(&open(65001, 1));
    let mut raw = bmp(3, &up);
    for (index, message) in [open(65001, 1), bgp_message(4, &[]), wire(10, false)]
        .into_iter()
        .enumerate()
    {
        let mut body = peer(101 + index as u32);
        body.extend(message);
        raw.extend(bmp(0, &body));
    }
    // Preserve the adverse OPEN/KEEPALIVE + quarantined UPDATE prefix.
    // A new verified PeerUp owns restoration of the reported context; the
    // same two-octet UPDATE then supplies the positive bound occurrence.
    raw.extend(bmp(3, &up));
    let mut recovered = peer(105);
    recovered.extend(wire(10, false));
    raw.extend(bmp(0, &recovered));
    let scratch = Scratch::new();
    let path = scratch.path("monitoring");
    let archive = bgp_bmp_store::create(
        &path,
        &raw,
        BmpSource {
            source_id: "bmp-typed-events".into(),
            checkpoint_id: "checkpoint".into(),
        },
        1024 * 1024,
        BmpLimits::default(),
        limits(),
    )
    .unwrap();
    let replay = bgp_bmp_store::replay(&path, 1024 * 1024, BmpLimits::default(), limits()).unwrap();
    let full_output = archive.encoded_len_bounded(usize::MAX).unwrap();
    let unchanged_source = fs::read(&path).unwrap();
    let mut exact = limits();
    exact.output_bytes = full_output;
    let bounded =
        bgp_bmp_store::replay(&path, 1024 * 1024, BmpLimits::default(), exact.clone()).unwrap();
    assert_eq!(bounded.json(), archive.json());
    exact.output_bytes -= 1;
    assert_eq!(
        bgp_bmp_store::replay(&path, 1024 * 1024, BmpLimits::default(), exact)
            .err()
            .expect("one-below BMP output must be rejected")
            .code,
        ErrorCode::LimitExceeded
    );
    assert_eq!(fs::read(&path).unwrap(), unchanged_source);
    for archive in [&archive, &replay] {
        assert_eq!(
            get(&archive.bmp_events[4], "status"),
            &Json::from("reported_peer_up")
        );
        for ordinal in [1usize, 2, 3, 5] {
            let events: Vec<_> = archive
                .source_events
                .iter()
                .filter(|e| e.source_record_index == ordinal)
                .collect();
            let containers: Vec<_> = events
                .iter()
                .filter(|e| e.observation_index.is_none())
                .collect();
            assert_eq!(containers.len(), 1);
            let observations: Vec<_> = events
                .iter()
                .filter(|e| e.observation_index.is_some())
                .collect();
            match ordinal.cmp(&3) {
                std::cmp::Ordering::Less => {
                    // RouteMonitoring's declared grammar requires UPDATE. OPEN/KEEPALIVE
                    // containers are opaque rejected inputs, without invented observations.
                    assert_eq!(containers[0].kind, ImportedSourceEventKind::Opaque);
                    assert!(observations.is_empty());
                }
                std::cmp::Ordering::Equal => {
                    assert_eq!(containers[0].kind, ImportedSourceEventKind::SessionMetadata);
                    assert!(observations.is_empty());
                    assert_eq!(
                        get(&archive.bmp_events[ordinal], "status"),
                        &Json::from("quarantined_route_monitoring")
                    );
                    assert_eq!(
                        get(&archive.bmp_events[ordinal], "issues"),
                        &Json::array([Json::from("missing_unambiguous_reported_peer_up")])
                    );
                }
                std::cmp::Ordering::Greater => {
                    assert_eq!(containers[0].kind, ImportedSourceEventKind::SessionMetadata);
                    assert_eq!(observations.len(), 1);
                    assert_eq!(observations[0].kind, ImportedSourceEventKind::Update);
                    let observed = archive
                        .state
                        .observations()
                        .get(observations[0].observation_index.unwrap())
                        .unwrap();
                    assert_eq!(observations[0].context.as_ref(), observed.import_context());
                    assert_eq!(observed.routes().len(), 1);
                    assert_eq!(observed.routes()[0].prefix().address, "203.0.113.0");
                    assert_eq!(
                        get(&archive.bmp_events[ordinal], "status"),
                        &Json::from("decoded_route_monitoring_candidate")
                    );
                }
            }
            assert_eq!(
                events
                    .iter()
                    .filter(|e| e.kind == ImportedSourceEventKind::Update)
                    .count(),
                usize::from(ordinal == 5)
            );
        }
    }
}

#[test]
fn identical_attributes_under_conflicting_record_labels_keep_exact_version_occurrences() {
    let scratch = Scratch::new();
    let path = scratch.path("conflicting-label");
    let ns = [23; 32];
    let mut w = writer(&path, ns);
    opens(&mut w, ns, 1, 100);
    send(&mut w, ns, 1, 1, "same-label", wire(10, false));
    let mut second = wire(10, false);
    second.extend_from_slice(&[24, 204, 0, 113]);
    let length = second.len() as u16;
    second[16..18].copy_from_slice(&length.to_be_bytes());
    send(&mut w, ns, 1, 2, "same-label", second);
    w.seal().unwrap();
    let store = load(&path);
    let full = store.query_evidence(&Query::default(), &limits()).unwrap();
    parsed_assert(&full,"r=next(r for r in x['routes'] if r['prefix']=='203.0.113.0/24')\nassert r['status']=='unresolved'\nv=r['version_occurrences']\nassert len(v)==2\nassert [len(a['occurrences']) for a in v]==[1,1]\nassert [len(a['occurrences'][0]['normalized_observation']['routes']) for a in v]==[1,2]\nassert len({a['occurrences'][0]['source_occurrence_id'] for a in v})==2\nassert len({a['occurrences'][0]['normalized_observation_sha256'] for a in v})==2");
    parsed_assert(&full,"b=next(r for r in x['routes'] if r['prefix']=='204.0.113.0/24')\nassert len(b['version_occurrences'])==1\nv=b['version_occurrences'][0]\nassert v['disposition']=='conflicting' and len(v['occurrences'])==1\no=v['occurrences'][0]\nassert o['route_index']==1 and o['native_origin']['route_index']==1\nassert len(o['normalized_observation']['routes'])==2");
    for version_index in 0..=1 {
        let query = Query {
            prefix: Some("203.0.113.0/24".into()),
            attribute_scope: Some(AttributeScope::AnyRetainedVersion),
            version_index: Some(version_index),
            ..Query::default()
        };
        let selected = store.query_evidence(&query, &limits()).unwrap();
        parsed_assert(&selected,&format!("a=x['attribute_matches']\nassert len(a)==1 and a[0]['version_index']=={version_index}\no=a[0]['occurrence']\nassert o['native_origin']['version_index']=={version_index}\nassert o['route_index']==0\nassert len(o['normalized_observation']['routes'])=={}",version_index+1));
    }
}

#[test]
fn repeated_source_occurrences_keep_one_native_version_and_exact_replay_origins() {
    for (name, second_frame, second_label, expected_origins) in [
        ("immutable", 1, "first", 1),
        ("native-replay", 2, "first", 2),
        ("repeat", 2, "second", 2),
    ] {
        let scratch = Scratch::new();
        let path = scratch.path(name);
        let ns = [24; 32];
        let mut w = writer(&path, ns);
        opens(&mut w, ns, 1, 100);
        send(&mut w, ns, 1, 1, "first", wire(10, false));
        send(&mut w, ns, 1, second_frame, second_label, wire(10, false));
        w.seal().unwrap();
        let archive = bgp_store::replay(&path, 1024 * 1024, limits()).unwrap();
        // Actual sealed replay owns source/native/snapshot element admission.
        // Locate its finite exact boundary, then require the adjacent rejection.
        let mut below = 0usize;
        let mut admitted = limits().elements;
        while admitted - below > 1 {
            let mid = below + (admitted - below) / 2;
            let mut bounded = limits();
            bounded.elements = mid;
            match bgp_store::replay(&path, 1024 * 1024, bounded) {
                Ok(_) => admitted = mid,
                Err(error) => {
                    assert_eq!(error.code, ErrorCode::LimitExceeded);
                    below = mid;
                }
            }
        }
        let mut bounded = limits();
        bounded.elements = admitted;
        bgp_store::replay(&path, 1024 * 1024, bounded.clone()).unwrap();
        bounded.elements = admitted - 1;
        assert_eq!(
            bgp_store::replay(&path, 1024 * 1024, bounded)
                .unwrap_err()
                .code,
            ErrorCode::LimitExceeded
        );
        let entry = archive
            .route_entries
            .iter()
            .find(|e| e.key.prefix.address == "203.0.113.0")
            .unwrap();
        assert_eq!(
            entry.status,
            pcap_evidence_product::deep::bgp_rib::RouteStatus::Active
        );
        assert_eq!(entry.versions.len(), 1);
        assert_eq!(entry.versions[0].occurrences.len(), expected_origins);
        let store = load(&path);
        let versions: Vec<_> = store.retained_route_versions().collect();
        assert_eq!(versions.len(), 1);
        assert_eq!(versions[0].2.native_version_index, Some(0));
        assert_eq!(versions[0].2.occurrences.len(), 2);
        assert!(versions[0]
            .2
            .occurrences
            .iter()
            .all(|o| o.native_event_index.is_some()));
        let full = store.query_evidence(&Query::default(), &limits()).unwrap();
        assert_eq!(store.state_evidence(&limits()).unwrap(), full);
        let profile=PolicyProfile::parse(b"schema=pcap-evidence.bgp.persisted-policy.v1\nprovenance=finite\ncomparison_context=finite\nmissing_local_preference=100\nmed_rule=skip\nage_rule=skip\n",&limits()).unwrap();
        let policy_output = store
            .policy_evidence(&Query::default(), &profile, &limits())
            .unwrap();
        validate_occurrence_refs(&policy_output);
        validate_occurrence_refs(&full);
        let mut exact = limits();
        exact.output_bytes = full.len();
        assert_eq!(
            store.query_evidence(&Query::default(), &exact).unwrap(),
            full
        );
        exact.output_bytes -= 1;
        assert_eq!(
            store
                .query_evidence(&Query::default(), &exact)
                .unwrap_err()
                .code,
            ErrorCode::LimitExceeded
        );
        parsed_assert(&full,"v=x['routes'][0]['version_occurrences']\nassert len(v)==1 and v[0]['native_version_index']==0\nassert v[0]['origin_binding']=='verified_native_version_occurrences'\no=v[0]['occurrences']\nassert len(o)==2 and len({a['source_occurrence_id'] for a in o})==2\nassert all(a['schema']=='pcap-evidence.bgp.route-occurrence-reference.v2' and a['native_origin']['version_index']==0 and a['native_origin']['observation_sha256']==a['normalized_observation_sha256'] and a['native_origin']['route_index']==a['route_index'] for a in o)");
    }
}

#[test]
fn captured_actual_receipt_output_is_exact_and_one_below_is_atomic() {
    let ns = [25; 32];
    let mut inputs = Vec::new();
    for index in 0..4usize {
        let frame = index as u64 + 1;
        let bytes = if index < 2 {
            let mut open = vec![0xff; 16];
            open.extend_from_slice(&29u16.to_be_bytes());
            open.push(1);
            open.extend_from_slice(&[4, 0xfd, 0xe9, 0, 90, 192, 0, 2, index as u8 + 1, 0]);
            open
        } else {
            wire(10, false)
        };
        let evidence = EvidenceBytes::from_packet(
            &bytes,
            PacketId {
                capture: ns,
                frame,
                record_offset: frame * 100,
            },
            0,
        );
        let metadata = PcapMetadata {
            source_id: "capture".into(),
            record_id: if index == 3 {
                "last".repeat(256)
            } else {
                format!("record-{frame}")
            },
            observed_at_ns: Some(frame as i64),
            session: Some(1),
            direction: Some(if index == 1 { 1 } else { 0 }),
            peer: Some("192.0.2.1".into()),
            local: Some("192.0.2.254".into()),
        };
        inputs.push((evidence, metadata));
    }
    let mut probe = CapturedSessionPipeline::new(ns, "capture".into(), 1, limits()).unwrap();
    let mut receipts = Vec::new();
    for (evidence, metadata) in &inputs {
        receipts.push(
            probe
                .apply_message(evidence, metadata.clone())
                .unwrap()
                .normalized,
        );
    }
    let exact_size = receipts
        .last()
        .unwrap()
        .encoded_len_bounded(usize::MAX)
        .unwrap();
    assert!(receipts[..3]
        .iter()
        .all(|value| value.encoded_len_bounded(usize::MAX).unwrap() < exact_size));
    let mut exact = limits();
    exact.output_bytes = exact_size;
    let mut admitted =
        CapturedSessionPipeline::new(ns, "capture".into(), 1, exact.clone()).unwrap();
    for ((evidence, metadata), expected) in inputs.iter().zip(&receipts) {
        assert_eq!(
            admitted
                .apply_message(evidence, metadata.clone())
                .unwrap()
                .normalized,
            *expected
        );
    }
    assert_eq!(
        admitted.rib().entries().values().next().unwrap().versions[0]
            .occurrences
            .len(),
        2
    );
    exact.output_bytes -= 1;
    let mut denied = CapturedSessionPipeline::new(ns, "capture".into(), 1, exact).unwrap();
    for (evidence, metadata) in &inputs[..3] {
        denied.apply_message(evidence, metadata.clone()).unwrap();
    }
    let before_wire = denied.wire_state().clone();
    let before_observer = denied.observer().events().to_vec();
    let before_native = denied.rib().events().to_vec();
    let before_entries = denied.rib().entries().clone();
    for _ in 0..2 {
        assert_eq!(
            denied
                .apply_message(&inputs[3].0, inputs[3].1.clone())
                .unwrap_err()
                .code,
            ErrorCode::LimitExceeded
        );
        assert_eq!(denied.wire_state(), &before_wire);
        assert_eq!(denied.observer().events(), before_observer);
        assert_eq!(denied.rib().events(), before_native);
        assert_eq!(denied.rib().entries(), &before_entries);
        assert!(!denied.tainted());
    }
}

fn continuity_message(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![0xff; 16];
    out.extend_from_slice(&((body.len() + 19) as u16).to_be_bytes());
    out.push(kind);
    out.extend_from_slice(body);
    out
}
fn continuity_mp_gap() -> Vec<u8> {
    let mut attrs = vec![
        0x40, 1, 1, 0, 0x40, 2, 4, 2, 1, 0xfd, 0xe9, 0x40, 3, 4, 192, 0, 2, 9,
    ];
    attrs.extend_from_slice(&[0x80, 14, 13, 0, 25, 1, 4, 192, 0, 2, 9, 0, 24, 203, 0, 113]);
    let mut body = vec![0, 0];
    body.extend_from_slice(&(attrs.len() as u16).to_be_bytes());
    body.extend(attrs);
    continuity_message(2, &body)
}
#[test]
fn decoded_continuity_is_bound_to_source_and_cached_replay_is_inert() {
    let scratch = Scratch::new();
    let path = scratch.path("continuity.store");
    let ns = [23; 32];
    let mut writer = JournalWriter::create(&path, "capture".into(), ns, 1 << 20, limits()).unwrap();
    opens(&mut writer, ns, 1, 100);
    send(&mut writer, ns, 1, 1, "before", wire(1, false));
    send(&mut writer, ns, 1, 2, "native-gap", continuity_mp_gap());
    send(&mut writer, ns, 1, 3, "after-gap", wire(1, false));
    send(&mut writer, ns, 1, 2, "native-gap", continuity_mp_gap());
    send(&mut writer, ns, 1, 4, "after-replay", wire(1, false));
    writer.seal().unwrap();
    for archive in [
        bgp_store::replay(&path, 1 << 20, limits()).unwrap(),
        bgp_store::replay(&path, 1 << 20, limits()).unwrap(),
    ] {
        let events: Vec<_> = archive
            .source_events
            .iter()
            .filter(|e| e.continuity.is_some())
            .collect();
        assert_eq!(events.len(), 2);
        for (event, index, applied) in [(events[0], 3, true), (events[1], 5, false)] {
            let c = event.continuity.as_ref().unwrap();
            assert_eq!(c.observation_index, index);
            assert_eq!(c.observation_sha256, archive.observations[index].sha256());
            assert_eq!(c.decision.newly_applied, applied);
            assert_eq!(c.decision.reason, "decoded_update_opaque_route_evidence");
            assert_eq!(event.kind.name(), "decoded_gap");
            assert_eq!(
                event.source_record_index,
                archive.observation_evidence[index].source_record_index
            );
            assert_eq!(
                event.journal_record_sha256,
                archive.observation_evidence[index].journal_record_sha256
            );
            assert_eq!(event.packet_spans.len(), 1);
            assert_eq!(event.packet_spans[0].packet.frame, 2);
            assert_eq!(
                get(&event.json(), "schema"),
                &Json::from("pcap-evidence.bgp.captured-source-event.v2")
            );
            assert!(archive.observations[index].routes().is_empty());
        }
    }
}
#[test]
fn decoded_continuity_family_preserves_actual_gap_reset_and_conflict_outcomes() {
    for case in [
        "ordinary",
        "contradictory-open",
        "protocol-reset",
        "identity-conflict",
        "empty",
        "eor",
    ] {
        let scratch = Scratch::new();
        let path = scratch.path("family.store");
        let ns = [24; 32];
        let mut writer =
            JournalWriter::create(&path, "capture".into(), ns, 1 << 20, limits()).unwrap();
        if case == "ordinary" {
            send(
                &mut writer,
                ns,
                1,
                100,
                "unilateral",
                continuity_message(
                    1,
                    &[
                        4, 0xfd, 0xe9, 0, 90, 192, 0, 2, 1, 8, 2, 6, 69, 4, 0, 1, 1, 2,
                    ],
                ),
            );
        } else {
            opens(&mut writer, ns, 1, 100);
            send(&mut writer, ns, 1, 1, "before", wire(1, false));
        }
        let (label, bytes) = match case {
            "ordinary" => ("boundary", wire(1, false)),
            "contradictory-open" => (
                "boundary",
                continuity_message(1, &[4, 0xfd, 0xe9, 0, 91, 192, 0, 2, 1, 0]),
            ),
            "protocol-reset" => ("boundary", continuity_message(3, &[6, 0])),
            "identity-conflict" => ("before", wire(9, false)),
            "empty" => (
                "boundary",
                continuity_message(2, &[0, 0, 0, 4, 0x40, 1, 1, 0]),
            ),
            "eor" => ("boundary", continuity_message(2, &[0, 0, 0, 0])),
            _ => unreachable!(),
        };
        send(&mut writer, ns, 1, 2, label, bytes);
        writer.seal().unwrap();
        let archive = bgp_store::replay(&path, 1 << 20, limits()).unwrap();
        let events: Vec<_> = archive
            .source_events
            .iter()
            .filter(|e| e.continuity.is_some())
            .collect();
        if matches!(case, "empty" | "eor") {
            assert!(events.is_empty());
            continue;
        }
        assert_eq!(events.len(), 1, "{case}");
        let c = events[0].continuity.as_ref().unwrap();
        assert!(c.decision.newly_applied);
        assert_eq!(c.decision.is_reset(), case == "protocol-reset");
        assert_eq!(
            c.observation_sha256,
            archive.observations[c.observation_index].sha256()
        );
        assert_eq!(c.decision.scope.session, "1");
        let mut other = c.decision.scope.clone();
        other.session = "2".into();
        assert!(!c.decision.affects_scope(&other));
        if case == "protocol-reset" {
            assert_eq!(c.decision.generations(), (0, 1));
        }
        if case == "identity-conflict" {
            assert_eq!(
                c.decision.native_status,
                Some(pcap_evidence_product::deep::bgp_rib::ApplyStatus::IdentityConflict)
            );
        }
    }
}
