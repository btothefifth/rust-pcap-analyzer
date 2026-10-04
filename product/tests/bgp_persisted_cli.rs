//! Tiny source-built stores exercised by fresh CLI processes. Expected policy
//! order and winning IDs are hand-calculated, not obtained from the evaluator.
use pcap_evidence::{
    provenance::{EvidenceBytes, PacketId},
    sha256,
};
use pcap_evidence_product::deep::{
    bgp::PcapMetadata,
    bgp_mrt::MrtLimits,
    bgp_mrt_store::MrtReplayOptions,
    bgp_persisted::{PolicyProfile, Query, VerifiedStore},
    bgp_store::JournalWriter,
    Limits,
};
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::atomic::{AtomicU64, Ordering},
};
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!(
            "bgp-persisted-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&p).unwrap();
        Self(p)
    }
    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn wire(med: u32, neighbor: u16) -> Vec<u8> {
    let mut attrs = vec![0x40, 1, 1, 0, 0x40, 2, 4, 2, 1];
    attrs.extend_from_slice(&neighbor.to_be_bytes());
    attrs.extend_from_slice(&[0x40, 3, 4, 192, 0, 2, 9, 0x80, 4, 4]);
    attrs.extend_from_slice(&med.to_be_bytes());
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
fn open_session(w: &mut JournalWriter, capture: [u8; 32], session: u64) {
    for direction in [0u8, 1] {
        let mut message = vec![0xff; 16];
        message.extend_from_slice(&29u16.to_be_bytes());
        message.push(1);
        message.extend_from_slice(&[4, 0xfd, 0xe9, 0, 90, 192, 0, 2, direction + 1, 0]);
        let evidence = EvidenceBytes::from_packet(
            &message,
            PacketId {
                capture,
                frame: 1000 + session * 2 + u64::from(direction),
                record_offset: 10000 + session * 100 + u64::from(direction),
            },
            0,
        );
        w.message(
            session,
            &evidence,
            &PcapMetadata {
                source_id: "capture-a".into(),
                record_id: format!("open-{session}-{direction}"),
                observed_at_ns: Some(99),
                session: Some(session),
                direction: Some(direction),
                peer: Some(format!("192.0.2.{session}")),
                local: Some("192.0.2.100".into()),
            },
        )
        .unwrap();
    }
}
fn capture(path: &Path, namespace: u8, meds: [u32; 2], neighbors: [u16; 2]) {
    let capture = [namespace; 32];
    let mut w = JournalWriter::create(
        path,
        "capture-a".into(),
        capture,
        1024 * 1024,
        Limits::default(),
    )
    .unwrap();
    for i in 0..2 {
        open_session(&mut w, capture, i as u64 + 1);
        let bytes = wire(meds[i], neighbors[i]);
        let e = EvidenceBytes::from_packet(
            &bytes,
            PacketId {
                capture,
                frame: i as u64 + 1,
                record_offset: i as u64 * 100,
            },
            0,
        );
        let session = i as u64 + 1;
        w.message(
            session,
            &e,
            &PcapMetadata {
                source_id: "capture-a".into(),
                record_id: format!("message-{session}"),
                observed_at_ns: Some(100),
                session: Some(session),
                direction: Some(0),
                peer: Some(format!("192.0.2.{session}")),
                local: Some("192.0.2.100".into()),
            },
        )
        .unwrap();
    }
    w.seal().unwrap();
}
fn profile(med: &str, age: &str, routers: bool) -> String {
    let mut s=format!("schema=pcap-evidence.bgp.persisted-policy.v1\nprovenance=synthetic-explicit-owner\ncomparison_context=router-fixture\nmissing_local_preference=100\nmed_rule={med}\nage_rule={age}\n");
    if routers {
        s.push_str("router_input=capture-a|1|192.0.2.1|false|0|192.0.2.1|true|192.0.2.1\nrouter_input=capture-a|2|192.0.2.2|false|0|192.0.2.2|true|192.0.2.2\n")
    }
    s
}
fn cli(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_pcap-depth"))
        .args(args)
        .output()
        .unwrap()
}
fn assert_cli_usage(result: &Output) {
    assert_eq!(result.status.code(), Some(4));
    let python = std::env::var("PYTHON").unwrap_or_else(|_| {
        if cfg!(windows) {
            "python".into()
        } else {
            "python3".into()
        }
    });
    let checked=Command::new(python).args([
        "-c", "import json,sys; d=json.loads(sys.argv[1]); assert d['error']=='usage' and d['field']=='arguments',d",
        std::str::from_utf8(&result.stderr).unwrap(),
    ]).output().unwrap();
    assert!(
        checked.status.success(),
        "{}",
        String::from_utf8_lossy(&checked.stderr)
    );
}
fn text(path: &Path) -> &str {
    path.to_str().unwrap()
}

// Independent source bytes: a valid IPv4 UPDATE carries LOCAL_PREF 200.
// Neither ASN equality nor a producer projection supplies relationship truth.
fn relationship_source(format: &str) -> Vec<u8> {
    fn bgp(kind: u8, body: &[u8]) -> Vec<u8> {
        let mut v = vec![255; 16];
        v.extend_from_slice(&((19 + body.len()) as u16).to_be_bytes());
        v.push(kind);
        v.extend_from_slice(body);
        v
    }
    fn open(asn: u16, id: u8) -> Vec<u8> {
        let mut v = vec![4];
        v.extend_from_slice(&asn.to_be_bytes());
        v.extend_from_slice(&[0, 90, 192, 0, 2, id, 0]);
        bgp(1, &v)
    }
    let width = if format == "mrt" { 2 } else { 4 };
    let mut attrs = vec![0x40, 1, 1, 0, 0x40, 2, width + 2, 2, 1];
    if width == 2 {
        attrs.extend_from_slice(&65001u16.to_be_bytes());
    } else {
        attrs.extend_from_slice(&65001u32.to_be_bytes());
    }
    attrs.extend_from_slice(&[0x40, 3, 4, 192, 0, 2, 1, 0x40, 5, 4]);
    attrs.extend_from_slice(&200u32.to_be_bytes());
    let mut body = vec![0, 0];
    body.extend_from_slice(&(attrs.len() as u16).to_be_bytes());
    body.extend(attrs);
    body.extend_from_slice(&[24, 198, 51, 100]);
    let update = bgp(2, &body);
    if format == "mrt" {
        let record = |subtype: u16, payload: &[u8]| {
            let mut body = vec![0xfd, 0xe9, 0xfd, 0xe8, 0, 7, 0, 1];
            body.extend_from_slice(&[192, 0, 2, 1, 192, 0, 2, 254]);
            body.extend_from_slice(payload);
            let mut v = 100u32.to_be_bytes().to_vec();
            v.extend_from_slice(&16u16.to_be_bytes());
            v.extend_from_slice(&subtype.to_be_bytes());
            v.extend_from_slice(&(body.len() as u32).to_be_bytes());
            v.extend(body);
            v
        };
        [
            record(0, &[0, 3, 0, 4]),
            record(1, &open(65001, 1)),
            record(6, &open(65000, 254)),
            record(0, &[0, 4, 0, 5]),
            record(0, &[0, 5, 0, 6]),
            record(1, &update),
        ]
        .concat()
    } else {
        let mut peer = vec![0, 0];
        peer.extend_from_slice(&[0; 20]);
        peer.extend_from_slice(&[192, 0, 2, 1]);
        peer.extend_from_slice(&65001u32.to_be_bytes());
        peer.extend_from_slice(&[192, 0, 2, 1]);
        peer.extend_from_slice(&100u32.to_be_bytes());
        peer.extend_from_slice(&0u32.to_be_bytes());
        let record = |kind: u8, body: &[u8]| {
            let mut v = vec![3];
            v.extend_from_slice(&((6 + body.len()) as u32).to_be_bytes());
            v.push(kind);
            v.extend_from_slice(body);
            v
        };
        let mut up = peer.clone();
        up.extend_from_slice(&[0; 12]);
        up.extend_from_slice(&[192, 0, 2, 254, 0, 179, 0x9c, 0x40]);
        up.extend(open(65000, 254));
        up.extend(open(65001, 1));
        peer.extend(update);
        [record(3, &up), record(0, &peer)].concat()
    }
}

fn relationship_store(s: &Scratch, format: &str, side: &str) -> PathBuf {
    let input = s.path(&format!("{side}.{format}"));
    fs::write(&input, relationship_source(format)).unwrap();
    let workspace = s.path(&format!("{side}-workspace"));
    let command = format!("import-{format}");
    let result = cli(&[
        "bgp",
        &command,
        text(&input),
        "--workspace",
        text(&workspace),
        "--source-id",
        side,
        "--checkpoint",
        side,
    ]);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    workspace.join(format!("bgp.{format}"))
}

fn association_relationship_oracle(
    path: &Path,
    left: &str,
    right: &str,
    left_format: &str,
    right_format: &str,
) {
    let python = std::env::var("PYTHON").unwrap_or_else(|_| {
        if cfg!(windows) {
            "python".into()
        } else {
            "python3".into()
        }
    });
    let script = r#"
import hashlib,json,sys
from pathlib import Path
d=json.loads(Path(sys.argv[1]).read_text())
def walk(v):
    if isinstance(v,dict):
        yield v
        for x in v.values(): yield from walk(x)
    elif isinstance(v,list):
        for x in v: yield from walk(x)
for n,(rel,fmt,key) in enumerate(zip(sys.argv[2:4],sys.argv[4:6],['route_evidence','internal_evidence'])):
    ref=d['stores'][n]
    assert ref['peer_relationship']==rel,(n,ref)
    assert ref['peer_relationship_basis']==('default_unknown' if rel=='unknown' else 'explicit_configuration'),ref
    side=['left','right'][n]
    assert ref['sealed_store']['source_id']==side,ref
    assert ref['sealed_store']['checkpoint_id']==side,ref
    source=Path(sys.argv[1]).parent/(side+'.'+fmt)
    assert ref['sealed_store']['source_sha256']==hashlib.sha256(source.read_bytes()).hexdigest(),ref
    rows=d['association_report'][key]
    if rel=='unknown':
        assert rows==[],rows # Unknown LOCAL_PREF quarantines the route action.
        continue
    assert len(rows)==1,rows
    routes=[v for v in walk(rows) if 'attributes' in v and 'attribute_ranges' in v]
    assert len(routes)==1,routes
    route=routes[0]
    assert route['action']=='announce',route
    assert route['attributes']['local_preference']==(200 if rel=='internal' else None),route
    assert route['attribute_ranges']==[],route # Imported spans use the source proof carrier.
    lp=[v for v in route['imported_attribute_occurrences']['occurrences'] if v['type']==5]
    assert len(lp)==1,lp
    lp=lp[0]
    assert lp['decoded']==200 and lp['flags']==64 and lp['value_hex']=='000000c8',lp
    assert lp['peer_relationship']==rel and lp['peer_relationship_basis']=='explicit_configuration',lp
    assert lp['peer_relationship_unresolved'] is False,lp
    assert lp['validation']['flags_valid'] and lp['validation']['length_valid'],lp
    assert lp['disposition']==('accept_evidence_only' if rel=='internal' else 'attribute_discard'),lp
"#;
    let result = Command::new(python)
        .args([
            "-c",
            script,
            text(path),
            left,
            right,
            left_format,
            right_format,
        ])
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
}

fn relationship_associate(
    s: &Scratch,
    left: &Path,
    right: &Path,
    name: &str,
    flags: &[&str],
) -> PathBuf {
    let output = s.path(name);
    let mut args = vec![
        "bgp",
        "associate",
        text(left),
        "--with-store",
        text(right),
        "--comparison-namespace",
        "explicit-relationship-test",
        "--clock-policy",
        "ignore",
        "--clock-basis",
        "synthetic-spatial-only",
        "--output",
        text(&output),
    ];
    args.extend_from_slice(flags);
    let result = cli(&args);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    output
}

#[test]
fn association_left_relationship_does_not_configure_omitted_right() {
    let s = Scratch::new();
    let left = relationship_store(&s, "mrt", "left");
    let right = relationship_store(&s, "mrt", "right");
    let output = relationship_associate(
        &s,
        &left,
        &right,
        "left-only.json",
        &["--peer-relationship", "internal"],
    );
    association_relationship_oracle(&output, "internal", "unknown", "mrt", "mrt");
}

#[test]
fn association_per_input_relationship_preserves_wire_usability_for_mrt_and_bmp() {
    for (left_format, right_format) in [
        ("mrt", "mrt"),
        ("mrt", "bmp"),
        ("bmp", "mrt"),
        ("bmp", "bmp"),
    ] {
        let s = Scratch::new();
        let left = relationship_store(&s, left_format, "left");
        let right = relationship_store(&s, right_format, "right");
        for (name, left_rel, right_rel, flags) in [
            (
                "internal-external.json",
                "internal",
                "external",
                vec![
                    "--peer-relationship",
                    "internal",
                    "--other-peer-relationship",
                    "external",
                ],
            ),
            (
                "external-internal.json",
                "external",
                "internal",
                vec![
                    "--peer-relationship",
                    "external",
                    "--other-peer-relationship",
                    "internal",
                ],
            ),
            (
                "right-only.json",
                "unknown",
                "internal",
                vec!["--other-peer-relationship", "internal"],
            ),
            ("default.json", "unknown", "unknown", vec![]),
        ] {
            let output = relationship_associate(&s, &left, &right, name, &flags);
            association_relationship_oracle(
                &output,
                left_rel,
                right_rel,
                left_format,
                right_format,
            );
        }
    }
}

#[test]
fn other_relationship_flag_rejects_wrong_commands_and_malformed_values_without_output() {
    let s = Scratch::new();
    let input = relationship_store(&s, "mrt", "left");
    let config = s.path("policy.txt");
    fs::write(&config, profile("skip", "skip", false)).unwrap();
    for (n, command) in ["query", "policy", "replay", "state", "export"]
        .iter()
        .enumerate()
    {
        let output = s.path(&format!("wrong-{n}.json"));
        let mut args = vec![
            "bgp",
            command,
            text(&input),
            "--other-peer-relationship",
            "internal",
            "--output",
            text(&output),
        ];
        if *command == "policy" {
            args.extend(["--policy-profile", text(&config)]);
        }
        let result = cli(&args);
        assert!(!result.status.success());
        assert_cli_usage(&result);
        assert!(!output.exists());
    }
    for format in ["mrt", "bmp"] {
        let source = s.path(&format!("wrong-input.{format}"));
        fs::write(&source, relationship_source(format)).unwrap();
        let workspace = s.path(&format!("denied-{format}-workspace"));
        let command = format!("import-{format}");
        let result = cli(&[
            "bgp",
            &command,
            text(&source),
            "--workspace",
            text(&workspace),
            "--source-id",
            "valid",
            "--checkpoint",
            "valid",
            "--other-peer-relationship",
            "internal",
        ]);
        assert!(!result.status.success());
        assert_cli_usage(&result);
        assert!(!workspace.exists());
    }
    let workspace = s.path("denied-workspace");
    let unit = s.path("valid.bgp");
    fs::write(&unit, wire(0, 65001)).unwrap();
    let pcap = s.path("empty.pcap");
    fs::write(
        &pcap,
        [
            0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 1, 0, 0,
            0,
        ],
    )
    .unwrap();
    for args in [
        vec![
            "decode",
            "bgp",
            text(&unit),
            "--other-peer-relationship",
            "internal",
        ],
        vec![
            "analyze",
            text(&pcap),
            "--workspace",
            text(&workspace),
            "--other-peer-relationship",
            "internal",
        ],
    ] {
        let result = cli(&args);
        assert!(!result.status.success());
        assert_cli_usage(&result);
        assert!(!s.path("denied-workspace").exists());
    }
    let output = s.path("session-query.json");
    let session = "mrt-bgp4mp:4:left:4:left:1:9:192.0.2.1:11:192.0.2.254:65001:65000:7:0";
    let control = s.path("valid-session-query.json");
    assert!(cli(&[
        "bgp",
        "query",
        text(&input),
        "--session",
        session,
        "--peer-relationship",
        "internal",
        "--output",
        text(&control)
    ])
    .status
    .success());
    let result = cli(&[
        "bgp",
        "query",
        text(&input),
        "--session",
        session,
        "--other-peer-relationship",
        "internal",
        "--output",
        text(&output),
    ]);
    assert!(!result.status.success());
    assert_cli_usage(&result);
    assert!(!output.exists());
    for (n, flags) in [
        vec!["--other-peer-relationship", "ibgp"],
        vec![
            "--other-peer-relationship",
            "internal",
            "--other-peer-relationship",
            "external",
        ],
        vec!["--other-peer-relationship"],
    ]
    .iter()
    .enumerate()
    {
        let output = s.path(&format!("malformed-{n}.json"));
        let mut args = vec![
            "bgp",
            "associate",
            text(&input),
            "--with-store",
            text(&input),
            "--comparison-namespace",
            "test",
            "--clock-policy",
            "same-clock",
            "--output",
            text(&output),
        ];
        args.extend_from_slice(flags);
        let result = cli(&args);
        assert!(!result.status.success());
        assert_cli_usage(&result);
        assert!(!output.exists());
    }
}

#[test]
fn relationship_scope_single_input_query_policy_and_capture_override_boundaries() {
    let python = std::env::var("PYTHON").unwrap_or_else(|_| {
        if cfg!(windows) {
            "python".into()
        } else {
            "python3".into()
        }
    });
    let script = r#"
import json,sys
from pathlib import Path
d=json.loads(Path(sys.argv[1]).read_text())
rel=sys.argv[2]
assert d['store']['peer_relationship']==rel,d['store']
assert d['store']['peer_relationship_basis']==('default_unknown' if rel=='unknown' else 'explicit_configuration'),d['store']
rows=d.get('routes',d.get('alternatives'))
if rel=='unknown':
    assert rows==[],rows
    if 'policy_results' in d: assert d['policy_results']==[],d
else:
    assert len(rows)==1 and rows[0]['status']=='active',rows
    attrs=rows[0]['alternatives'][0]['attributes']
    assert attrs['local_preference']==(200 if rel=='internal' else None),attrs
    if 'policy_results' in d:
        assert len(d['policy_results'])==1,d
"#;
    for format in ["mrt", "bmp"] {
        let s = Scratch::new();
        let store = relationship_store(&s, format, "left");
        let config = s.path("profile.txt");
        fs::write(&config, profile("skip", "skip", false)).unwrap();
        for command in ["query", "policy"] {
            for rel in ["internal", "external", "unknown"] {
                let output = s.path(&format!("{command}-{rel}.json"));
                let mut args = vec!["bgp", command, text(&store), "--output", text(&output)];
                if command == "policy" {
                    args.extend(["--policy-profile", text(&config)]);
                }
                if rel != "unknown" {
                    args.extend(["--peer-relationship", rel]);
                }
                let result = cli(&args);
                assert!(
                    result.status.success(),
                    "{}",
                    String::from_utf8_lossy(&result.stderr)
                );
                let result = Command::new(&python)
                    .args(["-c", script, text(&output), rel])
                    .output()
                    .unwrap();
                assert!(
                    result.status.success(),
                    "{}",
                    String::from_utf8_lossy(&result.stderr)
                );
            }
        }
        let captured = s.path("captured.journal");
        capture(&captured, 201, [0, 0], [65001, 65001]);
        relationship_associate(
            &s,
            &store,
            &captured,
            "captured-right-default.json",
            &["--peer-relationship", "internal"],
        );
        relationship_associate(
            &s,
            &captured,
            &store,
            "captured-left-default.json",
            &["--other-peer-relationship", "internal"],
        );
        for (n, left, right, flags) in [
            (
                0,
                &store,
                &captured,
                vec!["--other-peer-relationship", "internal"],
            ),
            (
                1,
                &captured,
                &store,
                vec!["--peer-relationship", "internal"],
            ),
        ] {
            let output = s.path(&format!("captured-override-{n}.json"));
            let mut args = vec![
                "bgp",
                "associate",
                text(left),
                "--with-store",
                text(right),
                "--comparison-namespace",
                "test",
                "--clock-policy",
                "same-clock",
                "--output",
                text(&output),
            ];
            args.extend(flags);
            let result = cli(&args);
            assert!(!result.status.success());
            assert!(String::from_utf8_lossy(&result.stderr)
                .contains("capture replay does not accept imported relationship override"));
            assert!(!output.exists());
        }
    }
}
#[test]
fn strict_profile_rejects_unknown_duplicate_missing_malformed_and_limits() {
    let l = Limits::default();
    let good = profile("same_neighbor_as", "skip", true);
    assert!(PolicyProfile::parse(good.as_bytes(), &l).is_ok());
    for bad in [
        good.replace("med_rule=same_neighbor_as\n", ""),
        format!("{good}med_rule=skip\n"),
        format!("{good}unexpected=true\n"),
        good.replace(
            "missing_local_preference=100",
            "missing_local_preference=0100",
        ),
        good.replace("med_rule=same_neighbor_as", "med_rule=default"),
        good.replace("|false|0|", "|maybe|0|"),
        format!("{good}router_input=capture-a|1|192.0.2.1|false|0|192.0.2.1|true|192.0.2.1\n"),
    ] {
        assert!(
            PolicyProfile::parse(bad.as_bytes(), &l).is_err(),
            "accepted {bad}"
        );
    }
    let mut small = l.clone();
    small.input_bytes = good.len();
    assert!(PolicyProfile::parse(good.as_bytes(), &small).is_ok());
    small.input_bytes -= 1;
    assert!(PolicyProfile::parse(good.as_bytes(), &small).is_err());
}
#[test]
fn fresh_policy_query_filters_trace_missing_inputs_med_scope_and_tie() {
    let s = Scratch::new();
    let source = s.path("source.journal");
    capture(&source, 7, [100, 1], [65001, 65002]);
    let config = s.path("profile.txt");
    fs::write(&config, profile("same_neighbor_as", "skip", true)).unwrap();
    let a = s.path("policy-a.json");
    let b = s.path("policy-b.json");
    for output in [&a, &b] {
        let result = cli(&[
            "bgp",
            "policy",
            text(&source),
            "--policy-profile",
            text(&config),
            "--output",
            text(output),
        ]);
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
    }
    let out = fs::read_to_string(&a).unwrap();
    assert_eq!(fs::read(&a).unwrap(), fs::read(&b).unwrap());
    // Reordering explicit router configuration cannot change the trace.
    let original = profile("same_neighbor_as", "skip", true);
    let mut lines: Vec<_> = original.lines().collect();
    lines.swap(6, 7);
    fs::write(&config, format!("{}\n", lines.join("\n"))).unwrap();
    let permuted = s.path("permuted.json");
    assert!(cli(&[
        "bgp",
        "policy",
        text(&source),
        "--policy-profile",
        text(&config),
        "--output",
        text(&permuted)
    ])
    .status
    .success());
    assert_eq!(fs::read(&a).unwrap(), fs::read(&permuted).unwrap());
    assert!(out.contains("\"selected\":\"rib:0\""), "{out}");
    assert!(out.contains("different_neighbor_as"));
    assert!(out.contains("\"criterion\":\"router_id\""));
    assert!(out.contains("\"source_authenticated\":false"));
    assert!(out.contains("\"candidate_store_binding\":\"not_provided_by_policy_api\""));
    fs::write(&config, profile("compare_all", "skip", true)).unwrap();
    let c = s.path("med.json");
    assert!(cli(&[
        "bgp",
        "policy",
        text(&source),
        "--policy-profile",
        text(&config),
        "--output",
        text(&c)
    ])
    .status
    .success());
    assert!(fs::read_to_string(&c)
        .unwrap()
        .contains("\"selected\":\"rib:1\""));
    fs::write(&config, profile("unknown", "skip", true)).unwrap();
    let d = s.path("unknown-med.json");
    assert!(cli(&[
        "bgp",
        "policy",
        text(&source),
        "--policy-profile",
        text(&config),
        "--output",
        text(&d)
    ])
    .status
    .success());
    let unknown = fs::read_to_string(&d).unwrap();
    assert!(unknown.contains("med_policy_configuration_missing"));
    assert!(unknown.contains("\"selected\":null"));
    fs::write(&config, profile("skip", "skip", false)).unwrap();
    let e = s.path("unknown-router.json");
    assert!(cli(&[
        "bgp",
        "policy",
        text(&source),
        "--policy-profile",
        text(&config),
        "--output",
        text(&e)
    ])
    .status
    .success());
    let unknown = fs::read_to_string(&e).unwrap();
    assert!(unknown.contains("incomparable_at_locally_originated"));
    assert!(unknown.contains("\"selected\":null"));
    let q = s.path("query.json");
    assert!(cli(&[
        "bgp",
        "query",
        text(&source),
        "--prefix",
        "203.0.113.0/24",
        "--afi",
        "1",
        "--safi",
        "1",
        "--source",
        "capture-a",
        "--peer",
        "192.0.2.2",
        "--status",
        "active",
        "--output",
        text(&q)
    ])
    .status
    .success());
    let query = fs::read_to_string(&q).unwrap();
    assert!(query.contains("\"id\":\"rib:1\""));
    assert!(!query.contains("\"id\":\"rib:0\""));
    assert!(query.contains("capture-namespace-sha256"));
    let none = s.path("none.json");
    assert!(cli(&[
        "bgp",
        "query",
        text(&source),
        "--checkpoint",
        "unavailable-capture-checkpoint",
        "--output",
        text(&none)
    ])
    .status
    .success());
    assert!(fs::read_to_string(&none).unwrap().contains("\"routes\":[]"));
}
#[test]
fn canonical_exact_output_no_overwrite_projection_and_corruption() {
    let s = Scratch::new();
    let source = s.path("source.journal");
    capture(&source, 8, [0, 0], [65001, 65001]);
    let a = s.path("query.json");
    assert!(cli(&["bgp", "query", text(&source), "--output", text(&a)])
        .status
        .success());
    let bytes = fs::read(&a).unwrap();
    let limit = bytes.len().to_string();
    let exact = s.path("exact.json");
    assert!(cli(&[
        "bgp",
        "query",
        text(&source),
        "--output",
        text(&exact),
        "--max-output-bytes",
        &limit
    ])
    .status
    .success());
    assert_eq!(bytes, fs::read(&exact).unwrap());
    let small = s.path("small.json");
    assert!(!cli(&[
        "bgp",
        "query",
        text(&source),
        "--output",
        text(&small),
        "--max-output-bytes",
        &(bytes.len() - 1).to_string()
    ])
    .status
    .success());
    assert!(!small.exists());
    assert!(!s.path("small.json.partial").exists());
    assert!(!cli(&["bgp", "query", text(&source), "--output", text(&a)])
        .status
        .success());
    assert_eq!(bytes, fs::read(&a).unwrap());
    let projection = s.path("projection.json");
    fs::write(&projection, &bytes).unwrap();
    let denied = s.path("denied.json");
    assert!(
        !cli(&["bgp", "query", text(&projection), "--output", text(&denied)])
            .status
            .success()
    );
    assert!(!denied.exists());
    let mut raw = fs::read(&source).unwrap();
    raw[100] ^= 1;
    let corrupted = s.path("corrupt.journal");
    fs::write(&corrupted, raw).unwrap();
    let denied = s.path("corruption.json");
    assert!(
        !cli(&["bgp", "query", text(&corrupted), "--output", text(&denied)])
            .status
            .success()
    );
    assert!(!denied.exists());
}
#[test]
fn multi_store_association_preserves_partitions_clock_unknown_and_occurrences() {
    let s = Scratch::new();
    let left = s.path("left.journal");
    let right = s.path("right.journal");
    capture(&left, 11, [0, 0], [65001, 65001]);
    capture(&right, 12, [0, 0], [65001, 65001]);
    let a = s.path("same.json");
    let result = cli(&[
        "bgp",
        "associate",
        text(&left),
        "--with-store",
        text(&right),
        "--comparison-namespace",
        "explicit-shared-analysis",
        "--clock-policy",
        "same-clock",
        "--output",
        text(&a),
    ]);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let out = fs::read_to_string(&a).unwrap();
    assert!(out.contains("unknown_clock"));
    assert!(out.contains("pcap-evidence.bgp.association.v2"));
    assert!(out.contains("pcap-evidence.association-input.v2"));
    assert!(out.contains("\"side\":\"route_evidence\""));
    assert!(out.contains(&sha256::hex(&[11; 32])));
    assert!(out.contains(&sha256::hex(&[12; 32])));
    assert!(out.contains("\"occurrences_merged\":false"));
    assert!(out.contains("insufficient_coverage"));
    let invalid = s.path("invalid.json");
    assert!(!cli(&[
        "bgp",
        "associate",
        text(&left),
        "--with-store",
        text(&right),
        "--comparison-namespace",
        "explicit-shared-analysis",
        "--clock-policy",
        "ignore",
        "--output",
        text(&invalid)
    ])
    .status
    .success());
    assert!(!invalid.exists());
    let ignored = s.path("ignored.json");
    assert!(cli(&[
        "bgp",
        "associate",
        text(&left),
        "--with-store",
        text(&right),
        "--comparison-namespace",
        "explicit-shared-analysis",
        "--clock-policy",
        "ignore",
        "--clock-basis",
        "explicit-offline-spatial-only",
        "--output",
        text(&ignored)
    ])
    .status
    .success());
    assert!(!fs::read_to_string(ignored)
        .unwrap()
        .contains("unknown_clock"));
    assert_eq!(fs::read_dir(&s.0).unwrap().count(), 4);
    let store = VerifiedStore::load(
        &left,
        1024 * 1024,
        MrtLimits::default(),
        Limits::default(),
        MrtReplayOptions::default(),
    )
    .unwrap();
    let base = store.query(&Query::default(), &Limits::default()).unwrap();
    let mut l = Limits {
        output_bytes: base.len(),
        ..Limits::default()
    };
    assert_eq!(store.query(&Query::default(), &l).unwrap(), base);
    l.output_bytes -= 1;
    assert!(store.query(&Query::default(), &l).is_err());
}

#[test]
fn captured_rejected_record_gaps_only_its_session_and_budget_failure_is_not_rejection() {
    use pcap_evidence_product::deep::{bgp_rib::RouteStatus, bgp_store};
    let scratch = Scratch::new();
    let path = scratch.path("gap.journal");
    let namespace = [21; 32];
    let mut writer = JournalWriter::create(
        &path,
        "capture-a".into(),
        namespace,
        1024 * 1024,
        Limits::default(),
    )
    .unwrap();
    open_session(&mut writer, namespace, 1);
    open_session(&mut writer, namespace, 2);
    for (session, record, bytes) in [
        (1, "first", wire(1, 65001)),
        (2, "sibling", wire(1, 65001)),
        (1, "bad", vec![0u8; 19]),
    ] {
        let evidence = EvidenceBytes::from_packet(
            &bytes,
            PacketId {
                capture: namespace,
                frame: if record == "bad" { 3 } else { session },
                record_offset: session * 100,
            },
            0,
        );
        writer
            .message(
                session,
                &evidence,
                &PcapMetadata {
                    source_id: "capture-a".into(),
                    record_id: record.into(),
                    observed_at_ns: Some(100),
                    session: Some(session),
                    direction: Some(0),
                    peer: Some(format!("192.0.2.{session}")),
                    local: Some("192.0.2.100".into()),
                },
            )
            .unwrap();
    }
    writer.seal().unwrap();
    let archive = bgp_store::replay(&path, 1024 * 1024, Limits::default()).unwrap();
    assert_eq!(archive.rejected_records, 1);
    assert_eq!(archive.route_entries.len(), 2);
    assert_eq!(
        archive
            .route_entries
            .iter()
            .find(|e| e.key.scope.session == "1")
            .unwrap()
            .status,
        RouteStatus::Unresolved
    );
    assert_eq!(
        archive
            .route_entries
            .iter()
            .find(|e| e.key.scope.session == "2")
            .unwrap()
            .status,
        RouteStatus::Active
    );
    assert_eq!(
        archive
            .sessions
            .iter()
            .find(|s| s.session == 1)
            .unwrap()
            .summary
            .gaps,
        1
    );
    assert_eq!(
        archive
            .sessions
            .iter()
            .find(|s| s.session == 2)
            .unwrap()
            .summary
            .gaps,
        0
    );
    let output = scratch.path("gap-policy.json");
    let profile_path = scratch.path("profile.txt");
    fs::write(&profile_path, profile("skip", "skip", true)).unwrap();
    assert!(cli(&[
        "bgp",
        "policy",
        text(&path),
        "--policy-profile",
        text(&profile_path),
        "--output",
        text(&output)
    ])
    .status
    .success());
    let policy = fs::read_to_string(output).unwrap();
    assert!(policy.contains("\"status\":\"unresolved\""));
    assert!(policy.contains("\"selected\":\"rib:1\""));
    let limits = Limits {
        retained_bytes: 1,
        ..Limits::default()
    };
    let error = bgp_store::replay(&path, 1024 * 1024, limits).unwrap_err();
    assert_eq!(error.code, pcap_evidence::ErrorCode::InvalidLength);
    assert_eq!(error.field, "bgp_journal_record");
    // The outer raw-record guard rejects before retaining a record. Find the exact configured retention boundary of this tiny actual replay.
    // This includes snapshots, typed entry copies and observation copies.
    let mut lo = 1usize;
    let mut hi = Limits::default().retained_bytes;
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        let l = Limits {
            retained_bytes: mid,
            ..Limits::default()
        };
        if bgp_store::replay(&path, 1024 * 1024, l).is_ok() {
            hi = mid
        } else {
            lo = mid + 1
        }
    }
    let mut exact = Limits {
        retained_bytes: lo,
        ..Limits::default()
    };
    let accepted = bgp_store::replay(&path, 1024 * 1024, exact.clone()).unwrap();
    assert_eq!(accepted.route_entries, archive.route_entries);
    exact.retained_bytes -= 1;
    let error = bgp_store::replay(&path, 1024 * 1024, exact).unwrap_err();
    assert_eq!(error.code, pcap_evidence::ErrorCode::LimitExceeded);
    assert!(
        lo > archive
            .observations
            .iter()
            .map(|o| o.normalized().encode().len())
            .sum::<usize>()
    );
}

#[test]
fn imported_collector_equivalence_keeps_checkpoints_and_never_invents_active_winner() {
    use pcap_evidence_product::deep::{bgp_mrt::MrtSource, bgp_mrt_store};
    // Independent finite TABLE_DUMP_V2 construction: one four-octet-AS IPv4
    // peer and two entries for the same prefix with distinct originated times.
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
    let mut attributes = vec![0x40, 1, 1, 0, 0x40, 2, 6, 2, 1];
    attributes.extend_from_slice(&65551u32.to_be_bytes());
    attributes.extend_from_slice(&[0x40, 3, 4, 192, 0, 2, 9]);
    let mut rib = vec![0, 0, 0, 7, 24, 203, 0, 113, 0, 2];
    for originated in [10u32, 11u32] {
        rib.extend_from_slice(&0u16.to_be_bytes());
        rib.extend_from_slice(&originated.to_be_bytes());
        rib.extend_from_slice(&(attributes.len() as u16).to_be_bytes());
        rib.extend_from_slice(&attributes);
    }
    let bytes = [record(11, 1, &peers), record(12, 2, &rib)].concat();
    let scratch = Scratch::new();
    let left = scratch.path("left.mrt");
    let right = scratch.path("right.mrt");
    let mut archives = Vec::new();
    for (path, checkpoint) in [(&left, "checkpoint-left"), (&right, "checkpoint-right")] {
        archives.push(
            bgp_mrt_store::create(
                path,
                &bytes,
                MrtSource {
                    source_id: "collector-a".into(),
                    checkpoint_id: checkpoint.into(),
                },
                1024 * 1024,
                MrtLimits::default(),
                Limits::default(),
            )
            .unwrap(),
        );
    }
    assert_eq!(
        archives[0].receipt.source_sha256,
        archives[1].receipt.source_sha256
    );
    assert_ne!(
        archives[0].receipt.terminal_sha256,
        archives[1].receipt.terminal_sha256
    );
    assert_eq!(archives[0].candidates.len(), 2);
    assert_eq!(archives[1].candidates.len(), 2);
    let config = scratch.path("profile.txt");
    fs::write(&config, profile("skip", "skip", false)).unwrap();
    let policy = scratch.path("policy.json");
    let outcome = cli(&[
        "bgp",
        "policy",
        text(&left),
        "--policy-profile",
        text(&config),
        "--output",
        text(&policy),
    ]);
    assert!(
        outcome.status.success(),
        "{}",
        String::from_utf8_lossy(&outcome.stderr)
    );
    let policy = fs::read_to_string(policy).unwrap();
    assert!(policy.contains("\"selected\":null"));
    assert!(policy.contains("collector_candidate"));
    assert!(policy.contains("collector:1:0"));
    assert!(policy.contains("collector:1:1"));
    assert!(policy.contains("alternatives"));
    let output = scratch.path("association.json");
    let outcome = cli(&[
        "bgp",
        "associate",
        text(&left),
        "--with-store",
        text(&right),
        "--comparison-namespace",
        "declared-equivalence-study",
        "--clock-policy",
        "same-clock",
        "--output",
        text(&output),
    ]);
    assert!(
        outcome.status.success(),
        "{}",
        String::from_utf8_lossy(&outcome.stderr)
    );
    let association = fs::read_to_string(output).unwrap();
    assert!(association.contains("checkpoint-left"));
    assert!(association.contains("checkpoint-right"));
    assert!(association.contains(&sha256::hex(&archives[0].receipt.terminal_sha256)));
    assert!(association.contains(&sha256::hex(&archives[1].receipt.terminal_sha256)));
    assert!(association.contains("not_current_candidate"));
    assert!(association.contains("\"occurrences_merged\":false"));
    assert!(association.contains("\"endpoint_state_claimed\":false"));
}

#[test]
fn captured_end_clear_reuse_keeps_terminal_history_and_exact_occurrence_selection() {
    use pcap_evidence_product::deep::bgp_store;
    fn send(w: &mut JournalWriter, ns: [u8; 32], frame: u64, bytes: Vec<u8>) {
        let evidence = EvidenceBytes::from_packet(
            &bytes,
            PacketId {
                capture: ns,
                frame,
                record_offset: frame * 100,
            },
            0,
        );
        w.message(
            1,
            &evidence,
            &PcapMetadata {
                source_id: "capture-a".into(),
                record_id: if frame == 21 {
                    "withdraw-record"
                } else {
                    "reused-record"
                }
                .into(),
                observed_at_ns: Some(100),
                session: Some(1),
                direction: Some(0),
                peer: Some("192.0.2.1".into()),
                local: Some("192.0.2.100".into()),
            },
        )
        .unwrap();
    }
    let scratch = Scratch::new();
    let left = scratch.path("history.journal");
    let right = scratch.path("current.journal");
    let ns = [31; 32];
    let mut writer = JournalWriter::create(
        &left,
        "capture-a".into(),
        ns,
        1024 * 1024,
        Limits::default(),
    )
    .unwrap();
    open_session(&mut writer, ns, 1);
    send(&mut writer, ns, 10, wire(0, 65001));
    writer.end_session(1).unwrap();
    open_session(&mut writer, ns, 1);
    send(&mut writer, ns, 20, wire(0, 65001));
    send(&mut writer, ns, 21, {
        let mut v = vec![0xff; 16];
        v.extend_from_slice(&27u16.to_be_bytes());
        v.push(2);
        v.extend_from_slice(&[0, 4, 24, 203, 0, 113, 0, 0]);
        v
    });
    writer.clear().unwrap();
    open_session(&mut writer, ns, 1);
    send(&mut writer, ns, 30, wire(500, 65001));
    writer.seal().unwrap();
    let mut writer = JournalWriter::create(
        &right,
        "capture-a".into(),
        [32; 32],
        1024 * 1024,
        Limits::default(),
    )
    .unwrap();
    open_session(&mut writer, [32; 32], 1);
    send(&mut writer, [32; 32], 40, wire(500, 65001));
    writer.seal().unwrap();
    let archive = bgp_store::replay(&left, 1024 * 1024, Limits::default()).unwrap();
    assert_eq!(archive.route_entries.len(), 3);
    assert_eq!(
        archive.route_entries[1].status,
        pcap_evidence_product::deep::bgp_rib::RouteStatus::Withdrawn
    );
    assert_eq!(archive.rejected_records, 0);
    assert_eq!(
        archive
            .route_entry_evidence
            .iter()
            .map(|e| e.current)
            .collect::<Vec<_>>(),
        vec![false, false, true]
    );
    assert_eq!(
        archive
            .route_entry_evidence
            .iter()
            .map(|e| e.lifecycle)
            .collect::<Vec<_>>(),
        vec![0, 1, 2]
    );
    let load = |p: &Path| {
        VerifiedStore::load(
            p,
            1024 * 1024,
            MrtLimits::default(),
            Limits::default(),
            MrtReplayOptions::default(),
        )
        .unwrap()
    };
    let a = load(&left);
    let b = load(&right);
    let prof = PolicyProfile::parse(
        profile("compare_all", "skip", true).as_bytes(),
        &Limits::default(),
    )
    .unwrap();
    let out = a
        .policy(&Query::default(), &prof, &Limits::default())
        .unwrap();
    assert!(out.contains("\"selected\":\"rib:2\""), "{out}");
    assert!(!out.contains("\"selected\":\"rib:0\""));
    assert!(!out.contains("\"selected\":\"rib:1\""));
    assert!(out.contains("original_partition_id"));
    use pcap_evidence_product::deep::bgp_association::{
        DimensionRule, DirectionRule, Policy, SpatialRule, TimePolicy,
    };
    let policy = Policy {
        policy_id: "explicit-finite-native-selection".into(),
        session: DimensionRule::Ignore,
        generation: DimensionRule::Ignore,
        flow: DimensionRule::Ignore,
        direction: DirectionRule::Ignore,
        spatial: SpatialRule::EqualPrefix,
        time: TimePolicy::Ignore {
            reason: "explicit finite offline witness".into(),
        },
    };
    for out in [
        a.associate(&b, "shared", &policy, &Limits::default())
            .unwrap(),
        b.associate(&a, "shared", &policy, &Limits::default())
            .unwrap(),
    ] {
        assert!(out.contains("not_current_candidate"));
        assert!(!out.contains("multiple_candidates"), "{out}");
        assert!(!out.contains("changed_content_conflict"), "{out}");
        assert!(!out.contains("duplicate_identity"), "{out}");
        assert!(out.contains("native_disposition"));
    }
}

#[test]
fn lowered_consumer_limits_admit_complete_rows_before_projection_copies() {
    let scratch = Scratch::new();
    let path = scratch.path("two.journal");
    capture(&path, 41, [0, 0], [65001, 65001]);
    let store = VerifiedStore::load(
        &path,
        1024 * 1024,
        MrtLimits::default(),
        Limits::default(),
        MrtReplayOptions::default(),
    )
    .unwrap();
    let profile =
        PolicyProfile::parse(profile("skip", "skip", true).as_bytes(), &Limits::default()).unwrap();
    let mut l = Limits {
        elements: 1,
        ..Limits::default()
    };
    assert!(store.query(&Query::default(), &l).is_err());
    assert!(store.policy(&Query::default(), &profile, &l).is_err());
    l.elements = 2;
    assert!(store.query(&Query::default(), &l).is_ok());
    let base = store.query(&Query::default(), &Limits::default()).unwrap();
    l = Limits::default();
    l.output_bytes = base.len();
    assert_eq!(store.query(&Query::default(), &l).unwrap(), base);
    l.output_bytes -= 1;
    assert!(store.query(&Query::default(), &l).is_err());
    for (field, value) in [
        ("output", 1),
        ("retained", 1),
        ("work", 1),
        ("fields", 1),
        ("depth", 1),
    ] {
        let mut l = Limits::default();
        match field {
            "output" => l.output_bytes = value,
            "retained" => l.retained_bytes = value,
            "work" => l.work = value,
            "fields" => l.fields = value,
            _ => l.depth = value,
        }
        assert!(store.query(&Query::default(), &l).is_err());
        assert!(store.policy(&Query::default(), &profile, &l).is_err());
    }
    // A large supported attribute is admitted under ample replay limits, then
    // measured by the consumer by borrowing its stored subtree. Unknown
    // transitive semantics deliberately do not enter native candidate state.
    let opaque = scratch.path("opaque.journal");
    let ns = [42; 32];
    let mut writer = JournalWriter::create(
        &opaque,
        "capture-a".into(),
        ns,
        1024 * 1024,
        Limits::default(),
    )
    .unwrap();
    open_session(&mut writer, ns, 1);
    let mut bytes = wire(0, 65001);
    let attrs = u16::from_be_bytes([bytes[21], bytes[22]]) as usize;
    let mut attr = vec![0xc0, 8, 252];
    for community in 0..63u32 {
        attr.extend_from_slice(&(0xfde9_0000 + community).to_be_bytes());
    }
    bytes.splice(23 + attrs..23 + attrs, attr);
    bytes[21..23].copy_from_slice(&((attrs + 255) as u16).to_be_bytes());
    let length = bytes.len() as u16;
    bytes[16..18].copy_from_slice(&length.to_be_bytes());
    let evidence = EvidenceBytes::from_packet(
        &bytes,
        PacketId {
            capture: ns,
            frame: 3,
            record_offset: 300,
        },
        0,
    );
    writer
        .message(
            1,
            &evidence,
            &PcapMetadata {
                source_id: "capture-a".into(),
                record_id: "opaque".into(),
                observed_at_ns: Some(100),
                session: Some(1),
                direction: Some(0),
                peer: Some("192.0.2.1".into()),
                local: Some("192.0.2.100".into()),
            },
        )
        .unwrap();
    writer.seal().unwrap();
    let store = VerifiedStore::load(
        &opaque,
        1024 * 1024,
        MrtLimits::default(),
        Limits::default(),
        MrtReplayOptions::default(),
    )
    .unwrap();
    let baseline = store.query(&Query::default(), &Limits::default()).unwrap();
    assert!(baseline.contains("rib:0"));
    for field in ["output", "retained", "work"] {
        let mut l = Limits::default();
        match field {
            "output" => l.output_bytes = 1,
            "retained" => l.retained_bytes = 1,
            _ => l.work = 1,
        }
        assert!(store.query(&Query::default(), &l).is_err());
        assert!(store.policy(&Query::default(), &profile, &l).is_err());
    }
    let mut l = Limits {
        output_bytes: baseline.len(),
        ..Limits::default()
    };
    assert_eq!(store.query(&Query::default(), &l).unwrap(), baseline);
    l.output_bytes -= 1;
    assert!(store.query(&Query::default(), &l).is_err());
}

#[test]
fn bmp_pre_and_post_policy_native_scopes_remain_separate_decisions() {
    fn bgp(kind: u8, body: &[u8]) -> Vec<u8> {
        let mut v = vec![255; 16];
        v.extend_from_slice(&((19 + body.len()) as u16).to_be_bytes());
        v.push(kind);
        v.extend_from_slice(body);
        v
    }
    fn bmp(kind: u8, body: &[u8]) -> Vec<u8> {
        let mut v = vec![3];
        v.extend_from_slice(&((6 + body.len()) as u32).to_be_bytes());
        v.push(kind);
        v.extend_from_slice(body);
        v
    }
    fn peer(flags: u8, seconds: u32) -> Vec<u8> {
        let mut v = vec![0, flags];
        v.extend_from_slice(&[0; 20]);
        v.extend_from_slice(&[192, 0, 2, 1]);
        v.extend_from_slice(&65001u32.to_be_bytes());
        v.extend_from_slice(&[10, 0, 0, 1]);
        v.extend_from_slice(&seconds.to_be_bytes());
        v.extend_from_slice(&7u32.to_be_bytes());
        v
    }
    fn open(asn: u16, id: u8) -> Vec<u8> {
        let mut b = vec![4];
        b.extend_from_slice(&asn.to_be_bytes());
        b.extend_from_slice(&[0, 90, 10, 0, 0, id, 0]);
        bgp(1, &b)
    }
    let mut up = peer(0, 100);
    up.extend_from_slice(&[0; 12]);
    up.extend_from_slice(&[192, 0, 2, 254]);
    up.extend_from_slice(&[0, 179, 0x9c, 0x40]);
    up.extend(open(65000, 254));
    up.extend(open(65001, 1));
    let mut input = bmp(3, &up);
    for (flags, seconds, preference) in [(0u8, 101u32, 200u32), (0x40, 102, 100)] {
        let mut attrs = vec![0x40, 1, 1, 0, 0x40, 2, 6, 2, 1];
        attrs.extend_from_slice(&65001u32.to_be_bytes());
        attrs.extend_from_slice(&[0x40, 3, 4, 192, 0, 2, 1, 0x40, 5, 4]);
        attrs.extend_from_slice(&preference.to_be_bytes());
        let mut body = vec![0, 0];
        body.extend_from_slice(&(attrs.len() as u16).to_be_bytes());
        body.extend(attrs);
        body.extend_from_slice(&[24, 198, 51, 100]);
        let mut rm = peer(flags, seconds);
        rm.extend(bgp(2, &body));
        input.extend(bmp(0, &rm));
    }
    let scratch = Scratch::new();
    let source = scratch.path("input.bmp");
    fs::write(&source, input).unwrap();
    let workspace = scratch.path("import");
    let result = cli(&[
        "bgp",
        "import-bmp",
        text(&source),
        "--workspace",
        text(&workspace),
        "--source-id",
        "bmp-a",
        "--checkpoint",
        "checkpoint-a",
        "--peer-relationship",
        "internal",
    ]);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let config = scratch.path("policy.txt");
    fs::write(&config, profile("skip", "skip", false)).unwrap();
    let output = scratch.path("policy.json");
    let result = cli(&[
        "bgp",
        "policy",
        text(&workspace.join("bgp.bmp")),
        "--peer-relationship",
        "internal",
        "--policy-profile",
        text(&config),
        "--output",
        text(&output),
    ]);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let out = fs::read_to_string(output).unwrap();
    assert!(out.contains("bmp:0:pre"), "{out}");
    assert!(out.contains("bmp:0:post"));
    assert_eq!(
        out.matches("\"schema\":\"pcap-evidence.bgp.policy-result.v1\"")
            .count(),
        2,
        "{out}"
    );
    assert_eq!(out.matches("\"selected\":\"rib:").count(), 2, "{out}");
    assert!(out.contains("\"local_preference\":200"));
    assert!(out.contains("\"local_preference\":100"));
    assert!(out.contains("\"comparisons\":[]"));
}

#[test]
fn complete_empty_and_populated_outputs_obey_exact_structural_limits() {
    use std::io::Write;
    use std::process::Stdio;
    fn structure(encoded: &str) -> (usize, usize) {
        let python = std::env::var("PYTHON").unwrap_or_else(|_| {
            if cfg!(windows) {
                "python".into()
            } else {
                "python3".into()
            }
        });
        let mut child=Command::new(python).args(["-c","import json,sys; v=json.load(sys.stdin); kids=lambda x:list(x.values()) if isinstance(x,dict) else x if isinstance(x,list) else []; count=lambda x:1+sum(count(y) for y in kids(x)); depth=lambda x:max([0]+[1+depth(y) for y in kids(x)]); print(count(v),depth(v))"]).stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(encoded.as_bytes())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(output.status.success());
        let text = String::from_utf8(output.stdout).unwrap();
        let mut values = text.split_whitespace().map(|s| s.parse::<usize>().unwrap());
        (values.next().unwrap(), values.next().unwrap())
    }
    let scratch = Scratch::new();
    let path = scratch.path("input.journal");
    capture(&path, 51, [0, 0], [65001, 65001]);
    let store = VerifiedStore::load(
        &path,
        1024 * 1024,
        MrtLimits::default(),
        Limits::default(),
        MrtReplayOptions::default(),
    )
    .unwrap();
    let profile =
        PolicyProfile::parse(profile("skip", "skip", true).as_bytes(), &Limits::default()).unwrap();
    for query in [
        Query {
            source: Some("absent-source".into()),
            ..Query::default()
        },
        Query::default(),
    ] {
        for policy in [false, true] {
            let render = |limits: &Limits| {
                if policy {
                    store.policy(&query, &profile, limits)
                } else {
                    store.query(&query, limits)
                }
            };
            let baseline = render(&Limits::default()).unwrap();
            let (nodes, depth) = structure(&baseline);
            let mut limits = Limits {
                fields: nodes,
                ..Limits::default()
            };
            assert_eq!(render(&limits).unwrap(), baseline);
            limits.fields -= 1;
            let error = render(&limits).unwrap_err();
            assert_eq!(error.code, pcap_evidence::ErrorCode::LimitExceeded);
            limits = Limits {
                depth,
                ..Limits::default()
            };
            assert_eq!(render(&limits).unwrap(), baseline);
            limits.depth -= 1;
            assert!(render(&limits).is_err());
        }
    }
}
