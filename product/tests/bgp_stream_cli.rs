//! Tiny independently encoded MRT sources exercised through fresh pcap-depth
//! processes. These controls own argv, sealed-input consumption, publication,
//! and checkpoint/window joins; parser continuity and scale remain separate.
use pcap_evidence::sha256;
use std::{
    ffi::OsString,
    fs, io,
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::atomic::{AtomicU64, Ordering},
};

static SERIAL: AtomicU64 = AtomicU64::new(0);

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        for _ in 0..1024 {
            let path = std::env::temp_dir().join(format!(
                "bgp-stream-cli-{}-{}",
                std::process::id(),
                SERIAL.fetch_add(1, Ordering::Relaxed)
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Self(path),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("create owned CLI test workspace: {error}"),
            }
        }
        panic!("CLI workspace namespace exhausted");
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

fn cli(args: Vec<OsString>) -> Output {
    // Root may select the retained baseline executable to record feature
    // absence before building the candidate. The ordinary default is Cargo's
    // actual executable, with no helper implementation of these commands.
    let binary = std::env::var_os("PCAP_DEPTH_TEST_BINARY")
        .unwrap_or_else(|| OsString::from(env!("CARGO_BIN_EXE_pcap-depth")));
    Command::new(binary).args(args).output().unwrap()
}

fn success(output: Output) {
    assert!(
        output.status.success(),
        "CLI failed ({:?}): {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn rejected(output: Output) {
    assert!(
        !output.status.success(),
        "CLI unexpectedly succeeded: {}",
        String::from_utf8_lossy(&output.stdout)
    );
}

fn import_args(input: &Path, workspace: &Path, source: &str, checkpoint: &str) -> Vec<OsString> {
    vec![
        "bgp".into(),
        "import-mrt-stream".into(),
        input.as_os_str().into(),
        "--workspace".into(),
        workspace.as_os_str().into(),
        "--source-id".into(),
        source.into(),
        "--checkpoint".into(),
        checkpoint.into(),
        "--max-source-bytes".into(),
        "1048576".into(),
        "--max-store-bytes".into(),
        "4194304".into(),
        "--max-record-bytes".into(),
        "65536".into(),
        "--max-records".into(),
        "128".into(),
        "--max-work".into(),
        "8388608".into(),
    ]
}

fn export_args(operation: &str, stores: &[&Path], workspace: &Path) -> Vec<OsString> {
    let mut args = vec!["bgp".into(), operation.into(), stores[0].as_os_str().into()];
    for store in &stores[1..] {
        args.extend(["--with-store".into(), store.as_os_str().into()]);
    }
    args.extend([
        "--workspace".into(),
        workspace.as_os_str().into(),
        "--peer-relationship".into(),
        "unknown".into(),
        "--max-source-bytes".into(),
        "1048576".into(),
        "--max-store-bytes".into(),
        "4194304".into(),
        "--max-output-bytes".into(),
        "2097152".into(),
    ]);
    args
}

fn replace_arg(args: &mut [OsString], flag: &str, value: impl Into<OsString>) {
    let index = args.iter().position(|arg| arg == flag).unwrap();
    args[index + 1] = value.into();
}

fn window_args(
    store: &Path,
    workspace: &Path,
    basis: &str,
    scope: &str,
    start_ns: i128,
    end_ns: i128,
) -> Vec<OsString> {
    let mut args = export_args("window", &[store], workspace);
    args.extend([
        "--asn".into(),
        "65551".into(),
        "--asn-role".into(),
        "origin".into(),
        "--time-basis".into(),
        basis.into(),
        "--clock-scope".into(),
        scope.into(),
        "--start-ns".into(),
        start_ns.to_string().into(),
        "--end-ns".into(),
        end_ns.to_string().into(),
    ]);
    args
}

fn import_source(root: &Scratch, name: &str, bytes: &[u8], source: &str) -> PathBuf {
    let input = root.path(&format!("{name}.mrt"));
    let workspace = root.path(name);
    fs::write(&input, bytes).unwrap();
    success(cli(import_args(&input, &workspace, source, name)));
    assert!(workspace.join("receipt.json").is_file());
    for artifact in ["receipt.json", "bgp.mrt-stream"] {
        assert_eq!(
            fs::read(workspace.join(format!("{artifact}.partial"))).unwrap(),
            fs::read(workspace.join(artifact)).unwrap(),
            "retained publication name differs from completed artifact"
        );
    }
    workspace.join("bgp.mrt-stream")
}

fn record(seconds: u32, kind: u16, subtype: u16, body: &[u8]) -> Vec<u8> {
    let mut bytes = seconds.to_be_bytes().to_vec();
    bytes.extend_from_slice(&kind.to_be_bytes());
    bytes.extend_from_slice(&subtype.to_be_bytes());
    bytes.extend_from_slice(&u32::try_from(body.len()).unwrap().to_be_bytes());
    bytes.extend_from_slice(body);
    bytes
}

fn peer_table(seconds: u32, peer_last: u8, asn: u32) -> Vec<u8> {
    // Collector BGP ID, empty view, one IPv4 peer, four-octet ASN.
    let mut body = vec![
        192, 0, 2, 1, 0, 0, 0, 1, 2, 192, 0, 2, 2, 203, 0, 113, peer_last,
    ];
    body.extend_from_slice(&asn.to_be_bytes());
    record(seconds, 13, 1, &body)
}

fn attributes(asn: u32, set: bool) -> Vec<u8> {
    // ORIGIN=IGP; one AS_SEQUENCE or AS_SET member; NEXT_HOP=192.0.2.9.
    let mut bytes = vec![0x40, 1, 1, 0, 0x40, 2, 6, if set { 1 } else { 2 }, 1];
    bytes.extend_from_slice(&asn.to_be_bytes());
    bytes.extend_from_slice(&[0x40, 3, 4, 192, 0, 2, 9]);
    bytes
}

fn rib(seconds: u32, originated: u32, sequence: u32, asn: u32, set: bool) -> Vec<u8> {
    let attrs = attributes(asn, set);
    let mut body = sequence.to_be_bytes().to_vec();
    body.extend_from_slice(&[24, 198, 51, 100, 0, 1, 0, 0]);
    body.extend_from_slice(&originated.to_be_bytes());
    body.extend_from_slice(&u16::try_from(attrs.len()).unwrap().to_be_bytes());
    body.extend(attrs);
    record(seconds, 13, 2, &body)
}

fn bgp(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut bytes = vec![255; 16];
    bytes.extend_from_slice(&u16::try_from(19 + body.len()).unwrap().to_be_bytes());
    bytes.push(kind);
    bytes.extend_from_slice(body);
    bytes
}

fn bgp4mp(seconds: u32, subtype: u16, payload: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&65551u32.to_be_bytes());
    body.extend_from_slice(&65552u32.to_be_bytes());
    body.extend_from_slice(&[0, 7, 0, 1, 198, 51, 100, 1, 198, 51, 100, 2]);
    body.extend_from_slice(payload);
    record(seconds, 16, subtype, &body)
}

fn open(asn: u32, router_last: u8) -> Vec<u8> {
    let mut body = vec![4, 0x5b, 0xa0, 0, 90, 192, 0, 2, router_last, 8, 2, 6, 65, 4];
    body.extend_from_slice(&asn.to_be_bytes());
    bgp(1, &body)
}

fn update() -> Vec<u8> {
    let attrs = attributes(65551, false);
    let mut body = vec![0, 0];
    body.extend_from_slice(&u16::try_from(attrs.len()).unwrap().to_be_bytes());
    body.extend(attrs);
    body.extend_from_slice(&[24, 198, 51, 100]);
    bgp(2, &body)
}

fn established_update() -> Vec<u8> {
    [
        bgp4mp(15, 5, &[0, 3, 0, 4]),
        bgp4mp(16, 4, &open(65551, 1)),
        bgp4mp(17, 7, &open(65552, 2)),
        bgp4mp(18, 5, &[0, 4, 0, 5]),
        bgp4mp(19, 5, &[0, 5, 0, 6]),
        bgp4mp(20, 4, &update()),
    ]
    .concat()
}

// Follow the existing CLI consumer pattern. Python reads real output artifacts
// and independently computes raw-byte digests/coordinates; it does not invoke
// a parser or evaluator to manufacture expected BGP results.
fn check_json(root: &Scratch, script: &str) {
    let python = std::env::var("PYTHON").unwrap_or_else(|_| {
        if cfg!(windows) {
            "python".into()
        } else {
            "python3".into()
        }
    });
    let checked = Command::new(python)
        .arg("-c")
        .arg(format!("{JSON_HELPERS}\n{script}"))
        .arg(&root.0)
        .output()
        .unwrap();
    assert!(
        checked.status.success(),
        "JSON consumer failed: {}",
        String::from_utf8_lossy(&checked.stderr)
    );
}

const JSON_HELPERS: &str = r#"
import hashlib,json,pathlib,struct,sys
root=pathlib.Path(sys.argv[1])
def load(path): return json.loads((root/path).read_bytes())
def read_rows(path): return [json.loads(line) for line in (root/path/'evidence.ndjson').read_bytes().splitlines()][:-1]
def walk(value):
    if isinstance(value,dict):
        yield value
        for child in value.values(): yield from walk(child)
    elif isinstance(value,list):
        for child in value: yield from walk(child)
def validate_export(name):
    data=(root/name/'evidence.ndjson').read_bytes()
    assert data.endswith(b'\n'), name
    lines=data.splitlines(keepends=True)
    rows=read_rows(name); manifest=load(name/'manifest.json'); sequence=load(name/'sequence.json')
    assert json.loads(lines[-1])==manifest, (name,'terminal manifest mismatch')
    row_bytes=b''.join(lines[:-1])
    assert manifest['schema']=='pcap-evidence.bgp.evidence-manifest.v1' and manifest['complete'] is True, manifest
    assert int(manifest['rows'])==len(rows) and int(manifest['rows_bytes'])==len(row_bytes), manifest
    assert manifest['rows_sha256']==hashlib.sha256(row_bytes).hexdigest(), manifest
    assert manifest['source_authenticated'] is False and manifest['endpoint_state_claimed'] is False, manifest
    assert sequence['schema']=='pcap-evidence.bgp.source-sequence.v1', sequence
    assert manifest['sequence']==sequence and sequence['independent_checkpoints'] is True, sequence
    assert all(row['schema']=='pcap-evidence.bgp.evidence-row.v1' and row['provisional'] is True for row in rows)
    for leaf in ['evidence.ndjson','sequence.json','manifest.json']:
        assert (root/name/(leaf+'.partial')).read_bytes()==(root/name/leaf).read_bytes(), (name,leaf,'retained publication bytes differ')
    return rows,manifest,sequence
def source_coordinates(input_name):
    raw=(root/input_name).read_bytes(); records=[]; offset=0
    while offset<len(raw):
        seconds,kind,subtype,length=struct.unpack('>IHHI',raw[offset:offset+12])
        size=12+length; record=raw[offset:offset+size]
        assert len(record)==size
        records.append((offset,size,seconds,hashlib.sha256(record).hexdigest()))
        offset+=size
    assert offset==len(raw)
    return raw,records
def validate_source(rows,input_name,source_id,checkpoint):
    raw,records=source_coordinates(input_name)
    assert rows, input_name
    assert {int(row['record_ordinal']) for row in rows}==set(range(len(records))), rows
    for row in rows:
        offset,size,seconds,digest=records[int(row['record_ordinal'])]
        assert row['source_id']==source_id and row['checkpoint_id']==checkpoint, row
        assert row['source_sha256']==hashlib.sha256(raw).hexdigest() and int(row['full_source_bytes'])==len(raw), row
        assert int(row['record_offset'])==offset and int(row['record_bytes'])==size and row['record_sha256']==digest, row
        assert int(row['mrt_record_time']['seconds'])==seconds and row['mrt_record_time']['microseconds'] is None, row
        assert int(row['mrt_record_time']['time_ns'])==seconds*1000000000, row
    assert [int(row['record_ordinal']) for row in rows]==sorted(int(row['record_ordinal']) for row in rows), rows
"#;

#[test]
fn ordinary_stream_import_and_fresh_chronology_preserve_reverse_clock_source_order() {
    let root = Scratch::new();
    let bytes = [
        peer_table(30, 9, 65551),
        rib(20, 19, 7, 65551, false),
        record(10, 64512, 99, &[0x42, 0x43]),
    ]
    .concat();
    let store = import_source(&root, "source", &bytes, "collector-a");
    let sealed = fs::read(&store).unwrap();
    assert_eq!(&sealed[..8], b"PCBMRT02");
    let output = root.path("chronology");
    success(cli(export_args("chronology", &[&store], &output)));
    assert_eq!(
        fs::read(&store).unwrap(),
        sealed,
        "fresh consumer changed sealed input"
    );
    check_json(
        &root,
        r#"
rows,manifest,sequence=validate_export(pathlib.Path('chronology'))
validate_source(rows,'source.mrt','collector-a','source')
assert [int(row['mrt_record_time']['seconds']) for row in rows]==[30,20,10], rows
assert any(row['observation'] is not None and int(row['record_ordinal'])==1 for row in rows), rows
assert any(row['event'] is not None and int(row['record_ordinal'])==2 for row in rows), rows
assert all(row['window_disposition'] is None and row['asn_disposition'] is None for row in rows), rows
entries=sequence['entries']; assert len(entries)==1 and int(entries[0]['ordinal'])==0, sequence
assert any(value.get('source_sha256')==hashlib.sha256((root/'source.mrt').read_bytes()).hexdigest() for value in walk(entries[0])), entries
receipt=load('source/receipt.json'); raw=(root/'source.mrt').read_bytes()
assert receipt['schema']=='pcap-evidence.bgp.mrt-stream-receipt.v2', receipt
assert receipt['source_sha256']==hashlib.sha256(raw).hexdigest() and int(receipt['source_bytes'])==len(raw), receipt
assert int(receipt['record_count'])==3 and receipt['source_id']=='collector-a' and receipt['checkpoint_id']=='source', receipt
assert receipt['seal']==entries[0]['store_seal'] and all(row['store_seal']==receipt['seal'] for row in rows), receipt
assert int(manifest['coverage']['timestamp_regressions'])==2 and int(manifest['coverage']['opaque'])==1, manifest
"#,
    );
}

#[test]
fn ordinary_checkpoint_sequence_replays_each_source_with_its_own_pit_and_open_context() {
    let root = Scratch::new();
    let a = [
        peer_table(30, 9, 65551),
        rib(31, 29, 1, 65551, false),
        established_update(),
    ]
    .concat();
    let b = [
        peer_table(10, 42, 65599),
        rib(11, 9, 2, 65599, false),
        bgp4mp(12, 4, &update()),
    ]
    .concat();
    let first = import_source(&root, "first", &a, "collector-a");
    let second = import_source(&root, "second", &b, "collector-b");
    let combined = root.path("combined");
    let alone = root.path("alone");
    success(cli(export_args(
        "chronology",
        &[&first, &second],
        &combined,
    )));
    success(cli(export_args("chronology", &[&second], &alone)));
    // A RIB without its own PIT cannot become an independent sealed source.
    let orphan = root.path("orphan.mrt");
    fs::write(&orphan, rib(11, 9, 2, 65599, false)).unwrap();
    let refused = root.path("orphan");
    rejected(cli(import_args(&orphan, &refused, "collector-b", "orphan")));
    assert!(!refused.join("receipt.json").exists());
    assert!(!refused.join("bgp.mrt-stream").exists());
    check_json(
        &root,
        r#"
rows,_,sequence=validate_export(pathlib.Path('combined')); alone,_,_=validate_export(pathlib.Path('alone'))
first=[row for row in rows if int(row['sequence_ordinal'])==0]
second=[row for row in rows if int(row['sequence_ordinal'])==1]
validate_source(first,'first.mrt','collector-a','first'); validate_source(second,'second.mrt','collector-b','second')
assert [int(row['sequence_ordinal']) for row in rows]==sorted(int(row['sequence_ordinal']) for row in rows), rows
assert [entry['checkpoint_id'] for entry in sequence['entries']]==['first','second'], sequence
def without_sequence(row): return {key:value for key,value in row.items() if key!='sequence_ordinal'}
assert [without_sequence(row) for row in second]==[without_sequence(row) for row in alone], (second,alone)
assert any(row['observation'] is not None and int(row['record_ordinal'])==7 for row in first), first
orphan=[row for row in second if int(row['record_ordinal'])==2]
assert orphan and all(row['observation'] is None for row in orphan), orphan
assert any(row['event'] and row['event'].get('parse_status')=='quarantined' for row in orphan), orphan
rib_rows=[row for row in second if row['observation'] is not None]
assert rib_rows and all('203.0.113.42' in json.dumps(row['observation']) for row in rib_rows), rib_rows
assert all('203.0.113.9' not in json.dumps(row['observation']) for row in rib_rows), rib_rows
"#,
    );
}

#[test]
fn ordinary_window_keeps_half_open_boundaries_and_unknown_witnesses() {
    let root = Scratch::new();
    let bytes = [
        peer_table(10, 9, 65551),
        rib(20, 19, 1, 65551, false),
        rib(30, 29, 2, 65551, false),
        rib(25, 24, 3, 65551, true),
        bgp4mp(40, 4, &bgp(4, &[])),
    ]
    .concat();
    let store = import_source(&root, "source", &bytes, "collector-a");
    for (name, basis, scope, start, end) in [
        (
            "record-window",
            "mrt-record",
            "collector-a",
            20_000_000_000,
            30_000_000_000,
        ),
        (
            "rib-window",
            "rib-originated",
            "collector-a",
            19_000_000_000,
            29_000_000_000,
        ),
        (
            "observation-window",
            "observation",
            "collector-a",
            19_000_000_000,
            29_000_000_000,
        ),
    ] {
        success(cli(window_args(
            &store,
            &root.path(name),
            basis,
            scope,
            start,
            end,
        )));
    }
    // A scope absent from the verified sequence is a selector error. A scope
    // present in a two-source sequence leaves other sources outside that scope.
    let unknown_scope = root.path("unknown-clock");
    let refusal = cli(window_args(
        &store,
        &unknown_scope,
        "mrt-record",
        "collector-b",
        20_000_000_000,
        30_000_000_000,
    ));
    fs::write(root.path("unknown-clock-error.json"), &refusal.stderr).unwrap();
    rejected(refusal);
    for artifact in ["evidence.ndjson", "sequence.json", "manifest.json"] {
        assert!(!unknown_scope.join(artifact).exists());
    }
    let other_store = import_source(&root, "clock-source", &bytes, "collector-b");
    let mut other_clock = window_args(
        &store,
        &root.path("other-clock"),
        "mrt-record",
        "collector-b",
        20_000_000_000,
        30_000_000_000,
    );
    other_clock.extend(["--with-store".into(), other_store.as_os_str().into()]);
    success(cli(other_clock));
    let mut member = window_args(
        &store,
        &root.path("member-window"),
        "mrt-record",
        "all-source-clocks",
        20_000_000_000,
        30_000_000_000,
    );
    replace_arg(&mut member, "--asn-role", "path-member");
    success(cli(member));
    check_json(
        &root,
        r#"
record_rows,record_manifest,_=validate_export(pathlib.Path('record-window'))
rib_rows,rib_manifest,_=validate_export(pathlib.Path('rib-window'))
observation_rows,_,_=validate_export(pathlib.Path('observation-window'))
other_rows,_,_=validate_export(pathlib.Path('other-clock'))
member_rows,_,_=validate_export(pathlib.Path('member-window'))
for rows in [record_rows,rib_rows,observation_rows,member_rows]: validate_source(rows,'source.mrt','collector-a','source')
outside_scope=[row for row in other_rows if row['source_id']=='collector-a']
chosen_scope=[row for row in other_rows if row['source_id']=='collector-b']
validate_source(outside_scope,'source.mrt','collector-a','source')
validate_source(chosen_scope,'clock-source.mrt','collector-b','clock-source')
scope_error=load('unknown-clock-error.json')
assert scope_error['error']=='protocol_framing' and scope_error['field']=='bgp_evidence_clock_scope', scope_error
def observation_at(rows,ordinal):
    found=[row for row in rows if int(row['record_ordinal'])==ordinal and row['observation'] is not None]
    assert len(found)==1, found
    return found[0]
for rows in [record_rows,rib_rows,observation_rows]:
    start=observation_at(rows,1); end=observation_at(rows,2); ambiguous=observation_at(rows,3)
    assert start['asn_disposition']=='matched' and start['window_disposition']=='inside_label_window' and start['selected'] is True, start
    assert end['asn_disposition']=='matched' and end['window_disposition']=='outside_label_window' and end['selected'] is False, end
    assert ambiguous['asn_disposition']=='unknown_asn' and ambiguous['selected'] is False, ambiguous
assert all(row['window_disposition']=='outside_clock_scope' and row['selected'] is False for row in outside_scope), outside_scope
assert observation_at(chosen_scope,1)['selected'] is True, chosen_scope
assert any(int(row['record_ordinal'])==4 and row['window_disposition']=='unknown_time' and row['selected'] is False for row in rib_rows), rib_rows
assert any(int(row['record_ordinal'])==4 and row['window_disposition']=='unknown_time' and row['selected'] is False for row in observation_rows), observation_rows
assert any(value=='unknown_time' for obj in walk(rib_manifest) for value in obj.values() if isinstance(value,str)), rib_manifest
assert any(value=='unknown_asn' for obj in walk(record_manifest) for value in obj.values() if isinstance(value,str)), record_manifest
member=observation_at(member_rows,1)
assert member['asn_disposition']=='matched' and member['selected'] is True, member
"#,
    );
}

#[test]
fn ordinary_window_distinguishes_literal_all_source_clocks_from_all_clock_selection() {
    let root = Scratch::new();
    let bytes = [peer_table(10, 9, 65551), rib(20, 19, 1, 65551, false)].concat();
    let literal = import_source(&root, "literal", &bytes, "all-source-clocks");
    let other = import_source(&root, "other", &bytes, "collector-b");
    let mut exact = window_args(
        &literal,
        &root.path("literal-window"),
        "mrt-record",
        "all-source-clocks",
        20_000_000_000,
        20_000_000_001,
    );
    let scope_flag = exact.iter().position(|arg| arg == "--clock-scope").unwrap();
    exact[scope_flag] = "--clock-source".into();
    exact.extend(["--with-store".into(), other.as_os_str().into()]);
    success(cli(exact));
    // Preserve the existing deliberate all-clock CLI spelling.
    let mut all = window_args(
        &literal,
        &root.path("all-window"),
        "mrt-record",
        "all-source-clocks",
        20_000_000_000,
        20_000_000_001,
    );
    all.extend(["--with-store".into(), other.as_os_str().into()]);
    success(cli(all));
    // Both syntaxes together are ambiguous and must fail before publication,
    // regardless of their order or whether their textual values agree.
    for (name, exact_first) in [("both-legacy-first", false), ("both-exact-first", true)] {
        let output = root.path(name);
        let mut both = window_args(
            &literal,
            &output,
            "mrt-record",
            "all-source-clocks",
            20_000_000_000,
            20_000_000_001,
        );
        let flag = both.iter().position(|arg| arg == "--clock-scope").unwrap();
        if exact_first {
            both[flag] = "--clock-source".into();
            both.extend(["--clock-scope".into(), "all-source-clocks".into()]);
        } else {
            both.extend(["--clock-source".into(), "all-source-clocks".into()]);
        }
        rejected(cli(both));
        assert!(
            !output.exists(),
            "ambiguous scope created an output workspace"
        );
    }
    // The exact literal must be present; the all-clock sentinel cannot bypass
    // ordinary source-reference admission when passed through --clock-source.
    let absent = root.path("absent-literal");
    let mut missing = window_args(
        &other,
        &absent,
        "mrt-record",
        "all-source-clocks",
        20_000_000_000,
        20_000_000_001,
    );
    let flag = missing
        .iter()
        .position(|arg| arg == "--clock-scope")
        .unwrap();
    missing[flag] = "--clock-source".into();
    let refusal = cli(missing);
    fs::write(root.path("absent-literal-error.json"), &refusal.stderr).unwrap();
    rejected(refusal);
    for artifact in ["evidence.ndjson", "sequence.json", "manifest.json"] {
        assert!(!absent.join(artifact).exists());
    }
    check_json(
        &root,
        r#"
exact,exact_manifest,_=validate_export(pathlib.Path('literal-window'))
all_rows,all_manifest,_=validate_export(pathlib.Path('all-window'))
for rows in [exact,all_rows]:
    validate_source([row for row in rows if row['source_id']=='all-source-clocks'],'literal.mrt','all-source-clocks','literal')
    validate_source([row for row in rows if row['source_id']=='collector-b'],'other.mrt','collector-b','other')
    assert len(rows)==4, rows
assert exact_manifest['window']['clock_scope']=='all-source-clocks', exact_manifest
assert exact_manifest['window']['clock_scope_kind']=='source', exact_manifest
assert all_manifest['window']['clock_scope']=='all-source-clocks', all_manifest
assert all_manifest['window']['clock_scope_kind']=='all_source_clocks', all_manifest
exact_selected=[row for row in exact if row['selected']]
assert [(row['source_id'],int(row['record_ordinal'])) for row in exact_selected]==[('all-source-clocks',1)], exact_selected
outside=[row for row in exact if row['source_id']=='collector-b']
assert len(outside)==2 and all(row['window_disposition']=='outside_clock_scope' and row['selected'] is False for row in outside), outside
all_selected=[row for row in all_rows if row['selected']]
assert [(row['source_id'],int(row['record_ordinal'])) for row in all_selected]==[('all-source-clocks',1),('collector-b',1)], all_selected
assert not any(row['window_disposition']=='outside_clock_scope' for row in all_rows), all_rows
assert int(exact_manifest['coverage']['selected'])==1 and int(all_manifest['coverage']['selected'])==2
error=load('absent-literal-error.json')
assert error['error']=='protocol_framing' and error['field']=='bgp_evidence_clock_scope', error
"#,
    );
}

fn tree_bytes(path: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    let mut entries = fs::read_dir(path)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect::<Vec<_>>();
    entries.sort();
    entries
        .into_iter()
        .map(|entry| {
            assert!(entry.is_file(), "unexpected nested CLI artifact");
            (entry.file_name().unwrap().into(), fs::read(entry).unwrap())
        })
        .collect()
}

#[test]
fn ordinary_import_chronology_and_window_never_overwrite_existing_workspace_bytes() {
    let root = Scratch::new();
    let bytes = [peer_table(10, 9, 65551), rib(20, 19, 1, 65551, false)].concat();
    let store = import_source(&root, "source", &bytes, "collector-a");
    let source_tree = tree_bytes(&root.path("source"));
    rejected(cli(import_args(
        &root.path("source.mrt"),
        &root.path("source"),
        "changed",
        "changed",
    )));
    assert_eq!(tree_bytes(&root.path("source")), source_tree);
    let output = root.path("chronology");
    success(cli(export_args("chronology", &[&store], &output)));
    let before = tree_bytes(&output);
    rejected(cli(export_args("chronology", &[&store], &output)));
    assert_eq!(tree_bytes(&output), before);
    rejected(cli(window_args(
        &store,
        &output,
        "mrt-record",
        "collector-a",
        0,
        30_000_000_000,
    )));
    assert_eq!(tree_bytes(&output), before);
    assert_eq!(tree_bytes(&root.path("source")), source_tree);
}

#[test]
fn ordinary_consumers_reject_corrupt_and_torn_seals_without_success_manifest() {
    let root = Scratch::new();
    let source = [peer_table(10, 9, 65551), rib(20, 19, 1, 65551, false)].concat();
    let store = import_source(&root, "source", &source, "collector-a");
    let bytes = fs::read(&store).unwrap();
    for (name, damaged) in [
        ("corrupt", {
            let mut value = bytes.clone();
            value[0] ^= 1;
            value
        }),
        ("torn", bytes[..bytes.len() - 1].to_vec()),
    ] {
        let input = root.path(&format!("{name}.mrt-stream"));
        fs::write(&input, &damaged).unwrap();
        for operation in ["chronology", "window"] {
            let output = root.path(&format!("{name}-{operation}"));
            let args = if operation == "window" {
                window_args(
                    &input,
                    &output,
                    "mrt-record",
                    "collector-a",
                    0,
                    30_000_000_000,
                )
            } else {
                export_args(operation, &[&input], &output)
            };
            rejected(cli(args));
            assert!(!output.join("manifest.json").exists());
            assert!(!output.join("evidence.ndjson").exists());
            assert!(!output.join("sequence.json").exists());
            assert_eq!(fs::read(&input).unwrap(), damaged);
        }
    }
    assert_eq!(fs::read(&store).unwrap(), bytes);
}

#[test]
fn ordinary_import_applies_explicit_caps_and_retains_owned_partial_on_failure() {
    let root = Scratch::new();
    let bytes = [peer_table(10, 9, 65551), rib(20, 19, 1, 65551, false)].concat();
    let input = root.path("source.mrt");
    fs::write(&input, &bytes).unwrap();
    let mut exact = import_args(&input, &root.path("exact"), "collector-a", "exact");
    replace_arg(&mut exact, "--max-source-bytes", bytes.len().to_string());
    success(cli(exact));
    for (name, flag, value) in [
        (
            "source-cap",
            "--max-source-bytes",
            (bytes.len() - 1).to_string(),
        ),
        ("store-cap", "--max-store-bytes", "1".into()),
        ("record-cap", "--max-record-bytes", "12".into()),
        ("count-cap", "--max-records", "1".into()),
        ("work-cap", "--max-work", "1".into()),
    ] {
        let workspace = root.path(name);
        let mut args = import_args(&input, &workspace, "collector-a", name);
        replace_arg(&mut args, flag, value);
        rejected(cli(args));
        assert!(!workspace.join("receipt.json").exists());
        assert!(!workspace.join("bgp.mrt-stream").exists());
        if name == "count-cap" {
            assert!(workspace.join("bgp.mrt-stream.partial").is_file());
            assert!(
                fs::metadata(workspace.join("bgp.mrt-stream.partial"))
                    .unwrap()
                    .len()
                    > 0
            );
        }
        assert_eq!(fs::read(&input).unwrap(), bytes);
    }
    let seal = fs::read(root.path("exact/bgp.mrt-stream")).unwrap();
    assert_eq!(&seal[..8], b"PCBMRT02");
    assert_ne!(sha256::digest(&seal), sha256::digest(&bytes));
}

#[test]
fn ordinary_export_output_cap_retains_partial_and_does_not_publish_complete_manifest() {
    let root = Scratch::new();
    let bytes = [peer_table(10, 9, 65551), rib(20, 19, 1, 65551, false)].concat();
    let store = import_source(&root, "source", &bytes, "collector-a");
    let sealed = fs::read(&store).unwrap();
    for operation in ["chronology", "window"] {
        let workspace = root.path(operation);
        let mut args = if operation == "window" {
            window_args(
                &store,
                &workspace,
                "mrt-record",
                "collector-a",
                0,
                30_000_000_000,
            )
        } else {
            export_args(operation, &[&store], &workspace)
        };
        replace_arg(&mut args, "--max-output-bytes", "1");
        rejected(cli(args));
        assert!(workspace.join("evidence.ndjson.partial").is_file());
        assert!(!workspace.join("evidence.ndjson").exists());
        assert!(!workspace.join("sequence.json").exists());
        assert!(!workspace.join("manifest.json").exists());
        assert_eq!(fs::read(&store).unwrap(), sealed);
    }
}
