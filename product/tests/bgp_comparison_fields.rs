//! Tiny real native producer -> committed v2 export -> Python comparison join.
//! Finite fixtures establish availability behavior, not protocol qualification.
use std::{
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
};
static SERIAL: AtomicU64 = AtomicU64::new(0);
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "bgp-comparison-fields-{}-{}",
            std::process::id(),
            SERIAL.fetch_add(1, Ordering::Relaxed)
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
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn run(args: Vec<OsString>) {
    let binary = std::env::var_os("PCAP_DEPTH_TEST_BINARY")
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_pcap-depth").into());
    let output = Command::new(binary).args(args).output().unwrap();
    assert!(
        output.status.success(),
        "native CLI failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
fn record(time: u32, subtype: u16, body: &[u8]) -> Vec<u8> {
    let mut bytes = time.to_be_bytes().to_vec();
    bytes.extend(16u16.to_be_bytes());
    bytes.extend(subtype.to_be_bytes());
    bytes.extend((body.len() as u32).to_be_bytes());
    bytes.extend(body);
    bytes
}
fn message(kind: u8, payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![255; 16];
    bytes.extend(((payload.len() + 19) as u16).to_be_bytes());
    bytes.push(kind);
    bytes.extend(payload);
    bytes
}
fn carrier(payload: &[u8]) -> Vec<u8> {
    let mut bytes = 64512u16.to_be_bytes().to_vec();
    bytes.extend(64513u16.to_be_bytes());
    bytes.extend([0, 7, 0, 1]);
    bytes.extend([198, 51, 100, 1, 198, 51, 100, 2]);
    bytes.extend(payload);
    bytes
}
fn source(case: &str) -> Vec<u8> {
    let open = |asn: u16, id: [u8; 4]| {
        let mut bytes = vec![4];
        bytes.extend(asn.to_be_bytes());
        bytes.extend([0, 90]);
        bytes.extend(id);
        bytes.push(0);
        message(1, &bytes)
    };
    let state = |time, old: u16, new: u16| {
        let mut bytes = old.to_be_bytes().to_vec();
        bytes.extend(new.to_be_bytes());
        record(time, 0, &carrier(&bytes))
    };
    let mut update = if case == "withdraw" || case == "hidden" {
        vec![0, 4, 24, 198, 51, 100]
    } else {
        vec![0, 0]
    };
    let mut attrs = if case == "withdraw" {
        Vec::new()
    } else {
        vec![
            0x40, 1, 1, 0, 0x40, 2, 4, 2, 1, 0xfc, 0x00, 0x40, 3, 4, 192, 0, 2, 9,
        ]
    };
    if case == "incomplete" {
        attrs.extend([0xc0, 99, 1, 7]);
    }
    if case == "hidden" {
        attrs.extend([0x80, 14, 13, 0, 99, 1, 4, 192, 0, 2, 9, 0, 24, 192, 0, 2]);
    }
    update.extend((attrs.len() as u16).to_be_bytes());
    update.extend(attrs);
    if case != "withdraw" {
        update.extend([24, 203, 0, 113]);
    }
    [
        state(10, 3, 4),
        record(11, 1, &carrier(&open(64512, [198, 51, 100, 1]))),
        record(12, 6, &carrier(&open(64513, [198, 51, 100, 2]))),
        state(13, 4, 5),
        state(14, 5, 6),
        record(15, 1, &carrier(&message(2, &update))),
    ]
    .concat()
}
fn import_export(scratch: &Scratch, case: &str) -> PathBuf {
    let input = scratch.path(&format!("{case}.mrt"));
    fs::write(&input, source(case)).unwrap();
    let imported = scratch.path(&format!("{case}-import"));
    let exported = scratch.path(&format!("{case}-export"));
    run(vec![
        "bgp".into(),
        "import-mrt-stream".into(),
        input.into_os_string(),
        "--workspace".into(),
        imported.clone().into_os_string(),
        "--source-id".into(),
        "fixture-source".into(),
        "--checkpoint".into(),
        "fixture-checkpoint".into(),
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
    ]);
    run(vec![
        "bgp".into(),
        "chronology".into(),
        imported.join("bgp.mrt-stream").into_os_string(),
        "--workspace".into(),
        exported.clone().into_os_string(),
        "--comparison-fields".into(),
        "per-field-v2".into(),
        "--peer-relationship".into(),
        "external".into(),
        "--max-source-bytes".into(),
        "1048576".into(),
        "--max-store-bytes".into(),
        "4194304".into(),
        "--max-output-bytes".into(),
        "2097152".into(),
    ]);
    exported
}
#[test]
fn native_per_field_exports_reach_python_comparison_with_tamper_controls() {
    let scratch = Scratch::new();
    for case in ["valid", "withdraw", "incomplete", "hidden"] {
        import_export(&scratch, case);
    }
    let python = std::env::var("PYTHON").unwrap_or_else(|_| {
        if cfg!(windows) {
            "python".into()
        } else {
            "python3".into()
        }
    });
    let script = r#"
import copy, hashlib, json, pathlib, sys
from tools.research import bgp_compare as bgp
from tools.research.contract import InvalidResearch
root=pathlib.Path(sys.argv[1])
assert pathlib.Path(bgp.__file__).resolve()==pathlib.Path('tools/research/bgp_compare.py').resolve()
for case in ('valid','withdraw','incomplete','hidden'):
    directory=root/(case+'-export')
    raw=(directory/'evidence.ndjson').read_bytes()
    manifest=json.loads((directory/'manifest.json').read_bytes())
    doc=bgp.from_native(raw,manifest,comparison_fields='per-field-v2')
    row=doc['observations'][-1]
    results={r['field']:r for r in bgp.compare(doc,doc)['rows'] if r['record_offset']==row['record_offset'] and r['group']=='nlri'}
    for name in ('route_actions','route_prefixes'):
        assert results[name]['result']==('not_comparable' if case=='hidden' else 'agreement'), (case,results)
    if case in ('withdraw','incomplete','hidden'):
        assert results['semantic_identity']['result']=='not_comparable'
        assert row['fields']['attributes']['route_attributes']['status']=='incomplete'
    if case!='hidden':
        expected_action='withdraw' if case=='withdraw' else 'announce'
        expected_address='198.51.100.0' if case=='withdraw' else '203.0.113.0'
        assert row['fields']['nlri']['route_actions']['value']==[{'route_index':'0','action':expected_action}]
        assert row['fields']['nlri']['route_prefixes']['value']==[{'route_index':'0','prefix':{'afi':1,'safi':1,'length':24,'address':expected_address},'path_id':None}]
    def rejects(data,m):
        try: bgp.from_native(data,m,comparison_fields='per-field-v2')
        except InvalidResearch: return
        raise AssertionError('tampered carrier accepted')
    rejects(raw.replace(b'"fixture-source"',b'"changed-source"',1),manifest)
    bad=copy.deepcopy(manifest); bad['field_availability_schema']='unknown'; rejects(raw,bad)
    # Rebuild only candidate-controlled commitments; contradictions must still reject.
    objects=[json.loads(line) for line in raw.splitlines()]
    rows=objects[:-1]
    assert objects[-1]['schema']=='pcap-evidence.bgp.evidence-manifest.v2'
    if case=='hidden': rows[-1]['field_availability']['status']='complete'
    else: rows[-1]['field_availability']['routes'][0]['action']='withdraw' if case!='withdraw' else 'announce'
    newraw=b''.join(json.dumps(r,separators=(',',':')).encode()+b'\n' for r in rows)
    bad=copy.deepcopy(manifest); bad['rows_bytes']=str(len(newraw)); bad['rows_sha256']=hashlib.sha256(newraw).hexdigest()
    payload={key:value for key,value in bad.items() if key!='semantic_identity'}
    bad['semantic_identity']=hashlib.sha256(b'pcap-evidence/bgp-evidence-manifest/v2\0'+json.dumps(payload,separators=(',',':')).encode()).hexdigest()
    rejects(newraw,bad)
"#;
    let output = Command::new(python)
        .current_dir(Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap())
        .args(["-B", "-c", script])
        .arg(&scratch.0)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "native/Python join failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
