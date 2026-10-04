use std::{
    fs,
    path::PathBuf,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

fn mrt_record(seconds: u32, kind: u16, subtype: u16, body: &[u8]) -> Vec<u8> {
    let mut value = Vec::new();
    value.extend_from_slice(&seconds.to_be_bytes());
    value.extend_from_slice(&kind.to_be_bytes());
    value.extend_from_slice(&subtype.to_be_bytes());
    value.extend_from_slice(&(body.len() as u32).to_be_bytes());
    value.extend_from_slice(body);
    value
}

fn mrt_fixture() -> Vec<u8> {
    let mut table = vec![
        192, 0, 2, 1, 0, 1, b'v', 0, 1, 2, 192, 0, 2, 2, 203, 0, 113, 9,
    ];
    table.extend_from_slice(&65551u32.to_be_bytes());
    let table = mrt_record(11, 13, 1, &table);
    let mut attributes = vec![0x40, 1, 1, 0, 0x40, 2, 6, 2, 1];
    attributes.extend_from_slice(&65551u32.to_be_bytes());
    attributes.extend_from_slice(&[0x40, 3, 4, 192, 0, 2, 9]);
    let mut rib = vec![0, 0, 0, 7, 24, 203, 0, 113, 0, 1, 0, 0];
    rib.extend_from_slice(&10u32.to_be_bytes());
    rib.extend_from_slice(&(attributes.len() as u16).to_be_bytes());
    rib.extend_from_slice(&attributes);
    [table, mrt_record(12, 13, 2, &rib)].concat()
}

#[cfg(all(feature = "standard", feature = "binary"))]
use pcap_evidence::{capture::Endian, sha256, time::Timestamp, writer::PcapWriter, Limits};

#[cfg(all(feature = "standard", feature = "binary"))]
fn bgp_message(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut message = vec![0xff; 16];
    message.extend_from_slice(&u16::try_from(19 + body.len()).unwrap().to_be_bytes());
    message.push(kind);
    message.extend_from_slice(body);
    message
}

#[cfg(all(feature = "standard", feature = "binary"))]
fn bgp_capability(code: u8, value: &[u8]) -> Vec<u8> {
    let mut capability = vec![code, u8::try_from(value.len()).unwrap()];
    capability.extend_from_slice(value);
    capability
}

#[cfg(all(feature = "standard", feature = "binary"))]
fn bgp_open(as16: u16, router_id: [u8; 4], capabilities: &[Vec<u8>]) -> Vec<u8> {
    let capabilities: Vec<u8> = capabilities.iter().flatten().copied().collect();
    let mut body = vec![4];
    body.extend_from_slice(&as16.to_be_bytes());
    body.extend_from_slice(&90u16.to_be_bytes());
    body.extend_from_slice(&router_id);
    body.push(u8::try_from(capabilities.len() + 2).unwrap());
    body.extend_from_slice(&[2, u8::try_from(capabilities.len()).unwrap()]);
    body.extend(capabilities);
    bgp_message(1, &body)
}

#[cfg(all(feature = "standard", feature = "binary"))]
fn bgp_attribute(flags: u8, code: u8, payload: &[u8]) -> Vec<u8> {
    let mut attribute = vec![flags, code, u8::try_from(payload.len()).unwrap()];
    attribute.extend_from_slice(payload);
    attribute
}

#[cfg(all(feature = "standard", feature = "binary"))]
fn bgp_update() -> Vec<u8> {
    let mut attributes = bgp_attribute(0x40, 1, &[0]);
    attributes.extend(bgp_attribute(0x40, 2, &[2, 1, 0, 1, 0x11, 0x70]));
    attributes.extend(bgp_attribute(0x40, 3, &[192, 0, 2, 1]));
    let mut body = vec![0, 0];
    body.extend_from_slice(&u16::try_from(attributes.len()).unwrap().to_be_bytes());
    body.extend(attributes);
    body.extend_from_slice(&[24, 203, 0, 113]);
    bgp_message(2, &body)
}

#[cfg(all(feature = "standard", feature = "binary"))]
fn internet_checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u64;
    for pair in bytes.chunks(2) {
        sum += (u64::from(pair[0]) << 8) + u64::from(*pair.get(1).unwrap_or(&0));
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(all(feature = "standard", feature = "binary"))]
#[allow(clippy::too_many_arguments)]
fn tcp_packet(
    source: [u8; 4],
    destination: [u8; 4],
    source_port: u16,
    destination_port: u16,
    sequence: u32,
    acknowledgment: u32,
    flags: u8,
    identification: u16,
    payload: &[u8],
) -> Vec<u8> {
    let mut packet = vec![0u8; 40];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&u16::try_from(40 + payload.len()).unwrap().to_be_bytes());
    packet[4..6].copy_from_slice(&identification.to_be_bytes());
    packet[8] = 64;
    packet[9] = 6;
    packet[12..16].copy_from_slice(&source);
    packet[16..20].copy_from_slice(&destination);
    packet[20..22].copy_from_slice(&source_port.to_be_bytes());
    packet[22..24].copy_from_slice(&destination_port.to_be_bytes());
    packet[24..28].copy_from_slice(&sequence.to_be_bytes());
    packet[28..32].copy_from_slice(&acknowledgment.to_be_bytes());
    packet[32] = 0x50;
    packet[33] = flags;
    packet[34..36].copy_from_slice(&65_535u16.to_be_bytes());
    packet.extend_from_slice(payload);
    let checksum = internet_checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&checksum.to_be_bytes());
    let mut pseudo_header = Vec::with_capacity(12 + packet.len() - 20);
    pseudo_header.extend_from_slice(&source);
    pseudo_header.extend_from_slice(&destination);
    pseudo_header.extend_from_slice(&[0, 6]);
    pseudo_header.extend_from_slice(&u16::try_from(packet.len() - 20).unwrap().to_be_bytes());
    pseudo_header.extend_from_slice(&packet[20..]);
    let checksum = internet_checksum(&pseudo_header);
    packet[36..38].copy_from_slice(&checksum.to_be_bytes());
    packet
}

#[cfg(all(feature = "standard", feature = "binary"))]
fn capture_ordered_bgp_session() -> Vec<u8> {
    let left = [10, 0, 0, 1];
    let right = [10, 0, 0, 2];
    let left_port = 50_000;
    let right_port = 179;
    let four_octet = bgp_capability(65, &70_000u32.to_be_bytes());
    let left_open = bgp_open(23_456, [192, 0, 2, 1], std::slice::from_ref(&four_octet));
    let right_open = bgp_open(23_456, [192, 0, 2, 2], &[four_octet]);
    let update = bgp_update();
    let update_split = 23;
    let update_start = 1_001 + u32::try_from(left_open.len()).unwrap();
    let left_data_end = 1_001 + u32::try_from(left_open.len() + update.len()).unwrap();
    let right_data_end = 2_001 + u32::try_from(right_open.len()).unwrap();

    let packets = [
        tcp_packet(left, right, left_port, right_port, 1_000, 0, 0x02, 1, &[]),
        tcp_packet(
            right,
            left,
            right_port,
            left_port,
            2_000,
            1_001,
            0x12,
            2,
            &[],
        ),
        tcp_packet(
            left,
            right,
            left_port,
            right_port,
            1_001,
            2_001,
            0x10,
            3,
            &[],
        ),
        tcp_packet(
            left, right, left_port, right_port, 1_001, 2_001, 0x18, 4, &left_open,
        ),
        tcp_packet(
            right,
            left,
            right_port,
            left_port,
            2_001,
            1_001 + u32::try_from(left_open.len()).unwrap(),
            0x18,
            5,
            &right_open,
        ),
        tcp_packet(
            left,
            right,
            left_port,
            right_port,
            update_start + u32::try_from(update_split).unwrap(),
            right_data_end,
            0x18,
            6,
            &update[update_split..],
        ),
        // Capture the leading UPDATE segment after its successor. The TCP
        // reassembler must restore sequence order without causing the BGP
        // merger to regress to direction-by-direction event ordering.
        tcp_packet(
            left,
            right,
            left_port,
            right_port,
            update_start,
            right_data_end,
            0x18,
            7,
            &update[..update_split],
        ),
        tcp_packet(
            left,
            right,
            left_port,
            right_port,
            left_data_end,
            right_data_end,
            0x11,
            8,
            &[],
        ),
        tcp_packet(
            right,
            left,
            right_port,
            left_port,
            right_data_end,
            left_data_end + 1,
            0x11,
            9,
            &[],
        ),
        tcp_packet(
            left,
            right,
            left_port,
            right_port,
            left_data_end + 1,
            right_data_end + 1,
            0x10,
            10,
            &[],
        ),
    ];
    let mut writer = PcapWriter::new(
        Vec::new(),
        Endian::Little,
        false,
        228,
        65_535,
        Limits::default(),
    )
    .unwrap();
    for (index, packet) in packets.iter().enumerate() {
        writer
            .packet(
                Timestamp::legacy(u32::try_from(index + 1).unwrap(), 0, false).unwrap(),
                u32::try_from(packet.len()).unwrap(),
                packet,
            )
            .unwrap();
    }
    writer.finish().unwrap()
}

#[test]
fn dnp3_pcap_depth_consumes_assembled_and_fragment_evidence() {
    let input = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../tests/fixtures/dnp3_tcp.pcap");
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_nanos();
    let workspace = std::env::temp_dir().join(format!(
        "pcap-evidence-depth-dnp3-{}-{nonce}",
        std::process::id()
    ));
    assert!(!workspace.exists(), "test workspace collision");

    let result = Command::new(env!("CARGO_BIN_EXE_pcap-depth"))
        .args([
            "analyze",
            input.to_str().expect("fixture path is UTF-8"),
            "--workspace",
            workspace.to_str().expect("workspace path is UTF-8"),
            "--format",
            "ndjson",
        ])
        .output()
        .expect("pcap-depth binary runs");
    assert!(
        result.status.success(),
        "pcap-depth failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    let events = fs::read_to_string(workspace.join("events.ndjson")).expect("events output");
    assert!(events.contains("\"depth_fragments\""));
    assert!(events.contains("\"depth_assembled\""));
    assert!(events.contains("\"application_object_evidence\""));

    fs::remove_dir_all(workspace).expect("remove isolated test workspace");
}

// Each fixture traverses TCP reconstruction, the shallow framer, DeepSink,
// sealed persistence, and fresh CLI consumers. Wire bytes and expectations are
// independent of the deep reducer; the malformed attribute length and /33 are
// deliberate complete-message witnesses.
#[cfg(all(feature = "standard", feature = "binary"))]
fn capture_bgp_omission(mode: &str) -> Vec<u8> {
    let cap = bgp_capability(65, &70_000u32.to_be_bytes());
    let opens = [
        bgp_open(23_456, [192, 0, 2, 1], std::slice::from_ref(&cap)),
        bgp_open(23_456, [192, 0, 2, 2], &[cap]),
    ];
    let route = bgp_update();
    let withdrawal = bgp_message(2, &[0, 4, 24, 203, 0, 113, 0, 0]);
    let mut next_route = route.clone();
    *next_route.last_mut().unwrap() = 114;
    let bad = match mode {
        "framer" => bgp_message(2, &[0, 0, 0, 3, 0x40, 1, 1, 24, 203, 0, 113]),
        "deep" => {
            let mut bad = route.clone();
            let length = bad.len();
            bad[length - 4] = 33;
            bad
        }
        "valid" => route.clone(),
        _ => panic!("unknown fixture"),
    };
    let mut packets = Vec::new();
    for session in 0..2u8 {
        let left = [10, 0, session, 1];
        let right = [10, 0, session, 2];
        let port = 50_000 + u16::from(session);
        let mut add = |reverse: bool, sequence, acknowledgment, flags, payload: &[u8]| {
            packets.push(tcp_packet(
                if reverse { right } else { left },
                if reverse { left } else { right },
                if reverse { 179 } else { port },
                if reverse { port } else { 179 },
                sequence,
                acknowledgment,
                flags,
                1,
                payload,
            ));
        };
        add(false, 1000, 0, 0x02, &[]);
        add(true, 2000, 1001, 0x12, &[]);
        add(false, 1001, 2001, 0x10, &[]);
        add(false, 1001, 2001, 0x18, &opens[0]);
        let mut left_end = 1001 + opens[0].len() as u32;
        add(true, 2001, left_end, 0x18, &opens[1]);
        let mut right_end = 2001 + opens[1].len() as u32;
        add(false, left_end, right_end, 0x18, &route);
        if session == 0 && mode == "valid" {
            // Identical TCP retransmission must not duplicate a source message.
            add(false, left_end, right_end, 0x18, &route);
        }
        left_end += route.len() as u32;
        if session == 0 {
            let continuation = if mode == "deep" {
                &next_route
            } else {
                &withdrawal
            };
            let chunk = [bad.as_slice(), continuation.as_slice()].concat();
            add(false, left_end, right_end, 0x18, &chunk);
            left_end += chunk.len() as u32;
            // The untouched direction continues after the omitted/rejected
            // record. Its independent /24 cannot restore lost continuity.
            add(true, right_end, left_end, 0x18, &next_route);
            right_end += next_route.len() as u32;
        }
        add(false, left_end, right_end, 0x11, &[]);
        add(true, right_end, left_end + 1, 0x11, &[]);
        add(false, left_end + 1, right_end + 1, 0x10, &[]);
    }
    let mut writer = PcapWriter::new(
        Vec::new(),
        Endian::Little,
        false,
        228,
        65_535,
        Limits::default(),
    )
    .unwrap();
    for (index, packet) in packets.iter().enumerate() {
        writer
            .packet(
                Timestamp::legacy((index + 1) as u32, 0, false).unwrap(),
                packet.len() as u32,
                packet,
            )
            .unwrap();
    }
    assert!(packets.len() <= 40);
    let capture = writer.finish().unwrap();
    assert!(capture.len() <= 10_000);
    capture
}

#[cfg(all(feature = "standard", feature = "binary"))]
fn assert_capture_bgp_omission(mode: &str) {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "pcap-depth-omission-{mode}-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir(&root).unwrap();
    let input = root.join("capture.pcap");
    let workspace = root.join("workspace");
    fs::write(&input, capture_bgp_omission(mode)).unwrap();
    let run = |args: &[&str]| {
        let output = Command::new(env!("CARGO_BIN_EXE_pcap-depth"))
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "fixture {root:?}: {:?}: {}",
            args,
            String::from_utf8_lossy(&output.stderr)
        );
    };
    run(&[
        "analyze",
        input.to_str().unwrap(),
        "--workspace",
        workspace.to_str().unwrap(),
        "--max-index-bytes",
        "4096",
        "--max-output-bytes",
        "1000000",
        "--max-bgp-journal-bytes",
        "1000000",
    ]);
    let journal = workspace.join("bgp.journal");
    for operation in ["state", "query", "export", "policy"] {
        let output = root.join(format!("{operation}.json"));
        let mut args = vec![
            "bgp",
            operation,
            journal.to_str().unwrap(),
            "--output",
            output.to_str().unwrap(),
        ];
        let profile = root.join("policy.txt");
        if operation == "query" {
            args.extend(["--session", "1"]);
        }
        if operation == "policy" {
            fs::write(&profile, "schema=pcap-evidence.bgp.persisted-policy.v1\nprovenance=synthetic-capture\ncomparison_context=offline-capture\nmissing_local_preference=100\nmed_rule=skip\nage_rule=skip\n").unwrap();
            args.extend(["--policy-profile", profile.to_str().unwrap()]);
        }
        run(&args);
    }
    let rich = root.join("rich.json");
    run(&[
        "bgp",
        "query",
        journal.to_str().unwrap(),
        "--prefix",
        "203.0.113.0/24",
        "--output",
        rich.to_str().unwrap(),
    ]);
    let all = root.join("all.json");
    run(&[
        "bgp",
        "query",
        journal.to_str().unwrap(),
        "--afi",
        "1",
        "--output",
        all.to_str().unwrap(),
    ]);
    let python = std::env::var("PYTHON").unwrap_or_else(|_| {
        if cfg!(windows) {
            "python".into()
        } else {
            "python3".into()
        }
    });
    let checked = Command::new(python).args(["-c", r#"
import hashlib,json,pathlib,struct,sys
root=pathlib.Path(sys.argv[1]); mode=sys.argv[2]
def load(name): return json.loads((root/name).read_text())
events=[json.loads(x)['event'] for x in (root/'workspace/events.ndjson').read_text().splitlines()]
assert not any('invalid_transport_checksum_observed' in json.dumps(e) for e in events)
messages=[e for e in events if e.get('protocol')=='bgp' and e['kind']=='protocol.message']
prior=[e for e in messages if e['session']=='1' and e['data'].get('depth_bgp_pipeline',{}).get('state',{}).get('active_routes')==1]
assert prior, 'fixture did not reach a valid prior route'
first_route=next(e for e in prior if e['data']['depth_bgp_pipeline']['state']['route_entries']==1)
assert first_route['data']['depth_bgp_pipeline']['state']['gaps']==0
immediate={e['session']:e['data']['depth_bgp_session_summary'] for e in events if 'depth_bgp_session_summary' in e['data']}
state=load('state.json'); snapshots={s['summary']['session']:s for s in state['sessions']}
query=load('query.json'); assert len(query['occurrences'])==1
assert query['occurrences'][0]==snapshots['1']
export=[json.loads(x) for x in (root/'export.json').read_text().splitlines()]
assert {s['summary']['session']:s for s in export if s.get('schema')=='pcap-evidence.bgp.session-snapshot.v1'}==snapshots
for sid in ['1','2']:
    assert immediate[sid]==snapshots[sid]['summary'], (mode,'immediate/replay summary mismatch',immediate[sid],snapshots[sid]['summary'])
    assert immediate[sid]['generation']==0
    assert not snapshots[sid]['state']['reset_records']
assert immediate['2']['gaps']==0 and immediate['2']['active_routes']==1
assert immediate['2']['route_entries']==1
rich=load('rich.json')['routes']; rows=load('all.json')['routes']
assert len(rich)==2 and all(not r['native_current'] for r in rows), 'END is historical, not selectable'
original=next(r for r in rows if r['session']=='1' and r['prefix']=='203.0.113.0/24')
assert any(first_route['data']['depth_bgp_pipeline']['record_id'] in v['witnesses'] for v in original['alternatives']), 'prior route witness lost'
assert all(r['generation']==0 for r in rows)
# Every closed candidate is excluded by policy, even the unaffected Active history.
def walk(x):
    if isinstance(x,dict):
        yield x
        for v in x.values(): yield from walk(v)
    elif isinstance(x,list):
        for v in x: yield from walk(v)
policy=list(walk(load('policy.json')))
assert any(x.get('schema')=='pcap-evidence.bgp.policy-result.v1' for x in policy)
assert all(x.get('selected') is None for x in policy if 'selected' in x)
if mode=='valid':
    assert immediate['1']['gaps']==0 and immediate['1']['withdrawn_routes']==1
    assert original['status']=='withdrawn'
    assert len(messages)==9, 'retransmission duplicated a framed message'
else:
    assert immediate['1']['gaps']==1, (mode,'one omission must produce one scoped gap',immediate['1'])
    assert immediate['1']['active_routes']==0 and immediate['1']['withdrawn_routes']==0
    assert immediate['1']['superseded_routes']==0
    assert all(r['status']=='unresolved' for r in rows if r['session']=='1')
    assert all(v['disposition']=='current' for v in original['alternatives']), 'omission invented withdrawal or supersession'
    later=[e for e in messages if e['session']=='1' and e['data'].get('depth_bgp_pipeline',{}).get('state',{}).get('gaps')==1]
    assert later and all(e['data']['depth_bgp_pipeline']['state']['active_routes']==0 for e in later)
    expected=bytes.fromhex('ffffffffffffffffffffffffffffffff001e020000000340010118cb0071') if mode=='framer' else None
    if mode=='framer':
        issues=[e for e in events if e['kind']=='protocol.issue' and e.get('protocol')=='bgp']
        assert len(issues)==1 and issues[0]['session']=='1' and issues[0]['direction'] is not None
        issue=issues[0]; assert issue['data']['depth_bgp_boundary']['generation']==0
        assert issue['data']['depth_bgp_boundary']['previous_generation']==0
        expected+=bytes.fromhex('ffffffffffffffffffffffffffffffff001b02000418cb00710000')
        evidence=issue['evidence']
        assert evidence['reconstructed_sha256']==hashlib.sha256(expected).hexdigest()
        assert int(evidence['byte_length'])==len(expected)
        assert len(evidence['spans'])==1
        capture=(root/'capture.pcap').read_bytes(); span=evidence['spans'][0]
        offset=int(span['record_offset'])+16+int(span['packet_start'])
        assert capture[offset:offset+len(expected)]==expected
        # The journal's existing GAP carrier binds the exact source event ID.
        journal=(root/'workspace/bgp.journal').read_bytes(); pos=42
        source_len=struct.unpack_from('<I',journal,pos)[0]; pos+=4+source_len
        kinds=[]; gaps=[]
        while pos<len(journal):
            kind=journal[pos]; size=struct.unpack_from('<Q',journal,pos+1)[0]
            body=journal[pos+73:pos+73+size]; kinds.append(kind)
            if kind==2:
                sid=struct.unpack_from('<Q',body)[0]; n=struct.unpack_from('<I',body,8)[0]
                gaps.append((sid,body[12:12+n].decode()))
            pos+=73+size
        assert gaps==[(1,issue['data']['depth_bgp_boundary']['record_id'])]
        assert 3 not in kinds and kinds.count(4)==2 and kinds[-1]==255
        assert state['rejected_records']=='0' and state['boundaries']=='1'
    else:
        rejected=[e for e in messages if e['data'].get('depth_bgp_pipeline',{}).get('status')=='rejected']
        assert len(rejected)==1 and rejected[0]['session']=='1'
        assert state['rejected_records']=='1' and state['boundaries']=='0', 'MESSAGE rejection must not add journal GAP'
print(json.dumps({'mode':mode,'capture_sha256':hashlib.sha256((root/'capture.pcap').read_bytes()).hexdigest(),'immediate':immediate,'rejected_records':state['rejected_records'],'boundaries':state['boundaries']},sort_keys=True))
"#, root.to_str().unwrap(), mode]).output().unwrap();
    assert!(
        checked.status.success(),
        "JSON oracle failed; retained fixture {root:?}: {}",
        String::from_utf8_lossy(&checked.stderr)
    );
    println!("{}", String::from_utf8_lossy(&checked.stdout));
    fs::remove_dir_all(root).unwrap();
}

#[test]
#[cfg(all(feature = "standard", feature = "binary"))]
fn bgp_capture_framer_omission_preserves_scoped_uncertainty_and_replay() {
    assert_capture_bgp_omission("framer");
}

#[test]
#[cfg(all(feature = "standard", feature = "binary"))]
fn bgp_capture_deep_rejection_preserves_scoped_uncertainty_and_replay() {
    assert_capture_bgp_omission("deep");
}

#[test]
#[cfg(all(feature = "standard", feature = "binary"))]
fn bgp_capture_valid_withdrawal_and_retransmission_control() {
    assert_capture_bgp_omission("valid");
}

#[test]
#[cfg(all(feature = "standard", feature = "binary"))]
fn bgp_pcap_depth_emits_normalized_route_evidence() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "pcap-evidence-depth-bgp-{}-{nonce}",
        std::process::id()
    ));
    let input = root.join("capture-ordered-bgp.pcap");
    let workspace = root.join("output");
    fs::create_dir(&root).expect("create isolated test root");
    let capture = capture_ordered_bgp_session();
    let capture_sha256 = sha256::hex(&sha256::digest(&capture));
    fs::write(&input, capture).expect("write BGP capture");
    assert!(!workspace.exists(), "test workspace collision");

    let result = Command::new(env!("CARGO_BIN_EXE_pcap-depth"))
        .args([
            "analyze",
            input.to_str().expect("fixture path is UTF-8"),
            "--workspace",
            workspace.to_str().expect("workspace path is UTF-8"),
            "--format",
            "ndjson",
        ])
        .output()
        .expect("pcap-depth binary runs");
    assert!(
        result.status.success(),
        "pcap-depth failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    let events = fs::read_to_string(workspace.join("events.ndjson")).expect("events output");
    assert!(events.contains("\"protocol\":\"bgp\""));
    assert!(events.contains("\"depth_bgp\""));
    assert!(events.contains("\"depth_bgp_pipeline\""));
    assert!(events.contains("pcap-evidence.bgp.pipeline-receipt.v1"));
    assert!(events.contains("\"depth_bgp_session_summary\""));
    assert!(events.contains("pcap-evidence.bgp.session-summary.v1"));
    assert!(events.contains("event-sha256:"));
    assert!(events.contains("pcap-evidence.bgp.route-evidence.v1"));
    assert!(events.contains("\"source_kind\":\"captured\""));
    // A passive capture proves bilateral advertisements and observed ordering,
    // not endpoint negotiation truth. The UPDATE must nevertheless be decoded
    // only after both OPEN records have been observed in capture order.
    assert!(events.contains("\"negotiation_established\":false"));
    assert!(events.contains("\"basis\":\"both_four_octet_advertisements\""));
    assert!(events.contains("\"active_routes\":1"));
    assert!(events.contains("\"route_entries\":1"));
    assert!(events.contains("\"session_events\":3"));
    assert!(events.contains("\"prefix\":{\"address\":\"203.0.113.0\",\"afi\":1,\"length\":24"));
    assert!(events.contains("\"effective_as_path\":[{\"kind\":2,\"values\":[70000]}]"));
    let reverse_open = events
        .find("\"identifier\":\"192.0.2.2\"")
        .expect("opposite-direction OPEN evidence");
    let update = events
        .find("\"address\":\"203.0.113.0\"")
        .expect("UPDATE evidence");
    assert!(
        reverse_open < update,
        "BGP stateful output must preserve cross-direction capture order"
    );
    assert!(!events.contains("invalid_transport_checksum_observed"));

    let receipt = fs::read_to_string(workspace.join("receipt.json")).expect("depth receipt");
    assert!(receipt.contains("pcap-evidence.bgp.source-journal.v1"));
    assert!(receipt.contains("\"sealed\":true"));
    assert!(receipt.contains(&capture_sha256));
    let journal = workspace.join("bgp.journal");
    assert!(journal.is_file());
    assert!(!workspace.join("bgp.journal.partial").exists());

    let state = root.join("bgp-state.json");
    let replay = Command::new(env!("CARGO_BIN_EXE_pcap-depth"))
        .args([
            "bgp",
            "state",
            journal.to_str().expect("journal path is UTF-8"),
            "--output",
            state.to_str().expect("state path is UTF-8"),
        ])
        .output()
        .expect("fresh-process BGP replay runs");
    assert!(
        replay.status.success(),
        "BGP replay failed: {}",
        String::from_utf8_lossy(&replay.stderr)
    );
    let state_bytes = fs::read(&state).expect("persisted BGP state");
    let state_text = String::from_utf8(state_bytes.clone()).expect("state is UTF-8");
    assert!(state_text.contains("pcap-evidence.bgp.journal-replay.v1"));
    assert!(state_text.contains("\"fresh_process_reduction\":true"));
    assert!(state_text.contains("\"active_routes\":1"));
    assert!(state_text.contains("\"address\":\"203.0.113.0\""));
    assert!(state_text.contains("\"values\":[70000]"));

    let query = root.join("bgp-session.json");
    let queried = Command::new(env!("CARGO_BIN_EXE_pcap-depth"))
        .args([
            "bgp",
            "query",
            journal.to_str().expect("journal path is UTF-8"),
            "--session",
            "1",
            "--output",
            query.to_str().expect("query path is UTF-8"),
        ])
        .output()
        .expect("fresh-process BGP query runs");
    assert!(
        queried.status.success(),
        "BGP query failed: {}",
        String::from_utf8_lossy(&queried.stderr)
    );
    let query_text = fs::read_to_string(&query).expect("BGP session query");
    assert!(query_text.contains("pcap-evidence.bgp.session-query.v1"));
    assert!(query_text.contains("pcap-evidence.bgp.session-snapshot.v1"));
    assert!(query_text.contains("\"status\":\"active\""));

    let export = root.join("bgp-export.ndjson");
    let exported = Command::new(env!("CARGO_BIN_EXE_pcap-depth"))
        .args([
            "bgp",
            "export",
            journal.to_str().expect("journal path is UTF-8"),
            "--output",
            export.to_str().expect("export path is UTF-8"),
        ])
        .output()
        .expect("fresh-process BGP export runs");
    assert!(exported.status.success());
    let export_text = fs::read_to_string(&export).expect("BGP export");
    assert!(export_text.contains("pcap-evidence.bgp.export-header.v1"));
    assert!(export_text.contains("pcap-evidence.bgp.session-snapshot.v1"));

    let overwrite = Command::new(env!("CARGO_BIN_EXE_pcap-depth"))
        .args([
            "bgp",
            "state",
            journal.to_str().expect("journal path is UTF-8"),
            "--output",
            state.to_str().expect("state path is UTF-8"),
        ])
        .output()
        .expect("no-overwrite check runs");
    assert!(!overwrite.status.success());
    assert_eq!(
        fs::read(&state).expect("original state survives"),
        state_bytes
    );

    let limited_state = root.join("limited-state.json");
    let limited_output = Command::new(env!("CARGO_BIN_EXE_pcap-depth"))
        .args([
            "bgp",
            "state",
            journal.to_str().expect("journal path is UTF-8"),
            "--output",
            limited_state.to_str().expect("limited path is UTF-8"),
            "--max-output-bytes",
            "1",
        ])
        .output()
        .expect("output budget check runs");
    assert!(!limited_output.status.success());
    assert!(!limited_state.exists());
    assert!(root.join("limited-state.json.partial").exists());

    let limited_workspace = root.join("limited-journal");
    let limited_journal = Command::new(env!("CARGO_BIN_EXE_pcap-depth"))
        .args([
            "analyze",
            input.to_str().expect("fixture path is UTF-8"),
            "--workspace",
            limited_workspace
                .to_str()
                .expect("limited workspace path is UTF-8"),
            "--format",
            "ndjson",
            "--max-bgp-journal-bytes",
            "128",
        ])
        .output()
        .expect("journal budget check runs");
    assert!(!limited_journal.status.success());
    assert!(limited_workspace.join("bgp.journal.partial").exists());
    assert!(!limited_workspace.join("bgp.journal").exists());

    fs::remove_dir_all(root).expect("remove isolated test workspace");
}

#[test]
fn bgp_mrt_cli_persists_replays_queries_and_exports_source_bound_candidates() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "pcap-evidence-depth-mrt-{}-{nonce}",
        std::process::id()
    ));
    let input = root.join("collector.mrt");
    let workspace = root.join("imported");
    fs::create_dir(&root).expect("create isolated MRT test root");
    fs::write(&input, mrt_fixture()).expect("write MRT source");

    let imported = Command::new(env!("CARGO_BIN_EXE_pcap-depth"))
        .args([
            "bgp",
            "import-mrt",
            input.to_str().expect("MRT path is UTF-8"),
            "--workspace",
            workspace.to_str().expect("workspace path is UTF-8"),
            "--source-id",
            "collector-a",
            "--checkpoint",
            "dump-7",
        ])
        .output()
        .expect("MRT import process runs");
    assert!(
        imported.status.success(),
        "MRT import failed: {}",
        String::from_utf8_lossy(&imported.stderr)
    );
    let store = workspace.join("bgp.mrt");
    assert!(store.is_file());
    assert!(!workspace.join("bgp.mrt.partial").exists());
    let receipt = fs::read_to_string(workspace.join("receipt.json")).expect("MRT receipt");
    assert!(receipt.contains("pcap-evidence.bgp.mrt-import-receipt.v2"));
    assert!(receipt.contains("\"collector_candidates\":\"1\""));
    assert!(receipt.contains("\"source_authenticated\":false"));

    let state = root.join("mrt-state.json");
    let replayed = Command::new(env!("CARGO_BIN_EXE_pcap-depth"))
        .args([
            "bgp",
            "state",
            store.to_str().expect("store path is UTF-8"),
            "--output",
            state.to_str().expect("state path is UTF-8"),
        ])
        .output()
        .expect("MRT replay process runs");
    assert!(
        replayed.status.success(),
        "MRT replay failed: {}",
        String::from_utf8_lossy(&replayed.stderr)
    );
    let state_bytes = fs::read(&state).expect("MRT state output");
    let state_text = String::from_utf8(state_bytes.clone()).expect("MRT state is UTF-8");
    assert!(state_text.contains("pcap-evidence.bgp.mrt-replay.v4"));
    assert!(state_text.contains("\"status\":\"collector_candidate\""));
    assert!(state_text.contains("\"status\":\"missing_scope\""));
    assert!(state_text.contains("\"address\":\"203.0.113.0\""));
    assert!(state_text.contains("\"direction\":null"));
    assert!(state_text.contains("\"endpoint_state_claimed\":false"));

    let query = root.join("mrt-session.json");
    let queried = Command::new(env!("CARGO_BIN_EXE_pcap-depth"))
        .args([
            "bgp",
            "query",
            store.to_str().expect("store path is UTF-8"),
            "--session",
            "mrt:0:0",
            "--output",
            query.to_str().expect("query path is UTF-8"),
        ])
        .output()
        .expect("MRT query process runs");
    assert!(queried.status.success());
    let query_text = fs::read_to_string(&query).expect("MRT query output");
    assert!(query_text.contains("pcap-evidence.bgp.imported-session-query.v4"));
    assert!(query_text.contains("collector_candidate"));
    assert!(query_text.contains("\"observation_index\":\"0\""));
    assert!(query_text.contains("\"observations\":["));

    let export = root.join("mrt-export.ndjson");
    let exported = Command::new(env!("CARGO_BIN_EXE_pcap-depth"))
        .args([
            "bgp",
            "export",
            store.to_str().expect("store path is UTF-8"),
            "--output",
            export.to_str().expect("export path is UTF-8"),
        ])
        .output()
        .expect("MRT export process runs");
    assert!(exported.status.success());
    let export_text = fs::read_to_string(&export).expect("MRT export output");
    assert!(export_text.contains("pcap-evidence.bgp.export-header.v4"));
    assert!(export_text.contains("\"source_kind\":\"imported\""));
    assert!(export_text.contains("pcap-evidence.bgp.mrt-record-summary.v1"));
    assert!(export_text.contains("pcap-evidence.bgp.mrt-observation.v1"));
    assert!(export_text.contains("pcap-evidence.bgp.collector-candidate.v2"));
    assert_eq!(export_text.matches("\"normalized_observation\"").count(), 1);
    let export_lines: Vec<_> = export_text.lines().collect();
    assert_eq!(export_lines.len(), 6);
    assert!(export_lines[0].contains("pcap-evidence.bgp.export-header.v4"));
    assert!(export_lines[1].contains("pcap-evidence.bgp.adj-rib-in-candidate.v1"));
    assert!(export_lines[1].contains("\"entries\":[]"));
    assert!(export_lines[1].contains("\"end_of_rib\":[]"));
    assert!(export_lines[1].contains("\"endpoint_state_claimed\":false"));

    let overwrite = Command::new(env!("CARGO_BIN_EXE_pcap-depth"))
        .args([
            "bgp",
            "state",
            store.to_str().expect("store path is UTF-8"),
            "--output",
            state.to_str().expect("state path is UTF-8"),
        ])
        .output()
        .expect("MRT no-overwrite check runs");
    assert!(!overwrite.status.success());
    assert_eq!(
        fs::read(&state).expect("original MRT state survives"),
        state_bytes
    );

    let limited = root.join("limited-mrt-state.json");
    let limited_result = Command::new(env!("CARGO_BIN_EXE_pcap-depth"))
        .args([
            "bgp",
            "state",
            store.to_str().expect("store path is UTF-8"),
            "--output",
            limited.to_str().expect("limited path is UTF-8"),
            "--max-output-bytes",
            "1",
        ])
        .output()
        .expect("MRT output budget check runs");
    assert!(!limited_result.status.success());
    assert!(!limited.exists());
    assert!(root.join("limited-mrt-state.json.partial").exists());

    let corrupt = root.join("corrupt.mrt-store");
    let mut corrupt_bytes = fs::read(&store).expect("read MRT store");
    corrupt_bytes[20] ^= 1;
    fs::write(&corrupt, corrupt_bytes).expect("write corrupt MRT store");
    let corrupt_output = root.join("corrupt-state.json");
    let rejected = Command::new(env!("CARGO_BIN_EXE_pcap-depth"))
        .args([
            "bgp",
            "state",
            corrupt.to_str().expect("corrupt path is UTF-8"),
            "--output",
            corrupt_output.to_str().expect("corrupt output is UTF-8"),
        ])
        .output()
        .expect("corrupt MRT replay process runs");
    assert!(!rejected.status.success());
    assert!(!corrupt_output.exists());

    fs::remove_dir_all(root).expect("remove isolated MRT test workspace");
}
