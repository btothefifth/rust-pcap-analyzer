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
    assert!(state_text.contains("pcap-evidence.bgp.mrt-replay.v3"));
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
    assert!(query_text.contains("pcap-evidence.bgp.imported-session-query.v3"));
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
    assert!(export_text.contains("pcap-evidence.bgp.export-header.v3"));
    assert!(export_text.contains("\"source_kind\":\"imported\""));
    assert!(export_text.contains("pcap-evidence.bgp.mrt-record-summary.v1"));
    assert!(export_text.contains("pcap-evidence.bgp.mrt-observation.v1"));
    assert!(export_text.contains("pcap-evidence.bgp.collector-candidate.v2"));
    assert_eq!(export_text.matches("\"normalized_observation\"").count(), 1);

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
