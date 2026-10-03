//! Independently built small RFC 7854/8671/9736 byte witnesses.
use pcap_evidence::{
    json::Json,
    provenance::{EvidenceBytes, PacketId},
    sha256,
};
use pcap_evidence_product::deep::{
    bgp::{self, PcapMetadata, SessionState},
    bgp_bmp::{BmpBatch, BmpBody, BmpLimits, BmpSource},
    bgp_bmp_store,
    bgp_rib::RouteStatus,
    bgp_state::Observation,
    Limits,
};
use std::{
    fs, io,
    path::PathBuf,
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
};
static SERIAL: AtomicU64 = AtomicU64::new(0);
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        for _ in 0..1024 {
            let path = std::env::temp_dir().join(format!(
                "pcap-bmp-{}-{}",
                std::process::id(),
                SERIAL.fetch_add(1, Ordering::Relaxed)
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Self(path),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(e) => panic!("scratch: {e}"),
            }
        }
        panic!("scratch namespace exhausted")
    }
    fn file(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn source(label: &str) -> BmpSource {
    BmpSource {
        source_id: label.into(),
        checkpoint_id: "checkpoint-a".into(),
    }
}
fn message(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![3];
    out.extend_from_slice(&((6 + body.len()) as u32).to_be_bytes());
    out.push(kind);
    out.extend_from_slice(body);
    out
}
fn bgp(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![255; 16];
    out.extend_from_slice(&((19 + body.len()) as u16).to_be_bytes());
    out.push(kind);
    out.extend_from_slice(body);
    out
}
fn open(asn: u16, id: u8) -> Vec<u8> {
    let mut body = vec![4];
    body.extend_from_slice(&asn.to_be_bytes());
    body.extend_from_slice(&90u16.to_be_bytes());
    body.extend_from_slice(&[10, 0, 0, id]);
    body.push(0);
    bgp(1, &body)
}
fn peer(peer: u8, flags: u8, seconds: u32) -> Vec<u8> {
    let mut out = vec![0, flags];
    out.extend_from_slice(&[0; 8]);
    out.extend_from_slice(&[0; 12]);
    out.extend_from_slice(&[192, 0, 2, peer]);
    out.extend_from_slice(&65001u32.to_be_bytes());
    out.extend_from_slice(&[10, 0, 0, peer]);
    out.extend_from_slice(&seconds.to_be_bytes());
    out.extend_from_slice(&7u32.to_be_bytes());
    assert_eq!(out.len(), 42);
    out
}
fn up(peer_id: u8) -> Vec<u8> {
    let mut body = peer(peer_id, 0, 100);
    body.extend_from_slice(&[0; 12]);
    body.extend_from_slice(&[192, 0, 2, 254]);
    body.extend_from_slice(&179u16.to_be_bytes());
    body.extend_from_slice(&40000u16.to_be_bytes());
    body.extend_from_slice(&open(65000, 254));
    body.extend_from_slice(&open(65001, peer_id));
    message(3, &body)
}
fn update(width: u8, announce: bool) -> Vec<u8> {
    if !announce {
        return bgp(2, &[0, 4, 24, 198, 51, 100, 0, 0]);
    }
    let mut attrs = vec![0x40, 1, 1, 0, 0x40, 2, 2 + width, 2, 1];
    if width == 2 {
        attrs.extend_from_slice(&65001u16.to_be_bytes());
    } else {
        attrs.extend_from_slice(&65001u32.to_be_bytes());
    }
    attrs.extend_from_slice(&[0x40, 3, 4, 192, 0, 2, 1]);
    let mut body = vec![0, 0];
    body.extend_from_slice(&(attrs.len() as u16).to_be_bytes());
    body.extend_from_slice(&attrs);
    body.extend_from_slice(&[24, 198, 51, 100]);
    bgp(2, &body)
}
fn captured_update(message: &[u8]) -> Json {
    let mut session = SessionState::default();
    let decode = |bytes: &[u8], frame: u64, direction: u8, session: &mut SessionState| {
        bgp::decode_pcap(
            &EvidenceBytes::from_packet(
                bytes,
                PacketId {
                    capture: sha256::digest(b"bmp-captured-parity"),
                    frame,
                    record_offset: frame * 128,
                },
                54,
            ),
            PcapMetadata {
                source_id: "capture-parity".into(),
                record_id: format!("frame:{frame}"),
                observed_at_ns: Some(frame as i64),
                session: Some(7),
                direction: Some(direction),
                peer: Some("192.0.2.1:179".into()),
                local: Some("192.0.2.254:40000".into()),
            },
            session,
            &Limits::default(),
        )
        .unwrap()
    };
    decode(&open(65000, 254), 1, 1, &mut session);
    decode(&open(65001, 1), 2, 0, &mut session);
    decode(message, 3, 0, &mut session)
}
fn rm(peer_id: u8, flags: u8, seconds: u32, announcement: bool) -> Vec<u8> {
    let mut body = peer(peer_id, flags, seconds);
    body.extend_from_slice(&update(if flags & 0x20 != 0 { 2 } else { 4 }, announcement));
    message(0, &body)
}
fn down(peer_id: u8, reason: u8) -> Vec<u8> {
    let mut body = peer(peer_id, 0, 10);
    body.push(reason);
    message(2, &body)
}
fn append(parts: &[Vec<u8>]) -> Vec<u8> {
    parts.iter().flatten().copied().collect()
}
fn store(bytes: &[u8]) -> (Scratch, bgp_bmp_store::BmpReplayArchive) {
    let scratch = Scratch::new();
    let archive = bgp_bmp_store::create(
        &scratch.file("bgp.bmp"),
        bytes,
        source("collector-a"),
        1_000_000,
        BmpLimits::default(),
        Limits::default(),
    )
    .unwrap();
    (scratch, archive)
}
fn field<'a>(value: &'a Json, key: &str) -> &'a Json {
    let Json::Object(items) = value else {
        panic!("object required")
    };
    &items.iter().find(|(name, _)| *name == key).unwrap().1
}

#[test]
fn common_and_peer_offsets_match_independent_byte_arithmetic() {
    let bytes = up(1);
    assert_eq!(bytes.len(), 126);
    assert_eq!(&bytes[1..5], &126u32.to_be_bytes());
    let batch = BmpBatch::parse(&bytes, source("collector-a"), &BmpLimits::default()).unwrap();
    let record = &batch.records[0];
    assert_eq!(record.offset, 0);
    assert_eq!(record.length, 126);
    let BmpBody::PeerUp {
        sent_open,
        received_open,
        ..
    } = &record.body
    else {
        panic!("peer up")
    };
    assert_eq!((sent_open.start, sent_open.end), (68, 97));
    assert_eq!((received_open.start, received_open.end), (97, 126));
    assert_eq!(batch.range_bytes(sent_open).unwrap(), open(65000, 254));
    assert_eq!(
        sent_open.sha256.as_deref(),
        Some(sha256::hex(&sha256::digest(&bytes[68..97])).as_str())
    );
}
#[test]
fn original_declared_frame_truncates_at_every_byte_boundary() {
    let bytes = up(1);
    for end in 0..bytes.len() {
        assert!(
            BmpBatch::parse(&bytes[..end], source("collector-a"), &BmpLimits::default()).is_err(),
            "cut={end}"
        );
    }
    let mut trailing = bytes.clone();
    trailing.push(3);
    assert!(BmpBatch::parse(&trailing, source("collector-a"), &BmpLimits::default()).is_err());
    let mut invalid = bytes.clone();
    invalid[0] = 2;
    assert!(BmpBatch::parse(&invalid, source("collector-a"), &BmpLimits::default()).is_err());
    invalid = bytes;
    invalid[1..5].copy_from_slice(&5u32.to_be_bytes());
    assert!(BmpBatch::parse(&invalid, source("collector-a"), &BmpLimits::default()).is_err());
}
#[test]
fn malformed_complete_known_record_retains_exact_range_and_neighbors() {
    let mut malformed = up(1);
    malformed[68] = 0;
    let unknown = message(251, &[8, 9]);
    let bytes = append(&[unknown.clone(), malformed.clone(), up(2)]);
    let batch = BmpBatch::parse(&bytes, source("collector-a"), &BmpLimits::default()).unwrap();
    assert_eq!(batch.records.len(), 3);
    assert!(matches!(
        batch.records[0].body,
        BmpBody::Opaque {
            reason: "unknown_message_type",
            ..
        }
    ));
    assert!(matches!(
        batch.records[1].body,
        BmpBody::Opaque {
            reason: "malformed_known_record",
            ..
        }
    ));
    assert_eq!(
        batch
            .range_bytes(&batch.record_range(&batch.records[1]))
            .unwrap(),
        malformed
    );
    assert!(matches!(batch.records[2].body, BmpBody::PeerUp { .. }));
    let (_, archive) = store(&bytes);
    assert_eq!(archive.state.observations().len(), 0);
    assert_eq!(archive.bmp_events.len(), 3);
}
#[test]
fn exact_framing_charges_and_one_unit_below_are_atomic() {
    let bytes = up(1);
    let defaults = BmpLimits::default();
    let batch = BmpBatch::parse(&bytes, source("collector-a"), &defaults).unwrap();
    for cap in ["input", "record", "retained", "work", "output"] {
        let mut limits = defaults.clone();
        match cap {
            "input" => {
                limits.input_bytes = bytes.len();
                limits.record_bytes = bytes.len();
            }
            "record" => limits.record_bytes = bytes.len(),
            "retained" => limits.retained_bytes = batch.retained_charge,
            "work" => limits.work = batch.work_charge,
            _ => limits.output_bytes = batch.output_charge,
        }
        assert!(
            BmpBatch::parse(&bytes, source("collector-a"), &limits).is_ok(),
            "exact {cap}"
        );
        match cap {
            "input" => {
                limits.input_bytes -= 1;
                limits.record_bytes -= 1;
            }
            "record" => limits.record_bytes -= 1,
            "retained" => limits.retained_bytes -= 1,
            "work" => limits.work -= 1,
            _ => limits.output_bytes -= 1,
        }
        assert!(
            BmpBatch::parse(&bytes, source("collector-a"), &limits).is_err(),
            "one below {cap}"
        );
    }
    let bytes = append(&[up(1), up(2)]);
    let mut limits = defaults.clone();
    limits.peers = 1;
    assert!(BmpBatch::parse(&bytes, source("collector-a"), &limits).is_err());
    limits.peers = 2;
    limits.records = 1;
    assert!(BmpBatch::parse(&bytes, source("collector-a"), &limits).is_err());
    limits.records = 2;
    assert!(BmpBatch::parse(&bytes, source("collector-a"), &limits).is_ok());
}
#[test]
fn peer_up_namespace_and_repeated_tlv_order_are_preserved() {
    let mut up_body = up(1)[6..].to_vec();
    up_body.extend_from_slice(&[
        0, 0, 0, 1, b'a', 0, 0, 0, 1, b'b', 0, 3, 0, 3, b'v', b'r', b'f',
    ]);
    let batch = BmpBatch::parse(
        &message(3, &up_body),
        source("collector-a"),
        &BmpLimits::default(),
    )
    .unwrap();
    let BmpBody::PeerUp { information, .. } = &batch.records[0].body else {
        panic!("peer up")
    };
    assert_eq!(
        information.iter().map(|t| t.kind).collect::<Vec<_>>(),
        vec![0, 0, 3]
    );
    assert_eq!(batch.range_bytes(&information[0].value).unwrap(), b"a");
    assert_eq!(batch.range_bytes(&information[1].value).unwrap(), b"b");
    let limits = BmpLimits {
        tlvs: 2,
        ..BmpLimits::default()
    };
    assert!(BmpBatch::parse(&message(3, &up_body), source("collector-a"), &limits).is_err());
    up_body.extend_from_slice(&[0, 4, 0, 2, 255, 255]);
    let batch = BmpBatch::parse(
        &message(3, &up_body),
        source("collector-a"),
        &BmpLimits::default(),
    )
    .unwrap();
    assert!(matches!(
        batch.records[0].body,
        BmpBody::Opaque {
            reason: "malformed_known_record",
            ..
        }
    ));
}
#[test]
fn unsupported_extensions_do_not_enter_candidate_state() {
    let outbound = rm(1, 0x10, 99, true);
    let mut loc = rm(1, 0, 98, true);
    loc[6] = 3;
    let mut unknownpeer = rm(1, 0, 98, true);
    unknownpeer[6] = 250;
    let bytes = append(&[
        up(1),
        message(1, &[]),
        outbound,
        loc,
        unknownpeer,
        message(6, &[1]),
        down(1, 6),
        message(252, &[7]),
        rm(1, 0, 1, true),
    ]);
    let (_, archive) = store(&bytes);
    assert_eq!(archive.state.observations().len(), 1);
    assert_eq!(archive.bmp_rib.entries().len(), 1);
    assert!(archive
        .bmp_rib
        .entries()
        .values()
        .all(|e| e.status == RouteStatus::Active));
}
#[test]
fn reported_clock_regression_never_reorders_announce_and_withdraw() {
    let bytes = append(&[up(1), rm(1, 0x20, 200, true), rm(1, 0x20, 1, false)]);
    let (_, archive) = store(&bytes);
    assert_eq!(archive.state.observations().len(), 2);
    assert!(archive
        .bmp_rib
        .entries()
        .values()
        .all(|e| e.status == RouteStatus::Withdrawn));
    assert_eq!(
        archive.state.observations()[0].source().observed_at_ns,
        Some(200_000_007_000)
    );
    assert_eq!(
        archive.state.observations()[1].source().observed_at_ns,
        Some(1_000_007_000)
    );
}
#[test]
fn a_flag_rewrites_wire_format_without_inventing_negotiation() {
    // Both reported OPENs lack AS4 capability; BMP still legitimately reformats AS_PATH to four octets.
    let (_, archive) = store(&append(&[up(1), rm(1, 0, 1, true)]));
    assert_eq!(archive.bmp_rib.entries().len(), 1);
    let normalized = archive.state.observations()[0].normalized();
    assert_eq!(
        field(
            field(normalized, "message_detail"),
            "negotiation_established"
        ),
        &Json::Bool(false)
    );
    assert!(archive
        .bmp_rib
        .entries()
        .values()
        .all(|e| e.status == RouteStatus::Active));
    let captured = captured_update(&update(2, true));
    let captured = Observation::from_normalized(&captured, None, &Limits::default()).unwrap();
    let imported_identity = archive.state.observations()[0].routes()[0].semantic_identity();
    let captured_identity = captured.routes()[0].semantic_identity();
    assert_eq!(
        field(imported_identity, "completeness"),
        &Json::String("complete".into())
    );
    assert_eq!(
        field(imported_identity, "fingerprint_sha256"),
        field(captured_identity, "fingerprint_sha256")
    );
    assert_ne!(
        archive.state.observations()[0].source().source_id,
        captured.source().source_id
    );
    assert_eq!(field(normalized, "evidence"), &Json::Null);
    // An unsupported optional transitive attribute cannot acquire a complete identity.
    let mut unsupported = update(4, true);
    let attrs = usize::from(u16::from_be_bytes([unsupported[21], unsupported[22]]));
    unsupported.splice(23 + attrs..23 + attrs, [0xC0, 99, 1, 7]);
    unsupported[21..23].copy_from_slice(&((attrs + 4) as u16).to_be_bytes());
    let length = unsupported.len() as u16;
    unsupported[16..18].copy_from_slice(&length.to_be_bytes());
    let mut body = peer(1, 0, 2);
    body.extend_from_slice(&unsupported);
    let (_, unsupported) = store(&append(&[up(1), message(0, &body)]));
    let identity = unsupported.state.observations()[0].routes()[0].semantic_identity();
    assert_eq!(
        field(identity, "completeness"),
        &Json::String("incomplete".into())
    );
    assert_eq!(field(identity, "fingerprint_sha256"), &Json::Null);
    let mut malformed = rm(1, 0, 1, true);
    malformed[48] = 0; // Exact outer framing, invalid embedded BGP marker.
    let (_, malformed) = store(&append(&[up(1), malformed]));
    assert!(malformed.state.observations().is_empty());
    assert!(malformed.bmp_rib.entries().is_empty());
    let (_, without) = store(&rm(1, 0, 1, true));
    assert!(without.state.observations().is_empty());
}
#[test]
fn policy_stream_peer_distinguisher_and_source_partitions_never_collapse() {
    let mut vrf_up = up(1);
    vrf_up[6] = 1;
    vrf_up[8..16].copy_from_slice(&1u64.to_be_bytes());
    let mut vrf_rm = rm(1, 0, 3, true);
    vrf_rm[6] = 1;
    vrf_rm[8..16].copy_from_slice(&1u64.to_be_bytes());
    let bytes = append(&[
        up(1),
        rm(1, 0, 5, true),
        rm(1, 0x40, 4, true),
        vrf_up,
        vrf_rm,
    ]);
    let (scratch, archive) = store(&bytes);
    assert_eq!(archive.bmp_rib.entries().len(), 3);
    let other = bgp_bmp_store::create(
        &scratch.file("other.bmp"),
        &bytes,
        source("collector-b"),
        1_000_000,
        BmpLimits::default(),
        Limits::default(),
    )
    .unwrap();
    let mut joined =
        pcap_evidence_product::deep::bgp_state::CandidateState::new(Limits::default()).unwrap();
    joined
        .apply_batch(
            archive
                .state
                .observations()
                .iter()
                .cloned()
                .chain(other.state.observations().iter().cloned()),
        )
        .unwrap();
    assert_eq!(joined.routes().len(), 6);
    let ids = archive
        .state
        .observations()
        .iter()
        .map(|o| o.source().session.clone().unwrap())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(ids.len(), 3);
}
#[test]
fn peer_down_closes_only_its_peer_and_reason_five_reports_coverage() {
    let bytes = append(&[
        up(1),
        up(2),
        rm(1, 0, 10, true),
        rm(1, 0x40, 9, true),
        rm(2, 0, 8, true),
        down(1, 5),
    ]);
    let (_, archive) = store(&bytes);
    let mut active = 0;
    let mut superseded = 0;
    for entry in archive.bmp_rib.entries().values() {
        match entry.status {
            RouteStatus::Active => active += 1,
            RouteStatus::Superseded => superseded += 1,
            _ => panic!("unexpected status"),
        }
    }
    assert_eq!((active, superseded), (1, 2));
    let last = archive.bmp_events.last().unwrap();
    assert_eq!(
        field(last, "status"),
        &Json::String("reported_coverage_close".into())
    );
    assert_eq!(
        field(field(last, "detail"), "reported_bgp_down"),
        &Json::Bool(false)
    );
}
#[test]
fn malformed_peer_context_gaps_old_routes_until_valid_peer_up() {
    let mut malformed = up(1);
    malformed[68] = 0;
    let bytes = append(&[
        up(1),
        up(2),
        rm(1, 0, 10, true),
        rm(2, 0, 10, true),
        malformed,
        rm(1, 0, 9, true),
    ]);
    let (_, archive) = store(&bytes);
    assert_eq!(archive.state.observations().len(), 2);
    let entries = archive.bmp_rib.entries().values().collect::<Vec<_>>();
    assert_eq!(
        entries
            .iter()
            .filter(|e| e.status == RouteStatus::Unresolved)
            .count(),
        1
    );
    assert_eq!(
        entries
            .iter()
            .filter(|e| e.status == RouteStatus::Active)
            .count(),
        1
    );
    let mut repaired = bytes;
    repaired.extend_from_slice(&up(1));
    repaired.extend_from_slice(&rm(1, 0, 8, true));
    let (_, archive) = store(&repaired);
    assert_eq!(
        archive
            .bmp_rib
            .entries()
            .values()
            .filter(|e| e.status == RouteStatus::Active)
            .count(),
        2
    );
}
#[test]
fn missing_peer_identity_marks_monitor_uncertainty_without_fabricated_reset() {
    let malformed = message(3, &[0; 4]);
    let bytes = append(&[
        up(1),
        up(2),
        rm(1, 0, 10, true),
        rm(2, 0, 10, true),
        malformed,
        rm(1, 0, 9, true),
    ]);
    let (_, archive) = store(&bytes);
    assert_eq!(archive.state.observations().len(), 2);
    assert!(archive
        .bmp_rib
        .entries()
        .values()
        .all(|e| e.status == RouteStatus::Unresolved));
    assert_eq!(
        field(
            archive.bmp_events.last().unwrap(),
            "monitor_coverage_uncertain"
        ),
        &Json::Bool(true)
    );
    assert!(archive.bmp_rib.events().iter().all(|event| !matches!(
        event.kind,
        pcap_evidence_product::deep::bgp_rib::RibEventKind::Reset { .. }
    )));
}
#[test]
fn sealed_restart_corruption_no_overwrite_and_exact_output_budget() {
    let bytes = append(&[up(1), rm(1, 0, 5, true), down(1, 4)]);
    let (scratch, archive) = store(&bytes);
    let path = scratch.file("bgp.bmp");
    let replay =
        bgp_bmp_store::replay(&path, 1_000_000, BmpLimits::default(), Limits::default()).unwrap();
    assert_eq!(archive.json(), replay.json());
    let old = fs::read(&path).unwrap();
    assert!(bgp_bmp_store::create(
        &path,
        &bytes,
        source("new"),
        1_000_000,
        BmpLimits::default(),
        Limits::default()
    )
    .is_err());
    assert_eq!(old, fs::read(&path).unwrap());
    let mut corrupted = old.clone();
    let middle = corrupted.len() / 2;
    corrupted[middle] ^= 1;
    fs::write(scratch.file("bad.bmp"), corrupted).unwrap();
    assert!(bgp_bmp_store::replay(
        &scratch.file("bad.bmp"),
        1_000_000,
        BmpLimits::default(),
        Limits::default()
    )
    .is_err());
    let output = archive.export_ndjson(1_000_000).unwrap();
    assert_eq!(archive.export_ndjson(output.len()).unwrap(), output);
    let mut writer = Vec::new();
    assert!(archive
        .write_export_ndjson(&mut writer, output.len() - 1)
        .is_err());
    assert!(writer.is_empty());
    let rejected = scratch.file("rejected.bmp");
    let mut short = bytes;
    short.pop();
    assert!(bgp_bmp_store::create(
        &rejected,
        &short,
        source("bad"),
        1_000_000,
        BmpLimits::default(),
        Limits::default()
    )
    .is_err());
    assert!(!rejected.exists());
}
#[test]
fn cli_import_and_fresh_state_query_export_use_normal_bgp_verbs() {
    let scratch = Scratch::new();
    let input = scratch.file("input.bmp");
    fs::write(&input, append(&[up(1), rm(1, 0, 5, true)])).unwrap();
    let workspace = scratch.file("run");
    let status = Command::new(env!("CARGO_BIN_EXE_pcap-depth"))
        .args(["bgp", "import-bmp"])
        .arg(&input)
        .arg("--workspace")
        .arg(&workspace)
        .args([
            "--source-id",
            "fixture",
            "--checkpoint",
            "bmp-test",
            "--max-bmp-bytes",
            "65536",
            "--max-journal-bytes",
            "1000000",
        ])
        .output()
        .unwrap();
    assert!(
        status.status.success(),
        "{}",
        String::from_utf8_lossy(&status.stderr)
    );
    let path = workspace.join("bgp.bmp");
    assert!(path.is_file());
    for verb in ["state", "query", "export"] {
        let output = scratch.file(&format!("{verb}.json"));
        let mut command = Command::new(env!("CARGO_BIN_EXE_pcap-depth"));
        command
            .args(["bgp", verb])
            .arg(&path)
            .arg("--output")
            .arg(&output);
        if verb == "query" {
            command.args(["--session", "bmp:0:pre"]);
        }
        let result = command.output().unwrap();
        assert!(
            result.status.success(),
            "{verb}: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        let text = fs::read_to_string(&output).unwrap();
        assert!(text.contains("bmp"));
        assert!(text.contains("198.51.100.0") || text.contains("198.51.100"));
    }
}

#[test]
fn known_structural_cuts_quarantine_without_losing_original_bytes() {
    let complete = up(1);
    // Keep common framing valid while cutting every per-peer, local-session,
    // first OPEN, and second OPEN byte. Empty optional TLVs is a valid boundary.
    for end in 6..complete.len() {
        let mut cut = complete[..end].to_vec();
        cut[1..5].copy_from_slice(&(end as u32).to_be_bytes());
        let batch = BmpBatch::parse(&cut, source("collector-a"), &BmpLimits::default()).unwrap();
        assert!(
            matches!(
                batch.records[0].body,
                BmpBody::Opaque {
                    reason: "malformed_known_record",
                    ..
                }
            ),
            "cut={end}"
        );
        assert_eq!(
            batch
                .range_bytes(&batch.record_range(&batch.records[0]))
                .unwrap(),
            cut
        );
    }
    // One unit beyond the trustworthy length remains fatal outer framing.
    let mut invalid = complete;
    invalid[1..5].copy_from_slice(&127u32.to_be_bytes());
    assert!(BmpBatch::parse(&invalid, source("collector-a"), &BmpLimits::default()).is_err());
}

#[test]
fn eor_zero_clock_and_monitor_termination_have_explicit_semantics() {
    let mut eor_body = peer(1, 0, 0);
    eor_body[38..42].copy_from_slice(&0u32.to_be_bytes());
    eor_body.extend_from_slice(&bgp(2, &[0, 0, 0, 0]));
    let bytes = append(&[
        up(1),
        rm(1, 0, 5, true),
        message(0, &eor_body),
        message(5, &[0, 1, 0, 2, 0, 1]),
        rm(1, 0, 4, true),
    ]);
    let (_, archive) = store(&bytes);
    assert_eq!(archive.bmp_rib.eors().len(), 1);
    assert_eq!(
        archive.bmp_rib.eors()[0].record_id,
        archive.state.observations()[1].source().record_id
    );
    assert_eq!(
        archive.state.observations()[1].source().observed_at_ns,
        None
    );
    assert!(archive
        .bmp_rib
        .entries()
        .values()
        .all(|entry| entry.status == RouteStatus::Superseded));
    assert_eq!(
        field(archive.bmp_events.last().unwrap(), "status"),
        &Json::String("quarantined_route_monitoring".into())
    );
}

#[test]
fn initiation_metadata_and_reserved_peer_bits_do_not_reset_context() {
    let mut initiation = vec![0, 1, 0, 1, b'd', 0, 2, 0, 1, b'n'];
    initiation.extend_from_slice(&[0, 0, 0, 1, b'a', 0, 0, 0, 1, b'b']);
    let bytes = append(&[
        up(1),
        rm(1, 0, 5, true),
        message(4, &initiation),
        rm(1, 0x0F, 4, false),
    ]);
    let (_, archive) = store(&bytes);
    assert!(archive
        .bmp_rib
        .entries()
        .values()
        .all(|entry| entry.status == RouteStatus::Withdrawn));
    assert!(archive
        .state
        .observations()
        .iter()
        .all(|observation| observation.import_context().unwrap().generation == 0));
    let batch = BmpBatch::parse(
        &message(4, &[0, 3, 0, 1, b'x', 0, 4, 0, 1, b'y']),
        source("collector-a"),
        &BmpLimits::default(),
    )
    .unwrap();
    assert!(matches!(
        batch.records[0].body,
        BmpBody::Opaque {
            reason: "malformed_known_record",
            ..
        }
    ));
}

#[test]
fn borrowed_output_matches_convenience_and_preflights_every_writer() {
    let (_, archive) = store(&append(&[up(1), rm(1, 0, 5, true)]));
    assert_eq!(
        field(archive.state.observations()[0].normalized(), "source_kind"),
        &Json::String("imported".into())
    );
    assert_eq!(
        field(archive.state.observations()[0].normalized(), "message_type"),
        &Json::Number(0)
    );
    let expected = archive.json().encode();
    assert_eq!(
        archive.encoded_len_bounded(expected.len()).unwrap(),
        expected.len()
    );
    assert_eq!(archive.encode_json(expected.len()).unwrap(), expected);
    let mut bytes = Vec::new();
    archive.write_json(&mut bytes, expected.len()).unwrap();
    assert_eq!(bytes, expected.as_bytes());
    bytes.clear();
    assert!(archive.write_json(&mut bytes, expected.len() - 1).is_err());
    assert!(bytes.is_empty());
    archive
        .write_bounded_line(&mut bytes, expected.len() + 1)
        .unwrap();
    assert_eq!(bytes, format!("{expected}\n").as_bytes());
    bytes.clear();
    assert!(archive
        .write_bounded_line(&mut bytes, expected.len())
        .is_err());
    assert!(bytes.is_empty());
    let expected_query = archive.session_query_json("bmp:0:pre").unwrap().encode();
    assert_eq!(
        archive
            .encode_session_query_bounded("bmp:0:pre", expected_query.len())
            .unwrap(),
        expected_query
    );
    archive
        .write_session_query_bounded_line("bmp:0:pre", &mut bytes, expected_query.len() + 1)
        .unwrap();
    assert_eq!(bytes, format!("{expected_query}\n").as_bytes());
    bytes.clear();
    assert!(archive
        .write_session_query_bounded_line("bmp:0:pre", &mut bytes, expected_query.len())
        .is_err());
    assert!(bytes.is_empty());
    let expected_rib = archive.bmp_rib_json(None).encode();
    archive
        .write_bmp_rib_bounded_line(None, &mut bytes, expected_rib.len() + 1)
        .unwrap();
    assert_eq!(bytes, format!("{expected_rib}\n").as_bytes());
    bytes.clear();
    assert!(archive
        .write_bmp_rib_bounded_line(None, &mut bytes, expected_rib.len())
        .is_err());
    assert!(bytes.is_empty());
    let export = archive.export_ndjson(1_000_000).unwrap();
    archive
        .write_export_ndjson(&mut bytes, export.len())
        .unwrap();
    assert_eq!(bytes, export.as_bytes());
    bytes.clear();
    assert!(archive
        .write_export_ndjson(&mut bytes, export.len() - 1)
        .is_err());
    assert!(bytes.is_empty());
    assert_eq!(
        export.lines().last().unwrap(),
        Json::object([
            ("schema", "pcap-evidence.bgp.bmp-rib-export.v1".into()),
            ("bmp_rib", archive.bmp_rib_json(None)),
        ])
        .encode()
    );
    let scratch = Scratch::new();
    let rejected = scratch.file("rejected.bmp");
    let limits = Limits {
        output_bytes: 1,
        ..Limits::default()
    };
    assert!(bgp_bmp_store::create(
        &rejected,
        &up(1),
        source("a"),
        1_000_000,
        BmpLimits::default(),
        limits
    )
    .is_err());
    assert!(!rejected.exists());
}

#[test]
fn malformed_termination_requires_reason_gaps_context_and_valid_up_recovers() {
    let malformed = [
        vec![],                                   // Required Reason absent.
        vec![0, 0, 0, 1, b'x'],                   // String does not replace Reason.
        vec![0, 1, 0, 1, 0],                      // Reason value must be exactly two octets.
        vec![0, 1, 0, 2, 0, 0, 0, 1, 0, 2, 0, 1], // Contradictory reasons.
    ];
    for body in malformed {
        let bytes = append(&[
            up(1),
            rm(1, 0, 5, true),
            message(5, &body),
            rm(1, 0, 4, true),
        ]);
        let (_, archive) = store(&bytes);
        assert!(matches!(
            archive.batch().records[2].body,
            BmpBody::Opaque {
                reason: "malformed_known_record",
                ..
            }
        ));
        assert_eq!(
            archive
                .batch()
                .range_bytes(&archive.batch().record_range(&archive.batch().records[2]))
                .unwrap(),
            message(5, &body)
        );
        assert!(archive
            .bmp_rib
            .entries()
            .values()
            .all(|entry| entry.status == RouteStatus::Unresolved));
        assert_eq!(
            field(&archive.bmp_events[2], "monitor_coverage_uncertain"),
            &Json::Bool(true)
        );
        assert_eq!(
            field(&archive.bmp_events[3], "status"),
            &Json::String("quarantined_route_monitoring".into())
        );
        assert!(archive
            .state
            .observations()
            .iter()
            .all(|o| o.import_boundary().is_none()));
        let recovered = append(&[bytes, up(1), rm(1, 0, 3, true)]);
        let (_, archive) = store(&recovered);
        assert_eq!(
            field(archive.bmp_events.last().unwrap(), "status"),
            &Json::String("decoded_route_monitoring_candidate".into())
        );
        assert!(archive
            .bmp_rib
            .entries()
            .values()
            .any(|entry| entry.key.scope.generation == 1 && entry.status == RouteStatus::Active));
    }
    // RFC 7854 Reason = 1 (unspecified), with the required two-byte value.
    let (_, valid) = store(&append(&[
        up(1),
        rm(1, 0, 5, true),
        message(5, &[0, 1, 0, 2, 0, 1]),
        rm(1, 0, 4, true),
    ]));
    assert_eq!(
        field(&valid.bmp_events[2], "status"),
        &Json::String("reported_monitor_termination".into())
    );
    assert!(valid
        .bmp_rib
        .entries()
        .values()
        .all(|entry| entry.status == RouteStatus::Superseded));
    // Identical repeated reason values are unambiguous; unknown values stay opaque.
    let repeated = message(5, &[0, 1, 0, 2, 0, 1, 0, 1, 0, 2, 0, 1]);
    assert!(matches!(
        BmpBatch::parse(&repeated, source("a"), &BmpLimits::default())
            .unwrap()
            .records[0]
            .body,
        BmpBody::Termination { .. }
    ));
    let (_, unknown) = store(&append(&[
        up(1),
        rm(1, 0, 5, true),
        message(5, &[0, 1, 0, 2, 0, 5]),
        rm(1, 0, 4, false),
    ]));
    assert!(matches!(
        unknown.batch().records[2].body,
        BmpBody::Opaque {
            reason: "unsupported_termination_reason",
            ..
        }
    ));
    assert!(unknown
        .bmp_rib
        .entries()
        .values()
        .all(|entry| entry.status == RouteStatus::Unresolved));
    assert_eq!(
        field(&unknown.bmp_events[2], "monitor_coverage_uncertain"),
        &Json::Bool(true)
    );
    assert_eq!(
        field(&unknown.bmp_events[3], "status"),
        &Json::String("quarantined_route_monitoring".into())
    );
    assert!(unknown
        .state
        .observations()
        .iter()
        .all(|o| o.import_boundary().is_none()));
    let (_, recovered) = store(&append(&[
        up(1),
        rm(1, 0, 5, true),
        message(5, &[0, 1, 0, 2, 0, 5]),
        rm(1, 0, 4, false),
        up(1),
        rm(1, 0, 3, true),
        rm(1, 0, 2, false),
    ]));
    assert_eq!(
        field(recovered.bmp_events.last().unwrap(), "status"),
        &Json::String("decoded_route_monitoring_candidate".into())
    );
    assert!(recovered
        .bmp_rib
        .entries()
        .values()
        .any(|entry| entry.key.scope.generation == 1 && entry.status == RouteStatus::Withdrawn));
}

#[test]
fn final_combined_retention_exact_floor_and_one_below_are_atomic() {
    let bytes = up(1);
    let (scratch, archive) = store(&bytes);
    let event_bytes = archive
        .bmp_events
        .iter()
        .map(|e| e.encode().len())
        .sum::<usize>();
    let exact = archive.state.retained_bytes()
        + archive.bmp_rib.retained_bytes()
        + archive.batch().retained_charge
        + event_bytes
        + archive.receipt.json().encode().len();
    assert_eq!(archive.retained_charge().unwrap(), exact);
    // Original defect: separate event/state admission passed at this cap,
    // although the archive retains both representations concurrently.
    let old_piecemeal_cap = archive.batch().retained_charge
        + archive.bmp_rib.retained_bytes()
        + event_bytes.max(archive.state.retained_bytes());
    assert!(old_piecemeal_cap < exact);
    let witness_path = scratch.file("piecemeal.bmp");
    assert!(bgp_bmp_store::create(
        &witness_path,
        &bytes,
        source("collector-a"),
        1_000_000,
        BmpLimits::default(),
        Limits {
            retained_bytes: old_piecemeal_cap,
            ..Limits::default()
        }
    )
    .is_err());
    assert!(!witness_path.exists());
    let exact_limits = Limits {
        retained_bytes: exact,
        ..Limits::default()
    };
    let path = scratch.file("exact.bmp");
    let accepted = bgp_bmp_store::create(
        &path,
        &bytes,
        source("collector-a"),
        1_000_000,
        BmpLimits::default(),
        exact_limits.clone(),
    )
    .unwrap();
    assert_eq!(accepted.retained_charge().unwrap(), exact);
    let replayed =
        bgp_bmp_store::replay(&path, 1_000_000, BmpLimits::default(), exact_limits).unwrap();
    assert_eq!(replayed.retained_charge().unwrap(), exact);
    let one_below = Limits {
        retained_bytes: exact - 1,
        ..Limits::default()
    };
    let rejected = scratch.file("below.bmp");
    assert!(bgp_bmp_store::create(
        &rejected,
        &bytes,
        source("collector-a"),
        1_000_000,
        BmpLimits::default(),
        one_below.clone()
    )
    .is_err());
    assert!(!rejected.exists());
    assert!(bgp_bmp_store::replay(&path, 1_000_000, BmpLimits::default(), one_below).is_err());
    let exact_work = archive.batch().work_charge
        + event_bytes
        + archive.bmp_rib.accounted_work()
        + archive.encoded_len_bounded(1_000_000).unwrap();
    let work_path = scratch.file("work-exact.bmp");
    bgp_bmp_store::create(
        &work_path,
        &bytes,
        source("collector-a"),
        1_000_000,
        BmpLimits::default(),
        Limits {
            work: exact_work,
            ..Limits::default()
        },
    )
    .unwrap();
    let work_below = scratch.file("work-below.bmp");
    assert!(bgp_bmp_store::create(
        &work_below,
        &bytes,
        source("collector-a"),
        1_000_000,
        BmpLimits::default(),
        Limits {
            work: exact_work - 1,
            ..Limits::default()
        }
    )
    .is_err());
    assert!(!work_below.exists());
}
