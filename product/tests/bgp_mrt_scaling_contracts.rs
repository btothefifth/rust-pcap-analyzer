//! Independent wire fixtures for the MRT admission/projection changes.
//! Synthetic local contracts, not corpus, endpoint, or throughput qualification.
use pcap_evidence::{json::Json, sha256};
use pcap_evidence_product::deep::{
    bgp_mrt::{Bgp4mpPayload, MrtBatch, MrtBody, MrtLimits, MrtSource},
    bgp_mrt_store,
    bgp_state::{ApplyStatus, CandidateState, Observation},
    Limits,
};
use std::{
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

static SERIAL: AtomicU64 = AtomicU64::new(0);
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        for _ in 0..1024 {
            let path = std::env::temp_dir().join(format!(
                "pcap-mrt-contract-{}-{}",
                std::process::id(),
                SERIAL.fetch_add(1, Ordering::Relaxed),
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Self(path),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("create owned test directory: {error}"),
            }
        }
        panic!("test directory namespace exhausted");
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

fn limits() -> Limits {
    Limits {
        work: 128 * 1024 * 1024,
        retained_bytes: 128 * 1024 * 1024,
        output_bytes: 128 * 1024 * 1024,
        ..Limits::default()
    }
}
fn source() -> MrtSource {
    MrtSource {
        source_id: "collector-a".into(),
        checkpoint_id: "snapshot-7".into(),
    }
}
fn record(seconds: u32, kind: u16, subtype: u16, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&seconds.to_be_bytes());
    out.extend_from_slice(&kind.to_be_bytes());
    out.extend_from_slice(&subtype.to_be_bytes());
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(body);
    out
}
fn table() -> Vec<u8> {
    // Collector ID; UTF-8 view name; one IPv4, four-octet-ASN peer.
    let mut body = vec![
        192, 0, 2, 1, 0, 1, b'v', 0, 1, 2, 192, 0, 2, 2, 203, 0, 113, 9,
    ];
    body.extend_from_slice(&65551u32.to_be_bytes());
    record(11, 13, 1, &body)
}
fn rib(index: usize) -> Vec<u8> {
    // ORIGIN=IGP, AS_SEQUENCE=[65551], NEXT_HOP=192.0.2.9.
    let mut attrs = vec![0x40, 1, 1, 0, 0x40, 2, 6, 2, 1];
    attrs.extend_from_slice(&65551u32.to_be_bytes());
    attrs.extend_from_slice(&[0x40, 3, 4, 192, 0, 2, 9]);
    let mut body = Vec::new();
    body.extend_from_slice(&(index as u32).to_be_bytes());
    body.extend_from_slice(&[32, 198, 18, (index >> 8) as u8, index as u8]);
    body.extend_from_slice(&1u16.to_be_bytes());
    body.extend_from_slice(&0u16.to_be_bytes());
    body.extend_from_slice(&(10 + index as u32).to_be_bytes());
    body.extend_from_slice(&(attrs.len() as u16).to_be_bytes());
    body.extend_from_slice(&attrs);
    record(12, 13, 2, &body)
}
fn mrt(count: usize, many_tables: bool) -> Vec<u8> {
    let mut out = table();
    for index in 0..count {
        if many_tables && index != 0 {
            out.extend(table());
        }
        out.extend(rib(index));
    }
    out
}
fn observations(count: usize, many_tables: bool) -> Vec<Observation> {
    let batch = MrtBatch::parse(&mrt(count, many_tables), source(), &MrtLimits::default()).unwrap();
    let mut out = Vec::new();
    for (index, record) in batch.records.iter().enumerate() {
        if let MrtBody::Rib(rib) = &record.body {
            for entry in 0..rib.entries.len() {
                let normalized = batch
                    .normalize_rib_entry(index, entry, &limits())
                    .unwrap()
                    .unwrap();
                out.push(Observation::from_normalized(&normalized, None, &limits()).unwrap());
            }
        }
    }
    out
}
fn build(path: &Path, bytes: &[u8], l: Limits) -> bgp_mrt_store::MrtReplayArchive {
    bgp_mrt_store::create(
        path,
        bytes,
        source(),
        4 * 1024 * 1024,
        MrtLimits::default(),
        l,
    )
    .unwrap()
}

#[test]
fn collector_batch_matches_sequential_state_byte_for_byte() {
    for many_tables in [false, true] {
        let values = observations(24, many_tables);
        let mut sequential = CandidateState::new(limits()).unwrap();
        for value in &values {
            sequential.apply(value.clone()).unwrap();
        }
        let mut batch = CandidateState::new(limits()).unwrap();
        let receipts = batch.apply_batch(values).unwrap();
        assert_eq!(batch.encode(), sequential.encode());
        assert_eq!(batch.retained_bytes(), sequential.retained_bytes());
        assert!(batch.routes().is_empty());
        assert_eq!(receipts.len(), 24);
        assert_eq!(batch.observations().len(), 24);
    }
}

#[test]
fn exact_replays_and_conflicting_identities_preserve_quarantine_semantics() {
    let original = observations(1, false).remove(0);
    let mut changed = original.normalized().clone();
    let Json::Object(fields) = &mut changed else {
        panic!("object");
    };
    fields.push(("fixture_annotation", "different record content".into()));
    let conflict = Observation::from_normalized(&changed, None, &limits()).unwrap();
    let values = vec![original.clone(), original.clone(), conflict, original];
    let mut sequential = CandidateState::new(limits()).unwrap();
    for value in &values {
        sequential.apply(value.clone()).unwrap();
    }
    let mut batch = CandidateState::new(limits()).unwrap();
    let receipts = batch.apply_batch(values).unwrap();
    assert_eq!(batch.encode(), sequential.encode());
    assert_eq!(
        receipts
            .iter()
            .filter(|o| o.status == ApplyStatus::IdenticalReplay)
            .count(),
        2
    );
    assert_eq!(batch.observations().len(), 2);
    assert_eq!(batch.sessions().len(), 1);
    assert!(batch.sessions()[0].identity_conflict);
    assert!(batch.routes().is_empty());
}

#[test]
fn unscoped_collector_batch_does_not_invent_direction_or_endpoint_routes() {
    let mut state = CandidateState::new(limits()).unwrap();
    state.apply_batch(observations(4, false)).unwrap();
    assert!(state.routes().is_empty());
    for observation in state.observations() {
        assert_eq!(observation.source().direction, None);
        assert_eq!(observation.source().generation, Some(0));
        assert!(observation.import_boundary().is_none());
    }
    assert!(state
        .outcomes()
        .iter()
        .all(|o| o.status == ApplyStatus::MissingScope));
}

#[test]
fn legacy_imports_are_not_silently_upgraded_to_contextual_collector_snapshots() {
    let mut value = observations(1, false).remove(0).normalized().clone();
    let Json::Object(fields) = &mut value else {
        panic!("object");
    };
    fields.retain(|(key, _)| *key != "import_context");
    let legacy = Observation::from_normalized(&value, None, &limits()).unwrap();
    let mut state = CandidateState::new(limits()).unwrap();
    state.apply_batch([legacy]).unwrap();
    assert!(state.observations()[0].import_context().is_none());
    assert_eq!(state.observations()[0].source().generation, None);
    assert!(state.routes().is_empty());
}

#[test]
fn batch_budget_failures_leave_committed_state_and_diagnostics_unchanged() {
    let values = observations(4, false);
    let mut state = CandidateState::new(limits()).unwrap();
    state.apply_batch(values.clone()).unwrap();
    for narrow in [
        Limits {
            output_bytes: state.encode().len() - 1,
            ..limits()
        },
        Limits {
            retained_bytes: state.retained_bytes() - 1,
            ..limits()
        },
        Limits {
            elements: 3,
            ..limits()
        },
        Limits {
            spans: 3,
            ..limits()
        },
        Limits {
            work: 1,
            ..limits()
        },
    ] {
        let mut bounded = CandidateState::new(narrow).unwrap();
        let before = bounded.encode().to_owned();
        let work = bounded.last_work();
        assert!(bounded.apply_batch(values.clone()).is_err());
        assert_eq!(bounded.encode(), before);
        assert_eq!(bounded.last_work(), work);
    }
    let mut empty = CandidateState::new(limits()).unwrap();
    assert!(empty.apply_batch(std::iter::empty()).unwrap().is_empty());
    assert_eq!(empty.last_work(), 0);
}

#[test]
fn deterministic_logical_work_grows_near_linearly_without_timing_claims() {
    let run = |count| {
        let mut state = CandidateState::new(limits()).unwrap();
        state.apply_batch(observations(count, true)).unwrap();
        state
    };
    let small = run(64);
    let large = run(128);
    assert_eq!(
        (small.observations().len(), large.observations().len()),
        (64, 128)
    );
    assert!(large.last_work() > small.last_work());
    assert!(large.last_work() < small.last_work() * 3);
    assert!(large.retained_bytes() < small.retained_bytes() * 3);
    let repeated = run(128);
    assert_eq!(large.last_work(), repeated.last_work());
    assert_eq!(large.encode(), repeated.encode());
}

#[test]
fn many_table_store_replays_with_distinct_bindings_and_exact_v3_json() {
    let temp = Scratch::new();
    let raw = mrt(24, true);
    let archive = build(&temp.file("source.mrt-store"), &raw, limits());
    assert_eq!(archive.candidates.len(), 24);
    let sessions: std::collections::BTreeSet<_> =
        archive.candidates.iter().map(|c| &c.session).collect();
    assert_eq!(sessions.len(), 24);
    let replayed = bgp_mrt_store::replay(
        &temp.file("source.mrt-store"),
        4 * 1024 * 1024,
        MrtLimits::default(),
        limits(),
    )
    .unwrap();
    let created_state = archive.state.encode().as_bytes();
    let replayed_state = replayed.state.encode().as_bytes();
    if created_state != replayed_state {
        let offset = created_state
            .iter()
            .zip(replayed_state)
            .position(|(created, replayed)| created != replayed)
            .unwrap_or(created_state.len().min(replayed_state.len()));
        let start = offset.saturating_sub(48);
        let created_end = (offset + 96).min(created_state.len());
        let replayed_end = (offset + 96).min(replayed_state.len());
        panic!(
            "created/replayed state differs at byte {offset} (lengths {} and {}): created={:?}; replayed={:?}",
            created_state.len(),
            replayed_state.len(),
            &created_state[start..created_end],
            &replayed_state[start..replayed_end],
        );
    }
    let legacy = archive
        .json()
        .encode_bounded(limits().output_bytes)
        .unwrap();
    assert_eq!(archive.encode_bounded(legacy.len()).unwrap(), legacy);
    assert_eq!(
        archive.encoded_len_bounded(legacy.len()).unwrap(),
        legacy.len()
    );
    assert!(archive.encoded_len_bounded(legacy.len() - 1).is_err());
    let mut line = Vec::new();
    assert_eq!(
        archive
            .write_bounded_line(&mut line, legacy.len() + 1)
            .unwrap(),
        legacy.len() + 1
    );
    assert_eq!(line, format!("{legacy}\n").as_bytes());
    let mut untouched = Vec::new();
    assert!(archive
        .write_bounded_line(&mut untouched, legacy.len())
        .is_err());
    assert!(untouched.is_empty());
}

#[test]
fn session_query_preserves_schema_and_preflights_before_writing() {
    let temp = Scratch::new();
    let archive = build(&temp.file("store"), &mrt(3, false), limits());
    let id = archive.candidates[0].session.clone();
    let expected = Json::object([
        (
            "schema",
            "pcap-evidence.bgp.imported-session-query.v3".into(),
        ),
        ("session", id.clone().into()),
        (
            "observations",
            archive
                .observations_for_candidates(&archive.session_candidates(&id))
                .unwrap(),
        ),
        (
            "candidates",
            Json::array(
                archive
                    .session_candidates(&id)
                    .into_iter()
                    .map(|c| c.json()),
            ),
        ),
        ("bgp4mp_candidates", Json::array([])),
        ("bgp4mp_events", Json::array([])),
        ("endpoint_state_claimed", false.into()),
    ])
    .encode_bounded_line(limits().output_bytes)
    .unwrap();
    let mut bytes = Vec::new();
    archive
        .write_session_query_bounded_line(&id, &mut bytes, expected.len())
        .unwrap();
    assert_eq!(bytes, expected.as_bytes());
    for (session, limit) in [
        (id.as_str(), expected.len() - 1),
        ("absent", expected.len()),
    ] {
        let mut out = Vec::new();
        assert!(archive
            .write_session_query_bounded_line(session, &mut out, limit)
            .is_err());
        assert!(out.is_empty());
    }
}

#[test]
fn v1_sealed_bytes_remain_exact_and_disk_rejection_leaves_no_destination() {
    let temp = Scratch::new();
    let raw = mrt(2, false);
    let archive = build(&temp.file("accepted"), &raw, limits());
    let labels = source();
    let mut expected = b"PCBMRT01".to_vec();
    expected.extend_from_slice(&1u16.to_le_bytes());
    for label in [&labels.source_id, &labels.checkpoint_id] {
        expected.extend_from_slice(&(label.len() as u32).to_le_bytes());
        expected.extend_from_slice(label.as_bytes());
    }
    expected.extend_from_slice(&(raw.len() as u64).to_le_bytes());
    expected.extend_from_slice(&sha256::digest(&raw));
    expected.extend_from_slice(&raw);
    let mut seal = sha256::Sha256::new();
    seal.update(b"pcap-evidence/bgp-mrt-source-store/v1\0");
    seal.update(&expected);
    expected.extend_from_slice(&seal.finalize());
    assert_eq!(fs::read(temp.file("accepted")).unwrap(), expected);
    assert_eq!(archive.receipt.source_bytes as usize, raw.len());
    assert!(bgp_mrt_store::create(
        &temp.file("too-small"),
        &raw,
        labels,
        expected.len() as u64 - 1,
        MrtLimits::default(),
        limits()
    )
    .is_err());
    assert!(!temp.file("too-small").exists());
}

#[test]
fn output_and_combined_retention_failures_precede_destination_creation() {
    let temp = Scratch::new();
    let raw = mrt(4, true);
    let archive = build(&temp.file("reference"), &raw, limits());
    let output_size = archive.encoded_len_bounded(limits().output_bytes).unwrap();
    let retained = archive.state.retained_bytes()
        + archive.batch().retained_bytes
        + archive
            .candidates
            .iter()
            .map(|c| c.json().encoded_len_bounded(usize::MAX).unwrap())
            .sum::<usize>();
    for (name, l) in [
        (
            "output",
            Limits {
                output_bytes: output_size - 1,
                ..limits()
            },
        ),
        (
            "retention",
            Limits {
                retained_bytes: retained - 1,
                ..limits()
            },
        ),
    ] {
        assert!(bgp_mrt_store::create(
            &temp.file(name),
            &raw,
            source(),
            4 * 1024 * 1024,
            MrtLimits::default(),
            l
        )
        .is_err());
        assert!(!temp.file(name).exists());
    }
    build(
        &temp.file("exact-retention"),
        &raw,
        Limits {
            retained_bytes: retained,
            ..limits()
        },
    );
}

#[test]
fn no_overwrite_and_source_admission_are_preserved() {
    let temp = Scratch::new();
    let raw = mrt(1, false);
    fs::write(temp.file("occupied"), b"owner-data").unwrap();
    assert!(bgp_mrt_store::create(
        &temp.file("occupied"),
        &raw,
        source(),
        4 * 1024 * 1024,
        MrtLimits::default(),
        limits()
    )
    .is_err());
    assert_eq!(fs::read(temp.file("occupied")).unwrap(), b"owner-data");
    fs::write(temp.file("source"), &raw).unwrap();
    assert_eq!(
        bgp_mrt_store::read_source(&temp.file("source"), raw.len() as u64).unwrap(),
        raw
    );
    assert!(bgp_mrt_store::read_source(&temp.file("source"), raw.len() as u64 - 1).is_err());
    let sparse = fs::File::create(temp.file("oversized-store")).unwrap();
    sparse.set_len(2 * 1024 * 1024).unwrap();
    assert!(bgp_mrt_store::replay(
        &temp.file("oversized-store"),
        8 * 1024 * 1024,
        MrtLimits::default(),
        limits()
    )
    .is_err());
}

struct FailWriter;
impl Write for FailWriter {
    fn write(&mut self, _bytes: &[u8]) -> io::Result<usize> {
        Err(io::Error::from(io::ErrorKind::BrokenPipe))
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
#[test]
fn output_io_errors_are_not_reported_as_success() {
    let temp = Scratch::new();
    let archive = build(&temp.file("store"), &mrt(1, false), limits());
    assert!(archive
        .write_bounded_line(&mut FailWriter, limits().output_bytes)
        .is_err());
}

fn bgp4mp(subtype: u16, extended: bool, ipv6: bool) -> Vec<u8> {
    let four = matches!(subtype, 4 | 7 | 9 | 11);
    let mut body = Vec::new();
    if extended {
        body.extend_from_slice(&123_456u32.to_be_bytes());
    }
    if four {
        body.extend_from_slice(&65551u32.to_be_bytes());
        body.extend_from_slice(&65552u32.to_be_bytes());
    } else {
        body.extend_from_slice(&65001u16.to_be_bytes());
        body.extend_from_slice(&65002u16.to_be_bytes());
    }
    body.extend_from_slice(&2u16.to_be_bytes());
    body.extend_from_slice(&(if ipv6 { 2u16 } else { 1u16 }).to_be_bytes());
    if ipv6 {
        body.extend_from_slice(&[0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        body.extend_from_slice(&[0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
    } else {
        body.extend_from_slice(&[203, 0, 113, 9, 192, 0, 2, 1]);
    }
    body.extend_from_slice(&[0xff; 16]);
    body.extend_from_slice(&19u16.to_be_bytes());
    body.push(4);
    record(21, if extended { 17 } else { 16 }, subtype, &body)
}

#[test]
fn source_ranges_cover_all_message_subtypes_et_and_address_families() {
    for subtype in [1, 4, 6, 7, 8, 9, 10, 11] {
        for extended in [false, true] {
            for ipv6 in [false, true] {
                let leading = record(1, 99, 0, &[7, 8]);
                let raw = [leading.clone(), bgp4mp(subtype, extended, ipv6)].concat();
                let batch = MrtBatch::parse(&raw, source(), &MrtLimits::default()).unwrap();
                assert!(batch.bgp4mp_message_source_range(0).unwrap().is_none());
                let span = batch.bgp4mp_message_source_range(1).unwrap().unwrap();
                assert_eq!(
                    batch
                        .verified_bgp4mp_message_source_range(1, &raw)
                        .unwrap()
                        .unwrap(),
                    span
                );
                let asn_bytes = if matches!(subtype, 4 | 7 | 9 | 11) {
                    8
                } else {
                    4
                };
                let expected_start = leading.len()
                    + 12
                    + usize::from(extended) * 4
                    + asn_bytes
                    + 4
                    + if ipv6 { 32 } else { 8 };
                assert_eq!(span.start as usize, expected_start);
                assert_eq!(span.end - span.start, 19);
                let slice = &raw[span.start as usize..span.end as usize];
                assert_eq!(span.sha256.unwrap(), sha256::hex(&sha256::digest(slice)));
                let MrtBody::Bgp4mp(message) = &batch.records[1].body else {
                    panic!("BGP4MP");
                };
                let Bgp4mpPayload::Message(bytes) = &message.payload else {
                    panic!("message");
                };
                assert_eq!(slice, bytes);
                assert!(!batch.source_authenticated);
            }
        }
    }
}

#[test]
fn inconsistent_message_metadata_and_ranges_fail_closed() {
    let batch = MrtBatch::parse(&bgp4mp(4, false, false), source(), &MrtLimits::default()).unwrap();
    let mut changed = batch.clone();
    changed.records[0].length += 1;
    assert!(changed.bgp4mp_message_source_range(0).is_err());
    let mut changed = batch.clone();
    changed.records[0].offset = u64::MAX;
    assert!(changed.bgp4mp_message_source_range(0).is_err());
    let mut changed = batch.clone();
    changed.records[0].time.microseconds = Some(0);
    assert!(changed.bgp4mp_message_source_range(0).is_err());
    let mut changed = batch.clone();
    changed.byte_length -= 1;
    assert!(changed.bgp4mp_message_source_range(0).is_err());
    let mut changed = batch.clone();
    let MrtBody::Bgp4mp(message) = &mut changed.records[0].body else {
        panic!("BGP4MP");
    };
    message.asn_width = 2;
    assert!(changed.bgp4mp_message_source_range(0).is_err());
    let mut changed = batch;
    let MrtBody::Bgp4mp(message) = &mut changed.records[0].body else {
        panic!("BGP4MP");
    };
    let Bgp4mpPayload::Message(bytes) = &mut message.payload else {
        panic!("message");
    };
    bytes.pop();
    assert!(changed.bgp4mp_message_source_range(0).is_err());
}

#[test]
fn unsupported_attributes_and_bgp4mp_remain_distinct_non_authoritative_evidence() {
    let temp = Scratch::new();
    let mut raw = mrt(1, false);
    let code = raw.len() - 6;
    assert_eq!(raw[code], 3); // NEXT_HOP type octet, not a length or data byte.
    raw[code] = 99;
    raw.extend(bgp4mp(4, false, false));
    raw.extend(record(30, 99, 1, &[1, 2, 3]));
    let archive = build(&temp.file("unsupported"), &raw, limits());
    assert_eq!(archive.unsupported_rib_entries, 1);
    assert_eq!(archive.bgp4mp_messages, 1);
    assert_eq!(archive.opaque_records, 1);
    assert!(archive.candidates.is_empty());
    assert!(archive.state.observations().is_empty());
    assert!(archive.state.routes().is_empty());
    assert_eq!(
        archive.encode_bounded(limits().output_bytes).unwrap(),
        archive.json().encode()
    );
}

fn cli(args: &[&std::ffi::OsStr]) -> std::process::Output {
    std::process::Command::new(env!("CARGO_BIN_EXE_pcap-depth"))
        .args(args)
        .output()
        .expect("execute fresh pcap-depth process")
}

#[test]
fn fresh_cli_import_state_query_export_and_failed_publication_contracts() {
    let temp = Scratch::new();
    let input = temp.file("source.mrt");
    let workspace = temp.file("workspace");
    let raw = mrt(3, false);
    fs::write(&input, &raw).unwrap();
    let imported = cli(&[
        "bgp".as_ref(),
        "import-mrt".as_ref(),
        input.as_os_str(),
        "--workspace".as_ref(),
        workspace.as_os_str(),
        "--source-id".as_ref(),
        "collector-a".as_ref(),
        "--checkpoint".as_ref(),
        "snapshot-7".as_ref(),
        "--max-mrt-bytes".as_ref(),
        "1048576".as_ref(),
    ]);
    assert!(
        imported.status.success(),
        "{}",
        String::from_utf8_lossy(&imported.stderr)
    );
    let store = workspace.join("bgp.mrt");
    assert!(store.is_file());
    assert!(workspace.join("receipt.json").is_file());
    let archive =
        bgp_mrt_store::replay(&store, 4 * 1024 * 1024, MrtLimits::default(), limits()).unwrap();
    for command in ["state", "replay", "query", "export"] {
        let output = temp.file(&format!("{command}.json"));
        let mut args = vec![
            "bgp".as_ref(),
            command.as_ref(),
            store.as_os_str(),
            "--output".as_ref(),
            output.as_os_str(),
        ];
        if command == "query" {
            args.extend([
                std::ffi::OsStr::new("--session"),
                std::ffi::OsStr::new("mrt:0:0"),
            ]);
        }
        let result = cli(&args);
        assert!(
            result.status.success(),
            "{command}: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        let actual = fs::read(&output).unwrap();
        if matches!(command, "state" | "replay") {
            assert_eq!(actual, format!("{}\n", archive.json().encode()).as_bytes());
        } else if command == "query" {
            let mut expected = Vec::new();
            archive
                .write_session_query_bounded_line("mrt:0:0", &mut expected, limits().output_bytes)
                .unwrap();
            assert_eq!(actual, expected);
        } else {
            assert_eq!(
                String::from_utf8(actual).unwrap().lines().count(),
                1 + archive.batch().records.len()
                    + archive.state.observations().len()
                    + archive.candidates.len()
            );
        }
    }
    let failed_output = temp.file("quota-failure.json");
    let result = cli(&[
        "bgp".as_ref(),
        "state".as_ref(),
        store.as_os_str(),
        "--output".as_ref(),
        failed_output.as_os_str(),
        "--max-output-bytes".as_ref(),
        "1".as_ref(),
    ]);
    assert!(!result.status.success());
    assert!(!failed_output.exists());
    let occupied = temp.file("occupied.json");
    fs::write(&occupied, b"do-not-replace").unwrap();
    let result = cli(&[
        "bgp".as_ref(),
        "state".as_ref(),
        store.as_os_str(),
        "--output".as_ref(),
        occupied.as_os_str(),
    ]);
    assert!(!result.status.success());
    assert_eq!(fs::read(&occupied).unwrap(), b"do-not-replace");
}

#[test]
fn rust_wire_fixture_matches_independent_python_oracle() {
    let raw = mrt(1, false);
    assert_eq!(raw.len(), 85);
    assert_eq!(
        sha256::hex(&sha256::digest(&raw)),
        "61c2248cd8ebe37435b950981f06b50c36781666c24e0b240638d39a710d29f3"
    );
}

#[test]
fn mixed_batch_receipts_use_final_conflict_classification_but_keep_replay_status() {
    let original = observations(1, false).remove(0);
    let mut changed = original.normalized().clone();
    let Json::Object(fields) = &mut changed else {
        panic!("object");
    };
    fields.push(("fixture_annotation", "conflicting content".into()));
    let conflict = Observation::from_normalized(&changed, None, &limits()).unwrap();
    let mut legacy = observations(2, false).remove(1).normalized().clone();
    let Json::Object(fields) = &mut legacy else {
        panic!("object");
    };
    fields.retain(|(key, _)| *key != "import_context");
    let legacy = Observation::from_normalized(&legacy, None, &limits()).unwrap();
    let mut state = CandidateState::new(limits()).unwrap();
    let receipts = state
        .apply_batch([original.clone(), original, conflict, legacy])
        .unwrap();
    assert_eq!(receipts[0].status, ApplyStatus::IdentityConflict);
    assert_eq!(receipts[1].status, ApplyStatus::IdenticalReplay);
    assert_eq!(receipts[2].status, ApplyStatus::IdentityConflict);
    for (index, receipt) in receipts.iter().enumerate() {
        if index != 1 {
            assert_eq!(receipt, &state.outcomes()[receipt.observation]);
        }
    }
}

#[test]
fn compact_candidate_references_reject_wrong_digest_route_and_source_bindings() {
    let temp = Scratch::new();
    let archive = build(&temp.file("references"), &mrt(2, false), limits());
    let good = archive.candidates[0].clone();
    assert!(archive.candidate_observation(&good).is_ok());
    let mut mutants = Vec::new();
    let mut bad = good.clone();
    bad.observation_index = usize::MAX;
    mutants.push(bad);
    let mut bad = good.clone();
    bad.observation_index = 1;
    mutants.push(bad);
    let mut bad = good.clone();
    bad.route_index = usize::MAX;
    mutants.push(bad);
    let mut bad = good.clone();
    bad.record_index = 0;
    mutants.push(bad);
    let mut bad = good.clone();
    bad.entry_index = usize::MAX;
    mutants.push(bad);
    let mut bad = good.clone();
    bad.observation_sha256[0] ^= 1;
    mutants.push(bad);
    let mut bad = good.clone();
    bad.source_id = "foreign".into();
    mutants.push(bad);
    let mut bad = good.clone();
    bad.checkpoint_id = "foreign".into();
    mutants.push(bad);
    let mut bad = good.clone();
    bad.record_id = "foreign".into();
    mutants.push(bad);
    let mut bad = good.clone();
    bad.session = "foreign".into();
    mutants.push(bad);
    let mut bad = good.clone();
    bad.peer = Some("foreign".into());
    mutants.push(bad);
    let mut bad = good.clone();
    bad.observed_at_ns = None;
    mutants.push(bad);
    let mut bad = good.clone();
    bad.prefix.address = "203.0.113.0".into();
    mutants.push(bad);
    let mut bad = good;
    bad.ambiguous_attributes = !bad.ambiguous_attributes;
    mutants.push(bad);
    for bad in mutants {
        assert!(archive.candidate_observation(&bad).is_err());
    }
}

#[test]
fn duplicate_indices_cannot_hide_an_invalid_second_candidate() {
    let temp = Scratch::new();
    let archive = build(&temp.file("duplicates"), &mrt(1, false), limits());
    let good = &archive.candidates[0];
    let mut bad = good.clone();
    bad.observation_sha256[0] ^= 1;
    assert!(archive.observations_for_candidates(&[good, &bad]).is_err());
    let deduplicated = archive.observations_for_candidates(&[good, good]).unwrap();
    let Json::Array(items) = deduplicated else {
        panic!("array");
    };
    assert_eq!(items.len(), 1);
}

#[test]
fn foreign_archive_candidates_do_not_resolve_by_coincident_numeric_index() {
    let temp = Scratch::new();
    let a = build(&temp.file("archive-a"), &mrt(1, false), limits());
    let b = build(&temp.file("archive-b"), &mrt(2, false), limits());
    assert_eq!(
        a.candidates[0].observation_index,
        b.candidates[0].observation_index
    );
    assert!(a.candidate_observation(&b.candidates[0]).is_err());
    assert!(b.candidate_observation(&a.candidates[0]).is_err());
}

#[test]
fn original_byte_verification_rejects_mutated_source_record_or_payload() {
    let source_bytes = bgp4mp(4, true, false);
    let batch = MrtBatch::parse(&source_bytes, source(), &MrtLimits::default()).unwrap();
    assert!(batch
        .verified_bgp4mp_message_source_range(0, &source_bytes)
        .unwrap()
        .is_some());
    let mut bytes = source_bytes.clone();
    bytes[0] ^= 1;
    assert!(batch
        .verified_bgp4mp_message_source_range(0, &bytes)
        .is_err());
    assert!(batch
        .verified_bgp4mp_message_source_range(0, &source_bytes[..source_bytes.len() - 1])
        .is_err());
    let mut changed = batch.clone();
    changed.records[0].sha256 = "00".repeat(32);
    assert!(changed
        .verified_bgp4mp_message_source_range(0, &source_bytes)
        .is_err());
    let mut changed = batch.clone();
    changed.records[0].time.seconds += 1;
    assert!(changed
        .verified_bgp4mp_message_source_range(0, &source_bytes)
        .is_err());
    let mut changed = batch.clone();
    changed.records[0].body = MrtBody::Opaque {
        reason: "fixture",
        bytes: Vec::new(),
    };
    assert!(changed
        .verified_bgp4mp_message_source_range(0, &source_bytes)
        .is_err());
    let mut changed = batch;
    let MrtBody::Bgp4mp(message) = &mut changed.records[0].body else {
        panic!("BGP4MP");
    };
    let Bgp4mpPayload::Message(bytes) = &mut message.payload else {
        panic!("message");
    };
    bytes[18] = 2; // Same frame size; exact payload verification must still fail.
    assert!(changed
        .verified_bgp4mp_message_source_range(0, &source_bytes)
        .is_err());
}

#[test]
fn invalid_projection_references_fail_before_writing_any_output() {
    let temp = Scratch::new();
    let mut archive = build(&temp.file("invalid-projection"), &mrt(2, false), limits());
    let session = archive.candidates[0].session.clone();
    archive.candidates[1].observation_sha256[0] ^= 1;
    let mut bytes = Vec::new();
    assert!(archive
        .write_bounded_line(&mut bytes, limits().output_bytes)
        .is_err());
    assert!(bytes.is_empty());
    assert!(archive
        .write_session_query_bounded_line(&session, &mut bytes, limits().output_bytes)
        .is_err());
    assert!(bytes.is_empty());
}
