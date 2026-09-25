mod common;
use common::*;
use pcap_evidence::correlate::{apply_labels, parse_labels, LABEL_HEADER};
use pcap_evidence::engine::{analyze, Config};
use pcap_evidence::index::{Index, VerifiedIndex};
use pcap_evidence::json::Json;
use pcap_evidence::publish::{read_bounded, write_new};
use pcap_evidence::sha256::{self, Sha256};
use pcap_evidence::time::{Resolution, Timestamp};
use pcap_evidence::{ErrorCode, Limits};

#[test]
fn sha256_independent_known_answer_vectors() {
    for (input, expected) in [
        (
            &b""[..],
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ),
        (
            &b"abc"[..],
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        ),
    ] {
        assert_eq!(sha256::hex(&sha256::digest(input)), expected);
    }
    assert_eq!(
        sha256::hex(&sha256::digest(&vec![b'a'; 1_000_000])),
        "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
    );
}
#[test]
fn sha256_incremental_chunking_and_empty_updates_preserve_digest() {
    let input: Vec<u8> = (0..2048).map(|n| (n % 251) as u8).collect();
    for n in [1, 7, 55, 56, 63, 64, 65, 511] {
        let mut h = Sha256::new();
        for chunk in input.chunks(n) {
            h.update(chunk);
            h.update(&[]);
        }
        assert_eq!(h.finalize(), sha256::digest(&input));
    }
}
#[test]
fn every_resolution_octet_round_trips_without_high_bit_loss() {
    for n in 0..=255u8 {
        assert_eq!(Resolution::from_pcapng(n).to_pcapng().unwrap(), n);
    }
    assert!(Resolution::Binary(128).to_pcapng().is_err());
}
#[test]
fn exact_timestamp_conserves_signed_offset_and_rejects_loss() {
    let t = Timestamp {
        ticks: 1,
        resolution: Resolution::Decimal(0),
        offset_seconds: -2,
    };
    assert_eq!(t.unix_nanos().unwrap(), -1_000_000_000);
    assert!(t.legacy_parts(true).is_err());
    let tiny = Timestamp {
        ticks: 1,
        resolution: Resolution::Decimal(10),
        offset_seconds: 0,
    };
    assert!(tiny.unix_nanos().is_err());
    assert_eq!(Timestamp { ticks: 10, ..tiny }.unix_nanos().unwrap(), 1);
    assert_eq!(
        Timestamp {
            ticks: 0,
            resolution: Resolution::Binary(127),
            offset_seconds: i64::MIN
        }
        .unix_nanos()
        .unwrap(),
        i128::from(i64::MIN) * 1_000_000_000
    );
}
#[test]
fn index_lookup_excludes_record_header_bytes() {
    let source = fixture("ethernet_udp_le_us.pcap");
    let bytes = Index::build(&source, Limits::default())
        .unwrap()
        .encode()
        .unwrap();
    let index = VerifiedIndex::load(&source, &bytes, Limits::default()).unwrap();
    assert_eq!(index.packet(1).unwrap(), &source[40..]);
    assert!(index.packet(0).is_err());
    assert!(index.packet(2).is_err());
}
#[test]
fn sidecar_self_hash_cannot_authorize_forged_metadata() {
    let source = fixture("ethernet_udp_le_us.pcap");
    let mut bytes = Index::build(&source, Limits::default())
        .unwrap()
        .encode()
        .unwrap();
    // First entry original_len field at header(56)+20; preserve wrapper size and rehash.
    bytes[76..80].copy_from_slice(&51u32.to_le_bytes());
    let end = bytes.len() - 32;
    let digest = sha256::digest(&bytes[..end]);
    bytes[end..].copy_from_slice(&digest);
    assert_eq!(
        VerifiedIndex::load(&source, &bytes, Limits::default())
            .err()
            .unwrap()
            .code,
        ErrorCode::InvalidIndex
    );
}
#[test]
fn index_wrong_source_and_truncated_sidecar_are_rejected() {
    let mut source = fixture("ethernet_udp_le_us.pcap");
    let bytes = Index::build(&source, Limits::default())
        .unwrap()
        .encode()
        .unwrap();
    source[49] ^= 1;
    assert_eq!(
        VerifiedIndex::load(&source, &bytes, Limits::default())
            .err()
            .unwrap()
            .code,
        ErrorCode::SourceMismatch
    );
    assert!(VerifiedIndex::load(&source, &bytes[..50], Limits::default()).is_err());
}
#[test]
fn index_time_search_handles_nonmonotonic_and_absent_times() {
    let source = fixture("mixed_sections.pcapng");
    let index = VerifiedIndex::build(&source, Limits::default()).unwrap();
    let matches = index.time_range(0, 10).unwrap();
    assert_eq!(matches.frames, vec![1]);
    assert_eq!(matches.unresolved_frames, vec![3]);
}
#[test]
fn output_publication_never_overwrites_existing_file() {
    let root = Temp::new();
    let path = root.0.join("report.json");
    write_new(&path, b"original").unwrap();
    assert_eq!(
        write_new(&path, b"replacement").unwrap_err().code,
        ErrorCode::OutputExists
    );
    assert_eq!(std::fs::read(&path).unwrap(), b"original");
    assert_eq!(std::fs::read_dir(&root.0).unwrap().count(), 1);
}
#[test]
fn concurrent_publication_has_exactly_one_winner() {
    let root = Temp::new();
    let path = root.0.join("result");
    let a = path.clone();
    let b = path.clone();
    let first = std::thread::spawn(move || write_new(&a, b"a"));
    let second = std::thread::spawn(move || write_new(&b, b"b"));
    let outcomes = [first.join().unwrap(), second.join().unwrap()];
    assert_eq!(outcomes.iter().filter(|r| r.is_ok()).count(), 1);
    assert_eq!(
        outcomes
            .iter()
            .filter_map(|r| r.as_ref().err())
            .next()
            .unwrap()
            .code,
        ErrorCode::OutputExists
    );
    assert_eq!(std::fs::read_dir(&root.0).unwrap().count(), 1);
}
#[cfg(unix)]
#[test]
fn publication_does_not_follow_destination_symlink() {
    let root = Temp::new();
    let original = root.0.join("source");
    let link = root.0.join("destination");
    std::fs::write(&original, b"keep").unwrap();
    std::os::unix::fs::symlink(&original, &link).unwrap();
    assert_eq!(
        write_new(&link, b"corrupt").unwrap_err().code,
        ErrorCode::OutputExists
    );
    assert_eq!(std::fs::read(&original).unwrap(), b"keep");
}
#[test]
fn bounded_read_accepts_exact_neighbor_and_rejects_excess() {
    let root = Temp::new();
    let p = root.0.join("in");
    std::fs::write(&p, b"abcd").unwrap();
    assert_eq!(read_bounded(&p, 4).unwrap(), b"abcd");
    assert_eq!(
        read_bounded(&p, 3).unwrap_err().code,
        ErrorCode::LimitExceeded
    );
}
#[test]
fn labels_produce_candidate_edges_not_attack_truth() {
    let mut analysis = analyze(&fixture("dnp3_tcp.pcap"), Config::default()).unwrap();
    let text = String::from_utf8(fixture("attempts.tsv")).unwrap();
    apply_labels(&mut analysis, &text).unwrap();
    assert_eq!(
        analysis.attempt_matches[0].status,
        "candidate_evidence_found"
    );
    assert_eq!(analysis.attempt_matches[0].matched_packets.len(), 10);
    assert_eq!(
        analysis.attempt_matches[1].status,
        "no_matching_evidence_in_supported_packets"
    );
    assert!(analysis.labels_sha256.is_some());
}
#[test]
fn label_changes_are_semantically_inert_to_packet_stream_reconstruction() {
    let mut analysis = analyze(&fixture("dnp3_tcp.pcap"), Config::default()).unwrap();
    let before = analysis.flows[0].streams[0].as_ref().unwrap().chunks[0]
        .bytes
        .clone();
    apply_labels(
        &mut analysis,
        &String::from_utf8(fixture("attempts.tsv")).unwrap(),
    )
    .unwrap();
    assert_eq!(
        analysis.flows[0].streams[0].as_ref().unwrap().chunks[0].bytes,
        before
    );
    let before_matches = analysis.attempt_matches.len();
    assert!(apply_labels(&mut analysis, "bad input").is_err());
    assert_eq!(analysis.attempt_matches.len(), before_matches);
}
#[test]
fn missing_packet_timestamp_is_unknown_not_outside_label_window() {
    let mut analysis = analyze(&fixture("timestamp_absent.pcapng"), Config::default()).unwrap();
    let labels =
        format!("{LABEL_HEADER}\nunknown-time\t0\t1\t10.0.0.1\t12000\t10.0.0.2\t12001\tudp\n");
    apply_labels(&mut analysis, &labels).unwrap();
    assert_eq!(
        analysis.attempt_matches[0].status,
        "insufficient_timestamp_evidence"
    );
    assert_eq!(analysis.attempt_matches[0].unresolved_time_packets.len(), 1);
    assert!(analysis.attempt_matches[0].matched_packets.is_empty());
}
#[test]
fn labels_reject_duplicate_identity_inverted_time_and_wildcards() {
    let row = "x\t0\t1\t10.0.0.1\t123\t10.0.0.2\t456\ttcp\n";
    assert!(parse_labels(&format!("{LABEL_HEADER}\n{row}{row}"), &Limits::default()).is_err());
    assert!(parse_labels(
        &format!("{LABEL_HEADER}\nx\t2\t1\t*\t123\t10.0.0.2\t456\ttcp\n"),
        &Limits::default()
    )
    .is_err());
    assert!(parse_labels(
        &format!("{LABEL_HEADER}\nx\t0\t1\t*\t123\t10.0.0.2\t456\ttcp\n"),
        &Limits::default()
    )
    .is_err());
}
#[test]
fn json_escaping_and_exact_size_limit() {
    let json = Json::object([("text", Json::string("\"\\\n\t\0é"))]);
    let encoded = json.encode();
    assert_eq!(encoded, "{\"text\":\"\\\"\\\\\\n\\t\\u0000é\"}");
    assert_eq!(json.encode_bounded(encoded.len()).unwrap(), encoded);
    assert!(json.encode_bounded(encoded.len() - 1).is_err());
    assert_eq!(
        json.encode_bounded_line(encoded.len() + 1).unwrap(),
        format!("{encoded}\n")
    );
    assert!(json.encode_bounded_line(encoded.len()).is_err());
}
#[test]
fn secrets_are_redacted_even_with_include_payload() {
    let source = fixture("mixed_sections.pcapng");
    let json = pcap_evidence::report::inspect(
        &source,
        Limits::default(),
        pcap_evidence::capture::ParseMode::Strict,
        true,
    )
    .unwrap()
    .encode();
    assert!(json.contains("secrets_redacted"));
    assert!(!json.contains("private-test-key-material"));
    assert!(!json.contains(&sha256::hex(b"private-test-key-material")));
}

#[cfg(unix)]
#[test]
fn sensitive_report_publication_defaults_to_owner_only_permissions() {
    use std::os::unix::fs::PermissionsExt;
    let root = Temp::new();
    let p = root.0.join("private.json");
    write_new(&p, b"private").unwrap();
    assert_eq!(
        std::fs::metadata(p).unwrap().permissions().mode() & 0o777,
        0o600
    );
}
