mod common;
use common::*;
use std::process::Command;
fn run(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_pcap-evidence"))
        .args(args)
        .output()
        .unwrap()
}
#[test]
fn help_and_invalid_flags_have_distinct_exit_status() {
    let out = run(&["--help"]);
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("USAGE"));
    let out = run(&["missing-command", "missing.pcap"]);
    assert_eq!(out.status.code(), Some(2));
}
#[test]
fn real_cli_inspects_and_does_not_modify_source() {
    let root = Temp::new();
    let capture = root.0.join("capture.pcap");
    let data = fixture("ethernet_udp_le_ns.pcap");
    std::fs::write(&capture, &data).unwrap();
    let out = run(&["inspect", capture.to_str().unwrap()]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.contains("1700000000123456789"));
    assert_eq!(std::fs::read(&capture).unwrap(), data);
    assert_eq!(std::fs::read_dir(&root.0).unwrap().count(), 1);
}
#[test]
fn cli_pipeline_labels_and_no_clobber_output() {
    let root = Temp::new();
    let capture = root.0.join("capture.pcap");
    let output = root.0.join("analysis.json");
    let labels = root.0.join("labels.tsv");
    std::fs::write(&capture, fixture("dnp3_tcp.pcap")).unwrap();
    std::fs::write(&labels, fixture("attempts.tsv")).unwrap();
    let args = [
        "analyze",
        capture.to_str().unwrap(),
        "--labels",
        labels.to_str().unwrap(),
        "-o",
        output.to_str().unwrap(),
    ];
    let out = run(&args);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let before = std::fs::read(&output).unwrap();
    assert!(String::from_utf8_lossy(&before).contains("candidate_evidence_found"));
    assert_eq!(run(&args).status.code(), Some(3));
    assert_eq!(std::fs::read(&output).unwrap(), before);
}
#[test]
fn cli_index_verify_and_packet_lookup() {
    let root = Temp::new();
    let capture = root.0.join("capture.pcap");
    let index = root.0.join("capture.pcidx");
    std::fs::write(&capture, fixture("ethernet_udp_le_us.pcap")).unwrap();
    assert!(run(&[
        "index",
        capture.to_str().unwrap(),
        "-o",
        index.to_str().unwrap()
    ])
    .status
    .success());
    assert!(run(&[
        "verify-index",
        capture.to_str().unwrap(),
        "--index",
        index.to_str().unwrap()
    ])
    .status
    .success());
    let packet = run(&[
        "packet",
        capture.to_str().unwrap(),
        "--index",
        index.to_str().unwrap(),
        "--frame",
        "1",
    ]);
    assert!(packet.status.success());
    assert!(String::from_utf8_lossy(&packet.stdout).contains("\"length\":50"));
}
#[test]
fn require_clean_returns_diagnostic_status_without_hiding_report() {
    let root = Temp::new();
    let capture = root.0.join("capture.pcap");
    std::fs::write(&capture, fixture("conflicting_tcp.pcap")).unwrap();
    let out = run(&["analyze", capture.to_str().unwrap(), "--require-clean"]);
    assert_eq!(out.status.code(), Some(4));
    assert!(String::from_utf8_lossy(&out.stdout).contains("conflicting_capture_bytes"));
}
