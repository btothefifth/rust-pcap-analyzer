//! Tiny capture -> sealed history -> actual application consumer regressions.
#[path = "../../history/tests/support/tiny_capture.rs"]
mod tiny_capture;
use pcap_evidence_history::{analyze_file, query::History, Cancellation, Config};
use pcap_evidence_history_app::{analyze, Request};
use pcap_evidence_product::deep::Limits;
use std::sync::atomic::AtomicBool;
use tiny_capture::{tcp, Temp};

fn consume(
    protocol: &str,
    payload: &[u8],
    retained_bytes: usize,
    page_bytes: usize,
) -> (pcap_evidence::Result<()>, String) {
    let temp = Temp::new();
    let source = temp.source(&[
        tcp(false, 100, 0, 2, &[]),
        tcp(false, 101, 0, 0x18, payload),
    ]);
    let workspace = temp.0.join("history");
    analyze_file(
        &source,
        &workspace,
        Config::default(),
        &Cancellation::default(),
    )
    .unwrap();
    let mut history = History::open(&source, &workspace).unwrap();
    let generation = history.generations(None, 10).unwrap()[0];
    let request = Request {
        generation,
        direction: 0,
        start: 0,
        end: payload.len() as i64,
        page_bytes,
        max_output_bytes: 1024 * 1024,
        protocol: protocol.into(),
        ua_security_none: protocol == "opcua_tcp",
    };
    let mut output = Vec::new();
    let result = analyze(
        &mut history,
        &request,
        Limits {
            retained_bytes,
            ..Limits::default()
        },
        &mut output,
        &AtomicBool::new(false),
    );
    (result, String::from_utf8(output).unwrap())
}
fn ua(request: u32, sequence: u32, flag: u8, payload: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::from(*b"MSG");
    bytes.push(flag);
    bytes.extend_from_slice(&(24u32 + payload.len() as u32).to_le_bytes());
    for value in [7, 42, sequence, request] {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    bytes.extend_from_slice(payload);
    bytes
}

#[test]
fn retained_payload_rejection_aborts_actual_history_consumer() {
    let payload = [3, 0, 0, 9, 2, 0xf0, 0, 5, 0, 3, 0, 0, 7, 2, 0xf0, 0x80];
    let (result, output) = consume("iso_cotp", &payload, 1, 3);
    assert_eq!(result.unwrap_err().field, "cotp_retained_bytes");
    assert!(output.contains("analysis.aborted"));
    assert!(!output.contains("analysis.complete"));
    assert!(!output.contains("protocol.message"));
}

#[test]
fn cotp_completion_survives_history_pages_and_releases_payload_budget() {
    let payload = [
        3, 0, 0, 8, 2, 0xf0, 0, 5, 3, 0, 0, 8, 2, 0xf0, 0x80, 0, 3, 0, 0, 9, 2, 0xf0, 0x80, 5, 0,
    ];
    let (result, output) = consume("iso_cotp", &payload, 2, 3);
    result.unwrap();
    assert_eq!(output.matches("\"kind\":\"protocol.message\"").count(), 2);
    assert!(output.contains("analysis.complete"));
    assert!(!output.contains("analysis.aborted"));
}

#[test]
fn ua_abort_advances_channel_and_allows_new_message_through_history_pages() {
    let mut payload = ua(1, 1, b'C', &[0]);
    payload.extend_from_slice(&ua(1, 2, b'A', &[]));
    payload.extend_from_slice(&ua(2, 3, b'F', &[0, 1]));
    let (result, output) = consume("opcua_tcp", &payload, 2, 5);
    result.unwrap();
    assert_eq!(output.matches("\"kind\":\"protocol.message\"").count(), 2);
    assert!(output.contains("message_aborted"));
    assert!(output.contains("opcua.service"));
    assert!(output.contains("analysis.complete"));
}

fn ua_request_body(id: u16) -> Vec<u8> {
    let mut body = vec![1, 0];
    body.extend_from_slice(&id.to_le_bytes());
    body.extend_from_slice(&[0, 0]);
    body.extend_from_slice(&0i64.to_le_bytes());
    body.extend_from_slice(&1u32.to_le_bytes());
    body.extend_from_slice(&0u32.to_le_bytes());
    body.extend_from_slice(&(-1i32).to_le_bytes());
    body.extend_from_slice(&0u32.to_le_bytes());
    body.extend_from_slice(&[0, 0, 0]);
    if id == 631 {
        body.extend_from_slice(&0u64.to_le_bytes());
        body.extend_from_slice(&3u32.to_le_bytes());
        body.extend_from_slice(&0i32.to_le_bytes());
    } else if id == 446 {
        for value in [0u32, 1, 1] {
            body.extend_from_slice(&value.to_le_bytes());
        }
        body.extend_from_slice(&(-1i32).to_le_bytes());
        body.extend_from_slice(&60000u32.to_le_bytes());
    } else {
        assert_eq!(id, 452);
    }
    body
}
fn ua_open(sequence: u32, policy: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::from(*b"OPNF");
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&7u32.to_le_bytes());
    bytes.extend_from_slice(&(policy.len() as i32).to_le_bytes());
    bytes.extend_from_slice(policy);
    bytes.extend_from_slice(&(-1i32).to_le_bytes());
    bytes.extend_from_slice(&(-1i32).to_le_bytes());
    bytes.extend_from_slice(&sequence.to_le_bytes());
    bytes.extend_from_slice(&2u32.to_le_bytes());
    bytes.extend_from_slice(&ua_request_body(446));
    let len = bytes.len() as u32;
    bytes[4..8].copy_from_slice(&len.to_le_bytes());
    bytes
}
fn ua_close(sequence: u32) -> Vec<u8> {
    let mut bytes = ua(3, sequence, b'F', &ua_request_body(452));
    bytes[..3].copy_from_slice(b"CLO");
    bytes
}

#[test]
fn ua_renewal_and_close_complete_actual_history_consumer_across_pages() {
    let body = ua_request_body(631);
    let mut payload = ua(1, 1, b'F', &body);
    payload.extend_from_slice(&ua_open(
        2,
        b"http://opcfoundation.org/UA/SecurityPolicy#None",
    ));
    payload.extend_from_slice(&ua(3, 3, b'F', &body));
    payload.extend_from_slice(&ua_close(4));
    for page_bytes in [5, payload.len()] {
        let (result, output) = consume("opcua_tcp", &payload, 256, page_bytes);
        result.unwrap();
        assert_eq!(output.matches("\"kind\":\"protocol.message\"").count(), 4);
        assert_eq!(output.matches("read_options").count(), 2);
        assert!(output.contains("analysis.complete"));
        assert!(!output.contains("analysis.aborted"));
    }
}

#[test]
fn ua_open_and_close_sequence_gaps_abort_actual_history_consumer() {
    for bad in [
        ua_open(3, b"http://opcfoundation.org/UA/SecurityPolicy#None"),
        ua_close(3),
    ] {
        let mut payload = ua(1, 1, b'C', &[0]);
        payload.extend_from_slice(&bad);
        payload.extend_from_slice(&ua(1, 4, b'F', &[1]));
        let (result, output) = consume("opcua_tcp", &payload, 256, 5);
        assert_eq!(result.unwrap_err().field, "ua_sequence");
        assert!(output.contains("analysis.aborted"));
        assert!(!output.contains("analysis.complete"));
        assert!(!output.contains("protocol.message"));
    }
}

#[test]
fn ua_opaque_policy_preserves_actual_history_consumer_sequence() {
    let body = ua_request_body(631);
    let mut payload = ua(1, 1, b'F', &body);
    payload.extend_from_slice(&ua_open(
        800,
        b"http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256",
    ));
    payload.extend_from_slice(&ua(3, 2, b'F', &body));
    let (result, output) = consume("opcua_tcp", &payload, 256, 5);
    result.unwrap();
    assert_eq!(output.matches("\"kind\":\"protocol.message\"").count(), 3);
    assert_eq!(output.matches("read_options").count(), 2);
    assert!(output.contains("secure_payload_requires_explicit_crypto_context"));
    assert!(output.contains("analysis.complete"));
    assert!(!output.contains("analysis.aborted"));
}
