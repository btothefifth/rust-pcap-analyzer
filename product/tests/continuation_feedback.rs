//! Finite synthetic continuation regressions, not endpoint qualification.
use pcap_evidence::{
    provenance::{EvidenceBytes, PacketId},
    ErrorCode,
};
use pcap_evidence_product::deep::{
    continuation::{Completed, Parser},
    Context, Limits,
};

fn evidence(bytes: &[u8], frame: u64) -> EvidenceBytes {
    EvidenceBytes::from_packet(
        bytes,
        PacketId {
            capture: [0x43; 32],
            frame,
            record_offset: frame * 100,
        },
        0,
    )
}
fn feed(
    parser: &mut Parser,
    at: &mut i64,
    bytes: &[u8],
    output: &mut Vec<Completed>,
) -> pcap_evidence::Result<()> {
    let result = parser.feed(*at, &evidence(bytes, *at as u64 + 1), &mut |item| {
        output.push(item);
        Ok(())
    });
    *at += bytes.len() as i64;
    result
}
fn cotp(part: &[u8], final_part: bool) -> Vec<u8> {
    let mut bytes = vec![3, 0];
    bytes.extend_from_slice(&u16::try_from(7 + part.len()).unwrap().to_be_bytes());
    bytes.extend_from_slice(&[2, 0xf0, if final_part { 0x80 } else { 0 }]);
    bytes.extend_from_slice(part);
    bytes
}
fn ua(channel: u32, request: u32, token: u32, sequence: u32, flag: u8, part: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::from(*b"MSG");
    bytes.push(flag);
    bytes.extend_from_slice(&u32::try_from(24 + part.len()).unwrap().to_le_bytes());
    for value in [channel, token, sequence, request] {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    bytes.extend_from_slice(part);
    bytes
}
fn ua_parser(retained_bytes: usize) -> Parser {
    Parser::new(
        "opcua_tcp",
        Limits {
            retained_bytes,
            ..Limits::default()
        },
        Context {
            ua_security_none: true,
            ..Context::default()
        },
    )
    .unwrap()
}

#[test]
fn cotp_uses_retained_limit_and_requires_cut_after_rejection() {
    let mut parser = Parser::new(
        "iso_cotp",
        Limits {
            retained_bytes: 1,
            ..Limits::default()
        },
        Context::default(),
    )
    .unwrap();
    let (mut at, mut output) = (0, Vec::new());
    let error = feed(&mut parser, &mut at, &cotp(&[5, 0], false), &mut output).unwrap_err();
    assert_eq!(error.code, ErrorCode::LimitExceeded);
    assert_eq!(error.field, "cotp_retained_bytes");
    let error = feed(&mut parser, &mut at, &cotp(&[], true), &mut output).unwrap_err();
    assert_eq!(error.field, "continuation_requires_cut");
    assert!(output.is_empty());
    parser.cut("test_rejected_payload_boundary").unwrap();
    feed(&mut parser, &mut at, &cotp(&[], true), &mut output).unwrap();
    assert_eq!(output.len(), 1);
}

#[test]
fn cotp_accumulates_across_pages_and_releases_after_final_and_cut() {
    let mut parser = Parser::new(
        "iso_cotp",
        Limits {
            retained_bytes: 2,
            ..Limits::default()
        },
        Context::default(),
    )
    .unwrap();
    let (mut at, mut output) = (0, Vec::new());
    feed(&mut parser, &mut at, &cotp(&[5], false), &mut output).unwrap();
    feed(&mut parser, &mut at, &cotp(&[0], true), &mut output).unwrap();
    assert_eq!(output[0].report.evidence.data(), &[5, 0]);
    assert_eq!(output[0].report.evidence.packets().len(), 2);
    feed(&mut parser, &mut at, &cotp(&[5, 0], true), &mut output).unwrap();
    feed(&mut parser, &mut at, &cotp(&[5, 0], false), &mut output).unwrap();
    parser.cut("test_pending_payload_boundary").unwrap();
    feed(&mut parser, &mut at, &cotp(&[5, 0], true), &mut output).unwrap();
    assert_eq!(output.len(), 3);
    assert!(parser.finish().unwrap().is_none());
}

#[test]
fn cotp_rejected_discontinuity_cannot_join_old_and_new_payloads() {
    let mut parser = Parser::new("iso_cotp", Limits::default(), Context::default()).unwrap();
    let mut output = Vec::new();
    let first = cotp(&[5], false);
    let mut at = 0;
    feed(&mut parser, &mut at, &first, &mut output).unwrap();
    // A missing byte is rejected even though the next page contains a TPKT.
    at += 1;
    assert!(feed(&mut parser, &mut at, &cotp(&[0], true), &mut output).is_err());
    let error = feed(&mut parser, &mut at, &cotp(&[0], true), &mut output).unwrap_err();
    assert_eq!(error.field, "continuation_requires_cut");
    assert!(output.is_empty());
    parser.cut("test_gap").unwrap();
    feed(&mut parser, &mut at, &cotp(&[5, 0], true), &mut output).unwrap();
    assert_eq!(output.len(), 1);
    assert_eq!(output[0].report.evidence.packets().len(), 1);
}

#[test]
fn ua_retained_limit_covers_all_channels_and_requests() {
    let mut parser = ua_parser(1);
    let (mut at, mut output) = (0, Vec::new());
    let error = feed(
        &mut parser,
        &mut at,
        &ua(7, 1, 42, 1, b'C', &[0, 1]),
        &mut output,
    )
    .unwrap_err();
    assert_eq!(error.field, "ua_retained_bytes");
    assert!(output.is_empty());
    for channels in [[7, 7, 7], [7, 8, 9]] {
        let mut parser = ua_parser(2);
        let (mut at, mut output) = (0, Vec::new());
        for (i, channel) in channels[..2].iter().enumerate() {
            let sequence = if channels[0] == channels[1] {
                i as u32 + 1
            } else {
                1
            };
            feed(
                &mut parser,
                &mut at,
                &ua(*channel, i as u32 + 1, 42, sequence, b'C', &[0]),
                &mut output,
            )
            .unwrap();
        }
        let sequence = if channels[0] == channels[2] { 3 } else { 1 };
        let error = feed(
            &mut parser,
            &mut at,
            &ua(channels[2], 3, 42, sequence, b'C', &[0]),
            &mut output,
        )
        .unwrap_err();
        assert_eq!(error.code, ErrorCode::LimitExceeded);
        assert_eq!(error.field, "ua_retained_bytes");
        assert!(output.is_empty());
        parser.cut("test_budget_boundary").unwrap();
        feed(
            &mut parser,
            &mut at,
            &ua(7, 4, 42, 77, b'F', &[0, 1]),
            &mut output,
        )
        .unwrap();
        assert_eq!(output.len(), 1);
    }
}

#[test]
fn ua_final_and_abort_release_retention_and_abort_consumes_sequence() {
    let mut parser = ua_parser(3);
    let (mut at, mut output) = (0, Vec::new());
    for bytes in [
        ua(7, 1, 42, 1, b'C', &[0]),
        ua(7, 2, 42, 2, b'C', &[0]),
        ua(7, 1, 42, 3, b'F', &[1]),
        ua(7, 3, 42, 4, b'C', &[0, 1]),
        ua(7, 3, 42, 5, b'A', &[]),
        ua(7, 2, 42, 6, b'F', &[1]),
        ua(7, 4, 42, 7, b'F', &[0, 1]),
    ] {
        feed(&mut parser, &mut at, &bytes, &mut output).unwrap();
    }
    assert_eq!(output.len(), 4);
    assert!(output[1].report.json().encode().contains("message_aborted"));
    assert!(parser.finish().unwrap().is_none());
}

#[test]
fn ua_abort_with_sequence_gap_rejects_and_requires_cut() {
    let mut parser = ua_parser(4);
    let (mut at, mut output) = (0, Vec::new());
    feed(
        &mut parser,
        &mut at,
        &ua(7, 1, 42, 1, b'C', &[0]),
        &mut output,
    )
    .unwrap();
    let error = feed(
        &mut parser,
        &mut at,
        &ua(7, 1, 42, 3, b'A', &[]),
        &mut output,
    )
    .unwrap_err();
    assert_eq!(error.field, "ua_sequence");
    let error = feed(
        &mut parser,
        &mut at,
        &ua(7, 2, 42, 4, b'F', &[0, 1]),
        &mut output,
    )
    .unwrap_err();
    assert_eq!(error.field, "continuation_requires_cut");
    assert!(output.is_empty());
    parser.cut("test_abort_sequence_boundary").unwrap();
    feed(
        &mut parser,
        &mut at,
        &ua(7, 2, 42, 4, b'F', &[0, 1]),
        &mut output,
    )
    .unwrap();
    assert_eq!(output.len(), 1);
}

#[test]
fn ua_token_change_cannot_resume_rejected_assembly() {
    let mut parser = ua_parser(8);
    let (mut at, mut output) = (0, Vec::new());
    feed(
        &mut parser,
        &mut at,
        &ua(7, 1, 42, 1, b'C', &[0]),
        &mut output,
    )
    .unwrap();
    let error = feed(
        &mut parser,
        &mut at,
        &ua(7, 1, 43, 2, b'C', &[1]),
        &mut output,
    )
    .unwrap_err();
    assert_eq!(error.field, "ua_token");
    let error = feed(
        &mut parser,
        &mut at,
        &ua(7, 1, 42, 3, b'F', &[1]),
        &mut output,
    )
    .unwrap_err();
    assert_eq!(error.field, "continuation_requires_cut");
    assert!(output.is_empty());
    parser.cut("test_token_boundary").unwrap();
    feed(
        &mut parser,
        &mut at,
        &ua(7, 2, 43, 3, b'F', &[0, 1]),
        &mut output,
    )
    .unwrap();
    assert_eq!(output[0].report.evidence.packets().len(), 1);
}

const UA_NONE: &[u8] = b"http://opcfoundation.org/UA/SecurityPolicy#None";

fn ua_request_body(id: u16) -> Vec<u8> {
    let mut body = vec![1, 0];
    body.extend_from_slice(&id.to_le_bytes());
    body.extend_from_slice(&[0, 0]); // null authentication token
    body.extend_from_slice(&0i64.to_le_bytes());
    body.extend_from_slice(&1u32.to_le_bytes());
    body.extend_from_slice(&0u32.to_le_bytes());
    body.extend_from_slice(&(-1i32).to_le_bytes());
    body.extend_from_slice(&0u32.to_le_bytes());
    body.extend_from_slice(&[0, 0, 0]); // null additional header
    match id {
        631 => {
            body.extend_from_slice(&0u64.to_le_bytes());
            body.extend_from_slice(&3u32.to_le_bytes());
            body.extend_from_slice(&0i32.to_le_bytes()); // zero Read nodes
        }
        446 => {
            for value in [0u32, 1, 1] {
                // protocol version, Renew, None
                body.extend_from_slice(&value.to_le_bytes());
            }
            body.extend_from_slice(&(-1i32).to_le_bytes()); // nonce
            body.extend_from_slice(&60000u32.to_le_bytes());
        }
        452 => {} // CloseSecureChannelRequest
        _ => panic!("unexpected fixture service"),
    }
    body
}
fn ua_open(channel: u32, sequence: u32, policy: &[u8], null_security: bool) -> Vec<u8> {
    let mut bytes = Vec::from(*b"OPNF");
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&channel.to_le_bytes());
    bytes.extend_from_slice(&(policy.len() as i32).to_le_bytes());
    bytes.extend_from_slice(policy);
    let empty = if null_security { -1i32 } else { 0 };
    bytes.extend_from_slice(&empty.to_le_bytes());
    bytes.extend_from_slice(&empty.to_le_bytes());
    bytes.extend_from_slice(&sequence.to_le_bytes());
    bytes.extend_from_slice(&2u32.to_le_bytes());
    bytes.extend_from_slice(&ua_request_body(446));
    let len = bytes.len() as u32;
    bytes[4..8].copy_from_slice(&len.to_le_bytes());
    bytes
}
fn ua_close(channel: u32, sequence: u32) -> Vec<u8> {
    let mut bytes = ua(channel, 3, 42, sequence, b'F', &ua_request_body(452));
    bytes[..3].copy_from_slice(b"CLO");
    bytes
}

#[test]
fn ua_renewal_and_close_share_channel_sequence_across_pages() {
    let mut parser = ua_parser(256);
    let body = ua_request_body(631);
    let mut bytes = ua(7, 1, 42, 1, b'F', &body);
    bytes.extend_from_slice(&ua_open(7, 2, UA_NONE, true));
    bytes.extend_from_slice(&ua(7, 3, 43, 3, b'F', &body));
    bytes.extend_from_slice(&ua_close(7, 4));
    let (mut at, mut output) = (0, Vec::new());
    for page in bytes.chunks(5) {
        feed(&mut parser, &mut at, page, &mut output).unwrap();
    }
    assert_eq!(output.len(), 4);
    assert_eq!(output[0].report.evidence.data(), body);
    assert_eq!(output[2].report.evidence.data(), body);
    assert!(output[1].report.json().encode().contains("sequence_number"));
    assert!(parser.finish().unwrap().is_none());
}

#[test]
fn ua_open_and_close_bad_sequences_require_cut_and_discard_pending_msg() {
    for kind in [b"OPN", b"CLO"] {
        for sequence in [0, 1, 3] {
            // reorder, reuse, gap
            let mut parser = ua_parser(256);
            let (mut at, mut output) = (0, Vec::new());
            feed(
                &mut parser,
                &mut at,
                &ua(7, 1, 42, 1, b'C', &[0]),
                &mut output,
            )
            .unwrap();
            let bad = if kind == b"OPN" {
                ua_open(7, sequence, UA_NONE, true)
            } else {
                ua_close(7, sequence)
            };
            let error = feed(&mut parser, &mut at, &bad, &mut output).unwrap_err();
            assert_eq!(error.field, "ua_sequence");
            assert_eq!(
                error.offset,
                if kind == b"OPN" {
                    (24 + UA_NONE.len()) as u64
                } else {
                    16
                }
            );
            let next = ua(7, 1, 42, 2, b'F', &[1]);
            let error = feed(&mut parser, &mut at, &next, &mut output).unwrap_err();
            assert_eq!(error.field, "continuation_requires_cut");
            assert!(output.is_empty());
            parser.cut("test_open_close_sequence_boundary").unwrap();
            let body = ua_request_body(631);
            feed(
                &mut parser,
                &mut at,
                &ua(7, 9, 42, 20, b'F', &body),
                &mut output,
            )
            .unwrap();
            assert_eq!(output.len(), 1);
            assert_eq!(output[0].report.evidence.data(), body);
            assert_eq!(output[0].report.evidence.packets().len(), 1);
        }
    }
}

#[test]
fn ua_open_keeps_channel_and_request_assembly_scopes_distinct() {
    let mut parser = ua_parser(256);
    let (mut at, mut output) = (0, Vec::new());
    let body = ua_request_body(631);
    for bytes in [
        ua(7, 1, 42, 10, b'C', &body[..3]),
        ua_open(8, 70, UA_NONE, false),
        ua_open(7, 11, UA_NONE, true),
        ua(7, 1, 42, 12, b'F', &body[3..]),
        ua(8, 3, 99, 71, b'F', &body),
    ] {
        feed(&mut parser, &mut at, &bytes, &mut output).unwrap();
    }
    assert_eq!(output.len(), 4);
    assert_eq!(output[2].report.evidence.data(), body);
    assert_eq!(output[2].report.evidence.packets().len(), 2);
    assert!(parser.finish().unwrap().is_none());
}

#[test]
fn ua_opaque_open_and_context_do_not_admit_plaintext_sequence() {
    let mut parser = ua_parser(256);
    let (mut at, mut output) = (0, Vec::new());
    let body = ua_request_body(631);
    feed(
        &mut parser,
        &mut at,
        &ua(7, 1, 42, 1, b'F', &body),
        &mut output,
    )
    .unwrap();
    let opaque = ua_open(
        7,
        800,
        b"http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256",
        true,
    );
    feed(&mut parser, &mut at, &opaque, &mut output).unwrap();
    feed(
        &mut parser,
        &mut at,
        &ua(7, 3, 42, 2, b'F', &body),
        &mut output,
    )
    .unwrap();
    assert_eq!(output.len(), 3);
    let json = output[1].report.json().encode();
    assert!(json.contains("secure_payload_requires_explicit_crypto_context"));
    assert!(!json.contains("sequence_number"));
    assert!(!json.contains("service_header"));
    let mut parser = Parser::new("opcua_tcp", Limits::default(), Context::default()).unwrap();
    let (mut at, mut output) = (0, Vec::new());
    for bytes in [
        ua_open(7, 800, UA_NONE, true),
        ua_close(7, 9),
        ua(7, 3, 42, 42, b'F', &body),
    ] {
        feed(&mut parser, &mut at, &bytes, &mut output).unwrap();
    }
    assert_eq!(output.len(), 3);
    assert!(output.iter().all(|item| item
        .report
        .json()
        .encode()
        .contains("secure_payload_requires_explicit_crypto_context")));
}

#[test]
fn ua_open_and_close_obey_channel_budget_and_sequence_wrap() {
    for first in [ua_open(7, 1, UA_NONE, true), ua_close(7, 1)] {
        let mut parser = Parser::new(
            "opcua_tcp",
            Limits {
                active: 1,
                ..Limits::default()
            },
            Context {
                ua_security_none: true,
                ..Context::default()
            },
        )
        .unwrap();
        let (mut at, mut output) = (0, Vec::new());
        feed(&mut parser, &mut at, &first, &mut output).unwrap();
        let error = feed(
            &mut parser,
            &mut at,
            &ua_open(8, 1, UA_NONE, true),
            &mut output,
        )
        .unwrap_err();
        assert_eq!(error.field, "ua_channels");
        parser.cut("test_channel_budget_boundary").unwrap();
        feed(
            &mut parser,
            &mut at,
            &ua_open(8, 1, UA_NONE, true),
            &mut output,
        )
        .unwrap();
    }
    let mut parser = ua_parser(256);
    let (mut at, mut output) = (0, Vec::new());
    for bytes in [
        ua(7, 1, 42, u32::MAX, b'F', &[0, 1]),
        ua_open(7, 1, UA_NONE, true),
        ua_close(7, 2),
    ] {
        feed(&mut parser, &mut at, &bytes, &mut output).unwrap();
    }
    assert_eq!(output.len(), 3);
}
