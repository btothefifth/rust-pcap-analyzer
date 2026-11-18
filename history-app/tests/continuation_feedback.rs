//! Tiny capture -> sealed history -> actual application consumer regressions.
#[path = "../../tests/support/tiny_capture.rs"]
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
    consume_with_limits(
        protocol,
        payload,
        page_bytes,
        Limits {
            retained_bytes,
            ..Limits::default()
        },
    )
}

fn consume_with_limits(
    protocol: &str,
    payload: &[u8],
    page_bytes: usize,
    limits: Limits,
) -> (pcap_evidence::Result<()>, String) {
    consume_packets(protocol, &[payload], page_bytes, limits)
}

fn consume_packets(
    protocol: &str,
    pieces: &[&[u8]],
    page_bytes: usize,
    limits: Limits,
) -> (pcap_evidence::Result<()>, String) {
    let temp = Temp::new();
    let mut frames = vec![tcp(false, 100, 0, 2, &[])];
    let mut length = 0;
    for &piece in pieces {
        frames.push(tcp(false, 101 + length as u32, 0, 0x18, piece));
        length += piece.len();
    }
    let source = temp.source(&frames);
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
        end: length as i64,
        page_bytes,
        max_output_bytes: 1024 * 1024,
        protocol: protocol.into(),
        ua_security_none: protocol == "opcua_tcp",
    };
    let mut output = Vec::new();
    let result = analyze(
        &mut history,
        &request,
        limits,
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
fn empty_cotp_fragment_is_incomplete_until_eot_in_actual_history_consumer() {
    for page_bytes in [1, 7, 64] {
        let mut payload = vec![3, 0, 0, 7, 2, 0xf0, 0];
        let (result, output) = consume("iso_cotp", &payload, 2, page_bytes);
        result.unwrap();
        assert_eq!(
            output
                .matches("\"kind\":\"application.incomplete\"")
                .count(),
            1
        );
        assert!(!output.contains("protocol.message"));
        assert!(output.contains("analysis.complete"));

        payload.extend_from_slice(&[3, 0, 0, 9, 2, 0xf0, 0x80, 5, 0]);
        let (result, output) = consume("iso_cotp", &payload, 2, page_bytes);
        result.unwrap();
        assert_eq!(output.matches("\"kind\":\"protocol.message\"").count(), 1);
        assert!(!output.contains("application.incomplete"));
        assert!(output.contains("analysis.complete"));
    }
}

#[test]
fn cotp_connection_change_aborts_actual_history_consumer_with_empty_pending_data() {
    for kind in [0xe0, 0xd0, 0x80, 0xc0] {
        for page_bytes in [1, 64] {
            let payload = [3, 0, 0, 7, 2, 0xf0, 0, 3, 0, 0, 11, 6, kind, 0, 0, 0, 1, 0];
            let (result, output) = consume("iso_cotp", &payload, 2, page_bytes);
            assert_eq!(result.unwrap_err().field, "cotp_connection_boundary");
            assert!(output.contains("analysis.aborted"));
            assert!(!output.contains("analysis.complete"));
            assert!(!output.contains("protocol.message"));
        }
    }
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

#[test]
fn modbus_mask_write_keeps_both_echo_roles_across_history_pages() {
    let adu = [0, 1, 0, 0, 0, 8, 1, 22, 0, 8, 0xff, 0, 0, 1];
    for page in [1, 5, 64] {
        let (result, output) = consume("modbus", &adu, 1024, page);
        result.unwrap();
        assert!(output.contains("unresolved_role"));
        assert_eq!(output.matches("and_mask").count(), 2);
        assert!(output.contains("analysis.complete"));
    }
}

#[test]
fn history_modbus_nested_interpretations_obey_field_budget() {
    let adu = [0, 1, 0, 0, 0, 8, 1, 22, 0, 8, 0xff, 0, 0, 1];
    for page in [1, 3, adu.len()] {
        for (fields, elements, spans, decoded) in [
            (1, 1, 1, 0),
            (8, 2, 8, 1),
            (15, 4, 16, 1),
            (16, 3, 16, 1),
            (16, 4, 13, 1),
            (16, 4, 14, 1),
            (16, 4, 15, 1),
            (16, 4, 16, 2),
        ] {
            let (result, output) = consume_with_limits(
                "modbus",
                &adu,
                page,
                Limits {
                    fields,
                    elements,
                    spans,
                    ..Limits::default()
                },
            );
            result.unwrap();
            assert!(output.contains("analysis.complete"));
            assert_eq!(
                output.matches("and_mask").count(),
                decoded,
                "{fields}/{elements}/{spans}, page {page}"
            );
            if spans == 13 {
                assert!(output.contains(r#""code":"semantic_tail_spans""#));
                let digest = pcap_evidence::sha256::hex(&pcap_evidence::sha256::digest(&adu[8..]));
                let expected = format!(
                    r#""undecoded_tail":{{"range":{{"start":"8","end":"14"}},"evidence":{{"sha256":"{digest}","spans":[]}}}}"#
                );
                assert!(output.contains(&expected), "limited v1 tail: {output}");
            }
            assert_eq!(output.contains("limit_exceeded"), decoded < 2);
        }
    }
}

#[test]
fn modbus_history_message_quota_is_shared_across_pages() {
    let adu = [0, 1, 0, 0, 0, 8, 1, 22, 0, 8, 0xff, 0, 0, 1];
    for count in [2, 3] {
        let payload = adu.repeat(count);
        let mut reference = None;
        for page in [1, adu.len(), payload.len()] {
            let (result, output) = consume_with_limits(
                "modbus",
                &payload,
                page,
                Limits {
                    elements: 2,
                    ..Limits::default()
                },
            );
            assert_eq!(output.matches("\"kind\":\"protocol.message\"").count(), 2);
            if count == 2 {
                result.unwrap();
                assert!(output.contains("analysis.complete"));
            } else {
                assert_eq!(result.unwrap_err().field, "messages_per_feed");
                assert!(output.contains("analysis.aborted"));
                assert!(output.contains("\"consumed_until\":\"28\""));
            }
            assert_eq!(reference.get_or_insert_with(|| output.clone()), &output);
        }
    }
}

#[test]
fn history_drains_a_complete_frame_before_charging_later_packet_spans() {
    let adu = [0, 1, 0, 0, 0, 3, 1, 0x83, 2];
    for spans in [1, 2, 3] {
        let mut expected = None;
        for page in [1, 9, 14] {
            let (result, output) = consume_packets(
                "modbus",
                &[&adu[..4], &adu[4..], &adu[..5]],
                page,
                Limits {
                    spans,
                    ..Limits::default()
                },
            );
            if spans == 1 {
                assert_eq!(result.unwrap_err().field, "stream_buffer_spans");
                assert!(!output.contains("protocol.message"));
            } else {
                result.unwrap();
                assert_eq!(output.matches("protocol.message").count(), 1);
                assert!(output.contains("application.incomplete"));
            }
            assert_eq!(expected.get_or_insert_with(|| output.clone()), &output);
        }
    }
}

#[test]
fn a_sparse_selection_obeys_the_same_work_limit_at_any_page_size() {
    let temp = Temp::new();
    let source = temp.source(&[tcp(false, 100, 0, 2, &[]), tcp(false, 101, 0, 0x18, b"abc")]);
    let workspace = temp.0.join("history");
    let config = Config {
        max_query_work: 4096,
        ..Config::default()
    };
    analyze_file(&source, &workspace, config, &Cancellation::default()).unwrap();
    let mut history = History::open(&source, &workspace).unwrap();
    let generation = history.generations(None, 10).unwrap()[0];
    // A one-byte query before the only placement skips to its start. A
    // one-byte query after it covers the rest of the selected gap in one page.
    for (start, end, gap_end) in [(-4090, 3, 0), (3, 4099, 4099)] {
        let page = history.evidence_page(generation, 0, start, end, 1).unwrap();
        assert_eq!(page.len(), 1);
        assert_eq!(
            (page[0].status.as_str(), page[0].start, page[0].end),
            ("gap", start, gap_end)
        );
    }
    for length in [4096, 4097] {
        let mut expected = None;
        for page_bytes in [1, 64, 4096] {
            let request = Request {
                generation,
                direction: 0,
                start: 3,
                end: 3 + length,
                page_bytes,
                max_output_bytes: 8192,
                protocol: "modbus".into(),
                ua_security_none: false,
            };
            let mut output = Vec::new();
            let result = analyze(
                &mut history,
                &request,
                Limits::default(),
                &mut output,
                &AtomicBool::new(false),
            );
            let report = String::from_utf8(output).unwrap();
            if length == 4096 {
                result.unwrap();
                assert_eq!(
                    report.matches(r#""kind":"application.boundary""#).count(),
                    1
                );
                assert!(report.contains(r#""start":"3","end":"4099""#));
                assert!(report.contains("analysis.complete"));
            } else {
                assert_eq!(result.unwrap_err().field, "history_app_range_work");
                assert!(report.contains("analysis.aborted"));
                assert!(report.contains(r#""consumed_until":"3""#));
            }
            assert_eq!(expected.get_or_insert_with(|| report.clone()), &report);
        }
    }
}

fn history_with_gap(config: Config) -> (Temp, History, [u8; 32]) {
    let temp = Temp::new();
    let source = temp.source(&[
        tcp(false, 100, 0, 2, &[]),
        tcp(false, 101, 0, 0x18, &[10, 20]),
        tcp(false, 105, 0, 0x18, &[0, 1, 0, 0, 0, 4, 1, 24, 0, 7]),
    ]);
    let workspace = temp.0.join("history");
    analyze_file(&source, &workspace, config, &Cancellation::default()).unwrap();
    let mut history = History::open(&source, &workspace).unwrap();
    let generation = history.generations(None, 10).unwrap()[0];
    (temp, history, generation)
}

#[test]
fn mixed_sparse_pages_fit_the_work_limit_without_changing_the_event_chain() {
    let (_temp, mut history, generation) = history_with_gap(Config {
        max_query_work: 512,
        ..Config::default()
    });
    assert_eq!(
        history.range(generation, 0, 0, 512).unwrap_err().field,
        "query_work"
    );
    assert_eq!(
        history
            .evidence_range(generation, 0, 0, 512)
            .unwrap_err()
            .field,
        "query_work"
    );
    for (end, budget) in [(512, 512), (120, 127)] {
        history.config.max_query_work = budget;
        let mut reference = None;
        for page_bytes in [1, 16, 512] {
            let request = Request {
                generation,
                direction: 0,
                start: 0,
                end,
                page_bytes,
                max_output_bytes: 65536,
                protocol: "modbus".into(),
                ua_security_none: false,
            };
            let mut output = Vec::new();
            let result = analyze(
                &mut history,
                &request,
                Limits::default(),
                &mut output,
                &AtomicBool::new(false),
            );
            let events = String::from_utf8(output).unwrap();
            if end == 512 {
                result.unwrap();
                assert_eq!(events.matches(r#""kind":"protocol.message""#).count(), 1);
                assert!(events.contains(r#""start":"14","end":"512""#));
                assert!(events.contains("analysis.complete"));
            } else {
                assert_eq!(result.unwrap_err().field, "query_work");
                assert!(events.contains(r#""consumed_until":"0""#));
            }
            assert_eq!(reference.get_or_insert_with(|| events.clone()), &events);
        }
    }
}

#[test]
fn cancellation_from_the_event_writer_aborts_at_the_published_prefix() {
    use std::io::{self, Write};
    use std::sync::atomic::Ordering;

    struct CancelOnEvent<'a> {
        flag: &'a AtomicBool,
        trigger: String,
        output: io::BufWriter<Vec<u8>>,
    }
    impl Write for CancelOnEvent<'_> {
        fn write(&mut self, line: &[u8]) -> io::Result<usize> {
            self.output.write_all(line)?;
            if std::str::from_utf8(line).unwrap().contains(&self.trigger) {
                self.flag.store(true, Ordering::Relaxed);
            }
            Ok(line.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            self.output.flush()
        }
    }
    let (_temp, mut history, generation) = history_with_gap(Config::default());
    for (start, end, trigger, until) in [
        (4, 128, "protocol.message", 14),
        (4, 14, "protocol.message", 14),
        (4, 128, "application.boundary", 128),
        (0, 2, "application.incomplete", 2),
    ] {
        let request = Request {
            generation,
            direction: 0,
            start,
            end,
            page_bytes: 16,
            max_output_bytes: 65536,
            protocol: "modbus".into(),
            ua_security_none: false,
        };
        let cancel = AtomicBool::new(false);
        let mut writer = CancelOnEvent {
            flag: &cancel,
            trigger: format!(r#""kind":"{trigger}""#),
            output: io::BufWriter::with_capacity(1024, Vec::new()),
        };
        let result = analyze(
            &mut history,
            &request,
            Limits::default(),
            &mut writer,
            &cancel,
        );
        assert_eq!(result.unwrap_err().field, "history_app_cancelled");
        let events = std::str::from_utf8(writer.output.get_ref()).unwrap();
        let mut lines = events.lines().rev();
        let abort = lines.next().unwrap();
        assert!(abort.contains(r#""kind":"analysis.aborted""#));
        assert!(abort.contains(&format!(r#""consumed_until":"{until}""#)));
        assert!(lines.next().unwrap().contains(&writer.trigger));
        assert!(!events.contains("analysis.complete"));
    }
}

#[test]
fn a_paged_gap_emits_one_boundary_with_the_discarded_prefix() {
    let (_temp, mut history, generation) = history_with_gap(Config::default());
    for end in [4, 14] {
        let mut request = Request {
            generation,
            direction: 0,
            start: 0,
            end,
            page_bytes: 14,
            max_output_bytes: 1024 * 1024,
            protocol: "modbus".into(),
            ua_security_none: false,
        };
        let mut expected = None;
        for page in [14, 1, 3] {
            request.page_bytes = page;
            let mut output = Vec::new();
            analyze(
                &mut history,
                &request,
                Limits::default(),
                &mut output,
                &AtomicBool::new(false),
            )
            .unwrap();
            let report = std::str::from_utf8(&output).unwrap();
            assert_eq!(
                report.matches(r#""kind":"application.boundary""#).count(),
                1
            );
            assert!(report.contains(r#""start":"2","end":"4""#));
            assert!(
                report.contains(&pcap_evidence::sha256::hex(&pcap_evidence::sha256::digest(
                    &[10, 20]
                )))
            );
            assert_eq!(report.contains("protocol.message"), end == 14);
            request.max_output_bytes = output.len() as u64;
            assert_eq!(expected.get_or_insert_with(|| output.clone()), &output);
            if end == 14 {
                // Leave room for the boundary and abort, but not the next message.
                let lines: Vec<_> = report.split_inclusive('\n').collect();
                let mut capped = request.clone();
                capped.max_output_bytes = (lines[0].len() + lines[1].len() + 1024) as u64;
                let mut partial = Vec::new();
                let error = analyze(
                    &mut history,
                    &capped,
                    Limits::default(),
                    &mut partial,
                    &AtomicBool::new(false),
                )
                .unwrap_err();
                assert_eq!(error.field, "history_app_output");
                let last = std::str::from_utf8(&partial)
                    .unwrap()
                    .lines()
                    .last()
                    .unwrap();
                assert!(last.contains(r#""sequence":"3","kind":"analysis.aborted""#));
                assert!(last.contains(r#""consumed_until":"4""#));
            }
        }
    }
}

#[test]
fn partially_agreeing_observations_preserve_messages_across_pages_and_retries() {
    let temp = Temp::new();
    let adu = [0, 1, 0, 0, 0, 4, 1, 24, 0, 7];
    let first = [adu.as_slice(), &[1, 2, 3], &adu].concat();
    let mut second = first.clone();
    second[10] = 4;
    second[12] = 5;
    let source = temp.source(&[
        tcp(false, 100, 0, 2, &[]),
        tcp(false, 101, 0, 0x18, &first),
        tcp(false, 101, 0, 0x18, &second),
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
    let end = first.len() as i64;
    let mut reference = None;
    for (page_bytes, intervals) in [(1, 64), (23, 64), (23, 2)] {
        history.config.max_query_intervals = intervals;
        if intervals == 2 {
            assert_eq!(
                history
                    .evidence_range(generation, 0, 0, end)
                    .unwrap_err()
                    .field,
                "query_evidence_references"
            );
        }
        let request = Request {
            generation,
            direction: 0,
            start: 0,
            end,
            page_bytes,
            max_output_bytes: 65536,
            protocol: "modbus".into(),
            ua_security_none: false,
        };
        let mut output = Vec::new();
        analyze(
            &mut history,
            &request,
            Limits::default(),
            &mut output,
            &AtomicBool::new(false),
        )
        .unwrap();
        let events = std::str::from_utf8(&output).unwrap();
        assert_eq!(events.matches(r#""kind":"protocol.message""#).count(), 2);
        for (a, b) in [(10, 11), (12, 13)] {
            assert!(events.contains(&format!(
                r#""start":"{a}","end":"{b}","transport_status":"conflicting_bytes""#
            )));
        }
        assert_eq!(reference.get_or_insert_with(|| output.clone()), &output);
    }
}

#[test]
fn completion_output_limit_flushes_accepted_events_to_the_underlying_writer() {
    let (_temp, mut history, generation) = history_with_gap(Config::default());
    let mut request = Request {
        generation,
        direction: 0,
        start: 0,
        end: 14,
        page_bytes: 14,
        max_output_bytes: 65536,
        protocol: "modbus".into(),
        ua_security_none: false,
    };
    let cancel = AtomicBool::new(false);
    let mut complete = Vec::new();
    analyze(
        &mut history,
        &request,
        Limits::default(),
        &mut complete,
        &cancel,
    )
    .unwrap();
    let chain = std::str::from_utf8(&complete).unwrap();
    let terminal = chain.lines().last().unwrap();
    assert!(terminal.contains(r#""kind":"analysis.complete""#));
    let prefix_len = chain.len() - terminal.len() - 1;

    for cap in [prefix_len, complete.len() - 1, complete.len()] {
        request.max_output_bytes = cap as u64;
        let mut writer = std::io::BufWriter::with_capacity(2 * complete.len(), Vec::new());
        let result = analyze(
            &mut history,
            &request,
            Limits::default(),
            &mut writer,
            &cancel,
        );
        let expected = if cap == complete.len() {
            result.unwrap();
            &complete[..]
        } else {
            assert_eq!(result.unwrap_err().field, "history_app_output");
            &complete[..prefix_len]
        };
        assert!(writer.buffer().is_empty());
        assert_eq!(writer.get_ref().as_slice(), expected);
    }
}
