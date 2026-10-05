use pcap_evidence::{
    json::Json,
    provenance::{EvidenceBytes, PacketId},
    sha256,
};
use pcap_evidence_product::deep::{self, iec104, iso::CotpSession, opcua, Limits, Report};

fn evidence(bytes: &[u8], frame: u64) -> EvidenceBytes {
    EvidenceBytes::from_packet(
        bytes,
        PacketId {
            capture: sha256::digest(b"nonbgp-feedback"),
            frame,
            record_offset: frame * 100,
        },
        0,
    )
}

#[test]
fn iec104_failed_report_preserves_session_state_in_both_directions() {
    let limits = Limits::default();
    let mut short = limits.clone();
    short.fields = 1;
    for direction in 0..=1 {
        let request = evidence(&[0x68, 4, 7, 0, 0, 0], 1);
        let confirmation = evidence(&[0x68, 4, 11, 0, 0, 0], 2);
        let mut session = iec104::Session::default();
        let before = session.json();
        assert!(session.observe(direction, &request, &short).is_err());
        assert_eq!(session.json(), before);
        let report = session
            .observe(1 - direction, &confirmation, &limits)
            .unwrap();
        assert!(report
            .notes
            .iter()
            .any(|n| n.code == "start_confirmation_without_request"));

        session.observe(direction, &request, &limits).unwrap();
        let report = session
            .observe(1 - direction, &confirmation, &limits)
            .unwrap();
        assert!(!report
            .notes
            .iter()
            .any(|n| n.code == "start_confirmation_without_request"));
        assert_eq!(session.active, Some(true));
        let before = session.json();
        let stop = evidence(&[0x68, 4, 19, 0, 0, 0], 3);
        assert!(session.observe(direction, &stop, &short).is_err());
        assert_eq!(session.json(), before);
        session.observe(direction, &stop, &limits).unwrap();
        assert_eq!(session.active, Some(false));
    }
}

#[test]
fn iec104_gap_invalidates_pending_start_requests_in_both_directions() {
    let limits = Limits::default();
    for direction in 0..=1 {
        let mut session = iec104::Session::default();
        session
            .observe(direction, &evidence(&[0x68, 4, 7, 0, 0, 0], 1), &limits)
            .unwrap();
        session.gap();
        assert_eq!(session.active, None);
        let confirmation = session
            .observe(
                1 - direction,
                &evidence(&[0x68, 4, 11, 0, 0, 0], 2),
                &limits,
            )
            .unwrap();
        assert!(confirmation
            .notes
            .iter()
            .any(|note| note.code == "start_confirmation_without_request"));
        assert!(session.tainted);
    }
}

#[test]
fn iec104_contiguous_and_post_gap_start_pairs_remain_observable() {
    let limits = Limits::default();
    for direction in 0..=1 {
        for gap_first in [false, true] {
            let mut session = iec104::Session::default();
            if gap_first {
                session.gap();
            }
            session
                .observe(direction, &evidence(&[0x68, 4, 7, 0, 0, 0], 1), &limits)
                .unwrap();
            let confirmation = session
                .observe(
                    1 - direction,
                    &evidence(&[0x68, 4, 11, 0, 0, 0], 2),
                    &limits,
                )
                .unwrap();
            assert!(!confirmation
                .notes
                .iter()
                .any(|note| note.code == "start_confirmation_without_request"));
            assert_eq!(session.active, Some(true));
            assert_eq!(session.tainted, gap_first);
        }
    }
}

fn dt(payload: &[u8], final_segment: bool, frame: u64) -> EvidenceBytes {
    let mut unit = vec![3, 0];
    unit.extend_from_slice(&((7 + payload.len()) as u16).to_be_bytes());
    unit.extend_from_slice(&[2, 0xf0, if final_segment { 0x80 } else { 0 }]);
    unit.extend_from_slice(payload);
    evidence(&unit, frame)
}

#[test]
fn cotp_interleaved_scopes_complete_independently_with_source_spans() {
    let mut session = CotpSession::new(Limits::default()).unwrap();
    assert!(session
        .push("A", &dt(b"A", false, 1), 1)
        .unwrap()
        .completed
        .is_none());
    let b = session
        .push("B", &dt(b"B", true, 2), 2)
        .unwrap()
        .completed
        .unwrap();
    assert_eq!(b.data(), b"B");
    assert!(b.validate());
    assert_eq!(b.packets().len(), 1);
    let ac = session
        .push("A", &dt(b"C", true, 3), 3)
        .unwrap()
        .completed
        .unwrap();
    assert_eq!(ac.data(), b"AC");
    assert!(ac.validate());
    assert_eq!(ac.packets().len(), 2);
    assert_eq!(
        session
            .push("A", &dt(b"D", true, 4), 4)
            .unwrap()
            .completed
            .unwrap()
            .data(),
        b"D"
    );
}

#[test]
fn cotp_gap_cuts_only_its_named_scope() {
    let mut session = CotpSession::new(Limits::default()).unwrap();
    session.push("A", &dt(b"A", false, 1), 1).unwrap();
    session.push("B", &dt(b"discard", false, 2), 2).unwrap();
    session.gap("B");
    assert_eq!(
        session
            .push("A", &dt(b"C", true, 3), 3)
            .unwrap()
            .completed
            .unwrap()
            .data(),
        b"AC"
    );
    let b = session
        .push("B", &dt(b"new", true, 4), 4)
        .unwrap()
        .completed
        .unwrap();
    assert_eq!(b.data(), b"new");
    assert_eq!(b.packets().len(), 1);
}

#[test]
fn cotp_rejected_push_does_not_advance_or_retain_a_scope_counter() {
    let mut limits = Limits::default();
    limits.active = 1;
    limits.retained_bytes = 2;
    let mut session = CotpSession::new(limits).unwrap();
    session.push("A", &dt(b"A", false, 1), 1).unwrap();
    assert!(session.push("B", &dt(b"B", true, 2), 2).is_err());
    assert!(session.push("A", &dt(b"too big", true, 3), 3).is_err());
    assert_eq!(
        session
            .push("A", &dt(b"C", true, 4), 4)
            .unwrap()
            .completed
            .unwrap()
            .data(),
        b"AC"
    );
    assert_eq!(
        session
            .push("B", &dt(b"B", true, 5), 5)
            .unwrap()
            .completed
            .unwrap()
            .data(),
        b"B"
    );
}

fn member<'a>(json: &'a Json, name: &str) -> Option<&'a Json> {
    let Json::Object(fields) = json else {
        panic!("expected object")
    };
    fields
        .iter()
        .find(|(key, _)| *key == name)
        .map(|(_, value)| value)
}

fn field<'a>(report: &'a Report, name: &str) -> &'a Json {
    &report
        .fields
        .iter()
        .find(|field| field.name == name)
        .unwrap()
        .value
}

fn write_response(header_diagnostic: &[u8], result_diagnostic: Option<&[u8]>) -> Vec<u8> {
    let mut body = vec![1, 0, 0xa4, 2]; // namespace 0, WriteResponse encoding 676
    body.extend_from_slice(&[0; 16]); // timestamp, request handle, status
    body.extend_from_slice(header_diagnostic);
    body.extend_from_slice(&2i32.to_le_bytes());
    for text in [b"en".as_slice(), b"text".as_slice()] {
        body.extend_from_slice(&(text.len() as i32).to_le_bytes());
        body.extend_from_slice(text);
    }
    body.extend_from_slice(&[0, 0, 0]); // null additional ExtensionObject
    body.extend_from_slice(&0i32.to_le_bytes()); // no result statuses
    body.extend_from_slice(&i32::from(result_diagnostic.is_some()).to_le_bytes());
    if let Some(diagnostic) = result_diagnostic {
        body.extend_from_slice(diagnostic);
    }
    body
}

#[test]
fn opcua_diagnostic_singleton_masks_name_the_correct_string_table_index() {
    // OPC 10000-6 5.2.2.12 Table 22: bit 0x04 is LocalizedText,
    // bit 0x08 is Locale. The indices themselves are retained, not resolved.
    for (mask, name, absent) in [
        (4, "localized_text", "locale"),
        (8, "locale", "localized_text"),
    ] {
        let diagnostic = [mask | 0x40, 0, 0, 0, 0, mask, 1, 0, 0, 0];
        let report = opcua::service(
            &evidence(&write_response(&diagnostic, None), 1),
            &Limits::default(),
        )
        .unwrap();
        assert!(report.notes.is_empty());
        let decoded = member(field(&report, "service_header"), "diagnostic").unwrap();
        assert_eq!(member(decoded, name), Some(&Json::from("0")));
        assert_eq!(member(decoded, absent), None);
        let inner = member(decoded, "inner").unwrap();
        assert_eq!(member(inner, name), Some(&Json::from("1")));
        assert_eq!(member(inner, absent), None);
    }
}

#[test]
fn opcua_diagnostic_wire_order_and_nested_result_indices_are_preserved() {
    // Locale precedes LocalizedText on the wire, despite mask-bit ordering.
    let diagnostic = [0x4c, 0, 0, 0, 0, 1, 0, 0, 0, 0x0c, 1, 0, 0, 0, 0, 0, 0, 0];
    let report = opcua::service(
        &evidence(&write_response(&diagnostic, Some(&diagnostic)), 1),
        &Limits::default(),
    )
    .unwrap();
    assert!(report.notes.is_empty());
    for decoded in [
        member(field(&report, "service_header"), "diagnostic").unwrap(),
        field(&report, "diagnostic[0]"),
    ] {
        assert_eq!(member(decoded, "locale"), Some(&Json::from("0")));
        assert_eq!(member(decoded, "localized_text"), Some(&Json::from("1")));
        let inner = member(decoded, "inner").unwrap();
        assert_eq!(member(inner, "locale"), Some(&Json::from("1")));
        assert_eq!(member(inner, "localized_text"), Some(&Json::from("0")));
    }
}

#[test]
fn opcua_complete_singleton_write_response_uses_explicit_security_context() {
    let mut body = vec![1, 0, 0xa4, 2];
    body.extend_from_slice(&[0; 16]);
    body.extend_from_slice(&[4, 0, 0, 0, 0]);
    body.extend_from_slice(&[1, 0, 0, 0, 1, 0, 0, 0, b'x']);
    body.extend_from_slice(&[0; 3]);
    body.extend_from_slice(&[0; 8]);
    assert_eq!(body.len(), 45);
    let mut chunk = Vec::from(*b"MSGF");
    chunk.extend_from_slice(&((24 + body.len()) as u32).to_le_bytes());
    chunk.extend_from_slice(&[0; 16]); // channel, token, sequence, request
    chunk.extend_from_slice(&body);
    let report = deep::decode(
        "opcua_tcp",
        &evidence(&chunk, 1),
        &deep::Context {
            ua_security_none: true,
            ..deep::Context::default()
        },
        &Limits::default(),
    )
    .unwrap();
    assert!(report.notes.is_empty());
    assert!(field(&report, "service")
        .encode()
        .contains("\"localized_text\":\"0\""));
    assert!(!field(&report, "service").encode().contains("\"locale\""));
}
