//! Identical numeric transaction/flow IDs remain scoped to source captures.
use pcap_evidence::{
    correlate,
    engine::{ApplicationAnalysis, ApplicationData},
    modbus::{self, Role},
    provenance::{EvidenceBytes, PacketId},
    tcp::{StreamChunk, StreamResult},
    Limits,
};

fn source(bytes: &[u8], capture: [u8; 32], frame: u64) -> EvidenceBytes {
    EvidenceBytes::from_packet(
        bytes,
        PacketId {
            capture,
            frame,
            record_offset: 100 * frame,
        },
        54,
    )
}
fn application(role: Role, capture: [u8; 32]) -> ApplicationAnalysis {
    let bytes: &[u8] = if role == Role::Request {
        &[0, 42, 0, 0, 0, 6, 1, 3, 0, 0, 0, 1]
    } else {
        &[0, 42, 0, 0, 0, 5, 1, 3, 2, 0, 9]
    };
    let input = StreamResult {
        base_sequence: Some(0),
        anchored_by_syn: true,
        chunks: vec![StreamChunk {
            offset: 0,
            bytes: source(bytes, capture, 1),
        }],
        gaps: vec![],
        conflicts: vec![],
        duplicate_observed_bytes: 0,
    };
    ApplicationAnalysis {
        flow: 0,
        direction: usize::from(role == Role::Response),
        protocol: "modbus",
        data: ApplicationData::Modbus(modbus::decode(&input, role, &Limits::default()).unwrap()),
    }
}

#[test]
fn modbus_transaction_candidates_separate_capture_identity_from_flow_numbers() {
    let request_a = application(Role::Request, [7; 32]);
    let response_a = application(Role::Response, [7; 32]);
    let request_b = application(Role::Request, [8; 32]);
    let response_b = application(Role::Response, [8; 32]);
    let cross =
        correlate::transactions(&[request_a.clone(), response_b.clone()], &Limits::default())
            .unwrap();
    assert_eq!(cross.len(), 2);
    assert!(cross.iter().all(|row| row.status != "candidate_pair"));
    let same = correlate::transactions(
        &[request_a, response_a, request_b, response_b],
        &Limits::default(),
    )
    .unwrap();
    assert_eq!(same.len(), 2);
    assert!(same.iter().all(|row| row.status == "candidate_pair"));
}

#[test]
fn mixed_or_absent_modbus_capture_scope_is_unclassified() {
    for absent in [false, true] {
        let mut request = application(Role::Request, [7; 32]);
        let ApplicationData::Modbus(result) = &mut request.data else {
            unreachable!()
        };
        let original = result.messages[0].raw.data().to_vec();
        let mut raw = EvidenceBytes::default();
        if !absent {
            raw.append(&source(&original[..8], [7; 32], 1), 64).unwrap();
            raw.append(&source(&original[8..], [8; 32], 2), 64).unwrap();
        }
        result.messages[0].raw = raw;
        let rows = correlate::transactions(
            &[request, application(Role::Response, [7; 32])],
            &Limits::default(),
        )
        .unwrap();
        assert!(rows.iter().all(|row| row.status != "candidate_pair"));
        assert!(rows
            .iter()
            .any(|row| row.reason == "modbus_transaction_capture_scope_invalid"));
    }
}
