use pcap_evidence::{
    engine::{self, Config},
    report,
};
fn capture(name: &str) -> Vec<u8> {
    std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("fixtures/semantics")
            .join(name),
    )
    .unwrap()
}
#[test]
fn snapshot_modbus_semantic_fields_reach_actual_report() {
    let a = engine::analyze(&capture("modbus_bits_valid.pcap"), Config::default()).unwrap();
    assert!(a.transactions.iter().any(|t| t.status == "candidate_pair"));
    let j = report::analysis(&a, false).encode();
    assert!(j.contains("pcap-evidence.modbus-alternatives.v1"));
    assert!(j.contains("starting_address_zero_based"));
    assert!(j.contains("packed_lsb_first"));
}
#[test]
fn snapshot_padding_bad_response_does_not_pair_as_consistent() {
    let a = engine::analyze(&capture("modbus_bits_bad_padding.pcap"), Config::default()).unwrap();
    assert!(a
        .transactions
        .iter()
        .any(|t| t.status == "inconsistent_response"));
    assert!(!a.transactions.iter().any(|t| t.status == "candidate_pair"));
}
#[test]
fn snapshot_dnp_split_reordered_duplicate_retains_semantic_objects() {
    let a = engine::analyze(&capture("dnp3_split_valid.pcap"), Config::default()).unwrap();
    let j = report::analysis(&a, false).encode();
    assert!(j.contains("object_semantic_subset"));
    assert!(j.contains("function_name"));
    assert!(j.contains("control_semantics"));
    assert!(j.contains("confirmed_user_data") || j.contains("unconfirmed_user_data"));
    assert!(j.contains("\"broadcast\":false"));
    assert!(j.contains("message_object_semantic_subset"));
    assert!(j.contains("lsb_zero_bit_position"));
    assert!(j.contains("\"value\":\"9\""));
}
#[test]
fn snapshot_dnp_gap_or_conflict_cannot_create_response_values() {
    for name in ["dnp3_split_gap.pcap", "dnp3_split_conflict.pcap"] {
        let a = engine::analyze(&capture(name), Config::default()).unwrap();
        let j = report::analysis(&a, false).encode();
        assert!(!j.contains("lsb_zero_bit_position"));
        assert!(a.has_diagnostics());
    }
}
#[test]
fn snapshot_semantic_extension_output_is_deterministic() {
    let b = capture("dnp3_split_valid.pcap");
    let a = engine::analyze(&b, Config::default()).unwrap();
    let c = engine::analyze(&b, Config::default()).unwrap();
    assert_eq!(report::analysis(&a, false), report::analysis(&c, false));
}

#[test]
fn modbus_read_mapping_retains_conditional_boundary_and_both_witnesses() {
    let full = capture("modbus_bits_valid.pcap");
    // Omit the three handshake records and restore capture order by sequence
    // for the two response fragments, so midstream alignment is observable.
    let mut mid = [&full[..24], &full[234..316], &full[392..], &full[316..392]].concat();
    // Keep the original monotonic record timestamps after the permutation.
    mid[106..114].copy_from_slice(&full[316..324]);
    mid[181..189].copy_from_slice(&full[392..400]);
    for (bytes, status) in [
        (&full, "candidate_pair"),
        (&mid, "candidate_unverified_boundary"),
    ] {
        let analysis = engine::analyze(bytes, Config::default()).unwrap();
        assert!(
            analysis.transactions.iter().any(|t| t.status == status),
            "{status}"
        );
        let json = report::analysis(&analysis, false).encode();
        assert!(json.contains(&format!("\"read_mapping\":{{\"status\":\"{status}\"")));
        assert!(json.contains("\"quantity\":9"));
        assert!(json.contains("\"padding_checked\":true"));
    }
}

#[test]
fn changed_modbus_references_cannot_retarget_a_mapping() {
    let mut analysis =
        engine::analyze(&capture("modbus_bits_valid.pcap"), Config::default()).unwrap();
    let index = analysis
        .transactions
        .iter()
        .position(|t| t.status == "candidate_pair")
        .unwrap();
    let reference = analysis.transactions[index].requests[0];
    let response = analysis.transactions[index].responses[0];
    analysis.transactions[index].requests[0] = response;
    let report = report::analysis(&analysis, false).encode();
    assert!(!report.contains("read_mapping"));
    assert!(report.contains("\"transaction_candidates\":[]"));
    analysis.transactions[index].requests[0] = reference;
    assert!(report::analysis(&analysis, false)
        .encode()
        .contains("read_mapping"));
    let other = engine::analyze(&capture("modbus_bits_valid.pcap"), Config::default()).unwrap();
    analysis.transactions[index] = other.transactions[index].clone();
    assert!(!report::analysis(&analysis, false)
        .encode()
        .contains("read_mapping"));
}

#[test]
fn modbus_decoder_failure_applies_only_to_its_capture_and_generation() {
    use pcap_evidence::{correlate::transactions, Error, Limits};
    let analysis = engine::analyze(&capture("modbus_bits_valid.pcap"), Config::default()).unwrap();
    let mut failure = engine::ApplicationAnalysis {
        flow: analysis.transactions[0].flow,
        direction: 0,
        protocol: "modbus",
        data: engine::ApplicationData::ModbusFailed {
            capture: [0; 32],
            error: Error::limit("test"),
        },
    };
    let mut observations = analysis.applications().to_vec();
    observations.push(failure.clone());
    assert!(transactions(&observations, &Limits::default())
        .unwrap()
        .iter()
        .any(|tx| tx.status == "candidate_pair"));
    failure.data = engine::ApplicationData::ModbusFailed {
        capture: analysis.capture_sha256,
        error: Error::limit("test"),
    };
    observations.push(failure);
    assert!(!transactions(&observations, &Limits::default())
        .unwrap()
        .iter()
        .any(|tx| tx.status == "candidate_pair"));
}

#[test]
fn moving_a_pair_to_another_flow_or_capture_invalidates_its_mapping() {
    let mut snapshot = engine::analyze(
        &capture("modbus_generation_overlap.pcap"),
        Default::default(),
    )
    .unwrap();
    let has_mapping =
        |s: &engine::Analysis| report::analysis(s, false).encode().contains("read_mapping");
    assert!(has_mapping(&snapshot));
    let original = snapshot.capture_sha256;
    snapshot.capture_sha256 = [1; 32];
    assert!(!has_mapping(&snapshot));
    snapshot.capture_sha256 = original;
    let pair = snapshot
        .transactions
        .iter_mut()
        .find(|t| t.status == "candidate_pair")
        .unwrap();
    assert_ne!(pair.flow, 0);
    pair.flow = 0;
    assert!(!has_mapping(&snapshot));
}

#[test]
fn partial_mbap_requires_one_capture_to_compete_with_a_pair() {
    use pcap_evidence::{
        correlate, modbus,
        provenance::{EvidenceBytes, PacketId},
        tcp::{StreamChunk, StreamResult},
        Limits,
    };
    let snapshot = engine::analyze(&capture("modbus_bits_valid.pcap"), Default::default()).unwrap();
    let pair = snapshot
        .transactions
        .iter()
        .find(|t| t.status == "candidate_pair")
        .unwrap();
    let app = &snapshot.applications()[pair.requests[0].application];
    let engine::ApplicationData::Modbus(data) = &app.data else {
        unreachable!()
    };
    let raw = &data.messages[pair.requests[0].message].raw;
    let first = raw.spans()[0].packet;
    for (capture, expect_pair) in [([7; 32], true), (first.capture, false)] {
        let mut bytes = raw.slice(0..2).unwrap();
        bytes
            .append(
                &EvidenceBytes::from_packet(&raw.data()[2..8], PacketId { capture, ..first }, 56),
                64,
            )
            .unwrap();
        let stream = StreamResult {
            base_sequence: None,
            anchored_by_syn: true,
            chunks: vec![StreamChunk { offset: 0, bytes }],
            gaps: vec![],
            conflicts: vec![],
            duplicate_observed_bytes: 0,
        };
        let result = modbus::decode(&stream, modbus::Role::Request, &Limits::default()).unwrap();
        assert_eq!(result.issues[0].code, "truncated_modbus_adu");
        let mut apps = snapshot.applications().to_vec();
        apps.push(engine::ApplicationAnalysis {
            data: engine::ApplicationData::Modbus(result),
            ..app.clone()
        });
        let groups = correlate::transactions(&apps, &Limits::default()).unwrap();
        assert_eq!(
            groups.iter().any(|t| t.status == "candidate_pair"),
            expect_pair
        );
    }
}

#[test]
fn snapshot_line_enforces_a_shared_byte_budget_across_decoded_messages() {
    use pcap_evidence::{detection, json::Json};
    for fixture in ["modbus_fc23_split.pcap", "dnp3_split_valid.pcap"] {
        let analysis = engine::analyze(&capture(fixture), Config::default()).unwrap();
        for include in [false, true] {
            let mut expected = report::analysis(&analysis, include);
            let snapshot = expected.encode_bounded_line(1 << 22).unwrap();
            assert_eq!(
                report::snapshot_line(&analysis, include, snapshot.len()).unwrap(),
                snapshot
            );
            assert_eq!(
                report::snapshot_line(&analysis, include, snapshot.len() - 1)
                    .unwrap_err()
                    .field,
                "report_bytes"
            );
            let Json::Object(fields) = &mut expected else {
                unreachable!()
            };
            fields.push((
                "protocol_detection",
                detection::analysis_json(&analysis).unwrap(),
            ));
            let line = expected.encode_bounded_line(1 << 22).unwrap();
            assert_eq!(
                report::analysis_line(&analysis, include, line.len()).unwrap(),
                line
            );
            assert_eq!(
                report::analysis_line(&analysis, include, line.len() - 1)
                    .unwrap_err()
                    .field,
                "report_bytes"
            );
            if fixture.starts_with("modbus") {
                let offsets: Vec<_> = line
                    .match_indices("\"semantic_subset\":")
                    .map(|(i, _)| i)
                    .collect();
                assert_eq!(offsets.len(), 2);
                // Both individual ADUs fit. The remaining capture-wide allowance
                // runs out while the second semantic report is being encoded.
                let limit = offsets[1] + 32;
                assert_eq!(
                    report::analysis_line(&analysis, include, limit)
                        .unwrap_err()
                        .field,
                    "report_bytes"
                );
            }
        }
    }
}
