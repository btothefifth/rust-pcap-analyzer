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

fn read_message(
    key: (u16, u8, u8),
    role: pcap_evidence::modbus::Role,
    frame: u64,
) -> pcap_evidence::modbus::ModbusMessage {
    use pcap_evidence::{
        modbus::{ModbusMessage, Role},
        provenance::{EvidenceBytes, PacketId},
    };
    let (tx, unit, function) = key;
    let [hi, lo] = tx.to_be_bytes();
    let mut adu = vec![hi, lo, 0, 0, 0, 6, unit, function];
    if role == Role::Request {
        adu.extend([0, 9, 0, 1]);
    } else {
        adu[5] = 5;
        adu.extend([2, 0, 42]);
    }
    let packet = PacketId {
        capture: [7; 32],
        frame,
        record_offset: frame * 100,
    };
    ModbusMessage::from_adu(EvidenceBytes::from_packet(&adu, packet, 54), role, 0, true).unwrap()
}

#[test]
fn edited_mbap_fields_compete_under_the_observed_key() {
    use pcap_evidence::{
        correlate::{transactions, MessageRef},
        engine::{ApplicationAnalysis, ApplicationData},
        modbus::{ModbusResult, Role},
        Limits,
    };

    let wire = (1, 2, 3);
    for peer in [(11, 2, 3), (1, 12, 3), (1, 2, 4)] {
        for role in [Role::Request, Role::Response] {
            let mut apps = Vec::new();
            for (direction, side) in [Role::Request, Role::Response].into_iter().enumerate() {
                let mut result = ModbusResult::default();
                let frame = direction as u64 + 1;
                result.messages.push(read_message(wire, side, frame));
                result.messages.push(read_message(peer, side, frame + 2));
                if side == role {
                    let mut edited = read_message(wire, side, 5);
                    (edited.transaction, edited.unit, edited.function) = peer;
                    result.messages.push(edited);
                }
                apps.push(ApplicationAnalysis {
                    flow: 0,
                    direction,
                    protocol: "modbus",
                    data: ApplicationData::Modbus(result),
                });
            }
            let rows = transactions(&apps, &Limits::default()).unwrap();
            let at = |application, message| MessageRef {
                application,
                message,
            };
            assert_eq!(rows.len(), 3);
            let pair = rows
                .iter()
                .find(|row| row.status == "candidate_pair")
                .unwrap();
            assert_eq!(pair.requests, [at(0, 1)]);
            assert_eq!(pair.responses, [at(1, 1)]);
            let ambiguous = rows.iter().find(|row| row.status == "ambiguous").unwrap();
            assert_eq!(ambiguous.reason, "competing_modbus_observation");
            assert_eq!(ambiguous.requests, [at(0, 0)]);
            assert_eq!(ambiguous.responses, [at(1, 0)]);
            let edited = rows
                .iter()
                .find(|row| row.status == "unclassified")
                .unwrap();
            assert_eq!(edited.reason, "modbus_mbap_metadata_mismatch");
            let witness = at(usize::from(role == Role::Response), 2);
            assert_eq!(
                edited
                    .requests
                    .iter()
                    .chain(&edited.responses)
                    .copied()
                    .collect::<Vec<_>>(),
                [witness]
            );
        }
    }
}

#[test]
fn edited_pdu_shape_is_classified_like_a_fresh_observation() {
    use pcap_evidence::{
        correlate::transactions,
        engine::{ApplicationAnalysis, ApplicationData},
        modbus::{ModbusMessage, ModbusResult, Role},
        provenance::EvidenceBytes,
        Limits,
    };
    let key = (1, 2, 3);
    for role in [Role::Request, Role::Response] {
        let good = read_message(key, role, 1);
        let mut bytes = good.raw.data().to_vec();
        match role {
            Role::Request => bytes[11] = 0, // Zero register quantity.
            Role::Response => bytes[8] = 4, // Only two register bytes follow.
            Role::Unknown => unreachable!(),
        }
        let raw = EvidenceBytes::from_packet(&bytes, good.raw.spans()[0].packet, 54);
        let fresh = ModbusMessage::from_adu(raw.clone(), role, 0, true).unwrap();
        let mut restored = fresh.clone();
        restored.raw = good.raw.clone();
        let matches_peer = |message: &ModbusMessage| match role {
            Role::Request => pcap_evidence::modbus::response_matches(
                message,
                &read_message(key, Role::Response, 2),
            ),
            Role::Response => pcap_evidence::modbus::response_matches(
                &read_message(key, Role::Request, 2),
                message,
            ),
            Role::Unknown => unreachable!(),
        };
        let mut edited = good;
        edited.raw = raw;
        assert!(!fresh.shape_valid && edited.shape_valid);
        assert!(!matches_peer(&edited));
        assert!(!restored.shape_valid && matches_peer(&restored));
        for peer_present in [false, true] {
            for observed in [&fresh, &edited] {
                let mut apps = Vec::new();
                for (direction, side) in [Role::Request, Role::Response].into_iter().enumerate() {
                    let mut result = ModbusResult::default();
                    result
                        .messages
                        .push(read_message((2, 2, 3), side, 3 + direction as u64));
                    if side == role {
                        result.messages.push(observed.clone());
                    } else if peer_present {
                        result.messages.push(read_message(key, side, 2));
                    }
                    apps.push(ApplicationAnalysis {
                        flow: 0,
                        direction,
                        protocol: "modbus",
                        data: ApplicationData::Modbus(result),
                    });
                }
                let rows = transactions(&apps, &Limits::default()).unwrap();
                let statuses: Vec<_> = rows.iter().map(|r| r.status).collect();
                assert_eq!(statuses.iter().filter(|&&s| s == "unclassified").count(), 1);
                assert_eq!(
                    statuses.iter().filter(|&&s| s == "candidate_pair").count(),
                    1
                );
                let pair = rows.iter().find(|r| r.status == "candidate_pair").unwrap();
                assert_eq!(pair.requests[0].message, 0);
                assert_eq!(pair.responses[0].message, 0);
                assert_eq!(rows.len(), if peer_present { 3 } else { 2 });
                if peer_present {
                    assert!(rows
                        .iter()
                        .any(|r| r.reason == "competing_modbus_observation"
                            && r.status == "ambiguous"));
                }
            }
        }
    }
}
