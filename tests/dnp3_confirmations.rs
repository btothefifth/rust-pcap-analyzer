//! Fixed independent wire fixtures plus mutations at the public evidence seam.
//! These tests do not use the candidate implementation to compute expected keys.
mod common;
use pcap_evidence::{
    correlate::{self, Dnp3ConfirmationCandidate, FragmentRef},
    dnp3::{self, Dnp3Result, MessageClass},
    engine::{self, ApplicationAnalysis, ApplicationData, Config},
    json::Json,
    provenance::{EvidenceBytes, PacketId, SourceSpan},
    report,
    semantics::{self, dnp3_workflow as workflow},
    sha256,
    tcp::{StreamChunk, StreamResult},
    ErrorCode, Limits,
};

const WIRES: &str = include_str!("fixtures/dnp3_confirmations.hex");
fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|p| u8::from_str_radix(&text[p..p + 2], 16).unwrap())
        .collect()
}
fn wire(name: &str) -> Vec<u8> {
    hex(WIRES
        .lines()
        .find_map(|line| {
            let mut words = line.split_whitespace();
            (words.next() == Some(name)).then(|| words.next().unwrap())
        })
        .unwrap())
}
fn id(frame: u64) -> PacketId {
    PacketId {
        capture: [42; 32],
        frame,
        record_offset: frame * 100,
    }
}
fn app_at(names: &[&str], direction: usize, first_frame: u64, flow: usize) -> ApplicationAnalysis {
    let mut raw = EvidenceBytes::default();
    for (i, name) in names.iter().enumerate() {
        raw.append(
            &EvidenceBytes::from_packet(&wire(name), id(first_frame + i as u64), 54),
            1024 * 1024,
        )
        .unwrap();
    }
    let stream = StreamResult {
        base_sequence: Some(1000),
        anchored_by_syn: true,
        chunks: vec![StreamChunk {
            offset: 0,
            bytes: raw,
        }],
        gaps: Vec::new(),
        conflicts: Vec::new(),
        duplicate_observed_bytes: 0,
    };
    ApplicationAnalysis {
        flow,
        direction,
        protocol: "dnp3",
        data: ApplicationData::Dnp3(dnp3::decode(&stream, &Limits::default()).unwrap()),
    }
}
fn app(names: &[&str], direction: usize) -> ApplicationAnalysis {
    app_at(names, direction, if direction == 0 { 10 } else { 20 }, 0)
}
fn data(a: &ApplicationAnalysis) -> &Dnp3Result {
    let ApplicationData::Dnp3(result) = &a.data else {
        panic!("DNP3 fixture")
    };
    result
}
fn data_mut(a: &mut ApplicationAnalysis) -> &mut Dnp3Result {
    let ApplicationData::Dnp3(result) = &mut a.data else {
        panic!("DNP3 fixture")
    };
    result
}
fn pair() -> Vec<ApplicationAnalysis> {
    vec![
        app(&["solicited_confirm"], 0),
        app(&["solicited_target"], 1),
    ]
}
fn candidates(apps: &[ApplicationAnalysis]) -> Vec<Dnp3ConfirmationCandidate> {
    correlate::dnp3_confirmation_candidates(apps, &Limits::default()).unwrap()
}
fn no_candidate(rows: &[Dnp3ConfirmationCandidate]) {
    assert!(rows.iter().all(|r| r.status != "candidate_confirmation"));
}
fn capture() -> Vec<u8> {
    let text = include_str!("fixtures/dnp3_confirmations_capture.hex");
    hex(text
        .lines()
        .find(|line| !line.starts_with('#') && !line.is_empty())
        .unwrap())
}
fn field<'a>(json: &'a Json, key: &str) -> &'a Json {
    let Json::Object(fields) = json else {
        panic!("expected object")
    };
    &fields.iter().find(|(name, _)| *name == key).unwrap().1
}
fn array(json: &Json) -> &[Json] {
    let Json::Array(items) = json else {
        panic!("expected array")
    };
    items
}

#[test]
fn solicited_candidate_has_exact_fragment_and_crc_checked_header_witnesses() {
    let rows = candidates(&pair());
    assert_eq!(rows.len(), 1);
    let row = &rows[0];
    assert_eq!(row.status, "candidate_confirmation");
    assert_eq!(
        row.reason,
        "unique_verified_fragment_identifiers_not_receipt_or_causality"
    );
    assert_eq!(row.flow, 0);
    assert_eq!(row.confirms.len(), 1);
    assert_eq!(row.targets.len(), 1);
    assert_eq!(
        row.confirms[0].reference,
        FragmentRef {
            application: 0,
            fragment: 0
        }
    );
    assert_eq!(
        row.targets[0].reference,
        FragmentRef {
            application: 1,
            fragment: 0
        }
    );
    let confirm = &row.confirms[0].witness;
    let target = &row.targets[0].witness;
    assert_eq!((confirm.source, confirm.destination), (1, 1024));
    assert_eq!((target.source, target.destination), (1024, 1));
    assert!(confirm.link_direction);
    assert!(!target.link_direction);
    assert_eq!(confirm.header_bytes.data(), &[0xc5, 0]);
    assert_eq!(target.header_bytes.data(), &[0xe5, 0x81, 0, 0]);
    assert_eq!(confirm.header.sequence(), 5);
    assert!(!confirm.header.confirm_requested());
    assert!(!confirm.header.unsolicited());
    assert!(target.header.confirm_requested());
    assert_eq!(
        confirm.header_bytes.spans(),
        &[SourceSpan {
            start: 0,
            end: 2,
            packet: id(10),
            packet_start: 65,
        }]
    );
    assert_eq!(
        target.header_bytes.spans(),
        &[SourceSpan {
            start: 0,
            end: 4,
            packet: id(20),
            packet_start: 65,
        }]
    );
    assert_eq!(confirm.packets, vec![id(10)]);
    assert_eq!(target.packets, vec![id(20)]);
    assert_eq!(confirm.links[0].header.data(), &hex("056408c4000401009a19"));
    assert_eq!(target.links[0].header.data(), &hex("05640a44010000046788"));
    assert_eq!(confirm.links[0].header.spans()[0].packet_start, 54);
    assert_eq!(
        confirm.links[0].transport_header.spans()[0].packet_start,
        64
    );
    assert_eq!(confirm.links[0].transport_header.data(), &[0xc0]);
    assert_eq!(
        sha256::hex(&confirm.links[0].frame_sha256),
        "e7649410719699401bdec5959d3f8f3dce8cbe010b6f9dc10f040ed862c14cda"
    );
    assert_eq!(
        sha256::hex(&target.links[0].frame_sha256),
        "4d97abd4e5103d92ed4f68c269cc063a32cdbd9d129001e067670806596ad698"
    );
    assert!(row.error.is_none());
}

#[test]
fn unsolicited_confirm_pairs_only_inside_its_separate_namespace() {
    let apps = vec![
        app(&["solicited_confirm", "unsolicited_confirm"], 0),
        app(&["solicited_target", "unsolicited_target"], 1),
    ];
    let rows = candidates(&apps);
    assert_eq!(rows.len(), 2);
    for (i, row) in rows.iter().enumerate() {
        assert_eq!(row.status, "candidate_confirmation");
        assert_eq!(row.confirms[0].witness.header.unsolicited(), i == 1);
        assert_eq!(row.targets[0].witness.header.unsolicited(), i == 1);
        assert_eq!(
            row.targets[0].witness.header.function,
            if i == 1 { 0x82 } else { 0x81 }
        );
    }
}

#[test]
fn unmatched_confirm_is_retained_and_legacy_transaction_output_is_unchanged() {
    let apps = [app(&["solicited_confirm"], 0)];
    let rows = candidates(&apps);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].status, "unmatched_confirmation");
    assert_eq!(rows[0].confirms.len(), 1);
    assert!(rows[0].targets.is_empty());
    let old = correlate::transactions(&apps, &Limits::default()).unwrap();
    assert_eq!(old.len(), 1);
    assert_eq!(old[0].status, "confirmation");
    assert_eq!(
        old[0].reason,
        "fragment_confirmation_observed_pairing_not_implemented"
    );
}

#[test]
fn equal_not_reversed_addresses_and_other_flows_do_not_match() {
    for target in [
        app(&["target_unreversed"], 1),
        app_at(&["solicited_target"], 1, 20, 1),
    ] {
        let rows = candidates(&[app(&["solicited_confirm"], 0), target]);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].status, "unmatched_confirmation");
        assert!(rows[0].targets.is_empty());
    }
}

#[test]
fn same_capture_direction_or_same_link_dir_is_not_a_candidate() {
    for (target, reason) in [
        (
            app_at(&["solicited_target"], 0, 20, 0),
            "captured_application_directions_not_opposite",
        ),
        (app(&["target_same_dir"], 1), "link_dir_not_opposite"),
    ] {
        let rows = candidates(&[app(&["solicited_confirm"], 0), target]);
        assert_eq!(rows[0].status, "unmatched_confirmation");
        assert!(rows[0].targets.is_empty());
        assert_eq!(rows[0].excluded_targets[0].reason, reason);
    }
}

#[test]
fn observed_opposite_dir_is_used_without_inventing_a_role_mapping() {
    let rows = candidates(&[
        app(&["confirm_inverse_dir"], 0),
        app(&["target_same_dir"], 1),
    ]);
    assert_eq!(rows[0].status, "candidate_confirmation");
    assert!(!rows[0].confirms[0].witness.link_direction);
    assert!(rows[0].targets[0].witness.link_direction);
}

#[test]
fn target_without_con_is_excluded_not_promoted() {
    let rows = candidates(&[app(&["solicited_confirm"], 0), app(&["target_no_con"], 1)]);
    assert_eq!(rows[0].status, "unmatched_confirmation");
    assert_eq!(
        rows[0].excluded_targets[0].reason,
        "target_does_not_request_confirmation"
    );
    assert!(!rows[0].excluded_targets[0]
        .fragment
        .witness
        .header
        .confirm_requested());
}

#[test]
fn sequence_and_uns_namespace_mismatches_remain_unmatched() {
    for (confirm, target) in [
        ("solicited_confirm", "target_sequence6"),
        ("solicited_confirm", "unsolicited_target"),
        ("unsolicited_confirm", "solicited_target"),
    ] {
        let rows = candidates(&[app(&[confirm], 0), app(&[target], 1)]);
        assert_eq!(rows[0].status, "unmatched_confirmation");
        assert!(rows[0].targets.is_empty());
    }
}

#[test]
fn duplicate_targets_are_all_retained_without_selecting_one() {
    let rows = candidates(&[
        app(&["solicited_confirm"], 0),
        app(&["solicited_target", "solicited_target"], 1),
    ]);
    assert_eq!(rows[0].status, "ambiguous");
    assert_eq!(rows[0].reason, "duplicate_or_reused_response_identifier");
    assert_eq!(rows[0].targets.len(), 2);
    assert_eq!(rows[0].targets[0].witness.packets, vec![id(20)]);
    assert_eq!(rows[0].targets[1].witness.packets, vec![id(21)]);
}

#[test]
fn duplicate_confirms_remain_ambiguous_even_without_a_target() {
    for with_target in [false, true] {
        let mut apps = vec![app(&["solicited_confirm", "solicited_confirm"], 0)];
        if with_target {
            apps.push(app(&["solicited_target"], 1));
        }
        let rows = candidates(&apps);
        assert_eq!(rows[0].status, "ambiguous");
        assert_eq!(
            rows[0].reason,
            "duplicate_or_reused_confirmation_identifier"
        );
        assert_eq!(rows[0].confirms.len(), 2);
    }
}

#[test]
fn conflicting_con_or_direction_headers_cannot_make_a_unique_target_win() {
    for extra in ["target_no_con", "target_same_dir"] {
        let rows = candidates(&[
            app(&["solicited_confirm"], 0),
            app(&["solicited_target", extra], 1),
        ]);
        assert_eq!(rows[0].status, "ambiguous");
        assert_eq!(rows[0].targets.len(), 1);
        assert_eq!(rows[0].excluded_targets.len(), 1);
    }
}

#[test]
fn multiple_outstations_remain_separate() {
    let rows = candidates(&[
        app(&["solicited_confirm", "confirm_other_outstation"], 0),
        app(&["target_other_outstation", "solicited_target"], 1),
    ]);
    assert_eq!(rows.len(), 2);
    for row in rows {
        assert_eq!(row.status, "candidate_confirmation");
        assert_eq!(
            row.confirms[0].witness.destination,
            row.targets[0].witness.source
        );
    }
}

#[test]
fn confirmation_targets_one_application_fragment_not_the_message_first_sequence() {
    let apps = [
        app(&["confirm_0"], 0),
        app(&["target_first_15", "target_final_0"], 1),
    ];
    let result = data(&apps[1]);
    assert_eq!(result.messages.len(), 1);
    assert!(result.messages[0].complete);
    assert_eq!(result.messages[0].first_sequence, 15);
    assert_eq!(result.fragments.len(), 2);
    let rows = candidates(&apps);
    assert_eq!(rows[0].status, "candidate_confirmation");
    assert_eq!(rows[0].targets[0].reference.fragment, 1);
    assert_eq!(rows[0].targets[0].witness.header.sequence(), 0);
    assert_eq!(
        rows[0].targets[0].witness.header_bytes.data(),
        &[0x60, 0x81, 0, 0]
    );
    assert_eq!(rows[0].targets[0].witness.packets, vec![id(21)]);
    for fragment in &result.fragments {
        let json = semantics::dnp3::fragment_json(fragment, semantics::Limits::default()).encode();
        assert!(json.contains("\"status\":\"incomplete\""));
        assert!(!json.contains("\"kind\":\"object_value\""));
    }
}

#[test]
fn a_transport_complete_target_does_not_require_a_complete_application_message() {
    for (target, confirm) in [
        ("target_first_15", "confirm_15"),
        ("target_final_0", "confirm_0"),
    ] {
        let apps = [app(&[confirm], 0), app(&[target], 1)];
        assert!(data(&apps[1]).messages.iter().all(|m| !m.complete));
        let rows = candidates(&apps);
        assert_eq!(rows[0].status, "candidate_confirmation");
        assert_eq!(rows[0].targets[0].reference.fragment, 0);
    }
}

#[test]
fn sequence_rollover_is_not_an_invented_transaction_epoch() {
    let rows = candidates(&[
        app(&["confirm_15", "confirm_0", "confirm_15"], 0),
        app(
            &[
                "target_complete_15",
                "target_complete_0",
                "target_complete_15",
            ],
            1,
        ),
    ]);
    assert_eq!(rows.len(), 2);
    let zero = rows
        .iter()
        .find(|r| r.confirms[0].witness.header.sequence() == 0)
        .unwrap();
    let fifteen = rows
        .iter()
        .find(|r| r.confirms[0].witness.header.sequence() == 15)
        .unwrap();
    assert_eq!(zero.status, "candidate_confirmation");
    assert_eq!(fifteen.status, "ambiguous");
    assert_eq!(fifteen.confirms.len(), 2);
    assert_eq!(fifteen.targets.len(), 2);
}

#[test]
fn malformed_confirm_controls_broadcast_and_bad_uns_remain_unclassified() {
    for bad in [
        "confirm_con_set",
        "confirm_nonfinal",
        "confirm_trailing_body",
        "confirm_broadcast",
    ] {
        let rows = candidates(&[app(&[bad], 0), app(&["solicited_target"], 1)]);
        no_candidate(&rows);
        assert!(rows.iter().any(|r| r.status == "unclassified"), "{bad}");
    }
    let rows = candidates(&[app(&["solicited_confirm"], 0), app(&["target_bad_uns"], 1)]);
    no_candidate(&rows);
    assert!(rows
        .iter()
        .any(|r| r.reason == "dnp3_application_control_function_conflict"));
}

#[test]
fn every_public_fragment_metadata_field_is_rechecked_for_both_participants() {
    for participant in 0..2 {
        for mutation in 0..13 {
            let mut apps = pair();
            let fragment = &mut data_mut(&mut apps[participant]).fragments[0];
            match mutation {
                0 => fragment.source ^= 1,
                1 => fragment.destination ^= 1,
                2 => fragment.control ^= 1,
                3 => fragment.function = 1,
                4 => fragment.sequence ^= 1,
                5 => fragment.class = MessageClass::Unknown,
                6 => fragment.iin = Some(9),
                7 => fragment.first = !fragment.first,
                8 => fragment.final_fragment = !fragment.final_fragment,
                9 => fragment.confirmation_requested = !fragment.confirmation_requested,
                10 => fragment.frames.clear(),
                11 => fragment.frames[0] = usize::MAX,
                _ => fragment.objects = EvidenceBytes::from_packet(&[9], id(90), 65),
            }
            let rows = candidates(&apps);
            no_candidate(&rows);
            assert!(
                rows.iter().any(|r| r.status == "unclassified"),
                "{participant}/{mutation}"
            );
        }
    }
}

#[test]
fn forged_public_link_fields_crc_and_source_offsets_are_not_witnesses() {
    for participant in 0..2 {
        for mutation in 0..10 {
            let mut apps = pair();
            let frame = &mut data_mut(&mut apps[participant]).frames[0];
            let packet = frame.raw.packets()[0];
            match mutation {
                0 => frame.control ^= 0x20,
                1 => frame.link_control.direction = !frame.link_control.direction,
                2 => frame.source ^= 1,
                3 => frame.destination ^= 1,
                4 => frame.broadcast = !frame.broadcast,
                5 => {
                    frame.user_data = EvidenceBytes::from_packet(frame.user_data.data(), packet, 65)
                }
                6 | 7 => {
                    let mut raw = frame.raw.data().to_vec();
                    let at = if mutation == 6 { 8 } else { raw.len() - 1 };
                    raw[at] ^= 1;
                    frame.raw = EvidenceBytes::from_packet(&raw, packet, 54);
                }
                8 => frame.raw = EvidenceBytes::from_packet(frame.raw.data(), packet, 55),
                _ => frame.raw = EvidenceBytes::from_packet(frame.raw.data(), packet, usize::MAX),
            }
            let rows = candidates(&apps);
            no_candidate(&rows);
            assert!(rows.iter().any(|r| r.error.is_some()));
        }
    }
}

#[test]
fn public_apdu_role_rewrite_cannot_hide_a_duplicate_confirm_from_verification() {
    let mut apps = vec![
        app(&["solicited_confirm", "solicited_confirm"], 0),
        app(&["solicited_target"], 1),
    ];
    let f = &mut data_mut(&mut apps[0]).fragments[1];
    // All public APDU fields agree with this forged READ, but the link frame
    // still carries the second original CONFIRM. A prefilter would hide it.
    f.raw = EvidenceBytes::from_packet(&[0xc5, 1], id(11), 65);
    f.function = 1;
    f.class = MessageClass::Request;
    let rows = candidates(&apps);
    no_candidate(&rows);
    assert!(rows.iter().any(|r| r.status == "unclassified"));
    assert!(rows
        .iter()
        .any(|r| r.status == "ambiguous" && !r.confirms.is_empty()));
}

#[test]
fn reused_frame_indices_and_post_fin_duplicates_cannot_be_laundered() {
    for duplicated_index in [true, false] {
        let mut apps = pair();
        let d = data_mut(&mut apps[0]);
        let second = if duplicated_index {
            0
        } else {
            d.frames.push(d.frames[0].clone());
            1
        };
        d.fragments[0].frames.push(second);
        no_candidate(&candidates(&apps));
    }
}

#[test]
fn selected_application_header_source_spans_are_rechecked_not_just_bytes() {
    let mut apps = pair();
    let f = &mut data_mut(&mut apps[1]).fragments[0];
    f.raw = EvidenceBytes::from_packet(f.raw.data(), id(20), 66);
    no_candidate(&candidates(&apps));
}

#[test]
fn all_truncated_link_and_application_prefixes_are_explicit_not_candidates() {
    for participant in 0..2 {
        let original = pair();
        let d = data(&original[participant]);
        for n in 0..d.frames[0].raw.len() {
            let mut apps = pair();
            data_mut(&mut apps[participant]).frames[0].raw = d.frames[0].raw.slice(0..n).unwrap();
            let rows = candidates(&apps);
            no_candidate(&rows);
            assert!(rows.iter().any(|r| r.error.is_some()));
        }
        for n in 0..d.fragments[0].raw.len() {
            let mut apps = pair();
            data_mut(&mut apps[participant]).fragments[0].raw =
                d.fragments[0].raw.slice(0..n).unwrap();
            no_candidate(&candidates(&apps));
        }
    }
}

#[test]
fn transport_wrap_and_reordered_duplicates_preserve_selected_header_and_all_packets() {
    let apps = [
        app(&["solicited_confirm"], 0),
        app(
            &[
                "transport_first",
                "transport_middle",
                "transport_first",
                "transport_final",
            ],
            1,
        ),
    ];
    let rows = candidates(&apps);
    assert_eq!(rows[0].status, "candidate_confirmation");
    let w = &rows[0].targets[0].witness;
    assert_eq!(w.header_bytes.data(), &[0xe5, 0x81, 0, 0]);
    assert_eq!(w.packets, vec![id(20), id(21), id(22), id(23)]);
    assert_eq!(w.links.len(), 4);
    assert_eq!(
        w.header_bytes.spans(),
        &[
            SourceSpan {
                start: 0,
                end: 2,
                packet: id(20),
                packet_start: 65
            },
            SourceSpan {
                start: 2,
                end: 3,
                packet: id(21),
                packet_start: 65
            },
            SourceSpan {
                start: 3,
                end: 4,
                packet: id(23),
                packet_start: 65
            },
        ]
    );
    assert!(data(&apps[1])
        .issues
        .iter()
        .any(|i| i.code == "reordered_duplicate_dnp3_transport_segment"));
}

#[test]
fn missing_or_conflicting_transport_bytes_never_create_a_target() {
    for parts in [
        vec!["transport_first", "transport_final"],
        vec![
            "transport_first",
            "transport_middle",
            "transport_middle_conflict",
            "transport_final",
        ],
    ] {
        let apps = [app(&["solicited_confirm"], 0), app(&parts, 1)];
        assert!(data(&apps[1]).fragments.is_empty());
        assert!(!data(&apps[1]).issues.is_empty());
        let rows = candidates(&apps);
        assert_eq!(rows[0].status, "unmatched_confirmation");
    }
}

#[test]
fn invalid_witness_taints_only_its_flow_without_using_its_forged_key() {
    let mut apps = pair();
    let mut bad = app_at(&["solicited_target"], 1, 30, 0);
    data_mut(&mut bad).fragments[0].sequence = 7;
    apps.push(bad);
    let rows = candidates(&apps);
    no_candidate(&rows);
    assert!(rows.iter().any(|r| r.status == "ambiguous"));
    apps[2].flow = 1;
    let rows = candidates(&apps);
    assert!(rows
        .iter()
        .any(|r| r.flow == 0 && r.status == "candidate_confirmation"));
    assert!(rows
        .iter()
        .any(|r| r.flow == 1 && r.status == "unclassified"));
}

#[test]
fn unsupported_secure_context_is_not_silently_removed_from_the_identifier_pool() {
    let mut apps = pair();
    apps.push(app_at(&["secure_function"], 1, 30, 0));
    let rows = candidates(&apps);
    no_candidate(&rows);
    assert!(rows
        .iter()
        .any(|r| r.reason == "dnp3_authentication_workflow_opaque"));
}

#[test]
fn object_payload_does_not_become_a_decoded_value_through_confirmation_correlation() {
    let apps = [
        app(&["solicited_confirm"], 0),
        app(&["target_unknown_objects"], 1),
    ];
    let rows = candidates(&apps);
    assert_eq!(rows[0].status, "candidate_confirmation");
    assert_eq!(
        rows[0].targets[0].witness.header_bytes.data(),
        &[0xe5, 0x81, 0, 0]
    );
    let objects =
        semantics::dnp3::fragment_json(&data(&apps[1]).fragments[0], semantics::Limits::default())
            .encode();
    assert!(!objects.contains("\"kind\":\"object_value\""));
}

#[test]
fn fcb_and_fcv_do_not_select_a_partner_or_infer_link_state() {
    for (confirm, target) in [
        ("confirm_fcb", "target_fcb"),
        ("confirm_link_confirmed", "target_link_confirmed"),
    ] {
        let rows = candidates(&[app(&[confirm], 0), app(&[target], 1)]);
        assert_eq!(rows[0].status, "candidate_confirmation");
    }
}

#[test]
fn invalid_capture_direction_and_outer_protocol_label_are_explicit() {
    for direction in [2, usize::MAX] {
        let mut apps = pair();
        apps[0].direction = direction;
        let rows = candidates(&apps);
        no_candidate(&rows);
        assert!(rows
            .iter()
            .any(|r| r.reason == "dnp3_confirmation_application_scope_invalid"));
    }
    let mut apps = pair();
    apps[1].protocol = "modbus";
    no_candidate(&candidates(&apps));
}

#[test]
fn the_same_numeric_flow_from_different_captures_cannot_pair() {
    let mut apps = pair();
    // Re-decode a genuinely internally-consistent target from a different capture.
    let raw = EvidenceBytes::from_packet(
        &wire("solicited_target"),
        PacketId {
            capture: [43; 32],
            ..id(20)
        },
        54,
    );
    let stream = StreamResult {
        base_sequence: Some(1000),
        anchored_by_syn: true,
        chunks: vec![StreamChunk {
            offset: 0,
            bytes: raw,
        }],
        gaps: vec![],
        conflicts: vec![],
        duplicate_observed_bytes: 0,
    };
    apps[1].data = ApplicationData::Dnp3(dnp3::decode(&stream, &Limits::default()).unwrap());
    let rows = candidates(&apps);
    assert_eq!(rows[0].status, "unmatched_confirmation");
}

#[test]
fn budget_exhaustion_is_typed_and_never_returns_partial_candidates() {
    for limits in [
        Limits {
            max_correlation_checks: 1,
            ..Limits::default()
        },
        Limits {
            max_protocol_messages: 1,
            ..Limits::default()
        },
        Limits {
            max_application_bytes: 1,
            ..Limits::default()
        },
    ] {
        assert_eq!(
            correlate::dnp3_confirmation_candidates(&pair(), &limits)
                .unwrap_err()
                .code,
            ErrorCode::LimitExceeded
        );
    }
    let apps = pair();
    let d = data(&apps[0]);
    let mut work = usize::MAX;
    assert_eq!(
        workflow::verified_fragment_witness(d, &d.fragments[0], &Limits::default(), &mut work)
            .unwrap_err()
            .code,
        ErrorCode::LimitExceeded
    );
}

#[test]
fn all_budget_values_below_the_first_success_are_explicit_limits() {
    let apps = pair();
    let first = (1..4096)
        .find(|&n| {
            let limits = Limits {
                max_correlation_checks: n,
                ..Limits::default()
            };
            match correlate::dnp3_confirmation_candidates(&apps, &limits) {
                Ok(rows) => {
                    assert_eq!(rows[0].status, "candidate_confirmation");
                    true
                }
                Err(error) => {
                    assert_eq!(error.code, ErrorCode::LimitExceeded);
                    false
                }
            }
        })
        .expect("small fixed fixture must fit a small bounded query");
    assert!(first > 32);
}

#[test]
fn response_only_and_unrelated_read_do_not_create_confirmation_rows() {
    assert!(candidates(&[app(&["solicited_target"], 1), app(&["read_unrelated"], 0)]).is_empty());
    assert!(candidates(&[]).is_empty());
}

#[test]
fn application_list_order_does_not_change_candidate_selection() {
    let mut apps = pair();
    let a = candidates(&apps);
    apps.reverse();
    let b = candidates(&apps);
    assert_eq!(a[0].status, b[0].status);
    assert_eq!(a[0].confirms[0].witness, b[0].confirms[0].witness);
    assert_eq!(a[0].targets[0].witness, b[0].targets[0].witness);
    assert_eq!(b[0].confirms[0].reference.application, 1);
}

#[test]
fn fixed_capture_reaches_engine_and_deterministic_root_json_with_exact_timestamps() {
    let input = capture();
    assert_eq!(
        sha256::hex(&sha256::digest(&input)),
        "12b5d3ee1f979749a4c52c20fc5962b83410d9ddf6287d2e360d1637ef32fe92"
    );
    let a = engine::analyze(&input, Config::default()).unwrap();
    let b = engine::analyze(&input, Config::default()).unwrap();
    assert!(a.dnp3_confirmation_error.is_none());
    assert_eq!(a.dnp3_confirmation_candidates.len(), 1);
    let row = &a.dnp3_confirmation_candidates[0];
    assert_eq!(row.status, "candidate_confirmation");
    assert_eq!(row.targets[0].witness.packets[0].frame, 4);
    assert_eq!(row.confirms[0].witness.packets[0].frame, 5);
    assert_eq!(row.targets[0].witness.packets[0].record_offset, 234);
    assert_eq!(row.confirms[0].witness.packets[0].record_offset, 321);
    assert_eq!(
        row.confirms[0].witness.header_bytes.spans()[0].packet_start,
        65
    );
    assert_eq!(a.packets[3].metadata.timestamp.unwrap().ticks, 4_000_000);
    assert_eq!(a.packets[4].metadata.timestamp.unwrap().ticks, 5_000_000);
    assert!(a.transactions.iter().any(|t| t.status == "confirmation"
        && t.reason == "fragment_confirmation_observed_pairing_not_implemented"));
    let json = report::analysis(&a, false);
    assert_eq!(json, report::analysis(&b, false));
    let encoded = json.encode();
    assert!(encoded.contains("\"hex\":\"c500\""));
    assert!(encoded.contains("\"hex\":\"e5810000\""));
    let item = &array(field(&json, "dnp3_confirmation_candidates"))[0];
    assert_eq!(field(item, "acceptance_established"), &Json::Bool(false));
    assert_eq!(field(item, "device_effect_established"), &Json::Bool(false));
    assert_eq!(
        field(item, "normative_conformance_certified"),
        &Json::Bool(false)
    );
    assert_eq!(field(&json, "dnp3_confirmation_error"), &Json::Null);
    assert!(json.encode_bounded(32).is_err());
}

#[test]
fn timestamps_and_capture_order_are_not_confirmation_matching_inputs() {
    let input = capture();
    let baseline = engine::analyze(&input, Config::default()).unwrap();
    let mut changed = input.clone();
    // Exact record offsets in the independent fixture; only timestamps change.
    changed[234..238].copy_from_slice(&9u32.to_le_bytes());
    changed[321..325].copy_from_slice(&1u32.to_le_bytes());
    let reversed = engine::analyze(&changed, Config::default()).unwrap();
    assert_eq!(
        baseline.dnp3_confirmation_candidates[0].status,
        reversed.dnp3_confirmation_candidates[0].status
    );
    assert_eq!(
        reversed.dnp3_confirmation_candidates[0].status,
        "candidate_confirmation"
    );
}

#[test]
fn engine_limit_error_is_separate_and_survives_json_projection() {
    let a = engine::analyze(
        &capture(),
        Config {
            limits: Limits {
                max_correlation_checks: 1,
                ..Limits::default()
            },
            ..Config::default()
        },
    )
    .unwrap();
    assert!(a.dnp3_confirmation_candidates.is_empty());
    assert_eq!(
        a.dnp3_confirmation_error.as_ref().unwrap().code,
        ErrorCode::LimitExceeded
    );
    assert!(a.has_diagnostics());
    let json = report::analysis(&a, false);
    assert_eq!(
        field(field(&json, "dnp3_confirmation_error"), "code"),
        &Json::from("limit_exceeded")
    );
}

#[test]
fn real_cli_emits_the_additive_section_without_changing_the_capture() {
    let temp = common::Temp::new();
    let path = temp.0.join("confirmations.pcap");
    let bytes = capture();
    std::fs::write(&path, &bytes).unwrap();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_pcap-evidence"))
        .arg("analyze")
        .arg(&path)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("\"dnp3_confirmation_candidates\":["));
    assert!(text.contains("\"status\":\"candidate_confirmation\""));
    assert!(text.contains("\"transaction_candidates\":["));
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
}
