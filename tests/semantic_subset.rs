use pcap_evidence::modbus::Role;
use pcap_evidence::provenance::{EvidenceBytes, PacketId};
use pcap_evidence::semantics::{self, dnp3, modbus, Limits, Status, Value};
use pcap_evidence::tcp::{OverlapPolicy, StreamAssembler};

fn ev(data: &[u8]) -> EvidenceBytes {
    EvidenceBytes::from_packet(
        data,
        PacketId {
            capture: [7; 32],
            frame: 1,
            record_offset: 24,
        },
        54,
    )
}
fn adu(pdu: &[u8]) -> EvidenceBytes {
    let mut data = vec![0, 42, 0, 0, 0, (pdu.len() + 1) as u8, 1];
    data.extend_from_slice(pdu);
    ev(&data)
}
fn dn(data: &EvidenceBytes) -> semantics::Report<'_> {
    dnp3::decode(data, dnp3::Context::ResponseValues, Limits::default()).unwrap()
}
fn values<'a>(r: &'a semantics::Report<'_>, name: &str) -> Vec<&'a Value> {
    r.records()
        .iter()
        .flat_map(|r| r.fields())
        .filter(|f| f.name() == name)
        .map(|f| f.value())
        .collect()
}
fn root_message(raw: &EvidenceBytes, role: Role) -> pcap_evidence::modbus::ModbusMessage {
    let mut s = StreamAssembler::new(Some(0), pcap_evidence::Limits::default());
    s.push(1, raw.clone()).unwrap();
    pcap_evidence::modbus::decode(
        &s.finish(OverlapPolicy::RejectConflict).unwrap(),
        role,
        &pcap_evidence::Limits::default(),
    )
    .unwrap()
    .messages
    .remove(0)
}

#[test]
fn dnp_read_classes_have_no_invented_values() {
    let b = ev(&[60, 2, 6, 60, 3, 6, 60, 4, 6]);
    let r = dnp3::decode(&b, dnp3::Context::ReadHeaders, Limits::default()).unwrap();
    assert_eq!(r.status(), Status::DecodedSubset);
    assert_eq!(r.consumed(), 9);
    assert_eq!(r.records().len(), 3);
    assert!(values(&r, "value").is_empty());
}
#[test]
fn dnp_packed_range_does_not_emit_padding_points() {
    let b = ev(&[1, 1, 0, 0, 9, 0x4d, 3]);
    let r = dn(&b);
    assert_eq!(values(&r, "value").len(), 10);
    assert_eq!(values(&r, "value")[0], &Value::Boolean(true));
    assert_eq!(values(&r, "value")[1], &Value::Boolean(false));
    assert_eq!(values(&r, "point_index")[9], &Value::Unsigned(9));
    assert_eq!(r.status(), Status::DecodedSubset);
}
#[test]
fn dnp_flags_retained_and_bit_seven_decoded() {
    let b = ev(&[1, 2, 0, 4, 4, 0x81]);
    let r = dn(&b);
    assert_eq!(values(&r, "flags"), vec![&Value::Unsigned(129)]);
    assert_eq!(values(&r, "value"), vec![&Value::Boolean(true)]);
}
#[test]
fn dnp_count_without_index_does_not_invent_one() {
    let b = ev(&[20, 6, 7, 1, 0x34, 0x12]);
    let r = dn(&b);
    assert!(values(&r, "point_index").is_empty());
    assert_eq!(values(&r, "value"), vec![&Value::Unsigned(0x1234)]);
}
#[test]
fn dnp_duplicate_prefixed_indices_remain_ordered() {
    let b = ev(&[20, 2, 0x17, 2, 5, 1, 10, 0, 5, 1, 20, 0]);
    let r = dn(&b);
    assert_eq!(
        values(&r, "point_index"),
        vec![&Value::Unsigned(5), &Value::Unsigned(5)]
    );
    assert_eq!(
        values(&r, "value"),
        vec![&Value::Unsigned(10), &Value::Unsigned(20)]
    );
}
#[test]
fn dnp_sixteen_bit_qualifiers_are_little_endian() {
    let b = ev(&[20, 6, 0x28, 1, 0, 0x34, 0x12, 0xcd, 0xab]);
    let r = dn(&b);
    assert_eq!(values(&r, "point_index"), vec![&Value::Unsigned(0x1234)]);
    assert_eq!(values(&r, "value"), vec![&Value::Unsigned(0xabcd)]);
}
#[test]
fn dnp_signed_analogs_are_exact() {
    let b = ev(&[30, 1, 0, 1, 2, 1, 0xfe, 0xff, 0xff, 0xff, 1, 0, 0, 0, 0x80]);
    let r = dn(&b);
    assert_eq!(
        values(&r, "value"),
        vec![&Value::Signed(-2), &Value::Signed(-2147483648)]
    );
}
#[test]
fn dnp_float_nan_payload_and_negative_zero_are_bits() {
    let b = ev(&[30, 5, 0, 0, 1, 1, 1, 0, 0xc0, 0x7f, 1, 0, 0, 0, 0x80]);
    let r = dn(&b);
    assert_eq!(
        values(&r, "value"),
        vec![
            &Value::Float32Bits(0x7fc00001),
            &Value::Float32Bits(0x80000000)
        ]
    );
    assert!(r.json().unwrap().encode().contains("7fc00001"));
}
#[test]
fn dnp_relative_time_is_not_promoted_to_absolute() {
    let b = ev(&[2, 3, 0x17, 1, 4, 0x81, 0x34, 0x12]);
    let r = dn(&b);
    assert_eq!(
        values(&r, "time"),
        vec![&Value::RelativeMilliseconds16(0x1234)]
    );
    assert!(r.json().unwrap().encode().contains("unresolved"));
}
#[test]
fn dnp_absolute_time_preserves_48_bit_quantity() {
    let b = ev(&[50, 1, 7, 1, 1, 2, 3, 4, 5, 6]);
    let r = dn(&b);
    assert_eq!(
        values(&r, "time"),
        vec![&Value::Milliseconds48(0x060504030201)]
    );
}
#[test]
fn dnp_unknown_width_stops_without_magic_resync() {
    let b = ev(&[20, 6, 7, 1, 10, 0, 99, 99, 7, 1, 1, 2, 0, 0, 0, 0x81]);
    let r = dn(&b);
    assert_eq!(r.status(), Status::Unsupported);
    assert_eq!(r.consumed(), 6);
    assert_eq!(values(&r, "value").len(), 1);
}
#[test]
fn dnp_unknown_qualifier_does_not_publish_a_header() {
    let b = ev(&[1, 2, 0x5b, 0, 0]);
    let r = dn(&b);
    assert_eq!(r.status(), Status::Unsupported);
    assert!(r.records().is_empty());
}
#[test]
fn dnp_inverted_range_rejected() {
    let b = ev(&[1, 2, 0, 8, 7]);
    let r = dn(&b);
    assert_eq!(r.status(), Status::Rejected);
}
#[test]
fn dnp_truncated_object_retains_prior_complete_value() {
    let b = ev(&[20, 2, 7, 2, 1, 10, 0, 1]);
    let r = dn(&b);
    assert_eq!(r.status(), Status::Incomplete);
    assert_eq!(r.consumed(), 7);
    assert_eq!(values(&r, "value").len(), 1);
}
#[test]
fn dnp_all_object_response_is_not_inferred() {
    let b = ev(&[1, 2, 6, 0x81]);
    assert_eq!(dn(&b).status(), Status::Unsupported);
}
#[test]
fn dnp_controls_and_authentication_are_not_decoded() {
    let b = ev(&[1, 2, 0, 0, 0, 0x81]);
    for f in [2, 3, 4, 5, 6, 0x20, 0x83] {
        let r = dnp3::decode(&b, dnp3::Context::from_function(f), Limits::default()).unwrap();
        assert_eq!(r.status(), Status::Unsupported);
        assert!(r.records().is_empty());
    }
}
#[test]
fn dnp_packed_nonrange_is_explicitly_unsupported() {
    let b = ev(&[1, 1, 7, 8, 255]);
    assert_eq!(dn(&b).status(), Status::Unsupported);
}
#[test]
fn dnp_record_limit_is_observable() {
    let b = ev(&[1, 1, 0, 0, 9, 0, 0]);
    let l = Limits {
        max_records: 3,
        ..Limits::default()
    };
    let r = dnp3::decode(&b, dnp3::Context::ResponseValues, l).unwrap();
    assert_eq!(r.status(), Status::Limited);
    assert!(r.records().len() <= 3);
}
#[test]
fn dnp_no_cross_fragment_object_stitching() {
    let a = ev(&[20, 2, 7, 1, 1]);
    let b = ev(&[10, 0]);
    assert_eq!(dn(&a).status(), Status::Incomplete);
    assert_eq!(dn(&b).status(), Status::Incomplete);
}
#[test]
fn semantic_witness_spans_cross_packet_boundary_exactly() {
    let mut b = ev(&[20, 6, 7, 1, 0x34]);
    let c = EvidenceBytes::from_packet(
        &[0x12],
        PacketId {
            capture: [7; 32],
            frame: 2,
            record_offset: 300,
        },
        60,
    );
    b.append(&c, 100).unwrap();
    let r = dn(&b);
    let j = r.json().unwrap().encode();
    assert!(j.contains("\"frame\":\"2\""));
    assert!(j.contains("\"packet_start\":\"60\""));
    assert!(j.contains("\"value\":\"4660\""));
}
#[test]
fn invalid_provenance_is_not_laundered() {
    let b = EvidenceBytes::from_packet(
        &[1, 2],
        PacketId {
            capture: [0; 32],
            frame: 1,
            record_offset: 0,
        },
        usize::MAX,
    );
    assert!(dnp3::decode(&b, dnp3::Context::ReadHeaders, Limits::default()).is_err());
}
#[test]
fn semantic_input_and_json_limits_fail_explicitly() {
    let b = ev(&[20, 6, 7, 1, 0, 0]);
    assert!(dnp3::decode(
        &b,
        dnp3::Context::ResponseValues,
        Limits {
            max_input_bytes: 1,
            ..Limits::default()
        }
    )
    .is_err());
    let r = dnp3::decode(
        &b,
        dnp3::Context::ResponseValues,
        Limits {
            max_json_bytes: 1,
            ..Limits::default()
        },
    )
    .unwrap();
    assert!(r.json().is_err());
}
#[test]
fn modbus_spec_fc15_values_and_zero_based_addresses() {
    // V1.1b3 section 6.11 worked request; independently framed MBAP.
    let b = adu(&[15, 0, 0x13, 0, 10, 2, 0xcd, 1]);
    let r = modbus::decode(&b, Role::Request, Limits::default()).unwrap();
    assert_eq!(r.status(), Status::DecodedSubset);
    assert_eq!(values(&r, "value").len(), 10);
    assert_eq!(values(&r, "address_zero_based")[0], &Value::Unsigned(19));
    assert_eq!(values(&r, "address_zero_based")[9], &Value::Unsigned(28));
}
#[test]
fn modbus_fc16_register_values_are_network_order() {
    let b = adu(&[16, 0, 1, 0, 2, 4, 0, 10, 1, 2]);
    let r = modbus::decode(&b, Role::Request, Limits::default()).unwrap();
    assert_eq!(
        values(&r, "register_u16"),
        vec![&Value::Unsigned(10), &Value::Unsigned(258)]
    );
}
#[test]
fn modbus_response_values_do_not_invent_register_addresses() {
    let b = adu(&[3, 4, 0, 10, 1, 2]);
    let r = modbus::decode(&b, Role::Response, Limits::default()).unwrap();
    assert_eq!(values(&r, "register_u16").len(), 2);
    assert!(values(&r, "address_zero_based").is_empty());
}
#[test]
fn modbus_bit_response_preserves_octets_without_fake_padding_coils() {
    let b = adu(&[1, 2, 0xff, 0xff]);
    let r = modbus::decode(&b, Role::Response, Limits::default()).unwrap();
    assert_eq!(r.status(), Status::DecodedSubset);
    assert_eq!(values(&r, "packed_lsb_first").len(), 2);
    assert!(values(&r, "value").is_empty());
    assert!(!r.issues().is_empty());
}
#[test]
fn modbus_unknown_role_retains_both_valid_echo_interpretations() {
    let b = adu(&[6, 0, 1, 0, 2]);
    let j = modbus::alternatives_json(&b, Role::Unknown, Limits::default()).encode();
    assert!(j.contains("unresolved_role"));
    assert!(j.contains("\"context\":\"request\""));
    assert!(j.contains("\"context\":\"response\""));
}
#[test]
fn modbus_address_range_edges_are_checked() {
    for (q, status) in [
        (1, Status::DecodedSubset),
        (2, Status::Rejected),
        (0, Status::Rejected),
    ] {
        let b = adu(&[3, 0xff, 0xff, 0, q]);
        assert_eq!(
            modbus::decode(&b, Role::Request, Limits::default())
                .unwrap()
                .status(),
            status
        );
    }
}
#[test]
fn modbus_exception_is_not_successful_execution() {
    let b = adu(&[0x83, 2]);
    let r = modbus::decode(&b, Role::Response, Limits::default()).unwrap();
    assert_eq!(r.status(), Status::DecodedSubset);
    assert_eq!(values(&r, "exception_code"), vec![&Value::Unsigned(2)]);
    assert!(r
        .json()
        .unwrap()
        .encode()
        .contains("\"device_effect_established\":false"));
}
#[test]
fn modbus_requires_exact_one_mbap_message() {
    let b = ev(&[0, 1, 0, 0, 0, 2, 1, 3, 0]);
    assert_eq!(
        modbus::decode(&b, Role::Request, Limits::default())
            .unwrap()
            .status(),
        Status::Rejected
    );
}
#[test]
fn modbus_read_response_padding_checked_only_with_request_quantity() {
    let request = root_message(&adu(&[1, 0, 0, 0, 9]), Role::Request);
    let good = root_message(&adu(&[1, 2, 0xff, 1]), Role::Response);
    let bad = root_message(&adu(&[1, 2, 0xff, 0x81]), Role::Response);
    assert!(pcap_evidence::modbus::response_matches(&request, &good));
    assert!(!pcap_evidence::modbus::response_matches(&request, &bad));
    assert_eq!(
        modbus::check_pair(&request, &bad, Limits::default()).unwrap(),
        modbus::PairStatus::Inconsistent
    );
}
#[test]
fn modbus_write_padding_recommendation_is_warning_not_framing_failure() {
    let b = adu(&[15, 0, 0, 0, 9, 2, 0xff, 0x81]);
    let r = modbus::decode(&b, Role::Request, Limits::default()).unwrap();
    assert_eq!(r.status(), Status::DecodedSubset);
    assert!(r
        .issues()
        .iter()
        .any(|i| i.code == "write_unused_bits_nonzero_recommendation"));
}
#[test]
fn streaming_padding_tokens_match_root_policy() {
    assert!(modbus::compatibility_matches(
        "modbus-bits-v1:quantity:9",
        "modbus-bits-v1:response:2:1"
    ));
    assert!(!modbus::compatibility_matches(
        "modbus-bits-v1:quantity:9",
        "modbus-bits-v1:response:2:129"
    ));
    assert!(modbus::compatibility_matches("count:4", "count:4"));
    assert!(modbus::compatibility_matches(
        "modbus-bits-v1:quantity:9",
        ""
    ));
    assert!(!modbus::compatibility_matches(
        "modbus-bits-v1:quantity:0",
        "modbus-bits-v1:response:0:0"
    ));
}
#[test]
fn systematic_padding_property_all_quantities() {
    for q in 1u16..=2000 {
        let mut data = vec![0; usize::from(q).div_ceil(8)];
        assert!(modbus::padding_is_zero(q, &data));
        if q % 8 != 0 {
            *data.last_mut().unwrap() = 1 << (q % 8);
            assert!(!modbus::padding_is_zero(q, &data));
        }
    }
}
#[test]
fn deterministic_prefix_and_mutation_properties() {
    let seeds: &[&[u8]] = &[
        &[1, 1, 0, 0, 9, 0x4d, 3],
        &[30, 1, 0, 0, 0, 1, 0xfe, 0xff, 0xff, 0xff],
        &[20, 2, 0x17, 1, 5, 1, 10, 0],
    ];
    for &seed in seeds {
        for len in 0..=seed.len() {
            let b = ev(&seed[..len]);
            let a = dn(&b);
            let c = dn(&b);
            assert!(a.consumed() <= b.len());
            assert_eq!(a.json().unwrap(), c.json().unwrap());
            for rec in a.records() {
                for f in rec.fields() {
                    assert!(f.range().end <= b.len());
                }
            }
        }
        for index in 0..seed.len() {
            for bit in 0..8 {
                let mut bytes = seed.to_vec();
                bytes[index] ^= 1 << bit;
                let b = ev(&bytes);
                let a = dn(&b);
                assert!(a.consumed() <= b.len());
                assert!(a.json().is_ok());
            }
        }
    }
}

#[test]
fn dnp_each_additional_fixed_width_variant_has_a_value_case() {
    let cases: &[(u8, u8, &[u8], &str, Value)] = &[
        (10, 2, &[0x81], "value", Value::Boolean(true)),
        (2, 1, &[0x81], "value", Value::Boolean(true)),
        (
            2,
            2,
            &[0x81, 1, 2, 3, 4, 5, 6],
            "time",
            Value::Milliseconds48(0x060504030201),
        ),
        (
            20,
            1,
            &[1, 0x78, 0x56, 0x34, 0x12],
            "value",
            Value::Unsigned(0x12345678),
        ),
        (
            20,
            5,
            &[0x78, 0x56, 0x34, 0x12],
            "value",
            Value::Unsigned(0x12345678),
        ),
        (30, 2, &[1, 0xfe, 0xff], "value", Value::Signed(-2)),
        (30, 3, &[0xfe, 0xff, 0xff, 0xff], "value", Value::Signed(-2)),
        (30, 4, &[0xfe, 0xff], "value", Value::Signed(-2)),
        (
            30,
            6,
            &[1, 0, 0, 0, 0, 0, 0, 0, 0x80],
            "value",
            Value::Float64Bits(0x8000000000000000),
        ),
        (
            51,
            1,
            &[1, 2, 3, 4, 5, 6],
            "time",
            Value::Milliseconds48(0x060504030201),
        ),
        (
            51,
            2,
            &[1, 2, 3, 4, 5, 6],
            "time",
            Value::Milliseconds48(0x060504030201),
        ),
    ];
    for (g, v, payload, name, value) in cases {
        let mut data = vec![*g, *v, 7, 1];
        data.extend_from_slice(payload);
        let b = ev(&data);
        let r = dn(&b);
        assert_eq!(r.status(), Status::DecodedSubset, "group {g} var {v}");
        assert_eq!(values(&r, name), vec![value]);
        data.pop();
        let b = ev(&data);
        assert_eq!(dn(&b).status(), Status::Incomplete);
    }
}
#[test]
fn dnp_range16_count16_and_output_packed_cases() {
    let b = ev(&[20, 6, 1, 0xff, 0, 0, 1, 1, 0, 2, 0]);
    let r = dn(&b);
    assert_eq!(
        values(&r, "point_index"),
        vec![&Value::Unsigned(255), &Value::Unsigned(256)]
    );
    let b = ev(&[20, 6, 8, 1, 0, 1, 0]);
    assert_eq!(dn(&b).status(), Status::DecodedSubset);
    let b = ev(&[10, 1, 0, 0, 1, 2]);
    let r = dn(&b);
    assert_eq!(
        values(&r, "value"),
        vec![&Value::Boolean(false), &Value::Boolean(true)]
    );
}
#[test]
fn modbus_all_existing_functions_and_roles_have_decoded_cases() {
    for f in 1..=4 {
        let b = adu(&[f, 0, 0, 0, 1]);
        assert_eq!(
            modbus::decode(&b, Role::Request, Limits::default())
                .unwrap()
                .status(),
            Status::DecodedSubset
        );
        let response = if f <= 2 {
            vec![f, 1, 1]
        } else {
            vec![f, 2, 0, 1]
        };
        let b = adu(&response);
        assert_eq!(
            modbus::decode(&b, Role::Response, Limits::default())
                .unwrap()
                .status(),
            Status::DecodedSubset
        );
    }
    for f in [5, 6, 15, 16] {
        let pdu = if f == 5 {
            vec![f, 0, 0, 0xff, 0]
        } else {
            vec![f, 0, 0, 0, 1]
        };
        let b = adu(&pdu);
        assert_eq!(
            modbus::decode(&b, Role::Response, Limits::default())
                .unwrap()
                .status(),
            Status::DecodedSubset
        );
    }
}
#[test]
fn modbus_default_budget_covers_maximum_fc15_bit_count() {
    let mut pdu = vec![15, 0, 0, 7, 0xb0, 246];
    pdu.extend_from_slice(&[0; 246]);
    let b = adu(&pdu);
    let r = modbus::decode(&b, Role::Request, Limits::default()).unwrap();
    assert_eq!(r.status(), Status::DecodedSubset);
    assert_eq!(values(&r, "value").len(), 1968);
    assert!(r.json().is_ok());
}
#[test]
fn dnp_fragment_helper_rejects_forged_context() {
    let raw = ev(&[0xc0, 1, 60, 2, 6]);
    let fragment = pcap_evidence::dnp3::ApplicationFragment {
        source: 1,
        destination: 2,
        control: 0xc0,
        function: 0x81,
        sequence: 0,
        class: pcap_evidence::dnp3::MessageClass::Response,
        iin: None,
        first: true,
        final_fragment: true,
        confirmation_requested: false,
        frames: vec![],
        objects: raw.slice(2..5).unwrap(),
        raw,
    };
    assert!(dnp3::fragment_json(&fragment, Limits::default())
        .encode()
        .contains("metadata_mismatch"));
}
#[test]
fn semantic_source_span_budget_cannot_be_bypassed_with_many_fragments() {
    let mut b = ev(&[20, 6, 7, 1]);
    b.append(
        &EvidenceBytes::from_packet(
            &[1],
            PacketId {
                capture: [7; 32],
                frame: 2,
                record_offset: 200,
            },
            54,
        ),
        100,
    )
    .unwrap();
    b.append(
        &EvidenceBytes::from_packet(
            &[0],
            PacketId {
                capture: [7; 32],
                frame: 3,
                record_offset: 300,
            },
            54,
        ),
        100,
    )
    .unwrap();
    assert!(dnp3::decode(
        &b,
        dnp3::Context::ResponseValues,
        Limits {
            max_source_spans: 1,
            ..Limits::default()
        }
    )
    .is_err());
}
