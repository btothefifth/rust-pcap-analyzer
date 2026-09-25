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
fn dnp_indexed_reads_and_control_functions_are_explicit() {
    let read = ev(&[2, 1, 0x17, 2, 3, 4]);
    let r = dnp3::decode(&read, dnp3::Context::ReadHeaders, Limits::default()).unwrap();
    assert_eq!(r.status(), Status::DecodedSubset);
    assert_eq!(
        values(&r, "point_index"),
        vec![&Value::Unsigned(3), &Value::Unsigned(4)]
    );

    let crob = ev(&[12, 1, 7, 1, 1, 2, 10, 0, 0, 0, 20, 0, 0, 0, 0]);
    for f in [3, 4, 5, 6] {
        let r = dnp3::decode(&crob, dnp3::Context::from_function(f), Limits::default()).unwrap();
        assert_eq!(r.status(), Status::DecodedSubset, "function {f}");
        assert_eq!(values(&r, "control_code"), vec![&Value::Unsigned(1)]);
        assert_eq!(values(&r, "on_time_ms"), vec![&Value::Unsigned(10)]);
        assert_eq!(values(&r, "off_time_ms"), vec![&Value::Unsigned(20)]);
    }

    let unsupported = ev(&[1, 2, 0, 0, 0, 0x81]);
    for f in [0x20, 0x83] {
        let r = dnp3::decode(
            &unsupported,
            dnp3::Context::from_function(f),
            Limits::default(),
        )
        .unwrap();
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
fn dnp_two_and_four_byte_index_prefixes_are_little_endian() {
    let two = ev(&[20, 6, 0x27, 1, 0x34, 0x12, 0xcd, 0xab]);
    let r = dn(&two);
    assert_eq!(values(&r, "point_index"), vec![&Value::Unsigned(0x1234)]);
    assert_eq!(values(&r, "value"), vec![&Value::Unsigned(0xabcd)]);

    let four = ev(&[20, 6, 0x38, 1, 0, 0x78, 0x56, 0x34, 0x12, 0xcd, 0xab]);
    let r = dn(&four);
    assert_eq!(
        values(&r, "point_index"),
        vec![&Value::Unsigned(0x12345678)]
    );
    assert_eq!(values(&r, "value"), vec![&Value::Unsigned(0xabcd)]);
}

#[test]
fn dnp_four_byte_ranges_preserve_wide_point_indices() {
    let b = ev(&[20, 6, 2, 1, 0, 0, 0, 1, 0, 0, 0, 0x34, 0x12]);
    let r = dn(&b);
    assert_eq!(values(&r, "point_index"), vec![&Value::Unsigned(1)]);
    assert_eq!(values(&r, "value"), vec![&Value::Unsigned(0x1234)]);
}

#[test]
fn dnp_deadband_unsigned_and_variable_octets_keep_wire_identity() {
    let deadband = ev(&[34, 3, 0, 0, 0, 0, 0, 0x80, 0x3f]);
    let r = dn(&deadband);
    assert_eq!(values(&r, "value"), vec![&Value::Float32Bits(0x3f800000)]);

    let octets = ev(&[110, 3, 0x17, 1, 5, 1, 2, 3]);
    let r = dn(&octets);
    assert_eq!(
        values(&r, "value"),
        vec![&Value::OctetsSha256 {
            length: 3,
            digest: pcap_evidence::sha256::digest(&[1, 2, 3]),
        }]
    );
    assert_eq!(values(&r, "point_index"), vec![&Value::Unsigned(5)]);
}

#[test]
fn dnp_unsigned_integer_object_is_not_treated_as_a_counter() {
    let b = ev(&[102, 1, 7, 1, 0x7f]);
    let r = dn(&b);
    assert_eq!(values(&r, "value"), vec![&Value::Unsigned(0x7f)]);
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

#[test]
fn dnp_group0_hashes_visible_string_and_preserves_exact_envelope() {
    let b = ev(&[0, 245, 7, 1, 1, 3, b'A', b'B', b'C']);
    let r = dn(&b);
    assert_eq!(r.status(), Status::DecodedSubset);
    assert_eq!(r.records().len(), 2);
    assert_eq!(r.records()[1].kind(), "attribute_value");
    assert_eq!(r.records()[1].range(), 4..9);
    assert_eq!(values(&r, "data_type"), vec![&Value::Unsigned(1)]);
    assert_eq!(values(&r, "length"), vec![&Value::Unsigned(3)]);
    assert!(matches!(
        values(&r, "value")[0],
        Value::OctetsSha256 { length: 3, .. }
    ));
}

#[test]
fn dnp_group0_decodes_numeric_attribute_types_without_semantic_names() {
    let b = ev(&[
        0, 209, 7, 1, 2, 2, 0x34, 0x12, // unsigned 0x1234
        0, 210, 7, 1, 3, 1, 0xfe, // signed -2
        0, 203, 7, 1, 4, 4, 1, 0, 0xc0, 0x7f, // float32 NaN bits
        0, 198, 7, 1, 7, 6, 1, 2, 3, 4, 5, 6,
    ]);
    let r = dn(&b);
    assert_eq!(r.status(), Status::DecodedSubset);
    assert_eq!(
        values(&r, "value"),
        vec![
            &Value::Unsigned(0x1234),
            &Value::Signed(-2),
            &Value::Float32Bits(0x7fc00001),
            &Value::Milliseconds48(0x060504030201),
        ]
    );
}

#[test]
fn dnp_group0_range_selector_keeps_each_attribute_source_bound() {
    let b = ev(&[0, 209, 0, 0, 1, 2, 2, 0x34, 0x12, 2, 2, 0x78, 0x56]);
    let r = dn(&b);
    assert_eq!(r.status(), Status::DecodedSubset);
    assert_eq!(
        values(&r, "point_index"),
        vec![&Value::Unsigned(0), &Value::Unsigned(1)]
    );
    assert_eq!(
        values(&r, "value"),
        vec![&Value::Unsigned(0x1234), &Value::Unsigned(0x5678)]
    );
    assert_eq!(r.records()[1].range(), 5..9);
    assert_eq!(r.records()[2].range(), 9..13);
}

#[test]
fn dnp_group0_truncated_value_stops_without_resynchronizing() {
    let b = ev(&[0, 245, 7, 1, 1, 4, b'A', b'B']);
    let r = dn(&b);
    assert_eq!(r.status(), Status::Incomplete);
    assert_eq!(r.consumed(), 4);
    assert_eq!(r.records().len(), 1);
    assert!(values(&r, "value").is_empty());
}

#[test]
fn dnp_group0_invalid_known_width_is_explicitly_unsupported() {
    let b = ev(&[0, 209, 7, 1, 2, 3, 1, 2, 3]);
    let r = dn(&b);
    assert_eq!(r.status(), Status::Unsupported);
    assert!(r
        .issues()
        .iter()
        .any(|i| i.code == "dnp3_attribute_unsigned_width"));
}

#[test]
fn dnp_group0_unknown_data_type_is_hashed_and_flagged_opaque() {
    let b = ev(&[0, 250, 7, 1, 0xee, 2, 0xaa, 0xbb]);
    let r = dn(&b);
    assert_eq!(r.status(), Status::DecodedSubset);
    assert!(r
        .issues()
        .iter()
        .any(|i| i.code == "dnp3_attribute_data_type_opaque"));
    assert!(matches!(
        values(&r, "value")[0],
        Value::OctetsSha256 { length: 2, .. }
    ));
}

#[test]
fn dnp_group0_boolean_attribute_uses_declared_variation_and_signed_wire_type() {
    let b = ev(&[0, 219, 7, 1, 3, 1, 1]);
    let r = dn(&b);
    assert_eq!(r.status(), Status::DecodedSubset);
    assert_eq!(values(&r, "value"), vec![&Value::Boolean(true)]);
}

#[test]
fn dnp_group0_all_attributes_request_is_header_only_evidence() {
    let b = ev(&[0, 254, 0, 0, 0]);
    let r = dnp3::decode(&b, dnp3::Context::ReadHeaders, Limits::default()).unwrap();
    assert_eq!(r.status(), Status::DecodedSubset);
    assert_eq!(r.consumed(), 5);
    assert_eq!(r.records().len(), 1);
    assert!(values(&r, "value").is_empty());
}

#[test]
fn dnp_group0_attribute_list_preserves_entries_and_exact_spans() {
    let b = ev(&[0, 255, 7, 1, 254, 4, 20, 0, 21, 1]);
    let r = dn(&b);
    assert_eq!(r.status(), Status::DecodedSubset);
    assert_eq!(
        r.records()
            .iter()
            .filter(|record| record.kind() == "attribute_list_entry")
            .count(),
        2
    );
    assert_eq!(r.records()[1].range(), 6..8);
    assert_eq!(r.records()[2].range(), 8..10);
    assert_eq!(r.records()[3].range(), 4..10);
    assert_eq!(
        values(&r, "variation"),
        vec![
            &Value::Unsigned(255),
            &Value::Unsigned(20),
            &Value::Unsigned(21)
        ]
    );
    assert_eq!(values(&r, "list_entry_count"), vec![&Value::Unsigned(2)]);
}

#[test]
fn dnp_group0_odd_attribute_list_is_unsupported_without_resynchronizing() {
    let b = ev(&[0, 255, 7, 1, 254, 3, 20, 0, 21]);
    let r = dn(&b);
    assert_eq!(r.status(), Status::Unsupported);
    assert_eq!(r.consumed(), 4);
    assert!(r
        .issues()
        .iter()
        .any(|issue| issue.code == "dnp3_attribute_list_width"));
}

#[test]
fn dnp_group70_file_command_retains_metadata_and_hashes_sensitive_fields() {
    let b = ev(&[
        70, 3, 0x5b, 1, 29, 0, 26, 0, 3, 0, 1, 2, 3, 4, 5, 6, 0x34, 0x12, 0xaa, 0xbb, 0xcc, 0xdd,
        100, 0, 0, 0, 1, 0, 64, 0, 9, 0, b'A', b'B', b'C',
    ]);
    let r = dn(&b);
    assert_eq!(r.status(), Status::DecodedSubset);
    assert_eq!(r.records()[1].kind(), "file_object");
    assert_eq!(r.records()[1].range(), 4..35);
    assert_eq!(values(&r, "file_size"), vec![&Value::Unsigned(100)]);
    assert_eq!(values(&r, "file_name_length"), vec![&Value::Unsigned(3)]);
    assert!(matches!(
        values(&r, "file_name")[0],
        Value::OctetsSha256 { length: 3, .. }
    ));
    assert!(matches!(
        values(&r, "auth_key")[0],
        Value::OctetsSha256 { length: 4, .. }
    ));
    let json = r.json().unwrap().encode();
    assert!(!json.contains("ABC"));
    assert!(!json.contains("aabbccdd"));
}

#[test]
fn dnp_group70_transport_and_status_variants_keep_block_and_hash_content() {
    let transport = ev(&[
        70, 5, 0x5b, 1, 11, 0, 1, 0, 0, 0, 2, 0, 0, 0, b'X', b'Y', b'Z',
    ]);
    let r = dn(&transport);
    assert_eq!(r.status(), Status::DecodedSubset);
    assert_eq!(values(&r, "block_number"), vec![&Value::Unsigned(2)]);
    assert!(matches!(
        values(&r, "content")[0],
        Value::OctetsSha256 { length: 3, .. }
    ));

    let status = ev(&[
        70, 6, 0x5b, 1, 12, 0, 1, 0, 0, 0, 3, 0, 0, 0, 0x17, b'o', b'k', b'!',
    ]);
    let r = dn(&status);
    assert_eq!(r.status(), Status::DecodedSubset);
    assert_eq!(values(&r, "status"), vec![&Value::Unsigned(0x17)]);
    assert!(matches!(
        values(&r, "status_text")[0],
        Value::OctetsSha256 { length: 3, .. }
    ));

    let command_status = ev(&[
        70, 4, 0x5b, 1, 15, 0, 1, 0, 0, 0, 100, 0, 0, 0, 2, 0, 9, 0, 0x17, b'o', b'k',
    ]);
    let r = dn(&command_status);
    assert_eq!(r.status(), Status::DecodedSubset);
    assert!(matches!(
        values(&r, "status_text")[0],
        Value::OctetsSha256 { length: 2, .. }
    ));
}

#[test]
fn dnp_group70_descriptor_and_specification_variants_are_bounded_and_hash_only() {
    let descriptor = ev(&[
        70, 7, 0x5b, 1, 27, 0, 20, 0, 7, 0, 1, 0, 0x44, 0x33, 0x22, 0x11, 1, 2, 3, 4, 5, 6, 0xaa,
        0xbb, 0x34, 0x12, b'f', b'o', b'o', b'.', b'd', b'a', b't',
    ]);
    let r = dn(&descriptor);
    assert_eq!(r.status(), Status::DecodedSubset);
    assert_eq!(values(&r, "file_type"), vec![&Value::Unsigned(1)]);
    assert_eq!(values(&r, "file_size"), vec![&Value::Unsigned(0x1122_3344)]);
    assert_eq!(values(&r, "request_id"), vec![&Value::Unsigned(0x1234)]);
    assert!(matches!(
        values(&r, "file_name")[0],
        Value::OctetsSha256 { length: 7, .. }
    ));
    let json = r.json().unwrap().encode();
    assert!(!json.contains("foo.dat"));

    let specification = ev(&[70, 8, 0x5b, 1, 4, 0, b't', b'e', b's', b't']);
    let r = dn(&specification);
    assert_eq!(r.status(), Status::DecodedSubset);
    assert_eq!(
        values(&r, "file_specification_length"),
        vec![&Value::Unsigned(4)]
    );
    assert!(matches!(
        values(&r, "file_specification")[0],
        Value::OctetsSha256 { length: 4, .. }
    ));
    let json = r.json().unwrap().encode();
    assert!(!json.contains("test"));
}

#[test]
fn dnp_group70_descriptor_offsets_and_lengths_are_not_guessed() {
    let bad_offset = ev(&[
        70, 7, 0x5b, 1, 21, 0, 19, 0, 7, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        b'x',
    ]);
    let r = dn(&bad_offset);
    assert_eq!(r.status(), Status::Rejected);
    assert!(r
        .issues()
        .iter()
        .any(|issue| issue.code == "dnp3_file_name_range"));

    let truncated = ev(&[70, 7, 0x5b, 1, 20, 0, 1, 0, 0]);
    let r = dn(&truncated);
    assert_eq!(r.status(), Status::Incomplete);
    assert_eq!(r.records().len(), 1);
}

#[test]
fn dnp_group70_file_requests_are_bounded_and_opaque_neighbors_stop() {
    let mut request_bytes = vec![70, 3, 0x5b, 1, 29, 0];
    request_bytes.extend_from_slice(&[0; 29]);
    request_bytes[6] = 26;
    request_bytes[8] = 3;
    request_bytes[32..35].copy_from_slice(b"ABC");
    let request = ev(&request_bytes);
    let r = dnp3::decode(&request, dnp3::Context::FileValues, Limits::default()).unwrap();
    assert_eq!(r.status(), Status::DecodedSubset);

    let opaque = ev(&[70, 2, 0x5b, 1, 1, 0, 0]);
    assert_eq!(dn(&opaque).status(), Status::Unsupported);

    let truncated = ev(&[70, 5, 0x5b, 1, 8, 0, 1, 0, 0, 0, 2, 0]);
    let r = dn(&truncated);
    assert_eq!(r.status(), Status::Incomplete);
    assert_eq!(r.records().len(), 1);
}

fn dnp_group70_minimum_payload(variation: u8, file_handle: u32) -> Vec<u8> {
    let mut payload = file_handle.to_le_bytes().to_vec();
    match variation {
        4 => {
            payload.extend_from_slice(&0x1234_5678u32.to_le_bytes());
            payload.extend_from_slice(&0x2345u16.to_le_bytes());
            payload.extend_from_slice(&0x3456u16.to_le_bytes());
            payload.push(0x17);
        }
        5 => payload.extend_from_slice(&0x4567_89abu32.to_le_bytes()),
        6 => {
            payload.extend_from_slice(&0x4567_89abu32.to_le_bytes());
            payload.push(0x17);
        }
        _ => unreachable!(),
    }
    payload
}

fn dnp_group70_command_or_descriptor_payload(variation: u8, file_size: u32) -> Vec<u8> {
    let length = match variation {
        3 => 26,
        7 => 21,
        _ => unreachable!(),
    };
    let mut payload = vec![0; length];
    payload[..2].copy_from_slice(&(length as u16).to_le_bytes());
    match variation {
        3 => {
            payload[16..20].copy_from_slice(&file_size.to_le_bytes());
            payload[24..26].copy_from_slice(&(file_size as u16).to_le_bytes());
        }
        7 => {
            payload[..2].copy_from_slice(&20u16.to_le_bytes());
            payload[2..4].copy_from_slice(&1u16.to_le_bytes());
            payload[6..10].copy_from_slice(&file_size.to_le_bytes());
            payload[18..20].copy_from_slice(&(file_size as u16).to_le_bytes());
            payload[20] = b'F';
        }
        _ => unreachable!(),
    }
    payload
}

fn dnp_group70_minimum_descriptor_payload(file_size: u32) -> Vec<u8> {
    let mut payload = vec![0; 20];
    payload[..2].copy_from_slice(&20u16.to_le_bytes());
    payload[2..4].copy_from_slice(&0u16.to_le_bytes());
    payload[6..10].copy_from_slice(&file_size.to_le_bytes());
    payload[18..20].copy_from_slice(&(file_size as u16).to_le_bytes());
    payload
}

fn dnp_group70_minimum(variation: u8) -> usize {
    match variation {
        3 => 26,
        4 => 13,
        5 => 8,
        6 => 9,
        7 => 20,
        _ => unreachable!(),
    }
}

fn dnp_group70_payload(variation: u8, identity: u32) -> Vec<u8> {
    match variation {
        3 | 7 => dnp_group70_command_or_descriptor_payload(variation, identity),
        4..=6 => dnp_group70_minimum_payload(variation, identity),
        _ => unreachable!(),
    }
}

fn dnp_group70_exact_minimum_payload(variation: u8, identity: u32) -> Vec<u8> {
    match variation {
        7 => dnp_group70_minimum_descriptor_payload(identity),
        _ => dnp_group70_payload(variation, identity),
    }
}

fn dnp_push_counted_object(
    bytes: &mut Vec<u8>,
    group: u8,
    variation: u8,
    count: u8,
    payload: &[u8],
) {
    bytes.extend_from_slice(&[group, variation, 0x07, count]);
    bytes.extend_from_slice(payload);
}

fn dnp_group70_issue_code(variation: u8) -> &'static str {
    match variation {
        3 => "dnp3_file_command",
        4 => "dnp3_file_command_status",
        5 => "dnp3_file_transport",
        6 => "dnp3_file_transport_status",
        7 => "dnp3_file_descriptor",
        _ => unreachable!(),
    }
}

#[test]
fn dnp_group70_variations3_to7_reject_every_short_declared_child_before_sibling_bytes() {
    for variation in 3..=7 {
        let minimum = dnp_group70_minimum(variation);
        let first = dnp_group70_payload(variation, 0x0102_0304);
        let sibling = dnp_group70_payload(variation, 0x0506_0708);
        assert!(first.len() >= minimum, "variation {variation}");
        assert!(sibling.len() >= minimum, "variation {variation}");

        for short_length in 0..minimum {
            // Even the zero-length child is followed by enough valid sibling
            // bytes to satisfy a fixed-width read that ignores the child bound.
            assert!(short_length + 2 + sibling.len() >= minimum);
            let mut bytes = vec![70, variation, 0x5b, 2];
            bytes.extend_from_slice(&(short_length as u16).to_le_bytes());
            bytes.extend_from_slice(&first[..short_length]);
            bytes.extend_from_slice(&(sibling.len() as u16).to_le_bytes());
            bytes.extend_from_slice(&sibling);

            let evidence = ev(&bytes);
            let decoded = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                dnp3::decode(&evidence, dnp3::Context::ResponseValues, Limits::default())
            }));
            let r = decoded
                .expect("short declared Group 70 child must not panic")
                .unwrap();
            assert_eq!(
                r.status(),
                Status::Rejected,
                "variation {variation}, declared length {short_length}"
            );
            assert!(
                r.issues()
                    .iter()
                    .any(|issue| issue.code == dnp_group70_issue_code(variation)),
                "variation {variation}, declared length {short_length}"
            );
            assert!(
                r.records()
                    .iter()
                    .all(|record| record.kind() != "file_object"),
                "variation {variation}, declared length {short_length}: no malformed/sibling object may be published"
            );
            for field in [
                "file_handle",
                "file_name_offset",
                "file_name_length",
                "file_size",
                "request_id",
            ] {
                assert!(
                    values(&r, field).is_empty(),
                    "variation {variation}, declared length {short_length}: leaked {field}"
                );
            }
            for record in r.records() {
                let record_range = record.range();
                assert!(record_range.start <= record_range.end && record_range.end <= bytes.len());
                for field in record.fields() {
                    let field_range = field.range();
                    assert!(
                        field_range.start >= record_range.start
                            && field_range.end <= record_range.end,
                        "variation {variation}, declared length {short_length}: field {} escaped record {:?}: {:?}",
                        field.name(),
                        record_range,
                        field_range
                    );
                }
            }
        }
    }
}

#[test]
fn dnp_group70_variations3_to7_decode_exact_minimum_adjacent_children_with_bounded_spans() {
    for variation in 3..=7 {
        let identities = [0x0102_0304, 0x0506_0708];
        let payloads = identities.map(|value| dnp_group70_exact_minimum_payload(variation, value));
        let minimum = dnp_group70_minimum(variation);
        let mut bytes = vec![70, variation, 0x5b, 2];
        for payload in &payloads {
            assert_eq!(payload.len(), minimum, "variation {variation}");
            bytes.extend_from_slice(&(payload.len() as u16).to_le_bytes());
            bytes.extend_from_slice(payload);
        }

        let evidence = ev(&bytes);
        let r = dn(&evidence);
        assert_eq!(
            r.status(),
            Status::DecodedSubset,
            "variation {variation}; issues: {:?}",
            r.issues()
        );
        let file_objects: Vec<_> = r
            .records()
            .iter()
            .filter(|record| record.kind() == "file_object")
            .collect();
        assert_eq!(file_objects.len(), 2, "variation {variation}");

        if matches!(variation, 3 | 7) {
            assert_eq!(
                values(&r, "file_size"),
                vec![
                    &Value::Unsigned(identities[0] as u64),
                    &Value::Unsigned(identities[1] as u64)
                ],
                "variation {variation}"
            );
            assert_eq!(
                values(&r, "request_id"),
                vec![&Value::Unsigned(0x0304), &Value::Unsigned(0x0708)],
                "variation {variation}"
            );
        } else {
            assert_eq!(
                values(&r, "file_handle"),
                vec![
                    &Value::Unsigned(identities[0] as u64),
                    &Value::Unsigned(identities[1] as u64)
                ],
                "variation {variation}"
            );
        }
        if variation == 7 {
            assert_eq!(
                values(&r, "file_name_length"),
                vec![&Value::Unsigned(0), &Value::Unsigned(0)],
                "the exact-minimum descriptor carries an explicit empty name length"
            );
            assert!(
                file_objects
                    .iter()
                    .flat_map(|record| record.fields())
                    .all(|field| field.name() != "file_name"),
                "empty file names have no zero-width source field"
            );
        }

        let mut child_start = 4;
        for (index, record) in file_objects.iter().enumerate() {
            let payload_start = child_start + 2;
            let payload_end = payload_start + minimum;
            let record_range = record.range();
            assert_eq!(
                record_range,
                child_start..payload_end,
                "variation {variation}"
            );
            for field in record.fields() {
                let field_range = field.range();
                assert!(
                    field_range.start >= record_range.start && field_range.end <= record_range.end,
                    "variation {variation} field {} escaped child {}: {:?} not in {:?}",
                    field.name(),
                    index,
                    field_range,
                    record_range
                );
                if field.name() == "length" {
                    assert_eq!(field_range, child_start..payload_start);
                } else {
                    assert!(
                        field_range.start >= payload_start && field_range.end <= payload_end,
                        "variation {variation} payload field {} escaped declared payload: {:?}",
                        field.name(),
                        field_range
                    );
                }
            }
            child_start = payload_end;
        }
    }
}

#[test]
fn dnp_group40_and_41_variation4_decode_float64_and_keep_sibling_alignment() {
    let patterns: [u64; 4] = [
        0x3ff0_0000_0000_0000, // 1.0
        0x8000_0000_0000_0000, // negative zero
        0x7ff0_0000_0000_0000, // positive infinity
        0x7ff8_1234_5678_9abc, // NaN with payload
    ];

    for group in [40, 41] {
        let mut payload = Vec::new();
        for (index, bits) in patterns.into_iter().enumerate() {
            if group == 40 {
                payload.push(0x20 + index as u8);
            }
            payload.extend_from_slice(&bits.to_le_bytes());
            if group == 41 {
                payload.push(0x40 + index as u8);
            }
        }
        let mut bytes = Vec::new();
        dnp_push_counted_object(&mut bytes, group, 4, patterns.len() as u8, &payload);
        dnp_push_counted_object(&mut bytes, 20, 1, 1, &[0x81, 0xef, 0xbe, 0xad, 0xde]);

        let evidence = ev(&bytes);
        let r = dn(&evidence);
        assert_eq!(r.status(), Status::DecodedSubset, "group {group}");
        let decoded_values = values(&r, "value");
        for (index, bits) in patterns.into_iter().enumerate() {
            assert_eq!(
                decoded_values[index],
                &Value::Float64Bits(bits),
                "group {group}, record {index}"
            );
        }
        assert_eq!(decoded_values[4], &Value::Unsigned(0xdead_beef));
        if group == 40 {
            assert_eq!(
                &values(&r, "flags")[..4],
                &[
                    &Value::Unsigned(0x20),
                    &Value::Unsigned(0x21),
                    &Value::Unsigned(0x22),
                    &Value::Unsigned(0x23)
                ]
            );
        } else {
            assert_eq!(
                values(&r, "command_status"),
                vec![
                    &Value::Unsigned(0x40),
                    &Value::Unsigned(0x41),
                    &Value::Unsigned(0x42),
                    &Value::Unsigned(0x43)
                ]
            );
        }
    }
}

#[test]
fn dnp_counter_event_variations5_and6_decode_timestamps_with_exact_boundaries() {
    let timestamps: [u64; 2] = [0x0605_0403_0201, 0x0a0b_0c0d_0e0f];
    for group in [21, 22, 23] {
        for (variation, value_width) in [(5, 4usize), (6, 2usize)] {
            let counter_values: [u64; 2] = if value_width == 4 {
                [0x1234_5678, 0x89ab_cdef]
            } else {
                [0x1234, 0xabcd]
            };
            let mut payload = Vec::new();
            for (index, value) in counter_values.into_iter().enumerate() {
                payload.push(0x80 + index as u8);
                let encoded_value = value.to_le_bytes();
                payload.extend_from_slice(&encoded_value[..value_width]);
                let encoded_time = timestamps[index].to_le_bytes();
                payload.extend_from_slice(&encoded_time[..6]);
            }
            let mut bytes = Vec::new();
            dnp_push_counted_object(&mut bytes, group, variation, 2, &payload);
            dnp_push_counted_object(&mut bytes, 20, 1, 1, &[0x81, 0xef, 0xbe, 0xad, 0xde]);

            let evidence = ev(&bytes);
            let r = dn(&evidence);
            assert_eq!(
                r.status(),
                Status::DecodedSubset,
                "group {group} var {variation}"
            );
            let decoded_values = values(&r, "value");
            assert_eq!(decoded_values[0], &Value::Unsigned(counter_values[0]));
            assert_eq!(decoded_values[1], &Value::Unsigned(counter_values[1]));
            assert_eq!(decoded_values[2], &Value::Unsigned(0xdead_beef));
            assert_eq!(
                values(&r, "time"),
                vec![
                    &Value::Milliseconds48(timestamps[0]),
                    &Value::Milliseconds48(timestamps[1])
                ],
                "group {group} var {variation}"
            );

            let record_width = 1 + value_width + 6;
            let mut truncated = Vec::new();
            dnp_push_counted_object(
                &mut truncated,
                group,
                variation,
                1,
                &payload[..record_width - 1],
            );
            let truncated_evidence = ev(&truncated);
            let incomplete = dn(&truncated_evidence);
            assert_eq!(
                incomplete.status(),
                Status::Incomplete,
                "group {group} var {variation} must require all six timestamp octets"
            );
            assert!(values(&incomplete, "value").is_empty());
        }
    }
}

#[test]
fn dnp_group4_event_variations_decode_all_double_bit_states_and_align_sibling() {
    for variation in [1, 2, 3] {
        let mut payload = Vec::new();
        let mut flags = Vec::new();
        let mut expected_times = Vec::new();
        for state in 0..4u8 {
            let raw_flags = 0x15 | (state << 6);
            flags.push(raw_flags);
            payload.push(raw_flags);
            match variation {
                1 => {}
                2 => {
                    let time = 0x0605_0403_0201u64 + u64::from(state);
                    let encoded_time = time.to_le_bytes();
                    payload.extend_from_slice(&encoded_time[..6]);
                    expected_times.push(Value::Milliseconds48(time));
                }
                3 => {
                    let time = 0x1230u16 + u16::from(state);
                    payload.extend_from_slice(&time.to_le_bytes());
                    expected_times.push(Value::RelativeMilliseconds16(time));
                }
                _ => unreachable!(),
            }
        }
        let mut bytes = Vec::new();
        dnp_push_counted_object(&mut bytes, 4, variation, 4, &payload);
        dnp_push_counted_object(&mut bytes, 20, 1, 1, &[0x81, 0xef, 0xbe, 0xad, 0xde]);

        let evidence = ev(&bytes);
        let r = dn(&evidence);
        assert_eq!(r.status(), Status::DecodedSubset, "variation {variation}");
        let decoded_flags = values(&r, "flags");
        for (index, raw_flags) in flags.iter().enumerate() {
            assert_eq!(
                decoded_flags[index],
                &Value::Unsigned(u64::from(*raw_flags)),
                "variation {variation}, raw flags {index}"
            );
        }
        let decoded_values = values(&r, "value");
        for state in 0..4u64 {
            assert_eq!(
                decoded_values[state as usize],
                &Value::Unsigned(state),
                "variation {variation}, state {state}"
            );
        }
        assert_eq!(decoded_values[4], &Value::Unsigned(0xdead_beef));
        assert_eq!(
            values(&r, "time"),
            expected_times.iter().collect::<Vec<_>>()
        );
    }
}
