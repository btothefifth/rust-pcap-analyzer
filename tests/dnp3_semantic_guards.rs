//! Primary DNP Users Group AN2013-004b Tables 2/3 define these negative
//! shapes; valid siblings exercise the same parser without guessing a layout.
use pcap_evidence::{
    dnp3,
    provenance::{EvidenceBytes, PacketId},
    semantics::{dnp3 as objects, dnp3_workflow as workflow, Limits, Status},
};

fn evidence(bytes: &[u8]) -> EvidenceBytes {
    EvidenceBytes::from_packet(
        bytes,
        PacketId {
            capture: [7; 32],
            frame: 1,
            record_offset: 24,
        },
        54,
    )
}

#[test]
fn unsupported_group_variations_stop_before_values_or_a_following_sibling() {
    for invalid in [
        vec![3, 3, 7, 1, 128, 0, 0, 0, 0, 0, 0],
        vec![3, 4, 7, 1, 128, 0, 0],
        vec![11, 3, 7, 1, 128, 0, 0],
        vec![13, 3, 7, 1, 128, 0, 0],
        vec![20, 9, 7, 1, 1, 0, 0, 0],
        vec![20, 10, 7, 1, 1, 0],
        vec![80, 2, 7, 1, 128],
    ] {
        let mut bytes = invalid.clone();
        bytes.extend_from_slice(&[1, 2, 7, 1, 129]);
        let raw = evidence(&bytes);
        let report =
            objects::decode(&raw, objects::Context::ResponseValues, Limits::default()).unwrap();
        assert_eq!(report.status(), Status::Unsupported, "{invalid:?}");
        assert_eq!(
            report.consumed(),
            4,
            "only the unsupported header may be inspected"
        );
        assert!(report
            .records()
            .iter()
            .all(|record| record.kind() != "object_value"));
        assert_eq!(
            report
                .source()
                .slice(report.consumed()..bytes.len())
                .unwrap()
                .data(),
            &bytes[4..]
        );
    }
}

#[test]
fn valid_event_frozen_counter_binary_and_iin_siblings_remain_decoded() {
    for valid in [
        vec![4, 2, 7, 1, 128, 0, 0, 0, 0, 0, 0],
        vec![2, 3, 7, 1, 128, 0, 0],
        vec![11, 2, 7, 1, 128, 0, 0, 0, 0, 0, 0],
        vec![13, 2, 7, 1, 0, 0, 0, 0, 0, 0, 0],
        vec![21, 9, 7, 1, 1, 0, 0, 0],
        vec![21, 10, 7, 1, 1, 0],
        vec![20, 5, 7, 1, 1, 0, 0, 0],
        vec![20, 6, 7, 1, 1, 0],
        vec![1, 2, 7, 1, 129],
        vec![80, 1, 0, 0, 0, 1],
    ] {
        let raw = evidence(&valid);
        let report =
            objects::decode(&raw, objects::Context::ResponseValues, Limits::default()).unwrap();
        assert_eq!(report.status(), Status::DecodedSubset, "{valid:?}");
        assert_eq!(report.consumed(), valid.len());
        assert_eq!(
            report
                .records()
                .iter()
                .filter(|record| record.kind() == "object_value")
                .count(),
            1
        );
    }
}

#[test]
fn read_and_control_functions_require_objects_but_header_only_workflows_remain_valid() {
    for function in [1, 3, 4, 5, 6] {
        let raw = evidence(&[0xc0, function]);
        let report = workflow::application(&raw, Limits::default()).unwrap();
        assert_eq!(report.status(), Status::Rejected, "function {function}");
        assert!(report
            .issues()
            .iter()
            .any(|issue| issue.code == "dnp3_workflow_objects_required"));
        let empty = EvidenceBytes::default();
        assert_eq!(
            objects::decode(
                &empty,
                objects::Context::from_function(function),
                Limits::default()
            )
            .unwrap()
            .status(),
            Status::Rejected
        );
    }
    for bytes in [
        vec![0xc0, 0],
        vec![0xc0, 23],
        vec![0xc0, 24],
        vec![0xc0, 0x81, 0, 0],
        vec![0xd0, 0x82, 0, 0],
    ] {
        let raw = evidence(&bytes);
        assert_eq!(
            workflow::application(&raw, Limits::default())
                .unwrap()
                .status(),
            Status::DecodedSubset
        );
    }
    let read = evidence(&[0xc0, 1, 60, 2, 6]);
    assert_eq!(
        workflow::application(&read, Limits::default())
            .unwrap()
            .status(),
        Status::DecodedSubset
    );
    let control = evidence(&[0xc0, 3, 12, 1, 7, 1, 3, 1, 100, 0, 0, 0, 100, 0, 0, 0, 0]);
    assert_eq!(
        workflow::application(&control, Limits::default())
            .unwrap()
            .status(),
        Status::DecodedSubset
    );
}

#[test]
fn activate_configuration_is_defined_but_semantically_outside_the_profile() {
    assert_eq!(
        dnp3::function_code(31),
        dnp3::FunctionCode::ActivateConfiguration
    );
    assert_eq!(dnp3::function_code(31).as_str(), "activate_configuration");
    let raw = evidence(&[0xc0, 31, 0, 196, 0, 0, 0]);
    assert_eq!(workflow::header(&raw).unwrap().function, 31);
    let report = workflow::application(&raw, Limits::default()).unwrap();
    assert_eq!(report.status(), Status::Unsupported);
    assert!(report
        .issues()
        .iter()
        .any(|issue| issue.code == "dnp3_workflow_outside_subset"));
    assert!(!report
        .issues()
        .iter()
        .any(|issue| issue.code == "dnp3_reserved_application_function"));
}
