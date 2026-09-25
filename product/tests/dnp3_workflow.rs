//! Source-bound deep continuation regressions; these are not normative vectors.
use pcap_evidence::{
    provenance::{EvidenceBytes, PacketId},
    semantics::{self, Status as SemanticStatus},
    Result,
};
use pcap_evidence_product::deep::{
    self,
    continuation::{Completed, Parser},
    Context, Limits, Status,
};

const VECTORS: &str = include_str!("../../tests/fixtures/dnp3_workflows.hex");
fn wire(name: &str, frame: u64) -> EvidenceBytes {
    let hex = VECTORS
        .lines()
        .find(|s| s.split_whitespace().next() == Some(name))
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap();
    let data: Vec<_> = (0..hex.len())
        .step_by(2)
        .map(|p| u8::from_str_radix(&hex[p..p + 2], 16).unwrap())
        .collect();
    EvidenceBytes::from_packet(
        &data,
        PacketId {
            capture: [9; 32],
            frame,
            record_offset: frame * 100,
        },
        54,
    )
}
fn feed(p: &mut Parser, at: i64, b: &EvidenceBytes, output: &mut Vec<Completed>) -> Result<()> {
    p.feed(at, b, &mut |r| {
        output.push(r);
        Ok(())
    })
}
fn parser() -> Parser {
    Parser::new("dnp3", Limits::default(), Context::default()).unwrap()
}

fn reference_dnp_crc16(bytes: &[u8]) -> u16 {
    let mut crc = 0u16;
    for byte in bytes {
        crc ^= u16::from(byte.reverse_bits()) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 {
                (crc << 1) ^ 0x3d65
            } else {
                crc << 1
            };
        }
    }
    crc.reverse_bits() ^ 0xffff
}

fn append_dnp_crc(bytes: &mut Vec<u8>, block: &[u8]) {
    bytes.extend_from_slice(&reference_dnp_crc16(block).to_le_bytes());
}

fn group70_response_frame(objects: &[u8], frame: u64) -> EvidenceBytes {
    let mut user_data = vec![0xc0, 0xc0, 0x81, 0x00, 0x00];
    user_data.extend_from_slice(objects);
    let link_length = u8::try_from(5 + user_data.len()).unwrap();
    let mut data = vec![0x05, 0x64, link_length, 0x44, 0x01, 0x00, 0x0a, 0x00];
    let header = data.clone();
    append_dnp_crc(&mut data, &header);
    for block in user_data.chunks(16) {
        data.extend_from_slice(block);
        append_dnp_crc(&mut data, block);
    }
    EvidenceBytes::from_packet(
        &data,
        PacketId {
            capture: [0x71; 32],
            frame,
            record_offset: frame * 1000,
        },
        data.len(),
    )
}

fn group70_v5_payload(file_handle: u32, block_number: u32) -> [u8; 8] {
    let mut payload = [0; 8];
    payload[..4].copy_from_slice(&file_handle.to_le_bytes());
    payload[4..].copy_from_slice(&block_number.to_le_bytes());
    payload
}

fn group70_v5_objects(children: &[&[u8]]) -> Vec<u8> {
    let mut objects = vec![70, 5, 0x5b, u8::try_from(children.len()).unwrap()];
    for child in children {
        objects.extend_from_slice(&u16::try_from(child.len()).unwrap().to_le_bytes());
        objects.extend_from_slice(child);
    }
    objects
}

fn dnp_apdu_from_frame(frame: &EvidenceBytes) -> EvidenceBytes {
    let (link, _) = pcap_evidence::dnp3::parse_link(frame, 0, 0).unwrap();
    link.user_data.slice(1..link.user_data.len()).unwrap()
}

#[test]
fn deep_continuation_group70_short_child_rejects_without_objects_and_valid_siblings_survive() {
    assert_eq!(reference_dnp_crc16(b"123456789"), 0xea82);

    let malformed_child = group70_v5_payload(0x0102_0304, 1);
    let valid_sibling = group70_v5_payload(0x0506_0708, 2);
    let malformed_objects = {
        let mut objects = vec![70, 5, 0x5b, 2, 7, 0];
        objects.extend_from_slice(&malformed_child[..7]);
        objects.extend_from_slice(&(valid_sibling.len() as u16).to_le_bytes());
        objects.extend_from_slice(&valid_sibling);
        objects
    };
    let malformed_frame = group70_response_frame(&malformed_objects, 100);
    let malformed_apdu = dnp_apdu_from_frame(&malformed_frame);
    let root = semantics::dnp3_workflow::application(&malformed_apdu, semantics::Limits::default())
        .unwrap();
    assert_eq!(root.status(), SemanticStatus::Rejected);
    assert_eq!(root.source(), &malformed_apdu);
    assert!(root
        .records()
        .iter()
        .all(|record| record.kind() != "file_object"));
    for record in root.records() {
        let record_range = record.range();
        assert!(record_range.start <= record_range.end && record_range.end <= malformed_apdu.len());
        for field in record.fields() {
            let field_range = field.range();
            assert!(
                field_range.start >= record_range.start && field_range.end <= record_range.end,
                "root field {} escaped record {:?}: {:?}",
                field.name(),
                record_range,
                field_range
            );
        }
    }

    let mut malformed_parser = parser();
    let mut malformed_output = Vec::new();
    assert!(feed(
        &mut malformed_parser,
        0,
        &malformed_frame,
        &mut malformed_output
    )
    .is_err());
    assert_eq!(malformed_output.len(), 1);
    let rejected = &malformed_output[0].report;
    assert_eq!(rejected.protocol, "dnp3.rejected");
    assert_eq!(rejected.evidence, malformed_frame);
    assert!(rejected
        .notes
        .iter()
        .any(|note| note.status == Status::Incomplete));
    assert!(rejected.fields.iter().all(|field| {
        !field.name.starts_with("file_object") && field.name != "root_application_workflow"
    }));
    assert!(!rejected.json().encode().contains("file_object"));

    let first = group70_v5_payload(0x0102_0304, 0x1112_1314);
    let second = group70_v5_payload(0x0506_0708, 0x2122_2324);
    let valid_frame = group70_response_frame(&group70_v5_objects(&[&first, &second]), 101);
    let mut valid_parser = parser();
    let mut valid_output = Vec::new();
    feed(&mut valid_parser, 0, &valid_frame, &mut valid_output).unwrap();
    assert_eq!(valid_output.len(), 1);
    let completed = &valid_output[0].report;
    assert!(completed.json().encode().contains("link_frame_evidence"));
    let text = completed.json().encode();
    let source_hash =
        pcap_evidence::sha256::hex(&pcap_evidence::sha256::digest(valid_frame.data()));
    assert!(text.contains(&source_hash));
    assert!(text.contains("\"status\":\"decoded_subset\""));
    assert_eq!(text.matches("\"kind\":\"file_object\"").count(), 2);
    assert!(text.contains("\"name\":\"file_object[0]\""));
    assert!(text.contains("\"name\":\"file_object[1]\""));
    for value in [0x0102_0304u32, 0x0506_0708u32] {
        assert_eq!(
            text.matches(&format!("\"{}\"", value)).count(),
            2,
            "file handle {value} must appear in both root and legacy projections"
        );
    }
}

#[test]
fn every_history_page_split_preserves_complete_workflow_and_source_hashes() {
    let raw = wire("time_write_absolute", 1);
    for split in 0..=raw.len() {
        let mut p = parser();
        let mut output = Vec::new();
        feed(&mut p, 0, &raw.slice(0..split).unwrap(), &mut output).unwrap();
        feed(
            &mut p,
            split as i64,
            &raw.slice(split..raw.len()).unwrap(),
            &mut output,
        )
        .unwrap();
        assert_eq!(output.len(), 1, "split={split}");
        let report = &output[0].report;
        let text = report.json().encode();
        assert!(text.contains("non_secure_time_write"));
        assert!(text.contains("123456"));
        assert!(text.contains("link_frame_evidence"));
        assert!(text.contains("application_evidence"));
        assert!(report.evidence.validate());
        assert_eq!(report.evidence.packets()[0].frame, 1);
        assert!(p.finish().unwrap().is_none());
    }
}

#[test]
fn multi_application_fragments_are_explicitly_incomplete_not_misparsed() {
    let first = wire("application_first", 1);
    let final_part = wire("application_final", 2);
    let mut p = parser();
    let mut output = Vec::new();
    feed(&mut p, 0, &first, &mut output).unwrap();
    feed(&mut p, first.len() as i64, &final_part, &mut output).unwrap();
    assert_eq!(output.len(), 2);
    for r in output {
        assert!(r
            .report
            .notes
            .iter()
            .any(|n| n.status == Status::Incomplete));
        let text = r.report.json().encode();
        assert!(!text.contains("\"kind\":\"object_value\""));
        assert!(text.contains("application_fragment_needs_verified_message_assembly"));
    }
}

#[test]
fn legacy_application_sequence_does_not_decode_a_middle_object_region() {
    let raw = wire("application_first", 1);
    let (link, _) = pcap_evidence::dnp3::parse_link(&raw, 0, 0).unwrap();
    let objects = link.user_data.slice(5..link.user_data.len()).unwrap();
    let mut sequence = deep::dnp::ApplicationSequence::new(8).unwrap();
    let report = sequence
        .observe(0x8f, 0x81, &objects, &Limits::default())
        .unwrap();
    assert!(report.notes.iter().any(|n| n.status == Status::Incomplete));
    assert!(!report.fields.iter().any(|f| f.name.starts_with("point[")));
}

#[test]
fn corrupt_crc_poisons_continuation_and_preserves_rejected_source() {
    let bad = wire("bad_crc_nested_frame", 1);
    let next = wire("record_time", 2);
    let mut p = parser();
    let mut output = Vec::new();
    assert!(feed(&mut p, 0, &bad, &mut output).is_err());
    assert_eq!(output.len(), 1);
    assert_eq!(output[0].report.evidence, bad);
    assert!(output[0]
        .report
        .notes
        .iter()
        .any(|n| n.status == Status::Rejected));
    assert!(feed(&mut p, bad.len() as i64, &next, &mut output).is_err());
    p.cut("test_explicit_new_scope").unwrap();
    feed(&mut p, bad.len() as i64, &next, &mut output).unwrap();
    assert_eq!(output.len(), 2);
}

#[test]
fn identical_transport_duplicate_retains_both_link_witnesses() {
    let names = [
        "transport_first",
        "transport_middle",
        "transport_middle",
        "transport_final",
    ];
    let mut p = parser();
    let mut output = Vec::new();
    let mut offset = 0;
    for (i, name) in names.iter().enumerate() {
        let raw = wire(name, i as u64 + 1);
        feed(&mut p, offset, &raw, &mut output).unwrap();
        offset += raw.len() as i64;
    }
    assert_eq!(output.len(), 2); // explicit duplicate, then completed APDU
    assert!(output[0].report.json().encode().contains("duplicate"));
    let text = output[1].report.json().encode();
    assert!(text.contains("link_frame_evidence"));
    assert!(text.contains("\"frame\":\"3\""));
    assert!(text.contains("\"kind\":\"object_value\""));
}

#[test]
fn reordered_or_conflicting_transport_requires_cut_not_speculation() {
    for middle in [
        "transport_first",
        "transport_middle_conflict",
        "transport_final",
    ] {
        let mut p = parser();
        let mut output = Vec::new();
        let a = wire("transport_first", 1);
        let b = wire("transport_middle", 2);
        feed(&mut p, 0, &a, &mut output).unwrap();
        let (at, bad) = if middle == "transport_final" {
            (a.len() as i64, wire(middle, 3)) // missing middle
        } else {
            feed(&mut p, a.len() as i64, &b, &mut output).unwrap();
            ((a.len() + b.len()) as i64, wire(middle, 3))
        };
        assert!(feed(&mut p, at, &bad, &mut output).is_err());
        let cut = p.cut("test_discontinuity").unwrap();
        assert!(cut.json().encode().contains("discarded_state_evidence"));
        assert!(cut.notes.iter().any(|n| n.status == Status::Incomplete));
    }
}

#[test]
fn truncated_declared_frame_retains_exact_range_at_finish() {
    let raw = wire("declared_truncated", 1);
    let mut p = parser();
    let mut output = Vec::new();
    feed(&mut p, 0, &raw, &mut output).unwrap();
    assert!(output.is_empty());
    let report = p.finish().unwrap().unwrap();
    assert_eq!(report.evidence, raw);
    assert!(report.notes.iter().any(|n| n.status == Status::Incomplete));
}
