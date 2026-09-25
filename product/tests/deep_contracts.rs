use pcap_evidence::{
    provenance::{EvidenceBytes, PacketId},
    sha256,
};
use pcap_evidence_product::deep::{
    self,
    model::Status,
    reassembly::{Segment, Segments, StreamBuffer},
    Context, Limits,
};

fn evidence(bytes: &[u8], frame: u64) -> EvidenceBytes {
    EvidenceBytes::from_packet(
        bytes,
        PacketId {
            capture: sha256::digest(b"deep-contract-test"),
            frame,
            record_offset: frame * 100,
        },
        0,
    )
}

#[test]
fn completed_segments_preserve_order_and_provenance() {
    let limits = Limits::default();
    let mut state = Segments::new(limits).unwrap();
    let first = state
        .push(
            "generation-1/direction-0",
            Segment {
                ordinal: 0,
                first: true,
                final_segment: false,
                bytes: evidence(b"abc", 1),
                frame: 1,
            },
        )
        .unwrap();
    assert_eq!(first.status, Status::Incomplete);

    let complete = state
        .push(
            "generation-1/direction-0",
            Segment {
                ordinal: 1,
                first: false,
                final_segment: true,
                bytes: evidence(b"def", 2),
                frame: 2,
            },
        )
        .unwrap();
    assert_eq!(complete.status, Status::Candidate);
    let bytes = complete.completed.unwrap();
    assert_eq!(bytes.data(), b"abcdef");
    assert!(bytes.validate());
    assert_eq!(bytes.packets().len(), 2);
}

#[test]
fn conflicting_duplicate_is_ambiguous_until_explicit_cut() {
    let mut state = Segments::new(Limits::default()).unwrap();
    let input = |payload| Segment {
        ordinal: 0,
        first: true,
        final_segment: true,
        bytes: evidence(payload, 1),
        frame: 1,
    };
    assert_eq!(
        state.push("scope", input(b"one")).unwrap().status,
        Status::Candidate
    );
    let conflict = state.push("scope", input(b"two")).unwrap();
    assert_eq!(conflict.status, Status::Ambiguous);
    assert!(state
        .push("scope", input(b"three"))
        .unwrap()
        .completed
        .is_none());
    let cut = state.cut("scope", "test_boundary").unwrap();
    assert_eq!(cut.status, Status::Incomplete);
    assert_eq!(state.retained_bytes(), 0);
}

#[test]
fn stream_buffer_requires_an_explicit_gap_reset() {
    let mut buffer = StreamBuffer::new(1024, 16).unwrap();
    buffer.push(100, &evidence(b"abc", 1)).unwrap();
    assert!(buffer.push(104, &evidence(b"x", 2)).is_err());
    assert!(buffer.push(103, &evidence(b"y", 2)).is_err());
    let discarded = buffer.gap();
    assert_eq!(discarded.data(), b"abc");
    buffer.push(104, &evidence(b"xy", 3)).unwrap();
    assert_eq!(buffer.bytes().data(), b"xy");
}

#[test]
fn opcua_secure_payload_stays_opaque_without_explicit_context() {
    let mut bytes = Vec::from(*b"MSGF");
    bytes.extend_from_slice(&24u32.to_le_bytes());
    bytes.extend_from_slice(&7u32.to_le_bytes());
    bytes.extend_from_slice(&9u32.to_le_bytes());
    bytes.extend_from_slice(&1u32.to_le_bytes());
    bytes.extend_from_slice(&2u32.to_le_bytes());
    let report = deep::decode(
        "opcua_tcp",
        &evidence(&bytes, 1),
        &Context::default(),
        &Limits::default(),
    )
    .unwrap();
    assert!(report
        .notes
        .iter()
        .any(|note| note.status == Status::Unsupported));
}

#[test]
fn opcua_hello_and_iec104_s_frame_are_bounded_units() {
    let mut hello = Vec::from(*b"HELF");
    hello.extend_from_slice(&32u32.to_le_bytes());
    hello.extend_from_slice(&[0u8; 20]);
    hello.extend_from_slice(&0i32.to_le_bytes());
    let ua = deep::decode(
        "opcua_tcp",
        &evidence(&hello, 1),
        &Context::default(),
        &Limits::default(),
    )
    .unwrap();
    assert_eq!(ua.protocol, "opcua_tcp");

    let iec = evidence(&[0x68, 4, 1, 0, 2, 0], 2);
    let report = deep::decode("iec104", &iec, &Context::default(), &Limits::default()).unwrap();
    assert_eq!(report.protocol, "iec104");
    assert!(report
        .fields
        .iter()
        .any(|field| field.name == "receive_sequence"));
}

#[test]
fn ber_parser_rejects_truncation_without_resynchronizing() {
    let limits = Limits::default();
    assert!(deep::ber::parse(&[0x02, 0x02, 0x01], &limits).is_err());
    let parsed = deep::ber::parse(&[0x02, 0x01, 0x05], &limits).unwrap();
    assert_eq!(parsed.len(), 1);
}

#[test]
fn continuation_preserves_state_across_verified_page_boundaries() {
    let frame = [0, 1, 0, 0, 0, 6, 1, 3, 0, 0, 0, 2];
    let mut parser =
        deep::continuation::Parser::new("modbus", Limits::default(), Context::default()).unwrap();
    let mut completed = Vec::new();
    parser
        .feed(0, &evidence(&frame[..4], 1), &mut |item| {
            completed.push(item);
            Ok(())
        })
        .unwrap();
    assert!(completed.is_empty());
    parser
        .feed(4, &evidence(&frame[4..], 2), &mut |item| {
            completed.push(item);
            Ok(())
        })
        .unwrap();
    assert_eq!(completed.len(), 1);
    assert_eq!(completed[0].stream_start, 0);
    assert_eq!(completed[0].stream_end, frame.len() as i64);
}

#[test]
fn malformed_depth_inputs_do_not_panic_or_resynchronize() {
    let protocols = [
        "dnp3.objects",
        "modbus.registers",
        "bacnet_ip",
        "enip_cip",
        "iec104",
        "iso_cotp",
        "mms",
        "goose",
        "sampled_values",
        "opcua_tcp",
        "ethercat",
        "profinet_rt",
        "powerlink",
        "stp",
        "zigbee",
    ];
    let mut state = 0x1234_5678u32;
    for len in 0..256 {
        let mut bytes = vec![0; len];
        for byte in &mut bytes {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            *byte = state as u8;
        }
        for protocol in protocols {
            let input = evidence(&bytes, (len as u64) + 1);
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                deep::decode(protocol, &input, &Context::default(), &Limits::default())
            }));
            assert!(
                result.is_ok(),
                "decoder panicked for {protocol} length {len}"
            );
        }
    }
}

#[test]
fn dnp_group70_file_variants_match_root_width_and_privacy_boundaries() {
    let descriptor = evidence(
        &[
            70, 7, 0x5b, 1, 27, 0, 20, 0, 7, 0, 1, 0, 0x44, 0x33, 0x22, 0x11, 1, 2, 3, 4, 5, 6,
            0xaa, 0xbb, 0x34, 0x12, b'f', b'o', b'o', b'.', b'd', b'a', b't',
        ],
        1,
    );
    let report = deep::dnp::objects(&descriptor, 25, &Limits::default()).unwrap();
    let text = report.json().encode();
    assert!(text.contains("file_type"));
    assert!(text.contains("287454020"));
    assert!(text.contains("request_id"));
    assert!(!text.contains("foo.dat"));

    let transport = evidence(
        &[70, 5, 0x5b, 1, 8, 0, 1, 0, 0, 0, 0xff, 0xff, 0xff, 0xff],
        2,
    );
    let text = deep::dnp::objects(&transport, 25, &Limits::default())
        .unwrap()
        .json()
        .encode();
    assert!(text.contains("4294967295"));
    assert!(!text.contains("last_block"));

    let status = evidence(
        &[
            70, 6, 0x5b, 1, 12, 0, 1, 0, 0, 0, 3, 0, 0, 0, 0x17, b'o', b'k', b'!',
        ],
        3,
    );
    let text = deep::dnp::objects(&status, 25, &Limits::default())
        .unwrap()
        .json()
        .encode();
    assert!(text.contains("status_text_bytes"));
    assert!(!text.contains("ok!"));

    let specification = evidence(&[70, 8, 0x5b, 1, 4, 0, b't', b'e', b's', b't'], 4);
    let text = deep::dnp::objects(&specification, 25, &Limits::default())
        .unwrap()
        .json()
        .encode();
    assert!(text.contains("file_specification_sha256"));
    assert!(!text.contains("test"));
}

#[test]
fn dnp_group70_descriptor_and_authentication_boundaries_are_explicit() {
    let bad = evidence(
        &[
            70, 7, 0x5b, 1, 21, 0, 19, 0, 7, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, b'x',
        ],
        5,
    );
    assert!(deep::dnp::objects(&bad, 25, &Limits::default()).is_err());

    let auth = evidence(&[70, 2, 0x5b, 1, 1, 0, 0], 6);
    let text = deep::dnp::objects(&auth, 25, &Limits::default())
        .unwrap()
        .json()
        .encode();
    assert!(text.contains("file_authentication_credentials_not_extracted"));
}
