//! DNP3 projections share the root evidence and workflow decoders. In particular,
//! fragment-local object bytes never masquerade as a complete application body.
use super::{dnp3, native_limits, one_stream, AnalyzerLimits, CorrelationHint, Output, Role};
use crate::{
    events::{Event, EventKind, Evidence, EvidenceStatus},
    Error, Result,
};
use pcap_evidence::{
    json::Json,
    protocol::ProbeTransport,
    provenance::EvidenceBytes,
    semantics::{self, dnp3_workflow as workflow},
};

pub(super) fn decode(
    raw: &EvidenceBytes,
    at: i64,
    boundary: bool,
    out: &mut Output<'_>,
    limits: &AnalyzerLimits,
) -> Result<()> {
    let native = native_limits(limits);
    let semantic = semantics::Limits::from_capture(&native);
    let d = dnp3::decode(&one_stream(raw, at, boundary), &native)?;
    for issue in &d.issues {
        out.issue("dnp3", issue.code, raw)?;
    }
    for rejected in &d.rejected_link_ranges {
        if *out.remaining == 0 {
            return Err(Error::limit("plugin_events"));
        }
        *out.remaining -= 1;
        let mut event = Event::new(
            EventKind::ProtocolIssue,
            if rejected.incomplete {
                EvidenceStatus::Incomplete
            } else {
                EvidenceStatus::Rejected
            },
            Json::object([
                ("reason", rejected.code.into()),
                ("layer", "link".into()),
                (
                    "declared_length",
                    rejected
                        .declared_length
                        .map_or(Json::Null, |n| n.to_string().into()),
                ),
                (
                    "resynchronization",
                    "not_performed_within_failed_boundary".into(),
                ),
            ]),
        );
        event.session = Some(out.context.session);
        event.direction = Some(out.context.direction);
        event.protocol = Some("dnp3".into());
        event.evidence = Evidence::bytes(&rejected.raw);
        event.stream_range = Some((
            rejected.stream_offset,
            rejected
                .stream_offset
                .checked_add(rejected.raw.len() as i64)
                .ok_or_else(|| Error::limit("stream_offset"))?,
        ));
        if let Err(error) = out.sink.emit(&event) {
            out.sink_failed = true;
            return Err(error);
        }
    }
    for frame in &d.frames {
        if *out.remaining == 0 {
            return Err(Error::limit("plugin_events"));
        }
        let decoded = workflow::link(&frame.raw, semantic.clone())?;
        let status = match decoded.status() {
            semantics::Status::DecodedSubset => {
                if out.context.ambiguous {
                    EvidenceStatus::Ambiguous
                } else {
                    EvidenceStatus::Observed
                }
            }
            semantics::Status::Incomplete => EvidenceStatus::Incomplete,
            semantics::Status::Unsupported => EvidenceStatus::Unsupported,
            semantics::Status::Rejected => EvidenceStatus::Rejected,
            semantics::Status::Limited => return Err(Error::limit("dnp3_link_semantics")),
        };
        *out.remaining -= 1;
        let mut event = Event::new(
            EventKind::Message,
            status,
            Json::object([
                ("layer", "link".into()),
                ("control", frame.control.into()),
                ("function_name", frame.link_control.function_name.into()),
                ("source", frame.source.into()),
                ("destination", frame.destination.into()),
                ("broadcast", frame.broadcast.into()),
                (
                    "destination_address_kind",
                    workflow::address_kind(frame.destination).into(),
                ),
                (
                    "broadcast_confirm_policy",
                    workflow::broadcast_confirm_policy(frame.destination)
                        .map_or(Json::Null, Json::from),
                ),
                ("link_workflow", decoded.json()?),
            ]),
        );
        event.session = Some(out.context.session);
        event.direction = Some(out.context.direction);
        event.protocol = Some("dnp3".into());
        event.evidence = Evidence::bytes(&frame.raw);
        event.stream_range = Some((
            frame.stream_offset,
            frame
                .stream_offset
                .checked_add(frame.raw.len() as i64)
                .ok_or_else(|| Error::limit("stream_offset"))?,
        ));
        if let Err(error) = out.sink.emit(&event) {
            out.sink_failed = true;
            return Err(error);
        }
    }
    let mut referenced = vec![false; d.fragments.len()];
    let mut verification_work = 0usize;
    if out.context.transport == ProbeTransport::Tcp {
        for fragment in &d.fragments {
            if !matches!(fragment.function, 0 | 0x81 | 0x82) {
                continue;
            }
            match workflow::verified_fragment_witness(&d, fragment, &native, &mut verification_work)
            {
                Ok(witness) => {
                    out.dnp3_confirmation_fragment(
                        &fragment.raw,
                        witness,
                        dnp3::function_code(fragment.function).as_str(),
                    )?;
                }
                Err(error) if error.code == pcap_evidence::ErrorCode::LimitExceeded => {
                    return Err(error);
                }
                Err(error) => {
                    out.issue(
                        "dnp3",
                        format!("dnp3_confirmation_fragment_unverified:{}", error.field),
                        &fragment.raw,
                    )?;
                }
            }
        }
    }
    for message in &d.messages {
        let mut selected = EvidenceBytes::default();
        for &index in &message.fragments {
            referenced[index] = true;
            selected.append(&d.fragments[index].raw, limits.max_buffer_bytes)?;
        }
        let role = match message.class {
            dnp3::MessageClass::Request => Role::Request,
            dnp3::MessageClass::Response => Role::Response,
            _ => Role::Unknown,
        };
        let no_response = role == Role::Request && matches!(message.function, 6 | 8 | 10 | 12);
        let verified =
            workflow::verified_message_direction(&d, message, &native, &mut verification_work);
        if verified
            .as_ref()
            .is_err_and(|e| e.code == pcap_evidence::ErrorCode::LimitExceeded)
        {
            return Err(Error::limit("dnp3_correlation_work"));
        }
        let pairing = if !message.complete {
            "incomplete"
        } else if no_response {
            "no_response_expected"
        } else if role == Role::Unknown {
            "not_a_solicited_request_response"
        } else if out.context.transport == ProbeTransport::Udp {
            "datagram_pairing_not_enabled"
        } else if let Err(e) = &verified {
            e.field
        } else if out.context.direction > 1 {
            "capture_direction_unknown"
        } else {
            "eligible_identifier_candidate_only"
        };
        let hint = if pairing == "eligible_identifier_candidate_only" {
            let (controller, outstation) = if role == Role::Request {
                (message.source, message.destination)
            } else {
                (message.destination, message.source)
            };
            Some(CorrelationHint {
                key: format!("{controller}:{outstation}:{}", message.first_sequence),
                role,
                compatibility: String::new(),
            })
        } else {
            None
        };
        out.message(
            "dnp3",
            &selected,
            None,
            Json::object([
                ("layer", "application_message".into()),
                ("source", message.source.into()),
                ("destination", message.destination.into()),
                ("function", message.function.into()),
                (
                    "function_name",
                    dnp3::function_code(message.function).as_str().into(),
                ),
                ("sequence", message.first_sequence.into()),
                ("class", message.class.as_str().into()),
                ("complete", message.complete.into()),
                ("pairing_eligibility", pairing.into()),
                (
                    "object_semantics",
                    "bounded_source_bound_non_secure_subset".into(),
                ),
                (
                    "object_semantic_subset",
                    semantics::dnp3::assembled_message_json(
                        &message.objects,
                        message.function,
                        message.complete,
                        semantic.clone(),
                    ),
                ),
                (
                    "object_semantic_subsets",
                    Json::array(message.fragments.iter().map(|index| {
                        Json::object([
                            ("fragment_index", (*index).into()),
                            (
                                "object_fields",
                                semantics::dnp3::fragment_json(
                                    &d.fragments[*index],
                                    semantic.clone(),
                                ),
                            ),
                            (
                                "application_workflow",
                                semantics::as_json(workflow::application(
                                    &d.fragments[*index].raw,
                                    semantic.clone(),
                                )),
                            ),
                        ])
                    })),
                ),
                (
                    "application_object_evidence",
                    Evidence::bytes(&message.objects).json(),
                ),
                (
                    "application_fragment_evidence",
                    Json::array(message.fragments.iter().map(|index| {
                        let fragment = &d.fragments[*index];
                        Json::object([
                            ("fragment_index", (*index).into()),
                            ("control", fragment.control.into()),
                            ("function", fragment.function.into()),
                            ("sequence", fragment.sequence.into()),
                            ("first", fragment.first.into()),
                            ("final", fragment.final_fragment.into()),
                            ("objects", Evidence::bytes(&fragment.objects).json()),
                            ("raw", Evidence::bytes(&fragment.raw).json()),
                        ])
                    })),
                ),
                (
                    "transport_scope",
                    if out.context.transport == ProbeTransport::Udp {
                        "one_datagram"
                    } else {
                        "one_reconstruction_window"
                    }
                    .into(),
                ),
            ]),
            hint,
            message.complete,
        )?;
    }
    for (index, fragment) in d.fragments.iter().enumerate() {
        if !referenced[index] {
            out.message(
                "dnp3",
                &fragment.raw,
                None,
                Json::object([
                    ("layer", "application_fragment".into()),
                    ("fragment_index", index.into()),
                    (
                        "reason",
                        "unmatched_or_conflicting_application_fragment".into(),
                    ),
                    (
                        "object_fields",
                        semantics::dnp3::fragment_json(fragment, semantic.clone()),
                    ),
                    (
                        "application_workflow",
                        semantics::as_json(workflow::application(&fragment.raw, semantic.clone())),
                    ),
                ]),
                None,
                false,
            )?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::{
        correlate_dnp3_confirmations, Context, Dnp3StreamingConfirmationRecord,
        IdentifierCorrelator, MessageRecord, TransactionCorrelator,
    };
    use super::*;
    use crate::events::EventSink;
    use pcap_evidence::{provenance::PacketId, wire::Endpoint};
    use std::net::{IpAddr, Ipv4Addr};

    const VECTORS: &str = include_str!("../../../tests/fixtures/dnp3_workflows.hex");
    const CONFIRMATION_VECTORS: &str =
        include_str!("../../../tests/fixtures/dnp3_confirmations.hex");
    #[derive(Default)]
    struct Sink(Vec<Event>);
    impl EventSink for Sink {
        fn run_id(&self) -> &str {
            "dnp-workflow-test"
        }
        fn emit(&mut self, event: &Event) -> Result<u64> {
            self.0.push(event.clone());
            Ok(self.0.len() as u64)
        }
    }
    fn raw(names: &[&str]) -> EvidenceBytes {
        let mut bytes = EvidenceBytes::default();
        for (i, name) in names.iter().enumerate() {
            let hex = VECTORS
                .lines()
                .chain(CONFIRMATION_VECTORS.lines())
                .find(|s| s.split_whitespace().next() == Some(*name))
                .unwrap()
                .split_whitespace()
                .nth(1)
                .unwrap();
            let data: Vec<_> = (0..hex.len())
                .step_by(2)
                .map(|p| u8::from_str_radix(&hex[p..p + 2], 16).unwrap())
                .collect();
            bytes
                .append(
                    &EvidenceBytes::from_packet(
                        &data,
                        PacketId {
                            capture: [3; 32],
                            frame: i as u64 + 1,
                            record_offset: 100 * (i as u64 + 1),
                        },
                        54,
                    ),
                    65536,
                )
                .unwrap();
        }
        bytes
    }
    fn observe_with_projection(
        names: &[&str],
        direction: u8,
        sink: &mut Sink,
        records: &mut Vec<MessageRecord>,
        dnp3_confirmations: &mut Vec<Dnp3StreamingConfirmationRecord>,
    ) {
        let context = Context {
            session: 7,
            window: 1,
            generation: Some(1),
            direction,
            source: Endpoint {
                address: IpAddr::V4(Ipv4Addr::LOCALHOST),
                port: 20000,
            },
            destination: Endpoint {
                address: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
                port: 40000,
            },
            transport: ProbeTransport::Tcp,
            ambiguous: false,
            boundary_verified: true,
            modbus_ports: Vec::new(),
        };
        let mut remaining = 1000;
        let mut out = Output {
            context: &context,
            sink,
            records,
            dnp3_confirmations,
            remaining: &mut remaining,
            max_message_bytes: 65536,
            sink_failed: false,
        };
        let limits = AnalyzerLimits {
            max_buffer_bytes: 65536,
            max_messages: 1000,
            max_work_bytes: 1048576,
        };
        decode(&raw(names), 0, true, &mut out, &limits).unwrap();
    }

    fn observe(names: &[&str], direction: u8, sink: &mut Sink, records: &mut Vec<MessageRecord>) {
        let mut dnp3_confirmations = Vec::new();
        observe_with_projection(names, direction, sink, records, &mut dnp3_confirmations);
    }

    #[test]
    fn link_projection_keeps_reserved_status_source_spans_and_hash() {
        let mut sink = Sink::default();
        let mut records = Vec::new();
        observe(&["secondary_reserved"], 1, &mut sink, &mut records);
        let event = sink
            .0
            .iter()
            .find(|e| e.data.encode().contains("link_workflow"))
            .unwrap();
        assert_eq!(event.status, EvidenceStatus::Rejected);
        assert_eq!(
            event.evidence.byte_length,
            raw(&["secondary_reserved"]).len()
        );
        assert!(event.evidence.reconstructed_sha256.is_some());
        assert_eq!(event.evidence.spans[0].packet_start, 54);
        assert!(records.is_empty());
    }

    #[test]
    fn streaming_assembled_objects_equal_root_and_partial_regions_stay_incomplete() {
        let mut sink = Sink::default();
        let mut records = Vec::new();
        observe(
            &["application_first", "application_final"],
            1,
            &mut sink,
            &mut records,
        );
        let text = sink
            .0
            .iter()
            .find(|e| e.data.encode().contains("application_message"))
            .unwrap()
            .data
            .encode();
        assert!(text.contains("\"kind\":\"object_value\""));
        assert!(text.contains("dnp3_application_fragment_needs_assembly"));
        assert!(text.contains("application_object_evidence"));
        assert!(text.contains("application_fragment_evidence"));
        assert!(text.contains("\"objects\":{\"byte_length\""));
        assert_eq!(records.len(), 1);
    }

    #[test]
    fn candidate_pairs_require_opposite_direction_and_reuse_stays_ambiguous() {
        for reused in [false, true] {
            let mut sink = Sink::default();
            let mut records = Vec::new();
            let requests: &[&str] = if reused {
                &["class_scan_15", "class_scan_15"]
            } else {
                &["class_scan_15"]
            };
            observe(requests, 0, &mut sink, &mut records);
            observe(&["event_response_15"], 1, &mut sink, &mut records);
            IdentifierCorrelator
                .correlate(&records, &mut sink, 1000)
                .unwrap();
            let transaction = sink.0.last().unwrap();
            assert_eq!(transaction.kind, EventKind::Transaction);
            assert_eq!(
                transaction.status,
                if reused {
                    EvidenceStatus::Ambiguous
                } else {
                    EvidenceStatus::Candidate
                }
            );
        }
        let mut sink = Sink::default();
        let mut records = Vec::new();
        observe(&["class_scan_15"], 0, &mut sink, &mut records);
        observe(&["event_response_15"], 0, &mut sink, &mut records);
        IdentifierCorrelator
            .correlate(&records, &mut sink, 1000)
            .unwrap();
        assert_eq!(sink.0.last().unwrap().status, EvidenceStatus::Ambiguous);
    }

    #[test]
    fn dnp3_projection_is_separate_and_carries_both_participant_witnesses() {
        let mut sink = Sink::default();
        let mut records = Vec::new();
        let mut confirmations = Vec::new();
        observe_with_projection(
            &["solicited_confirm"],
            0,
            &mut sink,
            &mut records,
            &mut confirmations,
        );
        observe_with_projection(
            &["solicited_target"],
            1,
            &mut sink,
            &mut records,
            &mut confirmations,
        );
        correlate_dnp3_confirmations(&confirmations, &mut sink, 1000).unwrap();
        let event = sink
            .0
            .iter()
            .find(|e| e.kind == EventKind::Dnp3Confirmation)
            .expect("DNP3-specific projection");
        assert_eq!(event.status, EvidenceStatus::Candidate);
        let data = event.data.encode();
        assert!(data.contains("generic_transaction_untouched"));
        assert!(data.contains("\"confirms\":["));
        assert!(data.contains("\"targets\":["));
        assert!(data.contains("\"evidence\""));
        assert!(event.related_events.len() >= 2);
        assert!(!sink
            .0
            .iter()
            .any(|e| e.kind == EventKind::Transaction
                && e.data.encode().contains("dnp3_confirmation")));
    }

    #[test]
    fn dnp3_projection_retains_unmatched_ambiguous_and_scope_separated_evidence() {
        let mut sink = Sink::default();
        let mut records = Vec::new();
        let mut confirmations = Vec::new();
        observe_with_projection(
            &["solicited_confirm"],
            0,
            &mut sink,
            &mut records,
            &mut confirmations,
        );
        correlate_dnp3_confirmations(&confirmations, &mut sink, 1000).unwrap();
        let unmatched = sink
            .0
            .iter()
            .find(|e| e.kind == EventKind::Dnp3Confirmation)
            .unwrap();
        assert_eq!(unmatched.status, EvidenceStatus::Incomplete);
        assert!(unmatched.data.encode().contains("no_verified_response"));
        assert!(unmatched.data.encode().contains("\"targets\":[]"));

        let mut sink = Sink::default();
        let mut records = Vec::new();
        let mut confirmations = Vec::new();
        observe_with_projection(
            &["solicited_confirm"],
            0,
            &mut sink,
            &mut records,
            &mut confirmations,
        );
        observe_with_projection(
            &["solicited_target"],
            1,
            &mut sink,
            &mut records,
            &mut confirmations,
        );
        let mut duplicate = confirmations[1].clone();
        duplicate.event = duplicate.event.saturating_add(1000);
        confirmations.push(duplicate);
        correlate_dnp3_confirmations(&confirmations, &mut sink, 1000).unwrap();
        assert_eq!(
            sink.0
                .iter()
                .find(|e| e.kind == EventKind::Dnp3Confirmation)
                .unwrap()
                .status,
            EvidenceStatus::Ambiguous
        );

        let mut separated = confirmations[..2].to_vec();
        separated[1].session = separated[1].session.saturating_add(1);
        let before = sink.0.len();
        correlate_dnp3_confirmations(&separated, &mut sink, 1000).unwrap();
        assert_eq!(sink.0.len(), before + 1);
        assert!(sink.0[before..]
            .iter()
            .all(|event| event.kind == EventKind::Dnp3Confirmation
                && event.status == EvidenceStatus::Incomplete));
    }

    #[test]
    fn dnp3_projection_budget_failure_precedes_output() {
        let mut sink = Sink::default();
        let mut records = Vec::new();
        let mut confirmations = Vec::new();
        observe_with_projection(
            &["solicited_confirm"],
            0,
            &mut sink,
            &mut records,
            &mut confirmations,
        );
        let before = sink.0.len();
        assert!(correlate_dnp3_confirmations(&confirmations, &mut sink, 1).is_err());
        assert_eq!(sink.0.len(), before);
    }

    #[test]
    fn no_response_broadcast_and_confirms_do_not_generate_response_hints() {
        let mut sink = Sink::default();
        let mut records = Vec::new();
        observe(
            &["confirm_solicited", "no_response_control", "broadcast_fffd"],
            0,
            &mut sink,
            &mut records,
        );
        assert!(records.is_empty());
        assert!(sink
            .0
            .iter()
            .any(|e| e.data.encode().contains("non_individual_address")));
    }

    #[test]
    fn rejected_crc_has_exact_source_range_and_orphan_fragment_is_not_dropped() {
        let mut sink = Sink::default();
        let mut records = Vec::new();
        observe(
            &["bad_crc_nested_frame", "application_final"],
            1,
            &mut sink,
            &mut records,
        );
        assert!(sink.0.iter().any(|e| e.status == EvidenceStatus::Rejected
            && e.evidence.byte_length == raw(&["bad_crc_nested_frame"]).len()));
        assert!(sink.0.iter().any(|e| e
            .data
            .encode()
            .contains("unmatched_or_conflicting_application_fragment")));
        assert!(records.is_empty());
    }
}
