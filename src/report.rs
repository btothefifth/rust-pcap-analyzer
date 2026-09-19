//! Deterministic JSON projections. Never emits decryption-secret bytes.
//! Nanosecond times and signed sequence offsets use decimal strings, not floats.
use crate::capture::{CaptureIter, PacketMeta, ParseMode, RecordKind};
use crate::correlate::MessageRef;
use crate::dnp3::ProtocolIssue;
use crate::engine::{Analysis, ApplicationData, Disposition};
use crate::json::Json as J;
use crate::provenance::{EvidenceBytes, PacketId};
use crate::sha256;
use crate::tcp::StreamResult;
use crate::time::{Resolution, Timestamp};
use crate::wire::Endpoint;
use crate::{Error, Limits, Result};
fn ids(packets: &[PacketId]) -> J {
    J::array(packets.iter().map(packet_id))
}
fn strings(values: &[&'static str]) -> J {
    J::array(values.iter().map(|s| J::from(*s)))
}
fn optional_u32(value: Option<u32>) -> J {
    value.map_or(J::Null, J::from)
}
fn exact(value: Option<i128>) -> J {
    value.map_or(J::Null, |n| J::string(n.to_string()))
}
fn reference(value: &MessageRef) -> J {
    J::object([
        ("application", value.application.into()),
        ("message", value.message.into()),
    ])
}
pub fn packet_id(id: &PacketId) -> J {
    // The document-level capture SHA scopes every nested packet reference.
    J::object([
        ("frame", id.frame.into()),
        ("record_offset", J::string(id.record_offset.to_string())),
    ])
}
pub fn error(error: &Error) -> J {
    J::object([
        ("code", error.code.as_str().into()),
        ("offset", J::string(error.offset.to_string())),
        ("field", error.field.into()),
        ("detail", error.detail.clone().into()),
    ])
}
pub fn timestamp(time: Option<Timestamp>) -> J {
    time.map_or(J::Null, |t| {
        let (base, exponent) = match t.resolution {
            Resolution::Decimal(n) => (10u8, n),
            Resolution::Binary(n) => (2u8, n),
        };
        J::object([
            ("ticks", J::string(t.ticks.to_string())),
            ("resolution_base", base.into()),
            ("resolution_exponent", exponent.into()),
            ("offset_seconds", J::string(t.offset_seconds.to_string())),
            ("unix_ns_exact", exact(t.unix_nanos().ok())),
            (
                "conversion_error",
                t.unix_nanos().err().as_ref().map_or(J::Null, error),
            ),
        ])
    })
}
pub fn metadata(packet: &PacketMeta) -> J {
    J::object([
        ("frame", packet.frame.into()),
        ("section", packet.section.into()),
        ("interface", packet.interface.into()),
        ("link_type", packet.link_type.into()),
        ("captured_len", packet.captured_len.into()),
        ("original_len", packet.original_len.into()),
        ("data_offset_in_record", packet.data_offset.into()),
        ("timestamp", timestamp(packet.timestamp)),
    ])
}
fn endpoint(value: Endpoint) -> J {
    J::object([
        ("address", value.address.to_string().into()),
        ("port", value.port.into()),
    ])
}
fn evidence(bytes: &EvidenceBytes, include_payload: bool) -> J {
    let mut fields = vec![
        ("length", bytes.len().into()),
        ("sha256", sha256::hex(&sha256::digest(bytes.data())).into()),
        (
            "spans",
            J::array(bytes.spans().iter().map(|span| {
                J::object([
                    ("start", span.start.into()),
                    ("end", span.end.into()),
                    ("packet", packet_id(&span.packet)),
                    ("packet_start", span.packet_start.into()),
                ])
            })),
        ),
    ];
    if include_payload {
        fields.push(("hex", sha256::hex(bytes.data()).into()));
    }
    J::object(fields)
}
fn stream(value: &StreamResult, include_payload: bool) -> J {
    J::object([
        ("base_sequence", optional_u32(value.base_sequence)),
        ("anchored_by_syn", value.anchored_by_syn.into()),
        (
            "duplicate_observed_bytes",
            value.duplicate_observed_bytes.into(),
        ),
        (
            "chunks",
            J::array(value.chunks.iter().map(|chunk| {
                J::object([
                    ("offset", J::string(chunk.offset.to_string())),
                    ("evidence", evidence(&chunk.bytes, include_payload)),
                ])
            })),
        ),
        (
            "gaps",
            J::array(value.gaps.iter().map(|gap| {
                J::object([
                    ("start", J::string(gap.start.to_string())),
                    ("end", J::string(gap.end.to_string())),
                    ("reason", gap.reason.into()),
                ])
            })),
        ),
        (
            "conflicts",
            J::array(value.conflicts.iter().map(|conflict| {
                J::object([
                    ("start", J::string(conflict.start.to_string())),
                    ("end", J::string(conflict.end.to_string())),
                    ("packets", ids(&conflict.packets)),
                ])
            })),
        ),
    ])
}
fn issues(values: &[ProtocolIssue]) -> J {
    J::array(values.iter().map(|issue| {
        J::object([
            ("code", issue.code.into()),
            ("stream_offset", J::string(issue.stream_offset.to_string())),
            ("packets", ids(&issue.packets)),
        ])
    }))
}
pub fn analysis(value: &Analysis, include_payload: bool) -> J {
    let config = &value.config;
    let limits = &config.limits;
    J::object([
        ("schema", "pcap-evidence.analysis.v1".into()),
        ("implementation_version", env!("CARGO_PKG_VERSION").into()),
        ("capture_sha256", sha256::hex(&value.capture_sha256).into()),
        ("capture_bytes", value.capture_bytes.into()),
        (
            "labels_sha256",
            value
                .labels_sha256
                .map_or(J::Null, |h| sha256::hex(&h).into()),
        ),
        (
            "status",
            if value.has_diagnostics() {
                "analysis_with_diagnostics"
            } else {
                "no_diagnostics_in_supported_path"
            }
            .into(),
        ),
        (
            "attack_verdict",
            "not_performed_external_labels_are_claims".into(),
        ),
        (
            "config",
            J::object([
                ("parse_mode", format!("{:?}", config.parse_mode).into()),
                ("overlap_policy", config.overlap_policy.as_str().into()),
                (
                    "checksum_policy",
                    format!("{:?}", config.checksum_policy).into(),
                ),
                (
                    "idle_timeout_ns",
                    J::string(config.idle_timeout_ns.to_string()),
                ),
                (
                    "dnp3_ports",
                    J::array(config.dnp3_ports.iter().map(|p| J::from(*p))),
                ),
                (
                    "modbus_ports",
                    J::array(config.modbus_ports.iter().map(|p| J::from(*p))),
                ),
                (
                    "limits",
                    J::object([
                        ("input_bytes", limits.max_input_bytes.into()),
                        ("block_bytes", limits.max_block_bytes.into()),
                        ("packet_bytes", limits.max_packet_bytes.into()),
                        ("records", limits.max_records.into()),
                        ("interfaces", limits.max_interfaces.into()),
                        ("options", limits.max_options.into()),
                        ("flows", limits.max_flows.into()),
                        ("segments_per_flow", limits.max_segments_per_flow.into()),
                        ("stream_span", limits.max_stream_span.into()),
                        ("retained_payload", limits.max_retained_payload.into()),
                        ("fragment_sets", limits.max_fragment_sets.into()),
                        ("fragments_per_set", limits.max_fragments_per_set.into()),
                        (
                            "fragment_frame_lifetime",
                            limits.fragment_frame_lifetime.into(),
                        ),
                        ("protocol_messages", limits.max_protocol_messages.into()),
                        ("application_bytes", limits.max_application_bytes.into()),
                        ("labels", limits.max_labels.into()),
                        ("correlation_checks", limits.max_correlation_checks.into()),
                    ]),
                ),
            ]),
        ),
        ("records", value.records.into()),
        ("metadata_records", value.metadata_records.into()),
        ("secret_blocks_redacted", value.secret_blocks.into()),
        (
            "packets",
            J::array(value.packets.iter().map(|packet| {
                let assignment = match &packet.disposition {
                    Disposition::Tcp { flow, direction } => {
                        J::object([("flow", (*flow).into()), ("direction", (*direction).into())])
                    }
                    Disposition::Rejected { code, detail } => {
                        J::object([("code", (*code).into()), ("detail", detail.clone().into())])
                    }
                    Disposition::FragmentIncomplete { reason } => {
                        J::object([("reason", (*reason).into())])
                    }
                    Disposition::Ambiguous { flows } => J::object([(
                        "candidate_flows",
                        J::array(flows.iter().map(|f| J::from(*f))),
                    )]),
                    _ => J::Null,
                };
                J::object([
                    ("id", packet_id(&packet.id)),
                    ("metadata", metadata(&packet.metadata)),
                    ("packet_sha256", sha256::hex(&packet.packet_sha256).into()),
                    ("source", packet.source.map_or(J::Null, endpoint)),
                    ("destination", packet.destination.map_or(J::Null, endpoint)),
                    ("transport", packet.transport.map_or(J::Null, J::from)),
                    ("disposition", packet.disposition.as_str().into()),
                    ("assignment", assignment),
                    ("warnings", strings(&packet.warnings)),
                ])
            })),
        ),
        (
            "flows",
            J::array(value.flows.iter().map(|flow| {
                J::object([
                    ("id", flow.id.into()),
                    ("generation", flow.generation.into()),
                    (
                        "scope",
                        J::object([
                            ("section", flow.key.scope.section.into()),
                            ("interface", flow.key.scope.interface.into()),
                            (
                                "vlans",
                                J::array(flow.key.scope.vlans.iter().map(|v| J::from(*v))),
                            ),
                        ]),
                    ),
                    ("endpoint_a", endpoint(flow.key.a)),
                    ("endpoint_b", endpoint(flow.key.b)),
                    (
                        "syn_sequences",
                        J::array(flow.syn.iter().map(|v| optional_u32(*v))),
                    ),
                    ("closed", flow.closed.into()),
                    ("midstream", flow.midstream.into()),
                    ("first_unix_ns", exact(flow.first_ns)),
                    ("last_unix_ns", exact(flow.last_ns)),
                    ("packets", ids(&flow.packets)),
                    ("anomalies", strings(&flow.anomalies)),
                    (
                        "reconstruction_errors",
                        J::array(flow.reconstruction_errors.iter().map(error)),
                    ),
                    (
                        "streams",
                        J::array(
                            flow.streams.iter().map(|s| {
                                s.as_ref().map_or(J::Null, |s| stream(s, include_payload))
                            }),
                        ),
                    ),
                ])
            })),
        ),
        (
            "applications",
            J::array(
                value
                    .applications
                    .iter()
                    .enumerate()
                    .map(|(index, application)| {
                        let data = match &application.data {
                            ApplicationData::Failed(e) => J::object([("error", error(e))]),
                            ApplicationData::Dnp3(d) => dnp3_data(d, include_payload, limits),
                            ApplicationData::Modbus(m) => J::object([
                                ("issues", issues(&m.issues)),
                                (
                                    "messages",
                                    J::array(m.messages.iter().map(|message| {
                                        J::object([
                                            (
                                                "stream_offset",
                                                J::string(message.stream_offset.to_string()),
                                            ),
                                            ("transaction", message.transaction.into()),
                                            ("unit", message.unit.into()),
                                            ("function", message.function.into()),
                                            ("role", message.role.as_str().into()),
                                            ("shape_valid", message.shape_valid.into()),
                                            (
                                                "semantics_supported",
                                                message.semantics_supported.into(),
                                            ),
                                            ("boundary_verified", message.boundary_verified.into()),
                                            ("raw", evidence(&message.raw, include_payload)),
                                            (
                                                "semantic_subset",
                                                crate::semantics::modbus::alternatives_json(
                                                    &message.raw,
                                                    message.role,
                                                    crate::semantics::Limits::from_capture(limits),
                                                ),
                                            ),
                                        ])
                                    })),
                                ),
                            ]),
                        };
                        J::object([
                            ("id", index.into()),
                            ("flow", application.flow.into()),
                            ("direction", application.direction.into()),
                            ("protocol", application.protocol.into()),
                            ("data", data),
                        ])
                    }),
            ),
        ),
        (
            "udp_applications",
            J::array(value.datagrams.iter().enumerate().map(|(id, app)| {
                let data = match &app.data {
                    Ok(d) => dnp3_data(d, include_payload, limits),
                    Err(e) => J::object([("error", error(e))]),
                };
                J::object([
                    ("id", id.into()),
                    ("transport", "udp".into()),
                    ("protocol", "dnp3".into()),
                    ("selection", "configured_port".into()),
                    (
                        "reconstruction_scope",
                        "single_udp_datagram_no_cross_datagram_state".into(),
                    ),
                    (
                        "scope",
                        J::object([
                            ("section", app.scope.section.into()),
                            ("interface", app.scope.interface.into()),
                            (
                                "vlans",
                                J::array(app.scope.vlans.iter().map(|v| J::from(*v))),
                            ),
                        ]),
                    ),
                    ("source", endpoint(app.source)),
                    ("destination", endpoint(app.destination)),
                    ("packets", ids(&app.packets)),
                    ("payload", evidence(&app.payload, include_payload)),
                    ("data", data),
                ])
            })),
        ),
        (
            "fragment_notices",
            J::array(
                value
                    .fragment_notices
                    .iter()
                    .map(|n| J::object([("code", n.code.into()), ("packets", ids(&n.packets))])),
            ),
        ),
        (
            "transaction_candidates",
            J::array(value.transactions.iter().map(|t| {
                J::object([
                    ("protocol", t.protocol.into()),
                    ("flow", t.flow.into()),
                    ("requests", J::array(t.requests.iter().map(reference))),
                    ("responses", J::array(t.responses.iter().map(reference))),
                    ("status", t.status.into()),
                    ("reason", t.reason.into()),
                ])
            })),
        ),
        (
            "correlation_error",
            value.correlation_error.as_ref().map_or(J::Null, error),
        ),
        (
            "attempt_label_matches",
            J::array(value.attempt_matches.iter().map(|m| {
                J::object([
                    ("attempt_id", m.attempt_id.clone().into()),
                    ("status", m.status.into()),
                    ("matched_packets", ids(&m.matched_packets)),
                    ("unresolved_time_packets", ids(&m.unresolved_time_packets)),
                    ("flows", J::array(m.flows.iter().map(|f| J::from(*f)))),
                    ("messages", J::array(m.messages.iter().map(reference))),
                ])
            })),
        ),
    ])
}

pub fn inspect(source: &[u8], limits: Limits, mode: ParseMode, include_payload: bool) -> Result<J> {
    let mut records = Vec::new();
    for record in CaptureIter::new(source, limits, mode)? {
        let record = record?;
        let body = match record.kind() {
            RecordKind::LegacyHeader(h) => J::object([
                ("kind", "pcap_header".into()),
                ("snaplen", h.snaplen.into()),
                ("link_word", h.link_word.into()),
                ("nanoseconds", h.nanos.into()),
            ]),
            RecordKind::Section {
                id,
                declared_length,
            } => J::object([
                ("kind", "section".into()),
                ("id", (*id).into()),
                (
                    "declared_length",
                    declared_length.map_or(J::Null, |n| J::string(n.to_string())),
                ),
            ]),
            RecordKind::Interface(i) => J::object([
                ("kind", "interface".into()),
                ("section", i.section.into()),
                ("id", i.id.into()),
                ("link_type", i.link_type.into()),
                ("snaplen", i.snaplen.into()),
                (
                    "clock",
                    timestamp(Some(Timestamp {
                        ticks: 0,
                        resolution: i.resolution,
                        offset_seconds: i.offset_seconds,
                    })),
                ),
            ]),
            RecordKind::Packet(p) => {
                let (_, bytes) = record.packet().ok_or_else(|| {
                    Error::new(
                        crate::ErrorCode::Invariant,
                        record.offset(),
                        "packet",
                        "missing parsed packet",
                    )
                })?;
                let mut fields = vec![
                    ("kind", "packet".into()),
                    ("metadata", metadata(p)),
                    ("packet_sha256", sha256::hex(&sha256::digest(bytes)).into()),
                ];
                if include_payload {
                    fields.push(("packet_hex", sha256::hex(bytes).into()));
                }
                J::object(fields)
            }
            RecordKind::Names { records } => J::object([
                ("kind", "names".into()),
                ("name_records", (*records).into()),
            ]),
            RecordKind::Statistics {
                interface,
                timestamp: t,
            } => J::object([
                ("kind", "statistics".into()),
                ("interface", (*interface).into()),
                ("timestamp", timestamp(Some(*t))),
            ]),
            RecordKind::Secrets {
                secrets_type,
                secrets_len,
            } => J::object([
                ("kind", "secrets_redacted".into()),
                ("secrets_type", (*secrets_type).into()),
                ("length", (*secrets_len).into()),
            ]),
            RecordKind::Custom { pen, copy_on_edit } => J::object([
                ("kind", "custom".into()),
                ("pen", (*pen).into()),
                ("copy_on_edit", (*copy_on_edit).into()),
            ]),
            RecordKind::Unknown { block_type } => J::object([
                ("kind", "unknown".into()),
                ("block_type", (*block_type).into()),
            ]),
        };
        records.push(J::object([
            ("offset", J::string(record.offset().to_string())),
            ("length", record.raw().len().into()),
            ("endian", format!("{:?}", record.endian()).into()),
            ("body", body),
            (
                "options",
                J::array(
                    record
                        .options()
                        .iter()
                        .map(|o| J::object([("code", o.code.into()), ("length", o.length.into())])),
                ),
            ),
            (
                "warnings",
                J::array(record.warnings().iter().map(|w| {
                    J::object([
                        ("code", w.code.into()),
                        ("offset", J::string(w.offset.to_string())),
                    ])
                })),
            ),
        ]));
    }
    Ok(J::object([
        ("schema", "pcap-evidence.inspect.v1".into()),
        (
            "capture_sha256",
            sha256::hex(&sha256::digest(source)).into(),
        ),
        ("capture_bytes", source.len().into()),
        ("records", J::Array(records)),
    ]))
}

fn dnp3_data(d: &crate::dnp3::Dnp3Result, include_payload: bool, limits: &Limits) -> J {
    J::object([
        (
            "object_semantics",
            "opaque_not_a_full_ieee1815_object_decoder".into(),
        ),
        ("issues", issues(&d.issues)),
        (
            "link_frames",
            J::array(d.frames.iter().map(|frame| {
                J::object([
                    ("stream_offset", J::string(frame.stream_offset.to_string())),
                    ("control", frame.control.into()),
                    ("source", frame.source.into()),
                    ("destination", frame.destination.into()),
                    ("raw", evidence(&frame.raw, false)),
                    ("user_data", evidence(&frame.user_data, include_payload)),
                ])
            })),
        ),
        (
            "application_fragments",
            J::array(d.fragments.iter().map(|fragment| {
                J::object([
                    ("control", fragment.control.into()),
                    ("function", fragment.function.into()),
                    ("sequence", fragment.sequence.into()),
                    ("class", fragment.class.as_str().into()),
                    ("iin", fragment.iin.map_or(J::Null, J::from)),
                    ("first", fragment.first.into()),
                    ("final", fragment.final_fragment.into()),
                    (
                        "confirmation_requested",
                        fragment.confirmation_requested.into(),
                    ),
                    (
                        "link_frames",
                        J::array(fragment.frames.iter().map(|f| J::from(*f))),
                    ),
                    ("raw", evidence(&fragment.raw, include_payload)),
                    (
                        "object_semantic_subset",
                        crate::semantics::dnp3::fragment_json(
                            fragment,
                            crate::semantics::Limits::from_capture(limits),
                        ),
                    ),
                ])
            })),
        ),
        (
            "messages",
            J::array(d.messages.iter().map(|message| {
                J::object([
                    ("source", message.source.into()),
                    ("destination", message.destination.into()),
                    ("function", message.function.into()),
                    ("first_sequence", message.first_sequence.into()),
                    ("class", message.class.as_str().into()),
                    ("complete", message.complete.into()),
                    (
                        "fragments",
                        J::array(message.fragments.iter().map(|f| J::from(*f))),
                    ),
                    ("packets", ids(&message.packets)),
                    ("objects", evidence(&message.objects, include_payload)),
                ])
            })),
        ),
    ])
}
