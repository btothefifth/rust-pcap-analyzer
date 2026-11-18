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
mod projection;
use projection::{Output, Projection as P};

fn ids(packets: &[PacketId]) -> P<'_> {
    P::array(packets.iter().map(packet_id))
}
fn strings<'a>(values: &'a [&'static str]) -> P<'a> {
    P::array(values.iter().map(|s| J::from(*s)))
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
fn evidence(bytes: &EvidenceBytes, include_payload: bool) -> P<'_> {
    let mut fields = vec![
        ("length", bytes.len().into()),
        ("sha256", sha256::hex(&sha256::digest(bytes.data())).into()),
        (
            "spans",
            P::array(bytes.spans().iter().map(move |span| {
                P::object([
                    ("start", span.start.into()),
                    ("end", span.end.into()),
                    ("packet", packet_id(&span.packet).into()),
                    ("packet_start", span.packet_start.into()),
                ])
            })),
        ),
    ];
    if include_payload {
        fields.push(("hex", P::Hex(bytes.data())));
    }
    P::object(fields)
}
fn stream(value: &StreamResult, include_payload: bool) -> P<'_> {
    P::object([
        ("base_sequence", optional_u32(value.base_sequence).into()),
        ("anchored_by_syn", value.anchored_by_syn.into()),
        (
            "duplicate_observed_bytes",
            value.duplicate_observed_bytes.into(),
        ),
        (
            "chunks",
            P::array(value.chunks.iter().map(move |chunk| {
                P::object([
                    ("offset", chunk.offset.to_string().into()),
                    ("evidence", evidence(&chunk.bytes, include_payload)),
                ])
            })),
        ),
        (
            "gaps",
            P::array(value.gaps.iter().map(move |gap| {
                P::object([
                    ("start", gap.start.to_string().into()),
                    ("end", gap.end.to_string().into()),
                    ("reason", gap.reason.into()),
                ])
            })),
        ),
        (
            "conflicts",
            P::array(value.conflicts.iter().map(move |conflict| {
                P::object([
                    ("start", conflict.start.to_string().into()),
                    ("end", conflict.end.to_string().into()),
                    ("packets", ids(&conflict.packets)),
                ])
            })),
        ),
    ])
}
fn issues(values: &[ProtocolIssue]) -> P<'_> {
    P::array(values.iter().map(move |issue| {
        P::object([
            ("code", issue.code.into()),
            ("stream_offset", issue.stream_offset.to_string().into()),
            ("packets", ids(&issue.packets)),
        ])
    }))
}
fn fragment_reference(value: &crate::correlate::FragmentRef) -> J {
    J::object([
        ("application", value.application.into()),
        ("fragment", value.fragment.into()),
    ])
}
fn confirmation_fragment(value: &crate::correlate::Dnp3ConfirmationFragment) -> P<'_> {
    let witness = &value.witness;
    let h = witness.header;
    P::object([
        ("reference", fragment_reference(&value.reference).into()),
        ("captured_direction", value.direction.into()),
        ("source", witness.source.into()),
        ("destination", witness.destination.into()),
        ("link_dir", witness.link_direction.into()),
        ("raw_control", h.control.into()),
        ("function", h.function.into()),
        ("sequence", h.sequence().into()),
        ("con", h.confirm_requested().into()),
        ("uns", h.unsolicited().into()),
        ("fir", h.first().into()),
        ("fin", h.final_fragment().into()),
        // These small non-secret headers are always exact; object payload is
        // neither decoded nor copied by confirmation correlation.
        ("header", evidence(&witness.header_bytes, true)),
        ("packets", ids(&witness.packets)),
        (
            "link_witnesses",
            P::array(witness.links.iter().map(move |link| {
                P::object([
                    ("frame", link.frame.into()),
                    ("raw_control", link.control.into()),
                    ("header", evidence(&link.header, true)),
                    ("transport_control", link.transport_control.into()),
                    ("transport_header", evidence(&link.transport_header, true)),
                    ("frame_length", link.frame_length.into()),
                    ("frame_sha256", sha256::hex(&link.frame_sha256).into()),
                ])
            })),
        ),
    ])
}
fn confirmation_candidate(value: &crate::correlate::Dnp3ConfirmationCandidate) -> P<'_> {
    P::object([
        ("flow", value.flow.into()),
        ("status", value.status.into()),
        ("reason", value.reason.into()),
        (
            "interpretation",
            "fragment_identifiers_not_receipt_or_causality".into(),
        ),
        ("device_effect_established", false.into()),
        ("acceptance_established", false.into()),
        ("normative_conformance_certified", false.into()),
        (
            "confirms",
            P::array(value.confirms.iter().map(confirmation_fragment)),
        ),
        (
            "targets",
            P::array(value.targets.iter().map(confirmation_fragment)),
        ),
        (
            "excluded_targets",
            P::array(value.excluded_targets.iter().map(move |excluded| {
                P::object([
                    ("reason", excluded.reason.into()),
                    ("fragment", confirmation_fragment(&excluded.fragment)),
                ])
            })),
        ),
        (
            "unclassified_fragments",
            P::array(value.unclassified_fragments.iter().map(fragment_reference)),
        ),
        ("error", value.error.as_ref().map_or(J::Null, error).into()),
    ])
}
fn bound_modbus_pair<'a>(
    value: &Analysis,
    t: &'a crate::correlate::Transaction,
) -> Option<&'a crate::correlate::ModbusPair> {
    let (status, reason, pair) = t.modbus_pair.as_ref()?;
    let ([req], [rsp]) = (t.requests.as_slice(), t.responses.as_slice()) else {
        return None;
    };
    if t.protocol != "modbus"
        || t.status != *status
        || t.reason != *reason
        || pair.refs != [*req, *rsp]
        || pair.capture != value.capture_sha256
        || pair.flow != t.flow
        || !value.flows.get(pair.flow).is_some_and(|f| {
            f.id == pair.flow
                && pair
                    .generation
                    .as_ref()
                    .is_some_and(|(generation, key)| *generation == f.generation && key == &f.key)
                && !f.has_transport_loss()
        })
    {
        return None;
    }
    for ((r, binding), direction) in pair.refs.iter().zip(&pair.bindings).zip(pair.directions) {
        let app = value.applications().get(r.application)?;
        let ApplicationData::Modbus(data) = &app.data else {
            return None;
        };
        if app.direction != direction
            || app.protocol != "modbus"
            || t.flow != app.flow
            || !binding.matches(data.messages.get(r.message)?)
        {
            return None;
        }
    }
    Some(pair)
}

fn modbus_pair_fields(
    pair: &crate::correlate::ModbusPair,
    status: &'static str,
) -> Option<(&'static str, J)> {
    let [a, b] = &pair.tokens;
    let [req, rsp] = &pair.refs;
    match status {
        "inconsistent_response" => {
            Some(("disagreeing_fields", crate::modbus::mismatch_fields(a, b)?))
        }
        "candidate_pair" | "candidate_unverified_boundary" => Some((
            "read_mapping",
            crate::modbus::pair_projection(a, b, status, reference(req), reference(rsp))?,
        )),
        _ => None,
    }
}
fn snapshot_fields(
    value: &Analysis,
    include_payload: bool,
) -> impl IntoIterator<Item = (&'static str, P<'_>)> {
    let config = &value.config;
    let limits = &config.limits;
    [
        ("schema", "pcap-evidence.analysis.v1".into()),
        ("implementation_version", env!("CARGO_PKG_VERSION").into()),
        ("capture_sha256", sha256::hex(&value.capture_sha256).into()),
        ("capture_bytes", value.capture_bytes.into()),
        (
            "labels_sha256",
            value
                .labels_sha256
                .map_or(J::Null, |h| sha256::hex(&h).into())
                .into(),
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
            P::object([
                ("parse_mode", format!("{:?}", config.parse_mode).into()),
                ("overlap_policy", config.overlap_policy.as_str().into()),
                (
                    "checksum_policy",
                    format!("{:?}", config.checksum_policy).into(),
                ),
                ("idle_timeout_ns", config.idle_timeout_ns.to_string().into()),
                (
                    "dnp3_ports",
                    P::array(config.dnp3_ports.iter().map(move |p| J::from(*p))),
                ),
                (
                    "modbus_ports",
                    P::array(config.modbus_ports.iter().map(move |p| J::from(*p))),
                ),
                (
                    "limits",
                    P::object([
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
            P::array(value.packets.iter().map(move |packet| {
                let assignment = match &packet.disposition {
                    Disposition::Tcp { flow, direction } => {
                        P::object([("flow", (*flow).into()), ("direction", (*direction).into())])
                    }
                    Disposition::Rejected { code, detail } => {
                        P::object([("code", (*code).into()), ("detail", detail.clone().into())])
                    }
                    Disposition::FragmentIncomplete { reason } => {
                        P::object([("reason", (*reason).into())])
                    }
                    Disposition::Ambiguous { flows } => P::object([(
                        "candidate_flows",
                        P::array(flows.iter().map(move |f| J::from(*f))),
                    )]),
                    _ => J::Null.into(),
                };
                P::object([
                    ("id", packet_id(&packet.id).into()),
                    ("metadata", metadata(&packet.metadata).into()),
                    ("packet_sha256", sha256::hex(&packet.packet_sha256).into()),
                    ("source", packet.source.map_or(J::Null, endpoint).into()),
                    (
                        "destination",
                        packet.destination.map_or(J::Null, endpoint).into(),
                    ),
                    (
                        "transport",
                        packet.transport.map_or(J::Null, J::from).into(),
                    ),
                    ("disposition", packet.disposition.as_str().into()),
                    ("assignment", assignment),
                    ("warnings", strings(&packet.warnings)),
                ])
            })),
        ),
        (
            "flows",
            P::array(value.flows.iter().map(move |flow| {
                P::object([
                    ("id", flow.id.into()),
                    ("generation", flow.generation.into()),
                    (
                        "scope",
                        P::object([
                            ("section", flow.key.scope.section.into()),
                            ("interface", flow.key.scope.interface.into()),
                            (
                                "link_interface",
                                optional_u32(flow.key.scope.link_interface).into(),
                            ),
                            (
                                "vlans",
                                P::array(flow.key.scope.vlans.iter().map(move |v| J::from(*v))),
                            ),
                        ]),
                    ),
                    ("endpoint_a", endpoint(flow.key.a).into()),
                    ("endpoint_b", endpoint(flow.key.b).into()),
                    (
                        "syn_sequences",
                        P::array(flow.syn.iter().map(move |v| optional_u32(*v))),
                    ),
                    ("closed", flow.closed.into()),
                    ("midstream", flow.midstream.into()),
                    ("first_unix_ns", exact(flow.first_ns).into()),
                    ("last_unix_ns", exact(flow.last_ns).into()),
                    ("packets", ids(&flow.packets)),
                    ("anomalies", strings(&flow.anomalies)),
                    (
                        "uncertain_payload_packet",
                        flow.uncertain_payload
                            .as_ref()
                            .map_or(J::Null, packet_id)
                            .into(),
                    ),
                    (
                        "reconstruction_errors",
                        P::array(flow.reconstruction_errors.iter().map(error)),
                    ),
                    (
                        "streams",
                        P::array(flow.streams.iter().map(move |s| {
                            s.as_ref()
                                .map_or(J::Null.into(), |s| stream(s, include_payload))
                        })),
                    ),
                ])
            })),
        ),
        (
            "applications",
            P::array(
                value
                    .applications()
                    .iter()
                    .enumerate()
                    .map(move |(index, application)| {
                        let data = match &application.data {
                            ApplicationData::Failed(e)
                            | ApplicationData::ModbusFailed { error: e, .. } => {
                                P::object([("error", error(e).into())])
                            }
                            ApplicationData::Dnp3(d) => dnp3_data(d, include_payload, limits),
                            ApplicationData::Modbus(m) => P::object([
                                ("issues", issues(&m.issues)),
                                (
                                    "messages",
                                    P::array(m.messages.iter().map(move |message| {
                                        P::object([
                                            (
                                                "stream_offset",
                                                message.stream_offset.to_string().into(),
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
                                                crate::semantics::modbus::message_fields(
                                                    message,
                                                    crate::semantics::Limits::from_capture(limits),
                                                )
                                                .into(),
                                            ),
                                        ])
                                    })),
                                ),
                            ]),
                        };
                        P::object([
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
            P::array(value.datagrams.iter().enumerate().map(move |(id, app)| {
                let data = match &app.data {
                    Ok(d) => dnp3_data(d, include_payload, limits),
                    Err(e) => P::object([("error", error(e).into())]),
                };
                P::object([
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
                        P::object([
                            ("section", app.scope.section.into()),
                            ("interface", app.scope.interface.into()),
                            (
                                "link_interface",
                                optional_u32(app.scope.link_interface).into(),
                            ),
                            (
                                "vlans",
                                P::array(app.scope.vlans.iter().map(move |v| J::from(*v))),
                            ),
                        ]),
                    ),
                    ("source", endpoint(app.source).into()),
                    ("destination", endpoint(app.destination).into()),
                    ("packets", ids(&app.packets)),
                    ("payload", evidence(&app.payload, include_payload)),
                    ("data", data),
                ])
            })),
        ),
        (
            "fragment_notices",
            P::array(
                value.fragment_notices.iter().map(move |n| {
                    P::object([("code", n.code.into()), ("packets", ids(&n.packets))])
                }),
            ),
        ),
        (
            "transaction_candidates",
            P::array(value.transactions.iter().filter_map(move |t| {
                let pair = bound_modbus_pair(value, t);
                let needs_binding = t.modbus_pair.is_some()
                    || (t.protocol == "modbus"
                        && matches!(t.status, "candidate_pair" | "candidate_unverified_boundary"));
                if needs_binding && pair.is_none() {
                    return None;
                }
                let mut fields = vec![
                    ("protocol", t.protocol.into()),
                    ("flow", t.flow.into()),
                    ("requests", P::array(t.requests.iter().map(reference))),
                    ("responses", P::array(t.responses.iter().map(reference))),
                    ("status", t.status.into()),
                    ("reason", t.reason.into()),
                ];
                if !t.competing.is_empty() {
                    fields.push((
                        "competing_observations",
                        P::array(t.competing.iter().map(move |(app, kind, index)| {
                            P::object([("application", (*app).into()), (*kind, (*index).into())])
                        })),
                    ));
                }
                if let Some((key, field)) = pair.and_then(|p| modbus_pair_fields(p, t.status)) {
                    fields.push((key, field.into()));
                }
                Some(P::Object(fields))
            })),
        ),
        (
            "correlation_error",
            value
                .correlation_error
                .as_ref()
                .map_or(J::Null, error)
                .into(),
        ),
        (
            "dnp3_confirmation_candidates",
            P::array(
                value
                    .dnp3_confirmation_candidates
                    .iter()
                    .map(confirmation_candidate),
            ),
        ),
        (
            "dnp3_confirmation_error",
            value
                .dnp3_confirmation_error
                .as_ref()
                .map_or(J::Null, error)
                .into(),
        ),
        (
            "attempt_label_matches",
            P::array(value.attempt_matches.iter().map(move |m| {
                P::object([
                    ("attempt_id", m.attempt_id.clone().into()),
                    ("status", m.status.into()),
                    ("matched_packets", ids(&m.matched_packets)),
                    ("unresolved_time_packets", ids(&m.unresolved_time_packets)),
                    ("flows", P::array(m.flows.iter().map(move |f| J::from(*f)))),
                    ("messages", P::array(m.messages.iter().map(reference))),
                ])
            })),
        ),
    ]
}

/// Collect the full JSON tree for callers that need to inspect or edit it.
pub fn analysis(value: &Analysis, include_payload: bool) -> J {
    P::object(snapshot_fields(value, include_payload)).into_json()
}

/// Encode the CLI report without retaining the projected capture-wide JSON tree.
/// The limit includes protocol detection and the final newline.
pub fn analysis_line(value: &Analysis, include_payload: bool, limit: usize) -> Result<String> {
    let mut out = Output {
        text: String::new(),
        limit,
    };
    out.push("{")?;
    out.fields(snapshot_fields(value, include_payload))?;
    out.push(",\"protocol_detection\":[")?;
    for (i, record) in crate::detection::flow_records(value).enumerate() {
        if i != 0 {
            out.push(",")?;
        }
        out.value(&record?)?;
    }
    out.push("]}\n")?;
    Ok(out.text)
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

fn dnp3_data<'a>(
    d: &'a crate::dnp3::Dnp3Result,
    include_payload: bool,
    limits: &'a Limits,
) -> P<'a> {
    P::object([
        (
            "object_semantics",
            "bounded_source_bound_non_secure_subset".into(),
        ),
        ("issues", issues(&d.issues)),
        (
            "rejected_link_ranges",
            P::array(d.rejected_link_ranges.iter().map(move |range| {
                P::object([
                    ("stream_offset", range.stream_offset.to_string().into()),
                    ("captured_length", range.raw.len().to_string().into()),
                    (
                        "declared_length",
                        range
                            .declared_length
                            .map_or(J::Null, |n| n.to_string().into())
                            .into(),
                    ),
                    (
                        "status",
                        if range.incomplete {
                            "incomplete"
                        } else {
                            "rejected"
                        }
                        .into(),
                    ),
                    ("reason", range.code.into()),
                    ("raw", evidence(&range.raw, false)),
                ])
            })),
        ),
        (
            "link_frames",
            P::array(d.frames.iter().map(move |frame| {
                P::object([
                    ("stream_offset", frame.stream_offset.to_string().into()),
                    ("control", frame.control.into()),
                    (
                        "control_semantics",
                        P::object([
                            ("direction_bit", frame.link_control.direction.into()),
                            ("primary", frame.link_control.primary.into()),
                            (
                                "fcb",
                                frame.link_control.fcb.map_or(J::Null, J::from).into(),
                            ),
                            (
                                "fcv",
                                frame.link_control.fcv.map_or(J::Null, J::from).into(),
                            ),
                            (
                                "dfc",
                                frame.link_control.dfc.map_or(J::Null, J::from).into(),
                            ),
                            (
                                "reserved",
                                frame.link_control.reserved.map_or(J::Null, J::from).into(),
                            ),
                            ("function", frame.link_control.function.into()),
                            ("function_name", frame.link_control.function_name.into()),
                        ]),
                    ),
                    ("source", frame.source.into()),
                    ("destination", frame.destination.into()),
                    ("broadcast", frame.broadcast.into()),
                    (
                        "destination_address_kind",
                        crate::semantics::dnp3_workflow::address_kind(frame.destination).into(),
                    ),
                    (
                        "broadcast_confirm_policy",
                        crate::semantics::dnp3_workflow::broadcast_confirm_policy(
                            frame.destination,
                        )
                        .map_or(J::Null, J::from)
                        .into(),
                    ),
                    (
                        "link_workflow",
                        crate::semantics::as_json(crate::semantics::dnp3_workflow::link(
                            &frame.raw,
                            crate::semantics::Limits::from_capture(limits),
                        ))
                        .into(),
                    ),
                    ("raw", evidence(&frame.raw, false)),
                    ("user_data", evidence(&frame.user_data, include_payload)),
                ])
            })),
        ),
        (
            "application_fragments",
            P::array(d.fragments.iter().map(move |fragment| {
                P::object([
                    ("control", fragment.control.into()),
                    ("function", fragment.function.into()),
                    (
                        "function_name",
                        crate::dnp3::function_code(fragment.function)
                            .as_str()
                            .into(),
                    ),
                    ("sequence", fragment.sequence.into()),
                    ("class", fragment.class.as_str().into()),
                    ("iin", fragment.iin.map_or(J::Null, J::from).into()),
                    ("first", fragment.first.into()),
                    ("final", fragment.final_fragment.into()),
                    (
                        "confirmation_requested",
                        fragment.confirmation_requested.into(),
                    ),
                    (
                        "link_frames",
                        P::array(fragment.frames.iter().map(move |f| J::from(*f))),
                    ),
                    ("raw", evidence(&fragment.raw, include_payload)),
                    (
                        "application_workflow",
                        crate::semantics::as_json(crate::semantics::dnp3_workflow::application(
                            &fragment.raw,
                            crate::semantics::Limits::from_capture(limits),
                        ))
                        .into(),
                    ),
                    (
                        "message_object_semantic_subset",
                        crate::semantics::dnp3::fragment_json(
                            fragment,
                            crate::semantics::Limits::from_capture(limits),
                        )
                        .into(),
                    ),
                ])
            })),
        ),
        (
            "messages",
            P::array(d.messages.iter().map(move |message| {
                P::object([
                    ("source", message.source.into()),
                    ("destination", message.destination.into()),
                    ("function", message.function.into()),
                    (
                        "function_name",
                        crate::dnp3::function_code(message.function).as_str().into(),
                    ),
                    ("first_sequence", message.first_sequence.into()),
                    ("class", message.class.as_str().into()),
                    ("complete", message.complete.into()),
                    (
                        "fragments",
                        P::array(message.fragments.iter().map(move |f| J::from(*f))),
                    ),
                    ("packets", ids(&message.packets)),
                    ("objects", evidence(&message.objects, include_payload)),
                    (
                        "object_semantic_subset",
                        crate::semantics::dnp3::assembled_message_json(
                            &message.objects,
                            message.function,
                            message.complete,
                            crate::semantics::Limits::from_capture(limits),
                        )
                        .into(),
                    ),
                ])
            })),
        ),
    ])
}
