//! Conservative protocol candidate pairing and externally supplied attempt labels.
//! A candidate edge is NOT proof that an attack occurred or succeeded.
use crate::dnp3::MessageClass;
use crate::engine::{Analysis, ApplicationAnalysis, ApplicationData};
use crate::modbus::Role;
use crate::provenance::PacketId;
use crate::wire::Endpoint;
use crate::{Error, ErrorCode, Limits, Result};
use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct MessageRef {
    pub application: usize,
    pub message: usize,
}
#[derive(Clone, Debug)]
pub struct Transaction {
    pub protocol: &'static str,
    pub flow: usize,
    pub requests: Vec<MessageRef>,
    pub responses: Vec<MessageRef>,
    pub status: &'static str,
    pub reason: &'static str,
}
#[derive(Default)]
struct Group {
    requests: Vec<MessageRef>,
    responses: Vec<MessageRef>,
    uncertain_boundary: bool,
}

/// Pair within one connection generation. Reused small sequence numbers remain
/// ambiguous rather than being joined by an invented clock/order heuristic.
pub fn transactions(
    applications: &[ApplicationAnalysis],
    limits: &Limits,
) -> Result<Vec<Transaction>> {
    // Protocol, flow, controller address/unit, outstation address, sequence/tx ID, function.
    let mut groups: BTreeMap<(&'static str, usize, u16, u16, u16, u8), Group> = BTreeMap::new();
    let mut output = Vec::new();
    let mut count = 0usize;
    for (ai, application) in applications.iter().enumerate() {
        match &application.data {
            ApplicationData::Dnp3(result) => {
                for (mi, message) in result.messages.iter().enumerate() {
                    count += 1;
                    if count > limits.max_protocol_messages {
                        return Err(Error::limit("correlation_messages"));
                    }
                    let reference = MessageRef {
                        application: ai,
                        message: mi,
                    };
                    if !message.complete
                        || !matches!(
                            message.class,
                            MessageClass::Request | MessageClass::Response
                        )
                    {
                        let (status, reason) = match message.class {
                            MessageClass::Unsolicited => ("unsolicited", "no_request_required"),
                            MessageClass::Confirm => {
                                ("confirmation", "not_an_independent_request_response_pair")
                            }
                            _ if !message.complete => {
                                ("incomplete", "application_fragments_missing")
                            }
                            _ => ("unclassified", "function_or_role_not_supported"),
                        };
                        output.push(Transaction {
                            protocol: "dnp3",
                            flow: application.flow,
                            requests: if message.class == MessageClass::Request {
                                vec![reference]
                            } else {
                                Vec::new()
                            },
                            responses: if message.class != MessageClass::Request {
                                vec![reference]
                            } else {
                                Vec::new()
                            },
                            status,
                            reason,
                        });
                        continue;
                    }
                    let (controller, outstation) = if message.class == MessageClass::Request {
                        (message.source, message.destination)
                    } else {
                        (message.destination, message.source)
                    };
                    let group = groups
                        .entry((
                            "dnp3",
                            application.flow,
                            controller,
                            outstation,
                            message.first_sequence as u16,
                            0,
                        ))
                        .or_default();
                    if message.class == MessageClass::Request {
                        group.requests.push(reference);
                    } else {
                        group.responses.push(reference);
                    }
                }
            }
            ApplicationData::Modbus(result) => {
                for (mi, message) in result.messages.iter().enumerate() {
                    count += 1;
                    if count > limits.max_protocol_messages {
                        return Err(Error::limit("correlation_messages"));
                    }
                    let reference = MessageRef {
                        application: ai,
                        message: mi,
                    };
                    if !message.shape_valid
                        || !message.semantics_supported
                        || message.role == Role::Unknown
                    {
                        output.push(Transaction {
                            protocol: "modbus",
                            flow: application.flow,
                            requests: if message.role == Role::Request {
                                vec![reference]
                            } else {
                                Vec::new()
                            },
                            responses: if message.role != Role::Request {
                                vec![reference]
                            } else {
                                Vec::new()
                            },
                            status: "unclassified",
                            reason: "invalid_or_unsupported_pdu_shape_or_endpoint_role",
                        });
                        continue;
                    }
                    let group = groups
                        .entry((
                            "modbus",
                            application.flow,
                            message.unit as u16,
                            0,
                            message.transaction,
                            message.function & 0x7f,
                        ))
                        .or_default();
                    group.uncertain_boundary |= !message.boundary_verified;
                    if message.role == Role::Request {
                        group.requests.push(reference);
                    } else {
                        group.responses.push(reference);
                    }
                }
            }
            ApplicationData::Failed(_) => {}
        }
    }
    for ((protocol, flow, _, _, _, _), group) in groups {
        let inconsistent_modbus =
            if protocol == "modbus" && group.requests.len() == 1 && group.responses.len() == 1 {
                let request = &group.requests[0];
                let response = &group.responses[0];
                match (
                    &applications[request.application].data,
                    &applications[response.application].data,
                ) {
                    (ApplicationData::Modbus(a), ApplicationData::Modbus(b)) => {
                        !crate::modbus::response_matches(
                            &a.messages[request.message],
                            &b.messages[response.message],
                        )
                    }
                    _ => false,
                }
            } else {
                false
            };
        let (status, reason) = match (group.requests.len(), group.responses.len()) {
            (1, 1) if inconsistent_modbus => (
                "inconsistent_response",
                "request_response_pdu_fields_disagree",
            ),
            (1, 1) if group.uncertain_boundary => (
                "candidate_unverified_boundary",
                "midstream_mbap_alignment_not_independently_proven",
            ),
            (1, 1) => (
                "candidate_pair",
                "matching_protocol_identifiers_not_attack_proof",
            ),
            (0, _) => ("orphan_response", "request_not_observed"),
            (_, 0) => ("unanswered", "response_not_observed"),
            _ => (
                "ambiguous",
                "identifier_reuse_or_duplicate_application_messages",
            ),
        };
        output.push(Transaction {
            protocol,
            flow,
            requests: group.requests,
            responses: group.responses,
            status,
            reason,
        });
    }
    Ok(output)
}

pub const LABEL_HEADER: &str =
    "attempt_id\tstart_ns\tend_ns\tsrc_ip\tsrc_port\tdst_ip\tdst_port\ttransport";
#[derive(Clone, Debug)]
pub struct AttemptLabel {
    pub id: String,
    pub start_ns: i128,
    pub end_ns: i128,
    pub source: Endpoint,
    pub destination: Endpoint,
    pub transport: &'static str,
}
#[derive(Clone, Debug)]
pub struct AttemptMatch {
    pub attempt_id: String,
    pub status: &'static str,
    pub matched_packets: Vec<PacketId>,
    pub unresolved_time_packets: Vec<PacketId>,
    pub flows: Vec<usize>,
    pub messages: Vec<MessageRef>,
}
fn invalid(line: usize, detail: impl Into<String>) -> Error {
    Error::new(
        ErrorCode::InvalidLabel,
        0,
        "labels",
        format!("line {line}: {}", detail.into()),
    )
}
/// Strict version 1 TSV. Times are signed, exact Unix nanoseconds. Inclusive bounds.
/// Blank lines are allowed; wildcards, duplicate IDs and silent trimming are not.
pub fn parse_labels(input: &str, limits: &Limits) -> Result<Vec<AttemptLabel>> {
    if input.len() > limits.max_input_bytes {
        return Err(Error::limit("labels_bytes"));
    }
    let mut lines = input.lines();
    if lines.next() != Some(LABEL_HEADER) {
        return Err(invalid(1, "expected the exact v1 TSV header"));
    }
    let mut seen = BTreeSet::new();
    let mut labels = Vec::new();
    for (index, line) in lines.enumerate() {
        if line.is_empty() {
            continue;
        }
        if labels.len() >= limits.max_labels {
            return Err(Error::limit("labels"));
        }
        let fields: Vec<_> = line.split('\t').collect();
        if fields.len() != 8 {
            return Err(invalid(index + 2, "expected 8 fields"));
        }
        if fields[0].is_empty()
            || fields[0].len() > 256
            || fields[0].chars().any(char::is_control)
            || fields.iter().any(|field| field.trim() != *field)
        {
            return Err(invalid(
                index + 2,
                "empty/overlong ID, control character or surrounding whitespace",
            ));
        }
        if !seen.insert(fields[0].to_owned()) {
            return Err(invalid(index + 2, "duplicate attempt ID"));
        }
        let start_ns = fields[1]
            .parse::<i128>()
            .map_err(|_| invalid(index + 2, "invalid start_ns"))?;
        let end_ns = fields[2]
            .parse::<i128>()
            .map_err(|_| invalid(index + 2, "invalid end_ns"))?;
        if start_ns > end_ns {
            return Err(invalid(index + 2, "start_ns exceeds end_ns"));
        }
        let source = Endpoint {
            address: fields[3]
                .parse::<IpAddr>()
                .map_err(|_| invalid(index + 2, "invalid src_ip"))?,
            port: fields[4]
                .parse::<u16>()
                .map_err(|_| invalid(index + 2, "invalid src_port"))?,
        };
        let destination = Endpoint {
            address: fields[5]
                .parse::<IpAddr>()
                .map_err(|_| invalid(index + 2, "invalid dst_ip"))?,
            port: fields[6]
                .parse::<u16>()
                .map_err(|_| invalid(index + 2, "invalid dst_port"))?,
        };
        let transport = match fields[7] {
            "tcp" => "tcp",
            "udp" => "udp",
            _ => return Err(invalid(index + 2, "transport must be tcp or udp")),
        };
        labels.push(AttemptLabel {
            id: fields[0].to_owned(),
            start_ns,
            end_ns,
            source,
            destination,
            transport,
        });
    }
    Ok(labels)
}
fn tuple(
    source: Endpoint,
    destination: Endpoint,
    transport: &'static str,
) -> (Endpoint, Endpoint, &'static str) {
    if source <= destination {
        (source, destination, transport)
    } else {
        (destination, source, transport)
    }
}
pub fn match_attempts(analysis: &Analysis, labels: &[AttemptLabel]) -> Result<Vec<AttemptMatch>> {
    if labels.len() > analysis.config.limits.max_labels {
        return Err(Error::limit("labels"));
    }
    let mut packet_tuples = BTreeMap::<_, Vec<usize>>::new();
    for (index, packet) in analysis.packets.iter().enumerate() {
        if let (Some(source), Some(destination), Some(transport)) =
            (packet.source, packet.destination, packet.transport)
        {
            packet_tuples
                .entry(tuple(source, destination, transport))
                .or_default()
                .push(index);
        }
    }
    let mut packet_messages: BTreeMap<PacketId, Vec<MessageRef>> = BTreeMap::new();
    let mut checks = 0usize;
    let budget = analysis.config.limits.max_correlation_checks;
    for (ai, application) in analysis.applications.iter().enumerate() {
        let message_packets: Vec<Vec<PacketId>> = match &application.data {
            ApplicationData::Dnp3(d) => d.messages.iter().map(|m| m.packets.clone()).collect(),
            ApplicationData::Modbus(m) => m.messages.iter().map(|m| m.raw.packets()).collect(),
            ApplicationData::Failed(_) => Vec::new(),
        };
        for (mi, ids) in message_packets.into_iter().enumerate() {
            for id in ids {
                checks += 1;
                if checks > budget {
                    return Err(Error::limit("correlation_checks"));
                }
                packet_messages.entry(id).or_default().push(MessageRef {
                    application: ai,
                    message: mi,
                });
            }
        }
    }
    let mut output = Vec::with_capacity(labels.len());
    for label in labels {
        let mut matched = Vec::new();
        let mut unresolved = Vec::new();
        let mut flows = BTreeSet::new();
        let mut messages = BTreeSet::new();
        if let Some(indices) =
            packet_tuples.get(&tuple(label.source, label.destination, label.transport))
        {
            for &index in indices {
                checks += 1;
                if checks > budget {
                    return Err(Error::limit("correlation_checks"));
                }
                let packet = &analysis.packets[index];
                match packet.metadata.timestamp.and_then(|t| t.unix_nanos().ok()) {
                    Some(time) if label.start_ns <= time && time <= label.end_ns => {
                        matched.push(packet.id);
                        if let crate::engine::Disposition::Tcp { flow, .. } = &packet.disposition {
                            flows.insert(*flow);
                        }
                        if let Some(references) = packet_messages.get(&packet.id) {
                            checks = checks
                                .checked_add(references.len())
                                .ok_or_else(|| Error::limit("correlation_checks"))?;
                            if checks > budget {
                                return Err(Error::limit("correlation_checks"));
                            }
                            messages.extend(references.iter().copied());
                        }
                    }
                    None => unresolved.push(packet.id),
                    _ => {}
                }
            }
        }
        let status = match (matched.is_empty(), unresolved.is_empty()) {
            (false, true) => "candidate_evidence_found",
            (false, false) => "candidates_and_unresolved_time",
            (true, false) => "insufficient_timestamp_evidence",
            (true, true) => "no_matching_evidence_in_supported_packets",
        };
        output.push(AttemptMatch {
            attempt_id: label.id.clone(),
            status,
            matched_packets: matched,
            unresolved_time_packets: unresolved,
            flows: flows.into_iter().collect(),
            messages: messages.into_iter().collect(),
        });
    }
    Ok(output)
}
/// Transactional application: invalid labels leave the analysis unchanged.
pub fn apply_labels(analysis: &mut Analysis, text: &str) -> Result<()> {
    let labels = parse_labels(text, &analysis.config.limits)?;
    let matches = match_attempts(analysis, &labels)?;
    analysis.attempt_matches = matches;
    analysis.labels_sha256 = Some(crate::sha256::digest(text.as_bytes()));
    Ok(())
}
