//! The real producer -> reconstruction -> protocol -> report path.
use crate::capture::{CaptureIter, PacketMeta, ParseMode, RecordKind};
use crate::correlate::{AttemptMatch, Transaction};
use crate::dnp3::{self, Dnp3Result};
use crate::fragment::{FragmentNotice, FragmentOutcome, FragmentReassembler};
use crate::modbus::{self, ModbusResult, Role};
use crate::provenance::PacketId;
use crate::sha256;
use crate::tcp::{Assignment, FlowResult, OverlapPolicy, TcpTracker};
use crate::wire::{self, Checksum, ChecksumPolicy, Endpoint, Scope, Transport};
use crate::{Error, ErrorCode, Limits, Result};

#[derive(Clone, Debug)]
pub struct Config {
    pub limits: Limits,
    pub parse_mode: ParseMode,
    pub overlap_policy: OverlapPolicy,
    pub checksum_policy: ChecksumPolicy,
    pub idle_timeout_ns: i128,
    pub dnp3_ports: Vec<u16>,
    pub modbus_ports: Vec<u16>,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            limits: Limits::default(),
            parse_mode: ParseMode::Strict,
            overlap_policy: OverlapPolicy::RejectConflict,
            checksum_policy: ChecksumPolicy::Observe,
            idle_timeout_ns: 120_000_000_000,
            dnp3_ports: vec![20000],
            modbus_ports: vec![502],
        }
    }
}
impl Config {
    pub fn validate(&self) -> Result<()> {
        self.limits.validate()?;
        if self.idle_timeout_ns <= 0 {
            return Err(Error::new(
                ErrorCode::Usage,
                0,
                "idle_timeout",
                "must be positive",
            ));
        }
        if self
            .dnp3_ports
            .iter()
            .any(|port| self.modbus_ports.contains(port))
        {
            return Err(Error::new(
                ErrorCode::Usage,
                0,
                "protocol_ports",
                "a port cannot select two dissectors",
            ));
        }
        if self.dnp3_ports.len() + self.modbus_ports.len() > 128 {
            return Err(Error::limit("protocol_ports"));
        }
        Ok(())
    }
}
#[derive(Clone, Debug)]
pub enum Disposition {
    Pending,
    Tcp { flow: usize, direction: usize },
    Udp,
    FragmentPending,
    FragmentIncomplete { reason: &'static str },
    Rejected { code: &'static str, detail: String },
    Ambiguous { flows: Vec<usize> },
}
impl Disposition {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Tcp { .. } => "tcp_assigned",
            Self::Udp => "udp_observed",
            Self::FragmentPending => "fragment_pending",
            Self::FragmentIncomplete { .. } => "fragment_incomplete",
            Self::Rejected { .. } => "rejected_or_unsupported",
            Self::Ambiguous { .. } => "ambiguous_generation",
        }
    }
}
#[derive(Clone, Debug)]
pub struct PacketObservation {
    pub id: PacketId,
    pub metadata: PacketMeta,
    pub packet_sha256: [u8; 32],
    pub source: Option<Endpoint>,
    pub destination: Option<Endpoint>,
    pub transport: Option<&'static str>,
    pub disposition: Disposition,
    pub warnings: Vec<&'static str>,
}
#[derive(Clone, Debug)]
pub enum ApplicationData {
    Dnp3(Dnp3Result),
    Modbus(ModbusResult),
    Failed(Error),
}
#[derive(Clone, Debug)]
pub struct ApplicationAnalysis {
    pub flow: usize,
    pub direction: usize,
    pub protocol: &'static str,
    pub data: ApplicationData,
}
#[derive(Clone, Debug)]
pub struct Analysis {
    pub capture_sha256: [u8; 32],
    pub labels_sha256: Option<[u8; 32]>,
    pub capture_bytes: usize,
    pub config: Config,
    pub records: usize,
    pub metadata_records: usize,
    pub secret_blocks: usize,
    pub packets: Vec<PacketObservation>,
    pub flows: Vec<FlowResult>,
    pub applications: Vec<ApplicationAnalysis>,
    pub datagrams: Vec<crate::datagram::DatagramAnalysis>,
    pub fragment_notices: Vec<FragmentNotice>,
    pub transactions: Vec<Transaction>,
    /// Independent fragment-level candidate identifiers; never application acceptance.
    pub dnp3_confirmation_candidates: Vec<crate::correlate::Dnp3ConfirmationCandidate>,
    pub dnp3_confirmation_error: Option<Error>,
    pub attempt_matches: Vec<AttemptMatch>,
    pub correlation_error: Option<Error>,
}
impl Analysis {
    /// Means no detected degradation in the supported path; not proof of capture completeness.
    pub fn has_diagnostics(&self) -> bool {
        self.datagrams.iter().any(|d| match &d.data {
            Err(_) => true,
            Ok(result) => !result.issues.is_empty() || result.messages.iter().any(|m| !m.complete),
        }) || self.packets.iter().any(|p| {
            !p.warnings.is_empty()
                || !matches!(p.disposition, Disposition::Tcp { .. } | Disposition::Udp)
        }) || !self.fragment_notices.is_empty()
            || self.correlation_error.is_some()
            || self.dnp3_confirmation_error.is_some()
            || self.flows.iter().any(|f| {
                f.midstream
                    || !f.closed
                    || !f.anomalies.is_empty()
                    || !f.reconstruction_errors.is_empty()
                    || f.streams
                        .iter()
                        .flatten()
                        .any(|s| !s.gaps.is_empty() || !s.conflicts.is_empty())
            })
            || self.applications.iter().any(|a| match &a.data {
                ApplicationData::Failed(_) => true,
                ApplicationData::Dnp3(d) => {
                    !d.issues.is_empty() || d.messages.iter().any(|m| !m.complete)
                }
                ApplicationData::Modbus(m) => !m.issues.is_empty(),
            })
    }
}
fn each_packet<F: FnMut(&mut PacketObservation)>(
    packets: &mut [PacketObservation],
    ids: &[PacketId],
    mut action: F,
) -> Result<()> {
    for id in ids {
        let index = id
            .frame
            .checked_sub(1)
            .and_then(|x| usize::try_from(x).ok())
            .ok_or_else(|| {
                Error::new(
                    ErrorCode::Invariant,
                    0,
                    "packet_identity",
                    "invalid frame ID",
                )
            })?;
        let packet = packets
            .get_mut(index)
            .filter(|p| p.id == *id)
            .ok_or_else(|| {
                Error::new(
                    ErrorCode::Invariant,
                    0,
                    "packet_identity",
                    "provenance points outside this capture",
                )
            })?;
        action(packet);
    }
    Ok(())
}
fn fragment_notice(packets: &mut [PacketObservation], notice: &FragmentNotice) -> Result<()> {
    each_packet(packets, &notice.packets, |packet| {
        packet.disposition = Disposition::FragmentIncomplete {
            reason: notice.code,
        };
    })
}
pub fn analyze(input: &[u8], config: Config) -> Result<Analysis> {
    config.validate()?;
    if input.len() > config.limits.max_input_bytes {
        return Err(Error::limit("input_bytes"));
    }
    let identity = sha256::digest(input);
    let mut fragments = FragmentReassembler::new(config.limits.clone());
    let mut tracker = TcpTracker::new(config.limits.clone(), config.idle_timeout_ns)?;
    let mut packets = Vec::new();
    let mut notices = Vec::new();
    let mut datagrams = Vec::new();
    let mut udp_retained = 0usize;
    let mut records = 0;
    let mut metadata_records = 0;
    let mut secret_blocks = 0;
    for record in CaptureIter::new(input, config.limits.clone(), config.parse_mode)? {
        let record = record?;
        records += 1;
        let (metadata, data) = match record.packet() {
            Some(p) => p,
            None => {
                metadata_records += 1;
                if matches!(record.kind(), RecordKind::Secrets { .. }) {
                    secret_blocks += 1;
                }
                continue;
            }
        };
        for notice in fragments.expire(metadata.frame) {
            fragment_notice(&mut packets, &notice)?;
            notices.push(notice);
        }
        let id = PacketId {
            capture: identity,
            frame: metadata.frame,
            record_offset: record.offset(),
        };
        if metadata.frame != packets.len() as u64 + 1 {
            return Err(Error::new(
                ErrorCode::Invariant,
                record.offset(),
                "frame",
                "noncontiguous packet numbering",
            ));
        }
        let mut warnings: Vec<_> = record.warnings().iter().map(|w| w.code).collect();
        if metadata.captured_len < metadata.original_len {
            warnings.push("snaplen_truncated_packet");
        }
        if metadata.timestamp.is_none() {
            warnings.push("capture_timestamp_absent");
        }
        let time = metadata.timestamp.and_then(|t| t.unix_nanos().ok());
        if metadata.timestamp.is_some() && time.is_none() {
            warnings.push("timestamp_not_exact_in_nanoseconds");
        }
        packets.push(PacketObservation {
            id,
            metadata: metadata.clone(),
            packet_sha256: sha256::digest(data),
            source: None,
            destination: None,
            transport: None,
            disposition: Disposition::Pending,
            warnings,
        });
        let at = packets.len() - 1;
        let scope = Scope {
            section: metadata.section,
            interface: metadata.interface,
            vlans: Vec::new(),
        };
        let network = match wire::decode_packet(metadata.link_type, data, id, scope) {
            Ok(d) => d,
            Err(e) => {
                packets[at].disposition = Disposition::Rejected {
                    code: e.code.as_str(),
                    detail: e.to_string(),
                };
                continue;
            }
        };
        if network.ip_checksum == Checksum::Invalid {
            packets[at].warnings.push("invalid_ipv4_checksum_observed");
        }
        if config.checksum_policy == ChecksumPolicy::RequireValid
            && network.ip_checksum == Checksum::Invalid
        {
            packets[at].disposition = Disposition::Rejected {
                code: "checksum",
                detail: "IPv4 checksum rejected by configured policy".into(),
            };
            continue;
        }
        let (datagram, mut contributors) = match fragments.push(network, metadata.frame)? {
            FragmentOutcome::Pending => {
                packets[at].disposition = Disposition::FragmentPending;
                continue;
            }
            FragmentOutcome::Rejected(notice) => {
                fragment_notice(&mut packets, &notice)?;
                notices.push(notice);
                continue;
            }
            FragmentOutcome::Complete(d, ids) => (d, ids),
        };
        if contributors.is_empty() {
            contributors.push(id);
        }
        let transport = match wire::decode_transport(&datagram, config.checksum_policy) {
            Ok(t) => t,
            Err(e) => {
                each_packet(&mut packets, &contributors, |p| {
                    p.disposition = Disposition::Rejected {
                        code: e.code.as_str(),
                        detail: e.to_string(),
                    };
                })?;
                continue;
            }
        };
        let datagram_scope = datagram.scope.clone();
        match transport {
            Transport::Tcp(segment) => {
                let source = segment.source;
                let destination = segment.destination;
                let checksum = segment.checksum;
                let assignment =
                    tracker.ingest_with_packets(datagram.scope, &contributors, time, segment)?;
                each_packet(&mut packets, &contributors, |p| {
                    p.source = Some(source);
                    p.destination = Some(destination);
                    p.transport = Some("tcp");
                    if checksum == Checksum::Invalid {
                        p.warnings.push("invalid_tcp_checksum_observed");
                    }
                    p.disposition = match &assignment {
                        Assignment::Assigned { flow_id, direction } => Disposition::Tcp {
                            flow: *flow_id,
                            direction: *direction,
                        },
                        Assignment::Ambiguous { candidate_flow_ids } => Disposition::Ambiguous {
                            flows: candidate_flow_ids.clone(),
                        },
                        Assignment::Unassigned { reason } => Disposition::Rejected {
                            code: reason,
                            detail: "cannot safely assign a connection generation".into(),
                        },
                    };
                })?;
            }
            Transport::Udp(datagram) => {
                each_packet(&mut packets, &contributors, |p| {
                    p.source = Some(datagram.source);
                    p.destination = Some(datagram.destination);
                    p.transport = Some("udp");
                    p.disposition = Disposition::Udp;
                    if datagram.checksum == Checksum::Invalid {
                        p.warnings.push("invalid_udp_checksum_observed");
                    }
                })?;
                if !datagram.payload.is_empty()
                    && (config.dnp3_ports.contains(&datagram.source.port)
                        || config.dnp3_ports.contains(&datagram.destination.port))
                {
                    if datagrams.len() >= config.limits.max_protocol_messages {
                        return Err(Error::limit("udp_applications"));
                    }
                    let retained = udp_retained
                        .checked_add(datagram.payload.len())
                        .ok_or_else(|| Error::limit("udp_retained_payload"))?;
                    if retained > config.limits.max_retained_payload {
                        return Err(Error::limit("udp_retained_payload"));
                    }
                    if let Some(application) = crate::datagram::analyze_udp(
                        &datagram_scope,
                        &datagram,
                        &contributors,
                        &config.dnp3_ports,
                        &config.limits,
                    )? {
                        datagrams.push(application);
                        udp_retained = retained;
                    }
                }
            }
        }
    }
    for notice in fragments.finish() {
        fragment_notice(&mut packets, &notice)?;
        notices.push(notice);
    }
    if packets.iter().any(|p| {
        matches!(
            p.disposition,
            Disposition::Pending | Disposition::FragmentPending
        )
    }) {
        return Err(Error::new(
            ErrorCode::Invariant,
            0,
            "packet_conservation",
            "nonterminal packet disposition remains at EOF",
        ));
    }
    let flows = tracker.finish(config.overlap_policy)?;
    let mut applications = Vec::new();
    for flow in &flows {
        let detected = crate::detection::classify_flow(flow, &config)?;
        let dnp = detected.dnp3;
        let modbus = detected.modbus;
        for direction in 0..2 {
            let stream = match &flow.streams[direction] {
                Some(s) if !s.chunks.is_empty() => s,
                _ => continue,
            };
            let (protocol, data) = if dnp && modbus {
                (
                    "ambiguous",
                    ApplicationData::Failed(Error::new(
                        ErrorCode::ProtocolFraming,
                        0,
                        "protocol_selection",
                        "multiple content/configuration interpretations remain unresolved",
                    )),
                )
            } else if dnp {
                (
                    "dnp3",
                    match dnp3::decode(stream, &config.limits) {
                        Ok(d) => ApplicationData::Dnp3(d),
                        Err(e) => ApplicationData::Failed(e),
                    },
                )
            } else if modbus {
                let a_server = config.modbus_ports.contains(&flow.key.a.port);
                let b_server = config.modbus_ports.contains(&flow.key.b.port);
                let role = if a_server == b_server {
                    Role::Unknown
                } else if (direction == 0 && a_server) || (direction == 1 && b_server) {
                    Role::Response
                } else {
                    Role::Request
                };
                (
                    "modbus",
                    match modbus::decode(stream, role, &config.limits) {
                        Ok(d) => ApplicationData::Modbus(d),
                        Err(e) => ApplicationData::Failed(e),
                    },
                )
            } else {
                continue;
            };
            applications.push(ApplicationAnalysis {
                flow: flow.id,
                direction,
                protocol,
                data,
            });
        }
    }
    let (transactions, correlation_error) =
        match crate::correlate::transactions(&applications, &config.limits) {
            Ok(t) => (t, None),
            Err(e) => (Vec::new(), Some(e)),
        };
    let (dnp3_confirmation_candidates, dnp3_confirmation_error) =
        match crate::correlate::dnp3_confirmation_candidates(&applications, &config.limits) {
            Ok(candidates) => (candidates, None),
            Err(error) => (Vec::new(), Some(error)),
        };
    Ok(Analysis {
        capture_sha256: identity,
        labels_sha256: None,
        capture_bytes: input.len(),
        config,
        records,
        metadata_records,
        secret_blocks,
        packets,
        flows,
        applications,
        datagrams,
        fragment_notices: notices,
        transactions,
        dnp3_confirmation_candidates,
        dnp3_confirmation_error,
        attempt_matches: Vec::new(),
        correlation_error,
    })
}
