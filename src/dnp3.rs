//! Passive DNP3 framing and transport/application fragment reconstruction.
//! Raw object bytes remain authoritative; bounded semantic interpretation lives
//! in `semantics::dnp3` and never implies endpoint/device effects.
use crate::provenance::{EvidenceBytes, PacketId};
use crate::tcp::StreamResult;
use crate::{Error, ErrorCode, Limits, Result};
use std::collections::BTreeMap;

#[derive(Clone, Debug)]
pub struct ProtocolIssue {
    pub code: &'static str,
    pub packets: Vec<PacketId>,
    pub stream_offset: i64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinkControl {
    pub direction: bool,
    pub primary: bool,
    pub fcb: Option<bool>,
    pub fcv: Option<bool>,
    pub dfc: Option<bool>,
    pub reserved: Option<bool>,
    pub function: u8,
    pub function_name: &'static str,
}

pub fn link_control(control: u8) -> LinkControl {
    let primary = control & 0x40 != 0;
    let function = control & 0x0f;
    let function_name = if primary {
        match function {
            0 => "reset_link_states",
            1 => "reset_user_process",
            2 => "test_link_states",
            3 => "confirmed_user_data",
            4 => "unconfirmed_user_data",
            9 => "request_link_status",
            _ => "primary_unknown",
        }
    } else {
        match function {
            0 => "ack",
            1 => "nack",
            11 => "link_status",
            14 => "link_service_not_functioning",
            15 => "link_service_not_implemented",
            _ => "secondary_unknown",
        }
    };
    LinkControl {
        direction: control & 0x80 != 0,
        primary,
        fcb: primary.then_some(control & 0x20 != 0),
        fcv: primary.then_some(control & 0x10 != 0),
        dfc: (!primary).then_some(control & 0x10 != 0),
        reserved: (!primary).then_some(control & 0x20 != 0),
        function,
        function_name,
    }
}

#[derive(Clone, Debug)]
pub struct LinkFrame {
    pub stream_offset: i64,
    pub control: u8,
    pub link_control: LinkControl,
    pub source: u16,
    pub destination: u16,
    pub broadcast: bool,
    pub user_data: EvidenceBytes,
    pub raw: EvidenceBytes,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum MessageClass {
    Request,
    Response,
    Unsolicited,
    Confirm,
    Unknown,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FunctionCode {
    Confirm,
    Read,
    Write,
    Select,
    Operate,
    DirectOperate,
    DirectOperateNoResponse,
    ImmediateFreeze,
    ImmediateFreezeNoResponse,
    FreezeClear,
    FreezeClearNoResponse,
    FreezeAtTime,
    FreezeAtTimeNoResponse,
    ColdRestart,
    WarmRestart,
    InitializeData,
    InitializeApplication,
    StartApplication,
    StopApplication,
    SaveConfiguration,
    EnableUnsolicited,
    DisableUnsolicited,
    AssignClass,
    DelayMeasure,
    RecordCurrentTime,
    OpenFile,
    CloseFile,
    DeleteFile,
    GetFileInfo,
    AuthenticateFile,
    AbortFile,
    AuthRequest,
    AuthRequestNoAck,
    Response,
    UnsolicitedResponse,
    AuthResponse,
    Unknown(u8),
}
impl FunctionCode {
    pub fn from_wire(function: u8) -> Self {
        match function {
            0x00 => Self::Confirm,
            0x01 => Self::Read,
            0x02 => Self::Write,
            0x03 => Self::Select,
            0x04 => Self::Operate,
            0x05 => Self::DirectOperate,
            0x06 => Self::DirectOperateNoResponse,
            0x07 => Self::ImmediateFreeze,
            0x08 => Self::ImmediateFreezeNoResponse,
            0x09 => Self::FreezeClear,
            0x0a => Self::FreezeClearNoResponse,
            0x0b => Self::FreezeAtTime,
            0x0c => Self::FreezeAtTimeNoResponse,
            0x0d => Self::ColdRestart,
            0x0e => Self::WarmRestart,
            0x0f => Self::InitializeData,
            0x10 => Self::InitializeApplication,
            0x11 => Self::StartApplication,
            0x12 => Self::StopApplication,
            0x13 => Self::SaveConfiguration,
            0x14 => Self::EnableUnsolicited,
            0x15 => Self::DisableUnsolicited,
            0x16 => Self::AssignClass,
            0x17 => Self::DelayMeasure,
            0x18 => Self::RecordCurrentTime,
            0x19 => Self::OpenFile,
            0x1a => Self::CloseFile,
            0x1b => Self::DeleteFile,
            0x1c => Self::GetFileInfo,
            0x1d => Self::AuthenticateFile,
            0x1e => Self::AbortFile,
            0x20 => Self::AuthRequest,
            0x21 => Self::AuthRequestNoAck,
            0x81 => Self::Response,
            0x82 => Self::UnsolicitedResponse,
            0x83 => Self::AuthResponse,
            other => Self::Unknown(other),
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Confirm => "confirm",
            Self::Read => "read",
            Self::Write => "write",
            Self::Select => "select",
            Self::Operate => "operate",
            Self::DirectOperate => "direct_operate",
            Self::DirectOperateNoResponse => "direct_operate_no_response",
            Self::ImmediateFreeze => "immediate_freeze",
            Self::ImmediateFreezeNoResponse => "immediate_freeze_no_response",
            Self::FreezeClear => "freeze_clear",
            Self::FreezeClearNoResponse => "freeze_clear_no_response",
            Self::FreezeAtTime => "freeze_at_time",
            Self::FreezeAtTimeNoResponse => "freeze_at_time_no_response",
            Self::ColdRestart => "cold_restart",
            Self::WarmRestart => "warm_restart",
            Self::InitializeData => "initialize_data",
            Self::InitializeApplication => "initialize_application",
            Self::StartApplication => "start_application",
            Self::StopApplication => "stop_application",
            Self::SaveConfiguration => "save_configuration",
            Self::EnableUnsolicited => "enable_unsolicited",
            Self::DisableUnsolicited => "disable_unsolicited",
            Self::AssignClass => "assign_class",
            Self::DelayMeasure => "delay_measure",
            Self::RecordCurrentTime => "record_current_time",
            Self::OpenFile => "open_file",
            Self::CloseFile => "close_file",
            Self::DeleteFile => "delete_file",
            Self::GetFileInfo => "get_file_info",
            Self::AuthenticateFile => "authenticate_file",
            Self::AbortFile => "abort_file",
            Self::AuthRequest => "auth_request",
            Self::AuthRequestNoAck => "auth_request_no_ack",
            Self::Response => "response",
            Self::UnsolicitedResponse => "unsolicited_response",
            Self::AuthResponse => "auth_response",
            Self::Unknown(_) => "unknown",
        }
    }
}
pub fn function_code(function: u8) -> FunctionCode {
    FunctionCode::from_wire(function)
}
impl MessageClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Request => "request",
            Self::Response => "response",
            Self::Unsolicited => "unsolicited",
            Self::Confirm => "confirm",
            Self::Unknown => "unknown",
        }
    }
}
#[derive(Clone, Debug)]
pub struct ApplicationFragment {
    pub source: u16,
    pub destination: u16,
    pub control: u8,
    pub function: u8,
    pub sequence: u8,
    pub class: MessageClass,
    pub iin: Option<u16>,
    pub first: bool,
    pub final_fragment: bool,
    pub confirmation_requested: bool,
    pub frames: Vec<usize>,
    pub raw: EvidenceBytes,
    pub objects: EvidenceBytes,
}
#[derive(Clone, Debug)]
pub struct ApplicationMessage {
    pub source: u16,
    pub destination: u16,
    pub function: u8,
    pub first_sequence: u8,
    pub class: MessageClass,
    pub complete: bool,
    pub fragments: Vec<usize>,
    pub packets: Vec<PacketId>,
    pub objects: EvidenceBytes,
}
/// A failed link boundary retained exactly as captured. A validated header can
/// provide a declared length even when the payload is truncated or has bad CRC.
#[derive(Clone, Debug)]
pub struct RejectedLinkRange {
    pub stream_offset: i64,
    pub declared_length: Option<usize>,
    pub code: &'static str,
    pub incomplete: bool,
    pub raw: EvidenceBytes,
}
#[derive(Clone, Debug, Default)]
pub struct Dnp3Result {
    pub frames: Vec<LinkFrame>,
    pub fragments: Vec<ApplicationFragment>,
    pub messages: Vec<ApplicationMessage>,
    pub issues: Vec<ProtocolIssue>,
    pub rejected_link_ranges: Vec<RejectedLinkRange>,
}

pub fn crc16_dnp(data: &[u8]) -> u16 {
    let mut crc = 0u16;
    for byte in data {
        crc ^= u16::from(*byte);
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xa6bc
            } else {
                crc >> 1
            };
        }
    }
    !crc
}
fn le16(b: &[u8]) -> u16 {
    u16::from_le_bytes([b[0], b[1]])
}

pub fn parse_link(
    bytes: &EvidenceBytes,
    offset: usize,
    stream_base: i64,
) -> Result<(LinkFrame, usize)> {
    let stream_offset = stream_base
        .checked_add(i64::try_from(offset).map_err(|_| Error::limit("stream_offset"))?)
        .ok_or_else(|| Error::limit("stream_offset"))?;

    let input = bytes
        .data()
        .get(offset..)
        .ok_or_else(|| Error::new(ErrorCode::Truncated, 0, "dnp3", "offset beyond input"))?;
    if input.len() < 10 {
        return Err(Error::new(
            ErrorCode::Truncated,
            0,
            "dnp3_header",
            "need 10 octets",
        ));
    }
    if input[..2] != [0x05, 0x64] {
        return Err(Error::new(
            ErrorCode::ProtocolFraming,
            0,
            "dnp3_magic",
            "not a DNP3 link frame",
        ));
    }
    if input[2] < 5 {
        return Err(Error::new(
            ErrorCode::InvalidLength,
            0,
            "dnp3_length",
            "length must include five fixed link octets",
        ));
    }
    if crc16_dnp(&input[..8]) != le16(&input[8..10]) {
        return Err(Error::new(
            ErrorCode::Checksum,
            0,
            "dnp3_header_crc",
            "header CRC mismatch",
        ));
    }
    let data_len = usize::from(input[2]) - 5;
    let total = 10 + data_len + 2 * data_len.div_ceil(16);
    if input.len() < total {
        return Err(Error::new(
            ErrorCode::Truncated,
            0,
            "dnp3_frame",
            "frame extends beyond contiguous captured bytes",
        ));
    }
    let mut user_data = EvidenceBytes::default();
    let mut p = 10;
    let mut remaining = data_len;
    while remaining > 0 {
        let n = remaining.min(16);
        if crc16_dnp(&input[p..p + n]) != le16(&input[p + n..p + n + 2]) {
            return Err(Error::new(
                ErrorCode::Checksum,
                0,
                "dnp3_data_crc",
                "data block CRC mismatch",
            ));
        }
        user_data.append(&bytes.slice(offset + p..offset + p + n)?, 250)?;
        p += n + 2;
        remaining -= n;
    }
    Ok((
        LinkFrame {
            stream_offset,
            control: input[3],
            link_control: link_control(input[3]),
            source: le16(&input[6..8]),
            destination: le16(&input[4..6]),
            broadcast: crate::semantics::dnp3_workflow::is_broadcast(le16(&input[4..6])),
            user_data,
            raw: bytes.slice(offset..offset + total)?,
        },
        total,
    ))
}

struct TransportAssembly {
    last_sequence: u8,
    seen_segments: BTreeMap<u8, Vec<u8>>,
    direction: bool,
    bytes: EvidenceBytes,
    frames: Vec<usize>,
}
struct AppAssembly {
    direction: bool,
    source: u16,
    destination: u16,
    function: u8,
    first_sequence: u8,
    last_sequence: u8,
    class: MessageClass,
    fragments: Vec<usize>,
    objects: EvidenceBytes,
    packets: Vec<PacketId>,
}

fn issue(
    out: &mut Dnp3Result,
    code: &'static str,
    packets: Vec<PacketId>,
    at: i64,
    limits: &Limits,
) -> Result<()> {
    if out.issues.len() >= limits.max_protocol_messages {
        return Err(Error::limit("dnp3_issues"));
    }
    out.issues.push(ProtocolIssue {
        code,
        packets,
        stream_offset: at,
    });
    Ok(())
}
fn emit_app(out: &mut Dnp3Result, app: AppAssembly, complete: bool, limits: &Limits) -> Result<()> {
    if out.messages.len() >= limits.max_protocol_messages {
        return Err(Error::limit("dnp3_messages"));
    }
    let mut packets = app.packets;
    packets.sort();
    packets.dedup();
    out.messages.push(ApplicationMessage {
        source: app.source,
        destination: app.destination,
        function: app.function,
        first_sequence: app.first_sequence,
        class: app.class,
        complete,
        fragments: app.fragments,
        packets,
        objects: app.objects,
    });
    Ok(())
}
fn app_fragment(
    bytes: EvidenceBytes,
    source: u16,
    destination: u16,
    frames: Vec<usize>,
) -> Result<ApplicationFragment> {
    let raw = bytes.data();
    if raw.len() < 2 {
        return Err(Error::new(
            ErrorCode::Truncated,
            0,
            "dnp3_application",
            "missing application control/function",
        ));
    }
    let control = raw[0];
    let function = raw[1];
    let unsolicited = control & 0x10 != 0;
    let class = match function {
        0 => MessageClass::Confirm,
        1..=31 if !unsolicited => MessageClass::Request,
        0x81 if !unsolicited => MessageClass::Response,
        0x82 if unsolicited => MessageClass::Unsolicited,
        _ => MessageClass::Unknown,
    };
    let response = [0x81, 0x82].contains(&function);
    let header = if response { 4 } else { 2 };
    if raw.len() < header {
        return Err(Error::new(
            ErrorCode::Truncated,
            0,
            "dnp3_iin",
            "response is missing IIN",
        ));
    }
    let iin = if response {
        Some(le16(&raw[2..4]))
    } else {
        None
    };
    let objects = bytes.slice(header..bytes.len())?;
    Ok(ApplicationFragment {
        source,
        destination,
        control,
        function,
        sequence: control & 15,
        class,
        iin,
        first: control & 0x80 != 0,
        final_fragment: control & 0x40 != 0,
        confirmation_requested: control & 0x20 != 0,
        frames,
        raw: bytes,
        objects,
    })
}

// A discontinuity in one addressed transport cannot authorize joining older
// application fragments to later ones. Other address pairs remain independent.
fn interrupt_applications(
    out: &mut Dnp3Result,
    applications: &mut BTreeMap<(u16, u16, MessageClass), AppAssembly>,
    key: (u16, u16),
    limits: &Limits,
) -> Result<()> {
    for class in [
        MessageClass::Request,
        MessageClass::Response,
        MessageClass::Unsolicited,
        MessageClass::Confirm,
        MessageClass::Unknown,
    ] {
        let key = (key.0, key.1, class);
        if let Some(pending) = applications.remove(&key) {
            emit_app(out, pending, false, limits)?;
        }
    }
    Ok(())
}

pub fn decode(stream: &StreamResult, limits: &Limits) -> Result<Dnp3Result> {
    limits.validate()?;
    let mut out = Dnp3Result::default();
    let mut rejected_bytes = 0usize;
    for chunk in &stream.chunks {
        let extent = i64::try_from(chunk.bytes.len()).map_err(|_| Error::limit("stream_offset"))?;
        chunk
            .offset
            .checked_add(extent)
            .ok_or_else(|| Error::limit("stream_offset"))?;
        if !chunk.bytes.validate() {
            return Err(Error::new(
                ErrorCode::Invariant,
                0,
                "provenance",
                "invalid DNP3 source spans",
            ));
        }

        let mut transport: BTreeMap<(u16, u16), TransportAssembly> = BTreeMap::new();
        let mut applications: BTreeMap<(u16, u16, MessageClass), AppAssembly> = BTreeMap::new();
        let mut p = 0;
        let mut skipped = 0usize;
        while p < chunk.bytes.len() {
            if chunk.bytes.data().get(p..p + 2) != Some(&[0x05, 0x64][..]) {
                skipped += 1;
                p += 1;
                continue;
            }
            let parsed = parse_link(&chunk.bytes, p, chunk.offset);
            let (frame, used) = match parsed {
                Ok(x) => x,
                Err(e) => {
                    // A CRC/framing failure invalidates pending transport state.
                    // Otherwise a later sequence could bridge bytes we did not trust.
                    for (_, partial) in std::mem::take(&mut transport) {
                        issue(
                            &mut out,
                            "transport_interrupted_by_bad_frame",
                            partial.bytes.packets(),
                            chunk.offset + p as i64,
                            limits,
                        )?;
                    }
                    for (_, pending) in std::mem::take(&mut applications) {
                        emit_app(&mut out, pending, false, limits)?;
                    }
                    issue(
                        &mut out,
                        if e.code == ErrorCode::Checksum {
                            "dnp3_crc_failure"
                        } else {
                            "dnp3_invalid_or_truncated_frame"
                        },
                        chunk
                            .bytes
                            .slice(p..(p + 10).min(chunk.bytes.len()))?
                            .packets(),
                        chunk.offset + p as i64,
                        limits,
                    )?;
                    let tail = &chunk.bytes.data()[p..];
                    let declared_length = if tail.len() >= 10
                        && tail[2] >= 5
                        && crc16_dnp(&tail[..8]) == le16(&tail[8..10])
                    {
                        let n = usize::from(tail[2] - 5);
                        Some(10 + n + 2 * n.div_ceil(16))
                    } else {
                        None
                    };
                    let captured_length = declared_length.unwrap_or(tail.len()).min(tail.len());
                    rejected_bytes = rejected_bytes
                        .checked_add(captured_length)
                        .filter(|n| *n <= limits.max_application_bytes)
                        .ok_or_else(|| Error::limit("dnp3_rejected_link_bytes"))?;
                    if out.rejected_link_ranges.len() >= limits.max_protocol_messages {
                        return Err(Error::limit("dnp3_rejected_link_ranges"));
                    }
                    out.rejected_link_ranges.push(RejectedLinkRange {
                        stream_offset: chunk.offset + p as i64,
                        declared_length,
                        code: e.field,
                        incomplete: e.code == ErrorCode::Truncated,
                        raw: chunk.bytes.slice(p..p + captured_length)?,
                    });
                    if tail.len() >= 10
                        && tail[2] >= 5
                        && crc16_dnp(&tail[..8]) == le16(&tail[8..10])
                    {
                        let data_len = usize::from(tail[2] - 5);
                        let declared = 10 + data_len + 2 * data_len.div_ceil(16);
                        // Never scan a corrupt frame body for a nested magic.
                        // A short declared frame consumes the rest of this chunk.
                        let rejected = declared.min(tail.len());
                        issue(
                            &mut out,
                            "dnp3_rejected_declared_link_range",
                            chunk.bytes.slice(p..p + rejected)?.packets(),
                            chunk.offset + p as i64,
                            limits,
                        )?;
                        p += rejected;
                        skipped = 0;
                    } else {
                        // At a recognized but invalid boundary its end is unknown.
                        // Do not silently resynchronize within this stream chunk.
                        issue(
                            &mut out,
                            "dnp3_link_boundary_lost_no_resynchronization",
                            chunk.bytes.slice(p..chunk.bytes.len())?.packets(),
                            chunk.offset + p as i64,
                            limits,
                        )?;
                        break;
                    }
                    continue;
                }
            };
            if skipped > 0 {
                for (_, partial) in std::mem::take(&mut transport) {
                    issue(
                        &mut out,
                        "transport_interrupted_by_resynchronization",
                        partial.bytes.packets(),
                        chunk.offset + p as i64,
                        limits,
                    )?;
                }
                for (_, pending) in std::mem::take(&mut applications) {
                    emit_app(&mut out, pending, false, limits)?;
                }
                issue(
                    &mut out,
                    "dnp3_link_resynchronized",
                    chunk.bytes.slice(p - skipped..p)?.packets(),
                    chunk.offset + (p - skipped) as i64,
                    limits,
                )?;
                skipped = 0;
            }
            p += used;
            if out.frames.len() >= limits.max_protocol_messages {
                return Err(Error::limit("dnp3_frames"));
            }
            let key = (frame.source, frame.destination);
            let at = frame.stream_offset;
            let frame_id = out.frames.len();
            let data = frame.user_data.clone();
            let primary_user_data =
                frame.link_control.primary && [3, 4].contains(&frame.link_control.function);
            if frame.link_control.reserved == Some(true) {
                issue(
                    &mut out,
                    "dnp3_reserved_link_control_bit",
                    frame.raw.packets(),
                    at,
                    limits,
                )?;
            }
            if matches!(
                frame.link_control.function_name,
                "primary_unknown" | "secondary_unknown"
            ) {
                issue(
                    &mut out,
                    "unsupported_dnp3_link_function",
                    frame.raw.packets(),
                    at,
                    limits,
                )?;
            }
            let link_issue = crate::semantics::dnp3_workflow::link_issue(
                frame.control,
                frame.source,
                frame.destination,
                data.len(),
            );
            let link_packets = frame.raw.packets();
            out.frames.push(frame);
            if let Some((_, code)) = link_issue {
                issue(&mut out, code, link_packets, at, limits)?;
                transport.remove(&key);
                interrupt_applications(&mut out, &mut applications, key, limits)?;
                continue;
            }
            if data.is_empty() {
                continue;
            }
            if !primary_user_data {
                issue(
                    &mut out,
                    "unsupported_dnp3_link_function_with_data",
                    data.packets(),
                    at,
                    limits,
                )?;
                transport.remove(&key);
                interrupt_applications(&mut out, &mut applications, key, limits)?;
                continue;
            }
            let direction = out.frames[frame_id].link_control.direction;
            let direction_changed = transport
                .get(&key)
                .is_some_and(|p| p.direction != direction)
                || [
                    MessageClass::Request,
                    MessageClass::Response,
                    MessageClass::Unsolicited,
                    MessageClass::Confirm,
                    MessageClass::Unknown,
                ]
                .iter()
                .any(|class| {
                    applications
                        .get(&(key.0, key.1, *class))
                        .is_some_and(|p| p.direction != direction)
                });
            if direction_changed {
                issue(
                    &mut out,
                    "dnp3_link_direction_changed_within_assembly",
                    data.packets(),
                    at,
                    limits,
                )?;
                transport.remove(&key);
                interrupt_applications(&mut out, &mut applications, key, limits)?;
            }
            let header = data.data()[0];
            let seq = header & 63;
            let first = header & 0x40 != 0;
            let last = header & 0x80 != 0;
            if let Some(previous) = transport.get_mut(&key) {
                if seq != ((previous.last_sequence + 1) & 63)
                    && previous
                        .seen_segments
                        .get(&seq)
                        .is_some_and(|b| b.as_slice() == data.data())
                {
                    if previous.frames.len() >= limits.max_protocol_messages {
                        return Err(Error::limit("dnp3_transport_frames"));
                    }
                    previous.frames.push(frame_id);
                    issue(
                        &mut out,
                        if previous.last_sequence == seq {
                            "duplicate_dnp3_transport_segment"
                        } else {
                            "reordered_duplicate_dnp3_transport_segment"
                        },
                        data.packets(),
                        at,
                        limits,
                    )?;
                    continue;
                }
            }
            let conflicting = !first
                && transport.get(&key).is_some_and(|p| {
                    seq != ((p.last_sequence + 1) & 63) && p.seen_segments.contains_key(&seq)
                });
            if conflicting {
                let old = transport
                    .remove(&key)
                    .ok_or_else(|| Error::limit("dnp3_state"))?;
                let mut packets = old.bytes.packets();
                packets.extend(data.packets());
                packets.sort();
                packets.dedup();
                issue(
                    &mut out,
                    "conflicting_dnp3_transport_duplicate",
                    packets,
                    at,
                    limits,
                )?;
                interrupt_applications(&mut out, &mut applications, key, limits)?;
                continue;
            }
            if first {
                if let Some(old) = transport.remove(&key) {
                    issue(
                        &mut out,
                        "dnp3_transport_restart_before_fin",
                        old.bytes.packets(),
                        at,
                        limits,
                    )?;
                    interrupt_applications(&mut out, &mut applications, key, limits)?;
                }

                if data.len() - 1 > limits.max_application_bytes {
                    return Err(Error::limit("dnp3_application_bytes"));
                }
                transport.insert(
                    key,
                    TransportAssembly {
                        last_sequence: seq,
                        seen_segments: BTreeMap::from([(seq, data.data().to_vec())]),
                        direction,
                        bytes: data.slice(1..data.len())?,
                        frames: vec![frame_id],
                    },
                );
            } else {
                match transport.get_mut(&key) {
                    None => {
                        issue(
                            &mut out,
                            "orphan_dnp3_transport_segment",
                            data.packets(),
                            at,
                            limits,
                        )?;
                        interrupt_applications(&mut out, &mut applications, key, limits)?;

                        continue;
                    }
                    Some(assembly) if seq != ((assembly.last_sequence + 1) & 63) => {
                        let old = transport
                            .remove(&key)
                            .ok_or_else(|| Error::limit("dnp3_state"))?;
                        let mut ids = old.bytes.packets();
                        ids.extend(data.packets());
                        ids.sort();
                        ids.dedup();
                        issue(
                            &mut out,
                            "dnp3_transport_sequence_gap_or_conflict",
                            ids,
                            at,
                            limits,
                        )?;
                        interrupt_applications(&mut out, &mut applications, key, limits)?;

                        continue;
                    }
                    Some(assembly) => {
                        assembly
                            .bytes
                            .append(&data.slice(1..data.len())?, limits.max_application_bytes)?;
                        assembly.last_sequence = seq;
                        assembly.seen_segments.insert(seq, data.data().to_vec());
                        if assembly.frames.len() >= limits.max_protocol_messages {
                            return Err(Error::limit("dnp3_transport_frames"));
                        }
                        assembly.frames.push(frame_id);
                    }
                }
            }
            if !last {
                continue;
            }
            let complete = transport
                .remove(&key)
                .ok_or_else(|| Error::limit("dnp3_state"))?;
            let frag = match app_fragment(complete.bytes.clone(), key.0, key.1, complete.frames) {
                Ok(frag) => frag,
                Err(_) => {
                    issue(
                        &mut out,
                        "invalid_dnp3_application_header",
                        complete.bytes.packets(),
                        at,
                        limits,
                    )?;
                    interrupt_applications(&mut out, &mut applications, key, limits)?;

                    continue;
                }
            };
            if out.fragments.len() >= limits.max_protocol_messages {
                return Err(Error::limit("dnp3_fragments"));
            }
            let frag_id = out.fragments.len();
            let app_key = (frag.source, frag.destination, frag.class);
            let mut packets = Vec::new();
            for i in &frag.frames {
                packets.extend(out.frames[*i].raw.packets());
            }
            packets.sort();
            packets.dedup();
            if frag.class == MessageClass::Unknown {
                issue(
                    &mut out,
                    "unsupported_or_inconsistent_dnp3_application_function",
                    packets.clone(),
                    at,
                    limits,
                )?;
            }
            let mut completion = None;
            if frag.first {
                if let Some(old) = applications.remove(&app_key) {
                    emit_app(&mut out, old, false, limits)?;
                }
                applications.insert(
                    app_key,
                    AppAssembly {
                        direction,
                        source: frag.source,
                        destination: frag.destination,
                        function: frag.function,
                        first_sequence: frag.sequence,
                        last_sequence: frag.sequence,
                        class: frag.class,
                        fragments: vec![frag_id],
                        objects: frag.objects.clone(),
                        packets: packets.clone(),
                    },
                );
            } else if let Some(previous) = applications.get_mut(&app_key) {
                if frag.sequence == ((previous.last_sequence + 1) & 15)
                    && frag.function == previous.function
                {
                    previous.last_sequence = frag.sequence;
                    previous.fragments.push(frag_id);
                    previous.packets.extend(packets.clone());
                    previous
                        .objects
                        .append(&frag.objects, limits.max_application_bytes)?;
                } else {
                    completion = applications.remove(&app_key);
                    issue(
                        &mut out,
                        "dnp3_application_sequence_gap_or_conflict",
                        packets.clone(),
                        at,
                        limits,
                    )?;
                }
            } else {
                issue(
                    &mut out,
                    "orphan_dnp3_application_fragment",
                    packets.clone(),
                    at,
                    limits,
                )?;
            }
            if let Some(old) = completion {
                emit_app(&mut out, old, false, limits)?;
            }
            let final_fragment = frag.final_fragment;
            out.fragments.push(frag);
            if final_fragment {
                if let Some(done) = applications.remove(&app_key) {
                    emit_app(&mut out, done, true, limits)?;
                }
            }
        }
        if skipped > 0 {
            issue(
                &mut out,
                "trailing_unframed_dnp3_bytes",
                chunk.bytes.slice(p - skipped..p)?.packets(),
                chunk.offset + (p - skipped) as i64,
                limits,
            )?;
        }
        for (_, pending) in transport {
            issue(
                &mut out,
                "incomplete_dnp3_transport_at_gap_or_eof",
                pending.bytes.packets(),
                chunk.offset + chunk.bytes.len() as i64,
                limits,
            )?;
        }
        for (_, pending) in applications {
            emit_app(&mut out, pending, false, limits)?;
        }
    }
    Ok(out)
}
