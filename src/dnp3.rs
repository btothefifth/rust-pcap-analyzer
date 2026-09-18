//! Passive DNP3 framing and transport/application fragment reconstruction.
//! Object payloads remain opaque; this is not an IEEE-1815 endpoint stack.
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
#[derive(Clone, Debug)]
pub struct LinkFrame {
    pub stream_offset: i64,
    pub control: u8,
    pub source: u16,
    pub destination: u16,
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
#[derive(Clone, Debug, Default)]
pub struct Dnp3Result {
    pub frames: Vec<LinkFrame>,
    pub fragments: Vec<ApplicationFragment>,
    pub messages: Vec<ApplicationMessage>,
    pub issues: Vec<ProtocolIssue>,
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
            source: le16(&input[6..8]),
            destination: le16(&input[4..6]),
            user_data,
            raw: bytes.slice(offset..offset + total)?,
        },
        total,
    ))
}

struct TransportAssembly {
    last_sequence: u8,
    last_segment: Vec<u8>,
    bytes: EvidenceBytes,
    frames: Vec<usize>,
}
struct AppAssembly {
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
    let keys: Vec<_> = applications
        .keys()
        .filter(|k| k.0 == key.0 && k.1 == key.1)
        .copied()
        .collect();
    for key in keys {
        if let Some(pending) = applications.remove(&key) {
            emit_app(out, pending, false, limits)?;
        }
    }
    Ok(())
}

pub fn decode(stream: &StreamResult, limits: &Limits) -> Result<Dnp3Result> {
    limits.validate()?;
    let mut out = Dnp3Result::default();
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
                    p += 1;
                    skipped += 1;
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
                frame.control & 0x40 != 0 && [3, 4].contains(&(frame.control & 0x0f));
            out.frames.push(frame);
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
            let header = data.data()[0];
            let seq = header & 63;
            let first = header & 0x40 != 0;
            let last = header & 0x80 != 0;
            if let Some(previous) = transport.get_mut(&key) {
                if previous.last_sequence == seq && previous.last_segment == data.data() {
                    if previous.frames.len() >= limits.max_protocol_messages {
                        return Err(Error::limit("dnp3_transport_frames"));
                    }
                    previous.frames.push(frame_id);
                    issue(
                        &mut out,
                        "duplicate_dnp3_transport_segment",
                        data.packets(),
                        at,
                        limits,
                    )?;
                    continue;
                }
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
                        last_segment: data.data().to_vec(),
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
                        assembly.last_segment = data.data().to_vec();
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
