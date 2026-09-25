//! Byte-derived, non-secure DNP3 workflow observations. No endpoint state machine.
//!
//! A workflow observation says what the captured header/selectors encode, not
//! that an outstation received, accepted, executed, or confirmed an operation.
//! Object parsing is delegated to the reviewed root decoder, including its
//! stop-at-unknown-layout rule. Incomplete application fragments are not decoded
//! as standalone object regions by this API.
use super::{fail, need, uint, Field, Limits, Record, Report, Status, Value};
use crate::dnp3::{link_control, parse_link};
use crate::provenance::EvidenceBytes;
use crate::{ErrorCode, Result};

/// Address encoding only. Multiple addresses do not establish physical topology.
pub fn address_kind(address: u16) -> &'static str {
    match address {
        0..=0xffef => "individual",
        0xfff0..=0xfffb => "reserved",
        0xfffc => "self_address",
        _ => "broadcast",
    }
}

pub fn is_broadcast(address: u16) -> bool {
    address >= 0xfffd
}

/// The address's encoded application-confirm policy, not observed confirmation.
pub fn broadcast_confirm_policy(address: u16) -> Option<&'static str> {
    match address {
        0xfffd => Some("not_required"),
        0xfffe => Some("required"),
        0xffff => Some("optional"),
        _ => None,
    }
}

/// Validation of the declared link subset, after framing/CRC validation. The
/// legacy/reserved function space is unsupported rather than guessed. FCB when
/// FCV=0 is retained but is NOT used for duplicate or endpoint-state inference.
pub fn link_issue(
    control: u8,
    source: u16,
    destination: u16,
    user_length: usize,
) -> Option<(ErrorCode, &'static str)> {
    let c = link_control(control);
    if !c.primary && c.reserved == Some(true) {
        return Some((
            ErrorCode::ProtocolFraming,
            "dnp3_secondary_reserved_control_bit",
        ));
    }
    let supported = if c.primary {
        matches!(c.function, 0 | 2 | 3 | 4 | 9)
    } else {
        matches!(c.function, 0 | 1 | 11 | 15)
    };
    if !supported {
        return Some((
            ErrorCode::UnsupportedTransport,
            "dnp3_link_function_outside_subset",
        ));
    }
    if c.primary && c.fcv != Some(matches!(c.function, 2 | 3)) {
        return Some((
            ErrorCode::ProtocolFraming,
            "dnp3_link_fcv_function_conflict",
        ));
    }
    if address_kind(source) != "individual" {
        return Some((
            ErrorCode::ProtocolFraming,
            "dnp3_non_individual_source_address",
        ));
    }
    match address_kind(destination) {
        "reserved" => {
            return Some((
                ErrorCode::ProtocolFraming,
                "dnp3_reserved_destination_address",
            ));
        }
        "self_address" => {
            return Some((
                ErrorCode::UnsupportedTransport,
                "dnp3_self_address_not_resolved",
            ));
        }
        _ => {}
    }
    let user_function = c.primary && matches!(c.function, 3 | 4);
    if is_broadcast(destination) && (!c.direction || !user_function) {
        return Some((
            ErrorCode::ProtocolFraming,
            "dnp3_broadcast_direction_or_function_conflict",
        ));
    }
    if user_function == (user_length == 0) {
        return Some((
            ErrorCode::ProtocolFraming,
            "dnp3_link_function_length_conflict",
        ));
    }
    None
}

/// Source-bound link fields. All field offsets address the original link frame,
/// including its CRC bytes; user-data stripping never changes these offsets.
pub fn link(raw: &EvidenceBytes, limits: Limits) -> Result<Report<'_>> {
    let mut out = Report::new(raw, "dnp3", "link_workflow", limits)?;
    let result = (|| -> Result<()> {
        let (frame, used) = parse_link(raw, 0, 0)?;
        if used != raw.len() {
            return Err(fail(
                ErrorCode::ProtocolFraming,
                used,
                "dnp3_link_trailing_bytes",
            ));
        }
        let c = frame.link_control;
        let mut fields = vec![
            Field::new("raw_control", Value::Unsigned(frame.control.into()), 3..4),
            Field::bit_field("direction_bit", c.direction, 3, 7),
            Field::bit_field("primary", c.primary, 3, 6),
            Field::derived(
                "function",
                c.function.into(),
                3..4,
                "low_four_link_control_bits",
            ),
            Field::new("source", Value::Unsigned(frame.source.into()), 6..8),
            Field::new(
                "destination",
                Value::Unsigned(frame.destination.into()),
                4..6,
            ),
            Field::derived(
                "broadcast_address",
                u64::from(is_broadcast(frame.destination)),
                4..6,
                "encoded_address_not_physical_topology",
            ),
        ];
        if c.primary {
            fields.push(Field::bit_field("fcb", frame.control & 0x20 != 0, 3, 5));
            fields.push(Field::bit_field("fcv", frame.control & 0x10 != 0, 3, 4));
        } else {
            fields.push(Field::bit_field(
                "reserved",
                frame.control & 0x20 != 0,
                3,
                5,
            ));
            fields.push(Field::bit_field("dfc", frame.control & 0x10 != 0, 3, 4));
        }
        for field in &mut fields {
            if field.bit.is_some() {
                field.basis = "dnp3_link_control_bit_lsb_zero";
            }
        }
        out.add(Record::new(
            if c.primary {
                "primary_link_control"
            } else {
                "secondary_link_control"
            },
            3..8,
            fields,
        ))?;
        if let Some((code, field)) = link_issue(
            frame.control,
            frame.source,
            frame.destination,
            frame.user_data.len(),
        ) {
            return Err(fail(code, 3, field));
        }
        out.advance(raw.len());
        Ok(())
    })();
    if let Err(e) = result {
        let at = usize::try_from(e.offset).unwrap_or(0).min(raw.len());
        out.stop(e, at);
    }
    Ok(out)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Header {
    pub control: u8,
    pub function: u8,
    pub length: usize,
}
impl Header {
    pub fn sequence(self) -> u8 {
        self.control & 15
    }
    pub fn first(self) -> bool {
        self.control & 0x80 != 0
    }
    pub fn final_fragment(self) -> bool {
        self.control & 0x40 != 0
    }
    pub fn confirm_requested(self) -> bool {
        self.control & 0x20 != 0
    }
    pub fn unsolicited(self) -> bool {
        self.control & 0x10 != 0
    }
}

/// Byte-derived header validation, without requiring a whole application message.
/// This is also used for correlation: UNS is a separate sequence namespace.
pub fn header(raw: &EvidenceBytes) -> Result<Header> {
    if !raw.validate() {
        return Err(fail(ErrorCode::Invariant, 0, "dnp3_workflow_provenance"));
    }
    let b = raw.data();
    need(b, 0, 2, "dnp3_workflow_header_truncated")?;
    let h = Header {
        control: b[0],
        function: b[1],
        length: if matches!(b[1], 0x81..=0x83) { 4 } else { 2 },
    };
    need(b, 0, h.length, "dnp3_workflow_iin_truncated")?;
    if matches!(h.function, 0x20 | 0x21 | 0x83 | 0x1d) {
        return Err(fail(
            ErrorCode::UnsupportedTransport,
            1,
            "dnp3_authentication_workflow_opaque",
        ));
    }
    if !matches!(h.function, 0..=0x1e | 0x81 | 0x82) {
        return Err(fail(
            ErrorCode::UnsupportedTransport,
            1,
            "dnp3_reserved_application_function",
        ));
    }
    if (h.function == 0x82 && !h.unsolicited())
        || (h.function != 0 && h.function != 0x82 && h.unsolicited())
        || (h.function < 0x80 && h.confirm_requested())
    {
        return Err(fail(
            ErrorCode::ProtocolFraming,
            0,
            "dnp3_application_control_function_conflict",
        ));
    }
    if matches!(h.function, 0 | 23 | 24) && (b.len() != 2 || !h.first() || !h.final_fragment()) {
        return Err(fail(
            ErrorCode::ProtocolFraming,
            0,
            "dnp3_header_only_workflow_shape",
        ));
    }
    Ok(h)
}

fn append_objects(out: &mut Report<'_>, objects: &Report<'_>, offset: usize) -> Result<()> {
    // The original parser owns qualifier/layout interpretation. Only translate
    // validated ranges into the parent APDU, retaining bit and basis metadata.
    for record in objects.records() {
        let mut fields = record.fields.clone();
        for field in &mut fields {
            field.range = field.range.start + offset..field.range.end + offset;
        }
        out.add(Record::new(
            record.kind,
            record.range.start + offset..record.range.end + offset,
            fields,
        ))?;
        if record.kind == "object_header" {
            let at = record.range.start;
            let b = objects.source().data();
            let (g, v) = (b[at], b[at + 1]);
            let kind = if g == 60 && (1..=4).contains(&v) {
                "class_selector"
            } else if matches!(g, 2 | 4 | 11 | 13 | 22 | 23 | 32 | 33 | 42 | 43 | 111) {
                "event_object_header"
            } else if matches!(g, 50..=52) {
                "time_object_header"
            } else {
                continue;
            };
            let mut fields = vec![
                Field::new(
                    "group",
                    Value::Unsigned(g.into()),
                    at + offset..at + offset + 1,
                ),
                Field::new(
                    "variation",
                    Value::Unsigned(v.into()),
                    at + offset + 1..at + offset + 2,
                ),
            ];
            if kind == "class_selector" {
                fields.push(Field::derived(
                    "class",
                    u64::from(v - 1),
                    at + offset + 1..at + offset + 2,
                    "group_60_variation_selects_class_not_observed_event_count",
                ));
            }
            out.add(Record::new(kind, at + offset..at + offset + 3, fields))?;
        }
    }
    let consumed = offset + objects.consumed();
    if objects.status() != Status::DecodedSubset {
        let code = match objects.status() {
            Status::Incomplete => ErrorCode::Truncated,
            Status::Unsupported => ErrorCode::UnsupportedTransport,
            Status::Limited => ErrorCode::LimitExceeded,
            _ => ErrorCode::ProtocolFraming,
        };
        let field = objects
            .issues()
            .last()
            .map_or("dnp3_object_subset_stopped", |i| i.code);
        out.stop(fail(code, consumed, field), consumed);
    } else {
        out.advance(consumed);
    }
    // Preserve every decoder diagnostic with its original range translated to
    // the APDU. A bounded duplicate terminal note is preferable to losing a
    // preceding warning; warn() makes diagnostic exhaustion explicitly limited.
    for issue in objects.issues() {
        out.warn(
            issue.code,
            issue.range.start + offset..issue.range.end + offset,
        );
    }
    Ok(())
}

/// Decode ONE complete APDU as workflow evidence. Non-final/orphan application
/// fragments explicitly remain incomplete; use the root message assembly for
/// object completion across fragments, never concatenate unverified regions here.
pub fn application(raw: &EvidenceBytes, limits: Limits) -> Result<Report<'_>> {
    let mut out = Report::new(raw, "dnp3", "application_workflow", limits.clone())?;
    let result = (|| -> Result<()> {
        let h = header(raw)?;
        let mut fields = vec![
            Field::new("raw_control", Value::Unsigned(h.control.into()), 0..1),
            Field::new("function", Value::Unsigned(h.function.into()), 1..2),
            Field::derived(
                "sequence",
                h.sequence().into(),
                0..1,
                "low_four_application_control_bits",
            ),
            Field::bit_field("first", h.first(), 0, 7),
            Field::bit_field("final", h.final_fragment(), 0, 6),
            Field::bit_field("confirmation_requested", h.confirm_requested(), 0, 5),
            Field::bit_field("unsolicited_namespace", h.unsolicited(), 0, 4),
        ];
        if h.length == 4 {
            fields.push(Field::new(
                "iin",
                Value::Unsigned(uint(raw.data(), 2, 2, true)),
                2..4,
            ));
        }
        for field in &mut fields {
            if field.bit.is_some() {
                field.basis = "dnp3_application_control_bit_lsb_zero";
            }
        }
        out.add(Record::new("application_header", 0..h.length, fields))?;
        if !h.first() || !h.final_fragment() {
            out.stop(
                fail(
                    ErrorCode::Truncated,
                    h.length,
                    "dnp3_workflow_requires_complete_message",
                ),
                h.length,
            );
            return Ok(());
        }
        let (kind, context) = match h.function {
            0 => ("confirm", None),
            1 => ("read_scan", Some(super::dnp3::Context::ReadHeaders)),
            2 => (
                "non_secure_time_write",
                Some(super::dnp3::Context::TimeWriteValues),
            ),
            3..=6 => (
                "control_request_observed",
                Some(super::dnp3::Context::ControlValues),
            ),
            25..=28 | 30 => ("file_control", Some(super::dnp3::Context::FileValues)),
            20 | 21 => (
                if h.function == 20 {
                    "enable_unsolicited_classes"
                } else {
                    "disable_unsolicited_classes"
                },
                Some(super::dnp3::Context::ClassHeaders),
            ),
            23 => ("delay_measure_request", None),
            24 => ("record_current_time_request", None),
            0x81 => (
                "solicited_response",
                Some(super::dnp3::Context::ResponseValues),
            ),
            0x82 => (
                "unsolicited_response",
                Some(super::dnp3::Context::ResponseValues),
            ),
            _ => {
                return Err(fail(
                    ErrorCode::UnsupportedTransport,
                    h.length,
                    "dnp3_workflow_outside_subset",
                ))
            }
        };
        out.add(Record::new(
            kind,
            0..h.length,
            vec![Field::new(
                "function",
                Value::Unsigned(h.function.into()),
                1..2,
            )],
        ))?;
        if let Some(context) = context {
            let objects = raw.slice(h.length..raw.len())?;
            let decoded = super::dnp3::decode(&objects, context, limits)?;
            append_objects(&mut out, &decoded, h.length)?;
        } else {
            out.advance(h.length);
        }
        Ok(())
    })();
    if let Err(e) = result {
        let at = usize::try_from(e.offset).unwrap_or(0).min(raw.len());
        out.stop(e, at);
    }
    Ok(out)
}

fn charge(work: &mut usize, amount: usize, limit: usize) -> Result<()> {
    *work = work
        .checked_add(amount)
        .filter(|n| *n <= limit)
        .ok_or_else(|| crate::Error::limit("dnp3_correlation_work"))?;
    Ok(())
}

/// Re-derive pairing authority from original CRC-checked link frames, not mutable
/// public message metadata. Work is charged across the caller's entire query.
/// This proves only a captured identifier/direction relation, not endpoint state.
pub fn verified_message_direction(
    result: &crate::dnp3::Dnp3Result,
    message: &crate::dnp3::ApplicationMessage,
    limits: &crate::Limits,
    work: &mut usize,
) -> Result<bool> {
    use crate::dnp3::MessageClass;
    use std::collections::BTreeMap;
    let mismatch = || fail(ErrorCode::Invariant, 0, "dnp3_pairing_witness_mismatch");
    if !message.complete || message.fragments.is_empty() {
        return Err(fail(
            ErrorCode::Truncated,
            0,
            "dnp3_pairing_incomplete_message",
        ));
    }
    if address_kind(message.source) != "individual"
        || address_kind(message.destination) != "individual"
    {
        return Err(fail(
            ErrorCode::UnsupportedTransport,
            0,
            "dnp3_pairing_non_individual_address",
        ));
    }
    let direction = match message.class {
        MessageClass::Request | MessageClass::Confirm => true,
        MessageClass::Response | MessageClass::Unsolicited => false,
        MessageClass::Unknown => return Err(mismatch()),
    };
    let mut objects = EvidenceBytes::default();
    let mut packets = Vec::new();
    let mut expected_app_sequence = message.first_sequence;
    for (ordinal, &index) in message.fragments.iter().enumerate() {
        charge(work, 1, limits.max_correlation_checks)?;
        let fragment = result.fragments.get(index).ok_or_else(mismatch)?;
        let h = header(&fragment.raw)?;
        let class = match h.function {
            0 => MessageClass::Confirm,
            1..=30 => MessageClass::Request,
            0x81 => MessageClass::Response,
            0x82 => MessageClass::Unsolicited,
            _ => return Err(mismatch()),
        };
        if fragment.source != message.source
            || fragment.destination != message.destination
            || h.function != message.function
            || class != message.class
            || h.first() != (ordinal == 0)
            || h.final_fragment() != (ordinal + 1 == message.fragments.len())
            || h.sequence() != expected_app_sequence
            || fragment.control != h.control
            || fragment.function != h.function
            || fragment.sequence != h.sequence()
            || fragment.class != class
            || fragment.first != h.first()
            || fragment.final_fragment != h.final_fragment()
            || fragment.confirmation_requested != h.confirm_requested()
            || fragment.iin != (h.length == 4).then(|| uint(fragment.raw.data(), 2, 2, true) as u16)
            || fragment.frames.is_empty()
        {
            return Err(mismatch());
        }
        expected_app_sequence = (h.sequence() + 1) & 15;
        let object_slice = fragment.raw.slice(h.length..fragment.raw.len())?;
        if object_slice != fragment.objects {
            return Err(mismatch());
        }
        let mut transport = EvidenceBytes::default();
        let mut previous = None;
        let mut final_seen = false;
        // At most 64 transport sequence slots. Overwrite only at a contiguous
        // rollover; retained duplicates never supply the assembled byte value.
        let mut seen: BTreeMap<u8, Vec<u8>> = BTreeMap::new();
        for &frame_index in &fragment.frames {
            let frame = result.frames.get(frame_index).ok_or_else(mismatch)?;
            charge(
                work,
                frame.raw.len().saturating_add(frame.raw.spans().len()),
                limits.max_correlation_checks,
            )?;
            let (parsed, used) = parse_link(&frame.raw, 0, frame.stream_offset)?;
            if used != frame.raw.len()
                || frame.control != parsed.control
                || frame.link_control != parsed.link_control
                || frame.source != parsed.source
                || frame.destination != parsed.destination
                || frame.user_data != parsed.user_data
                || frame.broadcast != parsed.broadcast
                || parsed.source != message.source
                || parsed.destination != message.destination
                || parsed.link_control.direction != direction
                || !parsed.link_control.primary
                || !matches!(parsed.link_control.function, 3 | 4)
                || link_issue(
                    parsed.control,
                    parsed.source,
                    parsed.destination,
                    parsed.user_data.len(),
                )
                .is_some()
            {
                return Err(mismatch());
            }
            let b = parsed.user_data.data();
            let seq = b[0] & 63; // nonempty was established by link_issue
            let expected = previous.map(|last: u8| (last + 1) & 63);
            if expected != Some(seq) && seen.get(&seq).is_some_and(|v| v.as_slice() == b) {
                packets.extend(parsed.raw.packets());
                continue;
            }
            if final_seen
                || (previous.is_none() != (b[0] & 64 != 0))
                || previous.is_some() && expected != Some(seq)
            {
                return Err(mismatch());
            }
            transport.append(
                &parsed.user_data.slice(1..b.len())?,
                limits.max_application_bytes,
            )?;
            previous = Some(seq);
            final_seen = b[0] & 128 != 0;
            seen.insert(seq, b.to_vec());
            packets.extend(parsed.raw.packets());
        }
        if !final_seen || transport != fragment.raw {
            return Err(mismatch());
        }
        charge(
            work,
            object_slice
                .len()
                .saturating_add(object_slice.spans().len()),
            limits.max_correlation_checks,
        )?;
        objects.append(&object_slice, limits.max_application_bytes)?;
    }
    packets.sort();
    packets.dedup();
    if objects != message.objects || packets != message.packets {
        return Err(mismatch());
    }
    Ok(direction)
}

/// A CRC-checked link-frame dependency of one verified application fragment.
/// Only headers are copied here; the original frame remains in `Dnp3Result`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FragmentLinkWitness {
    pub frame: usize,
    pub control: u8,
    pub header: EvidenceBytes,
    pub transport_control: u8,
    pub transport_header: EvidenceBytes,
    pub frame_length: usize,
    pub frame_sha256: [u8; 32],
}

/// Re-derived fragment identifiers, not a claim of receipt or device effects.
/// `header_bytes` includes IIN on responses. All ranges are local to each
/// EvidenceBytes value, with exact packet-relative source spans.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FragmentWitness {
    pub source: u16,
    pub destination: u16,
    pub link_direction: bool,
    pub header: Header,
    pub header_bytes: EvidenceBytes,
    pub packets: Vec<crate::provenance::PacketId>,
    pub links: Vec<FragmentLinkWitness>,
}

/// Verify ONE transport-complete application fragment, even when its application
/// message is incomplete or absent. This does not decode object bytes or consult
/// ApplicationMessage metadata. Flow identity and capture direction are supplied
/// by the caller, not derived from ports, timestamps or DNP3 endpoint state.
///
/// Every supplied link frame is reparsed with CRC checking; transport continuity,
/// raw APDU/provenance equality and every derived public fragment/link field must
/// agree. Identical transport duplicates retain witnesses, never another selected
/// byte value. Work is charged before traversal/copying across the caller's query.
/// Unlike verified_message_direction, this returns the observed DIR bit without
/// assuming a role-to-DIR mapping. A confirmation candidate must compare both DIRs.
pub fn verified_fragment_witness(
    result: &crate::dnp3::Dnp3Result,
    fragment: &crate::dnp3::ApplicationFragment,
    limits: &crate::Limits,
    work: &mut usize,
) -> Result<FragmentWitness> {
    use crate::dnp3::MessageClass;
    use std::collections::{BTreeMap, BTreeSet};
    let mismatch = || fail(ErrorCode::Invariant, 0, "dnp3_fragment_witness_mismatch");
    charge(work, 1, limits.max_correlation_checks)?;
    charge(work, fragment.raw.len(), limits.max_correlation_checks)?;
    charge(
        work,
        fragment.raw.spans().len(),
        limits.max_correlation_checks,
    )?;
    charge(work, fragment.objects.len(), limits.max_correlation_checks)?;
    charge(
        work,
        fragment.objects.spans().len(),
        limits.max_correlation_checks,
    )?;
    if fragment.raw.len() > limits.max_application_bytes {
        return Err(crate::Error::limit("dnp3_fragment_witness_bytes"));
    }
    let h = header(&fragment.raw)?;
    let class = match h.function {
        0 => MessageClass::Confirm,
        1..=30 => MessageClass::Request,
        0x81 => MessageClass::Response,
        0x82 => MessageClass::Unsolicited,
        _ => return Err(mismatch()),
    };
    if fragment.control != h.control
        || fragment.function != h.function
        || fragment.sequence != h.sequence()
        || fragment.class != class
        || fragment.first != h.first()
        || fragment.final_fragment != h.final_fragment()
        || fragment.confirmation_requested != h.confirm_requested()
        || fragment.iin != (h.length == 4).then(|| uint(fragment.raw.data(), 2, 2, true) as u16)
        || fragment.objects != fragment.raw.slice(h.length..fragment.raw.len())?
        || fragment.frames.is_empty()
    {
        return Err(mismatch());
    }
    if address_kind(fragment.source) != "individual"
        || address_kind(fragment.destination) != "individual"
    {
        return Err(fail(
            ErrorCode::UnsupportedTransport,
            0,
            "dnp3_confirmation_non_individual_address",
        ));
    }
    let capture = fragment
        .raw
        .spans()
        .first()
        .ok_or_else(mismatch)?
        .packet
        .capture;
    let mut transport = EvidenceBytes::default();
    let mut packets = Vec::new();
    let mut links = Vec::new();
    let mut direction = None;
    let mut previous = None;
    let mut final_seen = false;
    let mut seen: BTreeMap<u8, Vec<u8>> = BTreeMap::new();
    let mut frame_indices = BTreeSet::new();
    for &index in &fragment.frames {
        charge(work, 1, limits.max_correlation_checks)?;
        if !frame_indices.insert(index) {
            return Err(mismatch()); // one captured link witness cannot be listed twice
        }
        let frame = result.frames.get(index).ok_or_else(mismatch)?;
        charge(work, frame.raw.len(), limits.max_correlation_checks)?;
        charge(work, frame.raw.spans().len(), limits.max_correlation_checks)?;
        charge(work, frame.user_data.len(), limits.max_correlation_checks)?;
        charge(
            work,
            frame.user_data.spans().len(),
            limits.max_correlation_checks,
        )?;
        if !frame.raw.validate()
            || frame
                .raw
                .spans()
                .iter()
                .any(|s| s.packet.capture != capture)
        {
            return Err(mismatch());
        }
        let (parsed, used) = parse_link(&frame.raw, 0, frame.stream_offset)?;
        if used != frame.raw.len()
            || frame.control != parsed.control
            || frame.link_control != parsed.link_control
            || frame.source != parsed.source
            || frame.destination != parsed.destination
            || frame.broadcast != parsed.broadcast
            || frame.user_data != parsed.user_data
            || parsed.source != fragment.source
            || parsed.destination != fragment.destination
            || direction.is_some_and(|d| d != parsed.link_control.direction)
            || !parsed.link_control.primary
            || !matches!(parsed.link_control.function, 3 | 4)
            || link_issue(
                parsed.control,
                parsed.source,
                parsed.destination,
                parsed.user_data.len(),
            )
            .is_some()
        {
            return Err(mismatch());
        }
        direction = Some(parsed.link_control.direction);
        let b = parsed.user_data.data(); // link_issue established a nonempty data frame
        let sequence = b[0] & 63;
        let expected = previous.map(|last: u8| (last + 1) & 63);
        let duplicate = expected != Some(sequence)
            && seen.get(&sequence).is_some_and(|old| old.as_slice() == b);
        // A post-FIN APDU is a separate observation, not an in-assembly
        // retransmission. Do not launder duplicate confirms into one fragment.
        if final_seen {
            return Err(mismatch());
        }
        if !duplicate {
            if (previous.is_none() != (b[0] & 64 != 0))
                || previous.is_some() && expected != Some(sequence)
            {
                return Err(mismatch());
            }
            transport.append(
                &parsed.user_data.slice(1..b.len())?,
                limits.max_application_bytes,
            )?;
            previous = Some(sequence);
            final_seen = b[0] & 128 != 0;
            seen.insert(sequence, b.to_vec());
        }
        packets.extend(parsed.raw.packets());
        links.push(FragmentLinkWitness {
            frame: index,
            control: parsed.control,
            header: parsed.raw.slice(0..10)?,
            transport_control: b[0],
            transport_header: parsed.user_data.slice(0..1)?,
            frame_length: parsed.raw.len(),
            frame_sha256: crate::sha256::digest(parsed.raw.data()),
        });
    }
    if !final_seen || transport != fragment.raw {
        return Err(mismatch());
    }
    packets.sort();
    packets.dedup();
    Ok(FragmentWitness {
        source: fragment.source,
        destination: fragment.destination,
        link_direction: direction.ok_or_else(mismatch)?,
        header: h,
        header_bytes: fragment.raw.slice(0..h.length)?,
        packets,
        links,
    })
}
