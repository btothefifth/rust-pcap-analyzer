//! Additional bounded service/path fields, not device execution or conformance.
//! Public contract: docs/product/SERVICE_FIELDS.md. Unknown variants stay opaque.
use super::{Decoded, Field, Protocol};
use pcap_evidence::{json::Json, sha256, Error, ErrorCode, Result};

fn invalid(field: &'static str, detail: &'static str) -> Error {
    Error::new(ErrorCode::ProtocolFraming, 0, field, detail)
}
fn take(b: &[u8], start: usize, length: usize) -> Result<&[u8]> {
    b.get(
        start
            ..start
                .checked_add(length)
                .ok_or_else(|| Error::limit("service_extent"))?,
    )
    .ok_or_else(|| invalid("service_extent", "field extends beyond framed message"))
}
fn number(b: &[u8]) -> Result<u64> {
    if b.is_empty() || b.len() > 4 {
        return Err(invalid("unsigned", "unsigned field length outside 1..4"));
    }
    Ok(b.iter().fold(0u64, |n, v| (n << 8) | u64::from(*v)))
}
fn add(d: &mut Decoded, name: &'static str, value: Json, start: usize, end: usize) {
    d.fields.push(Field {
        name,
        value,
        start,
        end,
    });
}
fn n(d: &mut Decoded, name: &'static str, value: u64, start: usize, end: usize) {
    add(d, name, value.to_string().into(), start, end);
}

#[derive(Clone, Debug)]
struct Tag {
    number: u8,
    context: bool,
    opening: bool,
    closing: bool,
    start: usize,
    value: usize,
    end: usize,
}
fn tag(b: &[u8], at: &mut usize) -> Result<Tag> {
    let start = *at;
    let first = take(b, *at, 1)?[0];
    *at += 1;
    let mut number = first >> 4;
    if number == 15 {
        number = take(b, *at, 1)?[0];
        *at += 1;
        if number == 255 {
            return Err(invalid("bacnet_tag", "reserved extended tag"));
        }
    }
    let context = first & 8 != 0;
    let lvt = first & 7;
    if lvt >= 6 {
        if !context {
            return Err(invalid("bacnet_tag", "application opening/closing tag"));
        }
        return Ok(Tag {
            number,
            context,
            opening: lvt == 6,
            closing: lvt == 7,
            start,
            value: *at,
            end: *at,
        });
    }
    let mut length = usize::from(lvt);
    if !context && number == 1 {
        if lvt > 1 {
            return Err(invalid("bacnet_boolean", "boolean outside zero/one"));
        }
        length = 0;
    } else if lvt == 5 {
        let ext = take(b, *at, 1)?[0];
        *at += 1;
        length = match ext {
            254 => {
                let raw = take(b, *at, 2)?;
                *at += 2;
                usize::from(u16::from_be_bytes([raw[0], raw[1]]))
            }
            255 => {
                let raw = take(b, *at, 4)?;
                *at += 4;
                usize::try_from(u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]))
                    .map_err(|_| Error::limit("bacnet_length"))?
            }
            _ => usize::from(ext),
        };
    }
    if !context && number == 0 && length != 0 {
        return Err(invalid("bacnet_null", "NULL with a payload"));
    }
    let value = *at;
    take(b, value, length)?;
    *at += length;
    Ok(Tag {
        number,
        context,
        opening: false,
        closing: false,
        start,
        value,
        end: *at,
    })
}
fn expected(b: &[u8], at: &mut usize, number: u8, context: bool) -> Result<Tag> {
    let t = tag(b, at)?;
    if t.number != number || t.context != context || t.opening || t.closing {
        return Err(invalid("bacnet_service", "unexpected field tag/order"));
    }
    Ok(t)
}
fn tagged_number(b: &[u8], t: &Tag) -> Result<u64> {
    number(take(b, t.value, t.end - t.value)?)
}
fn object_id(d: &mut Decoded, b: &[u8], t: &Tag) -> Result<()> {
    if t.end - t.value != 4 {
        return Err(invalid(
            "bacnet_object",
            "object identifier must have four octets",
        ));
    }
    let value = tagged_number(b, t)?;
    n(d, "object_type", value >> 22, t.value, t.end);
    n(d, "object_instance", value & 0x3fffff, t.value, t.end);
    Ok(())
}
fn value_container(b: &[u8], at: &mut usize) -> Result<(usize, usize, Vec<Json>)> {
    let first = tag(b, at)?;
    if !first.context || first.number != 3 || !first.opening {
        return Err(invalid("bacnet_value", "expected opening tag three"));
    }
    let mut stack = vec![3u8];
    let mut observed = Vec::new();
    let value_start = *at;
    while !stack.is_empty() {
        if observed.len() >= 256 {
            return Err(Error::limit("bacnet_value_tags"));
        }
        let t = tag(b, at)?;
        if t.opening {
            if stack.len() >= 16 {
                return Err(Error::limit("bacnet_value_depth"));
            }
            stack.push(t.number);
        } else if t.closing {
            if stack.pop() != Some(t.number) {
                return Err(invalid("bacnet_value", "mismatched closing tag"));
            }
            if stack.is_empty() {
                if observed.is_empty() {
                    return Err(invalid("bacnet_value", "empty property value"));
                }
                return Ok((value_start, t.start, observed));
            }
        }
        observed.push(Json::object([
            ("tag", t.number.into()),
            ("context", t.context.into()),
            ("opening", t.opening.into()),
            ("closing", t.closing.into()),
            ("start", t.start.to_string().into()),
            ("value_start", t.value.to_string().into()),
            ("end", t.end.to_string().into()),
        ]));
    }
    Err(invalid("bacnet_value", "unclosed property value"))
}
fn bacnet(b: &[u8], d: &mut Decoded) -> Result<()> {
    let function = take(b, 1, 1)?[0];
    let mut at = match function {
        4 => 10,
        9..=11 => 4,
        _ => return Ok(()),
    };
    let ctl = take(b, at, 2)?[1];
    at += 2;
    if ctl & 0x20 != 0 {
        let len = usize::from(take(b, at, 3)?[2]);
        take(b, at + 3, len)?;
        at += 3 + len;
    }
    if ctl & 8 != 0 {
        let len = usize::from(take(b, at, 3)?[2]);
        take(b, at + 3, len)?;
        at += 3 + len;
    }
    if ctl & 0x20 != 0 {
        take(b, at, 1)?;
        at += 1;
    }
    if ctl & 0x80 != 0 {
        return Ok(());
    }
    let apdu = at;
    let control = take(b, at, 1)?[0];
    let kind = control >> 4;
    if matches!(kind, 0 | 3) && control & 8 != 0 {
        d.issues
            .push("segmented_bacnet_service_requires_reassembly");
        return Ok(());
    }
    let (service, header) = match kind {
        0 => (take(b, at, 4)?[3], 4),
        1 => (take(b, at, 2)?[1], 2),
        3 => (take(b, at, 3)?[2], 3),
        _ => return Ok(()),
    };
    n(
        d,
        "service_choice",
        u64::from(service),
        at + header - 1,
        at + header,
    );
    if kind == 0 || kind == 3 {
        let offset = if kind == 0 { 2 } else { 1 };
        n(
            d,
            "invoke_id",
            u64::from(b[at + offset]),
            at + offset,
            at + offset + 1,
        );
    }
    at += header;
    let understood = match (kind, service) {
        (1, 8) => {
            if at < b.len() {
                let low = expected(b, &mut at, 0, true)?;
                let high = expected(b, &mut at, 1, true)?;
                let a = tagged_number(b, &low)?;
                let z = tagged_number(b, &high)?;
                if a > z || z > 0x3fffff {
                    return Err(invalid("who_is_range", "invalid device instance interval"));
                }
                n(d, "device_instance_low", a, low.value, low.end);
                n(d, "device_instance_high", z, high.value, high.end);
            }
            true
        }
        (1, 0) => {
            let id = expected(b, &mut at, 12, false)?;
            object_id(d, b, &id)?;
            if tagged_number(b, &id)? >> 22 != 8 {
                return Err(invalid(
                    "i_am_object",
                    "I-Am requires a device object identifier",
                ));
            }
            let size = expected(b, &mut at, 2, false)?;
            let segmentation = expected(b, &mut at, 9, false)?;
            let vendor = expected(b, &mut at, 2, false)?;
            let apdu_size = tagged_number(b, &size)?;
            let seg = tagged_number(b, &segmentation)?;
            let v = tagged_number(b, &vendor)?;
            if apdu_size == 0 || seg > 3 || v > 65535 {
                return Err(invalid(
                    "i_am_fields",
                    "I-Am field outside its bounded range",
                ));
            }
            n(d, "maximum_apdu", apdu_size, size.value, size.end);
            n(
                d,
                "segmentation_supported",
                seg,
                segmentation.value,
                segmentation.end,
            );
            n(d, "vendor_id", v, vendor.value, vendor.end);
            true
        }
        (0, 12 | 15) | (3, 12) => {
            let id = expected(b, &mut at, 0, true)?;
            object_id(d, b, &id)?;
            let property = expected(b, &mut at, 1, true)?;
            n(
                d,
                "property_identifier",
                tagged_number(b, &property)?,
                property.value,
                property.end,
            );
            if at < b.len() && b[at] >> 4 == 2 && b[at] & 8 != 0 {
                let array = expected(b, &mut at, 2, true)?;
                n(
                    d,
                    "property_array_index",
                    tagged_number(b, &array)?,
                    array.value,
                    array.end,
                );
            }
            if service == 15 || kind == 3 {
                let (start, end, tags) = value_container(b, &mut at)?;
                add(d, "property_value_tags", Json::Array(tags), start, end);
                add(
                    d,
                    "property_value_sha256",
                    sha256::hex(&sha256::digest(&b[start..end])).into(),
                    start,
                    end,
                );
                if service == 15 && at < b.len() {
                    let priority = expected(b, &mut at, 4, true)?;
                    let value = tagged_number(b, &priority)?;
                    if !(1..=16).contains(&value) {
                        return Err(invalid("write_priority", "priority outside 1..16"));
                    }
                    n(d, "write_priority", value, priority.value, priority.end);
                }
                d.issues
                    .push("property_value_type_and_device_effect_not_established");
            }
            true
        }
        _ => false,
    };
    if understood {
        if at != b.len() {
            return Err(invalid(
                "bacnet_service",
                "trailing or duplicated service fields",
            ));
        }
        d.support = "implemented-partial";
        d.issues
            .retain(|issue| *issue != "bacnet_service_and_object_semantics_opaque");
        d.issues.push("bacnet_service_subset_not_device_semantics");
        n(
            d,
            "service_payload_start",
            (apdu + header) as u64,
            apdu,
            apdu + header,
        );
    }
    Ok(())
}
fn le16(b: &[u8], at: usize) -> Result<u16> {
    let x = take(b, at, 2)?;
    Ok(u16::from_le_bytes([x[0], x[1]]))
}
fn epath(b: &[u8], base: usize) -> Result<(Vec<Json>, bool)> {
    let mut at = 0;
    let mut segments = Vec::new();
    while at < b.len() {
        if segments.len() >= 128 {
            return Err(Error::limit("cip_path_segments"));
        }
        let start = at;
        let code = b[at];
        at += 1;
        let logical = match code & 0xfc {
            0x20 => Some("class"),
            0x24 => Some("instance"),
            0x28 => Some("member"),
            0x2c => Some("connection_point"),
            0x30 => Some("attribute"),
            _ => None,
        };
        if let Some(kind) = logical {
            let width = match code & 3 {
                0 => 1,
                1 => 2,
                2 => 4,
                _ => return Err(invalid("cip_path", "reserved logical segment format")),
            };
            if width > 1 {
                if take(b, at, 1)?[0] != 0 {
                    return Err(invalid("cip_path", "nonzero logical segment padding"));
                }
                at += 1;
            }
            let raw = take(b, at, width)?;
            let value = raw
                .iter()
                .enumerate()
                .fold(0u64, |v, (i, n)| v | (u64::from(*n) << (8 * i)));
            at += width;
            segments.push(Json::object([
                ("kind", kind.into()),
                ("value", value.to_string().into()),
                ("start", (base + start).to_string().into()),
                ("end", (base + at).to_string().into()),
            ]));
        } else if code == 0x91 {
            let length = usize::from(take(b, at, 1)?[0]);
            at += 1;
            if length == 0 {
                return Err(invalid("cip_symbol", "empty ANSI extended symbol"));
            }
            let raw = take(b, at, length)?;
            at += length;
            if length % 2 == 1 {
                if take(b, at, 1)?[0] != 0 {
                    return Err(invalid("cip_symbol", "nonzero symbol padding"));
                }
                at += 1;
            }
            segments.push(Json::object([
                ("kind", "ansi_extended_symbol".into()),
                ("symbol_hex", sha256::hex(raw).into()),
                ("start", (base + start).to_string().into()),
                ("end", (base + at).to_string().into()),
            ]));
        } else {
            segments.push(Json::object([
                ("kind", "unsupported_path_tail".into()),
                ("type_octet", code.into()),
                ("start", (base + start).to_string().into()),
                ("end", (base + b.len()).to_string().into()),
                ("sha256", sha256::hex(&sha256::digest(&b[start..])).into()),
            ]));
            return Ok((segments, false));
        }
    }
    Ok((segments, true))
}
fn cip(b: &[u8], d: &mut Decoded) -> Result<()> {
    let command = le16(b, 0)?;
    if ![0x6f, 0x70].contains(&command) {
        return Ok(());
    }
    let count = usize::from(le16(b, 30)?);
    if count > 64 {
        return Err(Error::limit("cpf_items"));
    }
    let mut at = 32;
    let mut messages = Vec::new();
    let mut all_paths = true;
    for ordinal in 0..count {
        let ty = le16(b, at)?;
        let length = usize::from(le16(b, at + 2)?);
        at += 4;
        let end = at + length;
        take(b, at, length)?;
        // Connected data item 0xB1 may contain implicit I/O, not a CIP message
        // router payload. Do not interpret it without captured connection state.
        if ty == 0xb1 {
            d.issues.push("connected_cip_requires_connection_semantics");
        }
        if ty == 0xb2 {
            let c = take(b, at, length)?;
            let service = take(c, 0, 2)?[0];
            let mut fields = vec![
                ("item_ordinal", Json::from(ordinal)),
                ("service", Json::from(service & 0x7f)),
                ("response", Json::from(service & 0x80 != 0)),
                ("start", Json::from(at.to_string())),
                ("end", Json::from(end.to_string())),
            ];
            let body;
            if service & 0x80 != 0 {
                take(c, 0, 4)?;
                if c[1] != 0 {
                    return Err(invalid("cip_response", "reserved response octet"));
                }
                body = 4 + usize::from(c[3]) * 2;
                take(c, 0, body)?;
                fields.push(("general_status", c[2].into()));
                fields.push((
                    "additional_status",
                    Json::array(
                        (0..usize::from(c[3]))
                            .map(|i| Json::from(u16::from_le_bytes([c[4 + i * 2], c[5 + i * 2]]))),
                    ),
                ));
            } else {
                body = 2 + usize::from(c[1]) * 2;
                let path = take(c, 2, body - 2)?;
                let (segments, complete) = epath(path, at + 2)?;
                all_paths &= complete;
                fields.push(("path_segments", Json::Array(segments)));
                fields.push(("path_semantics_complete", complete.into()));
            }
            fields.push(("service_data_start", (at + body).to_string().into()));
            fields.push((
                "service_data_sha256",
                sha256::hex(&sha256::digest(&c[body..])).into(),
            ));
            fields.push(("device_effect_established", false.into()));
            messages.push(Json::Object(fields));
        }
        at = end;
    }
    if at != b.len() {
        return Err(invalid("cip_cpf", "trailing CPF data"));
    }
    if !messages.is_empty() {
        add(
            d,
            "cip_service_observations",
            Json::Array(messages),
            32,
            b.len(),
        );
        d.support = "implemented-partial";
        d.issues
            .retain(|issue| *issue != "cip_paths_objects_and_connection_semantics_opaque");
        d.issues
            .push("cip_service_values_connections_and_device_effects_opaque");
        if !all_paths {
            d.issues.push("unsupported_cip_path_segments_retained");
        }
    }
    Ok(())
}
/// Invoked by the existing Protocol::decode facade before its range/duplicate-key
/// checks. Thus the plugin, JSON/TLV and GUI receive the SAME new field records.
pub(super) fn extend(protocol: Protocol, bytes: &[u8], decoded: &mut Decoded) -> Result<()> {
    let b = take(bytes, 0, decoded.consumed)?;
    match protocol {
        Protocol::BacnetIp => bacnet(b, decoded),
        Protocol::Enip => cip(b, decoded),
        _ => Ok(()),
    }
}
