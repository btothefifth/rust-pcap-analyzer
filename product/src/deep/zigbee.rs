//! IEEE 802.15.4 2003/2006 MAC + Zigbee NWK/APS + selected ZCL foundation
//! data types. Security-enabled payloads are opaque, not guessed as plaintext.
use super::model::*;
use pcap_evidence::{json::Json, provenance::EvidenceBytes, Error, Result};
fn crc(b: &[u8]) -> u16 {
    let mut c = 0u16;
    for &v in b {
        c ^= u16::from(v);
        for _ in 0..8 {
            c = if c & 1 != 0 {
                (c >> 1) ^ 0x8408
            } else {
                c >> 1
            };
        }
    }
    c
}
pub fn decode(bytes: &EvidenceBytes, fcs_present: bool, l: &Limits) -> Result<Report> {
    let full = bytes.data();
    let mut r = Report::new("zigbee", bytes, l)?;
    let end = if fcs_present {
        need(full, 4, "mac_fcs")?;
        let e = full.len() - 2;
        if crc(&full[..e]) != le16(full, e)? {
            r.note(Status::Rejected, "ieee802154_fcs_mismatch", e, full.len())?;
            return Ok(r);
        }
        e
    } else {
        full.len()
    };
    let b = &full[..end];
    need(b, 3, "mac_header")?;
    let fc = le16(b, 0)?;
    let version = (fc >> 12) & 3;
    r.u("mac_frame_control", u64::from(fc), 0..2)?;
    r.u("mac_sequence", u64::from(b[2]), 2..3)?;
    if version > 1 || fc & 0x0300 != 0 {
        r.note(
            Status::Unsupported,
            "ieee802154_2015_or_ie_sequence_suppression",
            0,
            end,
        )?;
        return Ok(r);
    }
    let (dest, src) = ((fc >> 10) & 3, (fc >> 14) & 3);
    if dest == 1 || src == 1 {
        return Err(bad("mac_address_mode", 0, "reserved addressing mode"));
    }
    let mut at = 3;
    if dest != 0 {
        need(b, at + 2, "dest_pan")?;
        r.u("destination_pan", u64::from(le16(b, at)?), at..at + 2)?;
        at += 2;
        let n = if dest == 2 { 2 } else { 8 };
        need(b, at + n, "dest_address")?;
        r.add(
            "destination_mac",
            hex(&b[at..at + n]),
            at..at + n,
            "little_endian_address_bytes",
        )?;
        at += n;
    }
    if src != 0 {
        if fc & 64 == 0 {
            need(b, at + 2, "source_pan")?;
            r.u("source_pan", u64::from(le16(b, at)?), at..at + 2)?;
            at += 2;
        } else if dest == 0 {
            return Err(bad(
                "pan_compression",
                0,
                "compressed PAN without destination",
            ));
        }
        let n = if src == 2 { 2 } else { 8 };
        need(b, at + n, "source_address")?;
        r.add(
            "source_mac",
            hex(&b[at..at + n]),
            at..at + n,
            "little_endian_address_bytes",
        )?;
        at += n;
    }
    if fc & 8 != 0 {
        r.note(Status::Unsupported, "mac_security_payload_opaque", at, end)?;
        return Ok(r);
    }
    if fc & 7 != 1 {
        r.note(Status::Unsupported, "not_mac_data_frame", at, end)?;
        return Ok(r);
    }
    need(b, at + 8, "zigbee_nwk")?;
    let nw = le16(b, at)?;
    r.u("nwk_frame_control", u64::from(nw), at..at + 2)?;
    if (nw >> 2) & 15 != 2 {
        r.note(Status::Unsupported, "nwk_protocol_version", at, end)?;
        return Ok(r);
    }
    r.u(
        "nwk_destination",
        u64::from(le16(b, at + 2)?),
        at + 2..at + 4,
    )?;
    r.u("nwk_source", u64::from(le16(b, at + 4)?), at + 4..at + 6)?;
    r.u("radius", u64::from(b[at + 6]), at + 6..at + 7)?;
    r.u("nwk_sequence", u64::from(b[at + 7]), at + 7..at + 8)?;
    at += 8;
    for (mask, name) in [
        (0x0800, "extended_destination"),
        (0x1000, "extended_source"),
    ] {
        if nw & mask != 0 {
            need(b, at + 8, "nwk_extended_address")?;
            r.add(name, hex(&b[at..at + 8]), at..at + 8, "extended_address")?;
            at += 8;
        }
    }
    if nw & 0x100 != 0 {
        need(b, at + 1, "multicast_control")?;
        r.u("multicast_control", u64::from(b[at]), at..at + 1)?;
        at += 1;
    }
    if nw & 0x400 != 0 {
        need(b, at + 2, "source_route")?;
        let count = usize::from(b[at]);
        let index = b[at + 1];
        if count > l.elements || usize::from(index) >= count && count != 0 {
            return Err(bad("source_route", at, "invalid relay count/index"));
        }
        need(b, at + 2 + count * 2, "source_route")?;
        r.add(
            "relay_list",
            Json::array(
                (0..count)
                    .map(|i| le16(b, at + 2 + i * 2).map(Json::from))
                    .collect::<Result<Vec<_>>>()?,
            ),
            at..at + 2 + count * 2,
            "ordered_relay_addresses",
        )?;
        at += 2 + count * 2;
    }
    if nw & 0x200 != 0 {
        need(b, at + 5, "nwk_security")?;
        let sc = b[at];
        r.u("security_control", u64::from(sc), at..at + 1)?;
        r.u("frame_counter", u64::from(le32(b, at + 1)?), at + 1..at + 5)?;
        r.note(
            Status::Unsupported,
            "zigbee_security_requires_authorized_key_and_nonce_context",
            at,
            end,
        )?;
        return Ok(r);
    }
    if nw & 3 != 0 {
        r.note(
            Status::Unsupported,
            "nwk_command_not_application_data",
            at,
            end,
        )?;
        return Ok(r);
    }
    aps(&mut r, b, at, l)?;
    Ok(r)
}
fn aps(r: &mut Report, b: &[u8], mut at: usize, l: &Limits) -> Result<()> {
    need(b, at + 1, "aps")?;
    let control = b[at];
    let begin = at;
    at += 1;
    r.u("aps_control", u64::from(control), begin..at)?;
    if control & 3 != 0 {
        r.note(Status::Unsupported, "aps_command_or_ack", at, b.len())?;
        return Ok(());
    }
    let mode = (control >> 2) & 3;
    if mode == 3 {
        r.u("aps_group", u64::from(le16(b, at)?), at..at + 2)?;
        at += 2;
    } else {
        need(b, at + 1, "aps_dest_endpoint")?;
        r.u("destination_endpoint", u64::from(b[at]), at..at + 1)?;
        at += 1;
    }
    need(b, at + 6, "aps_data_header")?;
    r.u("cluster_id", u64::from(le16(b, at)?), at..at + 2)?;
    r.u("profile_id", u64::from(le16(b, at + 2)?), at + 2..at + 4)?;
    r.u("source_endpoint", u64::from(b[at + 4]), at + 4..at + 5)?;
    r.u("aps_counter", u64::from(b[at + 5]), at + 5..at + 6)?;
    at += 6;
    if control & 0x80 != 0 {
        need(b, at + 1, "aps_extended")?;
        let ext = b[at];
        at += 1;
        if ext & 3 != 0 {
            r.note(
                Status::Incomplete,
                "aps_fragment_requires_reassembly",
                at - 1,
                b.len(),
            )?;
            return Ok(());
        }
    }
    if control & 0x20 != 0 {
        r.note(
            Status::Unsupported,
            "aps_security_payload_opaque",
            at,
            b.len(),
        )?;
        return Ok(());
    }
    need(b, at + 3, "zcl_header")?;
    let fc = b[at];
    let h = at;
    at += 1;
    if fc & 0xe0 != 0 {
        return Err(bad("zcl_frame_control", h, "reserved bits"));
    }
    if fc & 4 != 0 {
        r.u("manufacturer_code", u64::from(le16(b, at)?), at..at + 2)?;
        at += 2;
    }
    need(b, at + 2, "zcl_sequence_command")?;
    r.u("zcl_transaction", u64::from(b[at]), at..at + 1)?;
    let cmd = b[at + 1];
    r.u("zcl_command", u64::from(cmd), at + 1..at + 2)?;
    at += 2;
    if fc & 3 != 0 {
        r.note(
            Status::Unsupported,
            "manufacturer_or_cluster_specific_command",
            at,
            b.len(),
        )?;
        return Ok(());
    }
    let mut count = 0;
    while at < b.len() {
        count += 1;
        if count > l.elements {
            return Err(Error::limit("zcl_attributes"));
        }
        let p = at;
        let id = le16(b, at)?;
        at += 2;
        if cmd == 0 {
            r.u(format!("read_attribute[{count}]"), u64::from(id), p..at)?;
            continue;
        }
        if !matches!(cmd, 1 | 2 | 3 | 5 | 10) {
            r.note(Status::Unsupported, "zcl_foundation_command", p, b.len())?;
            break;
        }
        if cmd == 1 {
            need(b, at + 1, "zcl_status")?;
            let status = b[at];
            at += 1;
            if status != 0 {
                r.add(
                    format!("attribute[{count}]"),
                    Json::object([("id", id.into()), ("status", status.into())]),
                    p..at,
                    "read_attribute_failure",
                )?;
                continue;
            }
        }
        need(b, at + 1, "zcl_type")?;
        let ty = b[at];
        at += 1;
        let value = zcl_value(b, &mut at, ty, l, 0)?;
        r.add(
            format!("attribute[{count}]"),
            Json::object([("id", id.into()), ("type", ty.into()), ("value", value)]),
            p..at,
            "zcl_foundation_attribute_not_device_effect",
        )?;
    }
    Ok(())
}
pub fn zcl_value(b: &[u8], at: &mut usize, ty: u8, l: &Limits, depth: usize) -> Result<Json> {
    let mut remaining = l.elements;
    zcl_value_inner(b, at, ty, l, depth, &mut remaining)
}
fn zcl_value_inner(
    b: &[u8],
    at: &mut usize,
    ty: u8,
    l: &Limits,
    depth: usize,
    remaining: &mut usize,
) -> Result<Json> {
    if depth >= l.depth || *remaining == 0 {
        return Err(Error::limit("zcl_structure"));
    }
    *remaining -= 1;
    let width = match ty {
        0 => 0,
        0x08..=0x0f => usize::from(ty - 7),
        0x10 => 1,
        0x18..=0x1f => usize::from(ty - 0x17),
        0x20..=0x27 => usize::from(ty - 0x1f),
        0x28..=0x2f => usize::from(ty - 0x27),
        0x30 => 1,
        0x31 => 2,
        0x38 => 2,
        0x39 => 4,
        0x3a => 8,
        0xe0..=0xe2 => 4,
        0xe8 | 0xe9 => 2,
        0xea => 4,
        0xf0 => 8,
        0xf1 => 16,
        _ => usize::MAX,
    };
    if width != usize::MAX {
        need(
            b,
            at.checked_add(width)
                .ok_or_else(|| Error::limit("zcl_length"))?,
            "zcl_scalar",
        )?;
        let raw = &b[*at..*at + width];
        *at += width;
        return Ok(if (0x28..=0x2f).contains(&ty) {
            signed(raw, true)?.to_string().into()
        } else if (0x20..=0x27).contains(&ty) || matches!(ty, 0x30 | 0x31) {
            uint(raw, true)?.to_string().into()
        } else {
            hex(raw)
        });
    }
    if matches!(ty, 0x41..=0x44) {
        let n = if ty <= 0x42 {
            need(b, *at + 1, "zcl_string")?;
            let n = usize::from(b[*at]);
            *at += 1;
            if n == 255 {
                return Ok(Json::Null);
            }
            n
        } else {
            let n = usize::from(le16(b, *at)?);
            *at += 2;
            if n == 65535 {
                return Ok(Json::Null);
            }
            n
        };
        if n > l.input_bytes {
            return Err(Error::limit("zcl_string"));
        }
        need(b, *at + n, "zcl_string")?;
        let out = hex(&b[*at..*at + n]);
        *at += n;
        return Ok(out);
    }
    if ty == 0x4c || matches!(ty, 0x48 | 0x50 | 0x51) {
        let homogeneous = ty != 0x4c;
        let subtype = if homogeneous {
            need(b, *at + 1, "zcl_array_type")?;
            let t = b[*at];
            *at += 1;
            t
        } else {
            0
        };
        let count = usize::from(le16(b, *at)?);
        *at += 2;
        if count > *remaining {
            return Err(Error::limit("zcl_collection"));
        }
        let mut out = Vec::new();
        let mut next = l.clone();
        next.elements = l.elements.saturating_sub(count).max(1);
        for _ in 0..count {
            let t = if homogeneous {
                subtype
            } else {
                need(b, *at + 1, "zcl_member_type")?;
                let t = b[*at];
                *at += 1;
                t
            };
            out.push(zcl_value_inner(b, at, t, &next, depth + 1, remaining)?);
        }
        return Ok(Json::Array(out));
    }
    Err(bad(
        "zcl_type",
        *at,
        "unsupported datatype has no inferred width",
    ))
}
