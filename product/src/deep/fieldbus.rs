use super::model::*;
use pcap_evidence::{json::Json, provenance::EvidenceBytes, Error, Result};

pub fn decode(protocol: &str, bytes: &EvidenceBytes, l: &Limits) -> Result<Report> {
    match protocol {
        "ethercat" => ethercat(bytes, l),
        "profinet_rt" => profinet(bytes, l),
        "powerlink" => powerlink(bytes, l),
        "stp" => stp(bytes, l),
        _ => Err(bad("fieldbus", 0, "unsupported family")),
    }
}
fn ethercat(bytes: &EvidenceBytes, l: &Limits) -> Result<Report> {
    let b = bytes.data();
    let header = le16(b, 0)?;
    let n = usize::from(header & 0x7ff) + 2;
    need(b, n, "ethercat")?;
    let mut r = Report::new("ethercat", bytes, l)?;
    r.u("frame_type", u64::from(header >> 12), 0..2)?;
    if header >> 12 != 1 {
        r.note(Status::Unsupported, "ethercat_non_datagram_frame", 2, n)?;
        return Ok(r);
    }
    let mut p = 2;
    let mut count = 0;
    while p < n {
        count += 1;
        if count > l.elements {
            return Err(Error::limit("ethercat_datagrams"));
        }
        need(&b[..n], p + 10, "ethercat_datagram")?;
        let cmd = b[p];
        let length = le16(b, p + 6)?;
        let size = usize::from(length & 0x7ff);
        let end = p + 12 + size;
        need(&b[..n], end, "ethercat_data")?;
        r.add(
            format!("datagram[{count}]"),
            Json::object([
                ("command", cmd.into()),
                ("index", b[p + 1].into()),
                ("address_hex", hex(&b[p + 2..p + 6])),
                ("logical_address", le32(b, p + 2)?.to_string().into()),
                ("irq", le16(b, p + 8)?.into()),
                ("circulating", (length & 0x4000 != 0).into()),
                ("more", (length & 0x8000 != 0).into()),
                ("payload_hex", hex(&b[p + 10..p + 10 + size])),
                ("working_counter", le16(b, p + 10 + size)?.into()),
                ("device_process_state_verified", false.into()),
            ]),
            p..end,
            "ethercat_datagram_and_working_counter",
        )?;
        if cmd > 14 {
            r.note(
                Status::Unsupported,
                "ethercat_command_outside_subset",
                p,
                p + 1,
            )?;
        }
        if length & 0x3800 != 0 {
            r.note(
                Status::Rejected,
                "ethercat_reserved_length_bits",
                p + 6,
                p + 8,
            )?;
        }
        let more = length & 0x8000 != 0;
        p = end;
        if !more {
            if p < n {
                r.note(Status::Rejected, "bytes_after_last_ethercat_datagram", p, n)?;
            }
            break;
        }
        if p == n {
            r.note(
                Status::Incomplete,
                "ethercat_more_without_next_datagram",
                p,
                p,
            )?;
        }
    }
    if n < b.len() {
        r.note(
            Status::Unsupported,
            "ethernet_padding_or_trailer",
            n,
            b.len(),
        )?;
    }
    Ok(r)
}
fn profinet(bytes: &EvidenceBytes, l: &Limits) -> Result<Report> {
    let b = bytes.data();
    let id = be16(b, 0)?;
    let mut r = Report::new("profinet", bytes, l)?;
    r.u("frame_id", u64::from(id), 0..2)?;
    if (0xfefc..=0xfeff).contains(&id) {
        need(b, 12, "dcp_header")?;
        let n = 12 + usize::from(be16(b, 10)?);
        need(b, n, "dcp_data")?;
        r.u("dcp_service_id", u64::from(b[2]), 2..3)?;
        r.u("dcp_service_type", u64::from(b[3]), 3..4)?;
        r.u("transaction_id", u64::from(be32(b, 4)?), 4..8)?;
        r.u("response_delay", u64::from(be16(b, 8)?), 8..10)?;
        let mut p = 12;
        let mut count = 0;
        while p < n {
            count += 1;
            if count > l.elements {
                return Err(Error::limit("dcp_blocks"));
            }
            need(&b[..n], p + 4, "dcp_block")?;
            let (option, sub) = (b[p], b[p + 1]);
            let len = usize::from(be16(b, p + 2)?);
            need(&b[..n], p + 4 + len, "dcp_block")?;
            let raw = &b[p + 4..p + 4 + len];
            let mut v = vec![
                ("option", option.into()),
                ("suboption", sub.into()),
                ("raw", hex(raw)),
            ];
            if option == 1 && sub == 2 && len >= 14 {
                v.extend([
                    ("block_info", be16(raw, 0)?.into()),
                    (
                        "ip_address",
                        format!("{}.{}.{}.{}", raw[2], raw[3], raw[4], raw[5]).into(),
                    ),
                    (
                        "subnet",
                        format!("{}.{}.{}.{}", raw[6], raw[7], raw[8], raw[9]).into(),
                    ),
                    (
                        "gateway",
                        format!("{}.{}.{}.{}", raw[10], raw[11], raw[12], raw[13]).into(),
                    ),
                ]);
            } else if option == 2 && sub == 3 && len >= 6 {
                v.extend([
                    ("vendor_id", be16(raw, 2)?.into()),
                    ("device_id", be16(raw, 4)?.into()),
                ]);
            } else if option == 2 && sub == 2 && len >= 2 {
                v.push(("station_name_bytes", hex(&raw[2..])));
            }
            r.add(
                format!("dcp_block[{count}]"),
                Json::Object(v),
                p..p + 4 + len,
                "dcp_block_not_device_configuration_proof",
            )?;
            p += 4 + len;
            if len % 2 != 0 {
                need(&b[..n], p + 1, "dcp_padding")?;
                if b[p] != 0 {
                    r.note(Status::Ambiguous, "nonzero_dcp_alignment", p, p + 1)?;
                }
                p += 1;
            }
        }
        if n < b.len() {
            r.note(Status::Unsupported, "ethernet_tail_outside_dcp", n, b.len())?;
        }
    } else if (0x0100..=0xfbff).contains(&id) {
        need(b, 6, "pnio_rt")?;
        let n = b.len();
        r.u("cycle_counter", u64::from(be16(b, n - 4)?), n - 4..n - 2)?;
        r.u("data_status", u64::from(b[n - 2]), n - 2..n - 1)?;
        r.u("transfer_status", u64::from(b[n - 1]), n - 1..n)?;
        r.add(
            "process_data",
            hex(&b[2..n - 4]),
            2..n - 4,
            "captured_rt_payload_requires_io_cr_layout",
        )?;
        r.note(
            Status::Unsupported,
            "io_cr_padding_and_irt_schedule_require_connection_model",
            2,
            n,
        )?;
    } else {
        r.note(
            Status::Unsupported,
            "profinet_frame_family_unimplemented",
            2,
            b.len(),
        )?;
    }
    Ok(r)
}
fn powerlink(bytes: &EvidenceBytes, l: &Limits) -> Result<Report> {
    let b = bytes.data();
    need(b, 3, "powerlink_header")?;
    let mut r = Report::new("powerlink", bytes, l)?;
    let ty = b[0] & 0x7f;
    r.u("message_type", u64::from(ty), 0..1)?;
    r.u("destination_node", u64::from(b[1]), 1..2)?;
    r.u("source_node", u64::from(b[2]), 2..3)?;
    match ty {
        1 => {
            need(b, 20, "soc")?;
            r.add(
                "soc_flags_and_time",
                hex(&b[3..20]),
                3..20,
                "soc_wire_fields_clock_not_synchronized_by_parser",
            )?;
            if b[1] != 255 {
                r.note(Status::Ambiguous, "soc_not_broadcast", 1, 2)?;
            }
        }
        3 | 4 => {
            need(b, 10, "preq_pres")?;
            r.u("flags1", u64::from(b[4]), 4..5)?;
            r.u("flags2", u64::from(b[5]), 5..6)?;
            let n = usize::from(le16(b, 8)?);
            need(b, 10 + n, "powerlink_pdo")?;
            r.add(
                "pdo_bytes",
                hex(&b[10..10 + n]),
                10..10 + n,
                "powerlink_process_data_requires_mapping",
            )?;
            if 10 + n < b.len() {
                r.note(
                    Status::Unsupported,
                    "powerlink_trailing_ethernet_bytes",
                    10 + n,
                    b.len(),
                )?;
            }
        }
        5 => {
            need(b, 7, "soa")?;
            r.add(
                "soa_control_bytes",
                hex(&b[3..7]),
                3..7,
                "soa_control_subset",
            )?;
        }
        6 => {
            need(b, 4, "asnd")?;
            r.u("service_id", u64::from(b[3]), 3..4)?;
            r.note(Status::Unsupported, "asnd_service_semantics", 4, b.len())?;
        }
        _ => r.note(
            Status::Unsupported,
            "powerlink_message_type_unknown",
            0,
            b.len(),
        )?,
    }
    Ok(r)
}
fn stp(bytes: &EvidenceBytes, l: &Limits) -> Result<Report> {
    let b = bytes.data();
    need(b, 4, "bpdu")?;
    if be16(b, 0)? != 0 {
        return Err(bad("stp_protocol", 0, "nonzero protocol identifier"));
    }
    let (version, ty) = (b[2], b[3]);
    let mut r = Report::new("stp", bytes, l)?;
    r.u("version", u64::from(version), 2..3)?;
    r.u("bpdu_type", u64::from(ty), 3..4)?;
    if version == 0 && ty == 0x80 {
        return Ok(r);
    }
    if !matches!((version, ty), (0, 0) | (2, 2) | (3, 2)) {
        r.note(Status::Unsupported, "bpdu_version_type", 2, b.len())?;
        return Ok(r);
    }
    need(b, 35, "configuration_bpdu")?;
    r.u("flags", u64::from(b[4]), 4..5)?;
    r.add("root_id", hex(&b[5..13]), 5..13, "advertised_bridge_id")?;
    r.u("root_path_cost", u64::from(be32(b, 13)?), 13..17)?;
    r.add("bridge_id", hex(&b[17..25]), 17..25, "advertised_bridge_id")?;
    r.u("port_id", u64::from(be16(b, 25)?), 25..27)?;
    for (name, p) in [
        ("message_age", 27),
        ("max_age", 29),
        ("hello_time", 31),
        ("forward_delay", 33),
    ] {
        r.add(
            name,
            Json::object([
                ("ticks", be16(b, p)?.into()),
                ("ticks_per_second", "256".into()),
            ]),
            p..p + 2,
            "bpdu_fixed_point_timer",
        )?;
    }
    if be16(b, 27)? > be16(b, 29)? {
        r.note(Status::Ambiguous, "message_age_exceeds_max_age", 27, 31)?;
    }
    if version >= 2 {
        need(b, 36, "rstp_version1_length")?;
        if b[35] != 0 {
            return Err(bad("rstp_length", 35, "version1 length must be zero"));
        }
    }
    if version == 3 {
        need(b, 102, "mstp_fixed")?;
        let len = usize::from(be16(b, 36)?);
        if len < 64 || (len - 64) % 16 != 0 {
            return Err(bad("mstp_length", 36, "MSTI record alignment"));
        }
        let end = 38 + len;
        need(b, end, "mstp_records")?;
        let count = (len - 64) / 16;
        if count > l.elements {
            return Err(Error::limit("mstp_instances"));
        }
        r.u("mst_configuration_format", u64::from(b[38]), 38..39)?;
        r.add(
            "mst_configuration_name",
            hex(&b[39..71]),
            39..71,
            "configuration_name_bytes",
        )?;
        r.u("mst_revision", u64::from(be16(b, 71)?), 71..73)?;
        r.add(
            "mst_digest",
            hex(&b[73..89]),
            73..89,
            "advertised_configuration_digest_not_verified",
        )?;
        r.u(
            "cist_internal_root_path_cost",
            u64::from(be32(b, 89)?),
            89..93,
        )?;
        r.add("cist_bridge_id", hex(&b[93..101]), 93..101, "bridge_id")?;
        r.u("remaining_hops", u64::from(b[101]), 101..102)?;
        for i in 0..count {
            let p = 102 + i * 16;
            r.add(
                format!("msti[{i}]"),
                Json::object([
                    ("flags", b[p].into()),
                    ("regional_root_id", hex(&b[p + 1..p + 9])),
                    (
                        "internal_root_path_cost",
                        be32(b, p + 9)?.to_string().into(),
                    ),
                    ("bridge_priority", b[p + 13].into()),
                    ("port_priority", b[p + 14].into()),
                    ("remaining_hops", b[p + 15].into()),
                ]),
                p..p + 16,
                "mst_instance_advertisement",
            )?;
        }
    }
    r.note(
        Status::Unsupported,
        "physical_topology_and_port_role_outcome_not_established",
        0,
        b.len(),
    )?;
    Ok(r)
}
