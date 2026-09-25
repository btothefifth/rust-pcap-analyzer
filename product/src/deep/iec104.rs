//! IEC 60870-5-104 APCI and a bounded ASDU information-object subset.
//! Sequence and command observations are not proof that a controlled process moved.
use super::model::*;
use pcap_evidence::{json::Json, provenance::EvidenceBytes, Error, Result};
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Control {
    I { send: u16, receive: u16 },
    S { receive: u16 },
    U { function: u8 },
}
pub fn control(b: &[u8]) -> Result<Control> {
    need(b, 6, "iec104_apci")?;
    if b[0] != 0x68 || usize::from(b[1]) + 2 != b.len() || b[1] < 4 || b[1] > 253 {
        return Err(bad("iec104_apci", 0, "invalid start/length"));
    }
    if b[2] & 1 == 0 {
        if b[4] & 1 != 0 {
            return Err(bad("iec104_i", 4, "receive low bit set"));
        }
        Ok(Control::I {
            send: le16(b, 2)? >> 1,
            receive: le16(b, 4)? >> 1,
        })
    } else if b[2] & 3 == 1 {
        if b[2] != 1 || b[3] != 0 || b[4] & 1 != 0 || b.len() != 6 {
            return Err(bad("iec104_s", 2, "invalid S-format"));
        }
        Ok(Control::S {
            receive: le16(b, 4)? >> 1,
        })
    } else {
        if b[3..6] != [0, 0, 0] || b.len() != 6 || ![7, 11, 19, 35, 67, 131].contains(&b[2]) {
            return Err(bad("iec104_u", 2, "invalid U-format"));
        }
        Ok(Control::U { function: b[2] })
    }
}
fn shape(ty: u8) -> Option<(usize, &'static str, usize)> {
    Some(match ty {
        1 => (1, "single_point", 0),
        2 => (1, "single_point", 3),
        3 => (1, "double_point", 0),
        4 => (1, "double_point", 3),
        5 => (2, "step_position", 0),
        6 => (2, "step_position", 3),
        7 => (5, "bitstring32", 0),
        8 => (5, "bitstring32", 3),
        9 => (3, "normalized", 0),
        10 => (3, "normalized", 3),
        11 => (3, "scaled", 0),
        12 => (3, "scaled", 3),
        13 => (5, "float32", 0),
        14 => (5, "float32", 3),
        15 => (5, "integrated_total", 0),
        16 => (5, "integrated_total", 3),
        21 => (2, "normalized_no_quality", 0),
        30 => (1, "single_point", 7),
        31 => (1, "double_point", 7),
        32 => (2, "step_position", 7),
        33 => (5, "bitstring32", 7),
        34 => (3, "normalized", 7),
        35 => (3, "scaled", 7),
        36 => (5, "float32", 7),
        37 => (5, "integrated_total", 7),
        45 => (1, "single_command", 0),
        46 => (1, "double_command", 0),
        47 => (1, "regulating_command", 0),
        48 => (3, "set_normalized", 0),
        49 => (3, "set_scaled", 0),
        50 => (5, "set_float32", 0),
        51 => (4, "bitstring_command", 0),
        58 => (1, "single_command", 7),
        59 => (1, "double_command", 7),
        60 => (1, "regulating_command", 7),
        61 => (3, "set_normalized", 7),
        62 => (3, "set_scaled", 7),
        63 => (5, "set_float32", 7),
        64 => (4, "bitstring_command", 7),
        70 => (1, "end_initialization", 0),
        100 => (1, "interrogation", 0),
        101 => (1, "counter_interrogation", 0),
        102 => (0, "read_command", 0),
        103 => (0, "clock_sync", 7),
        104 => (2, "test_command", 0),
        105 => (1, "reset_process_command", 0),
        106 => (2, "delay_acquisition", 0),
        107 => (2, "test_command", 7),
        _ => return None,
    })
}
pub fn decode(bytes: &EvidenceBytes, l: &Limits) -> Result<Report> {
    let b = bytes.data();
    let c = control(b)?;
    let mut r = Report::new("iec104", bytes, l)?;
    match c {
        Control::I { send, receive } => {
            r.u("send_sequence", u64::from(send), 2..4)?;
            r.u("receive_sequence", u64::from(receive), 4..6)?;
        }
        Control::S { receive } => {
            r.u("receive_sequence", u64::from(receive), 4..6)?;
            return Ok(r);
        }
        Control::U { function } => {
            r.u("u_function", u64::from(function), 2..3)?;
            return Ok(r);
        }
    }
    need(b, 12, "iec104_asdu")?;
    let (ty, count, sq) = (b[6], usize::from(b[7] & 127), b[7] & 128 != 0);
    let cause = b[8] & 63;
    r.u("type_id", u64::from(ty), 6..7)?;
    r.u("object_count", count as u64, 7..8)?;
    r.flag("sequential_addresses", sq, 7..8)?;
    r.u("cause", u64::from(cause), 8..9)?;
    r.flag("negative_confirmation", b[8] & 64 != 0, 8..9)?;
    r.flag("test", b[8] & 128 != 0, 8..9)?;
    r.u("originator", u64::from(b[9]), 9..10)?;
    r.u("common_address", u64::from(le16(b, 10)?), 10..12)?;
    if count == 0 {
        r.note(Status::Rejected, "zero_object_count", 7, 8)?;
        return Ok(r);
    }
    if count > l.elements {
        return Err(Error::limit("asdu_count"));
    }
    let Some((width, kind, time)) = shape(ty) else {
        r.note(
            Status::Unsupported,
            "asdu_type_not_implemented",
            12,
            b.len(),
        )?;
        return Ok(r);
    };
    let mut at = 12;
    let mut first = 0;
    for i in 0..count {
        let address = if i == 0 || !sq {
            need(b, at + 3, "asdu_address")?;
            let value = uint(&b[at..at + 3], true)?;
            if i == 0 {
                first = value;
            }
            r.u(format!("object[{i}].address"), value, at..at + 3)?;
            at += 3;
            value
        } else {
            let value = first + i as u64;
            if value > 0xffffff {
                return Err(bad("asdu_address", at, "sequential IOA overflow"));
            }
            r.add(
                format!("object[{i}].address"),
                value.to_string().into(),
                12..15,
                "first_ioa_plus_ordinal",
            )?;
            value
        };
        need(b, at + width + time, "asdu_value")?;
        let raw = &b[at..at + width];
        let mut v = vec![
            ("kind", kind.into()),
            ("address", address.to_string().into()),
        ];
        match kind {
            "single_point" => v.extend([
                ("value", (raw[0] & 1).into()),
                ("quality_raw", (raw[0] & 0xf0).into()),
            ]),
            "double_point" => v.extend([
                ("value", (raw[0] & 3).into()),
                ("quality_raw", (raw[0] & 0xf0).into()),
            ]),
            "normalized" | "normalized_no_quality" | "set_normalized" => {
                let value = signed(&raw[..2], true)?;
                v.extend([
                    ("numerator", value.to_string().into()),
                    ("denominator", "32768".into()),
                ]);
                if width == 3 {
                    v.push(("quality_or_qualifier", raw[2].into()));
                }
            }
            "scaled" | "set_scaled" => v.extend([
                ("raw_signed", signed(&raw[..2], true)?.to_string().into()),
                ("quality_or_qualifier", raw[2].into()),
            ]),
            "float32" | "set_float32" => v.extend([
                ("float32_bits_le", hex(&raw[..4])),
                ("quality_or_qualifier", raw[4].into()),
            ]),
            "integrated_total" => v.extend([
                ("counter", signed(&raw[..4], true)?.to_string().into()),
                ("qualifier", raw[4].into()),
            ]),
            "single_command" | "double_command" | "regulating_command" => v.extend([
                ("value", (raw[0] & 3).into()),
                ("select", (raw[0] & 128 != 0).into()),
                ("qualifier", ((raw[0] >> 2) & 31).into()),
            ]),
            _ => v.push(("raw", hex(raw))),
        }
        r.add(
            format!("object[{i}].value"),
            Json::Object(v),
            at..at + width,
            "asdu_type_layout_not_device_effect",
        )?;
        at += width;
        if time > 0 {
            let raw = &b[at..at + time];
            let ms = le16(raw, 0)?;
            let mut t = vec![
                ("milliseconds", ms.into()),
                ("minute", (raw[2] & 63).into()),
                ("invalid", (raw[2] & 128 != 0).into()),
                ("raw", hex(raw)),
                ("absolute_utc_known", false.into()),
            ];
            if ms >= 60000 || raw[2] & 63 > 59 {
                r.note(Status::Rejected, "invalid_cp_time", at, at + time)?;
            }
            if time == 7 {
                t.extend([
                    ("hour", (raw[3] & 31).into()),
                    ("summer_time", (raw[3] & 128 != 0).into()),
                    ("day", (raw[4] & 31).into()),
                    ("weekday", (raw[4] >> 5).into()),
                    ("month", (raw[5] & 15).into()),
                    ("year_two_digits", (raw[6] & 127).into()),
                ]);
                if raw[3] & 31 > 23
                    || raw[4] & 31 == 0
                    || raw[5] & 15 == 0
                    || raw[5] & 15 > 12
                    || raw[6] & 127 > 99
                {
                    r.note(
                        Status::Rejected,
                        "invalid_cp56_calendar_fields",
                        at,
                        at + time,
                    )?;
                }
            }
            r.add(
                format!("object[{i}].time"),
                Json::Object(t),
                at..at + time,
                "raw_protocol_clock_timezone_unspecified",
            )?;
            at += time;
        }
    }
    if at != b.len() {
        r.note(Status::Rejected, "asdu_trailing_bytes", at, b.len())?;
    }
    Ok(r)
}
#[derive(Clone, Debug, Default)]
pub struct Session {
    next: [Option<u16>; 2],
    ack: [Option<u16>; 2],
    start_requested: [bool; 2],
    pub active: Option<bool>,
    pub tainted: bool,
}
impl Session {
    pub fn observe(&mut self, direction: u8, bytes: &EvidenceBytes, l: &Limits) -> Result<Report> {
        if direction > 1 {
            return Err(bad("iec104_direction", 0, "direction outside pair"));
        }
        let d = direction as usize;
        let peer = 1 - d;
        let before = self.json();
        let mut r = decode(bytes, l)?;
        match control(bytes.data())? {
            Control::I { send, receive } => {
                if self.next[d].is_some_and(|n| n != send) {
                    self.tainted = true;
                    r.note(Status::Ambiguous, "send_sequence_discontinuity", 2, 4)?;
                }
                self.next[d] = Some((send + 1) & 0x7fff);
                self.ack[d] = Some(receive);
                if self.active == Some(false) {
                    r.note(Status::Ambiguous, "i_format_while_stopped", 2, 6)?;
                }
            }
            Control::S { receive } => self.ack[d] = Some(receive),
            Control::U { function } => match function {
                7 => self.start_requested[d] = true,
                11 => {
                    if !self.start_requested[peer] {
                        r.note(
                            Status::Incomplete,
                            "start_confirmation_without_request",
                            2,
                            3,
                        )?;
                    }
                    self.active = Some(true);
                    self.start_requested[peer] = false;
                }
                19 => self.active = Some(false),
                35 => self.active = Some(false),
                67 | 131 => {}
                _ => {}
            },
        }
        r.add(
            "state_transition",
            Json::object([
                ("before", before),
                ("after", self.json()),
                ("endpoint_execution_verified", false.into()),
            ]),
            0..bytes.len(),
            "capture_order_state_observation",
        )?;
        Ok(r)
    }
    pub fn gap(&mut self) {
        self.next = [None, None];
        self.ack = [None, None];
        self.active = None;
        self.tainted = true;
    }
    pub fn json(&self) -> Json {
        Json::object([
            (
                "next_send",
                Json::array(self.next.iter().map(|x| x.map_or(Json::Null, Json::from))),
            ),
            (
                "last_ack",
                Json::array(self.ack.iter().map(|x| x.map_or(Json::Null, Json::from))),
            ),
            ("active", self.active.map_or(Json::Null, Json::from)),
            ("tainted", self.tainted.into()),
        ])
    }
}
