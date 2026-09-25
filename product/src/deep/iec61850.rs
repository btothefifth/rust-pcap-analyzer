use super::{ber, model::*};
use pcap_evidence::{json::Json, provenance::EvidenceBytes, sha256, Error, Result};
use std::collections::BTreeMap;

pub fn decode(protocol: &str, bytes: &EvidenceBytes, l: &Limits) -> Result<Report> {
    let b = bytes.data();
    need(b, 10, "iec61850_header")?;
    let n = usize::from(be16(b, 2)?);
    if n > b.len() || n < 10 {
        return Err(bad("iec61850_length", 2, "invalid declared APDU size"));
    }
    let mut r = Report::new(
        if protocol == "goose" {
            "goose"
        } else {
            "sampled_values"
        },
        bytes,
        l,
    )?;
    r.u("app_id", u64::from(be16(b, 0)?), 0..2)?;
    r.add(
        "reserved_or_security_fields",
        hex(&b[4..8]),
        4..8,
        "wire_header",
    )?;
    if n < b.len() {
        r.note(
            Status::Unsupported,
            "ethernet_tail_not_in_declared_apdu",
            n,
            b.len(),
        )?;
    }
    let tree = ber::parse(&b[8..n], l)?;
    if tree.len() != 1 {
        return Err(bad("iec61850_ber", 8, "one root required"));
    }
    let root = &tree[0];
    let body = &b[8..n];
    if protocol == "goose" {
        if !root.is(1, 1) || !root.constructed {
            return Err(bad("goose", 8, "application tag mismatch"));
        }
        let mut seen = std::collections::BTreeSet::new();
        let (mut declared, mut actual) = (None, None);
        for e in &root.children {
            if e.class != 2 {
                r.note(
                    Status::Unsupported,
                    "goose_unknown_class",
                    8 + e.header.start,
                    8 + e.end,
                )?;
                continue;
            }
            if !seen.insert(e.tag) {
                r.note(
                    Status::Ambiguous,
                    "duplicate_goose_field",
                    8 + e.header.start,
                    8 + e.end,
                )?;
            }
            let raw = &body[e.content.clone()];
            let name = match e.tag {
                0 => "gocb_ref",
                1 => "time_allowed_to_live_ms",
                2 => "dataset",
                3 => "go_id",
                4 => "event_time",
                5 => "st_num",
                6 => "sq_num",
                7 => "simulation",
                8 => "conf_rev",
                9 => "needs_commissioning",
                10 => "num_dataset_entries",
                11 => "all_data",
                _ => "unknown_field",
            };
            let v = match e.tag {
                1 | 5 | 6 | 8 | 10 => {
                    if raw.is_empty() || raw.len() > 5 {
                        return Err(bad(
                            "goose_integer",
                            8 + e.content.start,
                            "invalid integer width",
                        ));
                    }
                    let value = uint(raw, false)?;
                    if value > u64::from(u32::MAX) {
                        return Err(bad(
                            "goose_integer",
                            8 + e.content.start,
                            "integer exceeds u32",
                        ));
                    }
                    if e.tag == 10 {
                        declared = Some(value as usize);
                    }
                    value.to_string().into()
                }
                7 | 9 => {
                    if raw.len() != 1 {
                        return Err(bad(
                            "goose_boolean",
                            8 + e.content.start,
                            "invalid boolean width",
                        ));
                    }
                    (raw[0] != 0).into()
                }
                4 => {
                    if raw.len() != 8 {
                        return Err(bad(
                            "goose_time",
                            8 + e.content.start,
                            "UTC time is eight bytes",
                        ));
                    }
                    Json::object([
                        ("seconds", be32(raw, 0)?.to_string().into()),
                        ("fraction_24", uint(&raw[4..7], false)?.to_string().into()),
                        ("quality", raw[7].into()),
                        ("clock_synchronized", (raw[7] & 0x20 == 0).into()),
                    ])
                }
                11 => {
                    if !e.constructed {
                        return Err(bad(
                            "goose_data",
                            8 + e.header.start,
                            "allData must be constructed",
                        ));
                    }
                    actual = Some(e.children.len());
                    Json::array(
                        e.children
                            .iter()
                            .map(|c| ber::mms_data(c, body, l))
                            .collect::<Result<Vec<_>>>()?,
                    )
                }
                _ => hex(raw),
            };
            r.add(name, v, 8 + e.header.start..8 + e.end, "goose_schema_field")?;
        }
        for tag in [0, 1, 2, 4, 5, 6, 7, 8, 9, 10, 11] {
            if !seen.contains(&tag) {
                r.note(Status::Incomplete, "required_goose_field_missing", 8, n)?;
            }
        }
        if declared != actual {
            r.note(Status::Rejected, "dataset_count_mismatch", 8, n)?;
        }
    } else {
        if !root.is(1, 0) || !root.constructed {
            return Err(bad("sv", 8, "application tag mismatch"));
        }
        let mut declared = None;
        let mut actual = 0usize;
        for e in &root.children {
            if e.is(2, 0) {
                let n = uint(&body[e.content.clone()], false)?;
                if declared.replace(n as usize).is_some() {
                    r.note(
                        Status::Ambiguous,
                        "duplicate_no_asdu",
                        8 + e.header.start,
                        8 + e.end,
                    )?;
                }
                r.u("no_asdu", n, 8 + e.content.start..8 + e.content.end)?;
            } else if e.is(2, 2) && e.constructed {
                for asdu in &e.children {
                    if !asdu.is(0, 16) || !asdu.constructed {
                        return Err(bad(
                            "sv_asdu",
                            8 + asdu.header.start,
                            "ASDU must be SEQUENCE",
                        ));
                    }
                    let i = actual;
                    actual += 1;
                    if actual > l.elements {
                        return Err(Error::limit("sv_asdus"));
                    }
                    let mut seen = std::collections::BTreeSet::new();
                    for f in &asdu.children {
                        if f.class != 2 {
                            r.note(
                                Status::Unsupported,
                                "sv_unknown_tag_class",
                                8 + f.header.start,
                                8 + f.end,
                            )?;
                            continue;
                        }
                        if !seen.insert(f.tag) {
                            r.note(
                                Status::Ambiguous,
                                "duplicate_sv_field",
                                8 + f.header.start,
                                8 + f.end,
                            )?;
                        }
                        let raw = &body[f.content.clone()];
                        let (name, width) = match f.tag {
                            0 => ("sv_id", 0),
                            1 => ("dataset", 0),
                            2 => ("sample_count", 2),
                            3 => ("configuration_revision", 4),
                            4 => ("reference_time", 8),
                            5 => ("sample_synchronization", 1),
                            6 => ("sample_rate", 2),
                            7 => ("sequence_data", 0),
                            8 => ("sample_mode", 1),
                            _ => ("unknown", 0),
                        };
                        if width > 0 && raw.len() != width {
                            return Err(bad(
                                "sv_field_width",
                                8 + f.content.start,
                                "fixed field width mismatch",
                            ));
                        }
                        let value = if matches!(f.tag, 2 | 3 | 5 | 6 | 8) {
                            uint(raw, false)?.to_string().into()
                        } else {
                            hex(raw)
                        };
                        r.add(
                            format!("asdu[{i}].{name}"),
                            value,
                            8 + f.header.start..8 + f.end,
                            "sv_schema_field",
                        )?;
                    }
                    for tag in [0, 2, 3, 5, 7] {
                        if !seen.contains(&tag) {
                            r.note(
                                Status::Incomplete,
                                "required_sv_field_missing",
                                8 + asdu.header.start,
                                8 + asdu.end,
                            )?;
                        }
                    }
                }
            } else {
                r.note(
                    Status::Unsupported,
                    "sv_security_or_unknown_field",
                    8 + e.header.start,
                    8 + e.end,
                )?;
            }
        }
        if declared != Some(actual) {
            r.note(Status::Rejected, "sv_asdu_count_mismatch", 8, n)?;
        }
        r.note(
            Status::Unsupported,
            "sequence_data_requires_explicit_dataset_model",
            8,
            n,
        )?;
    }
    Ok(r)
}
#[derive(Clone)]
struct GooseState {
    st: u32,
    sq: u32,
    conf: u32,
    hash: [u8; 32],
    expires: Option<i128>,
    last: Option<i128>,
}
pub struct Observer {
    states: BTreeMap<String, GooseState>,
    max: usize,
}
impl Observer {
    pub fn new(max: usize) -> Result<Self> {
        if max == 0 || max > 65536 {
            return Err(Error::limit("goose_states"));
        }
        Ok(Self {
            states: BTreeMap::new(),
            max,
        })
    }
    /// Caller key includes L2 producer, VLAN, appId and gocbRef, not just stNum.
    pub fn observe(
        &mut self,
        key: &str,
        bytes: &EvidenceBytes,
        time_ns: Option<i128>,
        l: &Limits,
    ) -> Result<Report> {
        let mut r = decode("goose", bytes, l)?;
        if key.len() > 512 || key.is_empty() {
            return Err(Error::limit("goose_key"));
        }
        let lookup = |name: &str| -> Result<u32> {
            let values: Vec<_> = r.fields.iter().filter(|f| f.name == name).collect();
            if values.len() != 1 {
                return Err(bad("goose_state", 0, "missing or duplicate field"));
            }
            u32::try_from(number(Some(&values[0].value))?)
                .map_err(|_| Error::limit("goose_counter"))
        };
        let (st, sq, conf, ttl) = (
            lookup("st_num")?,
            lookup("sq_num")?,
            lookup("conf_rev")?,
            lookup("time_allowed_to_live_ms")?,
        );
        let data = r
            .fields
            .iter()
            .find(|f| f.name == "all_data")
            .ok_or_else(|| bad("goose_state", 0, "missing dataset"))?;
        let hash = sha256::digest(&bytes.data()[data.range.clone()]);
        if let Some(old) = self.states.get(key) {
            if time_ns.zip(old.last).is_some_and(|(now, last)| now < last) {
                r.note(Status::Ambiguous, "capture_time_reversal", 0, bytes.len())?;
            }
            if time_ns.zip(old.expires).is_some_and(|(now, end)| now > end) {
                r.note(
                    Status::Incomplete,
                    "advertised_ttl_expired_before_observation",
                    0,
                    bytes.len(),
                )?;
            }
            if conf != old.conf {
                r.note(
                    Status::Candidate,
                    "dataset_configuration_changed",
                    0,
                    bytes.len(),
                )?;
            }
            if st == old.st && hash != old.hash {
                r.note(
                    Status::Ambiguous,
                    "dataset_changed_without_state_number",
                    0,
                    bytes.len(),
                )?;
            }
            if st == old.st && sq <= old.sq {
                r.note(
                    Status::Ambiguous,
                    "repeated_or_reordered_sequence",
                    0,
                    bytes.len(),
                )?;
            }
            if st != old.st && sq != 0 {
                r.note(
                    Status::Incomplete,
                    "new_state_first_transmission_not_observed",
                    0,
                    bytes.len(),
                )?;
            }
        } else if self.states.len() >= self.max {
            return Err(Error::limit("goose_states"));
        }
        let expires = time_ns.and_then(|x| x.checked_add(i128::from(ttl) * 1_000_000));
        self.states.insert(
            key.into(),
            GooseState {
                st,
                sq,
                conf,
                hash,
                expires,
                last: time_ns,
            },
        );
        r.add(
            "observation_state",
            Json::object([
                (
                    "expiry_ns",
                    expires.map_or(Json::Null, |x| x.to_string().into()),
                ),
                ("wall_clock_used", false.into()),
                ("subscriber_behavior_verified", false.into()),
            ]),
            0..0,
            "capture_driven_advertisement_tracking",
        )?;
        Ok(r)
    }
}
