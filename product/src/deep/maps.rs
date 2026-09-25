//! Explicit operator models. Wire values and model-dependent engineering values
//! are separate observations; a write acknowledgment never proves physical motion.
use super::model::*;
use pcap_evidence::{json::Json, provenance::EvidenceBytes, sha256, Error, Result};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Scalar {
    U16,
    I16,
    U32,
    I32,
    U64,
    I64,
    F32,
    F64,
}
impl Scalar {
    pub fn words(self) -> usize {
        match self {
            Self::U16 | Self::I16 => 1,
            Self::U32 | Self::I32 | Self::F32 => 2,
            _ => 4,
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            Self::U16 => "u16",
            Self::I16 => "i16",
            Self::U32 => "u32",
            Self::I32 => "i32",
            Self::U64 => "u64",
            Self::I64 => "i64",
            Self::F32 => "ieee754_binary32",
            Self::F64 => "ieee754_binary64",
        }
    }
}
#[derive(Clone, Debug)]
pub struct RegisterField {
    pub name: String,
    /// Zero-based protocol address, not a human 4xxxx label.
    pub address: u16,
    pub scalar: Scalar,
    /// Output word i comes from input word `word_order[i]`. Must be a permutation.
    pub word_order: Vec<usize>,
    pub swap_bytes_in_word: bool,
    pub scale_numerator: i64,
    pub scale_denominator: u64,
    pub offset_numerator: i64,
    pub offset_denominator: u64,
    pub unit: String,
}
impl RegisterField {
    pub fn validate(&self) -> Result<()> {
        if self.name.is_empty()
            || self.name.len() > 128
            || self.unit.len() > 64
            || self.scale_denominator == 0
            || self.offset_denominator == 0
            || self.word_order.len() != self.scalar.words()
        {
            return Err(bad("register_model", 0, "invalid model shape"));
        }
        let mut order = self.word_order.clone();
        order.sort_unstable();
        if order != (0..self.scalar.words()).collect::<Vec<_>>()
            || usize::from(self.address) + self.scalar.words() > 65536
        {
            return Err(bad("register_model", 0, "word order/address outside model"));
        }
        Ok(())
    }
    fn json(&self) -> Json {
        Json::object([
            ("name", self.name.clone().into()),
            ("address", self.address.into()),
            ("type", self.scalar.name().into()),
            (
                "word_order",
                Json::array(self.word_order.iter().copied().map(Json::from)),
            ),
            ("swap_bytes_in_word", self.swap_bytes_in_word.into()),
            ("scale_numerator", self.scale_numerator.to_string().into()),
            (
                "scale_denominator",
                self.scale_denominator.to_string().into(),
            ),
            ("offset_numerator", self.offset_numerator.to_string().into()),
            (
                "offset_denominator",
                self.offset_denominator.to_string().into(),
            ),
            ("unit", self.unit.clone().into()),
        ])
    }
}
#[derive(Clone, Debug)]
pub struct DeviceMap {
    pub identifier: String,
    pub unit_id: u8,
    pub fields: Vec<RegisterField>,
}
impl DeviceMap {
    pub fn validate(&self, limits: &Limits) -> Result<()> {
        if self.identifier.is_empty()
            || self.identifier.len() > 128
            || self.fields.len() > limits.elements
        {
            return Err(Error::limit("device_map"));
        }
        let mut names = std::collections::BTreeSet::new();
        for f in &self.fields {
            f.validate()?;
            if !names.insert(&f.name) {
                return Err(bad("device_map", 0, "duplicate field name"));
            }
        }
        Ok(())
    }
    pub fn json(&self) -> Json {
        Json::object([
            ("schema", "pcap-evidence.register-model.v1".into()),
            ("identifier", self.identifier.clone().into()),
            ("unit_id", self.unit_id.into()),
            (
                "fields",
                Json::array(self.fields.iter().map(RegisterField::json)),
            ),
        ])
    }
    pub fn fingerprint(&self, limits: &Limits) -> Result<[u8; 32]> {
        self.validate(limits)?;
        Ok(sha256::digest(
            self.json().encode_bounded(limits.output_bytes)?.as_bytes(),
        ))
    }
}

pub fn raw_registers(bytes: &EvidenceBytes, limits: &Limits) -> Result<Report> {
    let mut r = Report::new("modbus.registers", bytes, limits)?;
    if bytes.len() % 2 != 0 {
        r.note(
            Status::Incomplete,
            "odd_register_byte_count",
            bytes.len() - 1,
            bytes.len(),
        )?;
    }
    for (i, b) in bytes.data().chunks_exact(2).enumerate() {
        if i >= limits.elements {
            return Err(Error::limit("register_count"));
        }
        r.u(
            format!("register[{i}]"),
            u64::from(u16::from_be_bytes([b[0], b[1]])),
            i * 2..i * 2 + 2,
        )?;
    }
    Ok(r)
}
/// `start_address` must come from the matched request or a separately attributed
/// operator assertion. Callers must not invent it from a read response alone.
pub fn apply_register_map(
    bytes: &EvidenceBytes,
    start_address: u16,
    unit_id: u8,
    map: &DeviceMap,
    limits: &Limits,
) -> Result<Report> {
    map.validate(limits)?;
    if map.unit_id != unit_id {
        return Err(bad("device_map", 0, "unit identity mismatch"));
    }
    if bytes.len() % 2 != 0 || usize::from(start_address) + bytes.len() / 2 > 65536 {
        return Err(bad("register_data", 0, "invalid register range"));
    }
    let mut r = Report::new("modbus.modelled", bytes, limits)?;
    r.add(
        "model_sha256",
        sha256::hex(&map.fingerprint(limits)?).into(),
        0..0,
        "operator_configuration",
    )?;
    r.add(
        "address_basis",
        "matched_request_or_explicit_operator_assertion".into(),
        0..0,
        "caller_contract",
    )?;
    for f in &map.fields {
        if f.address < start_address {
            continue;
        }
        let at = usize::from(f.address - start_address) * 2;
        let n = f.scalar.words() * 2;
        if at >= bytes.len() {
            continue;
        }
        if at + n > bytes.len() {
            r.note(
                Status::Incomplete,
                "model_field_not_fully_observed",
                at,
                bytes.len(),
            )?;
            continue;
        }
        let mut ordered = [0u8; 8];
        for (i, &source) in f.word_order.iter().enumerate() {
            let w = &bytes.data()[at + 2 * source..at + 2 * source + 2];
            ordered[2 * i] = w[usize::from(f.swap_bytes_in_word)];
            ordered[2 * i + 1] = w[usize::from(!f.swap_bytes_in_word)];
        }
        let bits = uint(&ordered[..n], false)?;
        let value = match f.scalar {
            Scalar::U16 | Scalar::U32 | Scalar::U64 => integer_value(i128::from(bits), f),
            Scalar::I16 | Scalar::I32 | Scalar::I64 => {
                integer_value(i128::from(signed(&ordered[..n], false)?), f)
            }
            Scalar::F32 => float_value(f64::from(f32::from_bits(bits as u32)), bits, f),
            Scalar::F64 => float_value(f64::from_bits(bits), bits, f),
        }?;
        r.add(
            f.name.clone(),
            Json::object([
                ("raw_wire_hex", hex(&bytes.data()[at..at + n])),
                ("ordered_bits", format!("{bits:016x}").into()),
                ("interpretation", value),
                ("unit", f.unit.clone().into()),
                ("address", f.address.into()),
                ("physical_effect_verified", false.into()),
            ]),
            at..at + n,
            "operator_model_not_wire_self_description",
        )?;
    }
    Ok(r)
}
fn integer_value(raw: i128, f: &RegisterField) -> Result<Json> {
    let den = i128::from(f.scale_denominator)
        .checked_mul(i128::from(f.offset_denominator))
        .ok_or_else(|| Error::limit("model_rational"))?;
    let num = raw
        .checked_mul(i128::from(f.scale_numerator))
        .and_then(|n| n.checked_mul(i128::from(f.offset_denominator)))
        .and_then(|n| {
            i128::from(f.offset_numerator)
                .checked_mul(i128::from(f.scale_denominator))
                .and_then(|v| n.checked_add(v))
        })
        .ok_or_else(|| Error::limit("model_rational"))?;
    let g = gcd(num.unsigned_abs(), den as u128) as i128;
    Ok(Json::object([
        ("kind", "exact_rational".into()),
        ("raw", raw.to_string().into()),
        ("numerator", (num / g).to_string().into()),
        ("denominator", (den / g).to_string().into()),
    ]))
}
fn gcd(mut a: u128, mut b: u128) -> u128 {
    while b != 0 {
        let v = a % b;
        a = b;
        b = v;
    }
    a.max(1)
}
fn float_value(raw: f64, bits: u64, f: &RegisterField) -> Result<Json> {
    let computed = raw * (f.scale_numerator as f64 / f.scale_denominator as f64)
        + f.offset_numerator as f64 / f.offset_denominator as f64;
    Ok(Json::object([
        ("kind", "binary_float_with_rounding".into()),
        ("raw_bits", format!("{bits:016x}").into()),
        (
            "raw_decimal",
            if raw.is_finite() {
                raw.to_string().into()
            } else {
                Json::Null
            },
        ),
        (
            "scaled_decimal",
            if computed.is_finite() {
                computed.to_string().into()
            } else {
                Json::Null
            },
        ),
        ("finite", raw.is_finite().into()),
    ]))
}

/// Explicit process-image fields, also usable for negotiated CIP I/O and SV data.
#[derive(Clone, Debug)]
pub struct ImageField {
    pub name: String,
    pub bit_offset: usize,
    pub bit_length: usize,
    pub signed: bool,
    pub lsb_first: bool,
}
pub fn process_image(
    bytes: &EvidenceBytes,
    model_id: &str,
    fields: &[ImageField],
    limits: &Limits,
) -> Result<Report> {
    if model_id.is_empty() || model_id.len() > 128 || fields.len() > limits.elements {
        return Err(Error::limit("process_image_model"));
    }
    let mut r = Report::new("configured.process_image", bytes, limits)?;
    let model = Json::object([
        ("id", model_id.into()),
        (
            "fields",
            Json::array(fields.iter().map(|f| {
                Json::object([
                    ("name", f.name.clone().into()),
                    ("bit_offset", f.bit_offset.to_string().into()),
                    ("bit_length", f.bit_length.into()),
                    ("signed", f.signed.into()),
                    ("lsb_first", f.lsb_first.into()),
                ])
            })),
        ),
    ]);
    r.add(
        "model_sha256",
        sha256::hex(&sha256::digest(
            model.encode_bounded(limits.output_bytes)?.as_bytes(),
        ))
        .into(),
        0..0,
        "operator_configuration",
    )?;
    for f in fields {
        let end = f
            .bit_offset
            .checked_add(f.bit_length)
            .ok_or_else(|| Error::limit("image_offset"))?;
        if f.bit_length == 0 || f.bit_length > 64 || end > bytes.len().saturating_mul(8) {
            return Err(bad(
                "process_image",
                f.bit_offset / 8,
                "field outside observed image",
            ));
        }
        let mut n = 0u64;
        for k in 0..f.bit_length {
            let bit = f.bit_offset + k;
            let b = bytes.data()[bit / 8];
            let v = (b >> if f.lsb_first { bit % 8 } else { 7 - bit % 8 }) & 1;
            if f.lsb_first {
                n |= u64::from(v) << k;
            } else {
                n = (n << 1) | u64::from(v);
            }
        }
        let v = if f.signed {
            let shift = 64 - f.bit_length;
            (((n << shift) as i64) >> shift).to_string()
        } else {
            n.to_string()
        };
        r.add(
            f.name.clone(),
            Json::object([
                ("value", v.into()),
                ("bit_offset", f.bit_offset.to_string().into()),
                ("bit_length", f.bit_length.into()),
                ("physical_state_verified", false.into()),
            ]),
            f.bit_offset / 8..end.div_ceil(8),
            "operator_process_image_map",
        )?;
    }
    Ok(r)
}
