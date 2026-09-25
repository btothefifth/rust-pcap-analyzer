//! OPC UA Binary types and explicitly unsecured service observations.
//! No encrypted bytes are offered to this decoder as plaintext. The optional
//! external transform adapter emits a DIFFERENT derived-evidence artifact.
use super::model::*;
use pcap_evidence::{json::Json, provenance::EvidenceBytes, sha256, Error, Result};

pub struct Binary<'a> {
    b: &'a [u8],
    pub at: usize,
    l: Limits,
    items: usize,
}
impl<'a> Binary<'a> {
    pub fn new(b: &'a [u8], l: &Limits) -> Result<Self> {
        l.validate()?;
        if b.len() > l.input_bytes {
            return Err(Error::limit("ua_binary_bytes"));
        }
        Ok(Self {
            b,
            at: 0,
            l: l.clone(),
            items: 0,
        })
    }
    fn charge(&mut self) -> Result<()> {
        self.items += 1;
        if self.items > self.l.elements {
            return Err(Error::limit("ua_elements"));
        }
        Ok(())
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .at
            .checked_add(n)
            .ok_or_else(|| Error::limit("ua_offset"))?;
        need(self.b, end, "ua_binary")?;
        let out = &self.b[self.at..end];
        self.at = end;
        Ok(out)
    }
    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    pub fn u16(&mut self) -> Result<u16> {
        le16(self.take(2)?, 0)
    }
    pub fn u32(&mut self) -> Result<u32> {
        le32(self.take(4)?, 0)
    }
    pub fn i32(&mut self) -> Result<i32> {
        Ok(self.u32()? as i32)
    }
    pub fn i64(&mut self) -> Result<i64> {
        signed(self.take(8)?, true)
    }
    pub fn string(&mut self, utf8: bool) -> Result<Json> {
        let n = self.i32()?;
        if n == -1 {
            return Ok(Json::Null);
        }
        if n < 0 || n as usize > self.l.input_bytes {
            return Err(bad("ua_string", self.at, "invalid string length"));
        }
        let raw = self.take(n as usize)?;
        if utf8 {
            let value =
                std::str::from_utf8(raw).map_err(|_| bad("ua_utf8", self.at, "invalid UTF-8"))?;
            Ok(value.into())
        } else {
            Ok(hex(raw))
        }
    }
    pub fn node(&mut self, expanded: bool) -> Result<(Json, Option<(u16, u32)>)> {
        self.charge()?;
        let encoding = self.u8()?;
        if !expanded && encoding & 0xc0 != 0 {
            return Err(bad(
                "ua_node_id",
                self.at - 1,
                "ExpandedNodeId flags on NodeId",
            ));
        }
        let (kind, ns, value, id) = match encoding & 63 {
            0 => {
                let n = u32::from(self.u8()?);
                ("numeric", 0, n.to_string().into(), Some((0, n)))
            }
            1 => {
                let ns = u16::from(self.u8()?);
                let n = u32::from(self.u16()?);
                ("numeric", ns, n.to_string().into(), Some((ns, n)))
            }
            2 => {
                let ns = self.u16()?;
                let n = self.u32()?;
                ("numeric", ns, n.to_string().into(), Some((ns, n)))
            }
            3 => {
                let ns = self.u16()?;
                ("string", ns, self.string(true)?, None)
            }
            4 => {
                let ns = self.u16()?;
                ("guid_raw_mixed_endian", ns, hex(self.take(16)?), None)
            }
            5 => {
                let ns = self.u16()?;
                ("bytes", ns, self.string(false)?, None)
            }
            _ => return Err(bad("ua_node_id", self.at - 1, "unknown NodeId encoding")),
        };
        let uri = if encoding & 128 != 0 {
            self.string(true)?
        } else {
            Json::Null
        };
        let server = if encoding & 64 != 0 {
            self.u32()?.to_string().into()
        } else {
            Json::Null
        };
        Ok((
            Json::object([
                ("kind", kind.into()),
                ("namespace_index", ns.into()),
                ("identifier", value),
                ("namespace_uri", uri),
                ("server_index", server),
            ]),
            id,
        ))
    }
    fn qname(&mut self) -> Result<Json> {
        let ns = self.u16()?;
        let name = self.string(true)?;
        Ok(Json::object([("namespace", ns.into()), ("name", name)]))
    }
    fn localized(&mut self) -> Result<Json> {
        let mask = self.u8()?;
        if mask & !3 != 0 {
            return Err(bad("ua_localized_text", self.at - 1, "reserved bits"));
        }
        let locale = if mask & 1 != 0 {
            self.string(true)?
        } else {
            Json::Null
        };
        let text = if mask & 2 != 0 {
            self.string(true)?
        } else {
            Json::Null
        };
        Ok(Json::object([("locale", locale), ("text", text)]))
    }
    fn extension(&mut self) -> Result<Json> {
        let (id, _) = self.node(false)?;
        let enc = self.u8()?;
        let (len, hash) = match enc {
            0 => (0, Json::Null),
            1 | 2 => {
                let n = self.i32()?;
                if n < 0 || n as usize > self.l.input_bytes {
                    return Err(bad("ua_extension", self.at, "invalid body size"));
                }
                let b = self.take(n as usize)?;
                (n as usize, sha256::hex(&sha256::digest(b)).into())
            }
            _ => return Err(bad("ua_extension", self.at - 1, "unknown encoding")),
        };
        Ok(Json::object([
            ("type_id", id),
            ("encoding", enc.into()),
            ("body_length", len.to_string().into()),
            ("body_sha256", hash),
            ("body_semantics", "opaque".into()),
        ]))
    }
    fn diagnostic(&mut self, depth: usize) -> Result<Json> {
        if depth >= self.l.depth {
            return Err(Error::limit("ua_diagnostic_depth"));
        }
        self.charge()?;
        let m = self.u8()?;
        if m & 128 != 0 {
            return Err(bad("ua_diagnostic", self.at - 1, "reserved bit"));
        }
        let mut fields = vec![("mask", m.into())];
        for (bit, name) in [
            (1, "symbolic_id"),
            (2, "namespace_uri"),
            (4, "locale"),
            (8, "localized_text"),
        ] {
            if m & bit != 0 {
                fields.push((name, self.i32()?.to_string().into()));
            }
        }
        if m & 16 != 0 {
            fields.push(("additional_info", self.string(true)?));
        }
        if m & 32 != 0 {
            fields.push(("inner_status", self.u32()?.to_string().into()));
        }
        if m & 64 != 0 {
            fields.push(("inner", self.diagnostic(depth + 1)?));
        }
        Ok(Json::Object(fields))
    }
    pub fn variant(&mut self, depth: usize) -> Result<Json> {
        if depth >= self.l.depth {
            return Err(Error::limit("ua_variant_depth"));
        }
        self.charge()?;
        let encoding = self.u8()?;
        let ty = encoding & 63;
        if ty == 0 {
            if encoding != 0 {
                return Err(bad("ua_variant", self.at - 1, "null variant with flags"));
            }
            return Ok(Json::Null);
        }
        if encoding & 64 != 0 && encoding & 128 == 0 {
            return Err(bad("ua_variant", self.at - 1, "dimensions without array"));
        }
        let mut count = None;
        let value = if encoding & 128 != 0 {
            let n = self.i32()?;
            if n < -1 || n as i64 > self.l.elements as i64 {
                return Err(Error::limit("ua_array"));
            }
            if n == -1 {
                Json::Null
            } else {
                count = Some(n as usize);
                let mut values = Vec::new();
                for _ in 0..n {
                    values.push(self.scalar(ty, depth + 1)?);
                }
                Json::Array(values)
            }
        } else {
            if ty == 24 {
                return Err(bad(
                    "ua_variant",
                    self.at,
                    "scalar Variant inside Variant prohibited",
                ));
            }
            self.scalar(ty, depth + 1)?
        };
        let dimensions = if encoding & 64 != 0 {
            let n = self.i32()?;
            if n < 2 || n as usize > self.l.depth {
                return Err(bad("ua_array_dimensions", self.at, "invalid rank"));
            }
            let mut ds = Vec::new();
            let mut product = 1usize;
            for _ in 0..n {
                let d = self.i32()?;
                if d <= 0 {
                    return Err(bad("ua_array_dimensions", self.at, "nonpositive dimension"));
                }
                product = product
                    .checked_mul(d as usize)
                    .ok_or_else(|| Error::limit("ua_dimensions"))?;
                ds.push(Json::from(d.to_string()));
            }
            if count != Some(product) {
                return Err(bad("ua_array_dimensions", self.at, "array length mismatch"));
            }
            Json::Array(ds)
        } else {
            Json::Null
        };
        Ok(Json::object([
            ("type", ty.into()),
            ("value", value),
            ("dimensions", dimensions),
        ]))
    }
    fn scalar(&mut self, ty: u8, depth: usize) -> Result<Json> {
        if depth >= self.l.depth {
            return Err(Error::limit("ua_type_depth"));
        }
        self.charge()?;
        match ty {
            1 => Ok((self.u8()? != 0).into()),
            2 => Ok((self.u8()? as i8).to_string().into()),
            3 => Ok(self.u8()?.to_string().into()),
            4 => Ok((self.u16()? as i16).to_string().into()),
            5 => Ok(self.u16()?.to_string().into()),
            6 => Ok(self.i32()?.to_string().into()),
            7 | 19 => Ok(self.u32()?.to_string().into()),
            8 | 13 => Ok(self.i64()?.to_string().into()),
            9 => Ok(uint(self.take(8)?, true)?.to_string().into()),
            10 => Ok(Json::object([("float32_bits_le", hex(self.take(4)?))])),
            11 => Ok(Json::object([("float64_bits_le", hex(self.take(8)?))])),
            12 => self.string(true),
            14 => Ok(hex(self.take(16)?)),
            15 | 16 | 26..=31 => self.string(false),
            17 => Ok(self.node(false)?.0),
            18 => Ok(self.node(true)?.0),
            20 => self.qname(),
            21 => self.localized(),
            22 => self.extension(),
            23 => self.data_value(depth + 1),
            24 => self.variant(depth + 1),
            25 => self.diagnostic(depth + 1),
            _ => Err(bad("ua_type", self.at, "unsupported built-in type")),
        }
    }
    pub fn data_value(&mut self, depth: usize) -> Result<Json> {
        if depth >= self.l.depth {
            return Err(Error::limit("ua_datavalue_depth"));
        }
        self.charge()?;
        let mask = self.u8()?;
        if mask & 0xc0 != 0 {
            return Err(bad("ua_datavalue", self.at - 1, "reserved mask bits"));
        }
        let mut out = vec![("mask", mask.into())];
        if mask & 1 != 0 {
            out.push(("value", self.variant(depth + 1)?));
        }
        if mask & 2 != 0 {
            out.push(("status", self.u32()?.to_string().into()));
        }
        if mask & 4 != 0 {
            out.push((
                "source_time_100ns_since_1601",
                self.i64()?.to_string().into(),
            ));
        }
        if mask & 16 != 0 {
            let p = self.u16()?;
            out.push(("source_picoseconds_raw", p.into()));
        }
        if mask & 8 != 0 {
            out.push((
                "server_time_100ns_since_1601",
                self.i64()?.to_string().into(),
            ));
        }
        if mask & 32 != 0 {
            out.push(("server_picoseconds_raw", self.u16()?.into()));
        }
        Ok(Json::Object(out))
    }
    fn request_header(&mut self) -> Result<Json> {
        let token_start = self.at;
        self.node(false)?;
        let token_end = self.at;
        let token_hash = sha256::hex(&sha256::digest(&self.b[token_start..token_end]));
        let ts = self.i64()?;
        let handle = self.u32()?;
        let diagnostics = self.u32()?;
        let audit = self.string(true)?;
        let timeout = self.u32()?;
        let additional = self.extension()?;
        Ok(Json::object([
            ("authentication_token_sha256", token_hash.into()),
            ("timestamp_100ns_since_1601", ts.to_string().into()),
            ("request_handle", handle.into()),
            ("return_diagnostics", diagnostics.into()),
            ("audit_entry_present", (!matches!(audit, Json::Null)).into()),
            ("timeout_hint_ms", timeout.into()),
            ("additional_header", additional),
        ]))
    }
    fn response_header(&mut self) -> Result<Json> {
        let ts = self.i64()?;
        let handle = self.u32()?;
        let result = self.u32()?;
        let diagnostic = self.diagnostic(0)?;
        let count = self.i32()?;
        if count < -1 || count as i64 > self.l.elements as i64 {
            return Err(Error::limit("ua_string_table"));
        }
        let mut strings = Vec::new();
        for _ in 0..count.max(0) {
            strings.push(self.string(true)?);
        }
        let additional = self.extension()?;
        Ok(Json::object([
            ("timestamp_100ns_since_1601", ts.to_string().into()),
            ("request_handle", handle.into()),
            ("service_result", result.to_string().into()),
            ("diagnostic", diagnostic),
            ("string_table", Json::Array(strings)),
            ("additional_header", additional),
        ]))
    }
}
/// Input is a complete unsecured/reconstructed service body beginning with its
/// encoding NodeId. Decrypted bodies use the separate transform provenance path.
pub fn service(bytes: &EvidenceBytes, l: &Limits) -> Result<Report> {
    let b = bytes.data();
    let mut c = Binary::new(b, l)?;
    let (node, id) = c.node(false)?;
    let mut r = Report::new("opcua.service", bytes, l)?;
    r.add("type_id", node, 0..c.at, "service_encoding_nodeid")?;
    let Some((0, id)) = id else {
        r.note(
            Status::Unsupported,
            "vendor_service_encoding",
            c.at,
            b.len(),
        )?;
        return Ok(r);
    };
    let response = matches!(id, 397 | 449 | 455 | 464 | 470 | 530 | 634 | 676);
    let request = matches!(id, 446 | 452 | 461 | 467 | 527 | 631 | 673);
    if !response && !request {
        r.note(
            Status::Unsupported,
            "service_schema_not_implemented",
            c.at,
            b.len(),
        )?;
        return Ok(r);
    }
    let start = c.at;
    let header = if response {
        c.response_header()?
    } else {
        c.request_header()?
    };
    r.add(
        "service_header",
        header,
        start..c.at,
        "ua_request_or_response_header",
    )?;
    if id == 631 {
        let p = c.at;
        let age = hex(c.take(8)?);
        let timestamps = c.u32()?;
        let count = c.i32()?;
        if count < 0 || count as usize > l.elements {
            return Err(Error::limit("ua_read_nodes"));
        }
        r.add(
            "read_options",
            Json::object([
                ("max_age_double_bits_le", age),
                ("timestamps_to_return", timestamps.into()),
            ]),
            p..p + 12,
            "read_request",
        )?;
        for i in 0..count {
            let p = c.at;
            let node = c.node(false)?.0;
            let attribute = c.u32()?;
            let index = c.string(true)?;
            let encoding = c.qname()?;
            r.add(
                format!("read[{i}]"),
                Json::object([
                    ("node", node),
                    ("attribute", attribute.into()),
                    ("index_range", index),
                    ("data_encoding", encoding),
                ]),
                p..c.at,
                "read_value_id",
            )?;
        }
    } else if id == 673 {
        let count = c.i32()?;
        if count < 0 || count as usize > l.elements {
            return Err(Error::limit("ua_write_nodes"));
        }
        for i in 0..count {
            let p = c.at;
            let node = c.node(false)?.0;
            let attribute = c.u32()?;
            let index = c.string(true)?;
            let value = c.data_value(0)?;
            r.add(
                format!("write[{i}]"),
                Json::object([
                    ("node", node),
                    ("attribute", attribute.into()),
                    ("index_range", index),
                    ("value", value),
                    ("physical_effect_verified", false.into()),
                ]),
                p..c.at,
                "write_value",
            )?;
        }
    } else if id == 634 {
        let count = c.i32()?;
        if count < -1 || count as i64 > l.elements as i64 {
            return Err(Error::limit("ua_read_results"));
        }
        for i in 0..count.max(0) {
            let p = c.at;
            let v = c.data_value(0)?;
            r.add(
                format!("result[{i}]"),
                v,
                p..c.at,
                "read_response_datavalue",
            )?;
        }
        let n = c.i32()?;
        if n < -1 || n as i64 > l.elements as i64 {
            return Err(Error::limit("ua_diagnostics"));
        }
        for i in 0..n.max(0) {
            let p = c.at;
            let v = c.diagnostic(0)?;
            r.add(
                format!("diagnostic[{i}]"),
                v,
                p..c.at,
                "service_result_diagnostic",
            )?;
        }
    } else if id == 676 {
        let count = c.i32()?;
        if count < -1 || count as i64 > l.elements as i64 {
            return Err(Error::limit("ua_write_results"));
        }
        for i in 0..count.max(0) {
            let p = c.at;
            let v = c.u32()?;
            r.u(format!("result[{i}].status"), u64::from(v), p..c.at)?;
        }
        let n = c.i32()?;
        if n < -1 || n as i64 > l.elements as i64 {
            return Err(Error::limit("ua_diagnostics"));
        }
        for i in 0..n.max(0) {
            let p = c.at;
            let v = c.diagnostic(0)?;
            r.add(
                format!("diagnostic[{i}]"),
                v,
                p..c.at,
                "service_result_diagnostic",
            )?;
        }
    } else {
        r.note(
            Status::Unsupported,
            "service_body_outside_read_write_subset",
            c.at,
            b.len(),
        )?;
        return Ok(r);
    }
    if c.at != b.len() {
        r.note(
            Status::Unsupported,
            "service_tail_uninterpreted",
            c.at,
            b.len(),
        )?;
    }
    Ok(r)
}
pub fn decode(bytes: &EvidenceBytes, security_none: bool, l: &Limits) -> Result<Report> {
    let b = bytes.data();
    need(b, 8, "ua_tcp")?;
    if usize::try_from(le32(b, 4)?).map_err(|_| Error::limit("ua_size"))? != b.len() {
        return Err(bad("ua_size", 4, "framed size mismatch"));
    }
    let ty = &b[..3];
    let mut r = Report::new("opcua_tcp", bytes, l)?;
    r.add("message_type", hex(ty), 0..3, "ua_tcp_header")?;
    r.u("chunk_type", u64::from(b[3]), 3..4)?;
    if ty == b"HEL" || ty == b"ACK" {
        need(b, 28, "ua_hello_ack")?;
        for (name, p) in [
            ("protocol_version", 8),
            ("receive_buffer", 12),
            ("send_buffer", 16),
            ("max_message", 20),
            ("max_chunks", 24),
        ] {
            r.u(name, u64::from(le32(b, p)?), p..p + 4)?;
        }
        if ty == b"HEL" {
            let mut c = Binary::new(&b[28..], l)?;
            r.add(
                "endpoint_url",
                c.string(true)?,
                28..28 + c.at,
                "hello_endpoint",
            )?;
            if 28 + c.at != b.len() {
                return Err(bad("ua_hello", 28 + c.at, "trailing bytes"));
            }
        }
        return Ok(r);
    }
    if ty == b"ERR" {
        need(b, 12, "ua_error")?;
        r.u("status", u64::from(le32(b, 8)?), 8..12)?;
        let mut c = Binary::new(&b[12..], l)?;
        r.add(
            "reason",
            c.string(true)?,
            12..12 + c.at,
            "ua_transport_error",
        )?;
        return Ok(r);
    }
    if !matches!(ty, b"OPN" | b"MSG" | b"CLO") {
        r.note(Status::Unsupported, "ua_message_type", 0, b.len())?;
        return Ok(r);
    }
    need(b, 12, "ua_channel")?;
    r.u("channel_id", u64::from(le32(b, 8)?), 8..12)?;
    let (mut at, unsecured) = if ty == b"OPN" {
        let mut c = Binary::new(&b[12..], l)?;
        let uri = c.string(true)?;
        let uri_none =
            uri == Json::String("http://opcfoundation.org/UA/SecurityPolicy#None".into());
        r.add(
            "security_policy_uri",
            uri,
            12..12 + c.at,
            "asymmetric_security_header",
        )?;
        let cert_start = c.at;
        let cert = c.string(false)?;
        r.add(
            "sender_certificate_present",
            (!matches!(&cert, Json::Null) && cert != Json::String(String::new())).into(),
            12 + cert_start..12 + c.at,
            "certificate_is_not_trust_validation",
        )?;
        let thumb = c.string(false)?;
        let _ = thumb;
        (12 + c.at, uri_none && security_none)
    } else {
        need(b, 16, "ua_token")?;
        r.u("token_id", u64::from(le32(b, 12)?), 12..16)?;
        (16, security_none)
    };
    if !unsecured {
        r.note(
            Status::Unsupported,
            "secure_payload_requires_explicit_crypto_context",
            at,
            b.len(),
        )?;
        return Ok(r);
    }
    need(b, at + 8, "ua_sequence")?;
    r.u("sequence_number", u64::from(le32(b, at)?), at..at + 4)?;
    r.u("request_id", u64::from(le32(b, at + 4)?), at + 4..at + 8)?;
    at += 8;
    if b[3] == b'A' {
        r.note(Status::Incomplete, "message_aborted", at, b.len())?;
        return Ok(r);
    }
    if b[3] != b'F' {
        if b[3] != b'C' {
            return Err(bad("ua_chunk", 3, "unknown chunk type"));
        }
        r.note(Status::Incomplete, "message_continues", at, b.len())?;
        return Ok(r);
    }
    let body = bytes.slice(at..bytes.len())?;
    r.add(
        "service",
        service(&body, l)?.json(),
        at..bytes.len(),
        "explicit_security_none_service_body",
    )?;
    Ok(r)
}
