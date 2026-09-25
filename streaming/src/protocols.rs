//! Narrow, bounds-checked protocol metadata decoders. None decrypts traffic,
//! attributes attacks, decodes arbitrary application bodies, or infers device state.
use crate::{malformed, Error, Result};
use pcap_evidence::{json::Json, sha256};
use std::net::Ipv6Addr;

fn need(b: &[u8], n: usize, field: &'static str) -> Result<()> {
    if b.len() < n {
        Err(malformed(field, "truncated structure"))
    } else {
        Ok(())
    }
}
pub(crate) fn be16(b: &[u8], p: usize) -> u16 {
    u16::from_be_bytes([b[p], b[p + 1]])
}
pub(crate) fn be32(b: &[u8], p: usize) -> u32 {
    u32::from_be_bytes([b[p], b[p + 1], b[p + 2], b[p + 3]])
}
fn le16(b: &[u8], p: usize) -> u16 {
    u16::from_le_bytes([b[p], b[p + 1]])
}
fn le32(b: &[u8], p: usize) -> u32 {
    u32::from_le_bytes([b[p], b[p + 1], b[p + 2], b[p + 3]])
}
fn le64(b: &[u8], p: usize) -> u64 {
    u64::from_le_bytes([
        b[p],
        b[p + 1],
        b[p + 2],
        b[p + 3],
        b[p + 4],
        b[p + 5],
        b[p + 6],
        b[p + 7],
    ])
}
fn ip4(b: &[u8]) -> String {
    format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3])
}
fn text(b: &[u8]) -> Json {
    // Exact captured bytes remain available through spans/hash. Do not introduce
    // U+FFFD and then use that lossy string as a correlation identity.
    match std::str::from_utf8(b) {
        Ok(s) if !s.chars().any(char::is_control) => Json::object([("text", s.into())]),
        _ => Json::object([("hex", sha256::hex(b).into())]),
    }
}
#[derive(Clone, Debug)]
pub struct DnsQuestion {
    pub name: String,
    pub kind: u16,
    pub class: u16,
}
#[derive(Clone, Debug)]
pub struct DnsMessage {
    pub id: u16,
    pub response: bool,
    pub truncated: bool,
    pub questions: Vec<DnsQuestion>,
    pub metadata: Json,
}

/// RFC 1035 compression. Pointers must point backwards, names have <=255 wire
/// octets, and traversal work is capped. No recursion, unchecked slicing or loops.
pub fn dns_name(b: &[u8], start: usize) -> Result<(String, usize)> {
    if start >= b.len() {
        return Err(malformed("dns_name", "start outside packet"));
    }
    let mut p = start;
    let mut consumed = None;
    let mut labels = Vec::new();
    let mut expanded = 1usize;
    for _ in 0..128 {
        need(b, p + 1, "dns_name")?;
        let n = b[p];
        if n & 0xc0 == 0xc0 {
            need(b, p + 2, "dns_pointer")?;
            let target = (usize::from(n & 63) << 8) | usize::from(b[p + 1]);
            if target >= p {
                return Err(malformed("dns_pointer", "forward/self compression pointer"));
            }
            consumed.get_or_insert(p + 2);
            p = target;
            continue;
        }
        if n & 0xc0 != 0 {
            return Err(malformed("dns_name", "unsupported extended label type"));
        }
        p += 1;
        if n == 0 {
            return Ok((
                if labels.is_empty() {
                    ".".into()
                } else {
                    labels.join(".")
                },
                consumed.unwrap_or(p),
            ));
        }
        let n = usize::from(n);
        need(b, p + n, "dns_label")?;
        expanded = expanded
            .checked_add(n + 1)
            .ok_or_else(|| Error::limit("dns_name"))?;
        if expanded > 255 {
            return Err(malformed("dns_name", "expanded name exceeds 255 octets"));
        }
        let mut label = String::new();
        for &x in &b[p..p + n] {
            if x.is_ascii_alphanumeric() || [b'-', b'_'].contains(&x) {
                label.push(char::from(x));
            } else {
                label.push_str(&format!("\\{x:03}"));
            }
        }
        labels.push(label);
        p += n;
    }
    Err(Error::limit("dns_name_steps"))
}
pub fn dns(b: &[u8]) -> Result<DnsMessage> {
    need(b, 12, "dns")?;
    let flags = be16(b, 2);
    let counts = [be16(b, 4), be16(b, 6), be16(b, 8), be16(b, 10)];
    let count: usize = counts.iter().map(|n| usize::from(*n)).sum();
    if count > 512 {
        return Err(Error::limit("dns_records"));
    }
    let mut p = 12;
    let mut questions = Vec::new();
    for _ in 0..counts[0] {
        let (name, next) = dns_name(b, p)?;
        p = next;
        need(b, p + 4, "dns_question")?;
        questions.push(DnsQuestion {
            name,
            kind: be16(b, p),
            class: be16(b, p + 2),
        });
        p += 4;
    }
    let mut records = Vec::new();
    for (section, n) in [
        ("answer", counts[1]),
        ("authority", counts[2]),
        ("additional", counts[3]),
    ] {
        for _ in 0..n {
            let (name, next) = dns_name(b, p)?;
            p = next;
            need(b, p + 10, "dns_rr")?;
            let kind = be16(b, p);
            let class = be16(b, p + 2);
            let ttl = be32(b, p + 4);
            let len = usize::from(be16(b, p + 8));
            p += 10;
            need(b, p + len, "dns_rdata")?;
            let data = &b[p..p + len];
            let value = match kind {
                1 if len == 4 => Json::object([("address", ip4(data).into())]),
                28 if len == 16 => {
                    let mut a = [0u8; 16];
                    a.copy_from_slice(data);
                    Json::object([("address", Ipv6Addr::from(a).to_string().into())])
                }
                2 | 5 | 12 => {
                    let (target, after) = dns_name(b, p)?;
                    if after != p + len {
                        return Err(malformed("dns_rdata", "name does not fill RDATA"));
                    }
                    Json::object([("name", target.into())])
                }
                15 => {
                    if len < 3 {
                        return Err(malformed("dns_mx", "short MX RDATA"));
                    }
                    let (target, after) = dns_name(b, p + 2)?;
                    if after != p + len {
                        return Err(malformed("dns_mx", "name does not fill RDATA"));
                    }
                    Json::object([
                        ("preference", be16(b, p).into()),
                        ("exchange", target.into()),
                    ])
                }
                _ => Json::object([
                    ("opaque_sha256", sha256::hex(&sha256::digest(data)).into()),
                    ("length", len.into()),
                ]),
            };
            records.push(Json::object([
                ("section", section.into()),
                ("name", name.into()),
                ("type", kind.into()),
                ("class", class.into()),
                ("ttl", ttl.into()),
                ("value", value),
            ]));
            p += len;
        }
    }
    if p != b.len() {
        return Err(malformed("dns", "unexplained trailing bytes"));
    }
    let response = flags & 0x8000 != 0;
    let truncated = flags & 0x0200 != 0;
    let metadata = Json::object([
        ("id", be16(b, 0).into()),
        ("response", response.into()),
        ("truncated", truncated.into()),
        ("opcode", ((flags >> 11) & 15).into()),
        ("rcode", (flags & 15).into()),
        (
            "questions",
            Json::array(questions.iter().map(|q| {
                Json::object([
                    ("name", q.name.clone().into()),
                    ("type", q.kind.into()),
                    ("class", q.class.into()),
                ])
            })),
        ),
        ("records", Json::Array(records)),
        ("dnssec_validation", "not_performed".into()),
    ]);
    Ok(DnsMessage {
        id: be16(b, 0),
        response,
        truncated,
        questions,
        metadata,
    })
}
pub fn dns_key(d: &DnsMessage) -> String {
    let mut out = d.id.to_string();
    for q in &d.questions {
        out.push_str(&format!(
            "|{}:{}:{}",
            q.name.to_ascii_lowercase(),
            q.kind,
            q.class
        ));
    }
    out
}

pub fn dhcp(b: &[u8]) -> Result<Json> {
    need(b, 240, "dhcp")?;
    if ![1, 2].contains(&b[0]) || b[2] == 0 || b[2] > 16 || b[236..240] != [99, 130, 83, 99] {
        return Err(malformed("dhcp", "not a supported BOOTP/DHCP header"));
    }
    let mut p = 240;
    let mut count = 0;
    let mut opts = Vec::new();
    let mut ended = false;
    let mut overload = false;
    while p < b.len() {
        let code = b[p];
        p += 1;
        if code == 0 {
            continue;
        }
        if code == 255 {
            ended = true;
            break;
        }
        count += 1;
        if count > 256 {
            return Err(Error::limit("dhcp_options"));
        }
        need(b, p + 1, "dhcp_option_length")?;
        let n = usize::from(b[p]);
        p += 1;
        need(b, p + n, "dhcp_option")?;
        let v = &b[p..p + n];
        let value = match code {
            53 if n == 1 => Json::object([("message_type", v[0].into())]),
            50 | 54 if n == 4 => Json::object([("address", ip4(v).into())]),
            51 if n == 4 => Json::object([("lease_seconds", be32(v, 0).into())]),
            12 | 60 => text(v),
            52 => {
                overload = true;
                text(v)
            }
            _ => Json::object([
                ("length", n.into()),
                ("sha256", sha256::hex(&sha256::digest(v)).into()),
            ]),
        };
        opts.push(Json::object([("code", code.into()), ("value", value)]));
        p += n;
    }
    Ok(Json::object([
        ("operation", b[0].into()),
        ("transaction_id", be32(b, 4).into()),
        ("client_address", ip4(&b[12..16]).into()),
        ("your_address", ip4(&b[16..20]).into()),
        ("server_address", ip4(&b[20..24]).into()),
        ("relay_address", ip4(&b[24..28]).into()),
        (
            "client_hardware",
            sha256::hex(&b[28..28 + usize::from(b[2])]).into(),
        ),
        ("options", Json::Array(opts)),
        ("end_option_observed", ended.into()),
        ("option_overload_uninterpreted", overload.into()),
    ]))
}
pub fn dhcpv6(b: &[u8]) -> Result<Json> {
    need(b, 4, "dhcpv6")?;
    if [12, 13].contains(&b[0]) {
        return Err(malformed("dhcpv6", "relay encapsulation not implemented"));
    }
    if !(1..=11).contains(&b[0]) {
        return Err(malformed("dhcpv6", "unsupported message type"));
    }
    let mut p = 4;
    let mut options = Vec::new();
    while p < b.len() {
        if options.len() >= 256 {
            return Err(Error::limit("dhcpv6_options"));
        }
        need(b, p + 4, "dhcpv6_option")?;
        let code = be16(b, p);
        let n = usize::from(be16(b, p + 2));
        p += 4;
        need(b, p + n, "dhcpv6_option")?;
        options.push(Json::object([
            ("code", code.into()),
            ("length", n.into()),
            (
                "opaque_sha256",
                sha256::hex(&sha256::digest(&b[p..p + n])).into(),
            ),
        ]));
        p += n;
    }
    Ok(Json::object([
        ("type", b[0].into()),
        (
            "transaction_id",
            ((u32::from(b[1]) << 16) | (u32::from(b[2]) << 8) | u32::from(b[3])).into(),
        ),
        ("options", Json::Array(options)),
    ]))
}

pub fn quic(b: &[u8]) -> Result<Json> {
    need(b, 7, "quic_long_header")?;
    if b[0] & 0x80 == 0 {
        return Err(malformed(
            "quic",
            "short header cannot be identified without connection context",
        ));
    }
    let version = be32(b, 1);
    if version != 0 && b[0] & 0x40 == 0 {
        return Err(malformed("quic", "fixed bit not set"));
    }
    let d = usize::from(b[5]);
    if d > 20 {
        return Err(malformed("quic", "destination CID too long"));
    }
    need(b, 7 + d, "quic_cids")?;
    let s = usize::from(b[6 + d]);
    if s > 20 {
        return Err(malformed("quic", "source CID too long"));
    }
    need(b, 7 + d + s, "quic_cids")?;
    let rest = &b[7 + d + s..];
    if version == 0 && (rest.is_empty() || rest.len() % 4 != 0) {
        return Err(malformed("quic", "invalid version-negotiation list"));
    }
    Ok(Json::object([
        ("version", version.into()),
        ("destination_cid", sha256::hex(&b[6..6 + d]).into()),
        ("source_cid", sha256::hex(&b[7 + d..7 + d + s]).into()),
        ("header_form", "long_invariant_metadata_only".into()),
        ("packet_protection_removed", false.into()),
        ("http3_decoded", false.into()),
    ]))
}

pub fn http_header(b: &[u8]) -> Result<(Json, usize)> {
    let end = b
        .windows(4)
        .position(|x| x == b"\r\n\r\n")
        .map(|p| p + 4)
        .ok_or_else(|| malformed("http", "incomplete header"))?;
    if end > 64 * 1024 {
        return Err(Error::limit("http_header"));
    }
    let first_end = b[..end]
        .windows(2)
        .position(|x| x == b"\r\n")
        .ok_or_else(|| malformed("http", "missing first line"))?;
    let line = std::str::from_utf8(&b[..first_end])
        .map_err(|_| malformed("http", "non-UTF8 start line"))?;
    let parts: Vec<_> = line.split(' ').collect();
    let response = line.starts_with("HTTP/1.");
    let start = if response {
        if parts.len() < 2
            || !["HTTP/1.0", "HTTP/1.1"].contains(&parts[0])
            || parts[1].len() != 3
            || !parts[1].bytes().all(|c| c.is_ascii_digit())
        {
            return Err(malformed("http", "invalid status line"));
        }
        Json::object([("version", parts[0].into()), ("status", parts[1].into())])
    } else {
        if parts.len() != 3
            || parts[0].is_empty()
            || !parts[0].bytes().all(token)
            || !["HTTP/1.0", "HTTP/1.1"].contains(&parts[2])
        {
            return Err(malformed("http", "invalid request line"));
        }
        Json::object([
            ("method", parts[0].into()),
            ("target", parts[1].into()),
            ("version", parts[2].into()),
        ])
    };
    let mut p = first_end + 2;
    let mut selected = Vec::new();
    let mut count = 0;
    let mut lengths = Vec::new();
    let mut transfer = false;
    while p < end - 2 {
        count += 1;
        if count > 256 {
            return Err(Error::limit("http_fields"));
        }
        let n = b[p..end]
            .windows(2)
            .position(|x| x == b"\r\n")
            .ok_or_else(|| malformed("http", "unterminated field"))?;
        let raw = &b[p..p + n];
        p += n + 2;
        let colon = raw
            .iter()
            .position(|c| *c == b':')
            .ok_or_else(|| malformed("http", "missing colon"))?;
        if colon == 0 || !raw[..colon].iter().copied().all(token) {
            return Err(malformed("http", "invalid/obsolete folded field name"));
        }
        let name = std::str::from_utf8(&raw[..colon])
            .map_err(|_| malformed("http", "invalid field name"))?
            .to_ascii_lowercase();
        let mut value = &raw[colon + 1..];
        while value.first().is_some_and(|c| [b' ', b'\t'].contains(c)) {
            value = &value[1..];
        }
        while value.last().is_some_and(|c| [b' ', b'\t'].contains(c)) {
            value = &value[..value.len() - 1];
        }
        if value.iter().any(|c| (*c < 32 && *c != b'\t') || *c == 127) {
            return Err(malformed("http", "control character in field"));
        }
        if name == "content-length" {
            let s = std::str::from_utf8(value)
                .map_err(|_| malformed("http", "invalid Content-Length"))?;
            for x in s.split(',') {
                let x = x.trim();
                if x.is_empty() || !x.bytes().all(|c| c.is_ascii_digit()) {
                    return Err(malformed("http", "invalid Content-Length"));
                }
                lengths.push(
                    x.parse::<u64>()
                        .map_err(|_| malformed("http", "Content-Length overflow"))?,
                );
            }
        }
        transfer |= name == "transfer-encoding";
        if [
            "host",
            "content-type",
            "content-length",
            "transfer-encoding",
            "user-agent",
            "server",
        ]
        .contains(&name.as_str())
        {
            selected.push(Json::object([
                ("name", name.into()),
                ("value", text(value)),
            ]));
        }
    }
    let ambiguous = (transfer && !lengths.is_empty()) || lengths.windows(2).any(|w| w[0] != w[1]);
    Ok((
        Json::object([
            ("response", response.into()),
            ("start_line", start),
            ("headers", Json::Array(selected)),
            ("framing_ambiguous", ambiguous.into()),
            ("body_decoded", false.into()),
            ("scope", "first_header_in_contiguous_analysis_window".into()),
        ]),
        end,
    ))
}
fn token(c: u8) -> bool {
    c.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&c)
}

/// TLS ClientHello handshake body (without the 4-byte handshake header).
/// Unknown extensions remain metadata. No keys, decryption, certificates, or JA3 claims.
pub fn tls_client_hello(b: &[u8]) -> Result<Json> {
    need(b, 35, "tls_client_hello")?;
    let version = be16(b, 0);
    let mut p = 34;
    let sid = usize::from(b[p]);
    p += 1;
    if sid > 32 {
        return Err(malformed("tls_session_id", "session ID exceeds 32 bytes"));
    }
    need(b, p + sid + 2, "tls_session_id")?;
    p += sid;
    let cipher_len = usize::from(be16(b, p));
    p += 2;
    if cipher_len == 0 || cipher_len % 2 != 0 || cipher_len > 4096 {
        return Err(malformed("tls_cipher_suites", "invalid vector length"));
    }
    need(b, p + cipher_len + 1, "tls_ciphers")?;
    let ciphers: Vec<Json> = b[p..p + cipher_len]
        .chunks_exact(2)
        .map(|x| be16(x, 0).into())
        .collect();
    p += cipher_len;
    let comp = usize::from(b[p]);
    p += 1;
    if comp == 0 {
        return Err(malformed("tls_compression", "empty vector"));
    }
    need(b, p + comp, "tls_compression")?;
    p += comp;
    let mut names = Vec::new();
    let mut alpn = Vec::new();
    let mut versions = Vec::new();
    let mut extension_types = Vec::new();
    if p < b.len() {
        need(b, p + 2, "tls_extensions")?;
        let total = usize::from(be16(b, p));
        p += 2;
        if total != b.len() - p {
            return Err(malformed("tls_extensions", "vector length mismatch"));
        }
        while p < b.len() {
            if extension_types.len() >= 256 {
                return Err(Error::limit("tls_extensions"));
            }
            need(b, p + 4, "tls_extension")?;
            let ty = be16(b, p);
            let n = usize::from(be16(b, p + 2));
            p += 4;
            need(b, p + n, "tls_extension")?;
            if extension_types.contains(&ty) {
                return Err(malformed("tls_extension", "duplicate extension"));
            }
            extension_types.push(ty);
            let v = &b[p..p + n];
            p += n;
            match ty {
                0 => {
                    need(v, 3, "tls_sni")?;
                    if usize::from(be16(v, 0)) + 2 != v.len() {
                        return Err(malformed("tls_sni", "list length mismatch"));
                    }
                    let mut q = 2;
                    while q < v.len() {
                        need(v, q + 3, "tls_sni_name")?;
                        let typ = v[q];
                        let size = usize::from(be16(v, q + 1));
                        q += 3;
                        need(v, q + size, "tls_sni_name")?;
                        if typ != 0 || size == 0 || !names.is_empty() {
                            return Err(malformed(
                                "tls_sni",
                                "unsupported, empty, or duplicate host_name",
                            ));
                        }
                        names.push(text(&v[q..q + size]));
                        q += size;
                    }
                }
                16 => {
                    need(v, 4, "tls_alpn")?;
                    if usize::from(be16(v, 0)) + 2 != v.len() {
                        return Err(malformed("tls_alpn", "list length mismatch"));
                    }
                    let mut q = 2;
                    while q < v.len() {
                        let size = usize::from(v[q]);
                        q += 1;
                        if size == 0 {
                            return Err(malformed("tls_alpn", "empty name"));
                        }
                        need(v, q + size, "tls_alpn_name")?;
                        alpn.push(text(&v[q..q + size]));
                        q += size;
                    }
                }
                43 => {
                    need(v, 1, "tls_versions")?;
                    let n = usize::from(v[0]);
                    if n == 0 || n % 2 != 0 || n + 1 != v.len() {
                        return Err(malformed("tls_versions", "invalid vector"));
                    }
                    versions.extend(v[1..].chunks_exact(2).map(|x| Json::from(be16(x, 0))));
                }
                _ => {}
            }
        }
    }
    Ok(Json::object([
        ("handshake", "client_hello".into()),
        ("legacy_version", version.into()),
        ("cipher_suites", Json::Array(ciphers)),
        ("sni", Json::Array(names)),
        ("alpn", Json::Array(alpn)),
        ("supported_versions", Json::Array(versions)),
        (
            "extension_types",
            Json::array(extension_types.into_iter().map(Json::from)),
        ),
    ]))
}
pub fn smb2(b: &[u8]) -> Result<Json> {
    need(b, 4, "smb")?;
    if b[..4] == [0xfd, b'S', b'M', b'B'] || b[..4] == [0xfc, b'S', b'M', b'B'] {
        return Ok(Json::object([
            ("scope", "transform_header_only".into()),
            ("decrypted_or_decompressed", false.into()),
        ]));
    }
    need(b, 64, "smb2_header")?;
    if b[..4] != [0xfe, b'S', b'M', b'B'] || le16(b, 4) != 64 {
        return Err(malformed("smb2", "bad signature/header size"));
    }
    let next = le32(b, 20) as usize;
    if next != 0 && (next < 64 || next % 8 != 0 || next > b.len()) {
        return Err(malformed("smb2", "invalid next-command offset"));
    }
    Ok(Json::object([
        ("command", le16(b, 12).into()),
        ("flags", le32(b, 16).into()),
        ("message_id", le64(b, 24).to_string().into()),
        ("session_id", le64(b, 40).to_string().into()),
        ("next_command_offset", next.into()),
        ("compound_tail_decoded", false.into()),
        ("scope", "first_smb2_header_only".into()),
    ]))
}
