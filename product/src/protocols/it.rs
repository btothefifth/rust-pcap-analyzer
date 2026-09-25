use super::common::*;
use super::{Decoded, Protocol};
use pcap_evidence::{Error, Result};

pub fn bgp(b: &[u8]) -> Result<Decoded> {
    need(b, 19, "bgp_header")?;
    if b[..16] != [255; 16] {
        return Err(bad("bgp_marker", "invalid marker"));
    }
    let n = usize::from(be16(b, 16));
    if !(19..=65535).contains(&n) {
        return Err(bad("bgp_length", "length outside BGP header range"));
    }
    need(b, n, "bgp_message")?;
    let mut d = Decoded::new(Protocol::Bgp, n)
        .num("message_type", b[18], 18, 19)
        .num("message_length", n as u64, 16, 18);
    match b[18] {
        1 => {
            if n < 29 || b[19] != 4 {
                return Err(bad("bgp_open", "short OPEN or unsupported version"));
            }
            if n > 4096 {
                return Err(bad("bgp_open", "OPEN exceeds base message limit"));
            }
            let extended = b[28] != 0 && b.get(29) == Some(&255);
            let (start, options, header) = if extended {
                if n < 32 {
                    return Err(bad(
                        "bgp_open_options",
                        "truncated extended optional length",
                    ));
                }
                (32, usize::from(be16(b, 30)), 3)
            } else {
                (29, usize::from(b[28]), 2)
            };
            if start + options != n {
                return Err(bad("bgp_open_options", "inconsistent option extent"));
            }
            let mut p = start;
            while p < n {
                if p + header > n {
                    return Err(bad("bgp_open_options", "truncated option"));
                }
                let length = if extended {
                    usize::from(be16(b, p + 1))
                } else {
                    usize::from(b[p + 1])
                };
                let end = p + header + length;
                if end > n {
                    return Err(bad("bgp_open_options", "option exceeds OPEN"));
                }
                p = end;
            }
            d = d
                .num("version", b[19], 19, 20)
                .num("autonomous_system_16", be16(b, 20), 20, 22)
                .num("hold_time", be16(b, 22), 22, 24)
                .num("identifier", be32(b, 24), 24, 28);
        }
        2 => {
            if n < 23 {
                return Err(bad("bgp_update", "short UPDATE"));
            }
            let withdrawn = usize::from(be16(b, 19));
            let at = 21 + withdrawn;
            if at + 2 > n {
                return Err(bad("bgp_update", "withdrawn range exceeds message"));
            }
            let attr = usize::from(be16(b, at));
            let end = at + 2 + attr;
            if end > n {
                return Err(bad("bgp_attributes", "attributes exceed message"));
            }
            let mut p = at + 2;
            let mut count = 0u64;
            while p < end {
                if count >= 256 {
                    return Err(Error::limit("bgp_attributes"));
                }
                if p + 3 > end {
                    return Err(bad("bgp_attributes", "truncated attribute header"));
                }
                let extended = b[p] & 0x10 != 0;
                let head = if extended { 4 } else { 3 };
                if p + head > end {
                    return Err(bad("bgp_attributes", "truncated extended length"));
                }
                let len = if extended {
                    usize::from(be16(b, p + 2))
                } else {
                    usize::from(b[p + 2])
                };
                p += head;
                if p + len > end {
                    return Err(bad("bgp_attributes", "attribute data exceeds block"));
                }
                p += len;
                count += 1;
            }
            // NLRI may carry ADD-PATH identifiers. The stateless framer cannot
            // select that grammar; the source-bound depth producer does so.
            d = d.num("withdrawn_bytes", withdrawn as u64, 19, 21).num(
                "attribute_count",
                count,
                at + 2,
                end,
            );
            d.issues.push("path_attribute_semantics_opaque");
        }
        3 => {
            if n < 21 {
                return Err(bad("bgp_notification", "short NOTIFICATION"));
            }
            d = d
                .num("error_code", b[19], 19, 20)
                .num("error_subcode", b[20], 20, 21);
        }
        4 => {
            if n != 19 {
                return Err(bad(
                    "bgp_keepalive",
                    "KEEPALIVE must have only the common header",
                ));
            }
        }
        5 => {
            if n != 23 {
                return Err(bad("bgp_route_refresh", "invalid route-refresh length"));
            }
            d = d.num("afi", be16(b, 19), 19, 21).num("safi", b[22], 22, 23);
        }
        _ => return Err(bad("bgp_type", "unsupported BGP message type")),
    }
    Ok(d)
}

pub fn netflow(b: &[u8]) -> Result<Decoded> {
    need(b, 20, "netflow9")?;
    if be16(b, 0) != 9 {
        return Err(bad("netflow_version", "not v9"));
    }
    let mut p = 20;
    let mut sets = 0u64;
    let mut templates = 0u64;
    while p < b.len() {
        need(b, p + 4, "netflow_flowset")?;
        let id = be16(b, p);
        let n = usize::from(be16(b, p + 2));
        if n < 4 || n % 4 != 0 {
            return Err(bad("netflow_flowset", "invalid FlowSet length/alignment"));
        }
        need(b, p + n, "netflow_flowset")?;
        if sets >= 256 {
            return Err(Error::limit("netflow_flowsets"));
        }
        if id == 0 {
            let mut q = p + 4;
            while q + 4 <= p + n {
                let tid = be16(b, q);
                let count = usize::from(be16(b, q + 2));
                if tid < 256 || count == 0 || count > 512 {
                    return Err(bad("netflow_template", "invalid template ID/field count"));
                }
                let end = q + 4 + count * 4;
                if end > p + n {
                    return Err(bad("netflow_template", "fields exceed template set"));
                }
                q = end;
                templates += 1;
            }
            if b[q..p + n].iter().any(|v| *v != 0) {
                return Err(bad("netflow_padding", "nonzero trailing template padding"));
            }
        } else if id == 1 {
            let mut q = p + 4;
            while q + 6 <= p + n {
                let scope = usize::from(be16(b, q + 2));
                let opts = usize::from(be16(b, q + 4));
                if be16(b, q) < 256 || scope % 4 != 0 || opts % 4 != 0 {
                    return Err(bad("netflow_options", "invalid options template"));
                }
                q += 6 + scope + opts;
                if q > p + n {
                    return Err(bad("netflow_options", "options exceed FlowSet"));
                }
            }
            if b[q..p + n].iter().any(|v| *v != 0) {
                return Err(bad("netflow_padding", "nonzero trailing options padding"));
            }
        } else if id < 256 {
            return Err(bad("netflow_flowset", "reserved FlowSet ID"));
        }
        p += n;
        sets += 1;
    }
    let mut d = Decoded::new(Protocol::Netflow9, b.len())
        .num("declared_record_count", be16(b, 2), 2, 4)
        .num("system_uptime", be32(b, 4), 4, 8)
        .num("export_unix_seconds", be32(b, 8), 8, 12)
        .num("sequence", be32(b, 12), 12, 16)
        .num("source_id", be32(b, 16), 16, 20)
        .num("flowset_count", sets, 20, b.len())
        .num("template_count", templates, 20, b.len());
    d.issues
        .push("data_records_require_exporter_scoped_template_history");
    Ok(d)
}

pub fn snmp(b: &[u8]) -> Result<Decoded> {
    let tree = ber(b)?;
    if tree.tag != 0x30 || tree.children.len() < 3 {
        return Err(bad(
            "snmp",
            "expected outer sequence and version/security/PDU",
        ));
    }
    let ver = &tree.children[0];
    if ver.tag != 2 {
        return Err(bad("snmp_version", "INTEGER version required"));
    }
    let version = ber_uint(b, ver)?;
    if ![0, 1, 3].contains(&version) {
        return Err(bad("snmp_version", "unsupported version"));
    }
    let mut d = Decoded::new(Protocol::Snmp, tree.end).num("version", version, ver.start, ver.end);
    if version == 3 {
        d.issues
            .push("snmpv3_security_parameters_and_scoped_data_opaque");
        return Ok(d);
    }
    if tree.children.len() != 3 || tree.children[1].tag != 4 {
        return Err(bad("snmp_community", "invalid v1/v2c envelope"));
    }
    let security = &tree.children[1];
    d = d.num(
        "community_length",
        (security.end - security.value_start) as u64,
        security.start,
        security.end,
    );
    let pdu = &tree.children[2];
    if !(0xa0..=0xa8).contains(&pdu.tag) {
        return Err(bad("snmp_pdu", "unsupported PDU tag"));
    }
    d = d.num("pdu_tag", pdu.tag, pdu.start, pdu.value_start);
    if pdu.tag == 0xa4 {
        d.issues.push("v1_trap_body_opaque");
        return Ok(d);
    }
    if pdu.children.len() != 4 || pdu.children[0].tag != 2 || pdu.children[3].tag != 0x30 {
        return Err(bad("snmp_pdu", "invalid request/response structure"));
    }
    let bindings = &pdu.children[3];
    if bindings.children.len() > 256 {
        return Err(Error::limit("snmp_varbinds"));
    }
    for v in &bindings.children {
        if v.tag != 0x30 || v.children.len() != 2 || v.children[0].tag != 6 {
            return Err(bad("snmp_varbind", "invalid binding envelope"));
        }
    }
    d = d.num(
        "varbind_count",
        bindings.children.len() as u64,
        bindings.start,
        bindings.end,
    );
    d.issues
        .push("community_not_exported_and_varbind_values_opaque");
    Ok(d)
}

fn line(b: &[u8]) -> Result<(&[u8], usize)> {
    let end = b
        .windows(2)
        .position(|p| p == b"\r\n")
        .ok_or_else(|| short("text_line", b.len() + 1))?;
    if end > 8192 {
        return Err(Error::limit("text_line"));
    }
    let s = &b[..end];
    if s.iter().any(|v| !matches!(*v, 0x20..=0x7e | b'\t')) {
        return Err(bad("text_line", "non-ASCII or control character"));
    }
    Ok((s, end + 2))
}
pub fn text_protocol(p: Protocol, b: &[u8]) -> Result<Decoded> {
    let (s, n) = line(b)?;
    if s.first().is_some_and(u8::is_ascii_whitespace) {
        return Err(bad(
            "text_line",
            "leading whitespace is outside this subset",
        ));
    }
    let words: Vec<_> = s
        .split(|v| *v == b' ')
        .filter(|w| !w.is_empty())
        .take(3)
        .collect();
    if words.is_empty() {
        return Err(bad("text_command", "empty line"));
    }
    let keyword = |x: &[u8]| String::from_utf8_lossy(x).to_ascii_uppercase();
    let mut d = Decoded::new(p, n);
    match p {
        Protocol::Ftp => {
            let token = keyword(words[0]);
            if words[0].len() >= 3
                && words[0][..3].iter().all(u8::is_ascii_digit)
                && words[0].get(3).is_none_or(|v| *v == b'-')
            {
                d = d.text("reply_code", String::from_utf8_lossy(&words[0][..3]), 0, 3);
                if words[0].get(3) == Some(&b'-') {
                    d.issues
                        .push("multiline_reply_continuation_not_reassembled");
                }
            } else if [
                "USER", "PASS", "ACCT", "CWD", "CDUP", "SMNT", "QUIT", "REIN", "PORT", "PASV",
                "TYPE", "STRU", "MODE", "RETR", "STOR", "STOU", "APPE", "ALLO", "REST", "RNFR",
                "RNTO", "ABOR", "DELE", "RMD", "MKD", "PWD", "LIST", "NLST", "SITE", "SYST",
                "STAT", "HELP", "NOOP", "FEAT", "AUTH", "PBSZ", "PROT", "EPRT", "EPSV", "SIZE",
                "MDTM",
            ]
            .contains(&token.as_str())
            {
                d = d.text("command", token, 0, words[0].len());
            } else {
                return Err(bad("ftp", "unknown command/reply prefix"));
            }
        }
        Protocol::Pop3 => {
            let t = keyword(words[0]);
            if ["+OK", "-ERR"].contains(&t.as_str()) {
                d = d.text("response", t, 0, words[0].len());
            } else if [
                "USER", "PASS", "STAT", "LIST", "RETR", "DELE", "NOOP", "RSET", "QUIT", "TOP",
                "UIDL", "APOP", "AUTH", "CAPA", "STLS",
            ]
            .contains(&t.as_str())
            {
                d = d.text("command", t, 0, words[0].len());
            } else {
                return Err(bad("pop3", "unknown command/reply"));
            }
        }
        Protocol::Imap => {
            if words.len() < 2 || words[0].len() > 64 {
                return Err(bad("imap", "missing tag/verb"));
            }
            let verb = keyword(words[1]);
            if ![
                "CAPABILITY",
                "NOOP",
                "LOGOUT",
                "STARTTLS",
                "AUTHENTICATE",
                "LOGIN",
                "SELECT",
                "EXAMINE",
                "CREATE",
                "DELETE",
                "RENAME",
                "SUBSCRIBE",
                "UNSUBSCRIBE",
                "LIST",
                "LSUB",
                "STATUS",
                "APPEND",
                "CHECK",
                "CLOSE",
                "UNSELECT",
                "EXPUNGE",
                "SEARCH",
                "FETCH",
                "STORE",
                "COPY",
                "MOVE",
                "UID",
                "ENABLE",
                "IDLE",
                "OK",
                "NO",
                "BAD",
                "BYE",
                "PREAUTH",
                "FLAGS",
                "EXISTS",
                "RECENT",
            ]
            .contains(&verb.as_str())
            {
                return Err(bad("imap", "unsupported command/reply"));
            }
            let start = words[0].len()
                + s[words[0].len()..]
                    .iter()
                    .take_while(|v| **v == b' ')
                    .count();
            d = d.text("verb", verb, start, start + words[1].len());
            d.issues.push("literal_and_multiline_data_not_reassembled");
        }
        _ => return Err(bad("text_protocol", "not a supported text protocol")),
    }
    d.issues.push("arguments_and_credentials_not_exported");
    Ok(d)
}

pub fn tftp(b: &[u8]) -> Result<Decoded> {
    need(b, 2, "tftp")?;
    let op = be16(b, 0);
    let mut d = Decoded::new(Protocol::Tftp, b.len()).num("opcode", op, 0, 2);
    match op {
        1 | 2 => {
            let mut p = 2;
            let filename_end = b[p..]
                .iter()
                .position(|v| *v == 0)
                .ok_or_else(|| bad("tftp_filename", "missing terminator"))?
                + p;
            if filename_end == p {
                return Err(bad("tftp_filename", "empty filename"));
            }
            p = filename_end + 1;
            let mode_end = b[p..]
                .iter()
                .position(|v| *v == 0)
                .ok_or_else(|| bad("tftp_mode", "missing terminator"))?
                + p;
            let mode = String::from_utf8_lossy(&b[p..mode_end]).to_ascii_lowercase();
            if !["netascii", "octet", "mail"].contains(&mode.as_str()) {
                return Err(bad("tftp_mode", "unsupported transfer mode"));
            }
            d = d.text("mode", mode, p, mode_end);
            p = mode_end + 1;
            let mut options = 0;
            while p < b.len() {
                for _ in 0..2 {
                    let end = b[p..]
                        .iter()
                        .position(|v| *v == 0)
                        .ok_or_else(|| bad("tftp_options", "unterminated option pair"))?
                        + p;
                    if end == p {
                        return Err(bad("tftp_options", "empty option name/value"));
                    }
                    p = end + 1;
                }
                options += 1;
                if options > 32 {
                    return Err(Error::limit("tftp_options"));
                }
            }
            d = d.num("option_count", options as u64, mode_end + 1, b.len());
        }
        3 => {
            need(b, 4, "tftp_data")?;
            d = d.num("block", be16(b, 2), 2, 4).num(
                "data_length",
                (b.len() - 4) as u64,
                4,
                b.len(),
            );
            d.issues
                .push("block_size_and_completion_require_negotiation_state");
        }
        4 => {
            if b.len() != 4 {
                return Err(bad("tftp_ack", "ACK is exactly four octets"));
            }
            d = d.num("block", be16(b, 2), 2, 4);
        }
        5 => {
            need(b, 5, "tftp_error")?;
            if b.last() != Some(&0) {
                return Err(bad("tftp_error", "missing message terminator"));
            }
            d = d.num("error_code", be16(b, 2), 2, 4);
        }
        6 => {
            need(b, 4, "tftp_oack")?;
            let fields: Vec<_> = b[2..].split(|v| *v == 0).collect();
            if b.last() != Some(&0)
                || fields.len() % 2 != 1
                || fields[..fields.len() - 1].iter().any(|v| v.is_empty())
            {
                return Err(bad("tftp_oack", "invalid option pairs"));
            }
            d.issues.push("options_not_negotiated");
        }
        _ => return Err(bad("tftp_opcode", "unsupported opcode")),
    }
    Ok(d)
}

pub fn telnet(b: &[u8]) -> Result<Decoded> {
    need(b, 2, "telnet_iac")?;
    if b[0] != 255 {
        return Err(bad("telnet", "no IAC framing evidence"));
    }
    let n = match b[1] {
        255 => 2,
        251..=254 => {
            need(b, 3, "telnet_option")?;
            3
        }
        250 => {
            need(b, 3, "telnet_subnegotiation")?;
            let mut p = 3;
            loop {
                need(b, p + 1, "telnet_subnegotiation")?;
                if b[p] == 255 {
                    need(b, p + 2, "telnet_subnegotiation")?;
                    if b[p + 1] == 240 {
                        break p + 2;
                    }
                    if b[p + 1] != 255 {
                        return Err(bad("telnet_subnegotiation", "unescaped IAC without SE"));
                    }
                    p += 2;
                } else {
                    p += 1;
                }
            }
        }
        240..=249 => 2,
        _ => return Err(bad("telnet_iac", "unsupported command")),
    };
    let mut d = Decoded::new(Protocol::Telnet, n).num("iac_command", b[1], 1, 2);
    if n >= 3 {
        d = d.num("option", b[2], 2, 3);
    }
    Ok(d)
}

pub fn sip(b: &[u8]) -> Result<Decoded> {
    let end = b
        .windows(4)
        .position(|p| p == b"\r\n\r\n")
        .ok_or_else(|| short("sip_headers", b.len() + 1))?
        + 4;
    if end > 16384 {
        return Err(Error::limit("sip_headers"));
    }
    let (first, line_end) = line(b)?;
    let words: Vec<_> = first.split(|v| *v == b' ').collect();
    if words.len() < 3 {
        return Err(bad("sip_line", "invalid start line"));
    }
    let mut d = Decoded::new(Protocol::Sip, end);
    if words[0] == b"SIP/2.0" {
        if words[1].len() != 3 || !words[1].iter().all(u8::is_ascii_digit) {
            return Err(bad("sip_status", "invalid status code"));
        }
        d = d.text("status", String::from_utf8_lossy(words[1]), 8, 11);
    } else {
        let method = String::from_utf8_lossy(words[0]);
        if ![
            "INVITE",
            "ACK",
            "OPTIONS",
            "BYE",
            "CANCEL",
            "REGISTER",
            "PRACK",
            "SUBSCRIBE",
            "NOTIFY",
            "PUBLISH",
            "INFO",
            "REFER",
            "MESSAGE",
            "UPDATE",
        ]
        .contains(&method.as_ref())
            || words.last() != Some(&b"SIP/2.0".as_slice())
        {
            return Err(bad("sip_method", "unknown method or version"));
        }
        d = d.text("method", method, 0, words[0].len());
    }
    let mut p = line_end;
    let mut length = None;
    let mut headers = 0u64;
    while p < end - 2 {
        let (s, n) = line(&b[p..end])?;
        if s.first().is_some_and(u8::is_ascii_whitespace) {
            return Err(bad(
                "sip_folding",
                "folded headers outside supported subset",
            ));
        }
        let colon = s
            .iter()
            .position(|v| *v == b':')
            .ok_or_else(|| bad("sip_header", "missing colon"))?;
        let key = String::from_utf8_lossy(&s[..colon]).to_ascii_lowercase();
        if key == "content-length" || key == "l" {
            let text = std::str::from_utf8(&s[colon + 1..])
                .map_err(|_| bad("sip_length", "invalid length"))?
                .trim();
            if text.is_empty() || !text.bytes().all(|v| v.is_ascii_digit()) {
                return Err(bad("sip_length", "nondecimal length"));
            }
            let value = text
                .parse::<usize>()
                .map_err(|_| Error::limit("sip_body"))?;
            if length.is_some_and(|old| old != value) {
                return Err(bad("sip_length", "conflicting Content-Length values"));
            }
            length = Some(value);
        }
        headers += 1;
        if headers > 128 {
            return Err(Error::limit("sip_headers"));
        }
        p += n;
    }
    // TCP SIP requires Content-Length. Never guess where an unframed body ends.
    let length = length.ok_or_else(|| {
        bad(
            "sip_length",
            "Content-Length required by this stream subset",
        )
    })?;
    let total = end
        .checked_add(length)
        .ok_or_else(|| Error::limit("sip_body"))?;
    need(b, total, "sip_body")?;
    d.consumed = total;
    d = d
        .num("header_count", headers, line_end, end)
        .num("body_length", length as u64, end, total);
    d.issues.push("body_and_authorization_headers_opaque");
    Ok(d)
}

pub fn rtp(b: &[u8]) -> Result<Decoded> {
    need(b, 12, "rtp")?;
    if b[0] >> 6 != 2 {
        return Err(bad("rtp_version", "not RTP v2"));
    }
    let cc = usize::from(b[0] & 15);
    let mut p = 12 + 4 * cc;
    need(b, p, "rtp_csrc")?;
    if b[0] & 0x10 != 0 {
        need(b, p + 4, "rtp_extension")?;
        let len = usize::from(be16(b, p + 2)) * 4;
        p += 4;
        need(b, p + len, "rtp_extension")?;
        p += len;
    }
    let padding = if b[0] & 0x20 != 0 {
        usize::from(*b.last().ok_or_else(|| short("rtp", 12))?)
    } else {
        0
    };
    if (b[0] & 0x20 != 0 && padding == 0) || padding > b.len() - p {
        return Err(bad("rtp_padding", "invalid RTP padding"));
    }
    let mut d = Decoded::new(Protocol::Rtp, b.len())
        .num("version", 2u64, 0, 1)
        .num("payload_type", b[1] & 0x7f, 1, 2)
        .num("sequence", be16(b, 2), 2, 4)
        .num("rtp_timestamp", be32(b, 4), 4, 8)
        .num("ssrc", be32(b, 8), 8, 12)
        .num(
            "payload_length",
            (b.len() - p - padding) as u64,
            p,
            b.len() - padding,
        );
    d.issues
        .push("structural_rtp_candidate_not_authenticated_media");
    Ok(d)
}
pub fn pptp(b: &[u8]) -> Result<Decoded> {
    need(b, 12, "pptp")?;
    let n = usize::from(be16(b, 0));
    if n < 12 || be16(b, 2) != 1 || be32(b, 4) != 0x1a2b3c4d || be16(b, 10) != 0 {
        return Err(bad("pptp", "invalid control header"));
    }
    need(b, n, "pptp_message")?;
    let ty = be16(b, 8);
    if !(1..=15).contains(&ty) {
        return Err(bad("pptp_type", "unknown control message"));
    }
    Ok(Decoded::new(Protocol::Pptp, n)
        .num("control_type", ty, 8, 10)
        .num("message_length", n as u64, 0, 2))
}
pub fn stp(b: &[u8]) -> Result<Decoded> {
    need(b, 4, "stp")?;
    if be16(b, 0) != 0 {
        return Err(bad("stp", "invalid protocol identifier"));
    }
    let n = match (b[2], b[3]) {
        (0, 0) => 35,
        (0, 0x80) => 4,
        (2, 2) => 36,
        _ => return Err(bad("stp", "unsupported BPDU variant")),
    };
    need(b, n, "stp_bpdu")?;
    let mut d = Decoded::new(Protocol::Stp, n)
        .num("version", b[2], 2, 3)
        .num("bpdu_type", b[3], 3, 4);
    if n >= 35 {
        d = d
            .num("flags", b[4], 4, 5)
            .num("root_path_cost", be32(b, 13), 13, 17)
            .num("port_id", be16(b, 25), 25, 27)
            .num("message_age_ticks_256", be16(b, 27), 27, 29)
            .num("max_age_ticks_256", be16(b, 29), 29, 31)
            .num("hello_time_ticks_256", be16(b, 31), 31, 33)
            .num("forward_delay_ticks_256", be16(b, 33), 33, 35);
    }
    if n == 36 && b[35] != 0 {
        return Err(bad("rstp", "unsupported version1 length"));
    }
    Ok(d)
}
