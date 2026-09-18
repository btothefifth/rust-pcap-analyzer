use pcap_evidence::{Error, ErrorCode, Result};
pub fn bad(field: &'static str, detail: &'static str) -> Error {
    Error::new(ErrorCode::ProtocolFraming, 0, field, detail)
}
pub fn short(field: &'static str, need: usize) -> Error {
    Error::new(
        ErrorCode::Truncated,
        0,
        field,
        format!("need at least {need} contiguous octets"),
    )
}
pub fn need(b: &[u8], n: usize, f: &'static str) -> Result<()> {
    if n > super::MAX_FRAME {
        return Err(Error::limit("protocol_frame"));
    }
    if b.len() < n {
        Err(short(f, n))
    } else {
        Ok(())
    }
}
pub fn be16(b: &[u8], i: usize) -> u16 {
    u16::from_be_bytes([b[i], b[i + 1]])
}
pub fn be32(b: &[u8], i: usize) -> u32 {
    u32::from_be_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]])
}
pub fn le16(b: &[u8], i: usize) -> u16 {
    u16::from_le_bytes([b[i], b[i + 1]])
}
pub fn le32(b: &[u8], i: usize) -> u32 {
    u32::from_le_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]])
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BerElement {
    pub tag: u8,
    pub start: usize,
    pub value_start: usize,
    pub end: usize,
    pub children: Vec<BerElement>,
}
/// Definite-length BER subset. Indefinite encoding is UNSUPPORTED, not malformed.
/// Constructed data is walked with independent depth/node/work limits.
pub fn ber(b: &[u8]) -> Result<BerElement> {
    if b.len() > super::MAX_FRAME {
        return Err(Error::limit("ber_input"));
    }
    fn element(
        b: &[u8],
        start: usize,
        limit: usize,
        depth: usize,
        nodes: &mut usize,
    ) -> Result<BerElement> {
        if depth > 16 || *nodes >= 1024 {
            return Err(Error::limit("ber_tree"));
        }
        *nodes += 1;
        if start.checked_add(2).is_none_or(|n| n > limit) {
            return Err(short("ber_header", start + 2));
        }
        let tag = b[start];
        if tag & 31 == 31 {
            return Err(Error::new(
                ErrorCode::UnsupportedTransport,
                start as u64,
                "ber_tag",
                "high-tag-number BER is outside this subset",
            ));
        }
        let len = b[start + 1];
        let mut p = start + 2;
        if len == 0x80 {
            return Err(Error::new(
                ErrorCode::UnsupportedTransport,
                start as u64,
                "ber_length",
                "indefinite BER not implemented",
            ));
        }
        let n = if len & 0x80 == 0 {
            usize::from(len)
        } else {
            let width = usize::from(len & 0x7f);
            if width == 0 || width > 4 {
                return Err(bad("ber_length", "invalid or excessive length width"));
            }
            if p + width > limit {
                return Err(short("ber_length", p + width));
            }
            let mut value = 0usize;
            for &v in &b[p..p + width] {
                value = value
                    .checked_mul(256)
                    .and_then(|x| x.checked_add(v as usize))
                    .ok_or_else(|| Error::limit("ber_length"))?;
            }
            p += width;
            value
        };
        let end = p.checked_add(n).ok_or_else(|| Error::limit("ber_length"))?;
        if end > limit {
            return Err(short("ber_value", end));
        }
        let mut children = Vec::new();
        if tag & 0x20 != 0 {
            let mut at = p;
            while at < end {
                let c = element(b, at, end, depth + 1, nodes)?;
                at = c.end;
                children.push(c);
            }
        }
        Ok(BerElement {
            tag,
            start,
            value_start: p,
            end,
            children,
        })
    }
    let mut nodes = 0;
    element(b, 0, b.len(), 0, &mut nodes)
}
pub fn ber_uint(b: &[u8], e: &BerElement) -> Result<u64> {
    let x = &b[e.value_start..e.end];
    if x.is_empty() || x.len() > 8 || x[0] & 0x80 != 0 {
        return Err(bad(
            "ber_integer",
            "unsupported negative or oversized integer",
        ));
    }
    Ok(x.iter().fold(0u64, |a, v| (a << 8) | u64::from(*v)))
}
pub fn crc16(b: &[u8], poly: u16, mut crc: u16, reflected: bool, xor: u16) -> u16 {
    for &x in b {
        if reflected {
            crc ^= u16::from(x);
            for _ in 0..8 {
                crc = if crc & 1 != 0 {
                    (crc >> 1) ^ poly
                } else {
                    crc >> 1
                };
            }
        } else {
            crc ^= u16::from(x) << 8;
            for _ in 0..8 {
                crc = if crc & 0x8000 != 0 {
                    (crc << 1) ^ poly
                } else {
                    crc << 1
                };
            }
        }
    }
    crc ^ xor
}
