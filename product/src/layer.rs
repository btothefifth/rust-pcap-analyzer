//! Supplementary L2 envelope decoding with exact packet-relative ranges.
use crate::{
    protocols::{Decoded, Protocol},
    Error, ErrorCode, Result,
};
pub fn decode(link: u32, b: &[u8]) -> Result<Option<(usize, Decoded)>> {
    if link == 165 {
        return Ok(Some((0, Protocol::BacnetMstp.decode(b)?)));
    }
    if link != 1 {
        return Ok(None);
    }
    if b.len() < 14 {
        return Err(Error::new(
            ErrorCode::Truncated,
            0,
            "ethernet",
            "need Ethernet header",
        ));
    }
    let mut ty = u16::from_be_bytes([b[12], b[13]]);
    let mut at = 14;
    let mut depth = 0;
    while [0x8100, 0x88a8, 0x9100].contains(&ty) {
        depth += 1;
        if depth > 8 {
            return Err(Error::limit("vlan_depth"));
        }
        if b.len() < at + 4 {
            return Err(Error::new(
                ErrorCode::Truncated,
                at as u64,
                "vlan",
                "short VLAN",
            ));
        }
        ty = u16::from_be_bytes([b[at + 2], b[at + 3]]);
        at += 4;
    }
    let p = match ty {
        0x88b8 => Protocol::Goose,
        0x88ba => Protocol::SampledValues,
        0x88a4 => Protocol::Ethercat,
        0x8892 => Protocol::Profinet,
        0x88ab => Protocol::Powerlink,
        0..=1500 => {
            let end = at + usize::from(ty);
            if end > b.len() {
                return Err(Error::new(
                    ErrorCode::Truncated,
                    at as u64,
                    "802_3",
                    "declared LLC data missing",
                ));
            }
            if end >= at + 3 && b[at..at + 3] == [0x42, 0x42, 3] {
                at += 3;
                return Ok(Some((at, Protocol::Stp.decode(&b[at..end])?)));
            }
            return Ok(None);
        }
        _ => return Ok(None),
    };
    if !p.compiled() {
        return Ok(None);
    }
    Ok(Some((at, p.decode(&b[at..])?)))
}
