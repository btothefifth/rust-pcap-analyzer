//! Shared CLI/library port-list semantics. The first option replaces defaults;
//! subsequent options append distinct values. Invalid input is transactional.
use crate::{Error, ErrorCode, Result};
pub fn extend_ports(current: &mut Vec<u16>, value: &str, replace: bool) -> Result<()> {
    let mut next = if replace { Vec::new() } else { current.clone() };
    for item in value.split(',') {
        let token = item.trim();
        if token.is_empty() || !token.bytes().all(|b| b.is_ascii_digit()) {
            return Err(Error::new(
                ErrorCode::Usage,
                0,
                "ports",
                "expected comma-separated unsigned port numbers",
            ));
        }
        let port = token
            .parse::<u16>()
            .map_err(|_| Error::new(ErrorCode::Usage, 0, "ports", "port must fit u16"))?;
        if !next.contains(&port) {
            next.push(port);
        }
        if next.len() > 128 {
            return Err(Error::limit("protocol_ports"));
        }
    }
    *current = next;
    Ok(())
}
