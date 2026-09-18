//! cargo run --example analyze -- capture.pcap
use pcap_evidence::engine::{analyze, Config};
use pcap_evidence::publish::read_bounded;
use pcap_evidence::{Error, ErrorCode, Result};
use std::path::PathBuf;
fn main() -> Result<()> {
    let path = PathBuf::from(
        std::env::args_os()
            .nth(1)
            .ok_or_else(|| Error::new(ErrorCode::Usage, 0, "path", "pass a capture path"))?,
    );
    let config = Config::default();
    let bytes = read_bounded(&path, config.limits.max_input_bytes)?;
    let result = analyze(&bytes, config)?;
    println!(
        "packets={} generations={} protocol_directions={} diagnostics={}",
        result.packets.len(),
        result.flows.len(),
        result.applications.len(),
        result.has_diagnostics()
    );
    Ok(())
}
