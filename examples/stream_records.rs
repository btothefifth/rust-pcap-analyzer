//! cargo run --example stream_records -- capture.pcapng
use pcap_evidence::capture::{CaptureReader, ParseMode};
use pcap_evidence::{Error, ErrorCode, Limits, Result};
use std::fs::File;
fn main() -> Result<()> {
    let path = std::env::args_os()
        .nth(1)
        .ok_or_else(|| Error::new(ErrorCode::Usage, 0, "path", "pass a capture path"))?;
    let reader = CaptureReader::new(File::open(path)?, Limits::default(), ParseMode::Strict)?;
    let mut packets = 0u64;
    for record in reader {
        let record = record?;
        if let Some((meta, data)) = record.packet() {
            packets += 1;
            println!(
                "frame={} offset={} bytes={} raw_time={:?}",
                meta.frame,
                record.offset(),
                data.len(),
                meta.timestamp
            );
        }
    }
    eprintln!("packets={packets}");
    Ok(())
}
