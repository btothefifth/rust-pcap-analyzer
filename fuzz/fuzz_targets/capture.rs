#![no_main]
use libfuzzer_sys::fuzz_target;
use pcap_evidence::capture::{CaptureIter, ParseMode};
use pcap_evidence::Limits;
fuzz_target!(|data: &[u8]| {
    let limits = Limits {
        max_input_bytes: 1024 * 1024,
        max_block_bytes: 64 * 1024,
        max_packet_bytes: 64 * 1024,
        max_records: 4096,
        max_options: 128,
        ..Limits::default()
    };
    for mode in [ParseMode::Strict, ParseMode::Evidence] {
        if let Ok(iter) = CaptureIter::new(data, limits.clone(), mode) {
            for record in iter.flatten() {
                if let Some((meta, packet)) = record.packet() {
                    assert_eq!(meta.captured_len as usize, packet.len());
                }
            }
        }
    }
});
