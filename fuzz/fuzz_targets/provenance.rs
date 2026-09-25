#![no_main]
mod support;
use libfuzzer_sys::fuzz_target;
use pcap_evidence::provenance::EvidenceBytes;
fuzz_target!(|data: &[u8]| {
    if data.len() > 65536 {
        return;
    }
    let mut joined = EvidenceBytes::default();
    let step = 1 + usize::from(data.first().copied().unwrap_or(0) % 31);
    let mut at = 0;
    for (i, part) in data.chunks(step).enumerate() {
        joined
            .append(
                &EvidenceBytes::from_packet(part, support::id(i as u64 + 1), at),
                data.len(),
            )
            .unwrap();
        at += part.len();
    }
    assert_eq!(joined.data(), data);
    assert!(joined.validate());
    let middle = data.len() / 2;
    for range in [0..middle, middle..data.len(), middle..middle, 0..data.len()] {
        let view = joined.slice(range.clone()).unwrap();
        assert_eq!(view.data(), &data[range]);
        assert!(view.validate());
        for span in view.spans() {
            assert_eq!(
                &view.data()[span.start..span.end],
                &data[span.packet_start..span.packet_start + span.end - span.start]
            );
        }
    }
    if !data.is_empty() {
        let invalid = EvidenceBytes::from_packet(data, support::id(1), usize::MAX);
        assert!(!invalid.validate());
        assert!(invalid.slice(0..0).is_err());
    }
});
