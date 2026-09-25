#![no_main]
mod support;
use libfuzzer_sys::fuzz_target;
use pcap_evidence::provenance::EvidenceBytes;
use pcap_evidence::tcp::{sequence_delta, OverlapPolicy, StreamAssembler};
fuzz_target!(|data: &[u8]| {
    if data.len() < 4 || data.len() > 65536 {
        return;
    }
    let base = u32::from_le_bytes(data[..4].try_into().unwrap());
    for policy in [
        OverlapPolicy::RejectConflict,
        OverlapPolicy::FirstObserved,
        OverlapPolicy::LastObserved,
    ] {
        let mut stream = StreamAssembler::new(
            if base & 1 == 0 {
                Some(base.wrapping_sub(1))
            } else {
                None
            },
            support::limits(),
        );
        let mut packets: Vec<&[u8]> = Vec::new();
        let mut fins = Vec::new();
        let mut at = 4;
        while at + 4 <= data.len() && packets.len() < 128 {
            let delta = i16::from_le_bytes([data[at], data[at + 1]]);
            let length = usize::from(data[at + 2]).min(data.len() - at - 4);
            let flags = data[at + 3];
            at += 4;
            let packet = &data[at..at + length];
            at += length;
            packets.push(packet);
            let sequence = base.wrapping_add(i32::from(delta) as u32);
            if stream
                .push(
                    sequence,
                    EvidenceBytes::from_packet(packet, support::id(packets.len() as u64), 0),
                )
                .is_err()
            {
                return;
            }
            if flags & 1 != 0 {
                let end = sequence.wrapping_add(length as u32);
                if stream.end_at(end).is_err() {
                    return;
                }
                fins.push(end);
            }
        }
        if let Ok(result) = stream.finish(policy) {
            for chunk in &result.chunks {
                assert!(chunk.bytes.validate());
                for span in chunk.bytes.spans() {
                    let source = packets[span.packet.frame as usize - 1];
                    assert_eq!(
                        &chunk.bytes.data()[span.start..span.end],
                        &source[span.packet_start..span.packet_start + span.end - span.start]
                    );
                }
                if let Some(anchor) = result.base_sequence {
                    for fin in &fins {
                        if let Ok(end) = sequence_delta(*fin, anchor) {
                            assert!(
                                chunk.offset + chunk.bytes.len() as i64 <= end,
                                "accepted bytes past observed FIN"
                            );
                        }
                    }
                }
            }
        }
    }
});
