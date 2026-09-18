#![no_main]
mod support;
use libfuzzer_sys::fuzz_target;
use pcap_evidence::capture::CaptureIter;
use pcap_evidence::dnp3::Dnp3Result;
use pcap_evidence::engine::{analyze, ApplicationData, Config, Disposition};
use pcap_evidence::provenance::EvidenceBytes;
fn dnp_bytes(value: &Dnp3Result, check: &impl Fn(&EvidenceBytes)) {
    for frame in &value.frames {
        check(&frame.raw);
        check(&frame.user_data);
    }
    for fragment in &value.fragments {
        check(&fragment.raw);
        check(&fragment.objects);
    }
    for message in &value.messages {
        check(&message.objects);
    }
}
fuzz_target!(|data: &[u8]| {
    if data.len() > 65536 {
        return;
    }
    let config = Config {
        limits: support::limits(),
        ..Config::default()
    };
    if let Ok(analysis) = analyze(data, config.clone()) {
        let mut originals = Vec::new();
        for record in CaptureIter::new(data, config.limits, config.parse_mode).unwrap() {
            let record = record.unwrap();
            if let Some((_, packet)) = record.packet() {
                originals.push((record.offset(), packet.to_vec()));
            }
        }
        assert_eq!(analysis.packets.len(), originals.len());
        let check = |bytes: &EvidenceBytes| {
            assert!(bytes.validate());
            for span in bytes.spans() {
                let frame = span.packet.frame.checked_sub(1).unwrap() as usize;
                let (offset, packet) = &originals[frame];
                assert_eq!(span.packet.capture, analysis.capture_sha256);
                assert_eq!(span.packet.record_offset, *offset);
                let end = span
                    .packet_start
                    .checked_add(span.end - span.start)
                    .unwrap();
                assert_eq!(
                    &bytes.data()[span.start..span.end],
                    packet.get(span.packet_start..end).unwrap()
                );
            }
        };
        for packet in &analysis.packets {
            assert!(!matches!(
                packet.disposition,
                Disposition::Pending | Disposition::FragmentPending
            ));
        }
        for flow in &analysis.flows {
            for stream in flow.streams.iter().flatten() {
                for chunk in &stream.chunks {
                    check(&chunk.bytes);
                }
            }
        }
        for app in &analysis.applications {
            match &app.data {
                ApplicationData::Dnp3(d) => dnp_bytes(d, &check),
                ApplicationData::Modbus(m) => {
                    for message in &m.messages {
                        check(&message.raw);
                    }
                }
                ApplicationData::Failed(_) => {}
            }
        }
        for datagram in &analysis.datagrams {
            check(&datagram.payload);
            if let Ok(d) = &datagram.data {
                dnp_bytes(d, &check);
            }
        }
    }
});
