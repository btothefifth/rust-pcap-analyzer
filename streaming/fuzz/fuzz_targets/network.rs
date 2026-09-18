#![no_main]
use libfuzzer_sys::fuzz_target;
use pcap_evidence::{
    provenance::{EvidenceBytes, PacketId},
    wire::Scope,
};
use pcap_evidence_stream::network::{self, Decoded};
fuzz_target!(|data: &[u8]| {
    if data.len() > 65536 {
        return;
    }
    let bytes = EvidenceBytes::from_packet(
        data,
        PacketId {
            capture: [0; 32],
            frame: 1,
            record_offset: 24,
        },
        0,
    );
    for link in [1, 101, 105, 127, 113, 276] {
        let scope = Scope {
            section: 0,
            interface: 0,
            vlans: vec![],
        };
        if let Ok(Decoded::Ip(d, _)) = network::decode(link, &bytes, scope) {
            assert!(d.payload.validate());
            if d.fragment.is_none() {
                if let Ok(d) = network::normalize(d) {
                    let _ = network::peel(&d);
                    let _ = network::transport_metadata(&d);
                }
            }
        }
    }
});
