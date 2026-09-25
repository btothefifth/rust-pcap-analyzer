#![no_main]
use libfuzzer_sys::fuzz_target;
use pcap_evidence::{
    modbus::Role,
    provenance::{EvidenceBytes, PacketId},
    semantics::{self, Limits},
};
fuzz_target!(|data: &[u8]| {
    if data.len() > 4096 {
        return;
    }
    let bytes = EvidenceBytes::from_packet(
        data,
        PacketId {
            capture: [1; 32],
            frame: 1,
            record_offset: 24,
        },
        54,
    );
    let limits = Limits {
        max_input_bytes: 4096,
        max_records: 64,
        max_fields: 256,
        max_source_spans: 1024,
        max_work: 16_384,
        max_json_bytes: 1024 * 1024,
    };
    for context in [
        semantics::dnp3::Context::ReadHeaders,
        semantics::dnp3::Context::ResponseValues,
    ] {
        let a = semantics::dnp3::decode(&bytes, context, limits.clone()).unwrap();
        let b = semantics::dnp3::decode(&bytes, context, limits.clone()).unwrap();
        assert_eq!(a.json(), b.json());
        assert!(a.consumed() <= data.len());
        for r in a.records() {
            for f in r.fields() {
                assert!(f.range().end <= data.len());
            }
        }
    }
    for role in [Role::Request, Role::Response, Role::Unknown] {
        let a = semantics::modbus::decode(&bytes, role, limits.clone()).unwrap();
        let b = semantics::modbus::decode(&bytes, role, limits.clone()).unwrap();
        assert_eq!(a.json(), b.json());
        assert!(a.consumed() <= data.len());
    }
});
