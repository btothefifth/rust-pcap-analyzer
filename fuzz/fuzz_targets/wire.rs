#![no_main]
mod support;
use libfuzzer_sys::fuzz_target;
use pcap_evidence::wire::{self, ChecksumPolicy, Scope, Transport};
fuzz_target!(|data: &[u8]| {
    if data.is_empty() || data.len() > 65536 {
        return;
    }
    let links = [1, 0, 108, 101, 228, 229, 113, 276];
    let source = &data[1..];
    let scope = Scope {
        section: 0,
        interface: 0,
        vlans: Vec::new(),
    };
    if let Ok(network) = wire::decode_packet(
        links[usize::from(data[0]) % links.len()],
        source,
        support::id(1),
        scope,
    ) {
        support::assert_source(source, &network.payload);
        for policy in [ChecksumPolicy::Observe, ChecksumPolicy::RequireValid] {
            if let Ok(transport) = wire::decode_transport(&network, policy) {
                match transport {
                    Transport::Tcp(t) => support::assert_source(source, &t.payload),
                    Transport::Udp(u) => support::assert_source(source, &u.payload),
                }
            }
        }
    }
});
