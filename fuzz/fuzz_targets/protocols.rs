#![no_main]
mod support;
use libfuzzer_sys::fuzz_target;
use pcap_evidence::protocol::{ProbeInput, ProbeRegistry, ProbeTransport};
use pcap_evidence::{datagram, dnp3, modbus};
fuzz_target!(|data: &[u8]| {
    if data.len() > 65536 {
        return;
    }
    let stream = support::stream(data);
    let limits = support::limits();
    if let Ok(parsed) = dnp3::decode(&stream, &limits) {
        support::assert_dnp(data, &parsed);
    }
    if let Ok(parsed) = datagram::decode_dnp3_datagram(&support::evidence(data), &limits) {
        support::assert_dnp(data, &parsed);
    }
    for role in [
        modbus::Role::Request,
        modbus::Role::Response,
        modbus::Role::Unknown,
    ] {
        if let Ok(parsed) = modbus::decode(&stream, role, &limits) {
            assert!(parsed.messages.len() + parsed.issues.len() <= limits.max_protocol_messages);
            for message in &parsed.messages {
                support::assert_source(data, &message.raw);
            }
        }
    }
    let registry = ProbeRegistry::builtins().unwrap();
    let prefix = &data[..data.len().min(4096)];
    for transport in [ProbeTransport::Tcp, ProbeTransport::Udp] {
        registry
            .inspect(&ProbeInput {
                transport,
                source_port: 1234,
                destination_port: 4321,
                prefix,
            })
            .unwrap();
    }
});
