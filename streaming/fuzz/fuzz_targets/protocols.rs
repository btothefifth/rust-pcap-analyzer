#![no_main]
use libfuzzer_sys::fuzz_target;
use pcap_evidence_stream::protocols;
fuzz_target!(|data: &[u8]| {
    if data.len() > 65536 {
        return;
    }
    let _ = protocols::dns(data);
    let _ = protocols::http_header(data);
    let _ = protocols::dhcp(data);
    let _ = protocols::dhcpv6(data);
    let _ = protocols::quic(data);
    let _ = protocols::tls_client_hello(data);
    let _ = protocols::smb2(data);
});
