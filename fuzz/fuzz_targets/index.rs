#![no_main]
mod support;
use libfuzzer_sys::fuzz_target;
use pcap_evidence::capture::Endian;
use pcap_evidence::index::{Index, VerifiedIndex};
use pcap_evidence::sha256;
use pcap_evidence::time::Timestamp;
use pcap_evidence::writer::PcapWriter;
fuzz_target!(|data: &[u8]| {
    if data.len() > 4096 {
        return;
    }
    let mut writer = PcapWriter::new(
        Vec::new(),
        Endian::Little,
        true,
        147,
        65535,
        support::limits(),
    )
    .unwrap();
    writer
        .packet(
            Timestamp::legacy(123, 456, true).unwrap(),
            data.len() as u32,
            data,
        )
        .unwrap();
    let capture = writer.finish().unwrap();
    let original = Index::build(&capture, support::limits())
        .unwrap()
        .encode()
        .unwrap();
    let verified = VerifiedIndex::load(&capture, &original, support::limits()).unwrap();
    assert_eq!(verified.packet(1).unwrap(), data);
    // Raw arbitrary sidecars exercise early validation, while this rehashed
    // mutation must still fail canonical source-metadata verification.
    let _ = VerifiedIndex::load(&capture, data, support::limits());
    let mut forged = original;
    let end = forged.len() - 32;
    let position = usize::from(data.first().copied().unwrap_or(0)) % end;
    forged[position] ^= 1;
    let digest = sha256::digest(&forged[..end]);
    forged[end..].copy_from_slice(&digest);
    assert!(VerifiedIndex::load(&capture, &forged, support::limits()).is_err());
});
