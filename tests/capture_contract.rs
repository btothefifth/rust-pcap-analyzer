mod common;
use common::*;
use pcap_evidence::capture::*;
use pcap_evidence::time::{Resolution, Timestamp};
use pcap_evidence::writer::{copy_exact, PcapNgWriter, PcapWriter};
use pcap_evidence::{ErrorCode, Limits};
use std::io::{self, Read};
fn records(data: &[u8]) -> Vec<Record<'_>> {
    CaptureIter::new(data, Limits::default(), ParseMode::Strict)
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
}
fn fails(data: &[u8]) -> ErrorCode {
    CaptureIter::new(data, Limits::default(), ParseMode::Strict)
        .unwrap()
        .find_map(Result::err)
        .unwrap()
        .code
}

#[test]
fn four_pcap_magic_forms_preserve_units_and_bytes() {
    for (name, ns) in [
        ("ethernet_udp_le_us.pcap", 1700000000123456000i128),
        ("ethernet_udp_be_us.pcap", 1700000000123456000),
        ("ethernet_udp_le_ns.pcap", 1700000000123456789),
        ("ethernet_udp_be_ns.pcap", 1700000000123456789),
    ] {
        let data = fixture(name);
        let parsed = records(&data);
        assert_eq!(parsed.len(), 2);
        let (p, raw) = parsed[1].packet().unwrap();
        assert_eq!(p.timestamp.unwrap().unix_nanos().unwrap(), ns);
        assert_eq!(p.frame, 1);
        assert_eq!(p.captured_len, 50);
        assert_eq!(parsed[1].offset(), 24);
        assert_eq!(
            raw.as_ptr(),
            data[40..].as_ptr(),
            "borrowed fast path must not copy packet data"
        );
        assert_eq!(&raw[42..], b"evidence");
    }
}
#[test]
fn section_endianness_interface_reset_and_signed_offset() {
    let data = fixture("mixed_sections.pcapng");
    let parsed = records(&data);
    assert_eq!(parsed.len(), 14);
    let packets: Vec<_> = parsed.iter().filter_map(Record::packet).collect();
    assert_eq!(packets.len(), 4);
    assert_eq!(packets[0].0.timestamp.unwrap().unix_nanos().unwrap(), 7);
    assert_eq!(packets[1].0.interface, 1);
    assert_eq!(packets[1].0.link_type, 101);
    assert_eq!(
        packets[1].0.timestamp.unwrap().unix_nanos().unwrap(),
        1_500_000_000
    );
    assert!(packets[2].0.timestamp.is_none());
    assert_eq!(packets[2].0.interface, 0);
    assert_eq!(packets[3].0.section, 1);
    assert_eq!(packets[3].0.interface, 0);
    assert_eq!(packets[3].0.link_type, 101);
    assert_eq!(
        packets[3].0.timestamp.unwrap().unix_nanos().unwrap(),
        3_000_004_000
    );
}
#[test]
fn binary_timestamp_inexactness_is_explicit() {
    let data = fixture("binary_inexact.pcapng");
    let parsed = records(&data);
    let time = parsed
        .last()
        .unwrap()
        .packet()
        .unwrap()
        .0
        .timestamp
        .unwrap();
    assert_eq!(time.resolution, Resolution::Binary(10));
    assert_eq!(
        time.unix_nanos().unwrap_err().code,
        ErrorCode::InexactTimestamp
    );
}
#[test]
fn unlimited_snaplen_simple_packet_has_no_fabricated_time() {
    let data = fixture("timestamp_absent.pcapng");
    let parsed = records(&data);
    let p = parsed[2].packet().unwrap().0;
    assert_eq!(p.captured_len, 50);
    assert!(p.timestamp.is_none());
}
#[test]
fn unknown_blocks_secrets_and_no_copy_custom_are_preserved_archivally() {
    let data = fixture("mixed_sections.pcapng");
    let parsed = records(&data);
    assert!(parsed.iter().any(|r| matches!(
        r.kind(),
        RecordKind::Secrets {
            secrets_type: 0x544c534b,
            ..
        }
    )));
    assert!(parsed.iter().any(|r| matches!(
        r.kind(),
        RecordKind::Custom {
            copy_on_edit: false,
            ..
        }
    )));
    assert!(parsed.iter().any(|r| matches!(
        r.kind(),
        RecordKind::Unknown {
            block_type: 0xabcdef01
        }
    )));
    let copy = copy_exact(&data, Vec::new(), Limits::default(), ParseMode::Strict).unwrap();
    assert_eq!(copy, data);
}
#[test]
fn classic_link_flags_do_not_become_linktype() {
    let data = fixture("pcap_link_flags.pcap");
    let parsed = records(&data);
    assert_eq!(parsed[1].packet().unwrap().0.link_type, 1);
    assert!(matches!(parsed[0].kind(), RecordKind::LegacyHeader(h) if h.link_word == 0x24000001));
}
#[test]
fn malformed_trailer_and_truncated_eof_are_distinct() {
    assert_eq!(
        fails(&fixture("bad_block_trailer.pcapng")),
        ErrorCode::LengthMismatch
    );
    assert_eq!(
        fails(&fixture("truncated_record.pcap")),
        ErrorCode::Truncated
    );
}
#[test]
fn iterator_is_fused_after_failure() {
    let data = fixture("truncated_record.pcap");
    let mut iter = CaptureIter::new(&data, Limits::default(), ParseMode::Strict).unwrap();
    assert!(iter.next().unwrap().is_ok());
    assert!(iter.next().unwrap().is_err());
    for _ in 0..20 {
        assert!(iter.next().is_none());
    }
}
struct TinyRead {
    bytes: Vec<u8>,
    position: usize,
    interrupt: bool,
}
impl Read for TinyRead {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.interrupt {
            self.interrupt = false;
            return Err(io::Error::from(io::ErrorKind::Interrupted));
        }
        if out.is_empty() || self.position == self.bytes.len() {
            return Ok(0);
        }
        out[0] = self.bytes[self.position];
        self.position += 1;
        self.interrupt = true;
        Ok(1)
    }
}
#[test]
fn streaming_one_byte_and_interrupted_reads_equal_borrowed() {
    let data = fixture("mixed_sections.pcapng");
    let wanted: Vec<_> = records(&data).into_iter().map(Record::into_owned).collect();
    let source = TinyRead {
        bytes: data,
        position: 0,
        interrupt: true,
    };
    let actual: Vec<_> = CaptureReader::new(source, Limits::default(), ParseMode::Strict)
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(actual, wanted);
}
#[test]
fn streaming_truncated_tail_terminates_without_refill_loop() {
    let source = TinyRead {
        bytes: fixture("truncated_record.pcap"),
        position: 0,
        interrupt: false,
    };
    let mut reader = CaptureReader::new(source, Limits::default(), ParseMode::Strict).unwrap();
    assert!(reader.next().unwrap().is_ok());
    assert_eq!(
        reader.next().unwrap().unwrap_err().code,
        ErrorCode::Truncated
    );
    assert!(reader.next().is_none());
}
#[test]
fn strict_and_evidence_modes_do_not_silently_normalize_lengths() {
    let mut data = fixture("ethernet_udp_le_us.pcap");
    data[36..40].copy_from_slice(&1u32.to_le_bytes());
    assert_eq!(fails(&data), ErrorCode::InvalidLength);
    let parsed: Vec<_> = CaptureIter::new(&data, Limits::default(), ParseMode::Evidence)
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(parsed[1].packet().unwrap().0.original_len, 1);
    assert!(!parsed[1].warnings().is_empty());
    assert_eq!(parsed[1].raw(), &data[24..]);
}
#[test]
fn invalid_microsecond_fraction_is_never_converted_as_nanoseconds() {
    let mut data = fixture("ethernet_udp_le_us.pcap");
    data[28..32].copy_from_slice(&1_000_000u32.to_le_bytes());
    assert_eq!(fails(&data), ErrorCode::InvalidTimestamp);
    let parsed: Vec<_> = CaptureIter::new(&data, Limits::default(), ParseMode::Evidence)
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert!(parsed[1].packet().unwrap().0.timestamp.is_none());
    assert!(!parsed[1].warnings().is_empty());
}
#[test]
fn oversized_declared_packet_rejected_before_payload_allocation() {
    let mut data = fixture("ethernet_udp_le_us.pcap");
    data[32..36].copy_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(fails(&data), ErrorCode::LimitExceeded);
}
#[test]
fn interface_reference_cannot_escape_section_scope() {
    let mut data = fixture("mixed_sections.pcapng");
    let position = records(&data).last().unwrap().offset() as usize;
    data[position + 8..position + 12].copy_from_slice(&1u32.to_be_bytes());
    assert_eq!(fails(&data), ErrorCode::MissingInterface);
}
#[test]
fn malformed_option_length_cannot_consume_following_block() {
    let mut data = fixture("mixed_sections.pcapng");
    // First IDB at 28, first option header at +16: length lives at 46.
    data[46..48].copy_from_slice(&65535u16.to_le_bytes());
    assert!(matches!(
        fails(&data),
        ErrorCode::InvalidOption | ErrorCode::InvalidLength
    ));
}
#[test]
fn new_writers_preserve_exact_time_and_endianness() {
    let time = Timestamp {
        ticks: 2_000_000_007,
        resolution: Resolution::Decimal(9),
        offset_seconds: -2,
    };
    for e in [Endian::Little, Endian::Big] {
        let mut writer = PcapNgWriter::new(Vec::new(), e, Limits::default()).unwrap();
        let interface = writer.interface(101, 0, time.resolution, -2).unwrap();
        writer.packet(interface, time, 3, b"abc").unwrap();
        let data = writer.finish().unwrap();
        let parsed = records(&data);
        assert_eq!(parsed[2].packet().unwrap().0.timestamp, Some(time));
        assert_eq!(parsed[2].packet().unwrap().1, b"abc");
    }
}
#[test]
fn classic_writer_rejects_precision_loss_and_accepts_exact_neighbor() {
    let mut writer = PcapWriter::new(
        Vec::new(),
        Endian::Little,
        false,
        1,
        65535,
        Limits::default(),
    )
    .unwrap();
    let exact = Timestamp {
        ticks: 1000,
        resolution: Resolution::Decimal(9),
        offset_seconds: 0,
    };
    writer.packet(exact, 1, b"a").unwrap();
    assert!(writer
        .packet(
            Timestamp {
                ticks: 1001,
                ..exact
            },
            1,
            b"a"
        )
        .is_err());
    let data = writer.finish().unwrap();
    assert_eq!(records(&data).len(), 2);
}
#[test]
fn invalid_input_copy_has_no_output_effect() {
    let mut output = Vec::new();
    assert!(copy_exact(
        &fixture("truncated_record.pcap"),
        &mut output,
        Limits::default(),
        ParseMode::Strict
    )
    .is_err());
    assert!(output.is_empty());
}
#[test]
fn decoder_need_more_does_not_advance_section_state() {
    let input = fixture("mixed_sections.pcapng");
    let mut decoder = Decoder::new(Limits::default(), ParseMode::Strict).unwrap();
    for n in 0..28 {
        assert!(matches!(
            decoder.decode(&input[..n], 0).unwrap(),
            Decode::NeedMore(_)
        ));
        assert!(decoder.format().is_none());
    }
    assert!(matches!(
        decoder.decode(&input[..28], 0).unwrap(),
        Decode::Record(_)
    ));
    assert_eq!(decoder.format(), Some(Format::PcapNg));
}
#[test]
fn bounded_salvage_identifies_section_but_does_not_invent_packets() {
    let mut data = vec![0xff; 16];
    data.extend_from_slice(&fixture("mixed_sections.pcapng"));
    let found = find_next_section(&data, 0, data.len(), &Limits::default());
    assert_eq!(found, Some(16));
}

struct FailsAfter {
    capacity: usize,
    written: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}
impl io::Write for FailsAfter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        use std::sync::atomic::Ordering;
        let old = self.written.load(Ordering::Relaxed);
        if old >= self.capacity {
            return Err(io::Error::other("injected disk failure"));
        }
        let n = bytes.len().min(self.capacity - old);
        self.written.fetch_add(n, Ordering::Relaxed);
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
#[test]
fn partial_write_poisons_writer_and_blocks_unsafe_retry() {
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    let count = Arc::new(AtomicUsize::new(0));
    let output = FailsAfter {
        capacity: 30,
        written: count.clone(),
    };
    let mut writer =
        PcapWriter::new(output, Endian::Little, false, 1, 65535, Limits::default()).unwrap();
    let time = Timestamp::legacy(1, 0, false).unwrap();
    assert!(writer.packet(time, 3, b"abc").is_err());
    assert_eq!(count.load(Ordering::Relaxed), 30);
    let failure = writer.packet(time, 3, b"abc").unwrap_err();
    assert_eq!(failure.field, "writer_failed");
    assert_eq!(count.load(Ordering::Relaxed), 30);
    assert!(writer.finish().is_err());

    let count = Arc::new(AtomicUsize::new(0));
    let output = FailsAfter {
        capacity: 30,
        written: count,
    };
    let mut writer = PcapNgWriter::new(output, Endian::Little, Limits::default()).unwrap();
    let time = Timestamp {
        ticks: 1,
        resolution: Resolution::Decimal(6),
        offset_seconds: 0,
    };
    assert!(writer
        .interface(1, 65535, Resolution::Decimal(6), 0)
        .is_err());
    assert_eq!(
        writer
            .interface(1, 65535, Resolution::Decimal(6), 0)
            .unwrap_err()
            .field,
        "writer_failed"
    );
    assert_eq!(
        writer.packet(0, time, 1, b"x").unwrap_err().field,
        "writer_failed"
    );
    assert!(writer.finish().is_err());
}
